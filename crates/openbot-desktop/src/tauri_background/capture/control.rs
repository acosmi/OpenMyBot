//! Append-only facts for one original capture owner. Durable bytes never mint authority.
use super::CaptureOperation;
use crate::desktop_release::{CaptureProfile, ReviewedNormalCaptureRequest};
use openbot_domain::backup::WholePgCarrierFault as Fault;
use openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck;
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tokio::task::JoinHandle;

const CONTROL: &str = ".wrokbot-capture-control-v1";
// root + intent + one consumer + nine stages + one pending fact.
const MAX_JOURNAL_JOBS: usize = 13;
const ORDINARY_AUDIT_LEAF: &str = "capture-audit-checkpoint-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlSourceIdentity {
    pub(crate) instance_id: String,
    pub(crate) dataset_id: String,
    pub(crate) deployment_id: String,
    pub(crate) tenant_id: String,
    pub(crate) system_identifier: String,
    pub(crate) database_oid: u32,
    pub(crate) key_id: String,
    pub(crate) key_version: u32,
    pub(crate) source_device: u64,
    pub(crate) source_inode: u64,
    pub(crate) source_uid: u32,
    pub(crate) canary_material_id: String,
    pub(crate) schema_material_id: String,
    pub(crate) migration_material_id: String,
    pub(crate) compatibility_material_id: String,
}
impl ControlSourceIdentity {
    fn check(&self) -> Result<(), Fault> {
        for s in [
            &self.instance_id,
            &self.dataset_id,
            &self.deployment_id,
            &self.tenant_id,
            &self.key_id,
            &self.canary_material_id,
            &self.schema_material_id,
            &self.migration_material_id,
            &self.compatibility_material_id,
        ] {
            if s.is_empty() || s.len() > 128 || s.capacity() > 128 || s.contains('\0') {
                return Err(Fault::IntentMismatch);
            }
        }
        let sys = self
            .system_identifier
            .parse::<u64>()
            .map_err(|_| Fault::IntentMismatch)?;
        if sys == 0
            || self.system_identifier.capacity() > 128
            || sys.to_string() != self.system_identifier
            || self.database_oid == 0
            || self.key_version != 1
            || self.source_device == 0
            || self.source_inode == 0
        {
            return Err(Fault::IntentMismatch);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
}
impl Identity {
    fn of(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct RecordIdentity {
    identity: Identity,
    mode: u32,
    links: u64,
    length: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl RecordIdentity {
    fn of(m: &Metadata) -> Self {
        Self {
            identity: Identity::of(m),
            mode: m.mode(),
            links: m.nlink(),
            length: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination {
    path: PathBuf,
    identity: Identity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestRecord {
    schema: String,
    version: u32,
    request_id: String,
    operation_id: String,
    bundle_id: String,
    owner_instance: String,
    owner_pid: u32,
    release_sha256: String,
    maintenance_sha256: String,
    profile_sha256: String,
    source_identity_sha256: String,
    intent_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentRecord {
    schema: String,
    version: u32,
    sequence: u32,
    stage: String,
    request_id: String,
    operation_id: String,
    bundle_id: String,
    owner_instance: String,
    owner_pid: u32,
    t0: u64,
    e: u64,
    c: u64,
    profile: CaptureProfile,
    release_sha256: String,
    maintenance_sha256: String,
    source_identity: ControlSourceIdentity,
    control: Destination,
    output: Destination,
    key_medium: Destination,
    temporary_basename: String,
    final_basename: String,
    key_basename: String,
}
#[derive(Serialize)]
struct IntentView<'a> {
    schema: &'static str,
    version: u32,
    sequence: u32,
    stage: &'static str,
    request_id: &'a str,
    operation_id: String,
    bundle_id: String,
    owner_instance: String,
    owner_pid: u32,
    t0: u64,
    e: u64,
    c: u64,
    profile: &'a CaptureProfile,
    release_sha256: String,
    maintenance_sha256: String,
    source_identity: &'a ControlSourceIdentity,
    control: Destination,
    output: Destination,
    key_medium: Destination,
    temporary_basename: String,
    final_basename: String,
    key_basename: String,
}
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlStage {
    NormalClosed,
    ConsumerConfirmed,
    SourceStarted,
    MaterialsFrozen,
    SourceClosed,
    KeyMediumVerified,
    TemporaryVerified,
    PublishedVerified,
    Closed,
    ClosingPending,
}
impl ControlStage {
    fn ordinal(self) -> u32 {
        match self {
            Self::NormalClosed => 1,
            Self::ConsumerConfirmed => 2,
            Self::SourceStarted => 3,
            Self::MaterialsFrozen => 4,
            Self::SourceClosed => 5,
            Self::KeyMediumVerified => 6,
            Self::TemporaryVerified => 7,
            Self::PublishedVerified => 8,
            Self::Closed => 9,
            Self::ClosingPending => 10,
        }
    }
    fn text(self) -> &'static str {
        match self {
            Self::NormalClosed => "normal_closed",
            Self::ConsumerConfirmed => "consumer_confirmed",
            Self::SourceStarted => "source_started",
            Self::MaterialsFrozen => "materials_frozen",
            Self::SourceClosed => "source_closed",
            Self::KeyMediumVerified => "key_medium_verified",
            Self::TemporaryVerified => "temporary_verified",
            Self::PublishedVerified => "published_verified",
            Self::Closed => "closed",
            Self::ClosingPending => "closing_pending",
        }
    }
}
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlOutcome {
    Actual,
    Late,
    Unknown,
}
/// Observations supplied by the original phase owners, never a permission or completion token.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlStageFacts {
    pub(crate) outcome: ControlOutcome,
    pub(crate) fault: Option<String>,
    pub(crate) issued_effects: u64,
    pub(crate) original_tasks: u64,
    pub(crate) joined_original_tasks: u64,
    pub(crate) live_proxy_futures: u64,
    pub(crate) parent_device: Option<u64>,
    pub(crate) parent_inode: Option<u64>,
    pub(crate) entry_device: Option<u64>,
    pub(crate) entry_inode: Option<u64>,
    pub(crate) output_bytes: Option<u64>,
    pub(crate) output_sha256: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageRecord {
    schema: String,
    version: u32,
    sequence: u32,
    stage: ControlStage,
    request_id: String,
    operation_id: String,
    bundle_id: String,
    intent_sha256: String,
    observed_monotonic_ns: u64,
    outcome: ControlOutcome,
    fault: Option<String>,
    issued_effects: u64,
    original_tasks: u64,
    joined_original_tasks: u64,
    live_proxy_futures: u64,
    parent_device: Option<u64>,
    parent_inode: Option<u64>,
    entry_device: Option<u64>,
    entry_inode: Option<u64>,
    output_bytes: Option<u64>,
    output_sha256: Option<String>,
}
pub(crate) struct CaptureIntentWitness {
    operation: [u8; 16],
    bundle: [u8; 16],
    intent_sha256: [u8; 32],
    canonical_intent: Vec<u8>,
    request_bytes: Vec<u8>,
    intent_identity: RecordIdentity,
    request_identity: RecordIdentity,
}
#[derive(Clone, Copy)]
struct Limits {
    record: u64,
    journal: u64,
    metadata: u64,
    records: u64,
    dirs: u64,
    files: u64,
    retained: u64,
    allocation: u64,
    reserve: u64,
    floor: u64,
    ordinary: OrdinaryAuditLimits,
    native: NativeHistoryLimits,
}
#[derive(Clone, Copy)]
struct OrdinaryAuditLimits {
    single: u64,
    plain: u64,
    spool: u64,
    material_files: u64,
    chunk: u64,
    path: u64,
    depth: u64,
    snapshot: u64,
}
#[derive(Clone, Copy)]
struct NativeHistoryLimits {
    single: u64,
    plain: u64,
    spool: u64,
    files: u64,
    dirs: u64,
    path: u64,
    depth: u64,
    fds: u64,
    wal: u64,
    wal_segments: u64,
    wal_span: u64,
    manifest: u64,
}
impl Limits {
    fn from_profile(p: &CaptureProfile) -> Result<Self, Fault> {
        p.validate().map_err(|_| Fault::ProfileInvalid)?;
        Ok(Self {
            record: p.native.max_control_bytes.min(p.carrier.max_metadata_bytes),
            journal: p.native.max_journal_bytes.min(p.carrier.max_journal_bytes),
            metadata: p.carrier.max_metadata_bytes,
            records: p.native.max_status_records,
            dirs: p.carrier.max_directories,
            files: p.carrier.max_open_files,
            retained: p.carrier.max_retained_prior_bytes,
            allocation: p.carrier.max_total_allocation_bytes,
            reserve: p
                .carrier
                .capacity_reserve_bytes
                .max(p.native.capacity_reserve_bytes),
            floor: p.carrier.free_floor_bytes.max(p.native.free_floor_bytes),
            ordinary: OrdinaryAuditLimits {
                single: p.carrier.max_single_plain_bytes,
                plain: p.carrier.max_material_plain_bytes,
                spool: p.carrier.max_spool_bytes,
                material_files: p.carrier.max_material_files,
                chunk: p.carrier.max_chunk_plain_bytes,
                path: p.carrier.max_path_bytes,
                depth: p.carrier.max_path_depth,
                snapshot: p.carrier.max_snapshot_bytes,
            },
            native: NativeHistoryLimits {
                single: p.native.max_single_file_bytes,
                plain: p.native.max_material_plain_bytes,
                spool: p.native.max_spool_bytes,
                files: p.native.max_material_files,
                dirs: p.native.max_directories,
                path: p.native.max_path_bytes,
                depth: p.native.max_depth,
                fds: p.native.max_open_files,
                wal: p.native.max_wal_bytes,
                wal_segments: p.native.max_wal_segments,
                wal_span: p.native.max_wal_span_bytes,
                manifest: p.native.max_backup_manifest_bytes,
            },
        })
    }
}
pub(crate) struct CaptureControlOwner {
    app: File,
    app_path: PathBuf,
    control: Option<File>,
    output: File,
    key: File,
    output_path: PathBuf,
    key_path: PathBuf,
    limits: Limits,
    request_id: String,
    operation_directory: Option<File>,
    operation_path: Option<PathBuf>,
    pending: Option<JoinHandle<JournalCompletion>>,
    retained: Vec<JournalRetained>,
    sequence: u32,
    journal_bytes: u64,
    history: History,
    resources: Arc<std::sync::Mutex<super::CaptureResourceTotals>>,
    poisoned: bool,
    begin_started: bool,
    consumer_started: bool,
    consumer_complete: bool,
}
#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct History {
    // These bytes/records are control-only; ordinary data is never journal/status credit.
    bytes: u64,
    ordinary_bytes: u64,
    ordinary_files: u64,
    ordinary_allocation: u64,
    allocation: u64,
    records: u64,
    dirs: u64,
    metadata: u64,
    native_bytes: u64,
    native_files: u64,
    native_dirs: u64,
    native_allocation: u64,
    native_wal_bytes: u64,
    native_wal_files: u64,
}
impl History {
    fn since(&self, base: &Self) -> Result<Self, Fault> {
        let sub = |a: u64, b: u64| a.checked_sub(b).ok_or(Fault::BoundsOverflow);
        Ok(Self {
            bytes: sub(self.bytes, base.bytes)?,
            ordinary_bytes: sub(self.ordinary_bytes, base.ordinary_bytes)?,
            ordinary_files: sub(self.ordinary_files, base.ordinary_files)?,
            ordinary_allocation: sub(self.ordinary_allocation, base.ordinary_allocation)?,
            allocation: sub(self.allocation, base.allocation)?,
            records: sub(self.records, base.records)?,
            dirs: sub(self.dirs, base.dirs)?,
            metadata: sub(self.metadata, base.metadata)?,
            native_bytes: sub(self.native_bytes, base.native_bytes)?,
            native_files: sub(self.native_files, base.native_files)?,
            native_dirs: sub(self.native_dirs, base.native_dirs)?,
            native_allocation: sub(self.native_allocation, base.native_allocation)?,
            native_wal_bytes: sub(self.native_wal_bytes, base.native_wal_bytes)?,
            native_wal_files: sub(self.native_wal_files, base.native_wal_files)?,
        })
    }

    fn retained_bytes(&self) -> Result<u64, Fault> {
        checked_add(self.bytes, self.ordinary_bytes)
    }
}
// Main needs the DATA return type; no fields or source handles are public.
pub(in crate::tauri_background) struct OriginalControlHistoryFootprint {
    observation: OriginalControlHistoryObservation,
    completed_request: Option<[u8; 64]>,
}
enum OriginalControlHistoryObservation {
    Unobserved,
    Absent { app: Identity },
    Present { app: Identity, root: RecordIdentity, blocks: u64, history: History },
}
impl OriginalControlHistoryFootprint {
    pub(in crate::tauri_background) fn unobserved() -> Self {
        Self { observation: OriginalControlHistoryObservation::Unobserved, completed_request: None }
    }
    pub(in crate::tauri_background) fn completed_request(&self, reviewed_request_id: &str) -> bool {
        match &self.completed_request {
            Some(id) => id.as_slice() == reviewed_request_id.as_bytes(),
            None => false,
        }
    }
}

// Concrete new DATA/return/lookup/observation slots, paid by the original book before
// its publication. Counts conservatively sum the named phases without stack reuse.
pub(super) fn original_control_data_fixed_bytes() -> Result<usize, Fault> {
    let slots = [
        (std::mem::size_of::<OriginalControlHistoryFootprint>(), std::mem::align_of::<OriginalControlHistoryFootprint>(), 3usize),
        (std::mem::size_of::<Result<OriginalControlHistoryFootprint, Fault>>(), std::mem::align_of::<Result<OriginalControlHistoryFootprint, Fault>>(), 2),
        (std::mem::size_of::<Option<OriginalControlHistoryFootprint>>(), std::mem::align_of::<Option<OriginalControlHistoryFootprint>>(), 1),
        // At most three original scans; lookup DATA is published only after full success.
        (std::mem::size_of::<Option<(&str, &mut bool)>>(), std::mem::align_of::<Option<(&str, &mut bool)>>(), 6),
        (std::mem::size_of::<Option<&(&str, &mut bool)>>(), std::mem::align_of::<Option<&(&str, &mut bool)>>(), 2),
        (std::mem::size_of::<Option<&str>>(), std::mem::align_of::<Option<&str>>(), 4),
        (std::mem::size_of::<Result<&str, Fault>>(), std::mem::align_of::<Result<&str, Fault>>(), 2),
        (std::mem::size_of::<&str>(), std::mem::align_of::<&str>(), 6),
        (std::mem::size_of::<&[u8]>(), std::mem::align_of::<&[u8]>(), 4),
        (std::mem::size_of::<bool>(), std::mem::align_of::<bool>(), 8),
        (std::mem::size_of::<[u8; 64]>(), std::mem::align_of::<[u8; 64]>(), 2),
        (std::mem::size_of::<Option<[u8; 64]>>(), std::mem::align_of::<Option<[u8; 64]>>(), 2),
        // Already-Closed startup moves only finite profile DATA into the original
        // sidecar's read-only classification await; no request/book is retained.
        (std::mem::size_of::<Option<CaptureProfile>>(), std::mem::align_of::<Option<CaptureProfile>>(), 2),
        (std::mem::size_of::<CaptureProfile>(), std::mem::align_of::<CaptureProfile>(), 1),
        (std::mem::size_of::<Option<ReviewedNormalCaptureRequest>>(), std::mem::align_of::<Option<ReviewedNormalCaptureRequest>>(), 1),
        (std::mem::size_of::<ReviewedNormalCaptureRequest>(), std::mem::align_of::<ReviewedNormalCaptureRequest>(), 1),
        (std::mem::size_of::<Option<&CaptureProfile>>(), std::mem::align_of::<Option<&CaptureProfile>>(), 2),
        (std::mem::size_of::<&CaptureProfile>(), std::mem::align_of::<&CaptureProfile>(), 2),
        (std::mem::size_of::<super::OriginalControlStorageFacts>(), std::mem::align_of::<super::OriginalControlStorageFacts>(), 2),
        (std::mem::size_of::<Result<super::OriginalControlStorageFacts, Fault>>(), std::mem::align_of::<Result<super::OriginalControlStorageFacts, Fault>>(), 1),
        // Six borrowed parameters plus their bounded reborrow/caller temporaries.
        (std::mem::size_of::<Option<&mut super::OriginalControlStorageFacts>>(), std::mem::align_of::<Option<&mut super::OriginalControlStorageFacts>>(), 12),
        (std::mem::size_of::<super::OriginalControlObjectFact>(), std::mem::align_of::<super::OriginalControlObjectFact>(), 4),
        (std::mem::size_of::<(&u64, &u64)>(), std::mem::align_of::<(&u64, &u64)>(), 3),
        (std::mem::size_of::<std::slice::Iter<'_, super::OriginalControlObjectFact>>(), std::mem::align_of::<std::slice::Iter<'_, super::OriginalControlObjectFact>>(), 3),
        (std::mem::size_of::<std::iter::Enumerate<std::slice::Iter<'_, super::OriginalControlObjectFact>>>(), std::mem::align_of::<std::iter::Enumerate<std::slice::Iter<'_, super::OriginalControlObjectFact>>>(), 1),
        (std::mem::size_of::<Option<&super::OriginalControlObjectFact>>(), std::mem::align_of::<Option<&super::OriginalControlObjectFact>>(), 2),
        (std::mem::size_of::<Option<(usize, &super::OriginalControlObjectFact)>>(), std::mem::align_of::<Option<(usize, &super::OriginalControlObjectFact)>>(), 1),
        (std::mem::size_of::<[Option<&File>; 4]>(), std::mem::align_of::<[Option<&File>; 4]>(), 1),
        (std::mem::size_of::<std::iter::Enumerate<std::array::IntoIter<Option<&File>, 4>>>(), std::mem::align_of::<std::iter::Enumerate<std::array::IntoIter<Option<&File>, 4>>>(), 1),
        (std::mem::size_of::<Option<(usize, Option<&File>)>>(), std::mem::align_of::<Option<(usize, Option<&File>)>>(), 1),
        (std::mem::size_of::<(usize, Option<&File>)>(), std::mem::align_of::<(usize, Option<&File>)>(), 1),
        (std::mem::size_of::<[Metadata; 3]>(), std::mem::align_of::<[Metadata; 3]>(), 1),
        (std::mem::size_of::<Option<[Metadata; 3]>>(), std::mem::align_of::<Option<[Metadata; 3]>>(), 1),
        (std::mem::size_of::<Metadata>(), std::mem::align_of::<Metadata>(), 16),
        (std::mem::size_of::<Result<Metadata, io::Error>>(), std::mem::align_of::<Result<Metadata, io::Error>>(), 16),
        (std::mem::size_of::<Option<Metadata>>(), std::mem::align_of::<Option<Metadata>>(), 1),
        (std::mem::size_of::<RecordIdentity>(), std::mem::align_of::<RecordIdentity>(), 8),
        (std::mem::size_of::<History>(), std::mem::align_of::<History>(), 3),
        (std::mem::size_of::<Result<History, Fault>>(), std::mem::align_of::<Result<History, Fault>>(), 2),
        (std::mem::size_of::<Result<(), Fault>>(), std::mem::align_of::<Result<(), Fault>>(), 8),
        (std::mem::size_of::<[&File; 3]>(), std::mem::align_of::<[&File; 3]>(), 1),
        (std::mem::size_of::<std::iter::Enumerate<std::array::IntoIter<&File, 3>>>(), std::mem::align_of::<std::iter::Enumerate<std::array::IntoIter<&File, 3>>>(), 1),
        (std::mem::size_of::<Option<(usize, &File)>>(), std::mem::align_of::<Option<(usize, &File)>>(), 1),
        (std::mem::size_of::<(usize, &File)>(), std::mem::align_of::<(usize, &File)>(), 1),
        (std::mem::size_of::<u64>(), std::mem::align_of::<u64>(), 12),
        (std::mem::size_of::<usize>(), std::mem::align_of::<usize>(), 6),
        (std::mem::size_of::<bool>(), std::mem::align_of::<bool>(), 6),
        (std::mem::size_of::<[super::OriginalControlRootObservation; 4]>(), std::mem::align_of::<[super::OriginalControlRootObservation; 4]>(), 2),
        (std::mem::size_of::<std::array::IntoIter<super::OriginalControlRootObservation, 4>>(), std::mem::align_of::<std::array::IntoIter<super::OriginalControlRootObservation, 4>>(), 1),
        (std::mem::size_of::<Option<super::OriginalControlRootObservation>>(), std::mem::align_of::<Option<super::OriginalControlRootObservation>>(), 1),
        (std::mem::size_of::<super::OriginalControlRootObservation>(), std::mem::align_of::<super::OriginalControlRootObservation>(), 2),
        (std::mem::size_of::<(usize, &super::OriginalControlObjectFact)>(), std::mem::align_of::<(usize, &super::OriginalControlObjectFact)>(), 1),
        (std::mem::size_of::<(u64, u64)>(), std::mem::align_of::<(u64, u64)>(), 1),
        // Three new pure caller paths each retain their own guard/LockResult and
        // invoke the original identity guard: no unrelated old guard is reused.
        (std::mem::size_of::<std::sync::MutexGuard<'_, super::CaptureResourceTotals>>(), std::mem::align_of::<std::sync::MutexGuard<'_, super::CaptureResourceTotals>>(), 6),
        (std::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'_, super::CaptureResourceTotals>>>(), std::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'_, super::CaptureResourceTotals>>>(), 6),
        (std::mem::size_of::<Result<[u8; 16], Fault>>(), std::mem::align_of::<Result<[u8; 16], Fault>>(), 3),
        (std::mem::size_of::<OriginalControlHistoryObservation>(), std::mem::align_of::<OriginalControlHistoryObservation>(), 2),
        (std::mem::size_of::<Option<History>>(), std::mem::align_of::<Option<History>>(), 2),
        // Original retained backing is paid before startup allocates it. Each entry
        // is one shared Work plus its real native-result/launch-panic slots.
        (std::mem::size_of::<JournalRetained>(), std::mem::align_of::<JournalRetained>(), MAX_JOURNAL_JOBS),
        (std::mem::size_of::<Vec<JournalRetained>>(), std::mem::align_of::<Vec<JournalRetained>>(), 1),
        // Account for these two new concrete entries in this existing fixed table too.
        (std::mem::size_of::<(usize, usize, usize)>(), std::mem::align_of::<(usize, usize, usize)>(), 3),
        // One extra original ControlOwner Arc word, not a second Arc allocation.
        (std::mem::size_of::<Arc<std::sync::Mutex<super::CaptureResourceTotals>>>(), std::mem::align_of::<Arc<std::sync::Mutex<super::CaptureResourceTotals>>>(), 1),
    ];
    slots.into_iter().try_fold(0usize, |total, (size, align, count)| {
        let amount = size.checked_add(align - 1).and_then(|n| n.checked_mul(count))
            .ok_or(Fault::BoundsOverflow)?;
        total.checked_add(amount).ok_or(Fault::BoundsOverflow)
    })
}

// One conservative typed-slot envelope for either FS01 method and its pure book helper.
// It is requested Rust DATA, not a kernel allocation theorem or a second resource book.
const ORIGINAL_CONTROL_ALLOCATION_METADATA: u64 = {
    let slots = [
        (core::mem::size_of::<Option<Result<u64, Fault>>>(), core::mem::align_of::<Option<Result<u64, Fault>>>(), 3usize),
        (core::mem::size_of::<Result<u64, Fault>>(), core::mem::align_of::<Result<u64, Fault>>(), 3usize),
        (core::mem::size_of::<[Option<io::Result<Metadata>>;2]>(), core::mem::align_of::<[Option<io::Result<Metadata>>;2]>(), 2usize),
        (core::mem::size_of::<io::Result<Metadata>>(), core::mem::align_of::<io::Result<Metadata>>(), 4usize),
        (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 4usize),
        (core::mem::size_of::<rustix::io::Result<rustix::fs::StatVfs>>(), core::mem::align_of::<rustix::io::Result<rustix::fs::StatVfs>>(), 2usize),
        (core::mem::size_of::<Option<&mut Option<Result<u64, Fault>>>>(), core::mem::align_of::<Option<&mut Option<Result<u64, Fault>>>>(), 4usize),
        (core::mem::size_of::<Option<&mut [Option<io::Result<Metadata>>;2]>>(), core::mem::align_of::<Option<&mut [Option<io::Result<Metadata>>;2]>>(), 4usize),
        (core::mem::size_of::<&mut Option<Result<u64, Fault>>>(), core::mem::align_of::<&mut Option<Result<u64, Fault>>>(), 4usize),
        (core::mem::size_of::<&mut [Option<io::Result<Metadata>>;2]>(), core::mem::align_of::<&mut [Option<io::Result<Metadata>>;2]>(), 4usize),
        (core::mem::size_of::<&Metadata>(), core::mem::align_of::<&Metadata>(), 4usize),
        (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 6usize),
        (core::mem::size_of::<&CaptureOperation>(), core::mem::align_of::<&CaptureOperation>(), 2usize),
        (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 3usize),
        (core::mem::size_of::<[(u64,u64,u64);2]>(), core::mem::align_of::<[(u64,u64,u64);2]>(), 4usize),
        (core::mem::size_of::<std::array::IntoIter<(u64,u64,u64),2>>(), core::mem::align_of::<std::array::IntoIter<(u64,u64,u64),2>>(), 2usize),
        (core::mem::size_of::<(u64,u64,u64)>(), core::mem::align_of::<(u64,u64,u64)>(), 4usize),
        (core::mem::size_of::<std::slice::Iter<'static, super::OriginalControlObjectFact>>(), core::mem::align_of::<std::slice::Iter<'static, super::OriginalControlObjectFact>>(), 6usize),
        (core::mem::size_of::<std::slice::IterMut<'static, super::OriginalControlObjectFact>>(), core::mem::align_of::<std::slice::IterMut<'static, super::OriginalControlObjectFact>>(), 2usize),
        (core::mem::size_of::<std::slice::Iter<'static, (u64,u64,u64)>>(), core::mem::align_of::<std::slice::Iter<'static, (u64,u64,u64)>>(), 4usize),
        (core::mem::size_of::<Option<&super::OriginalControlObjectFact>>(), core::mem::align_of::<Option<&super::OriginalControlObjectFact>>(), 4usize),
        (core::mem::size_of::<Option<&mut super::OriginalControlObjectFact>>(), core::mem::align_of::<Option<&mut super::OriginalControlObjectFact>>(), 2usize),
        (core::mem::size_of::<Option<&(u64,u64,u64)>>(), core::mem::align_of::<Option<&(u64,u64,u64)>>(), 4usize),
        (core::mem::size_of::<super::OriginalControlObjectFact>(), core::mem::align_of::<super::OriginalControlObjectFact>(), 2usize),
        (core::mem::size_of::<std::sync::MutexGuard<'static, super::CaptureResourceTotals>>(), core::mem::align_of::<std::sync::MutexGuard<'static, super::CaptureResourceTotals>>(), 3usize),
        (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, super::CaptureResourceTotals>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, super::CaptureResourceTotals>>>(), 3usize),
        (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 12usize),
        (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 24usize),
        (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 12usize),
        (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 8usize),
    ];
    let mut index = 0usize;
    let mut bytes = 0usize;
    while index < slots.len() {
        let one = slots[index].0.checked_add(slots[index].1)
            .expect("fixed allocation slot layout fits usize");
        let amount = one.checked_mul(slots[index].2)
            .expect("fixed allocation slot count fits usize");
        bytes = bytes.checked_add(amount).expect("fixed allocation slots fit usize");
        index += 1;
    }
    assert!(usize::BITS <= u64::BITS);
    bytes as u64
};

struct JournalWork {
    app: Option<File>,
    control: Option<File>,
    requests: Option<File>,
    operations: Option<File>,
    operation_directory: Option<File>,
    files: Vec<File>,
    // Separate from the two original writer FDs and canonical record bodies.
    record_files: Vec<File>,
    record_bytes: Vec<u8>,
    record_results: [Option<Result<(usize, Vec<u8>), Fault>>; 4],
    destination_identities: [Option<Identity>; 2],
    operation_path: Option<PathBuf>,
    clone_error: Option<io::Error>,
    operation_name: String,
    first: bool,
    name: String,
    bytes: Vec<u8>,
    request_name: String,
    request_bytes: Vec<u8>,
    clock: Arc<CaptureOperation>,
    limit: u64,
    reserve: u64,
    floor: u64,
    allocation: u64,
    intent_identity: Option<RecordIdentity>,
    request_identity: Option<RecordIdentity>,
    returned: Option<Result<(), Fault>>,
    panic: Option<Box<dyn std::any::Any + Send + 'static>>,
    history_output: Option<File>,
    history_key: Option<File>,
    history_dir: Option<rustix::fs::Dir>,
    history_frames: Vec<ClosedNativeFrame>,
    history_matched: Vec<u8>,
    history_io: Option<JournalHistoryIoResult>,
    history_result: Option<Result<JournalHistoryFact, Fault>>,
    fs_admission: Option<Result<u64, Fault>>,
    fs_observations: [Option<io::Result<Metadata>>; 2],
}
struct JournalCompletion {
    result: Result<(), Fault>,
}
type JournalJoin = Result<JournalCompletion, tokio::task::JoinError>;
// The original owner always holds the first Arc. Native join/launch-panic results
// stay outside the work mutex, including while a worker may still be active.
type JournalRetained = (
    Arc<std::sync::Mutex<JournalWork>>,
    Option<JournalJoin>,
    Option<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>,
);

// This is a pure preflight value query for the original seven-stage tail.
// Original producers retain their exact admission expressions and positions.
// Only named requested bytes/typed slots are covered; allocator, formatting,
// serializer, Tokio and physical/secret peaks remain separate unproved inputs.
pub(in crate::tauri_background::capture) fn original_remaining_stage_known_tail(
    record_limit: u64,
) -> Result<u64, Fault> {
    const APPEND: u64 = {
        let slots = [
            (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 2usize),
            (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 2usize),
            (core::mem::size_of::<Result<usize, Fault>>(), core::mem::align_of::<Result<usize, Fault>>(), 1usize),
            (core::mem::size_of::<Result<&'static JournalRetained, Fault>>(), core::mem::align_of::<Result<&'static JournalRetained, Fault>>(), 2usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 1usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 5usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            let one = slots[at].0.checked_add(slots[at].1)
                .expect("fixed journal slot layout fits usize");
            let amount = one.checked_mul(slots[at].2)
                .expect("fixed journal slot count fits usize");
            bytes = bytes.checked_add(amount)
                .expect("fixed journal slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const JOB_FIXED: u64 = {
        let slots = [
            (core::mem::size_of::<Option<File>>(), core::mem::align_of::<Option<File>>(), 2usize),
            (core::mem::size_of::<Option<rustix::fs::Dir>>(), core::mem::align_of::<Option<rustix::fs::Dir>>(), 1usize),
            (core::mem::size_of::<Vec<ClosedNativeFrame>>(), core::mem::align_of::<Vec<ClosedNativeFrame>>(), 1usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 1usize),
            (core::mem::size_of::<Option<JournalHistoryIoResult>>(), core::mem::align_of::<Option<JournalHistoryIoResult>>(), 1usize),
            (core::mem::size_of::<Option<Result<JournalHistoryFact, Fault>>>(), core::mem::align_of::<Option<Result<JournalHistoryFact, Fault>>>(), 1usize),
            (core::mem::size_of::<Option<Result<u64, Fault>>>(), core::mem::align_of::<Option<Result<u64, Fault>>>(), 1usize),
            (core::mem::size_of::<[Option<io::Result<Metadata>>;2]>(), core::mem::align_of::<[Option<io::Result<Metadata>>;2]>(), 1usize),
            (core::mem::size_of::<Option<&mut Option<Result<u64, Fault>>>>(), core::mem::align_of::<Option<&mut Option<Result<u64, Fault>>>>(), 3usize),
            (core::mem::size_of::<Option<&mut [Option<io::Result<Metadata>>;2]>>(), core::mem::align_of::<Option<&mut [Option<io::Result<Metadata>>;2]>>(), 3usize),
            // Empty constructor headers/array are distinct from Work's own
            // enlarged value and Arc allocation below. No backing exists yet.
            (core::mem::size_of::<Vec<File>>(), core::mem::align_of::<Vec<File>>(), 1usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 1usize),
            (core::mem::size_of::<[Option<Identity>; 2]>(), core::mem::align_of::<[Option<Identity>; 2]>(), 1usize),
            (core::mem::size_of::<Option<Identity>>(), core::mem::align_of::<Option<Identity>>(), 2usize),
            (core::mem::size_of::<Option<PathBuf>>(), core::mem::align_of::<Option<PathBuf>>(), 1usize),
            (core::mem::size_of::<Option<io::Error>>(), core::mem::align_of::<Option<io::Error>>(), 1usize),
            (core::mem::size_of::<[Option<Result<(usize, Vec<u8>), Fault>>; 4]>(), core::mem::align_of::<[Option<Result<(usize, Vec<u8>), Fault>>; 4]>(), 1usize),
            (core::mem::size_of::<Option<Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<Option<Result<(usize, Vec<u8>), Fault>>>(), 4usize),
            // At most three runtime views are constructed by write_intent
            // (two writers, then confirm); each construction's field borrows
            // and the view value are paid without assuming slot elision.
            (core::mem::size_of::<HistoryIo<'static>>(), core::mem::align_of::<HistoryIo<'static>>(), 3usize),
            (core::mem::size_of::<Option<(&CaptureOperation, bool)>>(), core::mem::align_of::<Option<(&CaptureOperation, bool)>>(), 3usize),
            (core::mem::size_of::<&mut Vec<File>>(), core::mem::align_of::<&mut Vec<File>>(), 3usize),
            (core::mem::size_of::<&mut Option<rustix::fs::Dir>>(), core::mem::align_of::<&mut Option<rustix::fs::Dir>>(), 3usize),
            (core::mem::size_of::<&mut Vec<ClosedNativeFrame>>(), core::mem::align_of::<&mut Vec<ClosedNativeFrame>>(), 3usize),
            (core::mem::size_of::<&mut Vec<u8>>(), core::mem::align_of::<&mut Vec<u8>>(), 6usize),
            (core::mem::size_of::<&mut Option<JournalHistoryIoResult>>(), core::mem::align_of::<&mut Option<JournalHistoryIoResult>>(), 3usize),
            (core::mem::size_of::<&mut Option<Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<&mut Option<Result<(usize, Vec<u8>), Fault>>>(), 4usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 4usize),
            (core::mem::size_of::<JournalWork>(), core::mem::align_of::<JournalWork>(), 1usize),
            (core::mem::size_of::<Arc<std::sync::Mutex<JournalWork>>>(), core::mem::align_of::<Arc<std::sync::Mutex<JournalWork>>>(), 2usize),
            (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 1usize),
            (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 1usize),
            (core::mem::size_of::<Vec<File>>(), core::mem::align_of::<Vec<File>>(), 1usize),
            (core::mem::size_of::<String>(), core::mem::align_of::<String>(), 2usize),
            (core::mem::size_of::<Arc<CaptureOperation>>(), core::mem::align_of::<Arc<CaptureOperation>>(), 1usize),
            (core::mem::size_of::<Result<(), std::collections::TryReserveError>>(), core::mem::align_of::<Result<(), std::collections::TryReserveError>>(), 3usize),
            (core::mem::size_of::<Result<usize, Fault>>(), core::mem::align_of::<Result<usize, Fault>>(), 2usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            (core::mem::size_of::<Option<u64>>(), core::mem::align_of::<Option<u64>>(), 3usize),
            (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 4usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 3usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 3usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            let one = slots[at].0.checked_add(slots[at].1)
                .expect("fixed journal slot layout fits usize");
            let amount = one.checked_mul(slots[at].2)
                .expect("fixed journal slot count fits usize");
            bytes = bytes.checked_add(amount)
                .expect("fixed journal slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const WORK_ALLOCATION: u64 = {
        let layout = match std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<std::sync::Mutex<JournalWork>>())
        {
            Ok((layout, _)) => layout.pad_to_align(),
            Err(_) => panic!("fixed journal Arc layout is valid"),
        };
        assert!(usize::BITS <= u64::BITS);
        layout.size() as u64
    };
    const CLONE_FIXED: u64 = {
        let slots = [
            (core::mem::size_of::<io::Result<File>>(), core::mem::align_of::<io::Result<File>>(), 1usize),
            (core::mem::size_of::<Option<io::Error>>(), core::mem::align_of::<Option<io::Error>>(), 1usize),
            (core::mem::size_of::<io::Error>(), core::mem::align_of::<io::Error>(), 1usize),
            (core::mem::size_of::<Option<io::Error>>(), core::mem::align_of::<Option<io::Error>>(), 1usize),
            (core::mem::size_of::<Option<&mut Option<io::Error>>>(), core::mem::align_of::<Option<&mut Option<io::Error>>>(), 4usize),
            (core::mem::size_of::<Option<&&mut Option<io::Error>>>(), core::mem::align_of::<Option<&&mut Option<io::Error>>>(), 2usize),
            (core::mem::size_of::<Option<&io::Error>>(), core::mem::align_of::<Option<&io::Error>>(), 2usize),
            (core::mem::size_of::<&io::Error>(), core::mem::align_of::<&io::Error>(), 2usize),
            (core::mem::size_of::<File>(), core::mem::align_of::<File>(), 1usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 1usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            let one = slots[at].0.checked_add(slots[at].1)
                .expect("fixed journal slot layout fits usize");
            let amount = one.checked_mul(slots[at].2)
                .expect("fixed journal slot count fits usize");
            bytes = bytes.checked_add(amount)
                .expect("fixed journal slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const START_FIXED: u64 = {
        let slots = [
            (core::mem::size_of::<Arc<std::sync::Mutex<JournalWork>>>(), core::mem::align_of::<Arc<std::sync::Mutex<JournalWork>>>(), 3usize),
            (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 2usize),
            (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 2usize),
            (core::mem::size_of::<Result<JoinHandle<JournalCompletion>, Box<dyn std::any::Any + Send + 'static>>>(), core::mem::align_of::<Result<JoinHandle<JournalCompletion>, Box<dyn std::any::Any + Send + 'static>>>(), 1usize),
            (core::mem::size_of::<Result<Result<(), Fault>, Box<dyn std::any::Any + Send + 'static>>>(), core::mem::align_of::<Result<Result<(), Fault>, Box<dyn std::any::Any + Send + 'static>>>(), 1usize),
            (core::mem::size_of::<JournalCompletion>(), core::mem::align_of::<JournalCompletion>(), 1usize),
            (core::mem::size_of::<Option<JournalJoin>>(), core::mem::align_of::<Option<JournalJoin>>(), 1usize),
            (core::mem::size_of::<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>(), core::mem::align_of::<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>(), 1usize),
            (core::mem::size_of::<Option<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>>(), core::mem::align_of::<Option<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>>(), 1usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 6usize),
            (core::mem::size_of::<&'static mut JournalWork>(), core::mem::align_of::<&'static mut JournalWork>(), 1usize),
            (core::mem::size_of::<&'static Arc<CaptureOperation>>(), core::mem::align_of::<&'static Arc<CaptureOperation>>(), 1usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 2usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 3usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            let one = slots[at].0.checked_add(slots[at].1)
                .expect("fixed journal slot layout fits usize");
            let amount = one.checked_mul(slots[at].2)
                .expect("fixed journal slot count fits usize");
            bytes = bytes.checked_add(amount)
                .expect("fixed journal slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const WAIT_FIXED: u64 = {
        let slots = [
            (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 1usize),
            (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 1usize),
            (core::mem::size_of::<JournalJoin>(), core::mem::align_of::<JournalJoin>(), 1usize),
            (core::mem::size_of::<Result<JournalJoin, tokio::time::error::Elapsed>>(), core::mem::align_of::<Result<JournalJoin, tokio::time::error::Elapsed>>(), 1usize),
            (core::mem::size_of::<tokio::time::Timeout<&'static mut JoinHandle<JournalCompletion>>>(), core::mem::align_of::<tokio::time::Timeout<&'static mut JoinHandle<JournalCompletion>>>(), 1usize),
            (core::mem::size_of::<Option<JoinHandle<JournalCompletion>>>(), core::mem::align_of::<Option<JoinHandle<JournalCompletion>>>(), 1usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 5usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 1usize),
            (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 1usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            let one = slots[at].0.checked_add(slots[at].1)
                .expect("fixed journal slot layout fits usize");
            let amount = one.checked_mul(slots[at].2)
                .expect("fixed journal slot count fits usize");
            bytes = bytes.checked_add(amount)
                .expect("fixed journal slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const PLACE_FIXED: u64 = {
        let slots = [
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 6usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<&CaptureOperation>(), core::mem::align_of::<&CaptureOperation>(), 2usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 3usize),
            (core::mem::size_of::<Option<&File>>(), core::mem::align_of::<Option<&File>>(), 2usize),
            (core::mem::size_of::<&str>(), core::mem::align_of::<&str>(), 2usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 2usize),
            (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 2usize),
            (core::mem::size_of::<RecordIdentity>(), core::mem::align_of::<RecordIdentity>(), 2usize),
            (core::mem::size_of::<(u64, u64, u32)>(), core::mem::align_of::<(u64, u64, u32)>(), 2usize),
            (core::mem::size_of::<rustix::fs::Stat>(), core::mem::align_of::<rustix::fs::Stat>(), 2usize),
            (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 2usize),
            (core::mem::size_of::<Option<&JournalHistoryIoResult>>(), core::mem::align_of::<Option<&JournalHistoryIoResult>>(), 2usize),
            (core::mem::size_of::<Fault>(), core::mem::align_of::<Fault>(), 2usize),
            (core::mem::size_of::<DirectoryMode>(), core::mem::align_of::<DirectoryMode>(), 2usize),
            (core::mem::size_of::<OFlags>(), core::mem::align_of::<OFlags>(), 2usize),
            (core::mem::size_of::<Mode>(), core::mem::align_of::<Mode>(), 2usize),
            (core::mem::size_of::<File>(), core::mem::align_of::<File>(), 2usize),
            (core::mem::size_of::<Option<File>>(), core::mem::align_of::<Option<File>>(), 2usize),
            (core::mem::size_of::<rustix::fd::OwnedFd>(), core::mem::align_of::<rustix::fd::OwnedFd>(), 2usize),
            (core::mem::size_of::<rustix::io::Errno>(), core::mem::align_of::<rustix::io::Errno>(), 2usize),
            (core::mem::size_of::<&mut Option<File>>(), core::mem::align_of::<&mut Option<File>>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed helper layout fits usize").checked_mul(slots[at].2)
                .expect("fixed helper count fits usize"))
                .expect("fixed helper slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const VERIFY_FIXED: u64 = {
        let slots = [
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 6usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<&CaptureOperation>(), core::mem::align_of::<&CaptureOperation>(), 2usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 3usize),
            (core::mem::size_of::<Option<&File>>(), core::mem::align_of::<Option<&File>>(), 2usize),
            (core::mem::size_of::<&str>(), core::mem::align_of::<&str>(), 2usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 2usize),
            (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 2usize),
            (core::mem::size_of::<RecordIdentity>(), core::mem::align_of::<RecordIdentity>(), 2usize),
            (core::mem::size_of::<(u64, u64, u32)>(), core::mem::align_of::<(u64, u64, u32)>(), 2usize),
            (core::mem::size_of::<rustix::fs::Stat>(), core::mem::align_of::<rustix::fs::Stat>(), 2usize),
            (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 2usize),
            (core::mem::size_of::<Option<&JournalHistoryIoResult>>(), core::mem::align_of::<Option<&JournalHistoryIoResult>>(), 2usize),
            (core::mem::size_of::<Fault>(), core::mem::align_of::<Fault>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed helper layout fits usize").checked_mul(slots[at].2)
                .expect("fixed helper count fits usize"))
                .expect("fixed helper slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const CREATE_FIXED: u64 = {
        let statvfs = core::mem::size_of::<rustix::io::Result<rustix::fs::StatVfs>>()
            .checked_add(core::mem::align_of::<rustix::io::Result<rustix::fs::StatVfs>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let open = core::mem::size_of::<rustix::io::Result<rustix::fd::OwnedFd>>()
            .checked_add(core::mem::align_of::<rustix::io::Result<rustix::fd::OwnedFd>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let open_error = core::mem::size_of::<Option<rustix::io::Errno>>()
            .checked_add(core::mem::align_of::<Option<rustix::io::Errno>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let errno_transfer = core::mem::size_of::<rustix::io::Errno>()
            .checked_add(core::mem::align_of::<rustix::io::Errno>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let fd_transfer = core::mem::size_of::<rustix::fd::OwnedFd>()
            .checked_add(core::mem::align_of::<rustix::fd::OwnedFd>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let metadata = core::mem::size_of::<io::Result<Metadata>>()
            .checked_add(core::mem::align_of::<io::Result<Metadata>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(3)
            .expect("fixed control IO slot count fits usize");
        let write = core::mem::size_of::<io::Result<usize>>()
            .checked_add(core::mem::align_of::<io::Result<usize>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let fsync = core::mem::size_of::<io::Result<()>>()
            .checked_add(core::mem::align_of::<io::Result<()>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(2)
            .expect("fixed control IO slot count fits usize");
        let clock_or_admission = core::mem::size_of::<Result<(), Fault>>()
            .checked_add(core::mem::align_of::<Result<(), Fault>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(10)
            .expect("fixed control IO slot count fits usize");
        let bytes = statvfs
            .checked_add(open)
            .expect("fixed control IO slots fit usize")
            .checked_add(open_error)
            .expect("fixed control IO slots fit usize")
            .checked_add(errno_transfer)
            .expect("fixed control IO slots fit usize")
            .checked_add(fd_transfer)
            .expect("fixed control IO slots fit usize")
            .checked_add(metadata)
            .expect("fixed control IO slots fit usize")
            .checked_add(write)
            .expect("fixed control IO slots fit usize")
            .checked_add(fsync)
            .expect("fixed control IO slots fit usize")
            .checked_add(clock_or_admission)
            .expect("fixed control IO slots fit usize");
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const CORE_TRANSFERS: u64 = {
        let slots = [
            (core::mem::size_of::<(usize, usize)>(), core::mem::align_of::<(usize, usize)>(), 3usize),
            (core::mem::size_of::<Result<(usize, usize), Fault>>(), core::mem::align_of::<Result<(usize, usize), Fault>>(), 3usize),
            (core::mem::size_of::<Result<Vec<u8>, Fault>>(), core::mem::align_of::<Result<Vec<u8>, Fault>>(), 2usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 2usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<Option<&mut super::OriginalControlStorageFacts>>(), core::mem::align_of::<Option<&mut super::OriginalControlStorageFacts>>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed record core layout fits usize").checked_mul(slots[at].2)
                .expect("fixed record core count fits usize"))
                .expect("fixed record core transfers fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const RESULT_TRANSFERS: u64 = {
        let slots = [
            (core::mem::size_of::<Result<(usize, usize), Fault>>(), core::mem::align_of::<Result<(usize, usize), Fault>>(), 2usize),
            (core::mem::size_of::<(usize, usize)>(), core::mem::align_of::<(usize, usize)>(), 2usize),
            (core::mem::size_of::<(usize, Vec<u8>)>(), core::mem::align_of::<(usize, Vec<u8>)>(), 3usize),
            (core::mem::size_of::<Result<(usize, Vec<u8>), Fault>>(), core::mem::align_of::<Result<(usize, Vec<u8>), Fault>>(), 3usize),
            (core::mem::size_of::<Option<Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<Option<Result<(usize, Vec<u8>), Fault>>>(), 2usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 3usize),
            (core::mem::size_of::<Option<&Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<Option<&Result<(usize, Vec<u8>), Fault>>>(), 2usize),
            (core::mem::size_of::<&Vec<u8>>(), core::mem::align_of::<&Vec<u8>>(), 2usize),
            (core::mem::size_of::<&Fault>(), core::mem::align_of::<&Fault>(), 2usize),
            (core::mem::size_of::<Fault>(), core::mem::align_of::<Fault>(), 2usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<&mut Option<Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<&mut Option<Result<(usize, Vec<u8>), Fault>>>(), 2usize),
            (core::mem::size_of::<Option<RecordIdentity>>(), core::mem::align_of::<Option<RecordIdentity>>(), 2usize),
            (core::mem::size_of::<RecordIdentity>(), core::mem::align_of::<RecordIdentity>(), 2usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 2usize),
            (core::mem::size_of::<&str>(), core::mem::align_of::<&str>(), 2usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 5usize),
            (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed record result layout fits usize").checked_mul(slots[at].2)
                .expect("fixed record result count fits usize"))
                .expect("fixed record result transfers fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const ADMIT_FIXED: u64 = {
        let slots = [
            (core::mem::size_of::<Result<(), std::collections::TryReserveError>>(), core::mem::align_of::<Result<(), std::collections::TryReserveError>>(), 2usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 2usize),
            (core::mem::size_of::<Vec<String>>(), core::mem::align_of::<Vec<String>>(), 1usize),
            (core::mem::size_of::<String>(), core::mem::align_of::<String>(), 2usize),
            (core::mem::size_of::<ClosedNativeFrame>(), core::mem::align_of::<ClosedNativeFrame>(), 1usize),
            (core::mem::size_of::<Option<File>>(), core::mem::align_of::<Option<File>>(), 1usize),
            (core::mem::size_of::<Option<ClosedNativeFrame>>(), core::mem::align_of::<Option<ClosedNativeFrame>>(), 1usize),
            (core::mem::size_of::<Option<rustix::fs::Dir>>(), core::mem::align_of::<Option<rustix::fs::Dir>>(), 1usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 3usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 3usize),
            (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 2usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 1usize),
            (core::mem::size_of::<&str>(), core::mem::align_of::<&str>(), 2usize),
        ];
        let mut at = 0usize;
        let mut n = 0usize;
        while at < slots.len() {
            n = n.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed history allocation layout fits usize").checked_mul(slots[at].2)
                .expect("fixed history allocation count fits usize"))
                .expect("fixed history allocation slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        n as u64
    };
    let io_once = {
        let slots = [
            // Actual return, enum construction, Option transfer and match return
            // are separate slots; no return-place optimization is assumed.
            (core::mem::size_of::<JournalHistoryIoResult>(), core::mem::align_of::<JournalHistoryIoResult>(), 3usize),
            (core::mem::size_of::<Option<JournalHistoryIoResult>>(), core::mem::align_of::<Option<JournalHistoryIoResult>>(), 2usize),
            (core::mem::size_of::<rustix::io::Result<rustix::fs::StatVfs>>(), core::mem::align_of::<rustix::io::Result<rustix::fs::StatVfs>>(), 1usize),
            (core::mem::size_of::<io::Result<usize>>(), core::mem::align_of::<io::Result<usize>>(), 1usize),
            (core::mem::size_of::<io::Result<()>>(), core::mem::align_of::<io::Result<()>>(), 1usize),
            (core::mem::size_of::<rustix::io::Result<()>>(), core::mem::align_of::<rustix::io::Result<()>>(), 1usize),
            (core::mem::size_of::<rustix::io::Result<std::ffi::CString>>(), core::mem::align_of::<rustix::io::Result<std::ffi::CString>>(), 1usize),
            (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 2usize),
            (core::mem::size_of::<Result<Metadata, Fault>>(), core::mem::align_of::<Result<Metadata, Fault>>(), 2usize),
            (core::mem::size_of::<Result<rustix::fs::Stat, Fault>>(), core::mem::align_of::<Result<rustix::fs::Stat, Fault>>(), 2usize),
            (core::mem::size_of::<rustix::fd::OwnedFd>(), core::mem::align_of::<rustix::fd::OwnedFd>(), 1usize),
            (core::mem::size_of::<File>(), core::mem::align_of::<File>(), 1usize),
            (core::mem::size_of::<HistoryFd<'static>>(), core::mem::align_of::<HistoryFd<'static>>(), 3usize),
            (core::mem::size_of::<Result<HistoryFd<'static>, Fault>>(), core::mem::align_of::<Result<HistoryFd<'static>, Fault>>(), 2usize),
            (core::mem::size_of::<(HistoryFd<'static>, RecordIdentity, u64)>(), core::mem::align_of::<(HistoryFd<'static>, RecordIdentity, u64)>(), 1usize),
            (core::mem::size_of::<Result<(HistoryFd<'static>, RecordIdentity, u64), Fault>>(), core::mem::align_of::<Result<(HistoryFd<'static>, RecordIdentity, u64), Fault>>(), 1usize),
            (core::mem::size_of::<Result<Option<Vec<u8>>, Fault>>(), core::mem::align_of::<Result<Option<Vec<u8>>, Fault>>(), 1usize),
            (core::mem::size_of::<Result<usize, Fault>>(), core::mem::align_of::<Result<usize, Fault>>(), 2usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 1usize),
            (core::mem::size_of::<Result<(), std::collections::TryReserveError>>(), core::mem::align_of::<Result<(), std::collections::TryReserveError>>(), 2usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 6usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 2usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 4usize),
            (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 2usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 2usize),
        ];
        // Conservatively include the constructed fixed array, its by-value
        // iterator payload and current tuple rather than assuming elision.
        let mut known = core::mem::size_of_val(&slots).checked_mul(2)
            .and_then(|n| n.checked_add(core::mem::size_of::<(usize, usize, usize)>().checked_mul(2)?))
            .and_then(|n| n.checked_add(core::mem::size_of::<usize>().checked_mul(4)?))
            .ok_or(Fault::BoundsOverflow)?;
        for (size, align, count) in slots {
            known = known.checked_add(size.checked_add(align).and_then(|n| n.checked_mul(count))
                .ok_or(Fault::BoundsOverflow)?).ok_or(Fault::BoundsOverflow)?;
        }
        u64::try_from(known).map_err(|_| Fault::BoundsOverflow)?
    };
    let h = checked_add(io_once, ADMIT_FIXED)?;
    // Same nominal closure type is used by append and this size-only query.
    let body = original_stage_body(false);
    let body_slots = core::mem::size_of_val(&body)
        .checked_add(core::mem::align_of_val(&body))
        .and_then(|n| n.checked_mul(2)).ok_or(Fault::BoundsOverflow)?;
    let t = checked_add(START_FIXED,
        u64::try_from(body_slots).map_err(|_| Fault::BoundsOverflow)?)?;
    let j = checked_add(JOB_FIXED, checked_add(WORK_ALLOCATION,
        checked_add(128, checked_add(64 + 5,
            (2 * core::mem::size_of::<File>()) as u64)?)?)?)?;
    // Every positive short write/read advances >=1 byte: w,r <= L <= R.
    // Do not replace this with ceil(R/65536) or one observed whole transfer.
    let io_count = record_limit.checked_mul(2)
        .and_then(|n| n.checked_add(27)).ok_or(Fault::BoundsOverflow)?;
    let mut stage = 0u64;
    for value in [
        APPEND, j, CLONE_FIXED.checked_mul(3).ok_or(Fault::BoundsOverflow)?,
        t, WAIT_FIXED, PLACE_FIXED,
        VERIFY_FIXED.checked_mul(7).ok_or(Fault::BoundsOverflow)?,
        CREATE_FIXED, CORE_TRANSFERS, RESULT_TRANSFERS,
        ADMIT_FIXED.checked_mul(5).ok_or(Fault::BoundsOverflow)?,
        (4 * core::mem::size_of::<File>()) as u64,
        record_limit.checked_mul(2).and_then(|n| n.checked_add(1))
            .ok_or(Fault::BoundsOverflow)?,
        io_count.checked_mul(h).ok_or(Fault::BoundsOverflow)?,
    ] {
        stage = checked_add(stage, value)?;
    }
    let growth_calls = record_limit.checked_add(3).ok_or(Fault::BoundsOverflow)?;
    let one_growth = ORIGINAL_CONTROL_ALLOCATION_METADATA.checked_add(ADMIT_FIXED)
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(h.checked_mul(4)?)).ok_or(Fault::BoundsOverflow)?;
    stage = checked_add(stage, growth_calls.checked_mul(one_growth).ok_or(Fault::BoundsOverflow)?)?;
    let seven_stages = stage.checked_mul(7).ok_or(Fault::BoundsOverflow)?;
    // Source-control readback has paid 2R+1 above. Original encode's one
    // separately requested backing R is not the same allocation.
    let encoded = record_limit.checked_mul(7).ok_or(Fault::BoundsOverflow)?;

    // Distinct original outer constructor/return value slots. These are not
    // new Work/File backing and do not refund any original producer charge.
    let outer_slots = [
        (core::mem::size_of::<StageRecord>(), core::mem::align_of::<StageRecord>(), 1usize),
        (core::mem::size_of::<ControlStageFacts>(), core::mem::align_of::<ControlStageFacts>(), 1usize),
        (core::mem::size_of::<String>(), core::mem::align_of::<String>(), 7usize),
        (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 4usize),
        (core::mem::size_of::<Result<Vec<u8>, Fault>>(), core::mem::align_of::<Result<Vec<u8>, Fault>>(), 2usize),
        (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 1usize),
        (core::mem::size_of::<u32>(), core::mem::align_of::<u32>(), 1usize),
        (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 1usize),
        (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 1usize),
    ];
    let mut outer_fixed = 0u64;
    for (size, align, count) in outer_slots {
        let one = size.checked_add(align).and_then(|n| n.checked_mul(count))
            .ok_or(Fault::BoundsOverflow)?;
        outer_fixed = checked_add(outer_fixed,
            u64::try_from(one).map_err(|_| Fault::BoundsOverflow)?)?;
    }
    // schema, request-id clone, two UUIDs, intent digest, caller's stage-name
    // and work.operation_name final text. J already owns its separate cloned
    // job-name/request-name and two-File backing, so none is billed again.
    let outer_text = ("wrokbot-capture-control".len() + 64 + 2 * 36 + 64 + 128 + 32) as u64;
    let outer = checked_add(outer_fixed, outer_text)?
        .checked_mul(7).ok_or(Fault::BoundsOverflow)?;
    // At most one original ClosingPending facts.fault final bounded text.
    // fmt internals/capacity peaks are not inferred from this requested length.
    let fault_text = checked_add(128,
        (core::mem::size_of::<String>() + core::mem::align_of::<String>()) as u64)?;

    // Exactly the five original Some(output) calls' existing fixed SHA fee.
    // That final SHA backing is moved into facts/StageRecord, never copied here.
    let sha_once = (core::mem::size_of::<String>() as u64)
        .checked_add(64)
        .and_then(|n| n.checked_add(core::mem::size_of::<std::array::IntoIter<u8, 32>>() as u64))
        .and_then(|n| n.checked_add(core::mem::size_of::<Option<u8>>() as u64))
        .and_then(|n| n.checked_add(core::mem::size_of::<Result<(), std::collections::TryReserveError>>() as u64))
        .ok_or(Fault::BoundsOverflow)?;
    let sha = sha_once.checked_mul(5).ok_or(Fault::BoundsOverflow)?;
    checked_add(seven_stages, checked_add(encoded,
        checked_add(outer, checked_add(fault_text, sha)?)?)?)
}

// Pure original one-bool factory: constructing it executes no writer body.
fn original_stage_body(
    closing: bool,
) -> impl FnOnce(&mut JournalWork) -> Result<(), Fault> + Send + 'static {
    move |work| work.write_stage(closing)
}


impl CaptureControlOwner {
    pub(crate) fn prepare(
        app_data_root: &File,
        reviewed: &ReviewedNormalCaptureRequest,
        resources: Arc<std::sync::Mutex<super::CaptureResourceTotals>>,
        first: OriginalControlHistoryFootprint,
    ) -> Result<Self, Fault> {
        let limits = Limits::from_profile(&reviewed.profile)?;
        if !digest_text(&reviewed.request_id) {
            return Err(Fault::IntentMismatch);
        }
        if limits.files < MAX_JOURNAL_JOBS as u64 * 8 + 8 || limits.dirs < 4 || limits.records < 11
        {
            return Err(Fault::CapacityExceeded);
        }
        let app = app_data_root.try_clone().map_err(io_fault)?;
        let app_path = bound_path(&app)?;
        let app_check = open_trusted_directory(&app_path, true)?;
        same_directory(&app, &app_check)?;
        let output = open_trusted_directory(&reviewed.output.absolute_path, true)?;
        let key = open_trusted_directory(&reviewed.key_medium.absolute_path, true)?;
        if Identity::of(&output.metadata().map_err(io_fault)?)
            != (Identity {
                device: reviewed.output.device,
                inode: reviewed.output.inode,
                uid: reviewed.output.uid,
            })
            || Identity::of(&key.metadata().map_err(io_fault)?)
                != (Identity {
                    device: reviewed.key_medium.device,
                    inode: reviewed.key_medium.inode,
                    uid: reviewed.key_medium.uid,
                })
        {
            return Err(Fault::PathUnsafe);
        }
        // The reviewed maintenance root is a validated relative descendant of this exact
        // original release root, so excluding the entire release also excludes maintenance.
        let release_path = bound_path(&reviewed.release_root)?;
        if release_path != reviewed.release_path {
            return Err(Fault::PathUnsafe);
        }
        let release_check = open_trusted_directory(&release_path, false)?;
        same_directory(&reviewed.release_root, &release_check)?;
        for destination in [
            &reviewed.output.absolute_path,
            &reviewed.key_medium.absolute_path,
            &app_path,
        ] {
            if destination.starts_with(&release_path) || release_path.starts_with(destination) {
                return Err(Fault::PathUnsafe);
            }
        }
        let release_identity = Identity::of(&reviewed.release_root.metadata().map_err(io_fault)?);
        for fd in [&output, &key, &app] {
            if Identity::of(&fd.metadata().map_err(io_fault)?) == release_identity {
                return Err(Fault::PathUnsafe);
            }
        }
        let cp = app_path.join(CONTROL);
        for (a, b) in [
            (&cp, &reviewed.output.absolute_path),
            (&cp, &reviewed.key_medium.absolute_path),
            (&app_path, &reviewed.output.absolute_path),
            (&app_path, &reviewed.key_medium.absolute_path),
            (
                &reviewed.output.absolute_path,
                &reviewed.key_medium.absolute_path,
            ),
        ] {
            if a.starts_with(b) || b.starts_with(a) {
                return Err(Fault::PathUnsafe);
            }
        }
        if Identity::of(&output.metadata().map_err(io_fault)?)
            == Identity::of(&key.metadata().map_err(io_fault)?)
        {
            return Err(Fault::PathUnsafe);
        }
        let app_observation = app.metadata().map_err(io_fault)?;
        let control = optional_directory(&app, CONTROL)?;
        let expected = match (&first.observation, &control) {
            (OriginalControlHistoryObservation::Unobserved, None) => None,
            (OriginalControlHistoryObservation::Absent { app: original }, None)
                if *original == Identity::of(&app_observation) => None,
            (OriginalControlHistoryObservation::Present { app: original, root, blocks, history }, Some(fd))
                if *original == Identity::of(&app_observation) => {
                    let before = fd.metadata().map_err(io_fault)?;
                    if RecordIdentity::of(&before) != *root || before.blocks() != *blocks {
                        return Err(Fault::ClosingPending);
                    }
                    Some(*history)
                }
            // Unobserved is not absence; an unexplained new root is not adopted.
            _ => return Err(Fault::ClosingPending),
        };
        let count = expected.unwrap_or_default();
        let maximum = count.records.checked_add(count.ordinary_files)
            .and_then(|n| n.checked_add(count.dirs))
            .and_then(|n| n.checked_add(3))
            .and_then(|n| n.checked_add((MAX_JOURNAL_JOBS as u64).checked_mul(2)?.checked_add(4)?))
            .and_then(|n| usize::try_from(n).ok()).ok_or(Fault::BoundsOverflow)?;
        // The only new object backing is paid before this allocation and scan.
        let mut storage = super::prepare_original_control_storage(
            &resources, &reviewed.profile.carrier_bounds()?, maximum,
        )?;
        let history = match &control {
            Some(fd) => scan_closed_history(fd, &limits, 7, Some(&mut storage), None)?,
            // This is the second actual NOENT on the original held parent, not caller DATA.
            None => History::default(),
        };
        if expected.is_some_and(|original| original != history) {
            return Err(Fault::ClosingPending);
        }
        for (index, held) in [Some(&app), control.as_ref(), Some(&output), Some(&key)]
            .into_iter().enumerate()
        {
            if let Some(fd) = held {
                let before = fd.metadata().map_err(io_fault)?;
                if !before.is_dir() || before.uid() != rustix::process::geteuid().as_raw()
                    || before.mode() & 0o7777 != 0o700
                { return Err(Fault::PathUnsafe); }
                let after = fd.metadata().map_err(io_fault)?;
                if RecordIdentity::of(&before) != RecordIdentity::of(&after)
                    || before.blocks() != after.blocks()
                { return Err(Fault::ClosingPending); }
                storage.observe(after.dev(), after.ino(), after.blocks(), 0)?;
                storage.roots[index] = super::OriginalControlRootObservation::Present {
                    device: after.dev(), inode: after.ino(),
                };
                if index == 1 {
                    ordinary_named_identity(&app, CONTROL, RecordIdentity::of(&after), true)?;
                }
            } else {
                // Only original optional_directory's actual NOENT reaches this slot.
                storage.roots[index] = super::OriginalControlRootObservation::Absent;
            }
        }
        if let OriginalControlHistoryObservation::Present { root, blocks, .. } = &first.observation {
            let after = control.as_ref().ok_or(Fault::ClosingPending)?.metadata().map_err(io_fault)?;
            if RecordIdentity::of(&after) != *root || after.blocks() != *blocks {
                return Err(Fault::ClosingPending);
            }
        }
        let app_after = app.metadata().map_err(io_fault)?;
        if RecordIdentity::of(&app_observation) != RecordIdentity::of(&app_after)
            || app_observation.blocks() != app_after.blocks()
        { return Err(Fault::ClosingPending); }
        if history.retained_bytes()? > limits.retained || history.allocation > limits.allocation {
            return Err(Fault::CapacityExceeded);
        }
        // Reserve the complete fixed workflow before master retention. No new stage can
        // independently spend a second full metadata/FD allowance.
        let per_job = checked_add(
            std::mem::size_of::<JournalWork>() as u64 * 3 + 2048,
            limits.record.checked_mul(2).ok_or(Fault::BoundsOverflow)?,
        )?;
        let all_jobs = per_job
            .checked_mul(MAX_JOURNAL_JOBS as u64)
            .ok_or(Fault::BoundsOverflow)?;
        let path_bytes = checked_add(
            app_path.capacity() as u64,
            checked_add(
                reviewed.output.absolute_path.capacity() as u64,
                reviewed.key_medium.absolute_path.capacity() as u64,
            )?,
        )?;
        let peak = checked_add(
            history.metadata,
            checked_add(
                all_jobs,
                checked_add(
                    limits.record.checked_mul(2).ok_or(Fault::BoundsOverflow)?,
                    checked_add(path_bytes, std::mem::size_of::<Self>() as u64 + 4096)?,
                )?,
            )?,
        )?;
        if peak > limits.metadata {
            return Err(Fault::CapacityExceeded);
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(MAX_JOURNAL_JOBS)
            .map_err(|_| Fault::CapacityExceeded)?;
        if retained.capacity() > MAX_JOURNAL_JOBS {
            return Err(Fault::CapacityExceeded);
        }
        storage.classified = true;
        super::install_original_control_storage(&resources, storage)?;
        Ok(Self {
            app,
            app_path,
            control,
            output,
            key,
            output_path: reviewed.output.absolute_path.clone(),
            key_path: reviewed.key_medium.absolute_path.clone(),
            limits,
            request_id: reviewed.request_id.clone(),
            operation_directory: None,
            operation_path: None,
            pending: None,
            retained,
            sequence: 0,
            journal_bytes: 0,
            history,
            resources,
            poisoned: false,
            begin_started: false,
            consumer_started: false,
            consumer_complete: false,
        })
    }
    pub(super) fn revalidate_original_storage_owner(
        &self,
        resources: &Arc<std::sync::Mutex<super::CaptureResourceTotals>>,
        bounds: &openbot_domain::backup::whole_pg_carrier::WholePgCarrierBounds,
    ) -> Result<(), Fault> {
        if !Arc::ptr_eq(&self.resources, resources) {
            return Err(Fault::IntentMismatch);
        }
        super::original_capture_resource_identity(resources, bounds)?;
        let totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
        if !totals.original_control_storage.classified {
            return Err(Fault::IntentMismatch);
        }
        Ok(())
    }

    pub(crate) async fn begin(
        &mut self,
        op: &Arc<CaptureOperation>,
        source: ControlSourceIdentity,
    ) -> Result<CaptureIntentWitness, Fault> {
        // Known fixed logical slots only; opaque producer/allocator peaks remain held.
        const FIXED_METADATA: u64 = {
            let slots = [
                (core::mem::size_of::<History>(), core::mem::align_of::<History>(), 1usize),
                (core::mem::size_of::<Limits>(), core::mem::align_of::<Limits>(), 1usize),
                (core::mem::size_of::<(DirectoryMode, Identity)>(), core::mem::align_of::<(DirectoryMode, Identity)>(), 2usize),
                (core::mem::size_of::<(DirectoryMode, Identity, Identity, Identity)>(), core::mem::align_of::<(DirectoryMode, Identity, Identity, Identity)>(), 2usize),
                (core::mem::size_of::<(Identity, Identity)>(), core::mem::align_of::<(Identity, Identity)>(), 2usize),
                (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 4usize),
                (core::mem::size_of::<Option<PathBuf>>(), core::mem::align_of::<Option<PathBuf>>(), 2usize),
                (core::mem::size_of::<Option<File>>(), core::mem::align_of::<Option<File>>(), 2usize),
                (core::mem::size_of::<(Option<File>, Option<PathBuf>)>(), core::mem::align_of::<(Option<File>, Option<PathBuf>)>(), 2usize),
                (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 1usize),
                (core::mem::size_of::<Option<&'static Result<JournalHistoryFact, Fault>>>(), core::mem::align_of::<Option<&'static Result<JournalHistoryFact, Fault>>>(), 1usize),
                (core::mem::size_of::<Result<&'static Result<JournalHistoryFact, Fault>, Fault>>(), core::mem::align_of::<Result<&'static Result<JournalHistoryFact, Fault>, Fault>>(), 1usize),
                (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 2usize),
                (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 2usize),
                (core::mem::size_of::<&'static Vec<JournalRetained>>(), core::mem::align_of::<&'static Vec<JournalRetained>>(), 1usize),
                (core::mem::size_of::<&'static File>(), core::mem::align_of::<&'static File>(), 2usize),
                (core::mem::size_of::<&'static Arc<CaptureOperation>>(), core::mem::align_of::<&'static Arc<CaptureOperation>>(), 1usize),
                (core::mem::size_of::<&'static usize>(), core::mem::align_of::<&'static usize>(), 1usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 2usize),
                (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 3usize),
                (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 3usize),
                (core::mem::size_of::<Result<usize, Fault>>(), core::mem::align_of::<Result<usize, Fault>>(), 2usize),
                (core::mem::size_of::<Result<&'static JournalRetained, Fault>>(), core::mem::align_of::<Result<&'static JournalRetained, Fault>>(), 3usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 2usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            ];
            let mut at = 0usize;
            let mut bytes = 0usize;
            while at < slots.len() {
                let one = slots[at].0.checked_add(slots[at].1)
                    .expect("fixed journal slot layout fits usize");
                let amount = one.checked_mul(slots[at].2)
                    .expect("fixed journal slot count fits usize");
                bytes = bytes.checked_add(amount)
                    .expect("fixed journal slots fit usize");
                at += 1;
            }
            assert!(usize::BITS <= u64::BITS);
            bytes as u64
        };
        op.require_effect()?;
        super::reserve_capture_resources(&op.resources, 0, FIXED_METADATA)?;
        if self.poisoned
            || self.begin_started
            || self.pending.is_some()
            || self.operation_directory.is_some()
            || self.request_id != op.reviewed().request_id
        {
            return Err(Fault::IntentMismatch);
        }
        source.check()?;
        self.begin_started = true;
        // First-t0 history classification is the original blocking job for
        // both Existing and New. The retained owner never lends this scan to the
        // async caller or locks an active work after timeout.
        let history_index = self.job(op, "", Vec::new(), Vec::new(), false, false)?;
        let prepared = (|| {
            let entry = self.retained.get(history_index).ok_or(Fault::IntentMismatch)?;
            let mut work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            let JournalWork { history_output, clone_error, .. } = &mut *work;
            runtime_clone_for_fact_observed(&self.output, op.as_ref(), false, &op.resources, history_output, Some(clone_error))?;
            let JournalWork { history_key, clone_error, .. } = &mut *work;
            runtime_clone_for_fact_observed(&self.key, op.as_ref(), false, &op.resources, history_key, Some(clone_error))?;
            Ok::<(), Fault>(())
        })();
        if let Err(fault) = prepared { self.poisoned = true; return Err(fault); }
        let expected = self.history;
        let limits = self.limits;
        self.start_job(history_index, op, false,
            move |work| work.prepare_original_history(expected, limits))?;
        self.wait_original(op).await?;
        let (child_mode, control_identity, output_identity, key_identity) = {
            let entry = self.retained.get(history_index).ok_or(Fault::IntentMismatch)?;
            let mut work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            let destinations = (
                work.destination_identities[0].ok_or(Fault::IntentMismatch)?,
                work.destination_identities[1].ok_or(Fault::IntentMismatch)?,
            );
            let (child_mode, control_identity) = match work.history_result.as_ref().ok_or(Fault::IntentMismatch)? {
                Ok(JournalHistoryFact::Existing(actual, identity)) if *actual == self.history && self.control.is_some() =>
                    (DirectoryMode::Existing, *identity),
                Ok(JournalHistoryFact::NewlyCreatedEmpty(identity)) if self.control.is_none() => {
                    let identity = *identity;
                    self.control = work.control.take();
                    (DirectoryMode::New, identity)
                }
                Err(fault) => return Err(*fault),
                _ => return Err(Fault::IntentMismatch),
            };
            (child_mode, control_identity, destinations.0, destinations.1)
        };
        let _ = self.control.as_ref().ok_or(Fault::IntentMismatch)?;
        if source.source_device == control_identity.device
            && source.source_inode == control_identity.inode
        {
            return Err(Fault::PathUnsafe);
        }
        let bundle32 = hex(&op.bundle_id());
        let intent = IntentView {
            schema: "wrokbot-capture-control",
            version: 1,
            sequence: 0,
            stage: "intent",
            request_id: &self.request_id,
            operation_id: uuid(op.operation_id()),
            bundle_id: uuid(op.bundle_id()),
            owner_instance: uuid(op.owner_instance()),
            owner_pid: std::process::id(),
            t0: op.original_t0_ns(),
            e: op.effect_deadline_ns(),
            c: op.closing_deadline_ns(),
            profile: op.profile(),
            release_sha256: hex(&op.reviewed().release_digest),
            maintenance_sha256: hex(&op.reviewed().maintenance_digest),
            source_identity: &source,
            control: Destination {
                path: self.app_path.join(CONTROL),
                identity: control_identity,
            },
            output: Destination {
                path: self.output_path.clone(),
                identity: output_identity,
            },
            key_medium: Destination {
                path: self.key_path.clone(),
                identity: key_identity,
            },
            temporary_basename: format!(".wrokbot-capture-{bundle32}.partial"),
            final_basename: format!("wrokbot-capture-{bundle32}.wbpg"),
            key_basename: format!("wrokbot-capture-{bundle32}.key"),
        };
        let canonical_intent = encode(&intent, self.limits.record)?;
        let digest: [u8; 32] = Sha256::digest(&canonical_intent).into();
        let request = RequestRecord {
            schema: "wrokbot-capture-request".into(),
            version: 1,
            request_id: self.request_id.clone(),
            operation_id: uuid(op.operation_id()),
            bundle_id: uuid(op.bundle_id()),
            owner_instance: uuid(op.owner_instance()),
            owner_pid: std::process::id(),
            release_sha256: hex(&op.reviewed().release_digest),
            maintenance_sha256: hex(&op.reviewed().maintenance_digest),
            profile_sha256: hex(&hash_encoded(op.profile(), self.limits.record)?),
            source_identity_sha256: hex(&hash_encoded(&source, self.limits.record)?),
            intent_sha256: hex(&digest),
        };
        let request_bytes = encode(&request, self.limits.record)?;
        self.check_new_record((canonical_intent.len() + request_bytes.len()) as u64, 2)?;
        let index = self.job(
            op,
            "00000000-intent.json",
            canonical_intent.clone(),
            request_bytes.clone(),
            true,
            false,
        )?;
        {
            let entry = self.retained.get(index).ok_or(Fault::IntentMismatch)?;
            let mut work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            work.operation_name = hex(&op.operation_id());
        }
        self.start_job(index, op, false, move |w| w.write_intent(child_mode))?;
        self.wait_original(op).await?;
        let (operation_directory, operation_path) = {
            let entry = self.retained.get(index).ok_or(Fault::IntentMismatch)?;
            let mut work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            if work.operation_directory.is_none() || work.operation_path.is_none() {
                return Err(Fault::IntentMismatch);
            }
            // Both original resources were checked before either linear take.
            (work.operation_directory.take(), work.operation_path.take())
        };
        self.operation_directory = operation_directory;
        self.operation_path = operation_path;
        self.journal_bytes = checked_add(
            self.journal_bytes,
            (canonical_intent.len() + request_bytes.len()) as u64,
        )?;
        let (intent_identity, request_identity) = {
            let entry = self.retained.get(index).ok_or(Fault::IntentMismatch)?;
            let work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            (
                work.intent_identity.ok_or(Fault::IntentMismatch)?,
                work.request_identity.ok_or(Fault::IntentMismatch)?,
            )
        };
        Ok(CaptureIntentWitness {
            operation: op.operation_id(),
            bundle: op.bundle_id(),
            intent_sha256: digest,
            canonical_intent,
            request_bytes,
            intent_identity,
            request_identity,
        })
    }
    pub(crate) fn operation_directory(&self) -> Result<&File, Fault> {
        self.operation_directory
            .as_ref()
            .ok_or(Fault::IntentMismatch)
    }
    pub(crate) fn operation_path(&self) -> Result<&Path, Fault> {
        self.operation_path.as_deref().ok_or(Fault::IntentMismatch)
    }
    pub(crate) fn destinations(&self) -> (&File, &File) {
        (&self.output, &self.key)
    }
    pub(crate) async fn confirm_before_source_start(
        &mut self,
        w: &CaptureIntentWitness,
        op: &Arc<CaptureOperation>,
    ) -> Result<(), Fault> {
        // Known fixed logical slots only; opaque producer/allocator peaks remain held.
        const FIXED_METADATA: u64 = {
            let slots = [
                (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 1usize),
                (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 1usize),
                (core::mem::size_of::<Result<usize, Fault>>(), core::mem::align_of::<Result<usize, Fault>>(), 1usize),
                (core::mem::size_of::<Result<&'static JournalRetained, Fault>>(), core::mem::align_of::<Result<&'static JournalRetained, Fault>>(), 1usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 1usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            ];
            let mut at = 0usize;
            let mut bytes = 0usize;
            while at < slots.len() {
                let one = slots[at].0.checked_add(slots[at].1)
                    .expect("fixed journal slot layout fits usize");
                let amount = one.checked_mul(slots[at].2)
                    .expect("fixed journal slot count fits usize");
                bytes = bytes.checked_add(amount)
                    .expect("fixed journal slots fit usize");
                at += 1;
            }
            assert!(usize::BITS <= u64::BITS);
            bytes as u64
        };
        op.require_effect()?;
        super::reserve_capture_resources(&op.resources, 0, FIXED_METADATA)?;
        self.check_witness(w, op)?;
        if self.consumer_complete {
            return Err(Fault::IntentMismatch);
        }
        if self.consumer_started {
            if self.pending.is_none() {
                return Err(Fault::ClosingPending);
            }
            self.wait_original(op).await?;
            op.require_effect()?;
            self.consumer_complete = true;
            return Ok(());
        }
        self.consumer_started = true;
        self.check_job_slot()?;
        let index = self.job(
            op,
            "00000000-intent.json",
            w.canonical_intent.clone(),
            w.request_bytes.clone(),
            false,
            false,
        )?;
        let prepared = (|| {
            let original = self.operation_directory.as_ref().ok_or(Fault::IntentMismatch)?;
            let entry = self.retained.get(index).ok_or(Fault::IntentMismatch)?;
            let mut work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            let JournalWork { operation_directory, clone_error, .. } = &mut *work;
            runtime_clone_for_fact_observed(original, op.as_ref(), false, &op.resources, operation_directory, Some(clone_error))?;
            work.operation_name = hex(&op.operation_id());
            work.intent_identity = Some(w.intent_identity);
            work.request_identity = Some(w.request_identity);
            Ok::<(), Fault>(())
        })();
        if let Err(fault) = prepared {
            self.poisoned = true;
            return Err(fault);
        }
        self.start_job(index, op, false, |w| w.confirm(0))?;
        self.wait_original(op).await?;
        op.require_effect()?;
        self.consumer_complete = true;
        Ok(())
    }
    pub(crate) async fn append(
        &mut self,
        w: &CaptureIntentWitness,
        op: &Arc<CaptureOperation>,
        stage: ControlStage,
        facts: ControlStageFacts,
    ) -> Result<(), Fault> {
        self.check_witness(w, op)?;
        if stage == ControlStage::ClosingPending {
            op.require_closing()?;
        } else {
            op.require_effect()?;
        }
        // Known fixed logical slots only; opaque producer/allocator peaks remain held.
        const FIXED_METADATA: u64 = {
            let slots = [
                (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 2usize),
                (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 2usize),
                (core::mem::size_of::<Result<usize, Fault>>(), core::mem::align_of::<Result<usize, Fault>>(), 1usize),
                (core::mem::size_of::<Result<&'static JournalRetained, Fault>>(), core::mem::align_of::<Result<&'static JournalRetained, Fault>>(), 2usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 1usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 5usize),
            ];
            let mut at = 0usize;
            let mut bytes = 0usize;
            while at < slots.len() {
                let one = slots[at].0.checked_add(slots[at].1)
                    .expect("fixed journal slot layout fits usize");
                let amount = one.checked_mul(slots[at].2)
                    .expect("fixed journal slot count fits usize");
                bytes = bytes.checked_add(amount)
                    .expect("fixed journal slots fit usize");
                at += 1;
            }
            assert!(usize::BITS <= u64::BITS);
            bytes as u64
        };
        super::reserve_capture_resources(&op.resources, 0, FIXED_METADATA)?;
        if self.poisoned
            || stage != ControlStage::ClosingPending && stage.ordinal() != self.sequence + 1
            || facts.joined_original_tasks > facts.original_tasks
            || facts
                .output_sha256
                .as_ref()
                .is_some_and(|v| !digest_text(v))
            || facts.fault.as_ref().is_some_and(|v| !fault_text(v))
        {
            return Err(Fault::IntentMismatch);
        }
        if stage != ControlStage::ClosingPending
            && (facts.outcome != ControlOutcome::Actual || facts.fault.is_some())
        {
            return Err(Fault::ClosingPending);
        }
        if stage == ControlStage::Closed
            && (facts.original_tasks != facts.joined_original_tasks
                || facts.live_proxy_futures != 0
                || facts.output_bytes.is_none()
                || facts.output_sha256.as_ref().is_none_or(|s| !digest_text(s)))
        {
            return Err(Fault::ClosingPending);
        }
        let sequence = self.sequence.checked_add(1).ok_or(Fault::BoundsOverflow)?;
        let record = StageRecord {
            schema: "wrokbot-capture-control".into(),
            version: 1,
            sequence,
            stage,
            request_id: self.request_id.clone(),
            operation_id: uuid(op.operation_id()),
            bundle_id: uuid(op.bundle_id()),
            intent_sha256: hex(&w.intent_sha256),
            observed_monotonic_ns: op.observed_ns()?,
            outcome: facts.outcome,
            fault: facts.fault,
            issued_effects: facts.issued_effects,
            original_tasks: facts.original_tasks,
            joined_original_tasks: facts.joined_original_tasks,
            live_proxy_futures: facts.live_proxy_futures,
            parent_device: facts.parent_device,
            parent_inode: facts.parent_inode,
            entry_device: facts.entry_device,
            entry_inode: facts.entry_inode,
            output_bytes: facts.output_bytes,
            output_sha256: facts.output_sha256,
        };
        let bytes = encode(&record, self.limits.record)?;
        self.check_new_record(bytes.len() as u64, 1)?;
        let name = format!("{sequence:08}-{}.json", stage.text());
        let len = bytes.len() as u64;
        let closing = stage == ControlStage::ClosingPending;
        let index = self.job(op, &name, bytes, Vec::new(), false, closing)?;
        let prepared = (|| {
            let original = self.operation_directory.as_ref().ok_or(Fault::IntentMismatch)?;
            let entry = self.retained.get(index).ok_or(Fault::IntentMismatch)?;
            let mut work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            let JournalWork { operation_directory, clone_error, .. } = &mut *work;
            runtime_clone_for_fact_observed(
                original, op.as_ref(), closing, &op.resources, operation_directory, Some(clone_error),
            )?;
            work.operation_name = hex(&op.operation_id());
            Ok::<(), Fault>(())
        })();
        if let Err(fault) = prepared {
            self.poisoned = true;
            return Err(fault);
        }
        self.start_job(index, op, closing, original_stage_body(closing))?;
        self.wait_original(op).await?;
        self.sequence = sequence;
        self.journal_bytes = checked_add(self.journal_bytes, len)?;
        if closing {
            self.poisoned = true;
        }
        // The joined stage and its accounting remain resident before these auxiliary FDs retire.
        let entry = self.retained.get(index).ok_or(Fault::IntentMismatch)?;
        let mut work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
        op.require_closing()?;
        drop(work.operations.take());
        op.require_closing()?;
        op.require_closing()?;
        drop(work.operation_directory.take());
        op.require_closing()?;
        op.require_closing()?;
        drop(work.control.take());
        op.require_closing()?;
        Ok(())
    }
    fn check_witness(&self, w: &CaptureIntentWitness, op: &CaptureOperation) -> Result<(), Fault> {
        if w.operation != op.operation_id()
            || w.bundle != op.bundle_id()
            || self.request_id != op.reviewed().request_id
            || Sha256::digest(&w.canonical_intent).as_slice() != w.intent_sha256
        {
            return Err(Fault::IntentMismatch);
        }
        Ok(())
    }
    fn check_new_record(&self, bytes: u64, count: u64) -> Result<(), Fault> {
        let total = checked_add(checked_add(self.history.bytes, self.journal_bytes)?, bytes)?;
        let records = checked_add(self.history.records, u64::from(self.sequence) + count + 2)?;
        let metadata = checked_add(self.history.metadata, checked_add(total, bytes)?)?;
        let retained = checked_add(total, self.history.ordinary_bytes)?;
        if total > self.limits.journal
            || retained > self.limits.retained
            || records > self.limits.records
            || metadata > self.limits.metadata
            || self.retained.len() as u64 * 8 + 16 > self.limits.files
        {
            return Err(Fault::CapacityExceeded);
        }
        Ok(())
    }
    fn check_job_slot(&self) -> Result<(), Fault> {
        if self.pending.is_some() || self.retained.len() >= MAX_JOURNAL_JOBS {
            return Err(Fault::ClosingPending);
        }
        Ok(())
    }
    fn job(
        &mut self,
        op: &Arc<CaptureOperation>,
        name: &str,
        bytes: Vec<u8>,
        request_bytes: Vec<u8>,
        first: bool,
        closing_fact: bool,
    ) -> Result<usize, Fault> {
        // Known fixed logical slots only; opaque producer/allocator peaks remain held.
        const FIXED_METADATA: u64 = {
            let slots = [
                (core::mem::size_of::<Option<File>>(), core::mem::align_of::<Option<File>>(), 2usize),
                (core::mem::size_of::<Option<rustix::fs::Dir>>(), core::mem::align_of::<Option<rustix::fs::Dir>>(), 1usize),
                (core::mem::size_of::<Vec<ClosedNativeFrame>>(), core::mem::align_of::<Vec<ClosedNativeFrame>>(), 1usize),
                (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 1usize),
                (core::mem::size_of::<Option<JournalHistoryIoResult>>(), core::mem::align_of::<Option<JournalHistoryIoResult>>(), 1usize),
                (core::mem::size_of::<Option<Result<JournalHistoryFact, Fault>>>(), core::mem::align_of::<Option<Result<JournalHistoryFact, Fault>>>(), 1usize),
                // Empty constructor headers/array are distinct from Work's own
                // enlarged value and Arc allocation below. No backing exists yet.
                (core::mem::size_of::<Vec<File>>(), core::mem::align_of::<Vec<File>>(), 1usize),
                (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 1usize),
                (core::mem::size_of::<[Option<Identity>; 2]>(), core::mem::align_of::<[Option<Identity>; 2]>(), 1usize),
                (core::mem::size_of::<Option<Identity>>(), core::mem::align_of::<Option<Identity>>(), 2usize),
                (core::mem::size_of::<Option<PathBuf>>(), core::mem::align_of::<Option<PathBuf>>(), 1usize),
                (core::mem::size_of::<Option<io::Error>>(), core::mem::align_of::<Option<io::Error>>(), 1usize),
                (core::mem::size_of::<Option<Result<u64, Fault>>>(), core::mem::align_of::<Option<Result<u64, Fault>>>(), 1usize),
                (core::mem::size_of::<[Option<io::Result<Metadata>>;2]>(), core::mem::align_of::<[Option<io::Result<Metadata>>;2]>(), 1usize),
                (core::mem::size_of::<Option<&mut Option<Result<u64, Fault>>>>(), core::mem::align_of::<Option<&mut Option<Result<u64, Fault>>>>(), 3usize),
                (core::mem::size_of::<Option<&mut [Option<io::Result<Metadata>>;2]>>(), core::mem::align_of::<Option<&mut [Option<io::Result<Metadata>>;2]>>(), 3usize),
                (core::mem::size_of::<[Option<Result<(usize, Vec<u8>), Fault>>; 4]>(), core::mem::align_of::<[Option<Result<(usize, Vec<u8>), Fault>>; 4]>(), 1usize),
                (core::mem::size_of::<Option<Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<Option<Result<(usize, Vec<u8>), Fault>>>(), 4usize),
                // At most three runtime views are constructed by write_intent
                // (two writers, then confirm); each construction's field borrows
                // and the view value are paid without assuming slot elision.
                (core::mem::size_of::<HistoryIo<'static>>(), core::mem::align_of::<HistoryIo<'static>>(), 3usize),
                (core::mem::size_of::<Option<(&CaptureOperation, bool)>>(), core::mem::align_of::<Option<(&CaptureOperation, bool)>>(), 3usize),
                (core::mem::size_of::<&mut Vec<File>>(), core::mem::align_of::<&mut Vec<File>>(), 3usize),
                (core::mem::size_of::<&mut Option<rustix::fs::Dir>>(), core::mem::align_of::<&mut Option<rustix::fs::Dir>>(), 3usize),
                (core::mem::size_of::<&mut Vec<ClosedNativeFrame>>(), core::mem::align_of::<&mut Vec<ClosedNativeFrame>>(), 3usize),
                (core::mem::size_of::<&mut Vec<u8>>(), core::mem::align_of::<&mut Vec<u8>>(), 6usize),
                (core::mem::size_of::<&mut Option<JournalHistoryIoResult>>(), core::mem::align_of::<&mut Option<JournalHistoryIoResult>>(), 3usize),
                (core::mem::size_of::<&mut Option<Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<&mut Option<Result<(usize, Vec<u8>), Fault>>>(), 4usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 4usize),
                (core::mem::size_of::<JournalWork>(), core::mem::align_of::<JournalWork>(), 1usize),
                (core::mem::size_of::<Arc<std::sync::Mutex<JournalWork>>>(), core::mem::align_of::<Arc<std::sync::Mutex<JournalWork>>>(), 2usize),
                (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 1usize),
                (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 1usize),
                (core::mem::size_of::<Vec<File>>(), core::mem::align_of::<Vec<File>>(), 1usize),
                (core::mem::size_of::<String>(), core::mem::align_of::<String>(), 2usize),
                (core::mem::size_of::<Arc<CaptureOperation>>(), core::mem::align_of::<Arc<CaptureOperation>>(), 1usize),
                (core::mem::size_of::<Result<(), std::collections::TryReserveError>>(), core::mem::align_of::<Result<(), std::collections::TryReserveError>>(), 3usize),
                (core::mem::size_of::<Result<usize, Fault>>(), core::mem::align_of::<Result<usize, Fault>>(), 2usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
                (core::mem::size_of::<Option<u64>>(), core::mem::align_of::<Option<u64>>(), 3usize),
                (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 4usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 3usize),
                (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 3usize),
            ];
            let mut at = 0usize;
            let mut bytes = 0usize;
            while at < slots.len() {
                let one = slots[at].0.checked_add(slots[at].1)
                    .expect("fixed journal slot layout fits usize");
                let amount = one.checked_mul(slots[at].2)
                    .expect("fixed journal slot count fits usize");
                bytes = bytes.checked_add(amount)
                    .expect("fixed journal slots fit usize");
                at += 1;
            }
            assert!(usize::BITS <= u64::BITS);
            bytes as u64
        };
        const WORK_ALLOCATION: u64 = {
            let layout = match std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
                .extend(std::alloc::Layout::new::<std::sync::Mutex<JournalWork>>())
            {
                Ok((layout, _)) => layout.pad_to_align(),
                Err(_) => panic!("fixed journal Arc layout is valid"),
            };
            assert!(usize::BITS <= u64::BITS);
            layout.size() as u64
        };
        self.check_job_slot()?;
        if !Arc::ptr_eq(&self.resources, &op.resources) {
            return Err(Fault::IntentMismatch);
        }
        if self.poisoned
            || self.retained.last().is_some_and(|entry| entry.1.is_none() || entry.2.is_some())
        {
            return Err(Fault::ClosingPending);
        }
        if bytes.capacity() as u64 > self.limits.record
            || request_bytes.capacity() as u64 > self.limits.record || name.len() > 128
            || self.retained.len() >= self.retained.capacity()
        {
            return Err(Fault::CapacityExceeded);
        }
        let guard = || if closing_fact { op.require_closing() } else { op.require_effect() };
        guard()?;
        let request_name_len = self.request_id.len().checked_add(5).ok_or(Fault::BoundsOverflow)?;
        let known = FIXED_METADATA.checked_add(WORK_ALLOCATION)
            .and_then(|n| n.checked_add(name.len() as u64))
            .and_then(|n| n.checked_add(request_name_len as u64))
            .and_then(|n| n.checked_add((2 * core::mem::size_of::<File>()) as u64))
            .ok_or(Fault::BoundsOverflow)?;
        super::reserve_capture_resources(&op.resources, 0, known)?;
        guard()?;
        let mut owned_name = String::new();
        owned_name.try_reserve_exact(name.len()).map_err(|_| Fault::CapacityExceeded)?;
        if owned_name.capacity() != name.len() { return Err(Fault::CapacityExceeded); }
        owned_name.push_str(name);
        let mut request_name = String::new();
        request_name.try_reserve_exact(request_name_len).map_err(|_| Fault::CapacityExceeded)?;
        if request_name.capacity() != request_name_len { return Err(Fault::CapacityExceeded); }
        request_name.push_str(&self.request_id);
        request_name.push_str(".json");
        let mut files = Vec::new();
        files.try_reserve_exact(2).map_err(|_| Fault::CapacityExceeded)?;
        if files.capacity() != 2 { return Err(Fault::CapacityExceeded); }
        let index = self.retained.len();
        let work = JournalWork {
            app: None, control: None, requests: None, operations: None,
            operation_directory: None, files, record_files: Vec::new(),
            record_bytes: Vec::new(), record_results: [None, None, None, None],
            destination_identities: [None, None], operation_path: None, clone_error: None,
            operation_name: String::new(), first,
            name: owned_name, bytes, request_name, request_bytes, clock: Arc::clone(op),
            limit: self.limits.record, reserve: self.limits.reserve, floor: self.limits.floor,
            allocation: self.limits.allocation, intent_identity: None, request_identity: None,
            returned: None, panic: None,
            history_output: None, history_key: None, history_dir: None,
            history_frames: Vec::new(), history_matched: Vec::new(),
            history_io: None, history_result: None,
            fs_admission: None, fs_observations: [None, None],
        };
        // No new FD exists during allocation. The original retained Arc is installed
        // before the first dup, and push cannot grow the precharged backing.
        self.retained.push((Arc::new(std::sync::Mutex::new(work)), None, None));
        let cloned = (|| {
            let entry = self.retained.get(index).ok_or(Fault::IntentMismatch)?;
            let mut work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            let JournalWork { app, clock, clone_error, .. } = &mut *work;
            runtime_clone_for_fact_observed(&self.app, clock.as_ref(), closing_fact, &clock.resources, app, Some(clone_error))?;
            if let Some(original) = self.control.as_ref() {
                let JournalWork { control, clock, clone_error, .. } = &mut *work;
                runtime_clone_for_fact_observed(original, clock.as_ref(), closing_fact, &clock.resources, control, Some(clone_error))?;
            }
            Ok::<(), Fault>(())
        })();
        if let Err(fault) = cloned {
            self.poisoned = true;
            return Err(fault);
        }
        Ok(index)
    }
    fn start_job(
        &mut self,
        index: usize,
        op: &Arc<CaptureOperation>,
        closing_fact: bool,
        body: impl FnOnce(&mut JournalWork) -> Result<(), Fault> + Send + 'static,
    ) -> Result<(), Fault> {
        // Known fixed logical slots only; opaque producer/allocator peaks remain held.
        const FIXED_METADATA: u64 = {
            let slots = [
                (core::mem::size_of::<Arc<std::sync::Mutex<JournalWork>>>(), core::mem::align_of::<Arc<std::sync::Mutex<JournalWork>>>(), 3usize),
                (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 2usize),
                (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 2usize),
                (core::mem::size_of::<Result<JoinHandle<JournalCompletion>, Box<dyn std::any::Any + Send + 'static>>>(), core::mem::align_of::<Result<JoinHandle<JournalCompletion>, Box<dyn std::any::Any + Send + 'static>>>(), 1usize),
                (core::mem::size_of::<Result<Result<(), Fault>, Box<dyn std::any::Any + Send + 'static>>>(), core::mem::align_of::<Result<Result<(), Fault>, Box<dyn std::any::Any + Send + 'static>>>(), 1usize),
                (core::mem::size_of::<JournalCompletion>(), core::mem::align_of::<JournalCompletion>(), 1usize),
                (core::mem::size_of::<Option<JournalJoin>>(), core::mem::align_of::<Option<JournalJoin>>(), 1usize),
                (core::mem::size_of::<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>(), core::mem::align_of::<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>(), 1usize),
                (core::mem::size_of::<Option<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>>(), core::mem::align_of::<Option<std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>>>(), 1usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 6usize),
                (core::mem::size_of::<&'static mut JournalWork>(), core::mem::align_of::<&'static mut JournalWork>(), 1usize),
                (core::mem::size_of::<&'static Arc<CaptureOperation>>(), core::mem::align_of::<&'static Arc<CaptureOperation>>(), 1usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 2usize),
                (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 3usize),
            ];
            let mut at = 0usize;
            let mut bytes = 0usize;
            while at < slots.len() {
                let one = slots[at].0.checked_add(slots[at].1)
                    .expect("fixed journal slot layout fits usize");
                let amount = one.checked_mul(slots[at].2)
                    .expect("fixed journal slot count fits usize");
                bytes = bytes.checked_add(amount)
                    .expect("fixed journal slots fit usize");
                at += 1;
            }
            assert!(usize::BITS <= u64::BITS);
            bytes as u64
        };
        if self.poisoned || self.pending.is_some()
            || index.checked_add(1) != Some(self.retained.len())
        { return Err(Fault::ClosingPending); }
        let guard = || if closing_fact { op.require_closing() } else { op.require_effect() };
        guard()?;
        let body_slots = core::mem::size_of_val(&body)
            .checked_add(core::mem::align_of_val(&body))
            .and_then(|n| n.checked_mul(2)).ok_or(Fault::BoundsOverflow)?;
        let known = FIXED_METADATA.checked_add(u64::try_from(body_slots).map_err(|_| Fault::BoundsOverflow)?)
            .ok_or(Fault::BoundsOverflow)?;
        super::reserve_capture_resources(&op.resources, 0, known)?;
        {
            let entry = self.retained.get(index).ok_or(Fault::IntentMismatch)?;
            if entry.1.is_some() || entry.2.is_some() { return Err(Fault::ClosingPending); }
            let work = entry.0.lock().map_err(|_| Fault::ClosingPending)?;
            if work.app.is_none() || work.returned.is_some() || work.panic.is_some()
                || !Arc::ptr_eq(&work.clock, op)
            { return Err(Fault::IntentMismatch); }
        }
        guard()?;
        let slot = Arc::clone(&self.retained[index].0);
        let spawned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tokio::task::spawn_blocking(move || {
                let mut work = match slot.lock() {
                    Ok(work) => work,
                    Err(poisoned) => {
                        let mut work = poisoned.into_inner();
                        work.returned = Some(Err(Fault::ClosingPending));
                        return JournalCompletion { result: Err(Fault::ClosingPending) };
                    }
                };
                let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&mut work)));
                let result = match returned {
                    Ok(result) => result,
                    Err(payload) => {
                        work.panic = Some(payload);
                        Err(Fault::ClosingPending)
                    }
                };
                work.returned = Some(result);
                JournalCompletion { result }
            })
        }));
        // Transfer the real handle or panic payload before the postcheck. Neither
        // branch locks a possibly active Work or takes the owner's retained Arc.
        let launch_failed = match spawned {
            Ok(handle) => { self.pending = Some(handle); false }
            Err(payload) => { self.retained[index].2 = Some(std::sync::Mutex::new(payload)); true }
        };
        if let Err(fault) = guard() {
            self.poisoned = true;
            return Err(fault);
        }
        if launch_failed {
            self.poisoned = true;
            return Err(Fault::ClosingPending);
        }
        Ok(())
    }
    async fn wait_original(&mut self, op: &CaptureOperation) -> Result<(), Fault> {
        // Known fixed logical slots only; opaque producer/allocator peaks remain held.
        const FIXED_METADATA: u64 = {
            let slots = [
                (core::mem::size_of::<std::sync::MutexGuard<'static, JournalWork>>(), core::mem::align_of::<std::sync::MutexGuard<'static, JournalWork>>(), 1usize),
                (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, JournalWork>>>(), 1usize),
                (core::mem::size_of::<JournalJoin>(), core::mem::align_of::<JournalJoin>(), 1usize),
                (core::mem::size_of::<Result<JournalJoin, tokio::time::error::Elapsed>>(), core::mem::align_of::<Result<JournalJoin, tokio::time::error::Elapsed>>(), 1usize),
                (core::mem::size_of::<tokio::time::Timeout<&'static mut JoinHandle<JournalCompletion>>>(), core::mem::align_of::<tokio::time::Timeout<&'static mut JoinHandle<JournalCompletion>>>(), 1usize),
                (core::mem::size_of::<Option<JoinHandle<JournalCompletion>>>(), core::mem::align_of::<Option<JoinHandle<JournalCompletion>>>(), 1usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 5usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 1usize),
                (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 1usize),
            ];
            let mut at = 0usize;
            let mut bytes = 0usize;
            while at < slots.len() {
                let one = slots[at].0.checked_add(slots[at].1)
                    .expect("fixed journal slot layout fits usize");
                let amount = one.checked_mul(slots[at].2)
                    .expect("fixed journal slot count fits usize");
                bytes = bytes.checked_add(amount)
                    .expect("fixed journal slots fit usize");
                at += 1;
            }
            assert!(usize::BITS <= u64::BITS);
            bytes as u64
        };
        op.require_closing()?;
        super::reserve_capture_resources(&op.resources, 0, FIXED_METADATA)?;
        let index = self.retained.len().checked_sub(1).ok_or(Fault::IntentMismatch)?;
        if self.retained[index].1.is_some() || self.retained[index].2.is_some() {
            return Err(Fault::ClosingPending);
        }
        let remaining = op.closing_remaining_ns()?;
        let handle = self.pending.as_mut().ok_or(Fault::IntentMismatch)?;
        let actual = match tokio::time::timeout(std::time::Duration::from_nanos(remaining), handle).await {
            Err(_) => {
                if let Err(fault) = op.require_closing() {
                    self.poisoned = true;
                    return Err(fault);
                }
                return Err(Fault::ClosingPending);
            }
            Ok(actual) => actual,
        };
        // Actual Ready result is resident before the finished handle or any
        // clock/fault classification. Timeout never takes the original handle.
        self.retained[index].1 = Some(actual);
        self.pending.take();
        if let Err(fault) = op.require_closing() {
            self.poisoned = true;
            return Err(fault);
        }
        let result = match self.retained[index].1.as_ref().expect("actual native join retained") {
            Err(join_error) => {
                self.poisoned = true;
                return Err(if join_error.is_cancelled() { Fault::Cancelled } else { Fault::ClosingPending });
            }
            Ok(completed) => completed.result,
        };
        if let Err(fault) = result {
            self.poisoned = true;
            return Err(fault);
        }
        // Only real successful original join/body and C permit this lock.
        // Error/timeout/creation-panic paths never wait on an active work mutex.
        let work = match self.retained[index].0.lock() {
            Ok(work) => work,
            Err(_) => {
                self.poisoned = true;
                return Err(Fault::ClosingPending);
            }
        };
        if work.returned != Some(Ok(())) || work.panic.is_some() || work.app.is_none() {
            self.poisoned = true;
            return Err(Fault::ClosingPending);
        }
        Ok(())
    }

}
impl JournalWork {

    fn prepare_original_history(&mut self, expected: History, limits: Limits) -> Result<(), Fault> {
        // Only new known fixed DATA and transfer slots. Existing Work/Arc/closure
        // allocation is already paid by job/start_job. No opaque stack/Tokio credit.
        const FIXED_METADATA: u64 = {
            let slots = [
                (core::mem::size_of::<HistoryIo<'static>>(), core::mem::align_of::<HistoryIo<'static>>(), 3usize),
                (core::mem::size_of::<Option<&mut Option<Result<u64, Fault>>>>(), core::mem::align_of::<Option<&mut Option<Result<u64, Fault>>>>(), 3usize),
                (core::mem::size_of::<Option<&mut [Option<io::Result<Metadata>>;2]>>(), core::mem::align_of::<Option<&mut [Option<io::Result<Metadata>>;2]>>(), 3usize),
                (core::mem::size_of::<JournalHistoryFact>(), core::mem::align_of::<JournalHistoryFact>(), 2usize),
                (core::mem::size_of::<Result<JournalHistoryFact, Fault>>(), core::mem::align_of::<Result<JournalHistoryFact, Fault>>(), 2usize),
                (core::mem::size_of::<Option<Identity>>(), core::mem::align_of::<Option<Identity>>(), 2usize),
                (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 4usize),
                (core::mem::size_of::<JournalHistoryFact>(), core::mem::align_of::<JournalHistoryFact>(), 2usize),
                (core::mem::size_of::<Result<JournalHistoryFact, Fault>>(), core::mem::align_of::<Result<JournalHistoryFact, Fault>>(), 3usize),
                (core::mem::size_of::<Option<Result<JournalHistoryFact, Fault>>>(), core::mem::align_of::<Option<Result<JournalHistoryFact, Fault>>>(), 1usize),
                (core::mem::size_of::<Result<History, Fault>>(), core::mem::align_of::<Result<History, Fault>>(), 2usize),
                (core::mem::size_of::<History>(), core::mem::align_of::<History>(), 2usize),
                (core::mem::size_of::<Limits>(), core::mem::align_of::<Limits>(), 1usize),
                (core::mem::size_of::<[super::OriginalControlRootObservation; 4]>(), core::mem::align_of::<[super::OriginalControlRootObservation; 4]>(), 2usize),
                (core::mem::size_of::<(usize, [super::OriginalControlRootObservation; 4])>(), core::mem::align_of::<(usize, [super::OriginalControlRootObservation; 4])>(), 1usize),
                (core::mem::size_of::<[(&File, usize); 3]>(), core::mem::align_of::<[(&File, usize); 3]>(), 1usize),
                (core::mem::size_of::<std::array::IntoIter<(&File, usize), 3>>(), core::mem::align_of::<std::array::IntoIter<(&File, usize), 3>>(), 1usize),
                (core::mem::size_of::<(&File, usize)>(), core::mem::align_of::<(&File, usize)>(), 1usize),
                (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 3usize),
                (core::mem::size_of::<RecordIdentity>(), core::mem::align_of::<RecordIdentity>(), 2usize),
                (core::mem::size_of::<(RecordIdentity, u64)>(), core::mem::align_of::<(RecordIdentity, u64)>(), 2usize),
                (core::mem::size_of::<Result<(RecordIdentity, u64), Fault>>(), core::mem::align_of::<Result<(RecordIdentity, u64), Fault>>(), 2usize),
                (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 1usize),
                (core::mem::size_of::<std::sync::MutexGuard<'static, super::CaptureResourceTotals>>(), core::mem::align_of::<std::sync::MutexGuard<'static, super::CaptureResourceTotals>>(), 1usize),
                (core::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, super::CaptureResourceTotals>>>(), core::mem::align_of::<std::sync::LockResult<std::sync::MutexGuard<'static, super::CaptureResourceTotals>>>(), 1usize),
                (core::mem::size_of::<Result<(), std::collections::TryReserveError>>(), core::mem::align_of::<Result<(), std::collections::TryReserveError>>(), 1usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 5usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 3usize),
                (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 2usize),
                (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 2usize),
            ];
            let mut at = 0usize;
            let mut bytes = 0usize;
            while at < slots.len() {
                bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                    .expect("fixed history layout fits usize").checked_mul(slots[at].2)
                    .expect("fixed history count fits usize"))
                    .expect("fixed history slots fit usize");
                at += 1;
            }
            assert!(usize::BITS <= u64::BITS);
            bytes as u64
        };
        if self.destination_identities[0].is_some() || self.destination_identities[1].is_some() {
            return Err(Fault::IntentMismatch);
        }
        self.clock.require_effect()?;
        super::reserve_capture_resources(&self.clock.resources, 0,
            FIXED_METADATA.checked_add(ORIGINAL_CONTROL_ALLOCATION_METADATA).ok_or(Fault::BoundsOverflow)?)?;
        let returned = (|| {
            let (count, roots) = {
                let totals = self.clock.resources.lock().map_err(|_| Fault::ClosingPending)?;
                if totals.owner_instance != self.clock.owner_instance()
                    || totals.original_control_storage.original_owner != totals.owner_instance
                    || !totals.original_control_storage.classified { return Err(Fault::IntentMismatch); }
                (totals.original_control_storage.objects.len(), totals.original_control_storage.roots)
            };
            let bitmap = count.checked_add(7).ok_or(Fault::BoundsOverflow)? / 8;
            if !self.history_matched.is_empty() || self.history_matched.capacity() != 0
                || self.history_result.is_some() { return Err(Fault::IntentMismatch); }
            self.clock.require_effect()?;
            super::reserve_capture_resources(&self.clock.resources, 0,
                u64::try_from(bitmap).map_err(|_| Fault::BoundsOverflow)?)?;
            self.history_matched.try_reserve_exact(bitmap).map_err(|_| Fault::CapacityExceeded)?;
            if self.history_matched.capacity() != bitmap { return Err(Fault::CapacityExceeded); }
            self.history_matched.resize(bitmap, 0);
            self.clock.require_effect()?;
            let JournalWork { app, control, clock, files, bytes,
                history_output, history_key, history_dir, history_frames,
                history_matched, history_io, fs_admission, fs_observations, .. } = self;
            let app = app.as_ref().ok_or(Fault::IntentMismatch)?;
            let output = history_output.as_ref().ok_or(Fault::IntentMismatch)?;
            let key = history_key.as_ref().ok_or(Fault::IntentMismatch)?;
            let mut io = HistoryIo { fs_admission: Some(&mut *fs_admission), fs_observations: Some(&mut *fs_observations),  clock: Some((clock.as_ref(), false)), original_objects: Some(count), maximum_files: 2,
                files: &mut *files, directory: &mut *history_dir, frames: &mut *history_frames,
                matched: &mut *history_matched, raw: &mut *history_io, bytes: &mut *bytes };
            // Original held app/output/key facts, not a second path open or a
            // replacement object table. The book mutex never spans IO.
            for (held, index) in [(app, 0usize), (output, 2usize), (key, 3usize)] {
                let before = io.metadata(HistoryFd::Original(held))?;
                if !before.is_dir() || before.uid() != rustix::process::geteuid().as_raw()
                    || before.mode() & 0o7777 != 0o700 { return Err(Fault::PathUnsafe); }
                match roots[index] {
                    super::OriginalControlRootObservation::Present { device, inode }
                        if (device, inode) == (before.dev(), before.ino()) => {}
                    _ => return Err(Fault::SourceChanged),
                }
                let after = io.metadata(HistoryFd::Original(held))?;
                if RecordIdentity::of(&before) != RecordIdentity::of(&after)
                    || before.blocks() != after.blocks() { return Err(Fault::SourceChanged); }
                io.observe(&after, 0)?;
            }
            if let Some(root) = control.as_ref() {
                let before = io.metadata(HistoryFd::Original(root))?;
                match roots[1] {
                    super::OriginalControlRootObservation::Present { device, inode }
                        if (device, inode) == (before.dev(), before.ino()) => {}
                    _ => return Err(Fault::SourceChanged),
                }
                history_named_identity(HistoryFd::Original(app), CONTROL,
                    RecordIdentity::of(&before), true, &mut io)?;
                let actual = scan_closed_history_observed(HistoryFd::Original(root), &limits,
                    7, None, &mut io, None)?;
                if actual != expected { return Err(Fault::SourceChanged); }
                let after = io.metadata(HistoryFd::Original(root))?;
                if RecordIdentity::of(&before) != RecordIdentity::of(&after)
                    || before.blocks() != after.blocks() { return Err(Fault::SourceChanged); }
                history_named_identity(HistoryFd::Original(app), CONTROL,
                    RecordIdentity::of(&after), true, &mut io)?;
                io.observe(&after, 0)?;
                io.complete_facts()?;
                io.guard()?;
                super::mark_original_control_growth_after_history(&clock.resources, clock.owner_instance())?;
                Ok(JournalHistoryFact::Existing(actual, Identity::of(&after)))
            } else {
                if !matches!(roots[1], super::OriginalControlRootObservation::Absent)
                    || expected != History::default() { return Err(Fault::SourceChanged); }
                io.absent(HistoryFd::Original(app), CONTROL)?;
                io.complete_facts()?;
                io.guard()?;
                super::mark_original_control_growth_after_history(&clock.resources, clock.owner_instance())?;
                drop(io);
                // The actual NOENT above does not authorize adoption on EEXIST.
                // The original exclusive New operation and owner slot remain.
                let mut io = HistoryIo { fs_admission: Some(&mut *fs_admission), fs_observations: Some(&mut *fs_observations),  clock: Some((clock.as_ref(), false)), original_objects: None, maximum_files: 2,
                    files: &mut *files, directory: &mut *history_dir, frames: &mut *history_frames,
                    matched: &mut *history_matched, raw: &mut *history_io, bytes: &mut *bytes };
                place_directory(app, CONTROL, clock, control, DirectoryMode::New, &mut io)?;
                sync(app, clock, &mut io)?;
                let root = control.as_ref().ok_or(Fault::IntentMismatch)?;
                let (identity, blocks) = io.start_entries(HistoryFd::Original(root))?;
                while let Some(name) = io.next_name(HistoryFd::Original(root))? {
                    if name != b"." && name != b".." { return Err(Fault::ClosingPending); }
                }
                // This is a real empty EOF on the new held FD, never an empty
                // History passed to the strict Existing grammar.
                io.finish_entries(HistoryFd::Original(root), identity, blocks, false)?;
                history_named_identity(HistoryFd::Original(app), CONTROL, identity, true, &mut io)?;
                io.guard()?;
                Ok(JournalHistoryFact::NewlyCreatedEmpty(identity.identity))
            }
        })();
        // Complete DATA result first; every resource-bearing IO result/FD/frame
        // already lives in this same original Work on all error/unwind paths.
        self.history_result = Some(returned);
        returned?;
        {
            // Retain the original complete history Result independently of
            // these original later destination observations. A later failure
            // is kept by the same Work.returned, never replacing the history.
            let JournalWork { clock, files, bytes, history_output, history_key,
                history_dir, history_frames, history_matched, history_io,
                destination_identities, fs_admission, fs_observations, .. } = self;
            let output = history_output.as_ref().ok_or(Fault::IntentMismatch)?;
            let key = history_key.as_ref().ok_or(Fault::IntentMismatch)?;
            let mut io = HistoryIo { fs_admission: Some(&mut *fs_admission), fs_observations: Some(&mut *fs_observations),  clock: Some((clock.as_ref(), false)), original_objects: None, maximum_files: 2,
                files: &mut *files, directory: &mut *history_dir, frames: &mut *history_frames,
                matched: &mut *history_matched, raw: &mut *history_io, bytes: &mut *bytes };
            destination_identities[0] = Some(runtime_identity(output, clock, &mut io)?);
            destination_identities[1] = Some(runtime_identity(key, clock, &mut io)?);
        }
        self.clock.require_effect()
    }
    fn write_intent(&mut self, child_mode: DirectoryMode) -> Result<(), Fault> {
        if !self.first || self.record_results[0].is_some() || self.record_results[1].is_some()
            || self.record_results[2].is_some() || self.record_results[3].is_some()
            || self.operation_path.is_some()
        { return Err(Fault::IntentMismatch); }
        {
            let mut io = HistoryIo { fs_admission: Some(&mut self.fs_admission), fs_observations: Some(&mut self.fs_observations),  clock: Some((self.clock.as_ref(), false)),
                original_objects: None, maximum_files: 4, files: &mut self.record_files,
                directory: &mut self.history_dir, frames: &mut self.history_frames,
                matched: &mut self.history_matched, raw: &mut self.history_io,
                bytes: &mut self.record_bytes };
            let root = self.control.as_ref().ok_or(Fault::IntentMismatch)?;
            place_directory(root, "requests", &self.clock, &mut self.requests, child_mode, &mut io)?;
            place_directory(root, "operations", &self.clock, &mut self.operations, child_mode, &mut io)?;
            create_record(self.requests.as_ref().ok_or(Fault::IntentMismatch)?,
                &self.request_name, &self.request_bytes, &self.clock, false,
                self.reserve, self.floor, self.allocation, &mut self.files,
                &mut io, &mut self.record_results[0])?;
            place_directory(self.operations.as_ref().ok_or(Fault::IntentMismatch)?,
                &self.operation_name, &self.clock, &mut self.operation_directory,
                DirectoryMode::New, &mut io)?;
            sync(self.operations.as_ref().ok_or(Fault::IntentMismatch)?, &self.clock, &mut io)?;
            create_record(self.operation_directory.as_ref().ok_or(Fault::IntentMismatch)?,
                &self.name, &self.bytes, &self.clock, false,
                self.reserve, self.floor, self.allocation, &mut self.files,
                &mut io, &mut self.record_results[1])?;
        }
        self.confirm(2)?;
        {
            let mut io = HistoryIo { fs_admission: Some(&mut self.fs_admission), fs_observations: Some(&mut self.fs_observations),  clock: Some((self.clock.as_ref(), false)),
                original_objects: None, maximum_files: 4, files: &mut self.record_files,
                directory: &mut self.history_dir, frames: &mut self.history_frames,
                matched: &mut self.history_matched, raw: &mut self.history_io,
                bytes: &mut self.record_bytes };
            runtime_bound_path(self.operation_directory.as_ref().ok_or(Fault::IntentMismatch)?,
                &self.clock, &mut io, &mut self.operation_path)
        }
    }
    fn confirm(&mut self, readback_base: usize) -> Result<(), Fault> {
        if !matches!(readback_base, 0 | 2) { return Err(Fault::IntentMismatch); }
        let request_slot = readback_base.checked_add(1).ok_or(Fault::BoundsOverflow)?;
        if self.record_results.get(readback_base).ok_or(Fault::IntentMismatch)?.is_some()
            || self.record_results.get(request_slot).ok_or(Fault::IntentMismatch)?.is_some()
        { return Err(Fault::IntentMismatch); }
        self.clock.require_effect()?;
        let mut io = HistoryIo { fs_admission: Some(&mut self.fs_admission), fs_observations: Some(&mut self.fs_observations),  clock: Some((self.clock.as_ref(), false)),
            original_objects: None, maximum_files: 4, files: &mut self.record_files,
            directory: &mut self.history_dir, frames: &mut self.history_frames,
            matched: &mut self.history_matched, raw: &mut self.history_io,
            bytes: &mut self.record_bytes };
        let root = self.control.as_ref().ok_or(Fault::IntentMismatch)?;
        verify_named_directory(self.app.as_ref().ok_or(Fault::IntentMismatch)?, CONTROL, root, &self.clock, &mut io)?;
        if self.requests.is_none() {
            place_directory(
                root,
                "requests",
                &self.clock,
                &mut self.requests,
                DirectoryMode::Existing,
                &mut io,
            )?;
        }
        if self.operations.is_none() {
            place_directory(
                root,
                "operations",
                &self.clock,
                &mut self.operations,
                DirectoryMode::Existing,
                &mut io,
            )?;
        }
        let requests = self.requests.as_ref().ok_or(Fault::IntentMismatch)?;
        let operations = self.operations.as_ref().ok_or(Fault::IntentMismatch)?;
        let op = self
            .operation_directory
            .as_ref()
            .ok_or(Fault::IntentMismatch)?;
        verify_named_directory(root, "requests", requests, &self.clock, &mut io)?;
        verify_named_directory(root, "operations", operations, &self.clock, &mut io)?;
        verify_named_directory(operations, &self.operation_name, op, &self.clock, &mut io)?;
        {
            if self.intent_identity.is_none() || self.request_identity.is_none() {
                self.request_identity = Some(runtime_record_identity(
                    self.files.first().ok_or(Fault::IntentMismatch)?, &self.clock, &mut io,
                )?);
                self.intent_identity = Some(runtime_record_identity(
                    self.files.get(1).ok_or(Fault::IntentMismatch)?, &self.clock, &mut io,
                )?);
            }
            read_bound_record_resident(op, "00000000-intent.json", self.limit,
                self.intent_identity, &mut io, &mut self.record_results[readback_base])?;
            // The original comparison follows BOTH real reads. A content
            // mismatch in the first completed body does not skip the second.
            read_bound_record_resident(requests, &self.request_name, self.limit,
                self.request_identity, &mut io, &mut self.record_results[request_slot])?;
        }
        let observed = match self.record_results[readback_base].as_ref() {
            Some(Ok((_, body))) => body,
            Some(Err(fault)) => return Err(*fault),
            None => return Err(Fault::IntentMismatch),
        };
        let request = match self.record_results[request_slot].as_ref() {
            Some(Ok((_, body))) => body,
            Some(Err(fault)) => return Err(*fault),
            None => return Err(Fault::IntentMismatch),
        };
        if observed != &self.bytes || request != &self.request_bytes {
            return Err(Fault::IntentMismatch);
        }
        verify_named_directory(self.app.as_ref().ok_or(Fault::IntentMismatch)?, CONTROL, root, &self.clock, &mut io)?;
        verify_named_directory(root, "requests", requests, &self.clock, &mut io)?;
        verify_named_directory(root, "operations", operations, &self.clock, &mut io)?;
        verify_named_directory(operations, &self.operation_name, op, &self.clock, &mut io)?;
        self.clock.require_effect()
    }
    fn write_stage(&mut self, closing: bool) -> Result<(), Fault> {
        if self.record_results[0].is_some() { return Err(Fault::IntentMismatch); }
        // New phase records require E; the only C path records already-issued outcomes.
        let guard = || {
            if closing {
                self.clock.require_closing()
            } else {
                self.clock.require_effect()
            }
        };
        guard()?;
        let mut io = HistoryIo { fs_admission: Some(&mut self.fs_admission), fs_observations: Some(&mut self.fs_observations),  clock: Some((self.clock.as_ref(), closing)),
            original_objects: None, maximum_files: 4, files: &mut self.record_files,
            directory: &mut self.history_dir, frames: &mut self.history_frames,
            matched: &mut self.history_matched, raw: &mut self.history_io,
            bytes: &mut self.record_bytes };
        let root = self.control.as_ref().ok_or(Fault::IntentMismatch)?;
        let op = self
            .operation_directory
            .as_ref()
            .ok_or(Fault::IntentMismatch)?;
        if !closing {
            verify_named_directory(self.app.as_ref().ok_or(Fault::IntentMismatch)?, CONTROL, root, &self.clock, &mut io)?;
            if self.operations.is_none() {
                place_directory(
                    root,
                    "operations",
                    &self.clock,
                    &mut self.operations,
                    DirectoryMode::Existing,
                    &mut io,
                )?;
            }
            let ops = self.operations.as_ref().ok_or(Fault::IntentMismatch)?;
            verify_named_directory(root, "operations", ops, &self.clock, &mut io)?;
            verify_named_directory(ops, &self.operation_name, op, &self.clock, &mut io)?;
        }
        {
            create_record(
                op,
                &self.name,
                &self.bytes,
                &self.clock,
                closing,
                self.reserve,
                self.floor,
                self.allocation,
                &mut self.files,
                &mut io,
                &mut self.record_results[0],
            )?;
        }
        if !closing {
            let ops = self.operations.as_ref().ok_or(Fault::IntentMismatch)?;
            verify_named_directory(self.app.as_ref().ok_or(Fault::IntentMismatch)?, CONTROL, root, &self.clock, &mut io)?;
            verify_named_directory(root, "operations", ops, &self.clock, &mut io)?;
            verify_named_directory(ops, &self.operation_name, op, &self.clock, &mut io)?;
        }
        guard()?;
        Ok(())
    }
}

/// Ordinary setup invokes this after the kernel lease and before reclaim/load_or_create.
pub(crate) fn inspect_startup_control(
    app: &File,
    profile: Option<&CaptureProfile>,
) -> Result<(), Fault> {
    match optional_directory(app, CONTROL)? {
        None => Ok(()),
        Some(root) => {
            let limits = Limits::from_profile(profile.ok_or(Fault::ClosingPending)?)?;
            scan_closed_history(&root, &limits, 1, None, None).map(|_| ())
        }
    }
}
pub(in crate::tauri_background) fn inspect_startup_control_for_capture(
    app: &File,
    profile: Option<&CaptureProfile>,
    reviewed_request_id: Option<&str>,
    resources: Option<&Arc<std::sync::Mutex<super::CaptureResourceTotals>>>,
) -> Result<OriginalControlHistoryFootprint, Fault> {
    // The noncapture branch keeps the original classification and IO behavior.
    if resources.is_none() {
        inspect_startup_control(app, profile)?;
        return Ok(OriginalControlHistoryFootprint::unobserved());
    }
    let profile = profile.ok_or(Fault::ClosingPending)?;
    let reviewed_request_id = reviewed_request_id.ok_or(Fault::IntentMismatch)?;
    if !digest_text(reviewed_request_id) { return Err(Fault::IntentMismatch); }
    super::original_capture_resource_identity(
        resources.expect("checked original book exists"), &profile.carrier_bounds()?,
    )?;
    let limits = Limits::from_profile(profile)?;
    let app_before = app.metadata().map_err(io_fault)?;
    private_directory(app)?;
    let mut completed = false;
    let observation = match optional_directory(app, CONTROL)? {
        None => OriginalControlHistoryObservation::Absent { app: Identity::of(&app_before) },
        Some(root) => {
            let before = root.metadata().map_err(io_fault)?;
            let history = scan_closed_history(&root, &limits, 1, None,
                Some((reviewed_request_id, &mut completed)))?;
            let after = root.metadata().map_err(io_fault)?;
            if RecordIdentity::of(&before) != RecordIdentity::of(&after)
                || before.blocks() != after.blocks()
            {
                return Err(Fault::ClosingPending);
            }
            ordinary_named_identity(app, CONTROL, RecordIdentity::of(&after), true)?;
            OriginalControlHistoryObservation::Present {
                app: Identity::of(&app_before), root: RecordIdentity::of(&after),
                blocks: after.blocks(), history,
            }
        }
    };
    let app_after = app.metadata().map_err(io_fault)?;
    if RecordIdentity::of(&app_before) != RecordIdentity::of(&app_after)
        || app_before.blocks() != app_after.blocks()
    {
        return Err(Fault::ClosingPending);
    }
    let completed_request = if completed {
        let mut id = [0u8; 64];
        id.copy_from_slice(reviewed_request_id.as_bytes());
        Some(id)
    } else { None };
    Ok(OriginalControlHistoryFootprint { observation, completed_request })
}

// These are bounded result/scratch DATA inside the one original JournalWork.
// They contain no second owner, task, clock or source grant.
enum JournalHistoryIoResult {
    Open(rustix::io::Result<rustix::fd::OwnedFd>),
    Dir(rustix::io::Result<rustix::fs::Dir>),
    Next(Option<rustix::io::Result<rustix::fs::DirEntry>>),
    Metadata(io::Result<Metadata>),
    Stat(rustix::io::Result<rustix::fs::Stat>),
    Read(io::Result<usize>),
    StatVfs(rustix::io::Result<rustix::fs::StatVfs>),
    Write(io::Result<usize>),
    Sync(io::Result<()>),
    Mkdir(rustix::io::Result<()>),
    GetPath(rustix::io::Result<std::ffi::CString>),
}
#[derive(Clone, Copy)]
enum JournalHistoryFact {
    Existing(History, Identity),
    NewlyCreatedEmpty(Identity),
}
#[derive(Clone, Copy)]
enum HistoryFd<'a> {
    Original(&'a File),
    Frame(usize),
    Temporary(usize),
}
struct HistoryIo<'a> {
    clock: Option<(&'a CaptureOperation, bool)>,
    original_objects: Option<usize>,
    maximum_files: usize,
    files: &'a mut Vec<File>,
    directory: &'a mut Option<rustix::fs::Dir>,
    frames: &'a mut Vec<ClosedNativeFrame>,
    matched: &'a mut Vec<u8>,
    raw: &'a mut Option<JournalHistoryIoResult>,
    bytes: &'a mut Vec<u8>,
    fs_admission: Option<&'a mut Option<Result<u64, Fault>>>,
    fs_observations: Option<&'a mut [Option<io::Result<Metadata>>;2]>,
}
impl HistoryIo<'_> {

    fn admit_original_allocation(
        &mut self, parent: &File, planned_bytes: u64, new_objects: usize,
    ) -> Result<(), Fault> {
        let (clock, _) = self.clock.ok_or(Fault::IntentMismatch)?;
        if self.original_objects.is_some() || self.fs_admission.is_none()
            || self.fs_observations.is_none()
        { return Err(Fault::IntentMismatch); }
        self.admit(0, ORIGINAL_CONTROL_ALLOCATION_METADATA)?;
        {
            let totals = clock.resources.lock().map_err(|_| Fault::ClosingPending)?;
            if totals.owner_instance != clock.owner_instance() {
                return Err(Fault::IntentMismatch);
            }
            if totals.original_control_storage.allocation_update_pending {
                return Err(Fault::ClosingPending);
            }
        }
        {
            let admission = self.fs_admission.as_deref_mut().ok_or(Fault::IntentMismatch)?;
            let observations = self.fs_observations.as_deref_mut().ok_or(Fault::IntentMismatch)?;
            match admission.as_ref() {
                None if observations.iter().all(Option::is_none) => {}
                Some(Ok(_)) if observations.iter().all(|value| matches!(value, Some(Ok(_)))) => {
                    // Only a completed successful observation pair can retire at this grammar edge.
                    admission.take();
                    observations[0].take();
                    observations[1].take();
                }
                _ => return Err(Fault::ClosingPending),
            }
        }
        self.before_io(0)?;
        let actual = parent.metadata();
        self.fs_observations.as_deref_mut().ok_or(Fault::IntentMismatch)?[0] = Some(actual);
        self.guard()?;
        let parent_identity = {
            let observations = self.fs_observations.as_deref().ok_or(Fault::IntentMismatch)?;
            let metadata = match observations[0].as_ref() {
                Some(Ok(value)) => value,
                Some(Err(_)) => return Err(Fault::IoFailure),
                None => return Err(Fault::IntentMismatch),
            };
            if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o700
            { return Err(Fault::PathUnsafe); }
            Identity::of(metadata)
        };
        self.before_io(0)?;
        let actual = rustix::fs::fstatvfs(parent);
        *self.raw = Some(JournalHistoryIoResult::StatVfs(actual));
        self.guard()?;
        let (grain, available) = match self.raw.as_ref() {
            Some(JournalHistoryIoResult::StatVfs(Ok(value))) => (
                value.f_frsize.max(value.f_bsize).max(512),
                value.f_bavail.checked_mul(value.f_frsize).ok_or(Fault::BoundsOverflow)?,
            ),
            Some(JournalHistoryIoResult::StatVfs(Err(_))) => return Err(Fault::IoFailure),
            _ => return Err(Fault::IntentMismatch),
        };
        let rounded = planned_bytes.checked_add(grain - 1).ok_or(Fault::BoundsOverflow)?
            .checked_div(grain).ok_or(Fault::BoundsOverflow)?
            .checked_mul(grain).ok_or(Fault::BoundsOverflow)?;
        // Finite operation admission only; no exclusive kernel reservation is asserted.
        let plan = rounded.checked_add(grain.checked_mul(2).ok_or(Fault::BoundsOverflow)?)
            .ok_or(Fault::BoundsOverflow)?;
        let reserve = clock.profile().carrier.capacity_reserve_bytes
            .max(clock.profile().native.capacity_reserve_bytes);
        let floor = clock.profile().carrier.free_floor_bytes
            .max(clock.profile().native.free_floor_bytes);
        if available < plan.checked_add(reserve.max(floor)).ok_or(Fault::BoundsOverflow)? {
            return Err(Fault::CapacityExceeded);
        }
        self.guard()?;
        let actual = super::reserve_original_control_growth(
            &clock.resources, clock.owner_instance(), parent_identity.device,
            parent_identity.inode, plan, new_objects,
        );
        *self.fs_admission.as_deref_mut().ok_or(Fault::IntentMismatch)? = Some(actual);
        actual?;
        Ok(())
    }

    fn observe_original_allocation(
        &mut self, parent: &File, child: &File,
    ) -> Result<(), Fault> {
        let (clock, _) = self.clock.ok_or(Fault::IntentMismatch)?;
        if self.original_objects.is_some()
            || !matches!(self.fs_admission.as_deref(), Some(Some(Ok(_))))
        { return Err(Fault::IntentMismatch); }
        self.admit(0, ORIGINAL_CONTROL_ALLOCATION_METADATA)?;
        {
            let observations = self.fs_observations.as_deref_mut().ok_or(Fault::IntentMismatch)?;
            if !matches!(observations[0], Some(Ok(_))) || observations[1].is_some() {
                return Err(Fault::IntentMismatch);
            }
            // The original effect and its postcheck succeeded; replace only the old
            // successful pre-admission metadata, never an error or unknown result.
            observations[0].take();
        }
        self.before_io(0)?;
        let actual = parent.metadata();
        self.fs_observations.as_deref_mut().ok_or(Fault::IntentMismatch)?[0] = Some(actual);
        self.guard()?;
        if !matches!(self.fs_observations.as_deref().ok_or(Fault::IntentMismatch)?[0], Some(Ok(_))) {
            return Err(Fault::IoFailure);
        }
        self.before_io(0)?;
        let actual = child.metadata();
        self.fs_observations.as_deref_mut().ok_or(Fault::IntentMismatch)?[1] = Some(actual);
        self.guard()?;
        let observations = self.fs_observations.as_deref().ok_or(Fault::IntentMismatch)?;
        let parent = match observations[0].as_ref() {
            Some(Ok(value)) => value,
            Some(Err(_)) => return Err(Fault::IoFailure),
            None => return Err(Fault::IntentMismatch),
        };
        let child = match observations[1].as_ref() {
            Some(Ok(value)) => value,
            Some(Err(_)) => return Err(Fault::IoFailure),
            None => return Err(Fault::IntentMismatch),
        };
        if !parent.is_dir() || parent.mode() & 0o7777 != 0o700
            || parent.uid() != rustix::process::geteuid().as_raw()
            || child.uid() != parent.uid() || child.dev() != parent.dev()
            || !(child.is_dir() && child.mode() & 0o7777 == 0o700
                || child.is_file() && child.mode() & 0o7777 == 0o600 && child.nlink() == 1)
        { return Err(Fault::PathUnsafe); }
        super::observe_original_control_allocation(
            &clock.resources, clock.owner_instance(),
            [(parent.dev(), parent.ino(), parent.blocks()),
             (child.dev(), child.ino(), child.blocks())],
        )
    }
    fn guard(&self) -> Result<(), Fault> {
        match self.clock {
            Some((clock, true)) => clock.require_closing(),
            Some((clock, false)) => clock.require_effect(),
            None => Ok(()),
        }
    }
    fn admit(&self, fds: u64, bytes: u64) -> Result<(), Fault> {
        // Every following allocation has its full requested logical backing and
        // these concrete return/header/transfer slots paid first. Allocator
        // internals and physical stack pages remain separate unproved inputs.
        const SLOTS: u64 = {
            let slots = [
                (core::mem::size_of::<Result<(), std::collections::TryReserveError>>(), core::mem::align_of::<Result<(), std::collections::TryReserveError>>(), 2usize),
                (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 2usize),
                (core::mem::size_of::<Vec<String>>(), core::mem::align_of::<Vec<String>>(), 1usize),
                (core::mem::size_of::<String>(), core::mem::align_of::<String>(), 2usize),
                (core::mem::size_of::<ClosedNativeFrame>(), core::mem::align_of::<ClosedNativeFrame>(), 1usize),
                (core::mem::size_of::<Option<File>>(), core::mem::align_of::<Option<File>>(), 1usize),
                (core::mem::size_of::<Option<ClosedNativeFrame>>(), core::mem::align_of::<Option<ClosedNativeFrame>>(), 1usize),
                (core::mem::size_of::<Option<rustix::fs::Dir>>(), core::mem::align_of::<Option<rustix::fs::Dir>>(), 1usize),
                (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 3usize),
                (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 3usize),
                (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 2usize),
                (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 1usize),
                (core::mem::size_of::<&str>(), core::mem::align_of::<&str>(), 2usize),
            ];
            let mut at = 0usize;
            let mut n = 0usize;
            while at < slots.len() {
                n = n.checked_add(slots[at].0.checked_add(slots[at].1)
                    .expect("fixed history allocation layout fits usize").checked_mul(slots[at].2)
                    .expect("fixed history allocation count fits usize"))
                    .expect("fixed history allocation slots fit usize");
                at += 1;
            }
            assert!(usize::BITS <= u64::BITS);
            n as u64
        };
        self.guard()?;
        if let Some((clock, _)) = self.clock {
            super::reserve_capture_resources(&clock.resources, fds,
                bytes.checked_add(SLOTS).ok_or(Fault::BoundsOverflow)?)?;
        }
        self.guard()
    }
    fn before_io(&mut self, fds: u64) -> Result<(), Fault> {
        // A prior non-resource success can be retired only on the next normal
        // grammar edge. Actual errors and resource-bearing returns are retained.
        if let Some(value) = self.raw.as_ref() {
            let completed = matches!(value,
                JournalHistoryIoResult::Metadata(Ok(_)) |
                JournalHistoryIoResult::Stat(Ok(_)) |
                JournalHistoryIoResult::Read(Ok(_)) |
                JournalHistoryIoResult::StatVfs(Ok(_)) |
                JournalHistoryIoResult::Write(Ok(_)) |
                JournalHistoryIoResult::Sync(Ok(_)) |
                JournalHistoryIoResult::Mkdir(Ok(_)) |
                JournalHistoryIoResult::Next(None) |
                JournalHistoryIoResult::Next(Some(Ok(_))));
            if !completed { return Err(Fault::ClosingPending); }
            self.raw.take();
        }
        let slots = [
            // Actual return, enum construction, Option transfer and match return
            // are separate slots; no return-place optimization is assumed.
            (core::mem::size_of::<JournalHistoryIoResult>(), core::mem::align_of::<JournalHistoryIoResult>(), 3usize),
            (core::mem::size_of::<Option<JournalHistoryIoResult>>(), core::mem::align_of::<Option<JournalHistoryIoResult>>(), 2usize),
            (core::mem::size_of::<rustix::io::Result<rustix::fs::StatVfs>>(), core::mem::align_of::<rustix::io::Result<rustix::fs::StatVfs>>(), 1usize),
            (core::mem::size_of::<io::Result<usize>>(), core::mem::align_of::<io::Result<usize>>(), 1usize),
            (core::mem::size_of::<io::Result<()>>(), core::mem::align_of::<io::Result<()>>(), 1usize),
            (core::mem::size_of::<rustix::io::Result<()>>(), core::mem::align_of::<rustix::io::Result<()>>(), 1usize),
            (core::mem::size_of::<rustix::io::Result<std::ffi::CString>>(), core::mem::align_of::<rustix::io::Result<std::ffi::CString>>(), 1usize),
            (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 2usize),
            (core::mem::size_of::<Result<Metadata, Fault>>(), core::mem::align_of::<Result<Metadata, Fault>>(), 2usize),
            (core::mem::size_of::<Result<rustix::fs::Stat, Fault>>(), core::mem::align_of::<Result<rustix::fs::Stat, Fault>>(), 2usize),
            (core::mem::size_of::<rustix::fd::OwnedFd>(), core::mem::align_of::<rustix::fd::OwnedFd>(), 1usize),
            (core::mem::size_of::<File>(), core::mem::align_of::<File>(), 1usize),
            (core::mem::size_of::<HistoryFd<'_>>(), core::mem::align_of::<HistoryFd<'_>>(), 3usize),
            (core::mem::size_of::<Result<HistoryFd<'_>, Fault>>(), core::mem::align_of::<Result<HistoryFd<'_>, Fault>>(), 2usize),
            (core::mem::size_of::<(HistoryFd<'_>, RecordIdentity, u64)>(), core::mem::align_of::<(HistoryFd<'_>, RecordIdentity, u64)>(), 1usize),
            (core::mem::size_of::<Result<(HistoryFd<'_>, RecordIdentity, u64), Fault>>(), core::mem::align_of::<Result<(HistoryFd<'_>, RecordIdentity, u64), Fault>>(), 1usize),
            (core::mem::size_of::<Result<Option<Vec<u8>>, Fault>>(), core::mem::align_of::<Result<Option<Vec<u8>>, Fault>>(), 1usize),
            (core::mem::size_of::<Result<usize, Fault>>(), core::mem::align_of::<Result<usize, Fault>>(), 2usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 1usize),
            (core::mem::size_of::<Result<(), std::collections::TryReserveError>>(), core::mem::align_of::<Result<(), std::collections::TryReserveError>>(), 2usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 6usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 2usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 4usize),
            (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 2usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 2usize),
        ];
        // Conservatively include the constructed fixed array, its by-value
        // iterator payload and current tuple rather than assuming elision.
        let mut known = core::mem::size_of_val(&slots).checked_mul(2)
            .and_then(|n| n.checked_add(core::mem::size_of::<(usize, usize, usize)>().checked_mul(2)?))
            .and_then(|n| n.checked_add(core::mem::size_of::<usize>().checked_mul(4)?))
            .ok_or(Fault::BoundsOverflow)?;
        for (size, align, count) in slots {
            known = known.checked_add(size.checked_add(align).and_then(|n| n.checked_mul(count))
                .ok_or(Fault::BoundsOverflow)?).ok_or(Fault::BoundsOverflow)?;
        }
        self.admit(fds, u64::try_from(known).map_err(|_| Fault::BoundsOverflow)?)
    }
    fn file<'a>(&'a self, fd: HistoryFd<'a>) -> Result<&'a File, Fault> {
        match fd {
            HistoryFd::Original(file) => Ok(file),
            HistoryFd::Frame(index) => self.frames.get(index).map(|frame| &frame.file)
                .ok_or(Fault::IntentMismatch),
            HistoryFd::Temporary(index) => self.files.get(index).ok_or(Fault::IntentMismatch),
        }
    }
    fn metadata(&mut self, fd: HistoryFd<'_>) -> Result<Metadata, Fault> {
        self.before_io(0)?;
        let actual = self.file(fd)?.metadata();
        *self.raw = Some(JournalHistoryIoResult::Metadata(actual));
        self.guard()?;
        match self.raw.as_ref() {
            Some(JournalHistoryIoResult::Metadata(Ok(value))) => Ok(value.clone()),
            Some(JournalHistoryIoResult::Metadata(Err(_))) => Err(Fault::IoFailure),
            _ => Err(Fault::IntentMismatch),
        }
    }
    fn stat(&mut self, parent: HistoryFd<'_>, name: &str, fault: Fault) -> Result<rustix::fs::Stat, Fault> {
        self.before_io(0)?;
        let actual = rustix::fs::statat(self.file(parent)?, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
        *self.raw = Some(JournalHistoryIoResult::Stat(actual));
        self.guard()?;
        match self.raw.as_ref() {
            Some(JournalHistoryIoResult::Stat(Ok(value))) => Ok(*value),
            Some(JournalHistoryIoResult::Stat(Err(_))) => Err(if self.clock.is_some() { Fault::IoFailure } else { fault }),
            _ => Err(Fault::IntentMismatch),
        }
    }
    fn open(&mut self, parent: HistoryFd<'_>, name: &str, directory: bool, fault: Fault)
        -> Result<HistoryFd<'static>, Fault>
    {
        if !matches!(self.maximum_files, 2 | 4) { return Err(Fault::IntentMismatch); }
        if self.files.len() >= self.maximum_files { return Err(Fault::CapacityExceeded); }
        if self.files.capacity() < self.maximum_files {
            let backing = self.maximum_files.checked_mul(core::mem::size_of::<File>()).ok_or(Fault::BoundsOverflow)?;
            self.admit(0, u64::try_from(backing).map_err(|_| Fault::BoundsOverflow)?)?;
            self.files.try_reserve_exact(self.maximum_files.checked_sub(self.files.len()).ok_or(Fault::BoundsOverflow)?)
                .map_err(|_| Fault::CapacityExceeded)?;
            if self.files.capacity() != self.maximum_files { return Err(Fault::CapacityExceeded); }
        }
        if self.files.capacity() != self.maximum_files { return Err(Fault::CapacityExceeded); }
        self.before_io(1)?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC |
            if directory { OFlags::DIRECTORY } else { OFlags::NONBLOCK };
        let actual = rustix::fs::openat(self.file(parent)?, name, flags, Mode::empty());
        *self.raw = Some(JournalHistoryIoResult::Open(actual));
        self.guard()?;
        if matches!(self.raw.as_ref(), Some(JournalHistoryIoResult::Open(Err(_)))) {
            return Err(if self.clock.is_some() { Fault::IoFailure } else { fault });
        }
        let actual = self.raw.take();
        match actual {
            Some(JournalHistoryIoResult::Open(Ok(fd))) => {
                let index = self.files.len();
                // Capacity is checked before IO, so this move cannot grow backing.
                self.files.push(File::from(fd));
                Ok(HistoryFd::Temporary(index))
            }
            other => { *self.raw = other; Err(Fault::IntentMismatch) }
        }
    }
    fn absent(&mut self, parent: HistoryFd<'_>, name: &str) -> Result<(), Fault> {
        // Actual NOENT is inspected only after the complete open result is
        // resident and its matching original post-E succeeds.
        self.before_io(1)?;
        let actual = rustix::fs::openat(self.file(parent)?, name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty());
        *self.raw = Some(JournalHistoryIoResult::Open(actual));
        self.guard()?;
        if matches!(self.raw.as_ref(), Some(JournalHistoryIoResult::Open(Err(rustix::io::Errno::NOENT)))) {
            self.raw.take();
            Ok(())
        } else if self.clock.is_some()
            && matches!(self.raw.as_ref(), Some(JournalHistoryIoResult::Open(Err(_))))
        { Err(Fault::IoFailure) } else { Err(Fault::SourceChanged) }
    }
    fn grow_frames(&mut self, maximum: usize) -> Result<(), Fault> {
        if self.frames.len() >= maximum { return Err(Fault::CapacityExceeded); }
        if self.frames.len() < self.frames.capacity() { return Ok(()); }
        let required = self.frames.len().checked_add(1).ok_or(Fault::BoundsOverflow)?;
        let backing = required.checked_mul(core::mem::size_of::<ClosedNativeFrame>())
            .ok_or(Fault::BoundsOverflow)?;
        self.admit(0, u64::try_from(backing).map_err(|_| Fault::BoundsOverflow)?)?;
        self.frames.try_reserve_exact(required.checked_sub(self.frames.len()).ok_or(Fault::BoundsOverflow)?)
            .map_err(|_| Fault::CapacityExceeded)?;
        if self.frames.capacity() != required { return Err(Fault::CapacityExceeded); }
        Ok(())
    }
    fn directory(&mut self, parent: HistoryFd<'_>, name: &str, maximum: usize, unsafe_fault: Fault)
        -> Result<(HistoryFd<'static>, RecordIdentity, u64), Fault>
    {
        self.grow_frames(maximum)?;
        let fd = self.open(parent, name, true, Fault::ClosingPending)?;
        let metadata = self.metadata(fd)?;
        if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700 { return Err(unsafe_fault); }
        let identity = RecordIdentity::of(&metadata);
        let blocks = metadata.blocks();
        let HistoryFd::Temporary(index) = fd else { return Err(Fault::IntentMismatch); };
        if index.checked_add(1) != Some(self.files.len()) { return Err(Fault::IntentMismatch); }
        let file = self.files.pop().ok_or(Fault::IntentMismatch)?;
        let index = self.frames.len();
        self.frames.push(ClosedNativeFrame { file, entries: None, relative: String::new(), identity, blocks });
        Ok((HistoryFd::Frame(index), identity, blocks))
    }
    fn start_entries(&mut self, fd: HistoryFd<'_>) -> Result<(RecordIdentity, u64), Fault> {
        if self.directory.is_some() { return Err(Fault::IntentMismatch); }
        if let HistoryFd::Frame(index) = fd {
            if self.frames.get(index).ok_or(Fault::IntentMismatch)?.entries.is_some() {
                return Err(Fault::IntentMismatch);
            }
        }
        let before = self.metadata(fd)?;
        let identity = RecordIdentity::of(&before);
        let blocks = before.blocks();
        if let HistoryFd::Frame(index) = fd {
            let frame = self.frames.get(index).ok_or(Fault::IntentMismatch)?;
            if frame.identity != identity || frame.blocks != blocks { return Err(Fault::ClosingPending); }
        } else if !before.is_dir() || before.uid() != rustix::process::geteuid().as_raw()
            || before.mode() & 0o7777 != 0o700 { return Err(Fault::PathUnsafe); }
        self.before_io(1)?;
        let actual = rustix::fs::Dir::read_from(self.file(fd)?);
        *self.raw = Some(JournalHistoryIoResult::Dir(actual));
        self.guard()?;
        if matches!(self.raw.as_ref(), Some(JournalHistoryIoResult::Dir(Err(_)))) {
            return Err(Fault::IoFailure);
        }
        match self.raw.take() {
            Some(JournalHistoryIoResult::Dir(Ok(directory))) => {
                *self.directory = Some(directory);
                if let HistoryFd::Frame(index) = fd {
                    self.frames.get_mut(index).ok_or(Fault::IntentMismatch)?.entries = self.directory.take();
                }
                Ok((identity, blocks))
            }
            other => { *self.raw = other; Err(Fault::IntentMismatch) }
        }
    }
    fn next_name(&mut self, fd: HistoryFd<'_>) -> Result<Option<Vec<u8>>, Fault> {
        self.before_io(0)?;
        let actual = match fd {
            HistoryFd::Frame(index) => self.frames.get_mut(index).ok_or(Fault::IntentMismatch)?
                .entries.as_mut().ok_or(Fault::IntentMismatch)?.next(),
            HistoryFd::Original(_) => self.directory.as_mut().ok_or(Fault::IntentMismatch)?.next(),
            HistoryFd::Temporary(_) => return Err(Fault::IntentMismatch),
        };
        *self.raw = Some(JournalHistoryIoResult::Next(actual));
        self.guard()?;
        let length = match self.raw.as_ref() {
            Some(JournalHistoryIoResult::Next(None)) => return Ok(None),
            Some(JournalHistoryIoResult::Next(Some(Ok(entry)))) => entry.file_name().to_bytes().len(),
            Some(JournalHistoryIoResult::Next(Some(Err(_)))) => return Err(Fault::IoFailure),
            _ => return Err(Fault::IntentMismatch),
        };
        self.admit(0, u64::try_from(length).map_err(|_| Fault::BoundsOverflow)?)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| Fault::CapacityExceeded)?;
        if bytes.capacity() != length { return Err(Fault::CapacityExceeded); }
        match self.raw.as_ref() {
            Some(JournalHistoryIoResult::Next(Some(Ok(entry)))) => bytes.extend_from_slice(entry.file_name().to_bytes()),
            _ => return Err(Fault::IntentMismatch),
        }
        Ok(Some(bytes))
    }
    fn finish_entries(&mut self, fd: HistoryFd<'_>, identity: RecordIdentity, blocks: u64, observe: bool) -> Result<(), Fault> {
        self.guard()?;
        if !matches!(self.raw.as_ref(), Some(JournalHistoryIoResult::Next(None))) {
            return Err(Fault::IntentMismatch);
        }
        let after = self.metadata(fd)?;
        if RecordIdentity::of(&after) != identity || after.blocks() != blocks {
            return Err(Fault::ClosingPending);
        }
        if observe { self.observe(&after, 0)?; }
        self.guard()?;
        match fd {
            HistoryFd::Frame(index) => { self.frames.get_mut(index).ok_or(Fault::IntentMismatch)?.entries.take(); }
            HistoryFd::Original(_) => { self.directory.take(); }
            HistoryFd::Temporary(_) => return Err(Fault::IntentMismatch),
        }
        self.raw.take();
        self.guard()
    }
    fn retire(&mut self, fd: HistoryFd<'_>) -> Result<(), Fault> {
        self.guard()?;
        match fd {
            HistoryFd::Temporary(index) if index.checked_add(1) == Some(self.files.len()) => { self.files.pop(); Ok(()) }
            HistoryFd::Frame(index) if index.checked_add(1) == Some(self.frames.len()) => {
                if self.frames[index].entries.is_some() { return Err(Fault::IntentMismatch); }
                self.frames.pop(); Ok(())
            }
            _ => Err(Fault::IntentMismatch),
        }
    }
    fn observe(&mut self, metadata: &Metadata, retained: u64) -> Result<(), Fault> {
        let Some((clock, _)) = self.clock else { return Ok(()); };
        if self.original_objects.is_none() { return Ok(()); }
        let allocation = metadata.blocks().checked_mul(512).ok_or(Fault::BoundsOverflow)?;
        let index = {
            let totals = clock.resources.lock().map_err(|_| Fault::ClosingPending)?;
            let facts = &totals.original_control_storage;
            if totals.owner_instance != clock.owner_instance() || facts.original_owner != totals.owner_instance
                || !facts.classified || self.original_objects != Some(facts.objects.len()) { return Err(Fault::IntentMismatch); }
            let index = facts.objects.iter().position(|fact| fact.device == metadata.dev() && fact.inode == metadata.ino())
                .ok_or(Fault::SourceChanged)?;
            let fact = &facts.objects[index];
            if fact.allocation != allocation || fact.retained_prior != retained { return Err(Fault::SourceChanged); }
            index
        };
        let byte = self.matched.get_mut(index / 8).ok_or(Fault::CapacityExceeded)?;
        *byte |= 1u8 << (index % 8);
        Ok(())
    }
    fn complete_facts(&self) -> Result<(), Fault> {
        let Some((clock, _)) = self.clock else { return Ok(()); };
        let totals = clock.resources.lock().map_err(|_| Fault::ClosingPending)?;
        if totals.owner_instance != clock.owner_instance() || !totals.original_control_storage.classified
            || totals.original_control_storage.original_owner != totals.owner_instance
            || self.original_objects != Some(totals.original_control_storage.objects.len()) {
            return Err(Fault::IntentMismatch);
        }
        for index in 0..totals.original_control_storage.objects.len() {
            if self.matched.get(index / 8).is_none_or(|byte| byte & (1u8 << (index % 8)) == 0) {
                return Err(Fault::SourceChanged);
            }
        }
        Ok(())
    }
    fn read_into_at(&mut self, fd: HistoryFd<'_>, buffer: &mut [u8], offset: u64)
        -> Result<usize, Fault>
    {
        self.before_io(0)?;
        let actual = self.file(fd)?.read_at(buffer, offset);
        *self.raw = Some(JournalHistoryIoResult::Read(actual));
        self.guard()?;
        match self.raw.as_ref() {
            Some(JournalHistoryIoResult::Read(Ok(count))) => Ok(*count),
            Some(JournalHistoryIoResult::Read(Err(_))) => Err(Fault::IoFailure),
            _ => Err(Fault::IntentMismatch),
        }
    }
    fn buffer(&mut self, amount: usize) -> Result<(), Fault> {
        if self.bytes.capacity() < amount {
            self.admit(0, u64::try_from(amount).map_err(|_| Fault::BoundsOverflow)?)?;
            self.bytes.try_reserve_exact(amount.checked_sub(self.bytes.len()).ok_or(Fault::BoundsOverflow)?)
                .map_err(|_| Fault::CapacityExceeded)?;
            if self.bytes.capacity() != amount { return Err(Fault::CapacityExceeded); }
        }
        self.bytes.resize(amount, 0);
        Ok(())
    }
}


fn history_private_directory(fd: HistoryFd<'_>, io: &mut HistoryIo<'_>) -> Result<(), Fault> {
    let metadata = io.metadata(fd)?;
    if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700 { return Err(Fault::PathUnsafe); }
    Ok(())
}
fn history_named_identity(parent: HistoryFd<'_>, name: &str,
    expected: RecordIdentity, directory: bool, io: &mut HistoryIo<'_>) -> Result<(), Fault>
{
    let named = io.stat(parent, name, Fault::ClosingPending)?;
    if rustix::fs::FileType::from_raw_mode(named.st_mode) != if directory {
        rustix::fs::FileType::Directory
    } else { rustix::fs::FileType::RegularFile }
        || named.st_dev as u64 != expected.identity.device || named.st_ino != expected.identity.inode
        || named.st_uid != expected.identity.uid || u32::from(named.st_mode) != expected.mode
        || u64::from(named.st_nlink) != expected.links
        || u64::try_from(named.st_size).map_err(|_| Fault::ClosingPending)? != expected.length
    { return Err(Fault::ClosingPending); }
    Ok(())
}
fn history_bounded_names(fd: HistoryFd<'_>, l: &Limits, h: &mut History,
    maximum: u64, io: &mut HistoryIo<'_>) -> Result<Vec<String>, Fault>
{
    h.dirs = checked_add(h.dirs, 1)?;
    if h.dirs > l.dirs { return Err(Fault::CapacityExceeded); }
    let (identity, blocks) = io.start_entries(fd)?;
    let mut result = Vec::new();
    while let Some(bytes) = io.next_name(fd)? {
        if bytes == b"." || bytes == b".." { continue; }
        h.metadata = checked_add(h.metadata, bytes.len() as u64 + 128)?;
        if h.metadata > l.metadata || result.len() as u64 >= maximum { return Err(Fault::CapacityExceeded); }
        if result.len() == result.capacity() {
            let required = result.len().checked_add(1).ok_or(Fault::BoundsOverflow)?;
            let backing = required.checked_mul(core::mem::size_of::<String>()).ok_or(Fault::BoundsOverflow)?;
            io.admit(0, u64::try_from(backing).map_err(|_| Fault::BoundsOverflow)?)?;
            result.try_reserve_exact(1).map_err(|_| Fault::CapacityExceeded)?;
            if result.capacity() != required { return Err(Fault::CapacityExceeded); }
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Fault::PathUnsafe)?;
        io.admit(0, u64::try_from(text.len()).map_err(|_| Fault::BoundsOverflow)?)?;
        let mut name = String::new();
        name.try_reserve_exact(text.len()).map_err(|_| Fault::CapacityExceeded)?;
        if name.capacity() != text.len() { return Err(Fault::CapacityExceeded); }
        name.push_str(text);
        result.push(name);
    }
    io.finish_entries(fd, identity, blocks, true)?;
    result.sort();
    Ok(result)
}
fn history_names(fd: HistoryFd<'_>, l: &Limits, h: &mut History, io: &mut HistoryIo<'_>) -> Result<Vec<String>, Fault> {
    history_bounded_names(fd, l, h, l.records, io)
}
fn history_operation_names(fd: HistoryFd<'_>, l: &Limits, h: &mut History, io: &mut HistoryIo<'_>) -> Result<Vec<String>, Fault> {
    history_bounded_names(fd, l, h, checked_add(l.records, 5)?, io)
}
fn history_charge(dir: HistoryFd<'_>, name: &str, bytes: &[u8], l: &Limits,
    h: &mut History, io: &mut HistoryIo<'_>) -> Result<(), Fault>
{
    let file = io.open(dir, name, false, Fault::PathUnsafe)?;
    let metadata = io.metadata(file)?;
    h.bytes = checked_add(h.bytes, bytes.len() as u64)?;
    h.allocation = checked_add(h.allocation, metadata.blocks().checked_mul(512).ok_or(Fault::BoundsOverflow)?)?;
    h.records = checked_add(h.records, 1)?;
    if h.bytes > l.journal || h.retained_bytes()? > l.retained
        || h.allocation > l.allocation || h.records > l.records { return Err(Fault::CapacityExceeded); }
    io.retire(file)
}
fn history_read_record(parent: HistoryFd<'_>, name: &str, limit: u64, expected: Option<RecordIdentity>,
    objects: Option<&mut super::OriginalControlStorageFacts>, io: &mut HistoryIo<'_>) -> Result<Vec<u8>, Fault>
{
    let (index, length) = history_read_record_core(parent, name, limit, expected, objects, io)?;
    io.retire(HistoryFd::Temporary(index))?;
    io.bytes.truncate(length);
    Ok(std::mem::take(io.bytes))
}
fn history_read_record_core(parent: HistoryFd<'_>, name: &str, limit: u64, expected: Option<RecordIdentity>,
    mut objects: Option<&mut super::OriginalControlStorageFacts>, io: &mut HistoryIo<'_>) -> Result<(usize, usize), Fault>
{
    // New core/legacy-wrapper tuple returns are distinct from the actual body
    // and its original IO return slots. Charge before its first actual open.
    const CORE_TRANSFERS: u64 = {
        let slots = [
            (core::mem::size_of::<(usize, usize)>(), core::mem::align_of::<(usize, usize)>(), 3usize),
            (core::mem::size_of::<Result<(usize, usize), Fault>>(), core::mem::align_of::<Result<(usize, usize), Fault>>(), 3usize),
            (core::mem::size_of::<Result<Vec<u8>, Fault>>(), core::mem::align_of::<Result<Vec<u8>, Fault>>(), 2usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 2usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<Option<&mut super::OriginalControlStorageFacts>>(), core::mem::align_of::<Option<&mut super::OriginalControlStorageFacts>>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed record core layout fits usize").checked_mul(slots[at].2)
                .expect("fixed record core count fits usize"))
                .expect("fixed record core transfers fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    io.admit(0, CORE_TRANSFERS)?;
    let file = io.open(parent, name, false, Fault::PathUnsafe)?;
    let before = io.metadata(file)?;
    if !before.is_file() || before.nlink() != 1 || before.mode() & 0o7777 != 0o600
        || before.uid() != rustix::process::geteuid().as_raw()
        || expected.is_some_and(|value| value != RecordIdentity::of(&before)) { return Err(Fault::IntentMismatch); }
    if before.len() > limit { return Err(Fault::CapacityExceeded); }
    let length = usize::try_from(before.len()).map_err(|_| Fault::CapacityExceeded)?;
    io.buffer(length.max(1))?;
    let mut at = 0usize;
    // The same original bounded body; the actual backing remains in work on failure.
    while at < length {
        let end = length.min(at.checked_add(64 * 1024).ok_or(Fault::BoundsOverflow)?);
        io.before_io(0)?;
        let HistoryFd::Temporary(index) = file else { return Err(Fault::IntentMismatch); };
        let actual = io.files.get(index).ok_or(Fault::IntentMismatch)?
            .read_at(&mut io.bytes[at..end], at as u64);
        *io.raw = Some(JournalHistoryIoResult::Read(actual));
        io.guard()?;
        let count = match io.raw.as_ref() {
            Some(JournalHistoryIoResult::Read(Ok(count))) => *count,
            Some(JournalHistoryIoResult::Read(Err(_))) => return Err(Fault::IoFailure),
            _ => return Err(Fault::IntentMismatch),
        };
        if count == 0 { return Err(Fault::ShortRead); }
        at = at.checked_add(count).ok_or(Fault::BoundsOverflow)?;
    }
    // Keep the record buffer resident. A separate admitted byte holds the original tail probe.
    let tail_index = io.bytes.len();
    let total = tail_index.checked_add(1).ok_or(Fault::BoundsOverflow)?;
    if io.bytes.capacity() < total {
        io.admit(0, u64::try_from(total).map_err(|_| Fault::BoundsOverflow)?)?;
        io.bytes.try_reserve_exact(1).map_err(|_| Fault::CapacityExceeded)?;
        if io.bytes.capacity() != total { return Err(Fault::CapacityExceeded); }
    }
    io.bytes.push(0);
    io.before_io(0)?;
    let HistoryFd::Temporary(index) = file else { return Err(Fault::IntentMismatch); };
    let actual = io.files.get(index).ok_or(Fault::IntentMismatch)?
        .read_at(&mut io.bytes[tail_index..total], at as u64);
    *io.raw = Some(JournalHistoryIoResult::Read(actual));
    io.guard()?;
    let tail = match io.raw.as_ref() {
        Some(JournalHistoryIoResult::Read(Ok(count))) => *count,
        Some(JournalHistoryIoResult::Read(Err(_))) => return Err(Fault::IoFailure),
        _ => return Err(Fault::IntentMismatch),
    };
    let after = io.metadata(file)?;
    if tail != 0 || Identity::of(&after) != Identity::of(&before) || after.len() != before.len()
        || after.mtime() != before.mtime() || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime() || after.ctime_nsec() != before.ctime_nsec()
    { return Err(Fault::IntentMismatch); }
    let named = io.stat(parent, name, Fault::PathUnsafe)?;
    if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
        || (named.st_dev as u64, named.st_ino, named.st_uid) != (after.dev(), after.ino(), after.uid())
        || expected.is_some_and(|value| value != RecordIdentity::of(&after))
    { return Err(Fault::IntentMismatch); }
    if objects.is_some() || io.original_objects.is_some() {
        if RecordIdentity::of(&before) != RecordIdentity::of(&after) || before.blocks() != after.blocks()
            || u64::try_from(named.st_blocks).map_err(|_| Fault::IntentMismatch)? != after.blocks()
            || u64::try_from(named.st_size).map_err(|_| Fault::IntentMismatch)? != after.len()
            || u32::from(named.st_mode) != after.mode() || u64::from(named.st_nlink) != after.nlink()
        { return Err(Fault::IntentMismatch); }
        if let Some(objects) = objects.as_deref_mut() {
            objects.observe(after.dev(), after.ino(), after.blocks(), after.len())?;
        }
        io.observe(&after, after.len())?;
    }
    let HistoryFd::Temporary(index) = file else { return Err(Fault::IntentMismatch); };
    Ok((index, length))
}

fn scan_closed_history(root: &File, l: &Limits, caller_files: u64,
    objects: Option<&mut super::OriginalControlStorageFacts>,
    reviewed_request: Option<(&str, &mut bool)>) -> Result<History, Fault> {
    // Ordinary/pre-t0 ABI retains the same sole grammar. Only the original
    // first-t0 worker supplies the resident fields and original clock/book.
    let mut files = Vec::new();
    let mut directory = None;
    let mut frames = Vec::new();
    let mut matched = Vec::new();
    let mut raw = None;
    let mut bytes = Vec::new();
    let mut io = HistoryIo { fs_admission: None, fs_observations: None,  clock: None, original_objects: None, maximum_files: 2, files: &mut files,
        directory: &mut directory, frames: &mut frames, matched: &mut matched,
        raw: &mut raw, bytes: &mut bytes };
    scan_closed_history_observed(HistoryFd::Original(root), l, caller_files, objects, &mut io, reviewed_request)
}
fn scan_closed_history_observed(root: HistoryFd<'_>, l: &Limits, caller_files: u64,
    mut objects: Option<&mut super::OriginalControlStorageFacts>, io: &mut HistoryIo<'_>,
    reviewed_request: Option<(&str, &mut bool)>) -> Result<History, Fault> {
    if let Some((id, _)) = reviewed_request.as_ref() {
        if !digest_text(id) { return Err(Fault::IntentMismatch); }
    }
    let mut completed_request = false;
    history_private_directory(root, io)?;
    let mut h = History::default();
    let root_names = history_names(root, l, &mut h, io)?;
    if root_names != ["operations".to_string(), "requests".to_string()] {
        return Err(Fault::ClosingPending);
    }
    let maximum = usize::try_from(l.dirs).map_err(|_| Fault::CapacityExceeded)?;
    let reqs = io.directory(root, "requests", maximum, Fault::PathUnsafe)?.0;
    let ops = io.directory(root, "operations", maximum, Fault::PathUnsafe)?.0;
    let roots_before = if objects.is_some() || io.original_objects.is_some() {
        Some([io.metadata(root)?, io.metadata(reqs)?, io.metadata(ops)?])
    } else { None };
    let request_names = history_names(reqs, l, &mut h, io)?;
    let operation_names = history_names(ops, l, &mut h, io)?;
    if request_names.len() != operation_names.len() || request_names.is_empty() {
        return Err(Fault::ClosingPending);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut shared_roots: Option<([RecordIdentity; 3], [u64; 3])> = None;
    for name in request_names {
        let operation_start = h;
        let prefix = name.get(..64).ok_or(Fault::ClosingPending)?;
        if name.len() != 69 || !digest_text(prefix) || name.get(64..) != Some(".json") {
            return Err(Fault::ClosingPending);
        }
        let raw = history_read_record(reqs, &name, l.record, None, objects.as_deref_mut(), io)?;
        history_charge(reqs, &name, &raw, l, &mut h, io)?;
        let request: RequestRecord = decode(&raw)?;
        if request.schema != "wrokbot-capture-request"
            || request.version != 1
            || request.request_id != name[..64]
        {
            return Err(Fault::ClosingPending);
        }
        let opid = uuid_bytes(&request.operation_id)?;
        let op_name = hex(&opid);
        if !seen.insert(op_name.clone()) || operation_names.binary_search(&op_name).is_err() {
            return Err(Fault::ClosingPending);
        }
        let op = io.directory(ops, &op_name, maximum, Fault::PathUnsafe)?.0;
        let op_before = if objects.is_some() || io.original_objects.is_some() { Some(io.metadata(op)?) } else { None };
        let mut records = history_operation_names(op, l, &mut h, io)?;
        let new_layout = match records
            .binary_search_by(|name| name.as_str().cmp(ORDINARY_AUDIT_LEAF))
        {
            Ok(ordinary) => { records.remove(ordinary); false }
            Err(_) => {
                for leaf in ["materials", "pg", "source-postgresql.conf",
                    "source-pg-hba.conf", "source-pg-ident.conf"] {
                    let index = records.binary_search_by(|name| name.as_str().cmp(leaf))
                        .map_err(|_| Fault::ClosingPending)?;
                    records.remove(index);
                }
                true
            }
        };
        if records.len() != 10 || records[0] != "00000000-intent.json" {
            return Err(Fault::ClosingPending);
        }
        let intent_bytes = history_read_record(op, "00000000-intent.json", l.record, None, objects.as_deref_mut(), io)?;
        history_charge(op, "00000000-intent.json", &intent_bytes, l, &mut h, io)?;
        let intent: IntentRecord = decode(&intent_bytes)?;
        intent
            .profile
            .validate()
            .map_err(|_| Fault::ClosingPending)?;
        intent.source_identity.check()?;
        if intent.schema != "wrokbot-capture-control"
            || intent.version != 1
            || intent.sequence != 0
            || intent.stage != "intent"
            || intent.request_id != request.request_id
            || intent.operation_id != request.operation_id
            || intent.bundle_id != request.bundle_id
            || intent.owner_instance != request.owner_instance
            || intent.owner_pid != request.owner_pid
            || intent.release_sha256 != request.release_sha256
            || intent.maintenance_sha256 != request.maintenance_sha256
            || request.intent_sha256 != hex(&Sha256::digest(&intent_bytes))
            || request.profile_sha256 != hex(&hash_encoded(&intent.profile, l.record)?)
            || request.source_identity_sha256
                != hex(&hash_encoded(&intent.source_identity, l.record)?)
            || intent.t0 >= intent.e
            || intent.e >= intent.c
        {
            return Err(Fault::ClosingPending);
        }
        let stages = [
            ControlStage::NormalClosed,
            ControlStage::ConsumerConfirmed,
            ControlStage::SourceStarted,
            ControlStage::MaterialsFrozen,
            ControlStage::SourceClosed,
            ControlStage::KeyMediumVerified,
            ControlStage::TemporaryVerified,
            ControlStage::PublishedVerified,
            ControlStage::Closed,
        ];
        let mut audit_binding = None;
        for (i, stage) in stages.into_iter().enumerate() {
            let name = format!("{:08}-{}.json", i + 1, stage.text());
            if records[i + 1] != name {
                return Err(Fault::ClosingPending);
            }
            let raw = history_read_record(op, &name, l.record, None, objects.as_deref_mut(), io)?;
            history_charge(op, &name, &raw, l, &mut h, io)?;
            let r: StageRecord = decode(&raw)?;
            if r.schema != "wrokbot-capture-control"
                || r.version != 1
                || r.sequence != i as u32 + 1
                || r.stage != stage
                || r.request_id != request.request_id
                || r.operation_id != request.operation_id
                || r.bundle_id != request.bundle_id
                || r.intent_sha256 != request.intent_sha256
                || r.outcome != ControlOutcome::Actual
                || r.fault.is_some()
                || r.observed_monotonic_ns < intent.t0
                || r.observed_monotonic_ns >= intent.e
            {
                return Err(Fault::ClosingPending);
            }
            if stage == ControlStage::MaterialsFrozen {
                audit_binding = Some(OrdinaryAuditBinding::from_record(&r)?);
            }
            if stage == ControlStage::Closed
                && (r.output_bytes.is_none()
                    || r.output_sha256.as_ref().is_none_or(|s| !digest_text(s))
                    || r.original_tasks != r.joined_original_tasks
                    || r.live_proxy_futures != 0)
            {
                return Err(Fault::ClosingPending);
            }
        }
        let original = Limits::from_profile(&intent.profile)?;
        if new_layout {
            let mut operation_base = operation_start;
            if shared_roots.is_none() {
                let fee = (std::mem::size_of::<Option<([RecordIdentity; 3], [u64; 3])>>() as u64)
                    .checked_add((std::mem::size_of::<Metadata>() as u64).checked_mul(6)
                        .ok_or(Fault::BoundsOverflow)?)
                    .and_then(|n| n.checked_add((std::mem::size_of::<rustix::fs::Stat>() as u64).checked_mul(4)?))
                    .ok_or(Fault::BoundsOverflow)?;
                h.metadata = checked_add(h.metadata, fee)?;
                if h.metadata > l.metadata { return Err(Fault::CapacityExceeded); }
                let observed = [io.metadata(root)?,
                    io.metadata(reqs)?, io.metadata(ops)?];
                let identities = observed.each_ref().map(RecordIdentity::of);
                let blocks = observed.each_ref().map(MetadataExt::blocks);
                history_named_identity(root, "requests", identities[1], true, io)?;
                history_named_identity(root, "operations", identities[2], true, io)?;
                let mut allocation = 0;
                for value in blocks {
                    allocation = checked_add(allocation,
                        value.checked_mul(512).ok_or(Fault::BoundsOverflow)?)?;
                }
                h.allocation = checked_add(h.allocation, allocation)?;
                if h.allocation > l.allocation { return Err(Fault::CapacityExceeded); }
                // Shared roots belong to the current history, not a second per-operation body.
                operation_base.metadata = checked_add(operation_base.metadata, fee)?;
                operation_base.allocation = checked_add(operation_base.allocation, allocation)?;
                shared_roots = Some((identities, blocks));
            }
            scan_closed_spool(ops, &op_name, op,
                audit_binding.as_ref().ok_or(Fault::ClosingPending)?,
                l, &original, &mut h, operation_base, caller_files, objects.as_deref_mut(), io)?;
        } else {
            verify_ordinary_audit_observed(
                ops,
                &op_name,
                op,
                audit_binding.as_ref().ok_or(Fault::ClosingPending)?,
                l,
                &original,
                &mut h,
                objects.as_deref_mut(),
                io,
            )?;
        }
        if let Some(before) = op_before {
            let after = io.metadata(op)?;
            if RecordIdentity::of(&before) != RecordIdentity::of(&after) || before.blocks() != after.blocks() {
                return Err(Fault::ClosingPending);
            }
            history_named_identity(ops, &op_name, RecordIdentity::of(&after), true, io)?;
            if let Some(objects) = objects.as_deref_mut() {
                objects.observe(after.dev(), after.ino(), after.blocks(), 0)?;
            }
            io.observe(&after, 0)?;
        }
        io.retire(op)?;
        if let Some((id, _)) = reviewed_request.as_ref() {
            completed_request |= request.request_id == *id;
        }
    }
    if let Some((identities, blocks)) = shared_roots {
        for (i, directory) in [root, reqs, ops].into_iter().enumerate() {
            let after = io.metadata(directory)?;
            if RecordIdentity::of(&after) != identities[i] || after.blocks() != blocks[i] {
                return Err(Fault::ClosingPending);
            }
        }
        history_named_identity(root, "requests", identities[1], true, io)?;
        history_named_identity(root, "operations", identities[2], true, io)?;
    }
    if let Some(before) = roots_before {
        for (index, directory) in [root, reqs, ops].into_iter().enumerate() {
            let after = io.metadata(directory)?;
            if RecordIdentity::of(&before[index]) != RecordIdentity::of(&after)
                || before[index].blocks() != after.blocks()
            { return Err(Fault::ClosingPending); }
            if let Some(objects) = objects.as_deref_mut() {
                objects.observe(after.dev(), after.ino(), after.blocks(), 0)?;
            }
            io.observe(&after, 0)?;
        }
        history_named_identity(root, "requests", RecordIdentity::of(&before[1]), true, io)?;
        history_named_identity(root, "operations", RecordIdentity::of(&before[2]), true, io)?;
    }
    io.retire(ops)?;
    io.retire(reqs)?;
    // A matching tombstone alone is insufficient: later operations and all
    // final held/named identities above must also have completed successfully.
    if let Some((_, observed)) = reviewed_request { *observed = completed_request; }
    Ok(h)
}
// Closed startup classification only. These borrowed counters never mint a source owner.
const METADATA_AUDIT_LEAF: &str = "audit-checkpoint.jsonl";
const CLOSED_METADATA_LEAVES: [&str; 13] = [
    "schema.jsonl", "migrations.jsonl", "receipt-frontier.jsonl",
    "audit-checkpoint.jsonl", "installation.json", "key-metadata.json",
    "profile-inventory.jsonl", "workspace-inventory.jsonl", "compatibility.json",
    "host-inventory.json", "driver-facts.json", "tool-inventory.json",
    "ui-preferences-v1.json",
];
const CLOSED_NATIVE_CONFIGS: [&str; 3] = [
    "source-postgresql.conf", "source-pg-hba.conf", "source-pg-ident.conf",
];
#[derive(Clone, Copy)]
enum ClosedChildren { Materials, Artifact, Metadata }
impl ClosedChildren {
    fn names(self) -> &'static [&'static str] {
        match self {
            Self::Materials => &["artifact-spool", "metadata"],
            Self::Artifact => &[".artifact-store-v1", "objects", "staging"],
            Self::Metadata => &CLOSED_METADATA_LEAVES,
        }
    }
}
#[derive(Clone, Copy)]
enum ClosedFileKind { Material, Native, Wal, Manifest }
impl ClosedFileKind {
    fn native(self) -> bool { !matches!(self, Self::Material) }
}
#[derive(Default)]
struct ClosedWalHistory {
    timeline: Option<[u8; 8]>,
    segment_bytes: u64,
    first: u64,
    last: u64,
}
impl ClosedWalHistory {
    fn observe(&mut self, name: &str, bytes: u64, span: u64) -> Result<(), Fault> {
        if name.len() != 24 || !name.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)) {
            return Ok(());
        }
        // The original PG17 segment names encode timeline/log/segment, not a linear hex span.
        if !(1024 * 1024..=1024 * 1024 * 1024).contains(&bytes)
            || !bytes.is_power_of_two()
        { return Err(Fault::ClosingPending); }
        if u32::from_str_radix(&name[..8], 16).map_err(|_| Fault::ClosingPending)? == 0 {
            return Err(Fault::ClosingPending);
        }
        let per_log = (1_u64 << 32).checked_div(bytes).ok_or(Fault::BoundsOverflow)?;
        let log = u64::from_str_radix(&name[8..16], 16).map_err(|_| Fault::ClosingPending)?;
        let segment = u64::from_str_radix(&name[16..], 16).map_err(|_| Fault::ClosingPending)?;
        if segment >= per_log { return Err(Fault::ClosingPending); }
        let at = log.checked_mul(per_log).and_then(|n| n.checked_add(segment))
            .ok_or(Fault::BoundsOverflow)?;
        let mut timeline = [0_u8; 8];
        timeline.copy_from_slice(&name.as_bytes()[..8]);
        if let Some(original) = self.timeline {
            if original != timeline || self.segment_bytes != bytes {
                return Err(Fault::ClosingPending);
            }
            self.first = self.first.min(at);
            self.last = self.last.max(at);
        } else {
            self.timeline = Some(timeline);
            self.segment_bytes = bytes;
            self.first = at;
            self.last = at;
        }
        if self.last.checked_sub(self.first).and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(bytes)).is_none_or(|n| n > span)
        { return Err(Fault::CapacityExceeded); }
        Ok(())
    }
}
struct ClosedNativeFrame {
    file: File,
    entries: Option<rustix::fs::Dir>,
    relative: String,
    identity: RecordIdentity,
    blocks: u64,
}
struct ClosedHistoryScan<'a, 'io> {
    current: &'a Limits,
    original: &'a Limits,
    history: &'a mut History,
    base: History,
    base_fds: u64,
    wal: ClosedWalHistory,
    io: &'a mut HistoryIo<'io>,
}
impl ClosedHistoryScan<'_, '_> {
    fn fds(&self, additional: u64) -> Result<u64, Fault> {
        checked_add(self.base_fds, additional)
    }
    fn check(&self) -> Result<(), Fault> {
        let operation = self.history.since(&self.base)?;
        for (h, l) in [(&*self.history, self.current), (&operation, self.original)] {
            if h.bytes > l.journal || h.records > l.records
                || h.retained_bytes()? > l.retained || h.allocation > l.allocation
                || h.dirs > l.dirs || h.metadata > l.metadata
                || h.ordinary_bytes > l.ordinary.plain.min(l.ordinary.spool).min(l.ordinary.snapshot)
                || h.ordinary_files > l.ordinary.material_files
                || h.ordinary_allocation > l.ordinary.spool
                || h.native_bytes > l.native.plain
                || h.native_files > l.native.files || h.native_dirs > l.native.dirs
                || h.native_allocation > l.native.spool
                || h.native_wal_bytes > l.native.wal
                || h.native_wal_files > l.native.wal_segments
            { return Err(Fault::CapacityExceeded); }
        }
        Ok(())
    }
    fn metadata(&mut self, amount: u64) -> Result<(), Fault> {
        self.io.admit(0, amount)?;
        self.history.metadata = checked_add(self.history.metadata, amount)?;
        self.check()
    }
    fn admit(&mut self, fds: u64, native: bool, metadata: u64) -> Result<(), Fault> {
        if fds > self.current.files.min(self.original.files)
            || native && fds > self.current.native.fds.min(self.original.native.fds)
        { return Err(Fault::CapacityExceeded); }
        self.metadata(metadata)
    }
    fn path(&self, bytes: u64, depth: u64, native: bool) -> Result<(), Fault> {
        if bytes > self.current.ordinary.path.min(self.original.ordinary.path)
            || depth > self.current.ordinary.depth.min(self.original.ordinary.depth)
            || native && (bytes > self.current.native.path.min(self.original.native.path)
                || depth.saturating_sub(1) > self.current.native.depth.min(self.original.native.depth))
        { return Err(Fault::CapacityExceeded); }
        Ok(())
    }
    fn overhead() -> Result<u64, Fault> {
        (std::mem::size_of::<File>() as u64)
            .checked_add(std::mem::size_of::<rustix::fs::Stat>() as u64)
            .and_then(|n| n.checked_add((std::mem::size_of::<Metadata>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<RecordIdentity>() as u64).checked_mul(2)?))
            .ok_or(Fault::BoundsOverflow)
    }
    fn charge_entry(&mut self, bytes: u64, blocks: u64, directory: bool, kind: ClosedFileKind)
        -> Result<(), Fault>
    {
        let allocation = blocks.checked_mul(512).ok_or(Fault::BoundsOverflow)?;
        self.history.allocation = checked_add(self.history.allocation, allocation)?;
        self.history.ordinary_allocation = checked_add(self.history.ordinary_allocation, allocation)?;
        if directory {
            self.history.dirs = checked_add(self.history.dirs, 1)?;
            if kind.native() { self.history.native_dirs = checked_add(self.history.native_dirs, 1)?; }
        } else {
            self.history.ordinary_files = checked_add(self.history.ordinary_files, 1)?;
            self.history.ordinary_bytes = checked_add(self.history.ordinary_bytes, bytes)?;
            if kind.native() {
                self.history.native_files = checked_add(self.history.native_files, 1)?;
                self.history.native_bytes = checked_add(self.history.native_bytes, bytes)?;
            }
            if matches!(kind, ClosedFileKind::Wal) {
                self.history.native_wal_bytes = checked_add(self.history.native_wal_bytes, bytes)?;
            }
        }
        if kind.native() {
            self.history.native_allocation = checked_add(self.history.native_allocation, allocation)?;
        }
        self.check()
    }
    fn directory(&mut self, parent: HistoryFd<'_>, name: &str, path: u64, depth: u64, native: bool, fds: u64)
        -> Result<(HistoryFd<'static>, RecordIdentity, u64), Fault>
    {
        self.path(path, depth, native)?;
        self.admit(fds, native, Self::overhead()?)?;
        let named = self.io.stat(parent, name, Fault::ClosingPending)?;
        if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
            || named.st_uid != rustix::process::geteuid().as_raw()
            || u32::from(named.st_mode) & 0o7777 != 0o700
        { return Err(Fault::ClosingPending); }
        let blocks = u64::try_from(named.st_blocks).map_err(|_| Fault::ClosingPending)?;
        self.charge_entry(0, blocks, true,
            if native { ClosedFileKind::Native } else { ClosedFileKind::Material })?;
        let maximum = usize::try_from(self.current.dirs.min(self.original.dirs))
            .map_err(|_| Fault::CapacityExceeded)?;
        let (file, identity, held_blocks) = self.io.directory(parent, name, maximum, Fault::ClosingPending)?;
        if identity.identity.device != named.st_dev as u64 || identity.identity.inode != named.st_ino
            || identity.identity.uid != named.st_uid || held_blocks != blocks || identity.mode != u32::from(named.st_mode)
            || identity.links != u64::from(named.st_nlink)
            || identity.length != u64::try_from(named.st_size).map_err(|_| Fault::ClosingPending)?
        { return Err(Fault::ClosingPending); }
        history_named_identity(parent, name, identity, true, self.io)?;
        Ok((file, identity, blocks))
    }
    fn finish_directory(&mut self, parent: HistoryFd<'_>, name: &str, file: HistoryFd<'_>, identity: RecordIdentity, blocks: u64,
        objects: Option<&mut super::OriginalControlStorageFacts>) -> Result<(), Fault>
    {
        let after = self.io.metadata(file)?;
        if RecordIdentity::of(&after) != identity || after.blocks() != blocks {
            return Err(Fault::ClosingPending);
        }
        history_named_identity(parent, name, identity, true, self.io)?;
        if let Some(objects) = objects {
            objects.observe(after.dev(), after.ino(), after.blocks(), 0)?;
        }
        self.io.observe(&after, 0)
    }
    fn file(&mut self, parent: HistoryFd<'_>, name: &str, path: u64, depth: u64,
        kind: ClosedFileKind, required_nonempty: bool, fds: u64,
        objects: Option<&mut super::OriginalControlStorageFacts>) -> Result<(), Fault>
    {
        self.path(path, depth, kind.native())?;
        self.admit(fds, kind.native(), Self::overhead()?)?;
        let named = self.io.stat(parent, name, Fault::ClosingPending)?;
        let bytes = u64::try_from(named.st_size).map_err(|_| Fault::ClosingPending)?;
        let blocks = u64::try_from(named.st_blocks).map_err(|_| Fault::ClosingPending)?;
        if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
            || named.st_uid != rustix::process::geteuid().as_raw()
            || u32::from(named.st_mode) & 0o7777 != 0o600 || named.st_nlink != 1
            || required_nonempty && bytes == 0
        { return Err(Fault::ClosingPending); }
        let mut single = self.current.ordinary.single.min(self.original.ordinary.single);
        if kind.native() { single = single.min(self.current.native.single).min(self.original.native.single); }
        if matches!(kind, ClosedFileKind::Manifest) {
            single = single.min(self.current.native.manifest).min(self.original.native.manifest);
        }
        if bytes > single { return Err(Fault::CapacityExceeded); }
        if matches!(kind, ClosedFileKind::Wal) {
            self.wal.observe(name, bytes, self.current.native.wal_span.min(self.original.native.wal_span))?;
            if name.len() == 24 && name.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)) {
                self.history.native_wal_files = checked_add(self.history.native_wal_files, 1)?;
            }
        }
        self.charge_entry(bytes, blocks, false, kind)?;
        let file = self.io.open(parent, name, false, Fault::ClosingPending)?;
        let before = self.io.metadata(file)?;
        let identity = RecordIdentity::of(&before);
        if before.dev() != named.st_dev as u64 || before.ino() != named.st_ino
            || before.uid() != named.st_uid || before.len() != bytes || before.blocks() != blocks
            || before.mode() != u32::from(named.st_mode) || before.nlink() != u64::from(named.st_nlink)
        { return Err(Fault::ClosingPending); }
        history_named_identity(parent, name, identity, false, self.io)?;
        // Payload remains deliberately unread by the sole closed classifier.
        let after = self.io.metadata(file)?;
        if RecordIdentity::of(&after) != identity || after.blocks() != blocks {
            return Err(Fault::ClosingPending);
        }
        history_named_identity(parent, name, identity, false, self.io)?;
        if let Some(objects) = objects {
            objects.observe(after.dev(), after.ino(), after.blocks(), after.len())?;
        }
        self.io.observe(&after, after.len())?;
        self.io.retire(file)
    }
    fn children(&mut self, directory: HistoryFd<'_>, role: ClosedChildren, fds: u64)
        -> Result<[bool; 13], Fault>
    {
        self.admit(fds, false, (std::mem::size_of::<rustix::fs::Dir>() as u64)
            .checked_add(std::mem::size_of::<[bool; 13]>() as u64).ok_or(Fault::BoundsOverflow)?)?;
        let names = role.names();
        let mut seen = [false; 13];
        let (identity, blocks) = self.io.start_entries(directory)?;
        loop {
            self.metadata(std::mem::size_of::<rustix::fs::DirEntry>() as u64)?;
            let Some(bytes) = self.io.next_name(directory)? else { break; };
            if bytes == b"." || bytes == b".." { continue; }
            let name = std::str::from_utf8(&bytes).map_err(|_| Fault::ClosingPending)?;
            let index = names.iter().position(|expected| *expected == name).ok_or(Fault::ClosingPending)?;
            if seen[index] { return Err(Fault::ClosingPending); }
            seen[index] = true;
        }
        let required = if matches!(role, ClosedChildren::Metadata) { 12 } else { names.len() };
        if seen[..required].iter().any(|present| !present) { return Err(Fault::ClosingPending); }
        self.io.finish_entries(directory, identity, blocks, true)?;
        Ok(seen)
    }
    fn artifact(&mut self, materials: HistoryFd<'_>,
        mut objects: Option<&mut super::OriginalControlStorageFacts>) -> Result<(), Fault> {
        let (root, identity, blocks) = self.directory(materials, "artifact-spool",
            "materials/artifact-spool".len() as u64, 2, false, self.fds(2)?)?;
        self.children(root, ClosedChildren::Artifact, self.fds(3)?)?;
        self.file(root, ".artifact-store-v1",
            "materials/artifact-spool/.artifact-store-v1".len() as u64, 3,
            ClosedFileKind::Material, true, self.fds(3)?, objects.as_deref_mut())?;
        for name in ["objects", "staging"] {
            let path = checked_add("materials/artifact-spool/".len() as u64, name.len() as u64)?;
            let (directory, child_identity, child_blocks) = self.directory(root, name, path, 3, false, self.fds(3)?)?;
            self.admit(self.fds(4)?, false, std::mem::size_of::<rustix::fs::Dir>() as u64)?;
            let (cursor_identity, cursor_blocks) = self.io.start_entries(directory)?;
            loop {
                self.metadata(std::mem::size_of::<rustix::fs::DirEntry>() as u64)?;
                let Some(bytes) = self.io.next_name(directory)? else { break; };
                if bytes == b"." || bytes == b".." { continue; }
                let leaf = std::str::from_utf8(&bytes).map_err(|_| Fault::ClosingPending)?;
                // The exact original canonical UUID grammar, no version/variant change.
                if leaf.len() != 36 || !leaf.bytes().enumerate().all(|(i, b)|
                    if [8, 13, 18, 23].contains(&i) { b == b'-' }
                    else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) })
                { return Err(Fault::ClosingPending); }
                self.file(directory, leaf, checked_add(checked_add(path, 1)?, leaf.len() as u64)?,
                    4, ClosedFileKind::Material, false, self.fds(5)?, objects.as_deref_mut())?;
            }
            self.io.finish_entries(directory, cursor_identity, cursor_blocks, true)?;
            self.finish_directory(root, name, directory, child_identity, child_blocks, objects.as_deref_mut())?;
            self.io.retire(directory)?;
        }
        self.finish_directory(materials, "artifact-spool", root, identity, blocks, objects)?;
        self.io.retire(root)
    }
    fn native(&mut self, operation: HistoryFd<'_>,
        mut objects: Option<&mut super::OriginalControlStorageFacts>) -> Result<(), Fault> {
        self.metadata(std::mem::size_of::<Vec<ClosedNativeFrame>>() as u64)?;
        // The original iterative frame Vec is borrowed from Work; no second
        // frame owner or recursive/native task is introduced.
        let base = self.io.frames.len();
        let mut admitted_depth = 0usize;
        self.grow_native_frames(1, &mut admitted_depth)?;
        let (file, _, _) = self.directory(operation, "pg", "pgdata".len() as u64, 1, true, self.fds(2)?)?;
        self.admit(self.fds(2)?, true, std::mem::size_of::<rustix::fs::Dir>() as u64)?;
        self.io.start_entries(file)?;
        while self.io.frames.len() > base {
            self.metadata(std::mem::size_of::<rustix::fs::DirEntry>() as u64)?;
            let index = self.io.frames.len().checked_sub(1).ok_or(Fault::ClosingPending)?;
            let current = HistoryFd::Frame(index);
            let Some(bytes) = self.io.next_name(current)? else {
                let frame = self.io.frames.get(index).ok_or(Fault::ClosingPending)?;
                let identity = frame.identity;
                let blocks = frame.blocks;
                let leaf_length = if index == base { 2 } else {
                    frame.relative.rsplit('/').next().ok_or(Fault::ClosingPending)?.len()
                };
                self.io.admit(0, u64::try_from(leaf_length).map_err(|_| Fault::BoundsOverflow)?)?;
                let mut leaf = String::new();
                leaf.try_reserve_exact(leaf_length).map_err(|_| Fault::CapacityExceeded)?;
                if leaf.capacity() != leaf_length { return Err(Fault::CapacityExceeded); }
                if index == base { leaf.push_str("pg"); } else {
                    leaf.push_str(self.io.frames[index].relative.rsplit('/').next().ok_or(Fault::ClosingPending)?);
                }
                let parent = if index == base { operation } else { HistoryFd::Frame(index - 1) };
                // Finish against the still resident File/Dir before any pop.
                self.io.finish_entries(current, identity, blocks, true)?;
                self.finish_directory(parent, &leaf, current, identity, blocks, objects.as_deref_mut())?;
                self.io.retire(current)?;
                continue;
            };
            if bytes == b"." || bytes == b".." { continue; }
            let name = std::str::from_utf8(&bytes).map_err(|_| Fault::ClosingPending)?;
            if name.is_empty() || name.contains('/') || name.contains('\\') { return Err(Fault::ClosingPending); }
            let frame = self.io.frames.get(index).ok_or(Fault::ClosingPending)?;
            let length = checked_add(frame.relative.len() as u64,
                checked_add(u64::from(!frame.relative.is_empty()), name.len() as u64)?)?;
            let native_depth = self.io.frames.len().checked_sub(base).ok_or(Fault::BoundsOverflow)?;
            let depth = checked_add(native_depth as u64, 1)?;
            let carrier_path = checked_add("pgdata/".len() as u64, length)?;
            self.path(carrier_path, depth, true)?;
            self.admit(self.fds((native_depth as u64).checked_mul(2).ok_or(Fault::BoundsOverflow)?)?,
                true, std::mem::size_of::<rustix::fs::Stat>() as u64)?;
            let named = self.io.stat(current, name, Fault::ClosingPending)?;
            if rustix::fs::FileType::from_raw_mode(named.st_mode) == rustix::fs::FileType::Directory {
                self.metadata(checked_add(length, std::mem::size_of::<String>() as u64)?)?;
                let length_usize = usize::try_from(length).map_err(|_| Fault::CapacityExceeded)?;
                let mut relative = String::new();
                relative.try_reserve_exact(length_usize).map_err(|_| Fault::CapacityExceeded)?;
                if relative.capacity() != length_usize { return Err(Fault::CapacityExceeded); }
                if !self.io.frames[index].relative.is_empty() {
                    relative.push_str(&self.io.frames[index].relative); relative.push('/');
                }
                relative.push_str(name);
                let fds = self.fds(checked_add(native_depth as u64, 1)?
                    .checked_mul(2).ok_or(Fault::BoundsOverflow)?)?;
                self.grow_native_frames(native_depth.checked_add(1).ok_or(Fault::BoundsOverflow)?, &mut admitted_depth)?;
                let (child, _, _) = self.directory(current, name, carrier_path, depth, true, fds)?;
                let HistoryFd::Frame(child_index) = child else { return Err(Fault::IntentMismatch); };
                self.io.frames[child_index].relative = relative;
                self.admit(fds, true, std::mem::size_of::<rustix::fs::Dir>() as u64)?;
                self.io.start_entries(child)?;
            } else {
                let relative = &self.io.frames[index].relative;
                let kind = if relative == "pg_wal" || relative.starts_with("pg_wal/") {
                    ClosedFileKind::Wal
                } else if relative.is_empty() && name == "backup_manifest" {
                    ClosedFileKind::Manifest
                } else { ClosedFileKind::Native };
                let fds = self.fds(checked_add(1, (native_depth as u64)
                    .checked_mul(2).ok_or(Fault::BoundsOverflow)?)?)?;
                self.file(current, name, carrier_path, depth, kind, false, fds, objects.as_deref_mut())?;
            }
        }
        Ok(())
    }
    fn grow_native_frames(&mut self, new: usize, admitted: &mut usize) -> Result<(), Fault> {
        if new <= *admitted { return Ok(()); }
        if new as u64 > checked_add(self.current.native.depth.min(self.original.native.depth), 1)? {
            return Err(Fault::CapacityExceeded);
        }
        // Preserve the original per-operation frame bound/counter. Physical
        // Work Vec backing is separately admitted before its actual growth.
        self.metadata((new as u64).checked_mul(std::mem::size_of::<ClosedNativeFrame>() as u64)
            .ok_or(Fault::BoundsOverflow)?)?;
        *admitted = new;
        Ok(())
    }
    fn materials(&mut self, operation: HistoryFd<'_>, binding: &OrdinaryAuditBinding,
        mut objects: Option<&mut super::OriginalControlStorageFacts>) -> Result<(), Fault> {
        let (materials, identity, blocks) = self.directory(operation, "materials",
            "materials".len() as u64, 1, false, self.fds(1)?)?;
        self.children(materials, ClosedChildren::Materials, self.fds(2)?)?;
        self.artifact(materials, objects.as_deref_mut())?;
        let (metadata, child_identity, child_blocks) = self.directory(materials, "metadata",
            "materials/metadata".len() as u64, 2, false, self.fds(2)?)?;
        let present = self.children(metadata, ClosedChildren::Metadata, self.fds(3)?)?;
        for (i, leaf) in CLOSED_METADATA_LEAVES.iter().enumerate() {
            if !present[i] || *leaf == METADATA_AUDIT_LEAF { continue; }
            self.file(metadata, leaf,
                checked_add("materials/metadata/".len() as u64, leaf.len() as u64)?,
                3, ClosedFileKind::Material, i != 12, self.fds(3)?, objects.as_deref_mut())?;
        }
        self.path("materials/metadata/audit-checkpoint.jsonl".len() as u64, 3, false)?;
        self.admit(self.fds(3)?, false, 0)?;
        // The same audit file is counted only by the original streaming-hash core below.
        let used = self.history.since(&self.base)?;
        let mut remaining = *self.original;
        remaining.metadata = remaining.metadata.checked_sub(used.metadata).ok_or(Fault::CapacityExceeded)?;
        remaining.allocation = remaining.allocation.checked_sub(used.allocation).ok_or(Fault::CapacityExceeded)?;
        remaining.ordinary.material_files = remaining.ordinary.material_files
            .checked_sub(used.ordinary_files).ok_or(Fault::CapacityExceeded)?;
        remaining.ordinary.plain = remaining.ordinary.plain
            .min(remaining.ordinary.snapshot).checked_sub(used.ordinary_bytes).ok_or(Fault::CapacityExceeded)?
            .min(remaining.retained.checked_sub(used.retained_bytes()?).ok_or(Fault::CapacityExceeded)?);
        remaining.ordinary.spool = remaining.ordinary.spool.checked_sub(
            used.ordinary_bytes.max(used.ordinary_allocation)).ok_or(Fault::CapacityExceeded)?;
        let mut current = *self.current;
        current.ordinary.plain = current.ordinary.plain.min(current.ordinary.snapshot);
        verify_ordinary_audit_at_observed(materials, "metadata", metadata, METADATA_AUDIT_LEAF,
            binding, &current, &remaining, self.history, objects.as_deref_mut(), self.io)?;
        self.check()?;
        self.finish_directory(materials, "metadata", metadata, child_identity, child_blocks, objects.as_deref_mut())?;
        self.io.retire(metadata)?;
        self.finish_directory(operation, "materials", materials, identity, blocks, objects)?;
        self.io.retire(materials)
    }
}
fn scan_closed_spool(
    operations: HistoryFd<'_>, operation_name: &str, operation: HistoryFd<'_>,
    binding: &OrdinaryAuditBinding, current: &Limits, original: &Limits,
    history: &mut History, base: History, caller_files: u64,
    mut objects: Option<&mut super::OriginalControlStorageFacts>, io: &mut HistoryIo<'_>,
) -> Result<(), Fault> {
    if caller_files == 0 { return Err(Fault::ClosingPending); }
    // The two fixed callers supply only their actually held original FD lower bound.
    // root/requests/operations/op add four. Other outer/opaque owners remain unproved.
    let base_fds = checked_add(caller_files, 4)?;
    let mut scan = ClosedHistoryScan { current, original, history, base, base_fds,
        wal: ClosedWalHistory::default(), io };
    let fixed = (std::mem::size_of::<ClosedHistoryScan<'_, '_>>() as u64)
        .checked_add((std::mem::size_of::<Limits>() as u64).checked_mul(2).ok_or(Fault::BoundsOverflow)?)
        .and_then(|n| n.checked_add((std::mem::size_of::<History>() as u64).checked_mul(2)?))
        .and_then(|n| n.checked_add((std::mem::size_of::<File>() as u64).checked_mul(base_fds)?))
        .and_then(|n| n.checked_add(ClosedHistoryScan::overhead().ok()?))
        .ok_or(Fault::BoundsOverflow)?;
    scan.admit(base_fds, false, fixed)?;
    let before = scan.io.metadata(operation)?;
    if !before.is_dir() || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o7777 != 0o700 { return Err(Fault::ClosingPending); }
    let identity = RecordIdentity::of(&before);
    history_named_identity(operations, operation_name, identity, true, scan.io)?;
    // operation was already counted by operation_entry_names; add its actual allocation once.
    scan.history.allocation = checked_add(scan.history.allocation,
        before.blocks().checked_mul(512).ok_or(Fault::BoundsOverflow)?)?;
    scan.check()?;
    for leaf in CLOSED_NATIVE_CONFIGS {
        scan.file(operation, leaf, leaf.len() as u64, 1, ClosedFileKind::Native, false, scan.fds(1)?, objects.as_deref_mut())?;
    }
    scan.native(operation, objects.as_deref_mut())?;
    scan.materials(operation, binding, objects.as_deref_mut())?;
    scan.finish_directory(operations, operation_name, operation, identity, before.blocks(), objects)
}

// Binding from the already validated MaterialsFrozen record, never from a leaf name.
struct OrdinaryAuditBinding {
    parent_device: u64,
    parent_inode: u64,
    entry_device: u64,
    entry_inode: u64,
    bytes: u64,
    sha256: [u8; 32],
}
impl OrdinaryAuditBinding {
    fn from_record(record: &StageRecord) -> Result<Self, Fault> {
        let digest = record.output_sha256.as_deref().ok_or(Fault::ClosingPending)?;
        if !digest_text(digest) {
            return Err(Fault::ClosingPending);
        }
        let mut sha256 = [0_u8; 32];
        for (out, pair) in sha256.iter_mut().zip(digest.as_bytes().chunks_exact(2)) {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(Fault::ClosingPending),
            };
            *out = (digit(pair[0])? << 4) | digit(pair[1])?;
        }
        let bound = Self {
            parent_device: record.parent_device.ok_or(Fault::ClosingPending)?,
            parent_inode: record.parent_inode.ok_or(Fault::ClosingPending)?,
            entry_device: record.entry_device.ok_or(Fault::ClosingPending)?,
            entry_inode: record.entry_inode.ok_or(Fault::ClosingPending)?,
            bytes: record.output_bytes.ok_or(Fault::ClosingPending)?,
            sha256,
        };
        if [
            bound.parent_device,
            bound.parent_inode,
            bound.entry_device,
            bound.entry_inode,
            bound.bytes,
        ].contains(&0) {
            return Err(Fault::ClosingPending);
        }
        Ok(bound)
    }
}
fn ordinary_named_identity(
    parent: &File,
    name: &str,
    expected: RecordIdentity,
    directory: bool,
) -> Result<(), Fault> {
    let named = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| Fault::ClosingPending)?;
    let file_type = rustix::fs::FileType::from_raw_mode(named.st_mode);
    if file_type != if directory {
        rustix::fs::FileType::Directory
    } else {
        rustix::fs::FileType::RegularFile
    }
        || named.st_dev as u64 != expected.identity.device
        || named.st_ino != expected.identity.inode
        || named.st_uid != expected.identity.uid
        || u32::from(named.st_mode) != expected.mode
        || u64::from(named.st_nlink) != expected.links
        || u64::try_from(named.st_size).map_err(|_| Fault::ClosingPending)? != expected.length
    {
        return Err(Fault::ClosingPending);
    }
    Ok(())
}
fn verify_ordinary_audit(
    operations: &File,
    operation_name: &str,
    operation: &File,
    binding: &OrdinaryAuditBinding,
    current: &Limits,
    original: &Limits,
    history: &mut History,
    objects: Option<&mut super::OriginalControlStorageFacts>,
) -> Result<(), Fault> {
    verify_ordinary_audit_at(operations, operation_name, operation, ORDINARY_AUDIT_LEAF,
        binding, current, original, history, objects)
}
fn verify_ordinary_audit_at(
    operations: &File, operation_name: &str, operation: &File, audit_leaf: &str,
    binding: &OrdinaryAuditBinding, current: &Limits, original: &Limits,
    history: &mut History, objects: Option<&mut super::OriginalControlStorageFacts>,
) -> Result<(), Fault> {
    let mut files = Vec::new();
    let mut directory = None;
    let mut frames = Vec::new();
    let mut matched = Vec::new();
    let mut raw = None;
    let mut bytes = Vec::new();
    let mut io = HistoryIo { fs_admission: None, fs_observations: None,  clock: None, original_objects: None, maximum_files: 2, files: &mut files,
        directory: &mut directory, frames: &mut frames, matched: &mut matched,
        raw: &mut raw, bytes: &mut bytes };
    verify_ordinary_audit_at_observed(HistoryFd::Original(operations), operation_name,
        HistoryFd::Original(operation), audit_leaf, binding, current, original, history, objects, &mut io)
}
fn verify_ordinary_audit_observed(
    operations: HistoryFd<'_>, operation_name: &str, operation: HistoryFd<'_>,
    binding: &OrdinaryAuditBinding, current: &Limits, original: &Limits,
    history: &mut History, objects: Option<&mut super::OriginalControlStorageFacts>, io: &mut HistoryIo<'_>,
) -> Result<(), Fault> {
    verify_ordinary_audit_at_observed(operations, operation_name, operation,
        ORDINARY_AUDIT_LEAF, binding, current, original, history, objects, io)
}
fn verify_ordinary_audit_at_observed(
    operations: HistoryFd<'_>,
    operation_name: &str,
    operation: HistoryFd<'_>,
    audit_leaf: &str,
    binding: &OrdinaryAuditBinding,
    current: &Limits,
    original: &Limits,
    history: &mut History,
    objects: Option<&mut super::OriginalControlStorageFacts>,
    io: &mut HistoryIo<'_>,
) -> Result<(), Fault> {
    // The original app caller stays live beside root/requests/operations/op/audit: at least six.
    // Other outer owners/Dir internals and the whole-operation FD peak remain separate HOLDs.
    if current.files < 6
        || original.files < 1
        || audit_leaf.len() as u64 > current.ordinary.path.min(original.ordinary.path)
        || current.ordinary.depth.min(original.ordinary.depth) < 1
        || binding.bytes > current.ordinary.single.min(original.ordinary.single)
        || binding.bytes > current.ordinary.plain.min(original.ordinary.plain)
        || binding.bytes > current.ordinary.spool.min(original.ordinary.spool)
        || original.ordinary.material_files < 1
    {
        return Err(Fault::CapacityExceeded);
    }
    let ordinary_bytes = checked_add(history.ordinary_bytes, binding.bytes)?;
    let ordinary_files = checked_add(history.ordinary_files, 1)?;
    if ordinary_bytes > current.ordinary.plain
        || ordinary_bytes > current.ordinary.spool
        || ordinary_files > current.ordinary.material_files
        || checked_add(history.bytes, ordinary_bytes)? > current.retained
    {
        return Err(Fault::CapacityExceeded);
    }
    // Admission is monotonic for this original history scan, including every later error.
    history.ordinary_bytes = ordinary_bytes;
    history.ordinary_files = ordinary_files;

    // Only a bounded streaming scratch Vec, never a whole-file JSON/body allocation.
    let overhead = (std::mem::size_of::<Sha256>() as u64)
        .checked_add(std::mem::size_of::<Vec<u8>>() as u64)
        .and_then(|v| v.checked_add(std::mem::size_of::<Option<OrdinaryAuditBinding>>() as u64))
        .and_then(|v| v.checked_add((std::mem::size_of::<RecordIdentity>() as u64).checked_mul(2)?))
        .and_then(|v| v.checked_add((std::mem::size_of::<Metadata>() as u64).checked_mul(4)?))
        .and_then(|v| v.checked_add(std::mem::size_of::<rustix::fs::Stat>() as u64))
        .and_then(|v| v.checked_add(std::mem::size_of::<File>() as u64))
        .and_then(|v| v.checked_add(std::mem::size_of::<[u8; 32]>() as u64))
        .and_then(|v| v.checked_add(std::mem::size_of::<[u8; 1]>() as u64))
        .ok_or(Fault::BoundsOverflow)?;
    let current_room = current.metadata
        .checked_sub(checked_add(history.metadata, overhead)?)
        .ok_or(Fault::CapacityExceeded)?;
    let original_room = original.metadata
        .checked_sub(overhead)
        .ok_or(Fault::CapacityExceeded)?;
    let chunk = current.ordinary.chunk.min(original.ordinary.chunk)
        .min(64 * 1024).min(current_room).min(original_room);
    if chunk == 0 {
        return Err(Fault::CapacityExceeded);
    }
    history.metadata = checked_add(history.metadata, checked_add(overhead, chunk)?)?;
    let chunk = usize::try_from(chunk).map_err(|_| Fault::CapacityExceeded)?;
    io.admit(0, checked_add(overhead, chunk as u64)?)?;
    let mut scratch = zeroize::Zeroizing::new(Vec::new());
    scratch.try_reserve_exact(chunk).map_err(|_| Fault::CapacityExceeded)?;
    if scratch.capacity() != chunk { return Err(Fault::CapacityExceeded); }
    let extra = scratch.capacity().checked_sub(chunk).ok_or(Fault::BoundsOverflow)?;
    history.metadata = checked_add(history.metadata, extra as u64)?;
    if history.metadata > current.metadata
        || checked_add(overhead, scratch.capacity() as u64)? > original.metadata
    {
        return Err(Fault::CapacityExceeded);
    }
    scratch.resize(chunk, 0);

    let parent_before = io.metadata(operation)?;
    if !parent_before.is_dir()
        || parent_before.mode() & 0o7777 != 0o700
        || parent_before.uid() != rustix::process::geteuid().as_raw()
        || parent_before.dev() != binding.parent_device
        || parent_before.ino() != binding.parent_inode
    {
        return Err(Fault::ClosingPending);
    }
    let parent_identity = RecordIdentity::of(&parent_before);
    history_named_identity(operations, operation_name, parent_identity, true, io)?;
    // Only the held op directory is used; no external path or arbitrary name is opened.
    let file = io.open(operation, audit_leaf, false, Fault::ClosingPending)?;
    let before = io.metadata(file)?;
    if !before.is_file()
        || before.mode() & 0o7777 != 0o600
        || before.uid() != parent_before.uid()
        || before.nlink() != 1
        || before.dev() != binding.entry_device
        || before.ino() != binding.entry_inode
        || before.len() != binding.bytes
    {
        return Err(Fault::ClosingPending);
    }
    let entry_identity = RecordIdentity::of(&before);
    history_named_identity(operation, audit_leaf, entry_identity, false, io)?;
    let allocation = before.blocks().checked_mul(512).ok_or(Fault::BoundsOverflow)?;
    let allocation_total = checked_add(history.allocation, allocation)?;
    let ordinary_allocation = checked_add(history.ordinary_allocation, allocation)?;
    if allocation > original.allocation
        || allocation > original.ordinary.spool
        || ordinary_allocation > current.ordinary.spool
        || allocation_total > current.allocation
    {
        return Err(Fault::CapacityExceeded);
    }
    history.allocation = allocation_total;
    history.ordinary_allocation = ordinary_allocation;

    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    while offset < binding.bytes {
        let amount = (binding.bytes - offset).min(scratch.len() as u64);
        let amount = usize::try_from(amount).map_err(|_| Fault::CapacityExceeded)?;
        let count = io.read_into_at(file, &mut scratch[..amount], offset)?;
        if count == 0 {
            return Err(Fault::ClosingPending);
        }
        digest.update(&scratch[..count]);
        offset = checked_add(offset, count as u64)?;
    }
    let mut tail = [0_u8; 1];
    if io.read_into_at(file, &mut tail, offset)? != 0
        || <[u8; 32]>::from(digest.finalize()) != binding.sha256
    {
        return Err(Fault::ClosingPending);
    }
    let after = io.metadata(file)?;
    if RecordIdentity::of(&after) != entry_identity || after.blocks() != before.blocks() {
        return Err(Fault::ClosingPending);
    }
    history_named_identity(operation, audit_leaf, entry_identity, false, io)?;
    let parent_after = io.metadata(operation)?;
    if RecordIdentity::of(&parent_after) != parent_identity {
        return Err(Fault::ClosingPending);
    }
    history_named_identity(operations, operation_name, parent_identity, true, io)?;
    if objects.is_some() || io.original_objects.is_some() {
        if parent_after.blocks() != parent_before.blocks() { return Err(Fault::ClosingPending); }
    }
    if let Some(objects) = objects {
        objects.observe(after.dev(), after.ino(), after.blocks(), after.len())?;
        objects.observe(parent_after.dev(), parent_after.ino(), parent_after.blocks(), 0)?;
    }
    io.observe(&after, after.len())?;
    io.observe(&parent_after, 0)?;
    io.retire(file)
}

fn charge(dir: &File, name: &str, bytes: &[u8], l: &Limits, h: &mut History) -> Result<(), Fault> {
    let f = open_read(dir, name)?;
    let m = f.metadata().map_err(io_fault)?;
    h.bytes = checked_add(h.bytes, bytes.len() as u64)?;
    h.allocation = checked_add(
        h.allocation,
        m.blocks().checked_mul(512).ok_or(Fault::BoundsOverflow)?,
    )?;
    h.records = checked_add(h.records, 1)?;
    if h.bytes > l.journal
        || h.retained_bytes()? > l.retained
        || h.allocation > l.allocation
        || h.records > l.records
    {
        return Err(Fault::CapacityExceeded);
    }
    Ok(())
}
fn names(dir: &File, l: &Limits, h: &mut History) -> Result<Vec<String>, Fault> {
    bounded_names(dir, l, h, l.records)
}
fn operation_entry_names(dir: &File, l: &Limits, h: &mut History) -> Result<Vec<String>, Fault> {
    bounded_names(dir, l, h, checked_add(l.records, 5)?)
}
fn bounded_names(
    dir: &File,
    l: &Limits,
    h: &mut History,
    maximum: u64,
) -> Result<Vec<String>, Fault> {
    h.dirs = checked_add(h.dirs, 1)?;
    if h.dirs > l.dirs {
        return Err(Fault::CapacityExceeded);
    }
    let mut result = Vec::new();
    let mut iter = rustix::fs::Dir::read_from(dir).map_err(|_| Fault::IoFailure)?;
    for entry in &mut iter {
        let e = entry.map_err(|_| Fault::IoFailure)?;
        let bytes = e.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        h.metadata = checked_add(h.metadata, bytes.len() as u64 + 128)?;
        if h.metadata > l.metadata || result.len() as u64 >= maximum {
            return Err(Fault::CapacityExceeded);
        }
        result.push(
            std::str::from_utf8(bytes)
                .map_err(|_| Fault::PathUnsafe)?
                .to_string(),
        );
    }
    result.sort();
    Ok(result)
}
pub(in crate::tauri_background) fn open_trusted_directory(path: &Path, private: bool) -> Result<File, Fault> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(Fault::PathUnsafe);
    }
    let uid = rustix::process::geteuid().as_raw();
    let mut fd = File::open("/").map_err(io_fault)?;
    for c in path.components() {
        let m = fd.metadata().map_err(io_fault)?;
        if !m.is_dir() || m.mode() & 0o022 != 0 || m.uid() != uid && m.uid() != 0 {
            return Err(Fault::PathUnsafe);
        }
        if let Component::Normal(n) = c {
            fd = rustix::fs::openat(
                &fd,
                n,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(|_| Fault::PathUnsafe)?;
        }
    }
    if private {
        private_directory(&fd)?;
    }
    if bound_path(&fd)? != path {
        return Err(Fault::PathUnsafe);
    }
    Ok(fd)
}
fn bound_path(fd: &File) -> Result<PathBuf, Fault> {
    let p = rustix::fs::getpath(fd).map_err(|_| Fault::PathUnsafe)?;
    let path = PathBuf::from(std::ffi::OsString::from_vec(p.into_bytes()));
    let m = std::fs::symlink_metadata(&path).map_err(io_fault)?;
    if m.file_type().is_symlink()
        || Identity::of(&m) != Identity::of(&fd.metadata().map_err(io_fault)?)
    {
        return Err(Fault::PathUnsafe);
    }
    Ok(path)
}
fn private_directory(fd: &File) -> Result<(), Fault> {
    let m = fd.metadata().map_err(io_fault)?;
    if !m.is_dir() || m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o7777 != 0o700 {
        return Err(Fault::PathUnsafe);
    }
    Ok(())
}
fn same_directory(a: &File, b: &File) -> Result<(), Fault> {
    if Identity::of(&a.metadata().map_err(io_fault)?)
        != Identity::of(&b.metadata().map_err(io_fault)?)
    {
        return Err(Fault::PathUnsafe);
    }
    Ok(())
}
fn optional_directory(parent: &File, name: &str) -> Result<Option<File>, Fault> {
    match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let file = File::from(fd);
            private_directory(&file)?;
            Ok(Some(file))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(Fault::ClosingPending),
    }
}
fn open_child_directory(parent: &File, name: &str) -> Result<File, Fault> {
    optional_directory(parent, name)?.ok_or(Fault::ClosingPending)
}
#[derive(Clone, Copy)]
enum DirectoryMode {
    New,
    Existing,
    ExistingOrNew,
}
fn place_directory(
    parent: &File, name: &str, clock: &CaptureOperation,
    slot: &mut Option<File>, mode: DirectoryMode, io: &mut HistoryIo<'_>,
) -> Result<(), Fault> {
    if slot.is_some() || !matches!(io.clock, Some((original, false)) if std::ptr::eq(original, clock)) {
        return Err(Fault::IntentMismatch);
    }
    const FIXED_METADATA: u64 = {
        let slots = [
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 6usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<&CaptureOperation>(), core::mem::align_of::<&CaptureOperation>(), 2usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 3usize),
            (core::mem::size_of::<Option<&File>>(), core::mem::align_of::<Option<&File>>(), 2usize),
            (core::mem::size_of::<&str>(), core::mem::align_of::<&str>(), 2usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 2usize),
            (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 2usize),
            (core::mem::size_of::<RecordIdentity>(), core::mem::align_of::<RecordIdentity>(), 2usize),
            (core::mem::size_of::<(u64, u64, u32)>(), core::mem::align_of::<(u64, u64, u32)>(), 2usize),
            (core::mem::size_of::<rustix::fs::Stat>(), core::mem::align_of::<rustix::fs::Stat>(), 2usize),
            (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 2usize),
            (core::mem::size_of::<Option<&JournalHistoryIoResult>>(), core::mem::align_of::<Option<&JournalHistoryIoResult>>(), 2usize),
            (core::mem::size_of::<Fault>(), core::mem::align_of::<Fault>(), 2usize),
            (core::mem::size_of::<DirectoryMode>(), core::mem::align_of::<DirectoryMode>(), 2usize),
            (core::mem::size_of::<OFlags>(), core::mem::align_of::<OFlags>(), 2usize),
            (core::mem::size_of::<Mode>(), core::mem::align_of::<Mode>(), 2usize),
            (core::mem::size_of::<File>(), core::mem::align_of::<File>(), 2usize),
            (core::mem::size_of::<Option<File>>(), core::mem::align_of::<Option<File>>(), 2usize),
            (core::mem::size_of::<rustix::fd::OwnedFd>(), core::mem::align_of::<rustix::fd::OwnedFd>(), 2usize),
            (core::mem::size_of::<rustix::io::Errno>(), core::mem::align_of::<rustix::io::Errno>(), 2usize),
            (core::mem::size_of::<&mut Option<File>>(), core::mem::align_of::<&mut Option<File>>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed helper layout fits usize").checked_mul(slots[at].2)
                .expect("fixed helper count fits usize"))
                .expect("fixed helper slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    clock.require_effect()?;
    super::reserve_capture_resources(&clock.resources, 0, FIXED_METADATA)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut created = false;
    if !matches!(mode, DirectoryMode::New) {
        io.before_io(1)?;
        let actual = rustix::fs::openat(parent, name, flags, Mode::empty());
        *io.raw = Some(JournalHistoryIoResult::Open(actual));
        clock.require_effect()?;
        match io.raw.as_ref() {
            Some(JournalHistoryIoResult::Open(Ok(_))) => {
                let actual = io.raw.take();
                match actual {
                    Some(JournalHistoryIoResult::Open(Ok(fd))) => *slot = Some(File::from(fd)),
                    other => { *io.raw = other; return Err(Fault::IntentMismatch); }
                }
            }
            Some(JournalHistoryIoResult::Open(Err(rustix::io::Errno::NOENT)))
                if matches!(mode, DirectoryMode::ExistingOrNew) => {
                // The same original permitted absence is a normal grammar
                // edge, like HistoryIo::absent, not a selected IO failure.
                io.raw.take();
            }
            Some(JournalHistoryIoResult::Open(Err(_))) => return Err(Fault::IoFailure),
            _ => return Err(Fault::IntentMismatch),
        }
    }
    if slot.is_none() {
        io.admit_original_allocation(parent, 0, 1)?;
        io.before_io(0)?;
        let actual = rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700));
        *io.raw = Some(JournalHistoryIoResult::Mkdir(actual));
        clock.require_effect()?;
        match io.raw.as_ref() {
            Some(JournalHistoryIoResult::Mkdir(Ok(()))) => {}
            Some(JournalHistoryIoResult::Mkdir(Err(rustix::io::Errno::EXIST))) => return Err(Fault::IntentMismatch),
            Some(JournalHistoryIoResult::Mkdir(Err(_))) => return Err(Fault::IoFailure),
            _ => return Err(Fault::IntentMismatch),
        }
        io.before_io(1)?;
        let actual = rustix::fs::openat(parent, name, flags, Mode::empty());
        *io.raw = Some(JournalHistoryIoResult::Open(actual));
        clock.require_effect()?;
        match io.raw.as_ref() {
            Some(JournalHistoryIoResult::Open(Ok(_))) => {}
            Some(JournalHistoryIoResult::Open(Err(_))) => return Err(Fault::IoFailure),
            _ => return Err(Fault::IntentMismatch),
        }
        let actual = io.raw.take();
        match actual {
            Some(JournalHistoryIoResult::Open(Ok(fd))) => *slot = Some(File::from(fd)),
            other => { *io.raw = other; return Err(Fault::IntentMismatch); }
        }
        created = true;
    }
    let held = slot.as_ref().ok_or(Fault::IntentMismatch)?;
    verify_named_directory(parent, name, held, clock, io)?;
    if created {
        io.observe_original_allocation(parent, held)?;
        sync(held, clock, io)?;
        sync(parent, clock, io)?;
    }
    Ok(())
}
fn verify_named_directory(
    parent: &File, name: &str, held: &File,
    clock: &CaptureOperation, io: &mut HistoryIo<'_>,
) -> Result<(), Fault> {
    if !matches!(io.clock, Some((original, false)) if std::ptr::eq(original, clock)) {
        return Err(Fault::IntentMismatch);
    }
    const FIXED_METADATA: u64 = {
        let slots = [
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 6usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<&CaptureOperation>(), core::mem::align_of::<&CaptureOperation>(), 2usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 3usize),
            (core::mem::size_of::<Option<&File>>(), core::mem::align_of::<Option<&File>>(), 2usize),
            (core::mem::size_of::<&str>(), core::mem::align_of::<&str>(), 2usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 2usize),
            (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 2usize),
            (core::mem::size_of::<RecordIdentity>(), core::mem::align_of::<RecordIdentity>(), 2usize),
            (core::mem::size_of::<(u64, u64, u32)>(), core::mem::align_of::<(u64, u64, u32)>(), 2usize),
            (core::mem::size_of::<rustix::fs::Stat>(), core::mem::align_of::<rustix::fs::Stat>(), 2usize),
            (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 2usize),
            (core::mem::size_of::<Option<&JournalHistoryIoResult>>(), core::mem::align_of::<Option<&JournalHistoryIoResult>>(), 2usize),
            (core::mem::size_of::<Fault>(), core::mem::align_of::<Fault>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed helper layout fits usize").checked_mul(slots[at].2)
                .expect("fixed helper count fits usize"))
                .expect("fixed helper slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    clock.require_effect()?;
    super::reserve_capture_resources(&clock.resources, 0, FIXED_METADATA)?;
    let st = io.stat(HistoryFd::Original(parent), name, Fault::PathUnsafe)?;
    let m = io.metadata(HistoryFd::Original(held))?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::Directory
        || !m.is_dir() || m.mode() & 0o7777 != 0o700
        || m.uid() != rustix::process::geteuid().as_raw()
    { return Err(Fault::PathUnsafe); }
    if (st.st_dev as u64, st.st_ino as u64, st.st_uid) != (m.dev(), m.ino(), m.uid()) {
        return Err(Fault::SourceChanged);
    }
    if st.st_mode as u32 & 0o7777 != m.mode() & 0o7777 { return Err(Fault::PathUnsafe); }
    Ok(())
}
fn runtime_clone(
    file: &File,
    clock: &CaptureOperation,
    slot: &mut Option<File>,
) -> Result<(), Fault> {
    runtime_clone_for_fact(file, clock, false, &clock.resources, slot)
}
fn runtime_clone_for_fact(
    file: &File,
    clock: &dyn CaptureClockCheck,
    closing_fact: bool,
    resources: &Arc<std::sync::Mutex<super::CaptureResourceTotals>>,
    slot: &mut Option<File>,
) -> Result<(), Fault> {
    runtime_clone_for_fact_observed(file, clock, closing_fact, resources, slot, None)
}
fn runtime_clone_for_fact_observed(
    file: &File,
    clock: &dyn CaptureClockCheck,
    closing_fact: bool,
    resources: &Arc<std::sync::Mutex<super::CaptureResourceTotals>>,
    slot: &mut Option<File>,
    mut error_slot: Option<&mut Option<io::Error>>,
) -> Result<(), Fault> {
    // Known fixed logical slots only; opaque producer/allocator peaks remain held.
    const FIXED_METADATA: u64 = {
        let slots = [
            (core::mem::size_of::<io::Result<File>>(), core::mem::align_of::<io::Result<File>>(), 1usize),
            (core::mem::size_of::<Option<io::Error>>(), core::mem::align_of::<Option<io::Error>>(), 1usize),
            (core::mem::size_of::<io::Error>(), core::mem::align_of::<io::Error>(), 1usize),
            (core::mem::size_of::<Option<io::Error>>(), core::mem::align_of::<Option<io::Error>>(), 1usize),
            (core::mem::size_of::<Option<&mut Option<io::Error>>>(), core::mem::align_of::<Option<&mut Option<io::Error>>>(), 4usize),
            (core::mem::size_of::<Option<&&mut Option<io::Error>>>(), core::mem::align_of::<Option<&&mut Option<io::Error>>>(), 2usize),
            (core::mem::size_of::<Option<&io::Error>>(), core::mem::align_of::<Option<&io::Error>>(), 2usize),
            (core::mem::size_of::<&io::Error>(), core::mem::align_of::<&io::Error>(), 2usize),
            (core::mem::size_of::<File>(), core::mem::align_of::<File>(), 1usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 1usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            let one = slots[at].0.checked_add(slots[at].1)
                .expect("fixed journal slot layout fits usize");
            let amount = one.checked_mul(slots[at].2)
                .expect("fixed journal slot count fits usize");
            bytes = bytes.checked_add(amount)
                .expect("fixed journal slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    if slot.is_some() || error_slot.as_ref().is_some_and(|original| original.is_some()) {
        return Err(Fault::IntentMismatch);
    }
    let guard = || if closing_fact { clock.require_closing() } else { clock.require_effect() };
    guard()?;
    super::reserve_capture_resources(resources, 1, FIXED_METADATA)?;
    guard()?;
    let copied = file.try_clone();
    let error = match copied {
        Ok(file) => { *slot = Some(file); None }
        Err(error) => match error_slot.as_deref_mut() {
            Some(original) => { *original = Some(error); None }
            None => Some(error),
        },
    };
    guard()?;
    if error_slot.as_ref().is_some_and(|original| original.is_some()) {
        return Err(Fault::IoFailure);
    }
    match error {
        Some(error) => Err(io_fault(error)),
        None => Ok(()),
    }
}
fn runtime_identity(file: &File, clock: &CaptureOperation, io: &mut HistoryIo<'_>) -> Result<Identity, Fault> {
    if !matches!(io.clock, Some((original, false)) if std::ptr::eq(original, clock)) {
        return Err(Fault::IntentMismatch);
    }
    const FIXED_METADATA: u64 = {
        let slots = [
            (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 3usize),
            (core::mem::size_of::<Result<Identity, Fault>>(), core::mem::align_of::<Result<Identity, Fault>>(), 3usize),
            (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 2usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 2usize),
            (core::mem::size_of::<&CaptureOperation>(), core::mem::align_of::<&CaptureOperation>(), 2usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed helper layout fits usize").checked_mul(slots[at].2)
                .expect("fixed helper count fits usize"))
                .expect("fixed helper slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    clock.require_effect()?;
    super::reserve_capture_resources(&clock.resources, 0, FIXED_METADATA)?;
    let m = io.metadata(HistoryFd::Original(file))?;
    Ok(Identity::of(&m))
}
fn runtime_record_identity(file: &File, clock: &CaptureOperation, io: &mut HistoryIo<'_>) -> Result<RecordIdentity, Fault> {
    // Only the known new fixed return slots are prepaid on the original book.
    // This is not an allocator, opaque payload or whole-operation peak proof.
    const POST_IO_METADATA: u64 = {
        let metadata = core::mem::size_of::<io::Result<Metadata>>()
            .checked_add(core::mem::align_of::<io::Result<Metadata>>())
            .expect("fixed metadata return layout fits usize");
        let clock_or_admission = core::mem::size_of::<Result<(), Fault>>()
            .checked_add(core::mem::align_of::<Result<(), Fault>>())
            .expect("fixed control return layout fits usize")
            .checked_mul(3)
            .expect("fixed control return count fits usize");
        let identity = core::mem::size_of::<RecordIdentity>()
            .checked_add(core::mem::align_of::<RecordIdentity>())
            .expect("fixed witness identity transfers fit usize")
            .checked_mul(2)
            .expect("fixed witness identity transfers fit usize");
        let returned = core::mem::size_of::<Result<RecordIdentity, Fault>>()
            .checked_add(core::mem::align_of::<Result<RecordIdentity, Fault>>())
            .expect("fixed witness returns fit usize")
            .checked_mul(2)
            .expect("fixed witness returns fit usize");
        let bytes = metadata.checked_add(clock_or_admission)
            .expect("fixed metadata postcheck slots fit usize")
            .checked_add(identity)
            .expect("fixed metadata postcheck slots fit usize")
            .checked_add(returned)
            .expect("fixed metadata postcheck slots fit usize");
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    if !matches!(io.clock, Some((original, false)) if std::ptr::eq(original, clock))
        || io.maximum_files != 4 || io.original_objects.is_some()
    { return Err(Fault::IntentMismatch); }
    clock.require_effect()?;
    super::reserve_capture_resources(&clock.resources, 0, POST_IO_METADATA)?;
    clock.require_effect()?;
    // The full actual Metadata result is in the same Work before post-E.
    let m = io.metadata(HistoryFd::Original(file))?;
    if !m.is_file()
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(Fault::PathUnsafe);
    }
    Ok(RecordIdentity::of(&m))
}
fn runtime_bound_path(file: &File, clock: &CaptureOperation, io: &mut HistoryIo<'_>, path_slot: &mut Option<PathBuf>) -> Result<(), Fault> {
    if path_slot.is_some() || !matches!(io.clock, Some((original, false)) if std::ptr::eq(original, clock)) {
        return Err(Fault::IntentMismatch);
    }
    // Locked rustix1.1.4/libc0.2.189 macOS getpath uses PATH_MAX1024.
    // Four requested backing bounds plus a distinct pathname conversion bound;
    // no old allocation refund, no no-copy or allocator-opaque exemption.
    const MAX_PATH: usize = 1024;
    const PATH_BACKING: u64 = {
        let initial = MAX_PATH.checked_mul(4).expect("fixed pinned path requests fit usize");
        let pathname = MAX_PATH.checked_add(1).expect("fixed pathname request fits usize");
        let bytes = initial.checked_add(pathname).expect("fixed pinned path requests fit usize");
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    const FIXED_METADATA: u64 = {
        let slots = [
            (core::mem::size_of::<std::ffi::CString>(), core::mem::align_of::<std::ffi::CString>(), 3usize),
            (core::mem::size_of::<std::ffi::OsString>(), core::mem::align_of::<std::ffi::OsString>(), 3usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 3usize),
            (core::mem::size_of::<Box<[u8]>>(), core::mem::align_of::<Box<[u8]>>(), 2usize),
            (core::mem::size_of::<Option<u8>>(), core::mem::align_of::<Option<u8>>(), 1usize),
            (core::mem::size_of::<PathBuf>(), core::mem::align_of::<PathBuf>(), 3usize),
            (core::mem::size_of::<Option<PathBuf>>(), core::mem::align_of::<Option<PathBuf>>(), 2usize),
            (core::mem::size_of::<Option<&PathBuf>>(), core::mem::align_of::<Option<&PathBuf>>(), 2usize),
            (core::mem::size_of::<rustix::io::Result<std::ffi::CString>>(), core::mem::align_of::<rustix::io::Result<std::ffi::CString>>(), 2usize),
            (core::mem::size_of::<Option<&JournalHistoryIoResult>>(), core::mem::align_of::<Option<&JournalHistoryIoResult>>(), 2usize),
            (core::mem::size_of::<Metadata>(), core::mem::align_of::<Metadata>(), 2usize),
            (core::mem::size_of::<Identity>(), core::mem::align_of::<Identity>(), 3usize),
            (core::mem::size_of::<Result<Identity, Fault>>(), core::mem::align_of::<Result<Identity, Fault>>(), 2usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 5usize),
            (core::mem::size_of::<&Path>(), core::mem::align_of::<&Path>(), 3usize),
            (core::mem::size_of::<&std::ffi::OsStr>(), core::mem::align_of::<&std::ffi::OsStr>(), 2usize),
            (core::mem::size_of::<&[u8]>(), core::mem::align_of::<&[u8]>(), 2usize),
            (core::mem::size_of::<std::path::Components<'static>>(), core::mem::align_of::<std::path::Components<'static>>(), 2usize),
            (core::mem::size_of::<std::path::Component<'static>>(), core::mem::align_of::<std::path::Component<'static>>(), 2usize),
            (core::mem::size_of::<Option<std::path::Component<'static>>>(), core::mem::align_of::<Option<std::path::Component<'static>>>(), 2usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 2usize),
            (core::mem::size_of::<&mut Option<PathBuf>>(), core::mem::align_of::<&mut Option<PathBuf>>(), 2usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 3usize),
            (core::mem::size_of::<bool>(), core::mem::align_of::<bool>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed helper layout fits usize").checked_mul(slots[at].2)
                .expect("fixed helper count fits usize"))
                .expect("fixed helper slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    clock.require_effect()?;
    super::reserve_capture_resources(&clock.resources, 0,
        FIXED_METADATA.checked_add(PATH_BACKING).ok_or(Fault::BoundsOverflow)?)?;
    io.before_io(0)?;
    let actual = rustix::fs::getpath(file);
    *io.raw = Some(JournalHistoryIoResult::GetPath(actual));
    clock.require_effect()?;
    match io.raw.as_ref() {
        Some(JournalHistoryIoResult::GetPath(Ok(path))) if path.as_bytes_with_nul().len() <= MAX_PATH => {}
        Some(JournalHistoryIoResult::GetPath(Ok(_))) => return Err(Fault::CapacityExceeded),
        Some(JournalHistoryIoResult::GetPath(Err(_))) => return Err(Fault::IoFailure),
        _ => return Err(Fault::IntentMismatch),
    }
    // Only infallible moves of the same returned backing precede the owner
    // slot; no allocation, clock call or IO occurs in this linear transfer.
    let actual = io.raw.take();
    match actual {
        Some(JournalHistoryIoResult::GetPath(Ok(path))) => {
            *path_slot = Some(PathBuf::from(std::ffi::OsString::from_vec(path.into_bytes())));
        }
        other => { *io.raw = other; return Err(Fault::IntentMismatch); }
    }
    let path = path_slot.as_ref().ok_or(Fault::IntentMismatch)?;
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() >= MAX_PATH {
        return Err(Fault::PathUnsafe);
    }
    io.before_io(0)?;
    let actual = std::fs::symlink_metadata(path);
    *io.raw = Some(JournalHistoryIoResult::Metadata(actual));
    clock.require_effect()?;
    let m = match io.raw.as_ref() {
        Some(JournalHistoryIoResult::Metadata(Ok(value))) => value.clone(),
        Some(JournalHistoryIoResult::Metadata(Err(_))) => return Err(Fault::IoFailure),
        _ => return Err(Fault::IntentMismatch),
    };
    if m.file_type().is_symlink() { return Err(Fault::PathUnsafe); }
    if Identity::of(&m) != runtime_identity(file, clock, io)? { return Err(Fault::SourceChanged); }
    Ok(())
}
fn open_read(parent: &File, name: &str) -> Result<File, Fault> {
    let fd = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| Fault::PathUnsafe)?;
    let m = fd.metadata().map_err(io_fault)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o600
    {
        return Err(Fault::PathUnsafe);
    }
    Ok(fd)
}
fn read_record(
    parent: &File,
    name: &str,
    limit: u64,
    clock: Option<(&CaptureOperation, bool)>,
    objects: Option<&mut super::OriginalControlStorageFacts>,
) -> Result<Vec<u8>, Fault> {
    read_bound_record_observed(parent, name, limit, clock, None, objects)
}
fn read_bound_record(
    parent: &File,
    name: &str,
    limit: u64,
    clock: Option<(&CaptureOperation, bool)>,
    expected: Option<RecordIdentity>,
) -> Result<Vec<u8>, Fault> {
    read_bound_record_observed(parent, name, limit, clock, expected, None)
}
fn read_bound_record_observed(
    parent: &File,
    name: &str,
    limit: u64,
    clock: Option<(&CaptureOperation, bool)>,
    expected: Option<RecordIdentity>,
    objects: Option<&mut super::OriginalControlStorageFacts>,
) -> Result<Vec<u8>, Fault> {
    let mut files = Vec::new();
    let mut directory = None;
    let mut frames = Vec::new();
    let mut matched = Vec::new();
    let mut raw = None;
    let mut bytes = Vec::new();
    let mut io = HistoryIo { fs_admission: None, fs_observations: None,  clock, original_objects: None, maximum_files: 2, files: &mut files,
        directory: &mut directory, frames: &mut frames, matched: &mut matched,
        raw: &mut raw, bytes: &mut bytes };
    history_read_record(HistoryFd::Original(parent), name, limit, expected, objects, &mut io)
}

fn read_bound_record_resident(
    parent: &File,
    name: &str,
    limit: u64,
    expected: Option<RecordIdentity>,
    io: &mut HistoryIo<'_>,
    output: &mut Option<Result<(usize, Vec<u8>), Fault>>,
) -> Result<(), Fault> {
    if output.is_some() || io.clock.is_none() || io.maximum_files != 4
        || io.original_objects.is_some()
    { return Err(Fault::IntentMismatch); }
    // Actual complete core/result/Option transfers, borrowed matches and
    // caller outputs coexist. This fee never substitutes for buffer backing.
    const RESULT_TRANSFERS: u64 = {
        let slots = [
            (core::mem::size_of::<Result<(usize, usize), Fault>>(), core::mem::align_of::<Result<(usize, usize), Fault>>(), 2usize),
            (core::mem::size_of::<(usize, usize)>(), core::mem::align_of::<(usize, usize)>(), 2usize),
            (core::mem::size_of::<(usize, Vec<u8>)>(), core::mem::align_of::<(usize, Vec<u8>)>(), 3usize),
            (core::mem::size_of::<Result<(usize, Vec<u8>), Fault>>(), core::mem::align_of::<Result<(usize, Vec<u8>), Fault>>(), 3usize),
            (core::mem::size_of::<Option<Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<Option<Result<(usize, Vec<u8>), Fault>>>(), 2usize),
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>(), 3usize),
            (core::mem::size_of::<Option<&Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<Option<&Result<(usize, Vec<u8>), Fault>>>(), 2usize),
            (core::mem::size_of::<&Vec<u8>>(), core::mem::align_of::<&Vec<u8>>(), 2usize),
            (core::mem::size_of::<&Fault>(), core::mem::align_of::<&Fault>(), 2usize),
            (core::mem::size_of::<Fault>(), core::mem::align_of::<Fault>(), 2usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<&mut Option<Result<(usize, Vec<u8>), Fault>>>(), core::mem::align_of::<&mut Option<Result<(usize, Vec<u8>), Fault>>>(), 2usize),
            (core::mem::size_of::<Option<RecordIdentity>>(), core::mem::align_of::<Option<RecordIdentity>>(), 2usize),
            (core::mem::size_of::<RecordIdentity>(), core::mem::align_of::<RecordIdentity>(), 2usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 2usize),
            (core::mem::size_of::<&str>(), core::mem::align_of::<&str>(), 2usize),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>(), 5usize),
            (core::mem::size_of::<u64>(), core::mem::align_of::<u64>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed record result layout fits usize").checked_mul(slots[at].2)
                .expect("fixed record result count fits usize"))
                .expect("fixed record result transfers fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    io.admit(0, RESULT_TRANSFERS)?;
    let returned = history_read_record_core(HistoryFd::Original(parent), name, limit, expected, None, io);
    *output = Some(match returned {
        Ok((index, length)) => {
            io.bytes.truncate(length);
            Ok((index, std::mem::take(io.bytes)))
        }
        Err(fault) => Err(fault),
    });
    // An already selected original failure wins. A late final guard can fail
    // with an actual completed body still resident, never erased or replaced.
    if let Some(Err(fault)) = output.as_ref() { return Err(*fault); }
    io.guard()
}

fn create_record(
    parent: &File,
    name: &str,
    bytes: &[u8],
    clock: &CaptureOperation,
    closing: bool,
    reserve: u64,
    floor: u64,
    allocation: u64,
    retained: &mut Vec<File>,
    io: &mut HistoryIo<'_>,
    output: &mut Option<Result<(usize, Vec<u8>), Fault>>,
) -> Result<(), Fault> {
    if output.is_some() || io.maximum_files != 4 || io.original_objects.is_some()
        || !matches!(io.clock, Some((original, mode)) if std::ptr::eq(original, clock) && mode == closing)
    { return Err(Fault::IntentMismatch); }
    // Prepay only the known fixed return/transfer slots; opaque internals remain
    // outside this local proof. The existing same-owner book never refunds them.
    const POST_IO_METADATA: u64 = {
        let statvfs = core::mem::size_of::<rustix::io::Result<rustix::fs::StatVfs>>()
            .checked_add(core::mem::align_of::<rustix::io::Result<rustix::fs::StatVfs>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let open = core::mem::size_of::<rustix::io::Result<rustix::fd::OwnedFd>>()
            .checked_add(core::mem::align_of::<rustix::io::Result<rustix::fd::OwnedFd>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let open_error = core::mem::size_of::<Option<rustix::io::Errno>>()
            .checked_add(core::mem::align_of::<Option<rustix::io::Errno>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let errno_transfer = core::mem::size_of::<rustix::io::Errno>()
            .checked_add(core::mem::align_of::<rustix::io::Errno>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let fd_transfer = core::mem::size_of::<rustix::fd::OwnedFd>()
            .checked_add(core::mem::align_of::<rustix::fd::OwnedFd>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let metadata = core::mem::size_of::<io::Result<Metadata>>()
            .checked_add(core::mem::align_of::<io::Result<Metadata>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(3)
            .expect("fixed control IO slot count fits usize");
        let write = core::mem::size_of::<io::Result<usize>>()
            .checked_add(core::mem::align_of::<io::Result<usize>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(1)
            .expect("fixed control IO slot count fits usize");
        let fsync = core::mem::size_of::<io::Result<()>>()
            .checked_add(core::mem::align_of::<io::Result<()>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(2)
            .expect("fixed control IO slot count fits usize");
        let clock_or_admission = core::mem::size_of::<Result<(), Fault>>()
            .checked_add(core::mem::align_of::<Result<(), Fault>>())
            .expect("fixed control IO slot layout fits usize")
            .checked_mul(10)
            .expect("fixed control IO slot count fits usize");
        let bytes = statvfs
            .checked_add(open)
            .expect("fixed control IO slots fit usize")
            .checked_add(open_error)
            .expect("fixed control IO slots fit usize")
            .checked_add(errno_transfer)
            .expect("fixed control IO slots fit usize")
            .checked_add(fd_transfer)
            .expect("fixed control IO slots fit usize")
            .checked_add(metadata)
            .expect("fixed control IO slots fit usize")
            .checked_add(write)
            .expect("fixed control IO slots fit usize")
            .checked_add(fsync)
            .expect("fixed control IO slots fit usize")
            .checked_add(clock_or_admission)
            .expect("fixed control IO slots fit usize");
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    let guard = || {
        if closing {
            clock.require_closing()
        } else {
            clock.require_effect()
        }
    };
    guard()?;
    super::reserve_capture_resources(&clock.resources, 0, POST_IO_METADATA)?;
    guard()?;
    io.before_io(0)?;
    let stats = rustix::fs::fstatvfs(parent);
    *io.raw = Some(JournalHistoryIoResult::StatVfs(stats));
    guard()?;
    let available = match io.raw.as_ref() {
        Some(JournalHistoryIoResult::StatVfs(Ok(stat))) => stat.f_bavail
            .checked_mul(stat.f_frsize).ok_or(Fault::BoundsOverflow)?,
        Some(JournalHistoryIoResult::StatVfs(Err(_))) => return Err(Fault::IoFailure),
        _ => return Err(Fault::IntentMismatch),
    };
    if bytes.len() as u64 > allocation
        || available < checked_add(bytes.len() as u64, reserve.max(floor))?
    {
        return Err(Fault::CapacityExceeded);
    }
    guard()?;
    if retained.len() >= 2 || retained.capacity() != 2 {
        return Err(Fault::CapacityExceeded);
    }
    // The original job prepaid/allocated these two writer slots. This call
    // cannot grow backing; the distinct actual opened FD is charged below.
    retained.try_reserve_exact(1).map_err(|_| Fault::CapacityExceeded)?;
    io.admit_original_allocation(parent, 0, 1)?;
    io.before_io(1)?;
    let opened = rustix::fs::openat(
        parent,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    );
    *io.raw = Some(JournalHistoryIoResult::Open(opened));
    guard()?;
    match io.raw.as_ref() {
        Some(JournalHistoryIoResult::Open(Err(rustix::io::Errno::EXIST))) => return Err(Fault::IntentMismatch),
        Some(JournalHistoryIoResult::Open(Err(_))) => return Err(Fault::IoFailure),
        Some(JournalHistoryIoResult::Open(Ok(_))) => {}
        _ => return Err(Fault::IntentMismatch),
    }
    let actual = io.raw.take();
    match actual {
        Some(JournalHistoryIoResult::Open(Ok(fd))) => retained.push(File::from(fd)),
        other => { *io.raw = other; return Err(Fault::IntentMismatch); }
    }
    let file = retained.last().ok_or(Fault::IntentMismatch)?;
    let m = io.metadata(HistoryFd::Original(file))?;
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || m.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(Fault::PathUnsafe);
    }
    io.observe_original_allocation(parent, file)?;
    guard()?;
    let mut at = 0usize;
    while at < bytes.len() {
        guard()?;
        let end = bytes
            .len()
            .min(at.checked_add(64 * 1024).ok_or(Fault::BoundsOverflow)?);
        io.admit_original_allocation(parent, (end - at) as u64, 0)?;
        io.before_io(0)?;
        let written = file.write_at(&bytes[at..end], at as u64);
        *io.raw = Some(JournalHistoryIoResult::Write(written));
        guard()?;
        let n = match io.raw.as_ref() {
            Some(JournalHistoryIoResult::Write(Ok(count))) => *count,
            Some(JournalHistoryIoResult::Write(Err(_))) => return Err(Fault::IoFailure),
            _ => return Err(Fault::IntentMismatch),
        };
        if n == 0 {
            return Err(Fault::IoFailure);
        }
        at = at.checked_add(n).ok_or(Fault::BoundsOverflow)?;
        io.observe_original_allocation(parent, file)?;
    }
    io.admit_original_allocation(parent, 0, 0)?;
    io.before_io(0)?;
    let synced_file = file.sync_all();
    *io.raw = Some(JournalHistoryIoResult::Sync(synced_file));
    guard()?;
    match io.raw.as_ref() {
        Some(JournalHistoryIoResult::Sync(Ok(()))) => {}
        Some(JournalHistoryIoResult::Sync(Err(_))) => return Err(Fault::IoFailure),
        _ => return Err(Fault::IntentMismatch),
    }
    io.observe_original_allocation(parent, file)?;
    io.admit_original_allocation(parent, 0, 0)?;
    io.before_io(0)?;
    let synced_parent = parent.sync_all();
    *io.raw = Some(JournalHistoryIoResult::Sync(synced_parent));
    guard()?;
    match io.raw.as_ref() {
        Some(JournalHistoryIoResult::Sync(Ok(()))) => {}
        Some(JournalHistoryIoResult::Sync(Err(_))) => return Err(Fault::IoFailure),
        _ => return Err(Fault::IntentMismatch),
    }
    io.observe_original_allocation(parent, file)?;
    // The separate actual read FD/body/result stay in the same original Work.
    guard()?;
    let original = io.metadata(HistoryFd::Original(file))?;
    read_bound_record_resident(parent, name, bytes.len() as u64,
        Some(RecordIdentity::of(&original)), io, output)?;
    guard()?;
    let original_after = io.metadata(HistoryFd::Original(file))?;
    if RecordIdentity::of(&original_after) != RecordIdentity::of(&original) {
        return Err(Fault::IntentMismatch);
    }
    guard()?;
    let observed = match output.as_ref() {
        Some(Ok((_, body))) => body,
        Some(Err(fault)) => return Err(*fault),
        None => return Err(Fault::IntentMismatch),
    };
    if observed.as_slice() != bytes {
        return Err(Fault::ReadbackFailed);
    }
    Ok(())
}
fn sync(file: &File, clock: &CaptureOperation, io: &mut HistoryIo<'_>) -> Result<(), Fault> {
    if !matches!(io.clock, Some((original, false)) if std::ptr::eq(original, clock)) {
        return Err(Fault::IntentMismatch);
    }
    const FIXED_METADATA: u64 = {
        let slots = [
            (core::mem::size_of::<io::Result<()>>(), core::mem::align_of::<io::Result<()>>(), 2usize),
            (core::mem::size_of::<Result<(), Fault>>(), core::mem::align_of::<Result<(), Fault>>(), 4usize),
            (core::mem::size_of::<&File>(), core::mem::align_of::<&File>(), 2usize),
            (core::mem::size_of::<&CaptureOperation>(), core::mem::align_of::<&CaptureOperation>(), 2usize),
            (core::mem::size_of::<&mut HistoryIo<'static>>(), core::mem::align_of::<&mut HistoryIo<'static>>(), 2usize),
            (core::mem::size_of::<Option<&JournalHistoryIoResult>>(), core::mem::align_of::<Option<&JournalHistoryIoResult>>(), 2usize),
        ];
        let mut at = 0usize;
        let mut bytes = 0usize;
        while at < slots.len() {
            bytes = bytes.checked_add(slots[at].0.checked_add(slots[at].1)
                .expect("fixed helper layout fits usize").checked_mul(slots[at].2)
                .expect("fixed helper count fits usize"))
                .expect("fixed helper slots fit usize");
            at += 1;
        }
        assert!(usize::BITS <= u64::BITS);
        bytes as u64
    };
    clock.require_effect()?;
    super::reserve_capture_resources(&clock.resources, 0, FIXED_METADATA)?;
    io.admit_original_allocation(file, 0, 0)?;
    io.before_io(0)?;
    let actual = file.sync_all();
    *io.raw = Some(JournalHistoryIoResult::Sync(actual));
    clock.require_effect()?;
    match io.raw.as_ref() {
        Some(JournalHistoryIoResult::Sync(Ok(()))) => io.observe_original_allocation(file, file),
        Some(JournalHistoryIoResult::Sync(Err(_))) => Err(Fault::IoFailure),
        _ => Err(Fault::IntentMismatch),
    }
}
fn encode<T: Serialize>(value: &T, limit: u64) -> Result<Vec<u8>, Fault> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Bounded {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if b.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            self.bytes
                .try_reserve_exact(b.len())
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
            self.bytes.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let maximum = usize::try_from(limit).map_err(|_| Fault::CapacityExceeded)?;
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(maximum)
        .map_err(|_| Fault::CapacityExceeded)?;
    if storage.capacity() > maximum {
        return Err(Fault::CapacityExceeded);
    }
    let mut sink = Bounded {
        bytes: storage,
        limit: maximum,
    };
    serde_json::to_writer(&mut sink, value).map_err(|_| Fault::CapacityExceeded)?;
    Ok(sink.bytes)
}
fn decode<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8]) -> Result<T, Fault> {
    let v: T = serde_json::from_slice(bytes).map_err(|_| Fault::ClosingPending)?;
    if encode(&v, bytes.len() as u64)? != bytes {
        return Err(Fault::NonCanonical);
    }
    Ok(v)
}
fn hash_encoded<T: Serialize>(v: &T, limit: u64) -> Result<[u8; 32], Fault> {
    Ok(Sha256::digest(encode(v, limit)?).into())
}
fn checked_add(a: u64, b: u64) -> Result<u64, Fault> {
    a.checked_add(b).ok_or(Fault::BoundsOverflow)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn uuid(bytes: [u8; 16]) -> String {
    let hex = b"0123456789abcdef";
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        output.push(char::from(hex[usize::from(byte >> 4)]));
        output.push(char::from(hex[usize::from(byte & 15)]));
    }
    output
}
fn uuid_bytes(value: &str) -> Result<[u8; 16], Fault> {
    let input = value.as_bytes();
    if input.len() != 36 || input[14] != b'4' {
        return Err(Fault::IntentMismatch);
    }
    let mut out = [0u8; 16];
    let mut digit = 0usize;
    for (index, byte) in input.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return Err(Fault::IntentMismatch);
            }
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err(Fault::IntentMismatch),
        };
        out[digit / 2] = (out[digit / 2] << 4) | nibble;
        digit += 1;
    }
    Ok(out)
}
fn digest_text(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn io_fault(_: io::Error) -> Fault {
    Fault::IoFailure
}

fn fault_text(s: &str) -> bool {
    matches!(
        s,
        "InvalidArgument"
            | "UnsupportedVersion"
            | "ProfileMissing"
            | "ProfileInvalid"
            | "BoundsOverflow"
            | "CapacityExceeded"
            | "ClockUnavailable"
            | "DeadlineExpired"
            | "Cancelled"
            | "IntentMismatch"
            | "ManifestInvalid"
            | "NonCanonical"
            | "MaterialMissing"
            | "ExtraMaterial"
            | "SourceChanged"
            | "PathUnsafe"
            | "SecretInvalid"
            | "NonceExhausted"
            | "FrameInvalid"
            | "AuthenticationFailed"
            | "ShortRead"
            | "ExtraTail"
            | "TerminalMissing"
            | "KeyMediumInvalid"
            | "ReadbackFailed"
            | "PublishUnknown"
            | "IoFailure"
            | "ClosingPending"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDINARY_STARTUP_HISTORY_PROFILE_JSON: &str = r#"{
  "native": {
    "effectNs": 120000000000,
    "convergenceNs": 30000000000,
    "maxSourceSecretBytes": 4096,
    "maxSecretMemoryBytes": 2097152,
    "maxNativeSecretCopies": 32,
    "maxControlBytes": 4224,
    "maxStatusBytes": 5376,
    "maxStatusRecords": 32,
    "maxStderrBytes": 65536,
    "maxMaterialFiles": 16384,
    "maxDirectories": 4096,
    "maxPathBytes": 4096,
    "maxDepth": 64,
    "maxSingleFileBytes": 268435456,
    "maxMaterialPlainBytes": 536870912,
    "maxWalBytes": 134217728,
    "maxWalSegments": 8,
    "maxWalSpanBytes": 134217728,
    "maxWalTimelines": 1,
    "maxBackupManifestBytes": 8388608,
    "maxTotalCopyBlocks": 65536,
    "copyBlockBytes": 65536,
    "maxSpoolBytes": 536870912,
    "maxRestoreCheckBytes": 536870912,
    "maxOpenFiles": 64,
    "maxJournalBytes": 16777216,
    "capacityReserveBytes": 67108864,
    "freeFloorBytes": 5368709120
  },
  "carrier": {
    "maxMaterialFiles": 32768,
    "maxDirectories": 8192,
    "maxPathBytes": 4096,
    "maxPathDepth": 64,
    "maxSinglePlainBytes": 1073741824,
    "maxMaterialPlainBytes": 2147483648,
    "maxManifestBytes": 4194304,
    "maxHeaderBytes": 4096,
    "maxDataChunks": 32768,
    "maxChunkPlainBytes": 65536,
    "maxWireBytes": 3221225472,
    "maxMetadataBytes": 268435456,
    "maxOpenFiles": 2048,
    "maxSnapshotBytes": 1073741824,
    "maxSpoolBytes": 1073741824,
    "maxRetainedPriorBytes": 1073741824,
    "maxJournalBytes": 16777216,
    "maxTotalAllocationBytes": 8589934592,
    "capacityReserveBytes": 67108864,
    "freeFloorBytes": 5368709120,
    "maxKeyMediumAllocationBytes": 2097152,
    "keyMediumReserveBytes": 1048576,
    "keyMediumFreeFloorBytes": 5368709120
  },
  "secrets": {
    "maxSourceSecretCount": 2,
    "maxOneSourceSecretBytes": 4096,
    "maxTotalSourceSecretBytes": 8192,
    "maxSecretStructureBytes": 67108864,
    "maxSecretMemoryBytes": 134217728,
    "classes": {
      "masterSource": {
        "maxCount": 1,
        "maxOneBytes": 32
      },
      "credentialWrapping": {
        "maxCount": 1,
        "maxOneBytes": 32
      },
      "remoteAssertionSigning": {
        "maxCount": 1,
        "maxOneBytes": 32
      },
      "applicationDerived": {
        "maxCount": 26,
        "maxOneBytes": 32
      },
      "scramSource": {
        "maxCount": 1,
        "maxOneBytes": 64
      },
      "pgConfigPasswords": {
        "maxCount": 67,
        "maxOneBytes": 64
      },
      "nativeSecretFrames": {
        "maxCount": 32,
        "maxOneBytes": 64
      },
      "recoveryKey": {
        "maxCount": 1,
        "maxOneBytes": 32
      },
      "streamKey": {
        "maxCount": 1,
        "maxOneBytes": 32
      },
      "keyMediumReadback": {
        "maxCount": 1,
        "maxOneBytes": 32
      },
      "decodeCryptoTemporary": {
        "maxCount": 8,
        "maxOneBytes": 65536
      }
    }
  },
  "drivers": {
    "maxLiveOriginalTasks": 64,
    "maxUnjoinedOriginalTasks": 64,
    "maxPendingConnects": 64,
    "maxLiveProxies": 16,
    "maxOwnerMetadataBytes": 16777216
  },
  "sql": {
    "maxRows": 4096,
    "maxRowBytes": 8192,
    "maxFieldBytes": 4096,
    "maxPages": 1024,
    "pageRows": 64,
    "maxCatalogObjects": 1024,
    "maxQueryTasks": 64,
    "phaseNs": 30000000000
  }
}"#;

    #[test]
    fn control_unknown_existing_layout_is_pending_and_not_repaired() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let profile: CaptureProfile =
            serde_json::from_str(ORDINARY_STARTUP_HISTORY_PROFILE_JSON).unwrap();
        Limits::from_profile(&profile).unwrap();

        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let root = PathBuf::from(format!(
            "/private/tmp/wb45-control-startup-unknown-{}",
            hex(&random)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let app = File::open(&root).unwrap();
        assert_eq!(inspect_startup_control(&app, None), Ok(()));

        let control = root.join(CONTROL);
        let requests = control.join("requests");
        let operations = control.join("operations");
        for directory in [&control, &requests, &operations] {
            std::fs::create_dir(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let unexpected_path = control.join("unexpected");
        let mut unexpected = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&unexpected_path)
            .unwrap();
        std::io::Write::write_all(&mut unexpected, b"do-not-adopt").unwrap();
        unexpected.sync_all().unwrap();
        let original = RecordIdentity::of(&unexpected.metadata().unwrap());
        drop(unexpected);

        let entries = |directory: &Path| {
            let mut names: Vec<_> = std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let before = [
            entries(&root),
            entries(&control),
            entries(&requests),
            entries(&operations),
        ];
        assert!(matches!(
            inspect_startup_control(&app, Some(&profile)),
            Err(Fault::ClosingPending)
        ));
        assert_eq!(
            std::fs::read(&unexpected_path).unwrap().as_slice(),
            b"do-not-adopt"
        );
        assert!(RecordIdentity::of(&std::fs::metadata(&unexpected_path).unwrap()) == original);
        assert_eq!(
            [
                entries(&root),
                entries(&control),
                entries(&requests),
                entries(&operations),
            ],
            before
        );

        drop(app);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn control_orphan_request_tombstone_is_pending_and_not_consumed() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut profile: CaptureProfile =
            serde_json::from_str(ORDINARY_STARTUP_HISTORY_PROFILE_JSON).unwrap();
        // Explicit finite test inputs also admit the complete historical intent.
        profile.native.max_control_bytes = 16384;
        profile.secrets.max_secret_structure_bytes = 64 * 1024 * 1024;
        profile.secrets.max_secret_memory_bytes = 128 * 1024 * 1024;
        profile.validate().unwrap();
        Limits::from_profile(&profile).unwrap();

        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let root = PathBuf::from(format!(
            "/private/tmp/wb45-control-startup-orphan-{}",
            hex(&random)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let app = File::open(&root).unwrap();
        let control = root.join(CONTROL);
        let requests = control.join("requests");
        let operations = control.join("operations");
        for directory in [&control, &requests, &operations] {
            std::fs::create_dir(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut request = RequestRecord {
            schema: "wrokbot-capture-request".into(),
            version: 1,
            request_id: "a".repeat(64),
            operation_id: "00000000-0000-4000-8000-000000000001".into(),
            bundle_id: "00000000-0000-4000-8000-000000000002".into(),
            owner_instance: "00000000-0000-4000-8000-000000000003".into(),
            owner_pid: std::process::id(),
            release_sha256: "b".repeat(64),
            maintenance_sha256: "c".repeat(64),
            profile_sha256: "d".repeat(64),
            source_identity_sha256: "e".repeat(64),
            intent_sha256: "f".repeat(64),
        };
        let bytes = encode(&request, profile.native.max_control_bytes).unwrap();
        let tombstone_path = requests.join(format!("{}.json", request.request_id));
        let mut tombstone = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tombstone_path)
            .unwrap();
        std::io::Write::write_all(&mut tombstone, &bytes).unwrap();
        tombstone.sync_all().unwrap();
        File::open(&requests).unwrap().sync_all().unwrap();
        let original = RecordIdentity::of(&tombstone.metadata().unwrap());
        drop(tombstone);

        let entries = |directory: &Path| {
            let mut names: Vec<_> = std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let before = [
            entries(&root),
            entries(&control),
            entries(&requests),
            entries(&operations),
        ];
        assert!(before[3].is_empty());
        assert_eq!(before[2].len(), 1);
        assert!(matches!(
            inspect_startup_control(&app, Some(&profile)),
            Err(Fault::ClosingPending)
        ));
        assert_eq!(std::fs::read(&tombstone_path).unwrap(), bytes);
        assert!(RecordIdentity::of(&std::fs::metadata(&tombstone_path).unwrap()) == original);
        assert_eq!(
            [
                entries(&root),
                entries(&control),
                entries(&requests),
                entries(&operations),
            ],
            before
        );

        // Complete this same ordinary on-disk history. It is a grammar/arm
        // classification case, not a substitute for the real capture pipeline.
        let operation = operations.join("00000000000040008000000000000001");
        std::fs::create_dir(&operation).unwrap();
        std::fs::set_permissions(&operation, std::fs::Permissions::from_mode(0o700)).unwrap();
        let operation_file = File::open(&operation).unwrap();
        let write = |path: &Path, body: &[u8]| {
            let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
                .mode(0o600).open(path).unwrap();
            file.write_all(body).unwrap();
            file.sync_all().unwrap();
        };
        let audit_path = operation.join(ORDINARY_AUDIT_LEAF);
        let audit = b"{}\n";
        write(&audit_path, audit);
        let audit_metadata = std::fs::metadata(&audit_path).unwrap();
        let parent_metadata = operation_file.metadata().unwrap();
        let identity = Identity::of(&parent_metadata);
        let source = ControlSourceIdentity {
            instance_id: "instance".into(), dataset_id: "dataset".into(),
            deployment_id: "deployment".into(), tenant_id: "tenant".into(),
            system_identifier: "1".into(), database_oid: 1, key_id: "key".into(),
            key_version: 1, source_device: identity.device, source_inode: identity.inode,
            source_uid: identity.uid, canary_material_id: "canary".into(),
            schema_material_id: "schema".into(), migration_material_id: "migration".into(),
            compatibility_material_id: "compatibility".into(),
        };
        let intent = IntentView {
            schema: "wrokbot-capture-control", version: 1, sequence: 0, stage: "intent",
            request_id: &request.request_id, operation_id: request.operation_id.clone(),
            bundle_id: request.bundle_id.clone(), owner_instance: request.owner_instance.clone(),
            owner_pid: request.owner_pid, t0: 1, e: 3, c: 4, profile: &profile,
            release_sha256: request.release_sha256.clone(), maintenance_sha256: request.maintenance_sha256.clone(),
            source_identity: &source,
            control: Destination { path: control.clone(), identity },
            output: Destination { path: root.join("output"), identity },
            key_medium: Destination { path: root.join("key"), identity },
            temporary_basename: ".capture.partial".into(), final_basename: "capture.wbpg".into(),
            key_basename: "capture.key".into(),
        };
        let intent_bytes = encode(&intent, profile.native.max_control_bytes).unwrap();
        request.profile_sha256 = hex(&hash_encoded(&profile, profile.native.max_control_bytes).unwrap());
        request.source_identity_sha256 = hex(&hash_encoded(&source, profile.native.max_control_bytes).unwrap());
        request.intent_sha256 = hex(&Sha256::digest(&intent_bytes));
        let request_bytes = encode(&request, profile.native.max_control_bytes).unwrap();
        write(&tombstone_path, &request_bytes);
        write(&operation.join("00000000-intent.json"), &intent_bytes);
        let stages = [ControlStage::NormalClosed, ControlStage::ConsumerConfirmed,
            ControlStage::SourceStarted, ControlStage::MaterialsFrozen, ControlStage::SourceClosed,
            ControlStage::KeyMediumVerified, ControlStage::TemporaryVerified,
            ControlStage::PublishedVerified, ControlStage::Closed];
        for stage in stages {
            let record = StageRecord {
                schema: "wrokbot-capture-control".into(), version: 1, sequence: stage.ordinal(), stage,
                request_id: request.request_id.clone(), operation_id: request.operation_id.clone(),
                bundle_id: request.bundle_id.clone(), intent_sha256: request.intent_sha256.clone(),
                observed_monotonic_ns: 2, outcome: ControlOutcome::Actual, fault: None,
                issued_effects: 1, original_tasks: 1, joined_original_tasks: 1, live_proxy_futures: 0,
                parent_device: Some(parent_metadata.dev()), parent_inode: Some(parent_metadata.ino()),
                entry_device: Some(audit_metadata.dev()), entry_inode: Some(audit_metadata.ino()),
                output_bytes: Some(audit.len() as u64), output_sha256: Some(hex(&Sha256::digest(audit))),
            };
            write(&operation.join(format!("{:08}-{}.json", stage.ordinal(), stage.text())),
                &encode(&record, profile.native.max_control_bytes).unwrap());
        }
        operation_file.sync_all().unwrap();
        File::open(&operations).unwrap().sync_all().unwrap();
        let resources = super::super::prepare_original_capture_resources(&profile.carrier_bounds().unwrap()).unwrap();
        let observed = inspect_startup_control_for_capture(&app, Some(&profile),
            Some(&request.request_id), Some(&resources)).unwrap();
        assert!(observed.completed_request(&request.request_id));
        let other_request = "b".repeat(64);
        assert!(!observed.completed_request(&other_request));
        let other = inspect_startup_control_for_capture(&app, Some(&profile),
            Some(&other_request), Some(&resources)).unwrap();
        assert!(!other.completed_request(&other_request));
        assert_eq!(std::fs::read(&tombstone_path).unwrap(), request_bytes);
        // Even the matching tombstone cannot publish completed DATA if Closed is missing.
        std::fs::remove_file(operation.join("00000009-closed.json")).unwrap();
        assert!(matches!(inspect_startup_control_for_capture(&app, Some(&profile),
            Some(&request.request_id), Some(&resources)), Err(Fault::ClosingPending)));
        assert_eq!(std::fs::read(&tombstone_path).unwrap(), request_bytes);
        drop(operation_file);

        drop(app);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn known_tail_rejects_overflow_without_effects() {
        assert!(matches!(
            original_remaining_stage_known_tail(u64::MAX),
            Err(Fault::BoundsOverflow)
        ));
    }

    #[test]
    fn known_tail_covers_short_io_fee_for_frozen_record_limit() {
        let record = 4224u64;
        // Independent structural floor: only before_io's 25 typed-array
        // entries, by-value iterator/current tuple and scalar counters.
        let per_io_floor = ((2 * 25 * 3 + 2 * 3 + 4)
            * core::mem::size_of::<usize>()) as u64;
        let actual = original_remaining_stage_known_tail(record).unwrap();
        assert!(actual >= 7 * (27 + 2 * record) * per_io_floor);
        let next = original_remaining_stage_known_tail(record + 1).unwrap();
        // A larger R must reserve both extra one-byte short IOs for every
        // remaining stage, plus the distinct three record-backings' slope.
        assert!(next - actual >= 14 * per_io_floor + 21);
    }

    #[test]
    fn control_record_decoder_rejects_duplicate_and_unknown_request_keys() {
        let request = RequestRecord {
            schema: "wrokbot-capture-request".into(),
            version: 1,
            request_id: "a".repeat(64),
            operation_id: uuid([1; 16]),
            bundle_id: uuid([2; 16]),
            owner_instance: uuid([3; 16]),
            owner_pid: 1,
            release_sha256: "b".repeat(64),
            maintenance_sha256: "c".repeat(64),
            profile_sha256: "d".repeat(64),
            source_identity_sha256: "e".repeat(64),
            intent_sha256: "f".repeat(64),
        };
        let bytes = encode(&request, 4096).unwrap();
        assert!(decode::<RequestRecord>(&bytes).is_ok());
        for tail in [
            b",\"version\":1}".as_slice(),
            b",\"unexpected\":true}".as_slice(),
        ] {
            let mut altered = bytes[..bytes.len() - 1].to_vec();
            altered.extend_from_slice(tail);
            assert!(decode::<RequestRecord>(&altered).is_err());
        }
        let mut whitespace = b" ".to_vec();
        whitespace.extend_from_slice(&bytes);
        assert!(matches!(
            decode::<RequestRecord>(&whitespace),
            Err(Fault::NonCanonical)
        ));
    }
    #[test]
    fn control_bounded_writer_and_fault_catalog_refuse_unbounded_text() {
        assert!(matches!(
            encode(&"x".repeat(4096), 1024),
            Err(Fault::CapacityExceeded)
        ));
        assert!(fault_text("ClosingPending") && fault_text("PublishUnknown"));
        assert!(!fault_text("user_secret") && !fault_text("/private/path"));
        assert!(!fault_text("IoFailure\nsecret") && !fault_text(""));
    }
    #[test]
    fn control_stage_sequence_and_ids_are_closed_not_derived_from_durable_pid() {
        assert_eq!(ControlStage::NormalClosed.ordinal(), 1);
        assert_eq!(ControlStage::PublishedVerified.ordinal(), 8);
        assert_eq!(ControlStage::Closed.ordinal(), 9);
        assert!(uuid_bytes("00000000-0000-4000-8000-000000000001").is_ok());
        assert!(uuid_bytes("00000000000040008000000000000001").is_err());
        assert!(uuid_bytes("00000000-0000-1000-8000-000000000001").is_err());
        assert!(serde_json::from_slice::<ControlStage>(b"\"reclaim\"").is_err());
        assert!(serde_json::from_slice::<ControlOutcome>(b"\"success\"").is_err());
    }

    #[test]
    fn control_readback_rejects_same_bytes_on_a_replaced_created_inode() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let root =
            std::path::PathBuf::from(format!("/private/tmp/wb45-control-inode-{}", hex(&random)));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(&root).unwrap();
        let original = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("record.json"))
            .unwrap();
        original.write_at(b"same", 0).unwrap();
        original.sync_all().unwrap();
        let expected = RecordIdentity::of(&original.metadata().unwrap());
        assert_eq!(
            read_bound_record(&parent, "record.json", 128, None, Some(expected)).unwrap(),
            b"same"
        );
        std::fs::rename(root.join("record.json"), root.join("old.json")).unwrap();
        let replacement = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("record.json"))
            .unwrap();
        replacement.write_at(b"same", 0).unwrap();
        replacement.sync_all().unwrap();
        assert_eq!(
            read_bound_record(&parent, "record.json", 128, None, None).unwrap(),
            b"same"
        );
        assert!(matches!(
            read_bound_record(&parent, "record.json", 128, None, Some(expected)),
            Err(Fault::IntentMismatch)
        ));
        drop(replacement);
        drop(original);
        drop(parent);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn control_closing_fact_borrows_original_fd_after_effect_deadline_only_with_live_c() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        struct FactClock(bool);
        impl CaptureClockCheck for FactClock {
            fn require_effect(&self) -> Result<(), Fault> {
                Err(Fault::DeadlineExpired)
            }
            fn require_closing(&self) -> Result<(), Fault> {
                if self.0 {
                    Ok(())
                } else {
                    Err(Fault::ClosingPending)
                }
            }
            fn effect_remaining_ns(&self) -> Result<u64, Fault> {
                Err(Fault::DeadlineExpired)
            }
            fn closing_remaining_ns(&self) -> Result<u64, Fault> {
                self.require_closing().map(|_| 1)
            }
            fn observed_ns(&self) -> Result<u64, Fault> {
                Ok(1)
            }
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let root = PathBuf::from(format!("/private/tmp/wb45-control-C-{}", hex(&random)));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("original");
        let original = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let bounds = openbot_domain::backup::whole_pg_carrier::WholePgCarrierBounds {
            max_material_files: 16, max_directories: 16, max_path_bytes: 64,
            max_path_depth: 8, max_single_plain_bytes: 4096, max_material_plain_bytes: 65536,
            max_manifest_bytes: 4096, max_header_bytes: 128, max_data_chunks: 32,
            max_chunk_plain_bytes: 4096, max_wire_bytes: 131072,
            max_metadata_bytes: 1048576, max_open_files: 8,
            max_snapshot_bytes: 65536, max_spool_bytes: 131072,
            max_retained_prior_bytes: 65536, max_journal_bytes: 4096,
            max_total_allocation_bytes: 1048576, capacity_reserve_bytes: 4096,
            free_floor_bytes: 4096, max_key_medium_allocation_bytes: 4096,
            key_medium_reserve_bytes: 4096, key_medium_free_floor_bytes: 4096,
        };
        let resources = super::super::original_capture_resources_for_test(&bounds).unwrap();
        let mut refused = None;
        assert!(matches!(
            runtime_clone_for_fact(&original, &FactClock(true), false, &resources, &mut refused),
            Err(Fault::DeadlineExpired)
        ));
        assert!(refused.is_none());
        let mut fact = None;
        runtime_clone_for_fact(&original, &FactClock(true), true, &resources, &mut fact).unwrap();
        assert!(
            Identity::of(&fact.as_ref().unwrap().metadata().unwrap()) == Identity::of(&original.metadata().unwrap())
        );
        assert!(matches!(
            runtime_clone_for_fact(&original, &FactClock(false), true, &resources, &mut refused),
            Err(Fault::ClosingPending)
        ));
        assert!(refused.is_none());
        struct PostClock(std::sync::atomic::AtomicUsize);
        impl CaptureClockCheck for PostClock {
            fn require_effect(&self) -> Result<(), Fault> { Err(Fault::DeadlineExpired) }
            fn require_closing(&self) -> Result<(), Fault> {
                if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                    Ok(())
                } else { Err(Fault::Cancelled) }
            }
            fn effect_remaining_ns(&self) -> Result<u64, Fault> { Err(Fault::DeadlineExpired) }
            fn closing_remaining_ns(&self) -> Result<u64, Fault> { self.require_closing().map(|_| 1) }
            fn observed_ns(&self) -> Result<u64, Fault> { Ok(1) }
        }
        let mut retained = None;
        let clock = PostClock(std::sync::atomic::AtomicUsize::new(0));
        assert_eq!(runtime_clone_for_fact(&original, &clock, true, &resources, &mut retained), Err(Fault::Cancelled));
        let copy = retained.as_ref().expect("post-C refusal retains the actual duplicate");
        assert!(Identity::of(&copy.metadata().unwrap()) == Identity::of(&original.metadata().unwrap()));
        use std::os::fd::AsRawFd;
        assert_ne!(copy.as_raw_fd(), original.as_raw_fd());
        drop(retained);
        drop(fact);
        drop(original);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
