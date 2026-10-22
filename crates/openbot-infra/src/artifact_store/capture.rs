//! Original Store capture barrier and same-worker FD snapshot. No caller can manufacture
//! a frozen Store by supplying a path, an empty inventory or a boolean.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;
use std::task::Poll;

use openbot_domain::backup::whole_pg_carrier::{WholePgCarrierBounds, WholePgCarrierFault};
use rustix::fs::{Dir, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

use super::{ArtifactStoreError, DatasetBoundArtifactStore, MARKER_NAME, MAX_MARKER_BYTES};
use crate::artifact_bytes::ArtifactCaptureDirectoryBorrow;
use crate::backup::whole_pg_capture_stream::CaptureClockCheck;

/// Pure finite configuration; these values do not establish a source capability.
pub type ArtifactCaptureBounds = WholePgCarrierBounds;

/// Owned destination descriptor. Construction performs no filesystem effect.
pub struct OwnedCaptureSpool {
    root: File,
}
impl OwnedCaptureSpool {
    pub fn from_owned_directory(root: File) -> Self {
        Self { root }
    }
}

/// Created only by closing the original Store gate and joining its original tasks.
pub struct ArtifactCaptureHold {
    store: Arc<DatasetBoundArtifactStore>,
    // Private original resources survive every ordinary snapshot refusal and every
    // public into_parts/into_retained move of this same hold; no pathname reopens them.
    retained: SnapshotRetained,
}

/// A retained refusal contains the actual original Store, not a reconstructed pathname.
pub struct ArtifactCaptureFailure {
    fault: WholePgCarrierFault,
    store: Arc<DatasetBoundArtifactStore>,
}
impl ArtifactCaptureFailure {
    pub fn fault(&self) -> WholePgCarrierFault {
        self.fault
    }
    pub fn original_store(&self) -> &Arc<DatasetBoundArtifactStore> {
        &self.store
    }
}

/// Each copied FD remains owned until it is moved to the one stream worker.
pub struct ArtifactSnapshotFile {
    pub relative_path: String,
    pub byte_length: u64,
    pub sha256: [u8; 32],
    file: File,
}
impl ArtifactSnapshotFile {
    pub fn into_owned_file(self) -> File {
        self.file
    }
}

pub struct ArtifactSnapshot {
    hold: ArtifactCaptureHold,
    spool: OwnedCaptureSpool,
    files: Vec<ArtifactSnapshotFile>,
    directories: u64,
    bytes: u64,
}
impl ArtifactSnapshot {
    pub fn files(&self) -> &[ArtifactSnapshotFile] {
        &self.files
    }
    pub fn directory_count(&self) -> u64 {
        self.directories
    }
    pub fn plain_bytes(&self) -> u64 {
        self.bytes
    }
    pub fn into_parts(
        self,
    ) -> (
        ArtifactCaptureHold,
        OwnedCaptureSpool,
        Vec<ArtifactSnapshotFile>,
    ) {
        (self.hold, self.spool, self.files)
    }
}

pub struct ArtifactSnapshotFailure {
    pub fault: WholePgCarrierFault,
    hold: ArtifactCaptureHold,
    spool: OwnedCaptureSpool,
    files: Vec<ArtifactSnapshotFile>,
}
impl ArtifactSnapshotFailure {
    pub fn into_retained(
        self,
    ) -> (
        ArtifactCaptureHold,
        OwnedCaptureSpool,
        Vec<ArtifactSnapshotFile>,
    ) {
        (self.hold, self.spool, self.files)
    }
}
pub type ArtifactSnapshotResult = Result<ArtifactSnapshot, ArtifactSnapshotFailure>;

impl DatasetBoundArtifactStore {
    /// Called once before the actual armed host publishes any artifact adapter.
    pub fn arm_capture_barrier(&self, max_original_tasks: u64) -> Result<(), ArtifactStoreError> {
        if max_original_tasks == 0 {
            return Err(ArtifactStoreError::Unavailable);
        }
        let mut state = self
            .capture_mutations
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if state.closed
            || state.poisoned
            || state.active != 0
            || state.bound.is_some()
            || !state.tasks.is_empty()
        {
            return Err(ArtifactStoreError::Busy);
        }
        state.bound = Some(max_original_tasks);
        Ok(())
    }

    /// Close all clones atomically. A dropped/failed waiter leaves this same gate closed and
    /// all original handles in the Store. It never manufactures an empty task collection.
    pub async fn freeze_for_capture(
        self: &Arc<Self>,
        clock: &dyn CaptureClockCheck,
    ) -> Result<ArtifactCaptureHold, ArtifactCaptureFailure> {
        let refusal = |fault| ArtifactCaptureFailure {
            fault,
            store: Arc::clone(self),
        };
        clock.require_effect().map_err(refusal)?;
        {
            let mut state = self
                .capture_mutations
                .state
                .lock()
                .map_err(|_| refusal(WholePgCarrierFault::ClosingPending))?;
            if state.bound.is_none() {
                return Err(refusal(WholePgCarrierFault::IntentMismatch));
            }
            state.closed = true;
        }
        loop {
            clock.require_closing().map_err(refusal)?;
            let changed = self.capture_mutations.changed.notified();
            tokio::pin!(changed);
            // Register before inspecting active; notify_waiters does not retain a permit.
            changed.as_mut().enable();
            let active = {
                let state = self
                    .capture_mutations
                    .state
                    .lock()
                    .map_err(|_| refusal(WholePgCarrierFault::ClosingPending))?;
                state.active
            };
            if active == 0 {
                break;
            }
            let remaining = clock.closing_remaining_ns().map_err(refusal)?;
            tokio::time::timeout(std::time::Duration::from_nanos(remaining), changed)
                .await
                .map_err(|_| refusal(WholePgCarrierFault::ClosingPending))?;
            clock.require_closing().map_err(refusal)?;
        }
        loop {
            let remaining = clock.closing_remaining_ns().map_err(refusal)?;
            let original_join = std::future::poll_fn(|context| {
                let Ok(mut state) = self.capture_mutations.state.lock() else {
                    return Poll::Ready(Some(Err(WholePgCarrierFault::ClosingPending)));
                };
                match state.tasks.poll_join_next(context) {
                    Poll::Ready(Some(Ok(()))) => Poll::Ready(Some(Ok(()))),
                    Poll::Ready(Some(Err(_))) => {
                        state.poisoned = true;
                        Poll::Ready(Some(Err(WholePgCarrierFault::ClosingPending)))
                    }
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                }
            });
            match tokio::time::timeout(std::time::Duration::from_nanos(remaining), original_join)
                .await
            {
                Ok(Some(Ok(()))) => {}
                Ok(None) => break,
                Ok(Some(Err(fault))) => return Err(refusal(fault)),
                Err(_) => return Err(refusal(WholePgCarrierFault::ClosingPending)),
            }
            clock.require_closing().map_err(refusal)?;
        }
        clock.require_effect().map_err(refusal)?;
        let state = self
            .capture_mutations
            .state
            .lock()
            .map_err(|_| refusal(WholePgCarrierFault::ClosingPending))?;
        if state.active != 0 || state.poisoned || !state.closed || !state.tasks.is_empty() {
            return Err(refusal(WholePgCarrierFault::ClosingPending));
        }
        drop(state);
        Ok(ArtifactCaptureHold {
            store: Arc::clone(self),
            retained: SnapshotRetained::default(),
        })
    }
}

/// The returned original handle must be installed in the outer resident owner before awaiting.
/// No timeout or task Drop here releases the original Store gate or deletes partial snapshots.
pub fn start_capture_snapshot(
    hold: ArtifactCaptureHold,
    spool: OwnedCaptureSpool,
    bounds: ArtifactCaptureBounds,
    clock: Arc<dyn CaptureClockCheck>,
) -> JoinHandle<ArtifactSnapshotResult> {
    tokio::task::spawn_blocking(move || snapshot(hold, spool, bounds, clock.as_ref()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    links: u64,
    len: u64,
    sec: i64,
    ns: i64,
}
impl Identity {
    fn of(meta: &std::fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            mode: meta.mode(),
            links: meta.nlink(),
            len: meta.len(),
            sec: meta.mtime(),
            ns: meta.mtime_nsec(),
        }
    }
}

// Actual FD custody only. Original source FDs earn no credit against new allocation.
#[derive(Default)]
struct SnapshotRetained {
    opened: Vec<SnapshotOpened>,
    readers: Vec<Dir>,
    partial: Option<File>,
    pending_logical_growth: u64,
    // The first capture verification opens this FD, not startup. All later checks and
    // marker copying borrow the exact same original slot without reopening its name.
    marker: Option<usize>,
    root_identity: Option<(Identity, i64, i64)>,
    marker_identity: Option<(Identity, i64, i64)>,
    directory_bridge_reserved: bool,
    marker_buffer: Vec<u8>,
    copy_buffer: Zeroizing<Vec<u8>>,
    // These are known Rust backing-storage charges, not allocator/opaque-Dir bounds.
    // They move with the original capsule and cannot be erased by a new counter.
    metadata: SnapshotMetadata,
    opened_capacity_bytes: u64,
    readers_capacity_bytes: u64,
    marker_capacity_bytes: u64,
    copy_capacity_bytes: u64,
}
struct SnapshotOpened {
    file: Arc<File>,
    allocated_directory: bool,
}
struct SnapshotCounter {
    directories: u64,
    files: u64,
    bytes: u64,
    // Each output Vec is distinct; its old charge remains in the capsule even if
    // the files Vec has moved out. A new Vec never reuses the old backing credit.
    output_capacity_bytes: u64,
    retained: SnapshotRetained,
}
#[derive(Default)]
struct SnapshotMetadata {
    bytes: u64,
    overflowed: bool,
}
impl SnapshotMetadata {
    fn charge(&mut self, bytes: u64, maximum: u64) -> Result<(), WholePgCarrierFault> {
        if self.overflowed {
            return Err(WholePgCarrierFault::BoundsOverflow);
        }
        let Some(next) = self.bytes.checked_add(bytes) else {
            self.overflowed = true;
            return Err(WholePgCarrierFault::BoundsOverflow);
        };
        // The original capsule keeps this conservative charge even if a local
        // path has dropped or an output Vec has moved. No refusal refunds it.
        self.bytes = next;
        if next > maximum {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        Ok(())
    }
}

fn snapshot(
    mut hold: ArtifactCaptureHold,
    spool: OwnedCaptureSpool,
    bounds: ArtifactCaptureBounds,
    clock: &dyn CaptureClockCheck,
) -> ArtifactSnapshotResult {
    let mut files = Vec::new();
    let mut count = SnapshotCounter {
        directories: 0,
        files: 0,
        bytes: 0,
        output_capacity_bytes: 0,
        retained: std::mem::take(&mut hold.retained),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bounds.check()?;
        clock.require_effect()?;
        let _original_mutex = hold
            .store
            .io
            .try_lock()
            .map_err(|_| WholePgCarrierFault::ClosingPending)?;
        let state = hold
            .store
            .capture_mutations
            .state
            .lock()
            .map_err(|_| WholePgCarrierFault::ClosingPending)?;
        if !state.closed || state.active != 0 || state.poisoned || !state.tasks.is_empty() {
            return Err(WholePgCarrierFault::ClosingPending);
        }
        drop(state);
        // The five distinct original descriptors are simultaneous even where their
        // inode is equal. Account them and the bridge's fixed slots before its first IO.
        prepare_directory_bridge(&mut count, &files, &bounds)?;
        verify_original_capture_store(&hold.store, &mut count, &files, &bounds, clock)?;
        let original_directories = hold.store.bytes.capture_original_directories_before(clock)?;
        {
            let store_root = metadata(&hold.store.root, clock)?;
            let byte_root = metadata(original_directories.original_fds().0, clock)?;
            if !byte_root.is_dir()
                || byte_root.mode() & 0o7777 != 0o700
                || (byte_root.dev(), byte_root.ino(), byte_root.uid(), byte_root.mode())
                    != (store_root.dev(), store_root.ino(), store_root.uid(), store_root.mode())
            {
                return Err(WholePgCarrierFault::SourceChanged);
            }
        }
        let destination = metadata(&spool.root, clock)?;
        let source = metadata(&hold.store.root, clock)?;
        if !destination.is_dir()
            || destination.uid() != source.uid()
            || destination.mode() & 0o077 != 0
            || (destination.dev(), destination.ino()) == (source.dev(), source.ino())
        {
            return Err(WholePgCarrierFault::PathUnsafe);
        }
        // These observations are no longer needed while the bridge verifies subtrees.
        drop((destination, source));
        let reader = retain_directory_reader(&spool.root, &bounds, clock, &mut count, &files)?;
        loop {
            clock.require_effect()?;
            let entry = count.retained.readers[reader].next();
            clock.require_effect()?;
            let Some(entry) = entry else {
                break;
            };
            let entry = entry.map_err(|_| WholePgCarrierFault::IoFailure)?;
            if entry.file_name().to_bytes() != b"." && entry.file_name().to_bytes() != b".." {
                return Err(WholePgCarrierFault::ExtraMaterial);
            }
        }
        copy_directory(
            &hold.store.root,
            &spool.root,
            &original_directories,
            "",
            0,
            &bounds,
            clock,
            &mut count,
            &mut files,
        )?;
        if !files.iter().any(|file| file.relative_path == MARKER_NAME) {
            return Err(WholePgCarrierFault::MaterialMissing);
        }
        verify_original_capture_store(&hold.store, &mut count, &files, &bounds, clock)?;
        // Every completed file and every retained output directory gets a final original-E
        // sync, then the complete actual allocation/FD gate includes the last file as well.
        for file in &files {
            sync(&file.file, clock)?;
        }
        for directory in &count.retained.opened {
            if directory.allocated_directory {
                sync(&directory.file, clock)?;
            }
        }
        sync(&spool.root, clock)?;
        check_snapshot_capacity(&spool.root, &count, &files, 0, &bounds, clock)?;
        original_directories.verify_original_before()?;
        if count.retained.partial.is_some() || count.retained.pending_logical_growth != 0 {
            return Err(WholePgCarrierFault::ClosingPending);
        }
        clock.require_effect()?;
        Ok(())
    }))
    .unwrap_or(Err(WholePgCarrierFault::ClosingPending));
    // No fallible postcheck remains between custody transfer and returning either result.
    hold.retained = count.retained;
    match result {
        Ok(()) => Ok(ArtifactSnapshot {
            hold,
            spool,
            files,
            directories: count.directories,
            bytes: count.bytes,
        }),
        Err(fault) => Err(ArtifactSnapshotFailure {
            fault,
            hold,
            spool,
            files,
        }),
    }
}

fn copy_directory(
    source: &File,
    target: &File,
    original_directories: &ArtifactCaptureDirectoryBorrow<'_>,
    prefix: &str,
    depth: u64,
    bounds: &ArtifactCaptureBounds,
    clock: &dyn CaptureClockCheck,
    count: &mut SnapshotCounter,
    output: &mut Vec<ArtifactSnapshotFile>,
) -> Result<(), WholePgCarrierFault> {
    original_directories.verify_original_before()?;
    clock.require_effect()?;
    let before = Identity::of(&metadata(source, clock)?);
    if depth == 0 {
        reserve_snapshot_directory(
            depth,
            (bounds.max_path_depth, bounds.max_directories),
            &mut count.directories,
        )?;
    }
    if depth > bounds.max_path_depth || count.directories > bounds.max_directories {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    if depth == 0 {
        prepare_opened_slot(count, output, bounds)?;
        clock.require_effect()?;
        let cloned = target.try_clone();
        match cloned {
            Ok(file) => {
                retain_opened(file, true, count, clock)?;
            }
            Err(_) => {
                clock.require_effect()?;
                return Err(WholePgCarrierFault::IoFailure);
            }
        }
    }
    check_snapshot_capacity(target, count, output, 0, bounds, clock)?;
    let reader = retain_directory_reader(source, bounds, clock, count, output)?;
    let mut original_children_seen = [false; 2];
    loop {
        clock.require_effect()?;
        let entry = count.retained.readers[reader].next();
        clock.require_effect()?;
        let Some(entry) = entry else {
            // EOF, including an empty child, is not an independent source proof.
            original_directories.verify_original_before()?;
            break;
        };
        let entry = entry.map_err(|_| WholePgCarrierFault::IoFailure)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name_text = name.to_str().map_err(|_| WholePgCarrierFault::PathUnsafe)?;
        if name_text.contains('/') || name_text.is_empty() {
            return Err(WholePgCarrierFault::PathUnsafe);
        }
        let path_len = prefix
            .len()
            .checked_add(usize::from(!prefix.is_empty()))
            .and_then(|n| n.checked_add(name_text.len()))
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
        let path_bytes =
            u64::try_from(path_len).map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
        if path_bytes > bounds.max_path_bytes {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        // Preserve the original fixed per-record allowance, in addition to the
        // required path bytes. No path String exists before this finite check.
        count.retained.metadata.charge(
            path_bytes
                .checked_add(256)
                .ok_or(WholePgCarrierFault::BoundsOverflow)?,
            bounds.max_metadata_bytes,
        )?;
        clock.require_effect()?;
        let observed = rustix::fs::statat(source, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
        clock.require_effect()?;
        let st = observed.map_err(|_| WholePgCarrierFault::SourceChanged)?;
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind == FileType::Directory {
            if !prefix.is_empty() || !matches!(name_text, "objects" | "staging") {
                return Err(WholePgCarrierFault::ExtraMaterial);
            }
            if depth
                .checked_add(1)
                .ok_or(WholePgCarrierFault::BoundsOverflow)?
                > bounds.max_path_depth
            {
                return Err(WholePgCarrierFault::CapacityExceeded);
            }
        }
        let mut path = String::new();
        let reserved = path.try_reserve_exact(path_len);
        let reported =
            u64::try_from(path.capacity()).map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
        count.retained.metadata.charge(
            reported.saturating_sub(path_bytes),
            bounds.max_metadata_bytes,
        )?;
        reserved.map_err(|_| WholePgCarrierFault::CapacityExceeded)?;
        if !prefix.is_empty() {
            path.push_str(prefix);
            path.push('/');
        }
        path.push_str(name_text);
        if kind == FileType::Directory {
            original_directories.verify_original_before()?;
            let (_, objects, staging) = original_directories.original_fds();
            let (child_index, child) = match name_text {
                "objects" => (0, objects),
                "staging" => (1, staging),
                _ => return Err(WholePgCarrierFault::ExtraMaterial),
            };
            if std::mem::replace(&mut original_children_seen[child_index], true) {
                return Err(WholePgCarrierFault::ExtraMaterial);
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            // Consume the known logical directory slot before any new mkdir effect.
            // No later refusal or failed IO returns that reservation to this operation.
            reserve_snapshot_directory(
                child_depth,
                (bounds.max_path_depth, bounds.max_directories),
                &mut count.directories,
            )?;
            // Directory metadata growth is physically sampled after the original effect;
            // no allocator upper bound is invented from f_frsize or a preferred IO size.
            check_snapshot_capacity(target, count, output, 0, bounds, clock)?;
            clock.require_effect()?;
            let created = rustix::fs::mkdirat(target, name, Mode::RUSR | Mode::WUSR | Mode::XUSR);
            clock.require_effect()?;
            created.map_err(|_| WholePgCarrierFault::IoFailure)?;
            let destination = open(target, name, (true, true), count, output, bounds, clock)?;
            let child_meta = metadata(child, clock)?;
            if !child_meta.is_dir()
                || child_meta.mode() & 0o7777 != 0o700
                || child_meta.uid() != before.uid
                || child_meta.dev() != st.st_dev as u64
                || child_meta.ino() != st.st_ino
            {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            drop(child_meta);
            check_snapshot_capacity(target, count, output, 0, bounds, clock)?;
            copy_directory(
                child,
                &destination,
                original_directories,
                &path,
                child_depth,
                bounds,
                clock,
                count,
                output,
            )?;
            original_directories.verify_original_before()?;
        } else if kind == FileType::RegularFile {
            if prefix.is_empty() && name_text != MARKER_NAME {
                return Err(WholePgCarrierFault::ExtraMaterial);
            }
            if !prefix.is_empty()
                && uuid::Uuid::parse_str(name_text)
                    .ok()
                    .is_none_or(|id| id.to_string() != name_text)
            {
                return Err(WholePgCarrierFault::PathUnsafe);
            }
            let original = if prefix.is_empty() && name_text == MARKER_NAME {
                let index = count
                    .retained
                    .marker
                    .ok_or(WholePgCarrierFault::MaterialMissing)?;
                Arc::clone(
                    &count
                        .retained
                        .opened
                        .get(index)
                        .ok_or(WholePgCarrierFault::MaterialMissing)?
                        .file,
                )
            } else {
                open(source, name, (false, false), count, output, bounds, clock)?
            };
            let meta = metadata(&original, clock)?;
            let identity = Identity::of(&meta);
            if !meta.is_file()
                || identity.links != 1
                || identity.uid != before.uid
                || identity.mode & 0o077 != 0
                || identity.ino != st.st_ino
            {
                return Err(WholePgCarrierFault::PathUnsafe);
            }
            count.files = count
                .files
                .checked_add(1)
                .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            count.bytes = count
                .bytes
                .checked_add(meta.len())
                .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            if count.files > bounds.max_material_files
                || meta.len() > bounds.max_single_plain_bytes
                || count.bytes > bounds.max_snapshot_bytes
                || count.bytes > bounds.max_material_plain_bytes
            {
                return Err(WholePgCarrierFault::CapacityExceeded);
            }
            if count.retained.partial.is_some() {
                return Err(WholePgCarrierFault::IntentMismatch);
            }
            prepare_file_slot(count, output, bounds)?;
            let required = output
                .len()
                .checked_add(1)
                .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            prepare_known_vec_capacity(
                output,
                required,
                &mut count.output_capacity_bytes,
                &mut count.retained.metadata,
                bounds.max_metadata_bytes,
            )?;
            check_snapshot_capacity(target, count, output, 0, bounds, clock)?;
            clock.require_effect()?;
            let created = rustix::fs::openat(
                target,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            );
            match created {
                Ok(file) => count.retained.partial = Some(File::from(file)),
                Err(_) => {
                    clock.require_effect()?;
                    return Err(WholePgCarrierFault::IoFailure);
                }
            }
            clock.require_effect()?;
            check_snapshot_capacity(target, count, output, 0, bounds, clock)?;
            let block = usize::try_from(bounds.max_chunk_plain_bytes.min(meta.len().max(1)))
                .map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
            // Wipe before any growth can release the old allocation. Keep the one
            // original worker buffer resident across files and all ordinary refusals.
            count.retained.copy_buffer.as_mut_slice().zeroize();
            prepare_known_vec_capacity(
                &mut count.retained.copy_buffer,
                block,
                &mut count.retained.copy_capacity_bytes,
                &mut count.retained.metadata,
                bounds.max_metadata_bytes,
            )?;
            if count.retained.copy_buffer.len() < block {
                count.retained.copy_buffer.resize(block, 0);
            }
            let mut sha = Sha256::new();
            let mut copied = 0_u64;
            loop {
                clock.require_effect()?;
                let observed = (&*original).read(&mut count.retained.copy_buffer[..block]);
                clock.require_effect()?;
                let n = observed.map_err(|_| WholePgCarrierFault::IoFailure)?;
                if n == 0 {
                    break;
                }
                copied = copied
                    .checked_add(n as u64)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?;
                if copied > meta.len() {
                    return Err(WholePgCarrierFault::SourceChanged);
                }
                sha.update(&count.retained.copy_buffer[..n]);
                let mut written = 0;
                while written < n {
                    let known_growth = u64::try_from(n - written)
                        .map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
                    count.retained.pending_logical_growth = known_growth;
                    check_snapshot_capacity(target, count, output, known_growth, bounds, clock)?;
                    clock.require_effect()?;
                    let observed = count
                        .retained
                        .partial
                        .as_ref()
                        .ok_or(WholePgCarrierFault::MaterialMissing)?
                        .write(&count.retained.copy_buffer[written..n]);
                    clock.require_effect()?;
                    let amount = match observed {
                        Ok(amount) => amount,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err(WholePgCarrierFault::IoFailure),
                    };
                    if amount == 0 {
                        return Err(WholePgCarrierFault::IoFailure);
                    }
                    written = written
                        .checked_add(amount)
                        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
                    check_snapshot_capacity(target, count, output, 0, bounds, clock)?;
                    count.retained.pending_logical_growth = 0;
                }
            }
            count.retained.copy_buffer.as_mut_slice().zeroize();
            let copy = count
                .retained
                .partial
                .as_ref()
                .ok_or(WholePgCarrierFault::MaterialMissing)?;
            sync(copy, clock)?;
            clock.require_effect()?;
            let positioned = (&*copy).seek(SeekFrom::Start(0));
            clock.require_effect()?;
            positioned.map_err(|_| WholePgCarrierFault::IoFailure)?;
            if copied != meta.len() || identity != Identity::of(&metadata(&original, clock)?) {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            clock.require_effect()?;
            let observed = rustix::fs::statat(source, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
            clock.require_effect()?;
            let named = observed.map_err(|_| WholePgCarrierFault::SourceChanged)?;
            if named.st_ino != identity.ino || named.st_dev as u64 != identity.dev {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            let file = count
                .retained
                .partial
                .take()
                .ok_or(WholePgCarrierFault::MaterialMissing)?;
            output.push(ArtifactSnapshotFile {
                relative_path: path,
                byte_length: copied,
                sha256: sha.finalize().into(),
                file,
            });
            check_snapshot_capacity(target, count, output, 0, bounds, clock)?;
        } else {
            return Err(WholePgCarrierFault::PathUnsafe);
        }
    }
    if prefix.is_empty() && original_children_seen != [true, true] {
        return Err(WholePgCarrierFault::MaterialMissing);
    }
    original_directories.verify_original_before()?;
    sync(target, clock)?;
    if before != Identity::of(&metadata(source, clock)?) {
        return Err(WholePgCarrierFault::SourceChanged);
    }
    check_snapshot_capacity(target, count, output, 0, bounds, clock)?;
    original_directories.verify_original_before()?;
    clock.require_effect()
}

// Internal arithmetic only. The caller supplies the same frozen limits and commits this
// one logical slot before mkdir; recursive entry checks the limits without reserving again.
fn reserve_snapshot_directory(
    depth: u64,
    (max_depth, max_directories): (u64, u64),
    directories: &mut u64,
) -> Result<(), WholePgCarrierFault> {
    let next = directories
        .checked_add(1)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    if depth > max_depth || next > max_directories {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    *directories = next;
    Ok(())
}

// Capture-specific only: the ordinary Store verifier/read_marker retain their original
// behavior. This observes the held original root and the one retained capture marker FD.
fn verify_original_capture_store(
    store: &DatasetBoundArtifactStore,
    count: &mut SnapshotCounter,
    files: &[ArtifactSnapshotFile],
    bounds: &ArtifactCaptureBounds,
    clock: &dyn CaptureClockCheck,
) -> Result<(), WholePgCarrierFault> {
    clock.require_effect()?;
    let root_before = metadata(&store.root, clock)?;
    clock.require_effect()?;
    let uid = rustix::process::geteuid().as_raw();
    clock.require_effect()?;
    let physical = store.physical_binding();
    if !root_before.is_dir()
        || root_before.mode() & 0o7777 != 0o700
        || root_before.uid() != uid
        || physical.device().parse::<u64>().ok() != Some(root_before.dev())
        || physical.inode().parse::<u64>().ok() != Some(root_before.ino())
        || physical.uid().parse::<u32>().ok() != Some(root_before.uid())
    {
        return Err(WholePgCarrierFault::SourceChanged);
    }
    let stable =
        |value: &std::fs::Metadata| (Identity::of(value), value.ctime(), value.ctime_nsec());
    match count.retained.root_identity {
        Some(original) if original != stable(&root_before) => {
            return Err(WholePgCarrierFault::SourceChanged);
        }
        None => count.retained.root_identity = Some(stable(&root_before)),
        Some(_) => {}
    }
    let expected_len =
        u64::try_from(store.marker_bytes.len()).map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
    if expected_len == 0 || expected_len > MAX_MARKER_BYTES {
        return Err(WholePgCarrierFault::SourceChanged);
    }
    let buffer_bytes = expected_len
        .checked_add(1)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    let buffer_len =
        usize::try_from(buffer_bytes).map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
    if !count.retained.marker_buffer.is_empty() && count.retained.marker_buffer.len() != buffer_len
    {
        return Err(WholePgCarrierFault::SourceChanged);
    }
    prepare_known_vec_capacity(
        &mut count.retained.marker_buffer,
        buffer_len,
        &mut count.retained.marker_capacity_bytes,
        &mut count.retained.metadata,
        bounds.max_metadata_bytes,
    )?;
    count.retained.marker_buffer.resize(buffer_len, 0);
    let observe_name = || {
        clock.require_effect()?;
        let observed = rustix::fs::statat(
            &store.root,
            MARKER_NAME,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        );
        clock.require_effect()?;
        observed.map_err(|_| WholePgCarrierFault::SourceChanged)
    };
    let named_before = observe_name()?;
    let index = if let Some(index) = count.retained.marker {
        index
    } else {
        prepare_opened_slot(count, files, bounds)?;
        clock.require_effect()?;
        let opened = rustix::fs::openat(
            &store.root,
            MARKER_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let index = count.retained.opened.len();
        match opened {
            Ok(file) => {
                count.retained.opened.push(SnapshotOpened {
                    file: Arc::new(File::from(file)),
                    allocated_directory: false,
                });
                count.retained.marker = Some(index);
            }
            Err(_) => {
                clock.require_effect()?;
                return Err(WholePgCarrierFault::SourceChanged);
            }
        }
        clock.require_effect()?;
        index
    };
    let marker = Arc::clone(
        &count
            .retained
            .opened
            .get(index)
            .ok_or(WholePgCarrierFault::MaterialMissing)?
            .file,
    );
    let before = metadata(&marker, clock)?;
    let matches_name = |named: &rustix::fs::Stat, actual: &std::fs::Metadata| {
        named.st_dev as u64 == actual.dev()
            && named.st_ino == actual.ino()
            && named.st_uid == actual.uid()
            && u32::from(named.st_mode) == actual.mode()
            && u64::from(named.st_nlink) == actual.nlink()
            && u64::try_from(named.st_size).ok() == Some(actual.len())
    };
    if !before.is_file()
        || before.mode() & 0o7777 != 0o400
        || before.nlink() != 1
        || before.uid() != uid
        || before.dev() != root_before.dev()
        || before.len() != expected_len
        || !matches_name(&named_before, &before)
    {
        return Err(WholePgCarrierFault::SourceChanged);
    }
    match count.retained.marker_identity {
        Some(original) if original != stable(&before) => {
            return Err(WholePgCarrierFault::SourceChanged);
        }
        None => count.retained.marker_identity = Some(stable(&before)),
        Some(_) => {}
    }
    let mut offset = 0_usize;
    loop {
        if offset == buffer_len {
            return Err(WholePgCarrierFault::SourceChanged);
        }
        clock.require_effect()?;
        let observed = marker.read_at(
            &mut count.retained.marker_buffer[offset..],
            u64::try_from(offset).map_err(|_| WholePgCarrierFault::BoundsOverflow)?,
        );
        clock.require_effect()?;
        let n = observed.map_err(|_| WholePgCarrierFault::IoFailure)?;
        if n == 0 {
            break;
        }
        offset = offset
            .checked_add(n)
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
        if u64::try_from(offset).map_err(|_| WholePgCarrierFault::BoundsOverflow)? > expected_len {
            return Err(WholePgCarrierFault::SourceChanged);
        }
    }
    let after = metadata(&marker, clock)?;
    let named_after = observe_name()?;
    let root_after = metadata(&store.root, clock)?;
    if offset != store.marker_bytes.len()
        || &count.retained.marker_buffer[..offset] != store.marker_bytes.as_slice()
        || stable(&before) != stable(&after)
        || stable(&root_before) != stable(&root_after)
        || !matches_name(&named_after, &after)
    {
        return Err(WholePgCarrierFault::SourceChanged);
    }
    clock.require_effect()
}

fn retained_handles(
    count: &SnapshotCounter,
    files: &[ArtifactSnapshotFile],
) -> Result<u64, WholePgCarrierFault> {
    // Each original FD is counted: Store.root, ByteStore root/objects/staging, spool.root,
    // retained open Files, libc directory readers, completed copies, and current partial.
    // Equal inodes and Arc clones do not merge distinct actual descriptors.
    // Other resident owners/global metadata still require the independent whole-op ledger.
    files
        .len()
        .checked_add(count.retained.opened.len())
        .and_then(|n| n.checked_add(count.retained.readers.len()))
        .and_then(|n| n.checked_add(usize::from(count.retained.partial.is_some())))
        .and_then(|n| n.checked_add(5))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(WholePgCarrierFault::BoundsOverflow)
}
// The existing bounds argument is the same operation's checked remaining slice;
// its caller must subtract other resident owners, never grant each owner a full profile.
// One retained charge covers the fixed view/three original identity pairs, three
// simultaneous metadata slots plus the syscall result, and named-stat/result slots.
// No dynamic storage is allocated by the bridge and a refusal never refunds this charge.
fn prepare_directory_bridge(
    count: &mut SnapshotCounter,
    files: &[ArtifactSnapshotFile],
    bounds: &ArtifactCaptureBounds,
) -> Result<(), WholePgCarrierFault> {
    if retained_handles(count, files)? > bounds.max_open_files {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    if !count.retained.directory_bridge_reserved {
        // Size-only mirror of the existing private Identity's two u64 fields.
        // Charge source array, iterator, next result and current bindings separately;
        // no optimizer or moved-from stack-slot reuse is assumed.
        type ChildObservation<'a> = (&'a str, &'a File, [u64; 2]);
        let verify_loop_slots = std::mem::size_of::<[ChildObservation<'_>; 2]>()
            .checked_add(std::mem::size_of::<
                std::array::IntoIter<ChildObservation<'_>, 2>,
            >())
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Option<ChildObservation<'_>>>())
            })
            .and_then(|n| n.checked_add(std::mem::size_of::<ChildObservation<'_>>()))
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
        let factory_loop_slots = std::mem::size_of::<[&std::fs::Metadata; 3]>()
            .checked_add(std::mem::size_of::<
                std::array::IntoIter<&std::fs::Metadata, 3>,
            >())
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Option<&std::fs::Metadata>>())
            })
            .and_then(|n| n.checked_add(std::mem::size_of::<&std::fs::Metadata>()))
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
        // The factory loop ends before its identity block exits and verification begins.
        let loop_slots = verify_loop_slots.max(factory_loop_slots);
        let fixed_bytes = std::mem::size_of::<ArtifactCaptureDirectoryBorrow<'_>>()
            .checked_add(std::mem::size_of::<[[bool; 2]; 2]>())
            .and_then(|n| n.checked_add(loop_slots))
            .and_then(|n| n.checked_add(std::mem::size_of::<[(u64, u64); 3]>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<[std::fs::Metadata; 3]>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<std::fs::Metadata, WholePgCarrierFault>>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<rustix::fs::Stat>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fs::Stat, WholePgCarrierFault>>()))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
        count.retained.metadata.charge(fixed_bytes, bounds.max_metadata_bytes)?;
        count.retained.directory_bridge_reserved = true;
    }
    Ok(())
}

fn prepare_file_slot(
    count: &SnapshotCounter,
    files: &[ArtifactSnapshotFile],
    bounds: &ArtifactCaptureBounds,
) -> Result<(), WholePgCarrierFault> {
    if retained_handles(count, files)?
        .checked_add(1)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?
        > bounds.max_open_files
    {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    Ok(())
}
// Monotonic known backing-storage bytes only: requested slots are charged before
// reserve, then Vec's actual reported capacity before any next IO. Opaque allocator
// bookkeeping, transient reallocation peaks and libc Dir allocations remain unproven.
fn charge_known_capacity(
    metadata: &mut SnapshotMetadata,
    charged: &mut u64,
    reported: u64,
    maximum: u64,
) -> Result<(), WholePgCarrierFault> {
    let next = (*charged).max(reported);
    let delta = next
        .checked_sub(*charged)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    *charged = next;
    metadata.charge(delta, maximum)
}
fn prepare_known_vec_capacity<T>(
    values: &mut Vec<T>,
    required_len: usize,
    charged: &mut u64,
    metadata: &mut SnapshotMetadata,
    maximum: u64,
) -> Result<(), WholePgCarrierFault> {
    let size =
        u64::try_from(std::mem::size_of::<T>()).map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
    let required = u64::try_from(required_len.max(values.capacity()))
        .map_err(|_| WholePgCarrierFault::BoundsOverflow)?
        .checked_mul(size)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    charge_known_capacity(metadata, charged, required, maximum)?;
    let reserved = values.try_reserve_exact(required_len.saturating_sub(values.len()));
    let reported = u64::try_from(values.capacity())
        .map_err(|_| WholePgCarrierFault::BoundsOverflow)?
        .checked_mul(size)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    charge_known_capacity(metadata, charged, reported, maximum)?;
    reserved.map_err(|_| WholePgCarrierFault::CapacityExceeded)
}
fn prepare_opened_slot(
    count: &mut SnapshotCounter,
    files: &[ArtifactSnapshotFile],
    bounds: &ArtifactCaptureBounds,
) -> Result<(), WholePgCarrierFault> {
    prepare_file_slot(count, files, bounds)?;
    let required = count
        .retained
        .opened
        .len()
        .checked_add(1)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    prepare_known_vec_capacity(
        &mut count.retained.opened,
        required,
        &mut count.retained.opened_capacity_bytes,
        &mut count.retained.metadata,
        bounds.max_metadata_bytes,
    )
}
fn retain_opened(
    file: File,
    allocated_directory: bool,
    count: &mut SnapshotCounter,
    clock: &dyn CaptureClockCheck,
) -> Result<Arc<File>, WholePgCarrierFault> {
    let original = Arc::new(file);
    count.retained.opened.push(SnapshotOpened {
        file: Arc::clone(&original),
        allocated_directory,
    });
    clock.require_effect()?;
    Ok(original)
}
fn retain_directory_reader(
    source: &File,
    bounds: &ArtifactCaptureBounds,
    clock: &dyn CaptureClockCheck,
    count: &mut SnapshotCounter,
    files: &[ArtifactSnapshotFile],
) -> Result<usize, WholePgCarrierFault> {
    prepare_file_slot(count, files, bounds)?;
    let required = count
        .retained
        .readers
        .len()
        .checked_add(1)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    prepare_known_vec_capacity(
        &mut count.retained.readers,
        required,
        &mut count.retained.readers_capacity_bytes,
        &mut count.retained.metadata,
        bounds.max_metadata_bytes,
    )?;
    clock.require_effect()?;
    let opened = Dir::read_from(source);
    let index = count.retained.readers.len();
    match opened {
        Ok(reader) => count.retained.readers.push(reader),
        Err(_) => {
            clock.require_effect()?;
            return Err(WholePgCarrierFault::IoFailure);
        }
    }
    clock.require_effect()?;
    Ok(index)
}
fn metadata(
    file: &File,
    clock: &dyn CaptureClockCheck,
) -> Result<std::fs::Metadata, WholePgCarrierFault> {
    clock.require_effect()?;
    let observed = file.metadata();
    clock.require_effect()?;
    observed.map_err(|_| WholePgCarrierFault::IoFailure)
}
fn sync(file: &File, clock: &dyn CaptureClockCheck) -> Result<(), WholePgCarrierFault> {
    clock.require_effect()?;
    let synced = file.sync_all();
    clock.require_effect()?;
    synced.map_err(|_| WholePgCarrierFault::IoFailure)
}

// Only actual retained output blocks receive allocation credit. Precharged next-write
// logical growth is a lower bound, NOT an OS allocation upper bound or a continuous peak.
fn check_snapshot_capacity(
    target: &File,
    count: &SnapshotCounter,
    files: &[ArtifactSnapshotFile],
    known_growth: u64,
    bounds: &ArtifactCaptureBounds,
    clock: &dyn CaptureClockCheck,
) -> Result<(), WholePgCarrierFault> {
    clock.require_effect()?;
    if retained_handles(count, files)? > bounds.max_open_files {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    let mut allocated = 0_u64;
    let destination = metadata(target, clock)?;
    for file in files {
        let meta = metadata(&file.file, clock)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.len() != file.byte_length
            || meta.dev() != destination.dev()
        {
            return Err(WholePgCarrierFault::SourceChanged);
        }
        allocated = allocated
            .checked_add(
                meta.blocks()
                    .checked_mul(512)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?,
            )
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    }
    for directory in &count.retained.opened {
        if !directory.allocated_directory {
            continue;
        }
        let meta = metadata(&directory.file, clock)?;
        if !meta.is_dir() || meta.dev() != destination.dev() {
            return Err(WholePgCarrierFault::SourceChanged);
        }
        allocated = allocated
            .checked_add(
                meta.blocks()
                    .checked_mul(512)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?,
            )
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    }
    if let Some(file) = &count.retained.partial {
        let meta = metadata(file, clock)?;
        if !meta.is_file() || meta.nlink() != 1 || meta.dev() != destination.dev() {
            return Err(WholePgCarrierFault::SourceChanged);
        }
        allocated = allocated
            .checked_add(
                meta.blocks()
                    .checked_mul(512)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?,
            )
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    }
    if allocated
        .checked_add(known_growth)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?
        > bounds.max_total_allocation_bytes
    {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    let remaining = bounds
        .max_total_allocation_bytes
        .checked_sub(allocated)
        .ok_or(WholePgCarrierFault::CapacityExceeded)?;
    clock.require_effect()?;
    let observed = rustix::fs::fstatvfs(target);
    clock.require_effect()?;
    let fs = observed.map_err(|_| WholePgCarrierFault::IoFailure)?;
    let free = fs
        .f_bavail
        .checked_mul(fs.f_frsize)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    let required = remaining
        .checked_add(bounds.capacity_reserve_bytes)
        .and_then(|n| n.checked_add(bounds.free_floor_bytes))
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    if free < required {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    clock.require_effect()
}

fn open(
    directory: &File,
    name: &std::ffi::CStr,
    (is_dir, allocated_directory): (bool, bool),
    count: &mut SnapshotCounter,
    files: &[ArtifactSnapshotFile],
    bounds: &ArtifactCaptureBounds,
    clock: &dyn CaptureClockCheck,
) -> Result<Arc<File>, WholePgCarrierFault> {
    let flags = OFlags::RDONLY
        | OFlags::NOFOLLOW
        | OFlags::CLOEXEC
        | if is_dir {
            OFlags::DIRECTORY
        } else {
            OFlags::empty()
        };
    prepare_opened_slot(count, files, bounds)?;
    clock.require_effect()?;
    let opened = rustix::fs::openat(directory, name, flags, Mode::empty());
    match opened {
        Ok(file) => retain_opened(File::from(file), allocated_directory, count, clock),
        Err(_) => {
            clock.require_effect()?;
            Err(WholePgCarrierFault::IoFailure)
        }
    }
}

#[cfg(test)]
mod directory_reservation_tests {
    use super::{WholePgCarrierFault, reserve_snapshot_directory};

    #[test]
    fn root_consumes_the_only_slot_before_a_child_can_be_reserved() {
        let mut directories = 0;
        assert_eq!(
            reserve_snapshot_directory(0, (1, 1), &mut directories),
            Ok(())
        );
        assert_eq!(directories, 1);
        assert_eq!(
            reserve_snapshot_directory(1, (1, 1), &mut directories),
            Err(WholePgCarrierFault::CapacityExceeded)
        );
        assert_eq!(directories, 1);
    }

    #[test]
    fn depth_or_counter_overflow_cannot_create_a_reservation() {
        let mut directories = 1;
        assert_eq!(
            reserve_snapshot_directory(2, (1, 3), &mut directories),
            Err(WholePgCarrierFault::CapacityExceeded)
        );
        assert_eq!(directories, 1);
        directories = u64::MAX;
        assert_eq!(
            reserve_snapshot_directory(1, (1, u64::MAX), &mut directories),
            Err(WholePgCarrierFault::BoundsOverflow)
        );
        assert_eq!(directories, u64::MAX);
    }
}

#[cfg(test)]
mod known_capacity_tests {
    use super::{SnapshotMetadata, WholePgCarrierFault, charge_known_capacity};

    #[test]
    fn a_refused_reservation_remains_charged_and_cannot_be_refunded() {
        let mut metadata = SnapshotMetadata::default();
        let mut charged = 0;
        assert_eq!(
            charge_known_capacity(&mut metadata, &mut charged, 9, 8),
            Err(WholePgCarrierFault::CapacityExceeded)
        );
        assert_eq!((metadata.bytes, charged), (9, 9));
        assert_eq!(
            charge_known_capacity(&mut metadata, &mut charged, 0, 8),
            Err(WholePgCarrierFault::CapacityExceeded)
        );
        assert_eq!((metadata.bytes, charged), (9, 9));
    }

    #[test]
    fn arithmetic_overflow_remains_a_refusal_after_the_same_account_moves() {
        let mut metadata = SnapshotMetadata {
            bytes: u64::MAX - 1,
            overflowed: false,
        };
        assert_eq!(
            metadata.charge(2, u64::MAX),
            Err(WholePgCarrierFault::BoundsOverflow)
        );
        let mut moved = metadata;
        assert_eq!(
            moved.charge(0, u64::MAX),
            Err(WholePgCarrierFault::BoundsOverflow)
        );
    }

    #[test]
    fn requested_and_later_reported_capacity_only_add_the_positive_delta() {
        let mut metadata = SnapshotMetadata::default();
        let mut charged = 0;
        for capacity in [32, 48, 16, 64] {
            assert_eq!(
                charge_known_capacity(&mut metadata, &mut charged, capacity, 64),
                Ok(())
            );
        }
        assert_eq!((metadata.bytes, charged), (64, 64));
        assert_eq!(
            charge_known_capacity(&mut metadata, &mut charged, 65, 64),
            Err(WholePgCarrierFault::CapacityExceeded)
        );
        assert_eq!((metadata.bytes, charged), (65, 65));
    }
}
