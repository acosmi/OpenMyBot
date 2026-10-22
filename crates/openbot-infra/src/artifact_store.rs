//! R424 trusted local root, independent store identity and actual IO observations.
//! All synchronous filesystem methods run on a blocking worker. Tokens here carry no actor
//! authorization. Same-UID hostile writers/ACL and atomic compare-unlink remain unproved.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use openbot_application::artifact_read_protocol::ArtifactReadEntryStop;
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::artifact_cleanup::ArtifactCleanupFenceKey;
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::artifact_administration::ObservedArtifactReadRecord;
pub(crate) use crate::artifact_bytes::ArtifactByteStorageLocation;
pub(crate) use crate::artifact_bytes::OriginalArtifactPhysicalObject;
use crate::artifact_bytes::{
    ArtifactBlob, ArtifactBlobReader, ArtifactByteError, ArtifactBytePhysicalUnlinkError,
    ArtifactByteProbe, ArtifactByteStore, ArtifactProbePhase,
};
use crate::artifact_read_lifecycle::ReadOperationState;
use crate::artifact_registry::ArtifactDatasetRegistry;

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub mod capture;

mod read_barrier;
pub use read_barrier::{ArtifactReadControlledBarrier, ArtifactReadControlledDrainAck};
pub(crate) use read_barrier::{
    PhysicalInvocationClaim, PhysicalInvocationQueryOwner, PhysicalWorkerLease,
    StoreReadEnrollment, StoreReadJobLease, StoreReadQueryLease, StoreReadQueryReservation,
    TerminalInvocationClaim, TerminalInvocationQueryOwner, TerminalPublishMode,
    TerminalWorkerLease,
};
use read_barrier::{StoreReadFdLease, StoreReadGate};

const MARKER_NAME: &str = ".artifact-store-v1";
const MAX_MARKER_BYTES: u64 = 4096;

#[cfg(test)]
#[path = "artifact_store/tests.rs"]
mod tests;

/// Open an explicit trusted host root with every absolute path component refusing symlinks.
/// This helper is for startup configuration; no application command accepts this path.
pub fn open_trusted_host_root(path: &std::path::Path) -> Result<File, ArtifactStoreError> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(ArtifactStoreError::UnsafeRoot);
    }
    let mut file = File::open("/").map_err(|_| ArtifactStoreError::Unavailable)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                file = File::from(
                    rustix::fs::openat(
                        &file,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| ArtifactStoreError::UnsafeRoot)?,
                );
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ArtifactStoreError::UnsafeRoot);
            }
        }
    }
    ArtifactRootPhysicalBinding::observe(&file)?;
    Ok(file)
}

/// Create/open only the fixed artifacts child of a current trusted private installation root.
pub fn open_trusted_installation_artifact_root(
    parent: &std::path::Path,
) -> Result<File, ArtifactStoreError> {
    let parent = open_trusted_host_root(parent)?;
    match rustix::fs::mkdirat(&parent, "artifacts", Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => parent
            .sync_all()
            .map_err(|_| ArtifactStoreError::Unavailable)?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(ArtifactStoreError::Unavailable),
    }
    let file = File::from(
        rustix::fs::openat(
            &parent,
            "artifacts",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ArtifactStoreError::UnsafeRoot)?,
    );
    ArtifactRootPhysicalBinding::observe(&file)?;
    if file
        .metadata()
        .map_err(|_| ArtifactStoreError::Unavailable)?
        .dev()
        != parent
            .metadata()
            .map_err(|_| ArtifactStoreError::Unavailable)?
            .dev()
    {
        return Err(ArtifactStoreError::UnsafeRoot);
    }
    Ok(file)
}

/// Redacted trusted-store startup failures, never paths or marker contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactStoreError {
    /// IO/database/schema observation was unavailable.
    #[error("artifact_store_unavailable")]
    Unavailable,
    /// A descriptor or actual private object was unsafe.
    #[error("artifact_store_unsafe_root")]
    UnsafeRoot,
    /// Namespace, dataset, marker or current physical root differs.
    #[error("artifact_store_binding_mismatch")]
    BindingMismatch,
    /// Another current kernel owner holds this root.
    #[error("artifact_store_busy")]
    Busy,
}

/// Closed physical errors of the internal snapshot-to-FD bridge. No host/wire mapping or
/// current authorization decision is implied by these observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactReadBridgeError {
    /// Current actual store/root observation failed.
    #[error("artifact_read_store: {0}")]
    Store(#[from] ArtifactStoreError),
    /// Actual bounded byte object/FD observation failed.
    #[error("artifact_read_bytes: {0}")]
    Bytes(#[from] ArtifactByteError),
}

/// A private-constructed FD reader retaining its original PG snapshot and exact Store Arc.
/// This is not a download handle, a session/window grant, or per-block current authorization.
/// Run synchronous IO on a blocking worker and move this entire reader into that worker.
pub struct StoreBoundArtifactReader {
    // Automatic field Drop ends the original File before releasing shared admission below.
    reader: ArtifactBlobReader,
    record: ObservedArtifactReadRecord,
    store: Arc<DatasetBoundArtifactStore>,
    failed: bool,
    read_lease: StoreReadFdLease,
}

impl core::fmt::Debug for StoreBoundArtifactReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreBoundArtifactReader")
            .field("fd_and_snapshot", &"<redacted>")
            .field("failed", &self.failed)
            .finish()
    }
}

impl StoreBoundArtifactReader {
    pub(crate) const fn record_snapshot(&self) -> &ObservedArtifactReadRecord {
        &self.record
    }

    /// Current original FD/root/marker tail; bounded sync checks only, no body read or await.
    pub(crate) fn verify_physical_current(&self) -> Result<(), ArtifactReadBridgeError> {
        if self.failed {
            return Err(ArtifactByteError::Io.into());
        }
        if !self.record.matches_store(&self.store) {
            return Err(ArtifactStoreError::BindingMismatch.into());
        }
        self.read_lease.verify_admission()?;
        let _guard = self
            .store
            .io
            .try_lock()
            .map_err(|_| ArtifactStoreError::Busy)?;
        self.store.check_current()?;
        self.reader.verify_current_descriptor()?;
        self.store.check_current()?;
        self.read_lease.verify_admission()?;
        Ok(())
    }
    /// Observe at most the frozen 4MiB physical chunk. Failure is terminal and wipes the entire
    /// caller buffer, including bytes not handed off; success grants no later public handoff.
    pub fn read_observed_chunk(
        &mut self,
        output: &mut [u8],
    ) -> Result<usize, ArtifactReadBridgeError> {
        let outcome = self.read_physical_chunk(output);
        if outcome.is_err() {
            self.failed = true;
            output.fill(0);
        }
        outcome
    }

    fn read_physical_chunk(&mut self, output: &mut [u8]) -> Result<usize, ArtifactReadBridgeError> {
        if self.failed {
            return Err(ArtifactByteError::Io.into());
        }
        if !self.record.matches_store(&self.store) {
            return Err(ArtifactStoreError::BindingMismatch.into());
        }
        self.read_lease.verify_admission()?;
        let _guard = self
            .store
            .io
            .try_lock()
            .map_err(|_| ArtifactStoreError::Busy)?;
        self.store.check_current()?;
        let length = self.reader.read_chunk(output)?;
        self.store.check_current()?;
        self.read_lease.verify_admission()?;
        Ok(length)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ArtifactRootPhysicalBinding {
    device: String,
    inode: String,
    uid: String,
}
impl ArtifactRootPhysicalBinding {
    pub(crate) fn device(&self) -> &str {
        &self.device
    }
    pub(crate) fn inode(&self) -> &str {
        &self.inode
    }
    pub(crate) fn uid(&self) -> &str {
        &self.uid
    }
    fn observe(root: &File) -> Result<Self, ArtifactStoreError> {
        let metadata = root
            .metadata()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if !metadata.is_dir()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(ArtifactStoreError::UnsafeRoot);
        }
        Ok(Self {
            device: metadata.dev().to_string(),
            inode: metadata.ino().to_string(),
            uid: metadata.uid().to_string(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoreMarker {
    schema: u16,
    deployment_id: String,
    tenant_id: String,
    dataset_id: String,
    store_id: String,
}

struct PreparedRoot {
    root: File,
    marker: StoreMarker,
    marker_bytes: Vec<u8>,
    physical: ArtifactRootPhysicalBinding,
    fresh_marker: bool,
}

/// Current same-Pool dataset and actual exclusive local root owner. Private construction and
/// per-request current checks, rather than a marker string, establish this binding.
pub struct DatasetBoundArtifactStore {
    registry: Arc<ArtifactDatasetRegistry>,
    root: File,
    marker_bytes: Vec<u8>,
    physical: ArtifactRootPhysicalBinding,
    store_id: Uuid,
    bytes: ArtifactByteStore,
    owner: Arc<()>,
    io: Mutex<()>,
    reads: Arc<StoreReadGate>,
    capture_mutations: Arc<CaptureMutationGate>,
}

// One gate belongs to the original Store Arc. It is armed before host publication. A
// cancelled operation is not an ACK: its original tasks remain here and uncertainty poisons
// capture instead of reopening the gate or silently refunding an unfinished operation.
struct CaptureMutationGate {
    state: Mutex<CaptureMutationState>,
    changed: tokio::sync::Notify,
}

struct CaptureMutationState {
    bound: Option<u64>,
    closed: bool,
    active: u64,
    poisoned: bool,
    tasks: tokio::task::JoinSet<()>,
}

pub(crate) struct CaptureMutationLease {
    operation: Arc<CaptureMutationOperation>,
    completed: bool,
}

struct CaptureMutationOperation {
    gate: Arc<CaptureMutationGate>,
    armed: bool,
    uncertain: std::sync::atomic::AtomicBool,
}

/// One original blocking task: Legacy holds its original JoinHandle; armed capture keeps
/// that actual handle in its Store JoinSet and gives the caller only the result receiver.
pub(crate) struct CaptureBlockingWorker<T> {
    original: Option<tokio::task::JoinHandle<T>>,
    receiver: Option<tokio::sync::oneshot::Receiver<T>>,
    refused: bool,
}
impl<T> Unpin for CaptureBlockingWorker<T> {}
impl<T> std::future::Future for CaptureBlockingWorker<T> {
    type Output = Result<T, ArtifactStoreError>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if this.refused {
            return std::task::Poll::Ready(Err(ArtifactStoreError::Busy));
        }
        if let Some(original) = this.original.as_mut() {
            return std::pin::Pin::new(original)
                .poll(cx)
                .map(|r| r.map_err(|_| ArtifactStoreError::Unavailable));
        }
        match this.receiver.as_mut() {
            Some(receiver) => std::pin::Pin::new(receiver)
                .poll(cx)
                .map(|r| r.map_err(|_| ArtifactStoreError::Unavailable)),
            None => std::task::Poll::Ready(Err(ArtifactStoreError::Unavailable)),
        }
    }
}

impl CaptureMutationGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(CaptureMutationState {
                bound: None,
                closed: false,
                active: 0,
                poisoned: false,
                tasks: tokio::task::JoinSet::new(),
            }),
            changed: tokio::sync::Notify::new(),
        })
    }

    fn enter(self: &Arc<Self>) -> Result<CaptureMutationLease, ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if state.closed || state.poisoned {
            return Err(ArtifactStoreError::Busy);
        }
        let next = state
            .active
            .checked_add(1)
            .ok_or(ArtifactStoreError::Unavailable)?;
        if state.bound.is_some_and(|bound| next > bound) {
            return Err(ArtifactStoreError::Busy);
        }
        state.active = next;
        Ok(CaptureMutationLease {
            operation: Arc::new(CaptureMutationOperation {
                gate: Arc::clone(self),
                armed: state.bound.is_some(),
                uncertain: std::sync::atomic::AtomicBool::new(false),
            }),
            completed: false,
        })
    }
}

impl CaptureMutationLease {
    pub(crate) fn complete(mut self) {
        self.completed = true;
    }
    pub(crate) fn delegated(&self) -> Self {
        Self {
            operation: Arc::clone(&self.operation),
            completed: false,
        }
    }
    pub(crate) fn record_returned(&mut self) {
        self.completed = true;
    }
    fn belongs_to(&self, store: &DatasetBoundArtifactStore) -> bool {
        Arc::ptr_eq(&self.operation.gate, &store.capture_mutations) && !self.completed
    }
}
impl Drop for CaptureMutationLease {
    fn drop(&mut self) {
        if self.operation.armed && !self.completed {
            self.operation
                .uncertain
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}
impl Drop for CaptureMutationOperation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.state.lock() {
            if self.uncertain.load(std::sync::atomic::Ordering::Acquire) {
                state.poisoned = true;
            }
            match state.active.checked_sub(1) {
                Some(active) => state.active = active,
                None => state.poisoned = true,
            }
        }
        self.gate.changed.notify_waiters();
    }
}

/// Borrowed only inside the original blocking worker. The std guard is deliberately !Send;
/// it is retained continuously through preflight, permission, actual IO and final observation.
pub(crate) struct OriginalStorePhysicalIo<'store> {
    original_store: &'store DatasetBoundArtifactStore,
    original_io_guard: std::sync::MutexGuard<'store, ()>,
    original_deadline: Instant,
    capture_lease: Option<CaptureMutationLease>,
}

impl Drop for OriginalStorePhysicalIo<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking()
            && let Some(lease) = self.capture_lease.take()
        {
            lease.complete();
        }
    }
}

pub(crate) enum ArtifactPhysicalUnlinkError<E> {
    Check(ArtifactReadBridgeError),
    Start(E),
}

impl OriginalStorePhysicalIo<'_> {
    fn check_original_before(&self) -> Result<(), ArtifactStoreError> {
        // Read the retained guard explicitly; this never reacquires the original mutex.
        let _held = &self.original_io_guard;
        if Instant::now() >= self.original_deadline {
            return Err(ArtifactStoreError::Unavailable);
        }
        self.original_store.check_current()?;
        if Instant::now() >= self.original_deadline {
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn preflight_installed_guarded(
        &self,
        blob: &ArtifactBlob,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
    ) -> Result<OriginalArtifactPhysicalObject, ArtifactReadBridgeError> {
        self.check_original_before()?;
        let mut guarded_stop = |phase| {
            self.check_original_before().is_err()
                || stop(phase)
                || self.check_original_before().is_err()
        };
        let original = self
            .original_store
            .bytes
            .preflight_installed_guarded_before(blob, self.original_deadline, &mut guarded_stop)?;
        self.check_original_before()?;
        Ok(original)
    }

    pub(crate) fn execute_installed_guarded<E>(
        &self,
        original: &OriginalArtifactPhysicalObject,
        remove: bool,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
        start: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<bool, ArtifactPhysicalUnlinkError<E>> {
        self.check_original_before()
            .map_err(|error| ArtifactPhysicalUnlinkError::Check(error.into()))?;
        let mut guarded_stop = |phase| {
            self.check_original_before().is_err()
                || stop(phase)
                || self.check_original_before().is_err()
        };
        let mut checked_start = || {
            // This filesystem check happens before the caller enters its permission/gate locks.
            self.check_original_before()
                .map_err(|error| ArtifactPhysicalUnlinkError::Check(error.into()))?;
            start().map_err(ArtifactPhysicalUnlinkError::Start)
        };
        match self.original_store.bytes.execute_installed_guarded_before(
            original,
            remove,
            self.original_deadline,
            &mut guarded_stop,
            &mut checked_start,
        ) {
            Ok(unlinked) => Ok(unlinked),
            Err(ArtifactBytePhysicalUnlinkError::Bytes(error)) => {
                Err(ArtifactPhysicalUnlinkError::Check(error.into()))
            }
            Err(ArtifactBytePhysicalUnlinkError::Start(error)) => Err(error),
        }
    }

    pub(crate) fn probe_actual_guarded(
        &self,
        id: Uuid,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
    ) -> ArtifactByteProbe {
        if self.check_original_before().is_err() {
            return ArtifactByteProbe::Indeterminate;
        }
        let mut guarded_stop = |phase| {
            self.check_original_before().is_err()
                || stop(phase)
                || self.check_original_before().is_err()
        };
        // Direct ByteStore delegation keeps the original guard. The ordinary Store wrapper
        // would try_lock a second time and is deliberately not used by this worker.
        let observation = self.original_store.bytes.probe_actual_guarded_before(
            id,
            self.original_deadline,
            &mut guarded_stop,
        );
        if self.check_original_before().is_err() {
            ArtifactByteProbe::Indeterminate
        } else {
            observation
        }
    }
}

impl core::fmt::Debug for DatasetBoundArtifactStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DatasetBoundArtifactStore")
            .field("binding", &"<redacted>")
            .finish()
    }
}

impl DatasetBoundArtifactStore {
    pub(crate) fn begin_capture_mutation(
        &self,
    ) -> Result<CaptureMutationLease, ArtifactStoreError> {
        self.capture_mutations.enter()
    }

    // Retain the actual original supervisor in the armed Store; Legacy keeps the original
    // lifecycle. The caller still observes its original oneshot outcome, not a synthetic join.
    pub(crate) fn spawn_capture_mutation(
        &self,
        work: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), ArtifactStoreError> {
        let mut state = self
            .capture_mutations
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if state.bound.is_some() {
            while let Some(result) = state.tasks.try_join_next() {
                if result.is_err() {
                    state.poisoned = true;
                }
            }
            if state.poisoned
                || state
                    .bound
                    .is_some_and(|bound| state.tasks.len() as u64 >= bound)
            {
                return Err(ArtifactStoreError::Busy);
            }
            state.tasks.spawn(work);
        } else {
            tokio::spawn(work);
        }
        Ok(())
    }

    pub(crate) fn capture_blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> CaptureBlockingWorker<T> {
        let Ok(mut state) = self.capture_mutations.state.lock() else {
            return CaptureBlockingWorker {
                original: None,
                receiver: None,
                refused: true,
            };
        };
        if state.bound.is_none() {
            return CaptureBlockingWorker {
                original: Some(tokio::task::spawn_blocking(work)),
                receiver: None,
                refused: false,
            };
        }
        while let Some(result) = state.tasks.try_join_next() {
            if result.is_err() {
                state.poisoned = true;
            }
        }
        if state.poisoned
            || state
                .bound
                .is_some_and(|bound| state.tasks.len() as u64 >= bound)
        {
            return CaptureBlockingWorker {
                original: None,
                receiver: None,
                refused: true,
            };
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        state.tasks.spawn_blocking(move || {
            let _ = sender.send(work());
        });
        CaptureBlockingWorker {
            original: None,
            receiver: Some(receiver),
            refused: false,
        }
    }

    pub(crate) fn try_physical_io_before_admitted(
        &self,
        original_deadline: Instant,
        admitted: &CaptureMutationLease,
    ) -> Result<OriginalStorePhysicalIo<'_>, ArtifactStoreError> {
        if Instant::now() >= original_deadline {
            return Err(ArtifactStoreError::Unavailable);
        }
        if !admitted.belongs_to(self) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let capture_lease = admitted.delegated();
        let original_io_guard = self.io.try_lock().map_err(|_| ArtifactStoreError::Busy)?;
        let original = OriginalStorePhysicalIo {
            original_store: self,
            original_io_guard,
            original_deadline,
            capture_lease: Some(capture_lease),
        };
        original.check_original_before()?;
        Ok(original)
    }

    /// Trusted host provides a no-symlink private directory descriptor, never a renderer path.
    /// Ordinary reopen is immutable; changed-root restore requires a separate future producer.
    pub async fn bind_host_root(
        root: File,
        registry: Arc<ArtifactDatasetRegistry>,
        policy: ArtifactQuotaPolicy,
    ) -> Result<Self, ArtifactStoreError> {
        registry
            .validate_current()
            .await
            .map_err(|_| ArtifactStoreError::BindingMismatch)?;
        crate::artifact_administration::verify_artifact_registration_schema(registry.pool())
            .await
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let binding = registry.binding();
        let namespace = (
            binding.deployment_id().to_owned(),
            binding.tenant_id().to_owned(),
            binding.dataset_id().to_owned(),
        );
        let prepared = tokio::task::spawn_blocking(move || prepare_root(root, namespace))
            .await
            .map_err(|_| ArtifactStoreError::Unavailable)??;
        let mut client = registry
            .pool()
            .get()
            .await
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        // The transaction originates here from this exact registry Pool. No external transaction
        // or caller-supplied owner token is accepted as same-database evidence.
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='5s'")
            .await
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let actual = transaction.query_opt(
            "SELECT dataset_id,binding_schema,initial_origin,created_at FROM openbot_internal.artifact_dataset_bindings WHERE deployment_id=$1 AND tenant_id=$2",
            &[&binding.deployment_id(), &binding.tenant_id()],
        ).await.map_err(|_| ArtifactStoreError::Unavailable)?.ok_or(ArtifactStoreError::BindingMismatch)?;
        if actual
            .try_get::<_, String>(0)
            .map_err(|_| ArtifactStoreError::BindingMismatch)?
            != binding.dataset_id()
            || actual
                .try_get::<_, i16>(1)
                .map_err(|_| ArtifactStoreError::BindingMismatch)?
                != 1
            || actual
                .try_get::<_, String>(2)
                .map_err(|_| ArtifactStoreError::BindingMismatch)?
                != binding.initial_origin()
            || actual
                .try_get::<_, time::OffsetDateTime>(3)
                .map_err(|_| ArtifactStoreError::BindingMismatch)?
                != binding.created_at()
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        if prepared.fresh_marker {
            transaction.execute(
                "INSERT INTO openbot_internal.artifact_store_bindings(deployment_id,tenant_id,dataset_id,store_id,root_device,root_inode,root_uid) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
                &[&binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id(), &prepared.marker.store_id,
                  &prepared.physical.device, &prepared.physical.inode, &prepared.physical.uid],
            ).await.map_err(|_| ArtifactStoreError::Unavailable)?;
        }
        let row = transaction.query_opt(
            "SELECT store_id,root_device,root_inode,root_uid FROM openbot_internal.artifact_store_bindings WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3",
            &[&binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id()],
        ).await.map_err(|_| ArtifactStoreError::Unavailable)?.ok_or(ArtifactStoreError::BindingMismatch)?;
        let expected = [
            &prepared.marker.store_id,
            &prepared.physical.device,
            &prepared.physical.inode,
            &prepared.physical.uid,
        ];
        for (index, value) in expected.into_iter().enumerate() {
            if row
                .try_get::<_, String>(index)
                .map_err(|_| ArtifactStoreError::BindingMismatch)?
                != *value
            {
                return Err(ArtifactStoreError::BindingMismatch);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        drop(client);
        registry
            .validate_current()
            .await
            .map_err(|_| ArtifactStoreError::BindingMismatch)?;
        let store_id = Uuid::parse_str(&prepared.marker.store_id)
            .map_err(|_| ArtifactStoreError::BindingMismatch)?;
        tokio::task::spawn_blocking(move || {
            if ArtifactRootPhysicalBinding::observe(&prepared.root)? != prepared.physical
                || read_marker(&prepared.root)? != Some(prepared.marker_bytes.clone())
            {
                return Err(ArtifactStoreError::BindingMismatch);
            }
            let bytes = ArtifactByteStore::bind_private_root(
                prepared
                    .root
                    .try_clone()
                    .map_err(|_| ArtifactStoreError::Unavailable)?,
                policy.max_artifact_bytes(),
            )
            .map_err(|_| ArtifactStoreError::Unavailable)?;
            let binding = registry.binding();
            let reads = StoreReadGate::new(
                binding.deployment_id(),
                binding.tenant_id(),
                binding.dataset_id(),
            );
            Ok(Self {
                registry,
                root: prepared.root,
                marker_bytes: prepared.marker_bytes,
                physical: prepared.physical,
                store_id,
                bytes,
                owner: Arc::new(()),
                io: Mutex::new(()),
                reads,
                capture_mutations: CaptureMutationGate::new(),
            })
        })
        .await
        .map_err(|_| ArtifactStoreError::Unavailable)?
    }

    /// Durable local-store identity, a locator rather than authority.
    #[must_use]
    pub const fn store_id(&self) -> Uuid {
        self.store_id
    }
    pub(crate) const fn physical_binding(&self) -> &ArtifactRootPhysicalBinding {
        &self.physical
    }
    pub(crate) fn read_dataset_id(&self) -> &str {
        self.registry.binding().dataset_id()
    }
    pub(crate) fn matches_registry_owner(&self, registry: &ArtifactDatasetRegistry) -> bool {
        Arc::ptr_eq(&self.registry.owner(), &registry.owner())
            && std::ptr::eq(self.registry.pool().manager(), registry.pool().manager())
    }
    fn check_current(&self) -> Result<(), ArtifactStoreError> {
        if ArtifactRootPhysicalBinding::observe(&self.root)? != self.physical
            || read_marker(&self.root)? != Some(self.marker_bytes.clone())
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        Ok(())
    }

    /// Inspect only this original Store's bytes on an owned blocking worker. An ordinary probe
    /// is no permission, deletion receipt or barrier acknowledgement, even when all IO succeeds.
    #[expect(
        dead_code,
        reason = "private guarded byte inspection foundation; producer integration is a separate task"
    )]
    pub(crate) fn probe_actual_guarded_before(
        &self,
        id: Uuid,
        original_deadline: Instant,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
    ) -> ArtifactByteProbe {
        if Instant::now() >= original_deadline {
            return ArtifactByteProbe::Indeterminate;
        }
        let Ok(_guard) = self.io.try_lock() else {
            return ArtifactByteProbe::Indeterminate;
        };
        if Instant::now() >= original_deadline
            || self.check_current().is_err()
            || Instant::now() >= original_deadline
        {
            return ArtifactByteProbe::Indeterminate;
        }
        let mut guarded_stop = |phase| {
            if Instant::now() >= original_deadline || self.check_current().is_err() {
                return true;
            }
            if Instant::now() >= original_deadline || stop(phase) {
                return true;
            }
            Instant::now() >= original_deadline
                || self.check_current().is_err()
                || Instant::now() >= original_deadline
        };
        let observation =
            self.bytes
                .probe_actual_guarded_before(id, original_deadline, &mut guarded_stop);
        if matches!(observation, ArtifactByteProbe::Indeterminate) {
            return observation;
        }
        if Instant::now() >= original_deadline
            || self.check_current().is_err()
            || Instant::now() >= original_deadline
        {
            return ArtifactByteProbe::Indeterminate;
        }
        observation
    }

    pub(crate) fn enroll_read(
        self: &Arc<Self>,
        state: &Arc<ReadOperationState>,
        artifact_id: &str,
        entry_stop: Option<Arc<dyn ArtifactReadEntryStop>>,
    ) -> Result<StoreReadEnrollment, ArtifactStoreError> {
        self.reads
            .enroll(Arc::clone(self), state, artifact_id, entry_stop)
    }

    pub(crate) fn begin_read_query(
        self: &Arc<Self>,
        artifact_id: &str,
    ) -> Result<StoreReadQueryReservation, ArtifactStoreError> {
        self.reads.begin_read_query(Arc::clone(self), artifact_id)
    }

    /// Called only after the original administration checked its actual snapshot Store identity.
    pub(crate) fn close_artifact_reads(
        self: &Arc<Self>,
        key: ArtifactCleanupFenceKey,
    ) -> Result<ArtifactReadControlledBarrier, ArtifactStoreError> {
        self.reads.close(&key)?;
        Ok(ArtifactReadControlledBarrier::new(Arc::clone(self), key))
    }
    /// Consume a descriptor minted by the actual owned-PG adapter for this exact Store Arc.
    /// Recheck current private root/marker and the real object's full digest before retaining its
    /// FD. This synchronous method belongs on the actual blocking worker; it does not recheck
    /// PG/host authority and cannot turn a stale source snapshot into a public delivery grant.
    pub fn open_observed_record(
        self: &Arc<Self>,
        record: ObservedArtifactReadRecord,
    ) -> Result<StoreBoundArtifactReader, ArtifactReadBridgeError> {
        if !record.matches_store(self) {
            return Err(ArtifactStoreError::BindingMismatch.into());
        }
        let read_lease = self.reads.admit_fd(record.read_cleanup_key()?)?;
        let _guard = self.io.try_lock().map_err(|_| ArtifactStoreError::Busy)?;
        self.check_current()?;
        let reader = self.bytes.open_verified(record.blob())?;
        self.check_current()?;
        read_lease.verify_admission()?;
        Ok(StoreBoundArtifactReader {
            reader,
            record,
            store: Arc::clone(self),
            failed: false,
            read_lease,
        })
    }

    /// Public preparation keeps the exact record/root/FD and checks its original stop budget.
    pub(crate) fn open_observed_record_guarded(
        self: &Arc<Self>,
        record: ObservedArtifactReadRecord,
        is_current: &mut impl FnMut(bool) -> bool,
    ) -> Result<StoreBoundArtifactReader, ArtifactReadBridgeError> {
        if !is_current(false) {
            return Err(ArtifactStoreError::Unavailable.into());
        }
        if !record.matches_store(self) {
            return Err(ArtifactStoreError::BindingMismatch.into());
        }
        let read_lease = self.reads.admit_fd(record.read_cleanup_key()?)?;
        let _guard = self.io.try_lock().map_err(|_| ArtifactStoreError::Busy)?;
        self.check_current()?;
        let reader = self
            .bytes
            .open_verified_guarded(record.blob(), is_current)?;
        self.check_current()?;
        if !is_current(false) {
            return Err(ArtifactStoreError::Unavailable.into());
        }
        read_lease.verify_admission()?;
        Ok(StoreBoundArtifactReader {
            reader,
            record,
            store: Arc::clone(self),
            failed: false,
            read_lease,
        })
    }

    /// Current disk-space observation, not an allocation guarantee. Call on a blocking worker.
    pub fn available_bytes(&self) -> Result<u64, ArtifactStoreError> {
        self.check_current()?;
        let space =
            rustix::fs::fstatvfs(&self.root).map_err(|_| ArtifactStoreError::Unavailable)?;
        space
            .f_bavail
            .checked_mul(space.f_frsize)
            .ok_or(ArtifactStoreError::Unavailable)
    }

    pub(crate) fn write_text_once(
        &self,
        id: Uuid,
        expected: [u8; 32],
        text: &[u8],
    ) -> VerifiedArtifactByteObservation {
        let Ok(capture_operation) = self.begin_capture_mutation() else {
            return self.observation(
                id,
                ArtifactByteWritePhase::BeforeWrite,
                ArtifactByteObservationState::Indeterminate,
            );
        };
        let result = self.write_text_once_admitted(&capture_operation, id, expected, text);
        capture_operation.complete();
        result
    }

    pub(crate) fn write_text_once_admitted(
        &self,
        admitted: &CaptureMutationLease,
        id: Uuid,
        expected: [u8; 32],
        text: &[u8],
    ) -> VerifiedArtifactByteObservation {
        if !admitted.belongs_to(self) {
            return self.observation(
                id,
                ArtifactByteWritePhase::BeforeWrite,
                ArtifactByteObservationState::Indeterminate,
            );
        }

        let mut phase = ArtifactByteWritePhase::BeforeWrite;
        let Ok(_guard) = self.io.lock() else {
            return self.observation(id, phase, ArtifactByteObservationState::Indeterminate);
        };
        if self.check_current().is_err()
            || !matches!(self.bytes.probe_actual(id), ArtifactByteProbe::Absent)
        {
            return self.observation(id, phase, ArtifactByteObservationState::Indeterminate);
        }
        let Ok(blob) = ArtifactBlob::from_record(id, text.len() as u64, expected) else {
            return self.observation(id, phase, ArtifactByteObservationState::DurableAbsent);
        };
        phase = ArtifactByteWritePhase::Staging;
        let mut reader = std::io::Cursor::new(text);
        let installed = match self.bytes.stage_for(&mut reader, &blob) {
            Ok(stage) => {
                phase = ArtifactByteWritePhase::Installing;
                self.bytes.install(stage).is_ok()
            }
            Err(_) => false,
        };
        if installed {
            phase = ArtifactByteWritePhase::Installed;
        }
        let state = match self.bytes.probe_actual(id) {
            ArtifactByteProbe::Absent => ArtifactByteObservationState::DurableAbsent,
            ArtifactByteProbe::Retained {
                location,
                byte_length,
                sha256,
            } => {
                if installed
                    && location == ArtifactByteStorageLocation::Object
                    && byte_length == text.len() as u64
                    && sha256 == expected
                {
                    ArtifactByteObservationState::DurableInstalled {
                        byte_length,
                        sha256,
                    }
                } else {
                    ArtifactByteObservationState::RetainedPartial {
                        location,
                        byte_length,
                        sha256,
                    }
                }
            }
            ArtifactByteProbe::Indeterminate => ArtifactByteObservationState::Indeterminate,
        };
        if self.check_current().is_err() {
            return self.observation(id, phase, ArtifactByteObservationState::Indeterminate);
        }
        self.observation(id, phase, state)
    }
    fn observation(
        &self,
        id: Uuid,
        phase: ArtifactByteWritePhase,
        state: ArtifactByteObservationState,
    ) -> VerifiedArtifactByteObservation {
        VerifiedArtifactByteObservation {
            artifact_id: id,
            phase,
            state,
            owner: Arc::clone(&self.owner),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactByteWritePhase {
    BeforeWrite,
    Staging,
    Installing,
    Installed,
}
impl ArtifactByteWritePhase {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeWrite => "before_write",
            Self::Staging => "staging",
            Self::Installing => "installing",
            Self::Installed => "installed",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactByteObservationState {
    DurableInstalled {
        byte_length: u64,
        sha256: [u8; 32],
    },
    DurableAbsent,
    RetainedPartial {
        location: ArtifactByteStorageLocation,
        byte_length: u64,
        sha256: [u8; 32],
    },
    Indeterminate,
}
pub(crate) struct VerifiedArtifactByteObservation {
    artifact_id: Uuid,
    phase: ArtifactByteWritePhase,
    state: ArtifactByteObservationState,
    owner: Arc<()>,
}
impl VerifiedArtifactByteObservation {
    pub(crate) const fn artifact_id(&self) -> Uuid {
        self.artifact_id
    }
    pub(crate) const fn state(&self) -> &ArtifactByteObservationState {
        &self.state
    }
    pub(crate) const fn phase(&self) -> ArtifactByteWritePhase {
        self.phase
    }
    pub(crate) fn matches_store(&self, store: &DatasetBoundArtifactStore) -> bool {
        Arc::ptr_eq(&self.owner, &store.owner)
    }
}

fn prepare_root(
    root: File,
    namespace: (String, String, String),
) -> Result<PreparedRoot, ArtifactStoreError> {
    let physical = ArtifactRootPhysicalBinding::observe(&root)?;
    root.try_lock().map_err(|_| ArtifactStoreError::Busy)?;
    let original = read_marker(&root)?;
    let fresh_marker = original.is_none();
    let (marker, marker_bytes) = if let Some(bytes) = original {
        let marker: StoreMarker =
            serde_json::from_slice(&bytes).map_err(|_| ArtifactStoreError::BindingMismatch)?;
        (marker, bytes)
    } else {
        let directory =
            rustix::fs::Dir::read_from(&root).map_err(|_| ArtifactStoreError::Unavailable)?;
        for entry in directory {
            let entry = entry.map_err(|_| ArtifactStoreError::Unavailable)?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                return Err(ArtifactStoreError::BindingMismatch);
            }
        }
        let marker = StoreMarker {
            schema: 1,
            deployment_id: namespace.0.clone(),
            tenant_id: namespace.1.clone(),
            dataset_id: namespace.2.clone(),
            store_id: Uuid::now_v7().to_string(),
        };
        let bytes = serde_json::to_vec(&marker).map_err(|_| ArtifactStoreError::Unavailable)?;
        let mut file = File::from(
            rustix::fs::openat(
                &root,
                MARKER_NAME,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| ArtifactStoreError::Unavailable)?,
        );
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fchmod(&file, Mode::RUSR).map_err(|_| ArtifactStoreError::Unavailable)?;
        file.sync_all()
            .and_then(|()| root.sync_all())
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        (marker, bytes)
    };
    let id = Uuid::parse_str(&marker.store_id).map_err(|_| ArtifactStoreError::BindingMismatch)?;
    if marker.schema != 1
        || (
            marker.deployment_id.as_str(),
            marker.tenant_id.as_str(),
            marker.dataset_id.as_str(),
        ) != (
            namespace.0.as_str(),
            namespace.1.as_str(),
            namespace.2.as_str(),
        )
        || id.get_version_num() != 7
        || id.get_variant() != uuid::Variant::RFC4122
        || id.to_string() != marker.store_id
        || serde_json::to_vec(&marker).map_err(|_| ArtifactStoreError::Unavailable)? != marker_bytes
        || ArtifactRootPhysicalBinding::observe(&root)? != physical
        || read_marker(&root)? != Some(marker_bytes.clone())
    {
        return Err(ArtifactStoreError::BindingMismatch);
    }
    Ok(PreparedRoot {
        root,
        marker,
        marker_bytes,
        physical,
        fresh_marker,
    })
}

fn read_marker(root: &File) -> Result<Option<Vec<u8>>, ArtifactStoreError> {
    let mut file = match rustix::fs::openat(
        root,
        MARKER_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ArtifactStoreError::UnsafeRoot),
    };
    let before = file
        .metadata()
        .map_err(|_| ArtifactStoreError::Unavailable)?;
    if !before.is_file()
        || before.mode() & 0o7777 != 0o400
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.dev()
            != root
                .metadata()
                .map_err(|_| ArtifactStoreError::Unavailable)?
                .dev()
        || before.len() == 0
        || before.len() > MAX_MARKER_BYTES
    {
        return Err(ArtifactStoreError::UnsafeRoot);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ArtifactStoreError::Unavailable)?;
    let after = file
        .metadata()
        .map_err(|_| ArtifactStoreError::Unavailable)?;
    let stable = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.uid(),
            m.mode(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if bytes.len() as u64 != before.len() || stable(&before) != stable(&after) {
        return Err(ArtifactStoreError::UnsafeRoot);
    }
    Ok(Some(bytes))
}
