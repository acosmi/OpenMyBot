//! Bounded Desktop first-frame projection; PostgreSQL owns every editing reply.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openbot_application::{UiPreferenceAdministration, UiPreferenceAdministrationError};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences};

const FILE_HEADER: &str = "openbot-ui-preferences-v1";
const FILE_MAX_BYTES: u64 = 256;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Host-owned first-frame cache. It never implements the authoritative editing port.
#[derive(Clone)]
pub struct DesktopUiPreferenceStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    path: PathBuf,
    mutation: Mutex<()>,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    capture: Mutex<capture_projection::Preparation>,
}

impl DesktopUiPreferenceStore {
    /// Bind to the exact host-selected settings file.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                path: path.into(),
                mutation: Mutex::new(()),
                #[cfg(all(
                    feature = "desktop-launcher",
                    feature = "postgres-maintenance",
                    target_os = "macos"
                ))]
                capture: Mutex::new(capture_projection::Preparation {
                    used: false,
                    state: None,
                    resources: None,
                }),
            }),
        }
    }

    /// Read bounded host-selected values for first paint only, never for an editing reply.
    /// Returned revision/time are absent; callers must not infer that a PG row is absent.
    pub fn read_first_frame_projection(
        &self,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        self.read()
    }

    fn read(&self) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let Some(preferences) = capture_projection::read_first_frame(self)? {
            return Ok(preferences);
        }
        read_file(&self.inner.path)
    }

    fn project_sync(
        &self,
        preferences: UiPreferences,
    ) -> Result<(), UiPreferenceAdministrationError> {
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if capture_projection::is_armed(self)? {
            return Err(UiPreferenceAdministrationError::Unavailable);
        }
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        // Reject a malformed existing projection rather than replacing unrelated bytes.
        self.read()?;
        write_atomic(&self.inner.path, preferences)
    }
}

/// Desktop editing delegates to the same PostgreSQL CAS and audit port as Server.
#[derive(Clone)]
pub struct DesktopUiPreferenceAdministration {
    authority: Arc<dyn UiPreferenceAdministration>,
    projection: DesktopUiPreferenceStore,
}

impl DesktopUiPreferenceAdministration {
    /// A host-selected cache path carries values for first paint, never a revision or authority.
    pub fn new(authority: Arc<dyn UiPreferenceAdministration>, path: impl Into<PathBuf>) -> Self {
        Self {
            authority,
            projection: DesktopUiPreferenceStore::new(path),
        }
    }

    async fn project(&self, preferences: UiPreferences) {
        // An absent PG row must not erase the old first-frame projection or create a row.
        if preferences.revision.is_none() {
            return;
        }
        let store = self.projection.clone();
        let result = tokio::task::spawn_blocking(move || store.project_sync(preferences)).await;
        if !matches!(result, Ok(Ok(()))) {
            tracing::warn!(
                "Committed UI preferences remain authoritative; first-frame cache unavailable"
            );
        }
    }
}

#[async_trait]
impl UiPreferenceAdministration for DesktopUiPreferenceAdministration {
    async fn get(
        &self,
        auth: &AuthContext,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        let mut operation = capture_projection::admit(&self.projection)?;
        let result = self.authority.get(auth).await;
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        capture_projection::observe_sql(&mut operation, &result);
        let preferences = result?;
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let Some(operation) = operation {
            capture_projection::project(self.projection.clone(), operation, preferences).await;
            return Ok(preferences);
        }
        self.project(preferences).await;
        Ok(preferences)
    }

    async fn update(
        &self,
        auth: &AuthContext,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        // A failed/unknown/409 PG result never becomes a file fallback or a second PG request.
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        let mut operation = capture_projection::admit(&self.projection)?;
        let result = self.authority.update(auth, update).await;
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        capture_projection::observe_sql(&mut operation, &result);
        let preferences = result?;
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let Some(operation) = operation {
            capture_projection::project(self.projection.clone(), operation, preferences).await;
            return Ok(preferences);
        }
        self.project(preferences).await;
        Ok(preferences)
    }
}

fn read_file(path: &Path) -> Result<UiPreferences, UiPreferenceAdministrationError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(UiPreferences::default());
        }
        Err(_) => return Err(UiPreferenceAdministrationError::Unavailable),
    };
    if !metadata.is_file() || metadata.len() > FILE_MAX_BYTES {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
    }
    let file =
        File::open(path).map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    let opened = file
        .metadata()
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    if !opened.is_file() || opened.len() > FILE_MAX_BYTES {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
    }
    read_preferences(file)
}

fn read_preferences(
    reader: impl io::Read,
) -> Result<UiPreferences, UiPreferenceAdministrationError> {
    let mut bytes = Vec::new();
    reader
        .take(FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    if bytes.len() as u64 > FILE_MAX_BYTES {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
    }
    let raw = std::str::from_utf8(&bytes)
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    parse(raw)
}

fn parse(raw: &str) -> Result<UiPreferences, UiPreferenceAdministrationError> {
    let mut lines = raw.lines();
    if lines.next() != Some(FILE_HEADER) {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "version" });
    }
    let theme = match lines.next() {
        Some("theme=-") => None,
        Some("theme=system") => Some(UiTheme::System),
        Some("theme=light") => Some(UiTheme::Light),
        Some("theme=dark") => Some(UiTheme::Dark),
        _ => return Err(UiPreferenceAdministrationError::Corrupt { field: "theme" }),
    };
    let locale = match lines.next() {
        Some("locale=-") => None,
        Some("locale=en") => Some(UiLocale::En),
        Some("locale=zh-CN") => Some(UiLocale::ZhCn),
        _ => return Err(UiPreferenceAdministrationError::Corrupt { field: "locale" }),
    };
    if lines.next().is_some() {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
    }
    Ok(UiPreferences {
        theme,
        locale,
        ..UiPreferences::default()
    })
}

fn render(preferences: UiPreferences) -> String {
    let theme = preferences.theme.map_or("-", UiTheme::as_str);
    let locale = preferences.locale.map_or("-", UiLocale::as_str);
    format!("{FILE_HEADER}\ntheme={theme}\nlocale={locale}\n")
}

fn write_atomic(
    path: &Path,
    preferences: UiPreferences,
) -> Result<(), UiPreferenceAdministrationError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(UiPreferenceAdministrationError::InvalidInput { field: "path" })?;
    fs::create_dir_all(parent).map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(UiPreferenceAdministrationError::InvalidInput { field: "path" })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{name}.tmp.{}.{sequence}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        let encoded = render(preferences);
        file.write_all(encoded.as_bytes())
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        file.sync_all()
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        drop(file);
        fs::rename(&temporary, path).map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
pub(crate) use capture_projection::{PreferenceCaptureSnapshot, RetainedPreferenceCapture};

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
mod capture_projection {
    use super::*;
    use crate::tauri_background::capture::{CaptureResourceTotals, reserve_capture_resources};
    use openbot_domain::backup::whole_pg_carrier::{
        WholePgCarrierBounds, WholePgCarrierFault as Fault,
    };
    use openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck;
    use sha2::{Digest, Sha256};
    use std::alloc::Layout;
    use std::future::{Future as _, poll_fn};
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};
    use std::task::{Context, Poll};
    use tokio::sync::Notify;
    use tokio::task::{Id, JoinError, JoinHandle, JoinSet};

    const ORIGINAL_LEAF: &str = "ui-preferences-v1";
    const SNAPSHOT_LEAF: &str = "ui-preferences-v1.json";
    // Original dot/leaf/tmp/pid/sequence grammar, u32/u64 unsigned decimal maxima.
    const TEMPORARY_NAME_BYTES: usize = 1 + ORIGINAL_LEAF.len() + 5 + 10 + 1 + 20;

    pub(super) struct Preparation {
        pub(super) used: bool,
        pub(super) state: Option<Arc<State>>,
        pub(super) resources: Option<Arc<Mutex<CaptureResourceTotals>>>,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct DirectoryIdentity {
        device: u64,
        inode: u64,
        uid: u32,
        mode: u32,
    }
    impl DirectoryIdentity {
        fn of(metadata: &fs::Metadata) -> Result<Self, Fault> {
            if !metadata.is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err(Fault::PathUnsafe);
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                mode: metadata.mode(),
            })
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        uid: u32,
        mode: u32,
        links: u64,
        bytes: u64,
        modified: i64,
        modified_ns: i64,
        changed: i64,
        changed_ns: i64,
    }
    impl FileIdentity {
        fn of(metadata: &fs::Metadata) -> Result<Self, Fault> {
            if !metadata.is_file()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() > FILE_MAX_BYTES
            {
                return Err(Fault::PathUnsafe);
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                bytes: metadata.len(),
                modified: metadata.mtime(),
                modified_ns: metadata.mtime_nsec(),
                changed: metadata.ctime(),
                changed_ns: metadata.ctime_nsec(),
            })
        }

        fn named_matches(&self, named: &rustix::fs::Stat) -> bool {
            rustix::fs::FileType::from_raw_mode(named.st_mode) == rustix::fs::FileType::RegularFile
                && self.device == named.st_dev as u64
                && self.inode == named.st_ino
                && self.uid == named.st_uid
                && self.mode == u32::from(named.st_mode)
                && self.links == named.st_nlink as u64
                && u64::try_from(named.st_size).ok() == Some(self.bytes)
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum OperationPhase {
        Sql,
        Projection,
        Worker,
        Finished,
        Unknown,
    }

    struct OriginalOperation {
        phase: OperationPhase,
        task: Option<Id>,
        joined: Option<Result<Result<(), UiPreferenceAdministrationError>, JoinError>>,
    }

    struct Gate {
        closed: bool,
        root: Option<DirectoryIdentity>,
        operations: Vec<OriginalOperation>,
        tasks: JoinSet<Result<(), UiPreferenceAdministrationError>>,
        active: u64,
        fault: Option<Fault>,
        unmatched: Option<Result<(Id, Result<(), UiPreferenceAdministrationError>), JoinError>>,
        fd_admissions: u64,
        metadata_reserved: u64,
    }

    pub(super) struct State {
        parent: File,
        parent_identity: DirectoryIdentity,
        bounds: WholePgCarrierBounds,
        resources: Arc<Mutex<CaptureResourceTotals>>,
        limit: usize,
        gate: Mutex<Gate>,
        changed: Notify,
    }

    // A ticket is never an RAII refund. Cancellation during SQL/projection preparation leaves
    // Unknown; a registered worker remains in the original JoinSet until its actual join.
    pub(super) struct Ticket {
        state: Arc<State>,
        slot: usize,
        settled: bool,
    }

    impl Drop for Ticket {
        fn drop(&mut self) {
            if self.settled {
                return;
            }
            if let Ok(mut gate) = self.state.gate.lock() {
                if let Some(operation) = gate.operations.get_mut(self.slot) {
                    if matches!(
                        operation.phase,
                        OperationPhase::Sql | OperationPhase::Projection
                    ) {
                        operation.phase = OperationPhase::Unknown;
                    }
                }
            }
            self.state.changed.notify_waiters();
        }
    }

    // Pinned1.98 alloc::sync ArcInner is repr(C), two Atomic<usize> then data.
    // This is requested Rust backing, never a measured allocator/runtime peak.
    fn arc_backing_bytes(body: Layout) -> Result<u64, Fault> {
        let (layout, _) = Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(body)
            .map_err(|_| Fault::BoundsOverflow)?;
        u64::try_from(layout.pad_to_align().size()).map_err(|_| Fault::BoundsOverflow)
    }

    fn store_backing_bytes(store: &DesktopUiPreferenceStore) -> Result<u64, Fault> {
        arc_backing_bytes(Layout::new::<StoreInner>())?
            .checked_add(arc_backing_bytes(Layout::new::<
                DesktopUiPreferenceAdministration,
            >())?)
            .and_then(|n| n.checked_add(store.inner.path.capacity() as u64))
            .ok_or(Fault::BoundsOverflow)
    }

    fn operation_known_bytes() -> Result<u64, Fault> {
        // Original ticket/closure/value/read buffers and the two cache-string backings.
        // JoinSet/task/waker/PG/panic/allocator internals remain separately unproved;
        // these actual known fields are not a zero fee for those opaque producers.
        (std::mem::size_of::<Ticket>() as u64)
            .checked_add(std::mem::size_of::<UiPreferences>() as u64)
            .and_then(|n| n.checked_add(std::mem::size_of::<DesktopUiPreferenceStore>() as u64))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<Arc<State>>() as u64))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<CacheBytes>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Sha256>() as u64))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<fs::Metadata>() as u64))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<rustix::fs::Stat>() as u64))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<String>() as u64))
            .and_then(|n| n.checked_add(FILE_MAX_BYTES))
            .and_then(|n| n.checked_add(TEMPORARY_NAME_BYTES as u64))
            .ok_or(Fault::BoundsOverflow)
    }

    fn snapshot_known_bytes() -> Result<u64, Fault> {
        arc_backing_bytes(Layout::new::<Mutex<SnapshotWork>>())?
            .checked_add(std::mem::size_of::<Arc<Mutex<SnapshotWork>>>() as u64)
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Result<SnapshotObservation, Fault>>() as u64)
            })
            .and_then(|n| n.checked_add(5 * std::mem::size_of::<CacheBytes>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Sha256>() as u64))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<fs::Metadata>() as u64))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<rustix::fs::Stat>() as u64))
            .ok_or(Fault::BoundsOverflow)
    }

    fn reserve_known(state: &State, gate: &mut Gate, fds: u64, metadata: u64) -> Result<(), Fault> {
        // The only lock order is original component mutex -> shared numeric book.
        // The book call completes before any allocation, syscall, worker or await.
        let admitted = (|| {
            let next_fds = gate
                .fd_admissions
                .checked_add(fds)
                .ok_or(Fault::BoundsOverflow)?;
            let next_metadata = gate
                .metadata_reserved
                .checked_add(metadata)
                .ok_or(Fault::BoundsOverflow)?;
            if next_fds > state.bounds.max_open_files
                || next_metadata > state.bounds.max_metadata_bytes
            {
                return Err(Fault::CapacityExceeded);
            }
            reserve_capture_resources(&state.resources, fds, metadata)?;
            Ok((next_fds, next_metadata))
        })();
        match admitted {
            Ok((fds, metadata)) => {
                gate.fd_admissions = fds;
                gate.metadata_reserved = metadata;
                Ok(())
            }
            Err(fault) => Err(*gate.fault.get_or_insert(fault)),
        }
    }

    fn gate_error() -> UiPreferenceAdministrationError {
        UiPreferenceAdministrationError::Unavailable
    }

    fn ui_fault(fault: Fault) -> UiPreferenceAdministrationError {
        match fault {
            Fault::PathUnsafe | Fault::SourceChanged | Fault::NonCanonical | Fault::ShortRead => {
                UiPreferenceAdministrationError::Corrupt { field: "file" }
            }
            _ => UiPreferenceAdministrationError::Unavailable,
        }
    }

    fn capture_state(
        store: &DesktopUiPreferenceStore,
    ) -> Result<Option<Arc<State>>, UiPreferenceAdministrationError> {
        let mut preparation = store.inner.capture.lock().map_err(|_| gate_error())?;
        preparation.used = true;
        Ok(preparation.state.as_ref().map(Arc::clone))
    }

    pub(super) fn is_armed(
        store: &DesktopUiPreferenceStore,
    ) -> Result<bool, UiPreferenceAdministrationError> {
        Ok(capture_state(store)?.is_some())
    }

    pub(super) fn admit(
        store: &DesktopUiPreferenceStore,
    ) -> Result<Option<Ticket>, UiPreferenceAdministrationError> {
        let Some(state) = capture_state(store)? else {
            return Ok(None);
        };
        let slot = {
            let mut gate = state.gate.lock().map_err(|_| gate_error())?;
            if gate.closed || gate.root.is_none() || gate.operations.len() >= state.limit {
                return Err(gate_error());
            }
            let prepared = (|| {
                let active = gate.active.checked_add(1).ok_or(Fault::BoundsOverflow)?;
                let needed = gate
                    .operations
                    .len()
                    .checked_add(1)
                    .ok_or(Fault::BoundsOverflow)?;
                let grows = needed > gate.operations.capacity();
                // Pinned1.98 grow_exact requests cap=len+additional and stores that cap.
                // Pay the whole new backing; old backings never refund, including reallocation.
                let backing = if grows {
                    u64::try_from(needed)
                        .map_err(|_| Fault::BoundsOverflow)?
                        .checked_mul(std::mem::size_of::<OriginalOperation>() as u64)
                        .ok_or(Fault::BoundsOverflow)?
                } else {
                    0 // No new backing allocation, not a fee for any opaque producer.
                };
                let metadata = operation_known_bytes()?
                    .checked_add(backing)
                    .ok_or(Fault::BoundsOverflow)?;
                Ok::<_, Fault>((active, needed, grows, metadata))
            })();
            let (active, needed, grows, metadata) = match prepared {
                Ok(values) => values,
                Err(fault) => return Err(ui_fault(*gate.fault.get_or_insert(fault))),
            };
            reserve_known(&state, &mut gate, 2, metadata).map_err(ui_fault)?;
            if grows {
                if gate.operations.try_reserve_exact(1).is_err() {
                    gate.fault.get_or_insert(Fault::CapacityExceeded);
                    return Err(gate_error());
                }
                // Defense against a different pin, not an after-allocation bound proof.
                if gate.operations.capacity() != needed {
                    gate.fault.get_or_insert(Fault::IntentMismatch);
                    return Err(gate_error());
                }
            }
            let slot = gate.operations.len();
            gate.operations.push(OriginalOperation {
                phase: OperationPhase::Sql,
                task: None,
                joined: None,
            });
            gate.active = active;
            slot
        };
        Ok(Some(Ticket {
            state,
            slot,
            settled: false,
        }))
    }

    fn finish(gate: &mut Gate, slot: usize) -> Result<(), Fault> {
        let operation = gate.operations.get_mut(slot).ok_or(Fault::IntentMismatch)?;
        if operation.phase != OperationPhase::Finished {
            operation.phase = OperationPhase::Finished;
            gate.active = gate.active.checked_sub(1).ok_or(Fault::IntentMismatch)?;
        }
        Ok(())
    }

    pub(super) fn observe_sql(
        ticket: &mut Option<Ticket>,
        result: &Result<UiPreferences, UiPreferenceAdministrationError>,
    ) {
        let Some(ticket) = ticket.as_mut() else {
            return;
        };
        if let Ok(mut gate) = ticket.state.gate.lock() {
            match result {
                Ok(_) => {
                    if let Some(operation) = gate.operations.get_mut(ticket.slot) {
                        operation.phase = OperationPhase::Projection;
                    }
                }
                Err(
                    UiPreferenceAdministrationError::CommitUnknown
                    | UiPreferenceAdministrationError::Unavailable,
                ) => {
                    if let Some(operation) = gate.operations.get_mut(ticket.slot) {
                        operation.phase = OperationPhase::Unknown;
                    }
                    ticket.settled = true;
                }
                Err(_) => {
                    if finish(&mut gate, ticket.slot).is_err() {
                        gate.fault.get_or_insert(Fault::ClosingPending);
                    }
                    ticket.settled = true;
                }
            }
        }
        ticket.state.changed.notify_waiters();
    }

    impl State {
        fn retain_join(
            &self,
            gate: &mut Gate,
            outcome: Result<(Id, Result<(), UiPreferenceAdministrationError>), JoinError>,
        ) {
            let id = match &outcome {
                Ok((id, _)) => *id,
                Err(error) => error.id(),
            };
            let Some(slot) = gate
                .operations
                .iter()
                .position(|operation| operation.task == Some(id))
            else {
                gate.unmatched = Some(outcome);
                gate.fault.get_or_insert(Fault::ClosingPending);
                return;
            };
            if gate.operations[slot].joined.is_some() {
                gate.unmatched = Some(outcome);
                gate.fault.get_or_insert(Fault::ClosingPending);
                return;
            }
            let failed = !matches!(&outcome, Ok((_, Ok(()))));
            // Cache the actual result/panic-bearing JoinError before any clock check/await.
            gate.operations[slot].joined = Some(outcome.map(|(_, value)| value));
            if finish(gate, slot).is_err() || failed {
                gate.fault.get_or_insert(Fault::ClosingPending);
            }
        }

        fn drain(
            &self,
            gate: &mut Gate,
            cx: &mut Context<'_>,
            clock: Option<&dyn CaptureClockCheck>,
        ) -> Result<(), Fault> {
            if gate.unmatched.is_some() {
                return Err(Fault::ClosingPending);
            }
            loop {
                check(clock)?;
                match gate.tasks.poll_join_next_with_id(cx) {
                    Poll::Ready(Some(outcome)) => {
                        self.retain_join(gate, outcome);
                        self.changed.notify_waiters();
                        check(clock)?;
                        if gate.unmatched.is_some() {
                            return Err(Fault::ClosingPending);
                        }
                    }
                    Poll::Ready(None) | Poll::Pending => {
                        check(clock)?;
                        return Ok(());
                    }
                }
            }
        }
    }

    pub(super) async fn project(
        store: DesktopUiPreferenceStore,
        mut ticket: Ticket,
        preferences: UiPreferences,
    ) {
        if preferences.revision.is_none() {
            if let Ok(mut gate) = ticket.state.gate.lock() {
                if finish(&mut gate, ticket.slot).is_err() {
                    gate.fault.get_or_insert(Fault::ClosingPending);
                }
                ticket.settled = true;
            }
            ticket.state.changed.notify_waiters();
            return;
        }
        let state = Arc::clone(&ticket.state);
        {
            let Ok(mut gate) = state.gate.lock() else {
                return;
            };
            if gate
                .operations
                .get(ticket.slot)
                .is_none_or(|op| op.phase != OperationPhase::Projection)
            {
                return;
            }
            let worker_state = Arc::clone(&state);
            let id = gate
                .tasks
                .spawn_blocking(move || project_original(&store, &worker_state, preferences))
                .id();
            // Original JoinSet owns the handle before this original operation's first await.
            gate.operations[ticket.slot].task = Some(id);
            gate.operations[ticket.slot].phase = OperationPhase::Worker;
        }
        state.changed.notify_waiters();
        loop {
            let notified = state.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let result = poll_fn(|cx| {
                let mut gate = match state.gate.lock() {
                    Ok(gate) => gate,
                    Err(_) => return Poll::Ready(Some(Err(gate_error()))),
                };
                if state.drain(&mut gate, cx, None).is_err() {
                    return Poll::Ready(Some(Err(gate_error())));
                }
                if let Some(joined) = gate.operations[ticket.slot].joined.as_ref() {
                    let result = match joined {
                        Ok(value) => *value,
                        Err(_) => Err(gate_error()),
                    };
                    return Poll::Ready(Some(result));
                }
                drop(gate);
                match notified.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            if let Some(result) = result {
                ticket.settled = true;
                if result.is_err() {
                    tracing::warn!(
                        "Committed UI preferences remain authoritative; first-frame cache unavailable"
                    );
                }
                return;
            }
        }
    }

    fn check(clock: Option<&dyn CaptureClockCheck>) -> Result<(), Fault> {
        match clock {
            Some(clock) => clock.require_effect(),
            None => Ok(()),
        }
    }

    // Only non-resource observations use this helper. File opens/dup install their actual
    // result in a resident slot before the post-effect check.
    fn observe<T>(
        clock: Option<&dyn CaptureClockCheck>,
        effect: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, Fault> {
        check(clock)?;
        let observed = effect();
        let after = check(clock);
        after?;
        match observed {
            Err(_) => Err(Fault::IoFailure),
            Ok(value) => Ok(value),
        }
    }

    fn parent_before(state: &State, clock: Option<&dyn CaptureClockCheck>) -> Result<(), Fault> {
        let expected = {
            let gate = state.gate.lock().map_err(|_| Fault::ClosingPending)?;
            gate.root.ok_or(Fault::ClosingPending)?
        };
        let actual = DirectoryIdentity::of(&observe(clock, || state.parent.metadata())?)?;
        if actual != expected || actual != state.parent_identity {
            return Err(Fault::SourceChanged);
        }
        Ok(())
    }

    fn named(
        parent: &File,
        leaf: &str,
        clock: Option<&dyn CaptureClockCheck>,
    ) -> Result<Option<rustix::fs::Stat>, Fault> {
        check(clock)?;
        let observed = rustix::fs::statat(parent, leaf, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
        let after = check(clock);
        after?;
        match observed {
            Ok(stat) => Ok(Some(stat)),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(_) => Err(Fault::IoFailure),
        }
    }

    struct CacheBytes {
        bytes: [u8; FILE_MAX_BYTES as usize + 1],
        len: usize,
        identity: Option<FileIdentity>,
        sha256: Option<[u8; 32]>,
    }

    fn read_held(file: &File, clock: Option<&dyn CaptureClockCheck>) -> Result<CacheBytes, Fault> {
        let before = FileIdentity::of(&observe(clock, || file.metadata())?)?;
        let mut bytes = [0; FILE_MAX_BYTES as usize + 1];
        let mut len = 0;
        loop {
            let count = observe(clock, || file.read_at(&mut bytes[len..], len as u64))?;
            if count == 0 {
                break;
            }
            len = len.checked_add(count).ok_or(Fault::BoundsOverflow)?;
            if len > FILE_MAX_BYTES as usize {
                return Err(Fault::CapacityExceeded);
            }
        }
        let after = FileIdentity::of(&observe(clock, || file.metadata())?)?;
        if before != after || before.bytes != len as u64 {
            return Err(Fault::SourceChanged);
        }
        Ok(CacheBytes {
            sha256: Some(Sha256::digest(&bytes[..len]).into()),
            bytes,
            len,
            identity: Some(before),
        })
    }

    fn read_source(
        state: &State,
        slot: &mut Option<File>,
        clock: Option<&dyn CaptureClockCheck>,
    ) -> Result<CacheBytes, Fault> {
        parent_before(state, clock)?;
        let before = named(&state.parent, ORIGINAL_LEAF, clock)?;
        let Some(before) = before else {
            if slot.is_some() {
                return Err(Fault::SourceChanged);
            }
            parent_before(state, clock)?;
            if named(&state.parent, ORIGINAL_LEAF, clock)?.is_some() {
                return Err(Fault::SourceChanged);
            }
            parent_before(state, clock)?;
            return Ok(CacheBytes {
                bytes: [0; FILE_MAX_BYTES as usize + 1],
                len: 0,
                identity: None,
                sha256: None,
            });
        };
        if slot.is_none() {
            // One of this original operation's prepaid source-FD slots.
            check(clock)?;
            let observed = rustix::fs::openat(
                &state.parent,
                ORIGINAL_LEAF,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            );
            let error = match observed {
                Ok(file) => {
                    *slot = Some(File::from(file));
                    None
                }
                Err(_) => Some(Fault::IoFailure),
            };
            let after = check(clock);
            after?;
            if let Some(error) = error {
                return Err(error);
            }
        }
        let held = slot.as_ref().ok_or(Fault::MaterialMissing)?;
        let bytes = read_held(held, clock)?;
        if !bytes
            .identity
            .ok_or(Fault::SourceChanged)?
            .named_matches(&before)
        {
            return Err(Fault::SourceChanged);
        }
        let after = named(&state.parent, ORIGINAL_LEAF, clock)?.ok_or(Fault::SourceChanged)?;
        if !bytes
            .identity
            .ok_or(Fault::SourceChanged)?
            .named_matches(&after)
        {
            return Err(Fault::SourceChanged);
        }
        parent_before(state, clock)?;
        Ok(bytes)
    }

    fn decode(bytes: &CacheBytes) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        if bytes.identity.is_none() {
            return Ok(UiPreferences::default());
        }
        let text = std::str::from_utf8(&bytes.bytes[..bytes.len])
            .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
        parse(text)
    }

    pub(super) fn read_first_frame(
        store: &DesktopUiPreferenceStore,
    ) -> Result<Option<UiPreferences>, UiPreferenceAdministrationError> {
        let Some(mut ticket) = admit(store)? else {
            return Ok(None);
        };
        let result = {
            let _guard = store.inner.mutation.lock().map_err(|_| gate_error())?;
            let mut original = None;
            read_source(&ticket.state, &mut original, None)
                .map_err(ui_fault)
                .and_then(|bytes| decode(&bytes))
        };
        if let Ok(mut gate) = ticket.state.gate.lock() {
            if finish(&mut gate, ticket.slot).is_err() {
                gate.fault.get_or_insert(Fault::ClosingPending);
            }
            ticket.settled = true;
        }
        ticket.state.changed.notify_waiters();
        result.map(Some)
    }

    fn project_original(
        store: &DesktopUiPreferenceStore,
        state: &State,
        preferences: UiPreferences,
    ) -> Result<(), UiPreferenceAdministrationError> {
        let _mutation = store.inner.mutation.lock().map_err(|_| gate_error())?;
        let mut original = None;
        let before = read_source(state, &mut original, None).map_err(ui_fault)?;
        decode(&before)?;
        let theme = preferences.theme.map_or("-", UiTheme::as_str);
        let locale = preferences.locale.map_or("-", UiLocale::as_str);
        let encoded_len = FILE_HEADER
            .len()
            .checked_add(1 + "theme=".len())
            .and_then(|n| n.checked_add(theme.len()))
            .and_then(|n| n.checked_add(1 + "locale=".len()))
            .and_then(|n| n.checked_add(locale.len() + 1))
            .ok_or_else(gate_error)?;
        if encoded_len as u64 > FILE_MAX_BYTES {
            return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
        }
        // The original closed3-line grammar; backing was reserved before original PG.
        let mut encoded = String::new();
        encoded.try_reserve_exact(encoded_len).map_err(|_| {
            if let Ok(mut gate) = state.gate.lock() {
                gate.fault.get_or_insert(Fault::CapacityExceeded);
            }
            gate_error()
        })?;
        if encoded.capacity() != encoded_len {
            return Err(gate_error());
        }
        encoded.push_str(FILE_HEADER);
        encoded.push_str("\ntheme=");
        encoded.push_str(theme);
        encoded.push_str("\nlocale=");
        encoded.push_str(locale);
        encoded.push('\n');
        if encoded.len() != encoded_len || encoded.capacity() != encoded_len {
            return Err(gate_error());
        }
        let sequence = TEMP_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| gate_error())?;
        let mut temporary = String::new();
        temporary
            .try_reserve_exact(TEMPORARY_NAME_BYTES)
            .map_err(|_| {
                if let Ok(mut gate) = state.gate.lock() {
                    gate.fault.get_or_insert(Fault::CapacityExceeded);
                }
                gate_error()
            })?;
        if temporary.capacity() != TEMPORARY_NAME_BYTES {
            return Err(gate_error());
        }
        use std::fmt::Write as _;
        write!(
            &mut temporary,
            ".{ORIGINAL_LEAF}.tmp.{}.{sequence}",
            std::process::id()
        )
        .map_err(|_| gate_error())?;
        if temporary.len() > TEMPORARY_NAME_BYTES || temporary.capacity() != TEMPORARY_NAME_BYTES {
            return Err(gate_error());
        }
        // The whole original operation admitted both source and atomic-write FDs before PG.
        let file = rustix::fs::openat(
            &state.parent,
            temporary.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map(File::from)
        .map_err(|_| gate_error())?;
        let result = (|| {
            (&file)
                .write_all(encoded.as_bytes())
                .map_err(|_| gate_error())?;
            file.sync_all().map_err(|_| gate_error())?;
            let current = named(&state.parent, ORIGINAL_LEAF, None).map_err(ui_fault)?;
            match (before.identity, current) {
                (None, None) => {}
                (Some(expected), Some(current)) if expected.named_matches(&current) => {}
                _ => return Err(gate_error()),
            }
            rustix::fs::renameat(
                &state.parent,
                temporary.as_str(),
                &state.parent,
                ORIGINAL_LEAF,
            )
            .map_err(|_| gate_error())?;
            state.parent.sync_all().map_err(|_| gate_error())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = rustix::fs::unlinkat(
                &state.parent,
                temporary.as_str(),
                rustix::fs::AtFlags::empty(),
            );
        }
        result
    }

    pub(crate) struct PreferenceCaptureSnapshot {
        material: Option<(File, u64, [u8; 32])>,
    }
    impl PreferenceCaptureSnapshot {
        pub(crate) fn byte_length(&self) -> Option<u64> {
            self.material.as_ref().map(|(_, len, _)| *len)
        }
        pub(crate) fn sha256(&self) -> Option<[u8; 32]> {
            self.material.as_ref().map(|(_, _, hash)| *hash)
        }
        pub(crate) fn into_owned_file(self) -> Option<File> {
            self.material.map(|(file, _, _)| file)
        }
    }

    #[derive(Clone, Copy)]
    enum SnapshotObservation {
        Absent,
        Present { len: u64, sha256: [u8; 32] },
    }

    struct SnapshotWork {
        state: Arc<State>,
        store: DesktopUiPreferenceStore,
        clock: Arc<dyn CaptureClockCheck>,
        destination: Option<File>,
        destination_identity: Option<DirectoryIdentity>,
        duplicate_attempted: bool,
        source: Option<File>,
        output: Option<File>,
    }

    pub(crate) struct RetainedPreferenceCapture {
        store: DesktopUiPreferenceStore,
        state: Arc<State>,
        clock: Option<Arc<dyn CaptureClockCheck>>,
        destination_fd: Option<i32>,
        work: Option<Arc<Mutex<SnapshotWork>>>,
        worker: Option<JoinHandle<Result<SnapshotObservation, Fault>>>,
        worker_spawn_entered: bool,
        joined: Option<Result<Result<SnapshotObservation, Fault>, JoinError>>,
        consumed: bool,
    }

    impl DesktopUiPreferenceAdministration {
        pub(crate) fn bind_original_capture_resources(
            &self,
            resources: Arc<Mutex<CaptureResourceTotals>>,
        ) -> Result<(), Fault> {
            let mut preparation = self
                .projection
                .inner
                .capture
                .lock()
                .map_err(|_| Fault::ClosingPending)?;
            if preparation.used || preparation.state.is_some() || preparation.resources.is_some() {
                return Err(Fault::IntentMismatch);
            }
            // The actual original Store/path and adapter backing, before publication.
            // No second Store, root, authority, book or owner identity is constructed.
            reserve_capture_resources(&resources, 0, store_backing_bytes(&self.projection)?)?;
            preparation.resources = Some(resources);
            Ok(())
        }

        pub(crate) fn prepare_capture_projection(
            self: Arc<Self>,
            bounds: WholePgCarrierBounds,
        ) -> Result<(Arc<Self>, RetainedPreferenceCapture), Fault> {
            let bounds = bounds.check()?;
            if SNAPSHOT_LEAF.len() as u64 > bounds.max_path_bytes {
                return Err(Fault::CapacityExceeded);
            }
            let store = self.projection.clone();
            let mut preparation = store
                .inner
                .capture
                .lock()
                .map_err(|_| Fault::ClosingPending)?;
            if preparation.used
                || preparation.state.is_some()
                || store.inner.path.file_name() != Some(std::ffi::OsStr::new(ORIGINAL_LEAF))
            {
                return Err(Fault::IntentMismatch);
            }
            let parent_path = store
                .inner
                .path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or(Fault::PathUnsafe)?;
            let resources = Arc::clone(
                preparation
                    .resources
                    .as_ref()
                    .ok_or(Fault::IntentMismatch)?,
            );
            let fixed = arc_backing_bytes(Layout::new::<State>())?
                .checked_add(std::mem::size_of::<RetainedPreferenceCapture>() as u64)
                .and_then(|n| {
                    n.checked_add(std::mem::size_of::<PreferenceCaptureSnapshot>() as u64)
                })
                .ok_or(Fault::BoundsOverflow)?;
            // Original trusted-root helper opens slash once then each normal component.
            // Count all actual FD admissions conservatively, including its transient walk.
            let startup_fds = parent_path
                .components()
                .try_fold(1u64, |count, component| match component {
                    std::path::Component::RootDir => Ok(count),
                    std::path::Component::Normal(_) => {
                        count.checked_add(1).ok_or(Fault::BoundsOverflow)
                    }
                    _ => Err(Fault::PathUnsafe),
                })?;
            let path_temporary = parent_path.as_os_str().len() as u64;
            let prepare_metadata = fixed
                .checked_add(path_temporary)
                .and_then(|n| n.checked_add(3 * std::mem::size_of::<String>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<fs::Metadata>() as u64))
                .ok_or(Fault::BoundsOverflow)?;
            let metadata_reserved = store_backing_bytes(&store)?
                .checked_add(prepare_metadata)
                .ok_or(Fault::BoundsOverflow)?;
            if metadata_reserved > bounds.max_metadata_bytes {
                return Err(Fault::CapacityExceeded);
            }
            let operation_fds = bounds
                .max_open_files
                .checked_sub(startup_fds)
                .and_then(|n| n.checked_sub(3))
                .ok_or(Fault::CapacityExceeded)?
                / 2;
            let limit = usize::try_from(operation_fds).map_err(|_| Fault::CapacityExceeded)?;
            if limit == 0 {
                return Err(Fault::CapacityExceeded);
            }
            // Never allocate every local ceiling/remaining byte for the first component.
            // Whole-operation book admission precedes root open and fixed Arc allocation.
            reserve_capture_resources(&resources, startup_fds, prepare_metadata)?;
            let operations = Vec::new();
            // Original startup validation only; no new caller root or create-directory path.
            let parent = openbot_infra::artifact_store::open_trusted_host_root(parent_path)
                .map_err(|_| Fault::PathUnsafe)?;
            let parent_identity =
                DirectoryIdentity::of(&parent.metadata().map_err(|_| Fault::IoFailure)?)?;
            let state = Arc::new(State {
                parent,
                parent_identity,
                bounds,
                resources,
                limit,
                gate: Mutex::new(Gate {
                    closed: false,
                    root: None,
                    operations,
                    tasks: JoinSet::new(),
                    active: 0,
                    fault: None,
                    unmatched: None,
                    fd_admissions: startup_fds,
                    metadata_reserved,
                }),
                changed: Notify::new(),
            });
            preparation.state = Some(Arc::clone(&state));
            drop(preparation);
            let owner = RetainedPreferenceCapture {
                store,
                state,
                clock: None,
                destination_fd: None,
                work: None,
                worker: None,
                worker_spawn_entered: false,
                joined: None,
                consumed: false,
            };
            Ok((self, owner))
        }
    }

    impl RetainedPreferenceCapture {
        pub(crate) fn original_store(&self) -> &DesktopUiPreferenceStore {
            &self.store
        }

        // Registered pre-t0 equality seam. This never opens, duplicates or exports a root.
        pub(crate) fn verify_original_installation_root(
            &mut self,
            original_root: &File,
        ) -> Result<(), Fault> {
            if self.clock.is_some() {
                return Err(Fault::IntentMismatch);
            }
            let mut gate = self.state.gate.lock().map_err(|_| Fault::ClosingPending)?;
            if gate.closed || !gate.operations.is_empty() {
                return Err(Fault::IntentMismatch);
            }
            let actual =
                DirectoryIdentity::of(&original_root.metadata().map_err(|_| Fault::IoFailure)?)?;
            let held = DirectoryIdentity::of(
                &self.state.parent.metadata().map_err(|_| Fault::IoFailure)?,
            )?;
            let again =
                DirectoryIdentity::of(&original_root.metadata().map_err(|_| Fault::IoFailure)?)?;
            if actual != again
                || actual != held
                || held != self.state.parent_identity
                || gate.root.is_some_and(|old| old != actual)
            {
                return Err(Fault::SourceChanged);
            }
            gate.root = Some(actual);
            Ok(())
        }

        // Registered pure DATA seam. These cumulative known charges are not a claim that
        // this local bound is the whole-operation/global remaining budget.
        pub(crate) fn retained_resource_usage(&self) -> Result<(u64, u64), Fault> {
            if self.worker_spawn_entered && self.worker.is_none() && self.joined.is_none() {
                return Err(Fault::ClosingPending);
            }
            if matches!(self.joined.as_ref(), Some(Err(_) | Ok(Err(_)))) {
                return Err(Fault::ClosingPending);
            }
            let gate = self
                .state
                .gate
                .try_lock()
                .map_err(|_| Fault::ClosingPending)?;
            if let Some(fault) = gate.fault {
                return Err(fault);
            }
            if gate.unmatched.is_some()
                || gate
                    .operations
                    .iter()
                    .any(|op| op.phase == OperationPhase::Unknown)
            {
                return Err(Fault::ClosingPending);
            }
            Ok((gate.fd_admissions, gate.metadata_reserved))
        }

        pub(crate) async fn close_and_snapshot(
            &mut self,
            destination: &File,
            clock: Arc<dyn CaptureClockCheck>,
        ) -> Result<PreferenceCaptureSnapshot, Fault> {
            if let Some(original) = self.clock.as_ref() {
                if !Arc::ptr_eq(original, &clock)
                    || self.destination_fd != Some(destination.as_raw_fd())
                {
                    return Err(Fault::IntentMismatch);
                }
            } else {
                self.destination_fd = Some(destination.as_raw_fd());
                self.clock = Some(Arc::clone(&clock));
            }
            clock.require_effect()?;
            if self.consumed {
                return Err(Fault::IntentMismatch);
            }
            parent_before(&self.state, Some(clock.as_ref()))?;
            {
                let mut gate = self.state.gate.lock().map_err(|_| Fault::ClosingPending)?;
                gate.closed = true;
            }
            self.state.changed.notify_waiters();
            let destination_identity =
                DirectoryIdentity::of(&observe(Some(clock.as_ref()), || destination.metadata())?)?;
            if destination_identity.device != self.state.parent_identity.device
                || destination_identity == self.state.parent_identity
            {
                return Err(Fault::PathUnsafe);
            }
            if self.work.is_none() {
                clock.require_effect()?;
                {
                    let mut gate = self.state.gate.lock().map_err(|_| Fault::ClosingPending)?;
                    reserve_known(&self.state, &mut gate, 3, snapshot_known_bytes()?)?;
                }
                self.work = Some(Arc::new(Mutex::new(SnapshotWork {
                    state: Arc::clone(&self.state),
                    store: self.store.clone(),
                    clock: Arc::clone(&clock),
                    destination: None,
                    destination_identity: Some(destination_identity),
                    duplicate_attempted: false,
                    source: None,
                    output: None,
                })));
                clock.require_effect()?;
            }
            {
                let work = self.work.as_ref().ok_or(Fault::ClosingPending)?;
                let mut work = work.try_lock().map_err(|_| Fault::ClosingPending)?;
                if work.destination_identity != Some(destination_identity) {
                    return Err(Fault::SourceChanged);
                }
                if work.destination.is_none() {
                    if work.duplicate_attempted {
                        return Err(Fault::IoFailure);
                    }
                    work.duplicate_attempted = true;
                    clock.require_effect()?;
                    let observed = destination.try_clone();
                    let error = match observed {
                        Ok(file) => {
                            work.destination = Some(file);
                            None
                        }
                        Err(_) => Some(Fault::IoFailure),
                    };
                    let after = clock.require_effect();
                    after?;
                    if let Some(error) = error {
                        return Err(error);
                    }
                }
            }
            loop {
                let notified = self.state.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let result = poll_fn(|cx| {
                    if let Err(fault) = clock.require_effect() {
                        return Poll::Ready(Some(Err(fault)));
                    }
                    let mut gate = match self.state.gate.lock() {
                        Ok(gate) => gate,
                        Err(_) => return Poll::Ready(Some(Err(Fault::ClosingPending))),
                    };
                    if let Err(fault) = self.state.drain(&mut gate, cx, Some(clock.as_ref())) {
                        return Poll::Ready(Some(Err(fault)));
                    }
                    if let Some(fault) = gate.fault {
                        return Poll::Ready(Some(Err(fault)));
                    }
                    if gate
                        .operations
                        .iter()
                        .any(|op| op.phase == OperationPhase::Unknown)
                    {
                        return Poll::Ready(Some(Err(Fault::ClosingPending)));
                    }
                    if gate.active == 0 && gate.tasks.is_empty() {
                        return Poll::Ready(Some(Ok(())));
                    }
                    drop(gate);
                    match notified.as_mut().poll(cx) {
                        Poll::Ready(()) => Poll::Ready(None),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await;
                match result {
                    Some(result) => {
                        result?;
                        break;
                    }
                    None => {}
                }
            }
            clock.require_effect()?;
            if self.worker.is_none() && self.joined.is_none() {
                if self.worker_spawn_entered {
                    return Err(Fault::ClosingPending);
                }
                self.worker_spawn_entered = true;
                let work = Arc::clone(self.work.as_ref().ok_or(Fault::ClosingPending)?);
                // Work and every File slot are already resident in self before the first await.
                self.worker = Some(tokio::task::spawn_blocking(move || {
                    snapshot_original(&work)
                }));
            }
            if self.joined.is_none() {
                let result = self.worker.as_mut().ok_or(Fault::ClosingPending)?.await;
                self.joined = Some(result);
            }
            clock.require_effect()?;
            let observation = match self.joined.as_ref().ok_or(Fault::ClosingPending)? {
                Ok(Ok(observation)) => *observation,
                Ok(Err(fault)) => return Err(*fault),
                Err(_) => return Err(Fault::ClosingPending),
            };
            let material = match observation {
                SnapshotObservation::Absent => None,
                SnapshotObservation::Present { len, sha256 } => {
                    let mut work = self
                        .work
                        .as_ref()
                        .ok_or(Fault::ClosingPending)?
                        .try_lock()
                        .map_err(|_| Fault::ClosingPending)?;
                    Some((
                        work.output.take().ok_or(Fault::MaterialMissing)?,
                        len,
                        sha256,
                    ))
                }
            };
            self.consumed = true;
            Ok(PreferenceCaptureSnapshot { material })
        }
    }

    fn snapshot_original(
        resident: &Arc<Mutex<SnapshotWork>>,
    ) -> Result<SnapshotObservation, Fault> {
        let mut work = resident.lock().map_err(|_| Fault::ClosingPending)?;
        let state = Arc::clone(&work.state);
        let store = work.store.clone();
        let clock = Arc::clone(&work.clock);
        let _mutation = store
            .inner
            .mutation
            .lock()
            .map_err(|_| Fault::ClosingPending)?;
        {
            let gate = state.gate.lock().map_err(|_| Fault::ClosingPending)?;
            if !gate.closed
                || gate.active != 0
                || !gate.tasks.is_empty()
                || gate.fault.is_some()
                || gate.unmatched.is_some()
                || gate
                    .operations
                    .iter()
                    .any(|op| op.phase != OperationPhase::Finished)
            {
                return Err(Fault::ClosingPending);
            }
        }
        clock.require_effect()?;
        let before = read_source(&state, &mut work.source, Some(clock.as_ref()))?;
        decode(&before).map_err(|_| Fault::NonCanonical)?;
        if before.identity.is_none() {
            return Ok(SnapshotObservation::Absent);
        }
        let len = before.len as u64;
        if len > state.bounds.max_single_plain_bytes
            || len > state.bounds.max_snapshot_bytes
            || len > state.bounds.max_spool_bytes
            || len > state.bounds.max_material_plain_bytes
        {
            return Err(Fault::CapacityExceeded);
        }
        let destination = work.destination.as_ref().ok_or(Fault::MaterialMissing)?;
        let actual =
            DirectoryIdentity::of(&observe(Some(clock.as_ref()), || destination.metadata())?)?;
        if Some(actual) != work.destination_identity
            || actual.device != state.parent_identity.device
            || actual == state.parent_identity
        {
            return Err(Fault::PathUnsafe);
        }
        // Destination dup, original source and output each consume their prepaid one-shot slot.
        clock.require_effect()?;
        let observed = rustix::fs::openat(
            destination,
            SNAPSHOT_LEAF,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        );
        let error = match observed {
            Ok(file) => {
                work.output = Some(File::from(file));
                None
            }
            Err(_) => Some(Fault::IoFailure),
        };
        let after = clock.require_effect();
        after?;
        if let Some(error) = error {
            return Err(error);
        }
        let output = work.output.as_ref().ok_or(Fault::MaterialMissing)?;
        let mut offset = 0;
        while offset < before.len {
            let count = observe(Some(clock.as_ref()), || {
                output.write_at(&before.bytes[offset..before.len], offset as u64)
            })?;
            if count == 0 {
                return Err(Fault::IoFailure);
            }
            offset = offset.checked_add(count).ok_or(Fault::BoundsOverflow)?;
        }
        observe(Some(clock.as_ref()), || output.sync_all())?;
        let observed = read_held(output, Some(clock.as_ref()))?;
        if observed.len != before.len || observed.sha256 != before.sha256 {
            return Err(Fault::SourceChanged);
        }
        let named_output = named(
            work.destination.as_ref().ok_or(Fault::MaterialMissing)?,
            SNAPSHOT_LEAF,
            Some(clock.as_ref()),
        )?
        .ok_or(Fault::SourceChanged)?;
        if !observed
            .identity
            .ok_or(Fault::SourceChanged)?
            .named_matches(&named_output)
        {
            return Err(Fault::SourceChanged);
        }
        observe(Some(clock.as_ref()), || {
            work.destination
                .as_ref()
                .ok_or_else(|| io::Error::other("destination absent"))?
                .sync_all()
        })?;
        let source_after = read_source(&state, &mut work.source, Some(clock.as_ref()))?;
        if source_after.identity != before.identity
            || source_after.len != before.len
            || source_after.sha256 != before.sha256
        {
            return Err(Fault::SourceChanged);
        }
        let destination_after = DirectoryIdentity::of(&observe(Some(clock.as_ref()), || {
            work.destination
                .as_ref()
                .ok_or_else(|| io::Error::other("destination absent"))?
                .metadata()
        })?)?;
        if Some(destination_after) != work.destination_identity {
            return Err(Fault::SourceChanged);
        }
        let final_output = read_held(
            work.output.as_ref().ok_or(Fault::MaterialMissing)?,
            Some(clock.as_ref()),
        )?;
        let final_name = named(
            work.destination.as_ref().ok_or(Fault::MaterialMissing)?,
            SNAPSHOT_LEAF,
            Some(clock.as_ref()),
        )?
        .ok_or(Fault::SourceChanged)?;
        if final_output.len != before.len
            || final_output.sha256 != before.sha256
            || !final_output
                .identity
                .ok_or(Fault::SourceChanged)?
                .named_matches(&final_name)
        {
            return Err(Fault::SourceChanged);
        }
        clock.require_effect()?;
        Ok(SnapshotObservation::Present {
            len,
            sha256: before.sha256.ok_or(Fault::MaterialMissing)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("local"),
            TenantId::new("local"),
            ActorId::new("local"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    #[test]
    fn parser_is_closed_and_round_trips_independent_fields() {
        let preferences = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            ..UiPreferences::default()
        };
        assert_eq!(parse(&render(preferences)).unwrap(), preferences);
        assert!(parse("openbot-ui-preferences-v1\ntheme=sepia\nlocale=en\n").is_err());
        assert!(parse("openbot-ui-preferences-v1\ntheme=dark\nlocale=en\nextra=x\n").is_err());
    }

    struct GrowingInput {
        initial: Vec<u8>,
        supplied: usize,
        available: usize,
    }

    impl io::Read for GrowingInput {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let remaining = self.available - self.supplied;
            let count = if self.supplied < self.initial.len() {
                output.len().min(self.initial.len() - self.supplied)
            } else {
                output.len().min(remaining)
            };
            for (index, byte) in output[..count].iter_mut().enumerate() {
                *byte = self
                    .initial
                    .get(self.supplied + index)
                    .copied()
                    .unwrap_or(b'x');
            }
            self.supplied += count;
            Ok(count)
        }
    }

    #[test]
    fn read_budget_stops_a_growing_source_after_one_excess_byte() {
        let initial = render(UiPreferences::default()).into_bytes();
        assert!(initial.len() < FILE_MAX_BYTES as usize);
        let mut growing = GrowingInput {
            initial,
            supplied: 0,
            available: 1024 * 1024,
        };
        assert_eq!(
            read_preferences(&mut growing),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(growing.supplied, FILE_MAX_BYTES as usize + 1);
        assert!(growing.available > growing.supplied);
    }

    #[test]
    fn read_boundary_checks_length_before_decoding_and_preserves_parser_errors() {
        assert_eq!(
            read_preferences(&b"x".repeat(256)[..]),
            Err(UiPreferenceAdministrationError::Corrupt { field: "version" })
        );
        assert_eq!(
            read_preferences(&b"x".repeat(257)[..]),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(
            read_preferences(&[0xff][..]),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        for (input, field) in [
            ("bad-version\ntheme=dark\nlocale=en\n", "version"),
            (
                "openbot-ui-preferences-v1\ntheme=sepia\nlocale=en\n",
                "theme",
            ),
            (
                "openbot-ui-preferences-v1\ntheme=dark\nlocale=bad\n",
                "locale",
            ),
            (
                "openbot-ui-preferences-v1\ntheme=dark\nlocale=en\nextra=x\n",
                "file",
            ),
        ] {
            assert_eq!(
                read_preferences(input.as_bytes()),
                Err(UiPreferenceAdministrationError::Corrupt { field })
            );
        }
        let preferences = UiPreferences {
            theme: Some(UiTheme::System),
            locale: Some(UiLocale::En),
            ..UiPreferences::default()
        };
        assert_eq!(
            read_preferences(render(preferences).as_bytes()),
            Ok(preferences)
        );
    }

    #[test]
    fn read_failure_keeps_the_file_corruption_class() {
        struct BrokenInput;
        impl io::Read for BrokenInput {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("owned test input failure"))
            }
        }
        assert_eq!(
            read_preferences(BrokenInput),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_reads_keep_missing_directory_and_link_semantics() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "openbot-desktop-ui-preferences-reading-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        assert_eq!(read_file(&path), Ok(UiPreferences::default()));
        assert_eq!(
            read_file(&root),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        let preferences = UiPreferences {
            theme: Some(UiTheme::Light),
            locale: Some(UiLocale::ZhCn),
            ..UiPreferences::default()
        };
        fs::write(&path, render(preferences)).unwrap();
        assert_eq!(read_file(&path), Ok(preferences));
        symlink("ui-preferences-v1", root.join("soft-link")).unwrap();
        fs::hard_link(&path, root.join("hard-link")).unwrap();
        assert_eq!(read_file(&root.join("soft-link")), Ok(preferences));
        assert_eq!(read_file(&root.join("hard-link")), Ok(preferences));
        fs::write(&path, [0xff]).unwrap();
        assert_eq!(
            read_file(&path),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        fs::write(&path, b"x".repeat(257)).unwrap();
        assert_eq!(
            read_file(&path),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejected_projection_preserves_original_bytes_and_no_temporary_output() {
        let root = std::env::temp_dir().join(format!(
            "openbot-ui-projection-rejected-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        let original = b"x".repeat(257);
        fs::write(&path, &original).unwrap();
        let store = DesktopUiPreferenceStore::new(&path);
        assert_eq!(
            store.read(),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(
            store.project_sync(committed(1)),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    fn committed(revision: i64) -> UiPreferences {
        UiPreferences {
            theme: Some(UiTheme::Light),
            locale: Some(UiLocale::ZhCn),
            revision: Some(revision),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[test]
    fn projection_replaces_without_revision_or_temporary_files() {
        let root = std::env::temp_dir().join(format!(
            "openbot-ui-projection-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        let store = DesktopUiPreferenceStore::new(&path);
        assert_eq!(store.read().unwrap(), UiPreferences::default());
        store.project_sync(committed(1)).unwrap();
        store.project_sync(committed(2)).unwrap();
        let cache = store.read().unwrap();
        assert_eq!(cache.theme, Some(UiTheme::Light));
        assert_eq!(cache.locale, Some(UiLocale::ZhCn));
        assert_eq!(cache.revision, None);
        assert_eq!(cache.updated_at, None);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    struct Authority {
        result: Mutex<Result<UiPreferences, UiPreferenceAdministrationError>>,
        updates: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl UiPreferenceAdministration for Authority {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            *self.result.lock().unwrap()
        }
        async fn update(
            &self,
            _auth: &AuthContext,
            _update: UpdateUiPreferences,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            self.updates.fetch_add(1, Ordering::Relaxed);
            *self.result.lock().unwrap()
        }
    }

    #[tokio::test]
    async fn pg_reply_is_authoritative_and_cache_failure_never_replays() {
        let root = std::env::temp_dir().join(format!(
            "openbot-ui-authority-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        let prior = render(UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            ..Default::default()
        });
        fs::write(&path, &prior).unwrap();
        let authority = Arc::new(Authority {
            result: Mutex::new(Ok(UiPreferences::default())),
            updates: std::sync::atomic::AtomicUsize::new(0),
        });
        let store = DesktopUiPreferenceAdministration::new(authority.clone(), &path);
        assert_eq!(store.get(&auth()).await.unwrap(), UiPreferences::default());
        assert_eq!(fs::read_to_string(&path).unwrap(), prior);
        *authority.result.lock().unwrap() = Err(UiPreferenceAdministrationError::StaleSnapshot(
            committed(2).revision_snapshot().unwrap(),
        ));
        let update = UpdateUiPreferences {
            theme: Some(UiTheme::Light),
            locale: None,
            expected_revision: Some(1),
        };
        assert!(matches!(
            store.update(&auth(), update).await,
            Err(UiPreferenceAdministrationError::StaleSnapshot(_))
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), prior);
        let corrupt = b"x".repeat(257);
        fs::write(&path, &corrupt).unwrap();
        *authority.result.lock().unwrap() = Ok(committed(3));
        assert_eq!(store.update(&auth(), update).await.unwrap(), committed(3));
        assert_eq!(fs::read(&path).unwrap(), corrupt);
        assert_eq!(authority.updates.load(Ordering::Relaxed), 2);
        fs::remove_file(&path).unwrap();
        assert_eq!(store.get(&auth()).await.unwrap(), committed(3));
        assert_eq!(read_file(&path).unwrap().revision, None);
        assert_eq!(read_file(&path).unwrap().theme, Some(UiTheme::Light));
        assert_eq!(authority.updates.load(Ordering::Relaxed), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
