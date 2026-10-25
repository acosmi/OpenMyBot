//! Original process, pipe and SQL-driver owners for the new, isolated maintenance fixture.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(test)]
use std::io::{Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;

use openbot_domain::vault::SecretBytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_postgres::tls::NoTlsStream;
use tokio_postgres::{Client, Connection, NoTls, Row, Socket};
use zeroize::{Zeroize, Zeroizing};

use super::MaintenanceError;
use super::bundle::{self, Program, VerifiedMaintenanceBundle};
use super::clock::{self, OperationClock};
use super::limits::{self, CapacityObservation, MaintenanceProfile, MaterialCounters};
use super::protocol::{self, StatusRecord, StatusTrail};

#[cfg(feature = "postgres-supervisor")]
#[path = "restore_isolation.rs"]
mod restore_isolation;

#[cfg(feature = "postgres-supervisor")]
use restore_isolation::{IsolationFailure, RestoreIsolationPolicy};

// No child exists on these failures. Legacy maintenance callers retain their
// original closed mapping; the restore owner additionally keeps native spawn IO.
struct NativeSpawnFailure {
    fault: MaintenanceError,
    original_io: Option<std::io::Error>,
}
impl From<MaintenanceError> for NativeSpawnFailure {
    fn from(fault: MaintenanceError) -> Self { Self { fault, original_io: None } }
}
impl From<std::io::Error> for NativeSpawnFailure {
    fn from(error: std::io::Error) -> Self {
        Self { fault: MaintenanceError::IoFailure, original_io: Some(error) }
    }
}
#[cfg(feature = "postgres-supervisor")]
enum RestoreProgramFailure {
    Isolation(IsolationFailure),
    Bundle(MaintenanceError),
    OriginalSpawn(NativeSpawnFailure),
    Identity(wrok_bot_macos_process::ProcessObservationError),
    ClosingGate(MaintenanceError),
    OriginalStopUnknown,
}

#[cfg(feature = "postgres-supervisor")]
enum RestoreStopState {
    Entered,
    Returned(Result<(), std::io::Error>),
}
#[cfg(feature = "postgres-supervisor")]
struct RestoreProgramOwner {
    original: ProgramOwner,
    identity: Result<wrok_bot_macos_process::ProcessIdentity, wrok_bot_macos_process::ProcessObservationError>,
    generation: [u64; 3],
    stop: Option<RestoreStopState>,
    post_directories: Result<(), IsolationFailure>,
    post_software: Result<(), MaintenanceError>,
}

// The full restore session/candidate/config producer is a separately registered
// dependency. This adapter mints no authority and never starts a replacement clock.
#[cfg(feature = "postgres-supervisor")]
fn spawn_restore_program(
    policy: &RestoreIsolationPolicy<'_>,
    bundle: &VerifiedMaintenanceBundle,
    authenticated_config_args: &[OsString],
    clock: &OperationClock,
    secret: Arc<SecretBytes>,
    limits: (u64, u64, bool),
) -> Result<RestoreProgramOwner, RestoreProgramFailure> {
    let generation = policy.generation_identity().map_err(RestoreProgramFailure::Isolation)?;
    let command = policy.checked_postgres_command(bundle, authenticated_config_args)?;
    policy.revalidate().map_err(RestoreProgramFailure::Isolation)?;
    // This real sandbox-exec Command enters the original spawn body; no second
    // Child/pipe abstraction, optional sandbox or unisolated fallback is used.
    let original = spawn_program_retaining_io(command, "restore_postgres", clock, secret, false, limits, false)
        .map_err(RestoreProgramFailure::OriginalSpawn)?;
    // No fallible return drops a spawned Child. Capture failure remains resident
    // with that owner and cannot authorize another native request.
    let identity = wrok_bot_macos_process::ProcessIdentity::capture(original.pid);
    let post_software = bundle.checked_command(Program::Postgres).map(|_| ());
    let post_directories = policy.revalidate();
    // Post-check failure stays WITH the original Child and raw identity outcome.
    // The only remaining operations are original-resource stop/wait; no grant is
    // returned and no failure path silently drops or restarts this process.
    Ok(RestoreProgramOwner { original, identity, generation, stop: None,
        post_directories, post_software })
}

#[cfg(feature = "postgres-supervisor")]
fn request_restore_stop(
    owner: &mut RestoreProgramOwner,
    clock: &OperationClock,
) -> Result<(), RestoreProgramFailure> {
    if owner.stop.is_some() { return Err(RestoreProgramFailure::OriginalStopUnknown); }
    // This is the still-resident, unreaped original Child, not a saved PID or
    // reconstructed journal observer. No new pg_ctl process is created.
    if owner.original.role != "restore_postgres"
        || owner.original.child.id() != Some(owner.original.pid) {
        return Err(RestoreProgramFailure::Identity(
            wrok_bot_macos_process::ProcessObservationError::ObservationChanged));
    }
    owner.identity.as_ref().map_err(|error| RestoreProgramFailure::Identity(*error))?
        .revalidate().map_err(RestoreProgramFailure::Identity)?;
    let pid = i32::try_from(owner.original.pid).ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or(RestoreProgramFailure::Identity(
            wrok_bot_macos_process::ProcessObservationError::InvalidPid))?;
    clock.permit_closing_request().map_err(RestoreProgramFailure::ClosingGate)?;
    owner.stop = Some(RestoreStopState::Entered);
    let result = rustix::process::kill_process(pid, rustix::process::Signal::TERM)
        .map_err(std::io::Error::from);
    let requested = result.is_ok();
    owner.stop = Some(RestoreStopState::Returned(result));
    // A successful signal request is not child exit, pipe join or a close receipt.
    // An error/unknown retains the original result and never retries this request.
    if requested { Ok(()) } else { Err(RestoreProgramFailure::OriginalStopUnknown) }
}

#[cfg(feature = "postgres-supervisor")]
struct RestoreProgramResult {
    tool: Result<ToolResult, MaintenanceError>,
    identity: Result<wrok_bot_macos_process::ProcessIdentity, wrok_bot_macos_process::ProcessObservationError>,
    generation: [u64; 3],
    stop: Option<RestoreStopState>,
    post_directories: Result<(), IsolationFailure>,
    post_software: Result<(), MaintenanceError>,
}
#[cfg(feature = "postgres-supervisor")]
async fn wait_restore_program(
    owner: RestoreProgramOwner,
    capacity: &mut CapacityMonitor<'_>,
    closing: bool,
) -> RestoreProgramResult {
    // Capturing a birth or requesting TERM never substitutes for this original
    // wait and all original pipe joins. Both raw stop and identity outcomes stay.
    let RestoreProgramOwner { original, identity, generation, stop,
        post_directories, post_software } = owner;
    // Only request_restore_stop may issue this restore owner's one TERM. The
    // original wait's optional deadline TERM is disabled, so Unknown cannot send
    // another native request. It still waits the same Child and joins all pipes.
    RestoreProgramResult { tool: wait_program(original, capacity, closing, false).await,
        identity, generation, stop, post_directories, post_software }
}

const ROLE: &str = "wrokbot_maintenance_fixture";
const PORT: u16 = 5432;

#[derive(Serialize)]
pub(crate) struct ToolchainReceipt {
    schema: &'static str,
    schema_version: u32,
    operation: String,
    profile_sha256: String,
    bundle: bundle::BundleVerificationReceipt,
    clock: ClockReceipt,
    tools: Vec<ToolObservation>,
    sql_drivers: Vec<SqlDriverObservation>,
    connection_attempts: u64,
    connection_attempts_joined: u64,
    native: NativeReceipt,
    source_identity: SourceIdentity,
    material: MaterialInventory,
    capacity: Vec<CapacityObservation>,
    restore_readback: bool,
    restore_restart_readback: bool,
    source_authenticated: bool,
    native_usable: bool,
    platform_signature_verified: bool,
    production_release_authorized: bool,
    backup_capture_completed: bool,
    restore_current: bool,
    b: bool,
    c: bool,
    ready: bool,
    secret_scope: &'static str,
    fd_scope: &'static str,
    known_rust_fd_peak_bound: u64,
}
#[derive(Serialize)]
struct ClockReceipt {
    t0_ns: u64,
    effect_deadline_ns: u64,
    convergence_deadline_ns: u64,
    finished_ns: u64,
}
#[derive(Serialize)]
struct SourceIdentity {
    system_id: u64,
    timeline: u32,
    wal_segment_bytes: u32,
    sentinel_rows: i64,
    rollback_rows: i64,
    data_checksums: bool,
}
#[derive(Clone, Serialize)]
struct DrainReport {
    bytes: u64,
    sha256: String,
    limit_exceeded: bool,
    secret_found: bool,
}
struct DrainResult {
    report: DrainReport,
    preview: Vec<u8>,
}
#[derive(Serialize)]
struct ToolObservation {
    role: &'static str,
    pid: u32,
    started_ns: u64,
    wait_observed_ns: Option<u64>,
    pipe_joins_observed_ns: Option<u64>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    original_child_wait: bool,
    stdin_writer_joined: Option<bool>,
    stdout_reader_joined: bool,
    stderr_reader_joined: bool,
    original_wait_errors: u64,
    deadline_expired: bool,
    secret_absent_from_argv_env: bool,
    stdout: Option<DrainReport>,
    stderr: Option<DrainReport>,
}
struct ToolResult {
    observation: ToolObservation,
    preview: Vec<u8>,
    error: Option<MaintenanceError>,
}

struct ProgramOwner {
    role: &'static str,
    child: Child,
    pid: u32,
    started: u64,
    setup_error: bool,
    args_env_clean: bool,
    input: Option<JoinHandle<Result<(), MaintenanceError>>>,
    output: Option<JoinHandle<Result<DrainResult, MaintenanceError>>>,
    error: Option<JoinHandle<Result<DrainResult, MaintenanceError>>>,
}
#[derive(Serialize)]
struct SqlDriverObservation {
    postmaster: usize,
    original_driver_joined: bool,
    driver_result_ok: Option<bool>,
    query_tasks_started: u64,
    query_tasks_joined: u64,
    query_results_ok: u64,
}
struct OwnedRoot {
    path: PathBuf,
    _directory: File,
    _parent: File,
}
struct CapacityMonitor<'a> {
    root: &'a OwnedRoot,
    profile: &'a MaintenanceProfile,
    clock: &'a OperationClock,
    rows: &'a mut Vec<CapacityObservation>,
    encoded_bytes: &'a mut u64,
}
impl CapacityMonitor<'_> {
    fn observe(&mut self, next_restore_write: u64) -> Result<(), MaintenanceError> {
        self.clock.permit_closing_request()?;
        let held = self.root._directory.metadata()?;
        let named = fs::symlink_metadata(&self.root.path)?;
        if !named.is_dir()
            || (held.dev(), held.ino(), held.uid(), held.mode())
                != (named.dev(), named.ino(), named.uid(), named.mode())
        {
            return Err(MaintenanceError::CapacityExceeded);
        }
        let p = self.profile.fields();
        let nodes = p
            .max_material_files
            .checked_add(p.max_directories)
            .and_then(|n| n.checked_add(8))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let allocated = |path: &Path| -> Result<u64, MaintenanceError> {
            match fs::symlink_metadata(path) {
                Ok(_) => allocated_tree(path, nodes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
                Err(_) => Err(MaintenanceError::IoFailure),
            }
        };
        let source = allocated(&self.root.path.join("source"))?;
        let spool = allocated(&self.root.path.join("spool"))?;
        let restore = allocated(&self.root.path.join("restore-check"))?;
        if restore
            .checked_add(next_restore_write)
            .is_none_or(|n| n > p.max_restore_check_bytes)
        {
            return Err(MaintenanceError::CapacityExceeded);
        }
        let retained = allocated_tree(
            &self.root.path,
            nodes
                .checked_mul(3)
                .ok_or(MaintenanceError::CapacityExceeded)?,
        )?;
        let v =
            rustix::fs::fstatvfs(&self.root._directory).map_err(|_| MaintenanceError::IoFailure)?;
        let free = v
            .f_bavail
            .checked_mul(v.f_frsize)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let row = CapacityObservation {
            free_bytes: free,
            retained_allocated_bytes: retained,
            remaining_source_bytes: p
                .max_material_plain_bytes
                .checked_add(p.max_wal_bytes)
                .and_then(|n| n.checked_sub(source))
                .ok_or(MaintenanceError::CapacityExceeded)?,
            remaining_spool_bytes: p
                .max_spool_bytes
                .checked_sub(spool)
                .ok_or(MaintenanceError::CapacityExceeded)?,
            remaining_restore_bytes: p
                .max_restore_check_bytes
                .checked_sub(restore)
                .ok_or(MaintenanceError::CapacityExceeded)?,
            // The full future on-disk receipt remains reserved; in-memory rows are not disk use.
            remaining_journal_bytes: p.max_journal_bytes,
            reserve_bytes: p.capacity_reserve_bytes,
            free_floor_bytes: p.free_floor_bytes,
        };
        let row_bytes = serde_json::to_vec(&row).map_err(|_| MaintenanceError::IoFailure)?;
        let next_bytes = self
            .encoded_bytes
            .checked_add(row_bytes.len() as u64)
            .and_then(|n| n.checked_add(u64::from(!self.rows.is_empty())))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let memory = (self.rows.len() as u64)
            .checked_add(1)
            .and_then(|n| n.checked_mul(std::mem::size_of::<CapacityObservation>() as u64))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if next_bytes > p.max_journal_bytes || memory > p.max_journal_bytes {
            return Err(MaintenanceError::CapacityExceeded);
        }
        self.clock.permit_closing_request()?;
        let result = row.validate();
        self.rows
            .try_reserve_exact(1)
            .map_err(|_| MaintenanceError::CapacityExceeded)?;
        self.rows.push(row);
        *self.encoded_bytes = next_bytes;
        result
    }
}
type Connecting =
    JoinHandle<Result<(Client, Connection<Socket, NoTlsStream>), tokio_postgres::Error>>;
type Querying = JoinHandle<(Client, Result<Vec<Row>, tokio_postgres::Error>)>;
struct SqlOwner {
    client: Option<Client>,
    driver: JoinHandle<Result<(), tokio_postgres::Error>>,
    query: Option<Querying>,
    postmaster: usize,
    driver_joined: bool,
    driver_result_ok: Option<bool>,
    queries_started: u64,
    queries_joined: u64,
    queries_ok: u64,
}
struct PostmasterOwner {
    process: Option<ProgramOwner>,
    data: PathBuf,
    stopped: bool,
    stop_attempted: bool,
}
pub(crate) struct OwnedFixtureSource {
    bundle: VerifiedMaintenanceBundle,
    profile: MaintenanceProfile,
    clock: OperationClock,
    operation: [u8; 16],
    secret: Arc<SecretBytes>,
    new_root: PathBuf,
    root: Option<OwnedRoot>,
    postmasters: Vec<PostmasterOwner>,
    sql: Vec<SqlOwner>,
    connecting: Option<Connecting>,
    connecting_postmaster: Option<usize>,
    native: Option<NativeOwner>,
    tools: Vec<ToolObservation>,
    capacity: Vec<CapacityObservation>,
    capacity_encoded_bytes: u64,
    identity: Option<SourceIdentity>,
    connection_attempts: u64,
    connection_attempts_joined: u64,
    #[cfg(test)]
    scenario: OwnedNativeTestScenario,
    #[cfg(test)]
    test_tighter_c: Option<u64>,
}
pub(crate) struct BasebackupRequest {
    output: PathBuf,
    socket: PathBuf,
    postmaster: usize,
}
pub(crate) enum BasebackupOutcome {
    Completed {
        source: OwnedFixtureSource,
        receipt: NativeReceipt,
    },
    FailedClosed {
        source: OwnedFixtureSource,
        error: MaintenanceError,
    },
    Closing {
        owner: OwnedFixtureSource,
        error: MaintenanceError,
    },
}
pub(crate) struct RetainedMaintenanceFailure {
    owner: Option<Box<OwnedFixtureSource>>,
    error: MaintenanceError,
}
#[derive(Serialize)]
pub(crate) struct NativeReceipt {
    pid: u32,
    original_child_wait: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
    wait_observed_ns: Option<u64>,
    all_pipe_joins_observed_ns: Option<u64>,
    stdin_writer_joined: bool,
    stdout_reader_joined: bool,
    stderr_reader_joined: bool,
    statuses: Vec<StatusRecord>,
    stderr: DrainReport,
    worker_created: bool,
    worker_wait_observed: bool,
    original_wait_errors: u64,
    closed_late: bool,
    secret_absent_from_argv_env: bool,
    data_complete_before_effect_deadline: bool,
    closed_before_convergence_deadline: bool,
}

struct NativeOwner {
    child: Child,
    pid: u32,
    args_env_clean: bool,
    writer: Option<JoinHandle<Result<(), MaintenanceError>>>,
    reader: Option<JoinHandle<Result<StatusTrail, MaintenanceError>>>,
    stderr: Option<JoinHandle<Result<DrainResult, MaintenanceError>>>,
    control: mpsc::Sender<Control>,
    wait: Option<ExitStatus>,
    wait_ns: Option<u64>,
    wait_errors: u64,
    pipes_closed_ns: Option<u64>,
    writer_joined: bool,
    reader_joined: bool,
    stderr_joined: bool,
    trail: Option<StatusTrail>,
    drain: Option<DrainResult>,
    join_error: Option<MaintenanceError>,
}
pub(super) enum Control {
    FinishAfterWait,
    Cancel(u64),
    #[cfg(test)]
    TestEof,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnedNativeTestScenario {
    Normal,
    CancelAfterWorker,
    EofAfterWorker,
    TightDeadlineAfterWorker,
    ConnectionBeforeStart,
    DisconnectAfterWorker,
    TamperManifest,
    TamperWal,
    Capacity,
}
impl NativeOwner {
    fn physically_closed(&self) -> bool {
        self.pid != 0
            && self.wait.is_some()
            && self.writer_joined
            && self.reader_joined
            && self.stderr_joined
            && self.trail.as_ref().is_some_and(StatusTrail::owners_closed)
    }
}

pub(super) fn validate_secret_memory_budget(
    source_max: u64,
    copies: u64,
    max_memory: u64,
) -> Result<(), MaintenanceError> {
    if !(1..=4096).contains(&source_max) || copies < 12 {
        return Err(MaintenanceError::SecretInvalid);
    }
    // Keep the original known Rust reservoirs; native buffers cannot borrow their reservation.
    let rust_secret_peak = 6_u64
        .checked_mul(8192 + 8192 + 2 * 63)
        .and_then(|n| n.checked_add(512 + 32 + 64 + 65 + 104))
        .ok_or(MaintenanceError::SecretInvalid)?;
    let copied_secret_peak = source_max
        .checked_add(1)
        .and_then(|n| n.checked_mul(copies))
        .ok_or(MaintenanceError::SecretInvalid)?;
    // Two fixed secret[4097] reservoirs across fork plus the known UTF8 normalization bound.
    // Reviewed plaintext-containing capacities only, not process RSS or all SASL state.
    let normalized_secret_peak = 2_u64
        .checked_mul(4097)
        .and_then(|static_bytes| {
            source_max
                .checked_mul(292)
                .and_then(|n| n.checked_add(static_bytes))
        })
        .and_then(|n| n.checked_add(8))
        .ok_or(MaintenanceError::SecretInvalid)?;
    let native_secret_peak = copied_secret_peak.max(normalized_secret_peak);
    if rust_secret_peak
        .checked_add(native_secret_peak)
        .is_none_or(|n| n > max_memory)
    {
        return Err(MaintenanceError::SecretInvalid);
    }
    Ok(())
}

impl OwnedFixtureSource {
    fn new(
        bundle: VerifiedMaintenanceBundle,
        new_root: PathBuf,
        profile: MaintenanceProfile,
    ) -> Result<Self, MaintenanceError> {
        let p = profile.fields();
        // One fixed 32-byte random seed and its 64-byte textual representation; there is no caller
        // password, reuse, file spool, TTY, environment credential or recovery/master key.
        if p.max_source_secret_bytes < 64 {
            return Err(MaintenanceError::SecretInvalid);
        }
        // Prepay the original Rust reservation and known native allocated capacities before any
        // random/secret allocation. Opaque SASL/allocator/OS internals and whole-memory wipe remain
        // explicitly unproven; no default, budget increase, or borrowing supplies admission.
        validate_secret_memory_budget(
            p.max_source_secret_bytes,
            p.max_native_secret_copies,
            p.max_secret_memory_bytes,
        )?;
        // max_files_per_process has an upstream minimum 25. This explicit fixture also needs its
        // own bounded original pipes/SQL socket/verification FDs; no global runtime RLIMIT claim.
        if !(32..=i32::MAX as u64).contains(&p.max_open_files) {
            return Err(MaintenanceError::ProfileInvalid);
        }
        validate_new_root_name(&new_root, bundle.root())?;
        let clock = OperationClock::start(p.effect_ns, p.convergence_ns)?;
        let mut operation = [0; 16];
        getrandom::fill(&mut operation).map_err(|_| MaintenanceError::IoFailure)?;
        let mut random = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *random).map_err(|_| MaintenanceError::IoFailure)?;
        let mut encoded = Vec::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in random.iter() {
            encoded.push(HEX[usize::from(byte >> 4)]);
            encoded.push(HEX[usize::from(byte & 15)]);
        }
        random.zeroize();
        Ok(Self {
            bundle,
            profile,
            clock,
            operation,
            secret: Arc::new(SecretBytes::new(encoded)),
            new_root,
            root: None,
            postmasters: Vec::new(),
            sql: Vec::new(),
            connecting: None,
            connecting_postmaster: None,
            native: None,
            tools: Vec::new(),
            capacity: Vec::new(),
            capacity_encoded_bytes: 2,
            identity: None,
            connection_attempts: 0,
            connection_attempts_joined: 0,
            #[cfg(test)]
            scenario: OwnedNativeTestScenario::Normal,
            #[cfg(test)]
            test_tighter_c: None,
        })
    }
    fn root_path(&self) -> Result<&Path, MaintenanceError> {
        self.root
            .as_ref()
            .map(|r| r.path.as_path())
            .ok_or(MaintenanceError::IoFailure)
    }
    fn source_socket(&self) -> Result<PathBuf, MaintenanceError> {
        Ok(self.root_path()?.join("socket"))
    }
    fn restore_socket(&self) -> Result<PathBuf, MaintenanceError> {
        Ok(self.root_path()?.join("rsock"))
    }

    fn capacity_monitor(&mut self) -> Result<CapacityMonitor<'_>, MaintenanceError> {
        Ok(CapacityMonitor {
            root: self.root.as_ref().ok_or(MaintenanceError::IoFailure)?,
            profile: &self.profile,
            clock: &self.clock,
            rows: &mut self.capacity,
            encoded_bytes: &mut self.capacity_encoded_bytes,
        })
    }
    fn capacity_check(&mut self) -> Result<(), MaintenanceError> {
        self.capacity_monitor()?.observe(0)
    }
    fn check_owned_fd_budget(&self, additional: u64) -> Result<(), MaintenanceError> {
        let pg = self.postmasters.iter().filter(|p| !p.stopped).count() as u64;
        let sql = self.sql.iter().filter(|s| !s.driver_joined).count() as u64;
        let native = u64::from(self.native.as_ref().is_some_and(|n| !n.physically_closed()));
        // Three retained directory owners, two original postmaster readers per active process,
        // one SQL socket per original driver, three native pipes, and at most four sequential
        // verifier FDs. These are source-owned handles, not every Tokio/loader/PG kernel FD.
        let known = pg
            .checked_mul(2)
            .and_then(|n| n.checked_add(sql))
            .and_then(|n| n.checked_add(native.checked_mul(3)?))
            .and_then(|n| n.checked_add(7))
            .and_then(|n| n.checked_add(additional))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if known > self.profile.fields().max_open_files {
            return Err(MaintenanceError::CapacityExceeded);
        }
        Ok(())
    }
    async fn tool(
        &mut self,
        role: &'static str,
        program: Program,
        args: Vec<OsString>,
        input: bool,
        closing: bool,
        preview: bool,
    ) -> Result<Vec<u8>, MaintenanceError> {
        if closing {
            self.clock.permit_closing_request()?;
        } else {
            self.clock.permit_effect()?;
        }
        let mut command = self.bundle.checked_command(program)?;
        command.args(args).current_dir(self.root_path()?);
        self.check_owned_fd_budget(3)?;
        if !closing {
            self.capacity_check()?;
        }
        let secret = Arc::clone(&self.secret);
        let max_status = self.profile.fields().max_status_bytes;
        let max_stderr = self.profile.fields().max_stderr_bytes;
        let mut capacity = self.capacity_monitor()?;
        let owner = spawn_program(
            command,
            role,
            capacity.clock,
            secret,
            input,
            (max_status, max_stderr, preview),
            closing,
        )?;
        let result = wait_program(owner, &mut capacity, closing, true).await;
        match result {
            Ok(result) => {
                let error = result.error;
                let preview = result.preview;
                self.tools.push(result.observation);
                if let Some(error) = error {
                    Err(error)
                } else {
                    Ok(preview)
                }
            }
            Err(error) => Err(error),
        }
    }
    async fn version_probes(&mut self) -> Result<(), MaintenanceError> {
        for (program, role, prefix) in [
            (
                Program::Postgres,
                "postgres-version",
                "postgres (PostgreSQL) 17.11",
            ),
            (
                Program::InitDb,
                "initdb-version",
                "initdb (PostgreSQL) 17.11",
            ),
            (Program::PgCtl, "pgctl-version", "pg_ctl (PostgreSQL) 17.11"),
            (
                Program::BaseBackup,
                "basebackup-version",
                "wrokbot-maintenance protocol1 PG17.11",
            ),
        ] {
            let output = self
                .tool(
                    role,
                    program,
                    vec![OsString::from("--version")],
                    false,
                    false,
                    true,
                )
                .await?;
            let text =
                std::str::from_utf8(&output).map_err(|_| MaintenanceError::SourcePinMismatch)?;
            if text.trim_end() != prefix {
                return Err(MaintenanceError::SourcePinMismatch);
            }
        }
        Ok(())
    }
    async fn initialize(&mut self) -> Result<(), MaintenanceError> {
        self.clock.permit_effect()?;
        self.root = Some(create_new_owned_root(&self.new_root, &self.clock)?);
        self.capacity_check()?;
        let socket = self.source_socket()?;
        private_directory(&socket, &self.clock)?;
        let rsock = self.restore_socket()?;
        private_directory(&rsock, &self.clock)?;
        private_directory(&self.root_path()?.join("spool"), &self.clock)?;
        self.version_probes().await?;
        let source = self.root_path()?.join("source");
        let args = vec![
            OsString::from("--pgdata"),
            source.as_os_str().to_owned(),
            OsString::from("--username"),
            OsString::from(ROLE),
            OsString::from("--auth-local=scram-sha-256"),
            OsString::from("--auth-host=reject"),
            OsString::from("--pwfile=/dev/stdin"),
            OsString::from("--locale=C"),
            OsString::from("--encoding=UTF8"),
            OsString::from("--data-checksums"),
            OsString::from("--no-instructions"),
            OsString::from("--no-clean"),
        ];
        self.tool("initdb", Program::InitDb, args, true, false, false)
            .await?;
        write_fixture_config(
            &source,
            &socket,
            self.profile.fields().max_open_files,
            &self.clock,
        )?;
        let source_index = self.start_postmaster(source, socket).await?;
        let sql = self.connect_ready(source_index).await?;
        let payload = bundle::encode_hex(&self.operation);
        let setup = format!(
            "BEGIN; CREATE TABLE wrokbot_maintenance_sentinel(id bigint PRIMARY KEY,payload text NOT NULL); \
            INSERT INTO wrokbot_maintenance_sentinel VALUES(1,'owned-{payload}'); \
            CREATE TABLE wrokbot_maintenance_rollback(id bigint PRIMARY KEY); \
            COMMIT; BEGIN; INSERT INTO wrokbot_maintenance_rollback VALUES(1); ROLLBACK;"
        );
        self.query_owned(sql, setup, true).await?;
        self.query_owned(sql, "SELECT pg_switch_wal()".to_owned(), false)
            .await?;
        let identity = self.read_identity(sql).await?;
        if identity.sentinel_rows != 1 || identity.rollback_rows != 0 || !identity.data_checksums {
            return Err(MaintenanceError::RestoreCheckFailed);
        }
        self.identity = Some(identity);
        Ok(())
    }
    async fn start_postmaster(
        &mut self,
        data: PathBuf,
        _socket: PathBuf,
    ) -> Result<usize, MaintenanceError> {
        self.clock.permit_effect()?;
        self.capacity_check()?;
        let mut command = self.bundle.checked_command(Program::Postgres)?;
        command.arg("-D").arg(&data).current_dir(self.root_path()?);
        self.check_owned_fd_budget(3)?;
        let owner = spawn_program(
            command,
            "postmaster",
            &self.clock,
            Arc::clone(&self.secret),
            false,
            (
                self.profile.fields().max_status_bytes,
                self.profile.fields().max_stderr_bytes,
                false,
            ),
            false,
        )?;
        self.postmasters.push(PostmasterOwner {
            process: Some(owner),
            data,
            stopped: false,
            stop_attempted: false,
        });
        Ok(self.postmasters.len() - 1)
    }
    async fn connect_ready(&mut self, postmaster: usize) -> Result<usize, MaintenanceError> {
        let data = self
            .postmasters
            .get(postmaster)
            .ok_or(MaintenanceError::ConnectionFailed)?
            .data
            .clone();
        let socket = if data.file_name() == Some(std::ffi::OsStr::new("source")) {
            self.source_socket()?
        } else {
            self.restore_socket()?
        };
        loop {
            self.clock.permit_effect()?;
            self.capacity_check()?;
            let mut config = tokio_postgres::Config::new();
            config
                .host_path(&socket)
                .port(PORT)
                .user(ROLE)
                .dbname("postgres")
                .password(self.secret.expose());
            self.connection_attempts = self
                .connection_attempts
                .checked_add(1)
                .ok_or(MaintenanceError::CapacityExceeded)?;
            self.connecting = Some(tokio::spawn(async move { config.connect(NoTls).await }));
            self.connecting_postmaster = Some(postmaster);
            let result = loop {
                self.clock.permit_effect()?;
                self.capacity_check()?;
                let duration = self.clock.effect_wait()?.min(Duration::from_millis(100));
                let observed = {
                    let pending = self
                        .connecting
                        .as_mut()
                        .ok_or(MaintenanceError::ConnectionFailed)?;
                    tokio::select! {value=pending=>Some(value),_=tokio::time::sleep(duration)=>None}
                };
                if let Some(result) = observed {
                    break result;
                }
            };
            self.connecting.take();
            self.connecting_postmaster = None;
            self.connection_attempts_joined = self
                .connection_attempts_joined
                .checked_add(1)
                .ok_or(MaintenanceError::CapacityExceeded)?;
            match result {
                Ok(Ok((client, connection))) => {
                    let driver = tokio::spawn(connection);
                    self.sql.push(SqlOwner {
                        client: Some(client),
                        driver,
                        query: None,
                        postmaster,
                        driver_joined: false,
                        driver_result_ok: None,
                        queries_started: 0,
                        queries_joined: 0,
                        queries_ok: 0,
                    });
                    return Ok(self.sql.len() - 1);
                }
                Ok(Err(error)) => {
                    // Only bounded startup-not-ready/refused retries, never retry a SQL effect.
                    if error
                        .as_db_error()
                        .is_some_and(|e| e.code().code() != "57P03")
                    {
                        return Err(MaintenanceError::ConnectionFailed);
                    }
                    if let Some(owner) = self
                        .postmasters
                        .get_mut(postmaster)
                        .and_then(|p| p.process.as_mut())
                        && owner.child.try_wait()?.is_some()
                    {
                        return Err(MaintenanceError::SourceWaitUnknown);
                    }
                    tokio::time::sleep(self.clock.effect_wait()?.min(Duration::from_millis(20)))
                        .await;
                }
                Err(_) => return Err(MaintenanceError::PipeJoinUnknown),
            }
        }
    }
    async fn query_owned(
        &mut self,
        index: usize,
        sql: String,
        batch: bool,
    ) -> Result<Vec<Row>, MaintenanceError> {
        self.clock.permit_effect()?;
        self.capacity_check()?;
        let connection = self
            .sql
            .get_mut(index)
            .ok_or(MaintenanceError::ConnectionFailed)?;
        let client = connection
            .client
            .take()
            .ok_or(MaintenanceError::ConnectionFailed)?;
        connection.queries_started = connection
            .queries_started
            .checked_add(1)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        connection.query = Some(tokio::spawn(async move {
            let result = if batch {
                client.batch_execute(&sql).await.map(|_| Vec::new())
            } else {
                client.query(&sql, &[]).await
            };
            (client, result)
        }));
        let result = loop {
            self.clock.permit_effect()?;
            self.capacity_check()?;
            let duration = self.clock.effect_wait()?.min(Duration::from_millis(100));
            let observed = {
                let handle = self.sql[index]
                    .query
                    .as_mut()
                    .ok_or(MaintenanceError::ConnectionFailed)?;
                tokio::select! {r=handle=>Some(r),_=tokio::time::sleep(duration)=>None}
            };
            if let Some(result) = observed {
                break result;
            }
        };
        self.sql[index].query.take();
        self.sql[index].queries_joined = self.sql[index]
            .queries_joined
            .checked_add(1)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let (client, result) = result.map_err(|_| MaintenanceError::PipeJoinUnknown)?;
        if result.is_ok() {
            self.sql[index].queries_ok = self.sql[index]
                .queries_ok
                .checked_add(1)
                .ok_or(MaintenanceError::CapacityExceeded)?;
        }
        self.sql[index].client = Some(client);
        self.clock.permit_effect()?;
        result.map_err(|_| MaintenanceError::ConnectionFailed)
    }
    async fn read_identity(&mut self, sql: usize) -> Result<SourceIdentity, MaintenanceError> {
        let rows = self
            .query_owned(
                sql,
                "SELECT system_identifier::text FROM pg_control_system()".to_owned(),
                false,
            )
            .await?;
        let system_id = rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(MaintenanceError::RestoreCheckFailed)?;
        let rows = self
            .query_owned(
                sql,
                "SELECT timeline_id FROM pg_control_checkpoint()".to_owned(),
                false,
            )
            .await?;
        let timeline = rows
            .first()
            .and_then(|r| r.try_get::<_, i32>(0).ok())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(MaintenanceError::RestoreCheckFailed)?;
        let rows = self
            .query_owned(
                sql,
                "SELECT bytes_per_wal_segment FROM pg_control_init()".to_owned(),
                false,
            )
            .await?;
        let segment = rows
            .first()
            .and_then(|r| r.try_get::<_, i32>(0).ok())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(MaintenanceError::RestoreCheckFailed)?;
        let rows = self
            .query_owned(
                sql,
                "SELECT count(*)::bigint FROM wrokbot_maintenance_sentinel".to_owned(),
                false,
            )
            .await?;
        let sentinel = rows
            .first()
            .and_then(|r| r.try_get::<_, i64>(0).ok())
            .ok_or(MaintenanceError::RestoreCheckFailed)?;
        let payload = self
            .query_owned(
                sql,
                "SELECT payload FROM wrokbot_maintenance_sentinel WHERE id=1".to_owned(),
                false,
            )
            .await?;
        if payload.first().and_then(|r| r.try_get::<_, String>(0).ok())
            != Some(format!("owned-{}", bundle::encode_hex(&self.operation)))
        {
            return Err(MaintenanceError::RestoreCheckFailed);
        }
        let rows = self
            .query_owned(
                sql,
                "SELECT count(*)::bigint FROM wrokbot_maintenance_rollback".to_owned(),
                false,
            )
            .await?;
        let rollback = rows
            .first()
            .and_then(|r| r.try_get::<_, i64>(0).ok())
            .ok_or(MaintenanceError::RestoreCheckFailed)?;
        let rows = self
            .query_owned(sql, "SHOW data_checksums".to_owned(), false)
            .await?;
        let checksums = rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .is_some_and(|s| s == "on");
        Ok(SourceIdentity {
            system_id,
            timeline,
            wal_segment_bytes: segment,
            sentinel_rows: sentinel,
            rollback_rows: rollback,
            data_checksums: checksums,
        })
    }
    async fn stop_postmaster(&mut self, index: usize) -> Result<(), MaintenanceError> {
        let mut first = None;
        let data = self
            .postmasters
            .get(index)
            .ok_or(MaintenanceError::SourceWaitUnknown)?
            .data
            .clone();
        // Drop only our fixed clients. Join idle original drivers before requesting fast shutdown,
        // so normal shutdown does not turn a clean client EOF into a fabricated success.
        {
            let mut capacity = CapacityMonitor {
                root: self.root.as_ref().ok_or(MaintenanceError::IoFailure)?,
                profile: &self.profile,
                clock: &self.clock,
                rows: &mut self.capacity,
                encoded_bytes: &mut self.capacity_encoded_bytes,
            };
            for sql in &mut self.sql {
                if sql.postmaster != index || sql.driver_joined {
                    continue;
                }
                sql.client.take();
                if sql.query.is_none() {
                    loop {
                        if let Err(error) = capacity.observe(0) {
                            first.get_or_insert(error);
                            break;
                        }
                        let Ok(duration) = self.clock.effect_wait() else {
                            break;
                        };
                        if duration.is_zero() {
                            break;
                        }
                        let observed = tokio::select! {
                            value=&mut sql.driver=>Some(value),
                            _=tokio::time::sleep(duration.min(Duration::from_millis(100)))=>None,
                        };
                        if let Some(result) = observed {
                            sql.driver_joined = true;
                            sql.driver_result_ok = Some(matches!(&result, Ok(Ok(()))));
                            if !matches!(result, Ok(Ok(()))) {
                                first.get_or_insert(MaintenanceError::ConnectionFailed);
                            }
                            break;
                        }
                    }
                }
            }
        }
        if !self.postmasters[index].stopped {
            let already_exited = match self.postmasters[index].process.as_mut() {
                Some(process) => process.child.try_wait()?.is_some(),
                None => return Err(MaintenanceError::SourceWaitUnknown),
            };
            if !already_exited && !self.postmasters[index].stop_attempted {
                self.clock.permit_closing_request()?;
                self.postmasters[index].stop_attempted = true;
                let args = vec![
                    OsString::from("-D"),
                    data.as_os_str().to_owned(),
                    OsString::from("stop"),
                    OsString::from("--mode=fast"),
                    OsString::from("--no-wait"),
                ];
                if let Err(error) = self
                    .tool(
                        "pgctl-stop-request",
                        Program::PgCtl,
                        args,
                        false,
                        true,
                        false,
                    )
                    .await
                    && first.is_none()
                {
                    first = Some(error);
                }
            }
            // No PID disappearance, pg_ctl status, signal success or elapsed C replaces this wait.
            let root = self.root.as_ref().ok_or(MaintenanceError::IoFailure)?;
            let owner = self.postmasters[index]
                .process
                .take()
                .ok_or(MaintenanceError::SourceWaitUnknown)?;
            let mut capacity = CapacityMonitor {
                root,
                profile: &self.profile,
                clock: &self.clock,
                rows: &mut self.capacity,
                encoded_bytes: &mut self.capacity_encoded_bytes,
            };
            let waited = wait_program(owner, &mut capacity, true, false).await?;
            if first.is_none() {
                first = waited.error;
            }
            self.tools.push(waited.observation);
            self.postmasters[index].stopped = true;
        }
        if self.connecting_postmaster == Some(index) {
            if let Some(task) = self.connecting.take() {
                let result = task.await;
                self.connection_attempts_joined = self.connection_attempts_joined.saturating_add(1);
                match result {
                    Ok(Ok((client, connection))) => {
                        let mut driver = tokio::spawn(connection);
                        drop(client);
                        let observed = (&mut driver).await;
                        self.sql.push(SqlOwner {
                            client: None,
                            // The same original driver handle remains here after its observed join.
                            driver,
                            query: None,
                            postmaster: index,
                            driver_joined: true,
                            driver_result_ok: Some(matches!(&observed, Ok(Ok(())))),
                            queries_started: 0,
                            queries_joined: 0,
                            queries_ok: 0,
                        });
                        if !matches!(observed, Ok(Ok(()))) && first.is_none() {
                            first = Some(MaintenanceError::ConnectionFailed);
                        }
                    }
                    Ok(Err(_)) => {
                        if first.is_none() {
                            first = Some(MaintenanceError::ConnectionFailed);
                        }
                    }
                    Err(_) => {
                        if first.is_none() {
                            first = Some(MaintenanceError::PipeJoinUnknown);
                        }
                    }
                }
            }
            self.connecting_postmaster = None;
        }
        for sql in &mut self.sql {
            if sql.postmaster != index || sql.driver_joined {
                continue;
            }
            if let Some(task) = sql.query.take() {
                let result = task.await;
                sql.queries_joined = sql.queries_joined.saturating_add(1);
                match result {
                    Ok((client, result)) => {
                        if result.is_ok() {
                            sql.queries_ok = sql.queries_ok.saturating_add(1);
                        } else if first.is_none() {
                            first = Some(MaintenanceError::ConnectionFailed);
                        }
                        drop(client);
                    }
                    Err(_) => {
                        if first.is_none() {
                            first = Some(MaintenanceError::PipeJoinUnknown);
                        }
                    }
                }
            }
            sql.client.take();
            let result = (&mut sql.driver).await;
            sql.driver_joined = true;
            sql.driver_result_ok = Some(matches!(&result, Ok(Ok(()))));
            if !matches!(result, Ok(Ok(()))) && first.is_none() {
                first = Some(MaintenanceError::ConnectionFailed);
            }
        }
        if let Some(error) = first {
            Err(error)
        } else {
            Ok(())
        }
    }
    async fn close_original_sources(&mut self) -> Result<(), MaintenanceError> {
        let mut first = None;
        if let Some(native) = self.native.as_ref()
            && native.wait.is_none()
        {
            let _requested = native
                .control
                .try_send(Control::Cancel(self.clock.convergence()));
        }
        for i in (0..self.postmasters.len()).rev() {
            if let Err(error) = self.stop_postmaster(i).await
                && first.is_none()
            {
                first = Some(error);
            }
        }
        if let Some(native) = self.native.as_mut() {
            settle_native(native, &self.clock).await;
        }
        if let Some(error) = first {
            Err(error)
        } else {
            Ok(())
        }
    }
    fn original_owners_closed(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(NativeOwner::physically_closed)
            && self.postmasters.iter().all(|p| p.stopped)
            && self
                .sql
                .iter()
                .all(|s| s.driver_joined && s.query.is_none())
            && self.connecting.is_none()
    }
    fn sql_observations(&self) -> Vec<SqlDriverObservation> {
        self.sql
            .iter()
            .map(|s| SqlDriverObservation {
                postmaster: s.postmaster,
                original_driver_joined: s.driver_joined,
                driver_result_ok: s.driver_result_ok,
                query_tasks_started: s.queries_started,
                query_tasks_joined: s.queries_joined,
                query_results_ok: s.queries_ok,
            })
            .collect()
    }
}

impl RetainedMaintenanceFailure {
    fn plain(error: MaintenanceError) -> Self {
        Self { owner: None, error }
    }
    pub(super) async fn retain_until_original_owners_close(mut self) -> MaintenanceError {
        if let Some(mut owner) = self.owner.take() {
            let _close_result = owner.close_original_sources().await;
            if !owner.original_owners_closed() {
                // A missing original worker/parent wait cannot be repaired by PID polling or by
                // returning an exit code. This resident job keeps the original owners and roots.
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let _ = &owner;
                }
            }
        }
        self.error
    }
}

pub(crate) async fn run_owned_selftest(
    bundle: VerifiedMaintenanceBundle,
    new_root: PathBuf,
    profile: MaintenanceProfile,
) -> Result<ToolchainReceipt, RetainedMaintenanceFailure> {
    let mut source = OwnedFixtureSource::new(bundle, new_root, profile)
        .map_err(RetainedMaintenanceFailure::plain)?;
    if let Err(error) = source.initialize().await {
        return Err(RetainedMaintenanceFailure {
            owner: Some(Box::new(source)),
            error,
        });
    }
    let request = match (source.root_path(), source.source_socket()) {
        (Ok(root), Ok(socket)) => BasebackupRequest {
            output: root.join("spool/pg"),
            socket,
            postmaster: 0,
        },
        _ => {
            return Err(RetainedMaintenanceFailure {
                owner: Some(Box::new(source)),
                error: MaintenanceError::IoFailure,
            });
        }
    };
    let (mut source, native) = match run_basebackup(source, request).await {
        BasebackupOutcome::Completed { source, receipt } => (source, receipt),
        BasebackupOutcome::FailedClosed { source, error } => {
            return Err(RetainedMaintenanceFailure {
                owner: Some(Box::new(source)),
                error,
            });
        }
        BasebackupOutcome::Closing { owner, error } => {
            return Err(RetainedMaintenanceFailure {
                owner: Some(Box::new(owner)),
                error,
            });
        }
    };
    let result = finish_selftest(&mut source, &native).await;
    match result {
        Ok(material) => {
            let identity = match source.identity.take() {
                Some(i) => i,
                None => {
                    return Err(RetainedMaintenanceFailure {
                        owner: Some(Box::new(source)),
                        error: MaintenanceError::RestoreCheckFailed,
                    });
                }
            };
            let finished = source
                .clock
                .observed()
                .map_err(RetainedMaintenanceFailure::plain)?;
            if finished >= source.clock.convergence() {
                return Err(RetainedMaintenanceFailure {
                    owner: Some(Box::new(source)),
                    error: MaintenanceError::DeadlineExpired,
                });
            }
            let receipt = ToolchainReceipt {
                schema: "wrokbot-pg-maintenance-toolchain-receipt",
                schema_version: 1,
                operation: bundle::encode_hex(&source.operation),
                profile_sha256: format!(
                    "{:x}",
                    Sha256::digest(
                        source
                            .profile
                            .encoded()
                            .map_err(RetainedMaintenanceFailure::plain)?
                    )
                ),
                bundle: source.bundle.verification_receipt(),
                clock: ClockReceipt {
                    t0_ns: source.clock.t0(),
                    effect_deadline_ns: source.clock.effect(),
                    convergence_deadline_ns: source.clock.convergence(),
                    finished_ns: finished,
                },
                sql_drivers: source.sql_observations(),
                connection_attempts: source.connection_attempts,
                connection_attempts_joined: source.connection_attempts_joined,
                tools: std::mem::take(&mut source.tools),
                native,
                source_identity: identity,
                material,
                capacity: std::mem::take(&mut source.capacity),
                restore_readback: true,
                restore_restart_readback: true,
                source_authenticated: true,
                native_usable: true,
                platform_signature_verified: false,
                production_release_authorized: false,
                backup_capture_completed: false,
                restore_current: false,
                b: false,
                c: false,
                ready: false,
                secret_scope: "Owned SecretBytes and native-owned buffers only; no whole-process/SASL/OS memory wipe claim",
                fd_scope: "Consumer-owned FD inventory and native/PG per-process bounds; no global OS/Tokio RLIMIT claim",
                known_rust_fd_peak_bound: 17,
            };
            let bytes = serde_json::to_vec(&receipt)
                .map_err(|_| RetainedMaintenanceFailure::plain(MaintenanceError::IoFailure))?;
            if bytes.len() as u64 > source.profile.fields().max_journal_bytes {
                return Err(RetainedMaintenanceFailure {
                    owner: Some(Box::new(source)),
                    error: MaintenanceError::CapacityExceeded,
                });
            }
            Ok(receipt)
        }
        Err(error) => Err(RetainedMaintenanceFailure {
            owner: Some(Box::new(source)),
            error,
        }),
    }
}

pub(crate) async fn run_basebackup(
    mut source: OwnedFixtureSource,
    request: BasebackupRequest,
) -> BasebackupOutcome {
    let result = native_backup(&mut source, &request).await;
    match result {
        Ok(receipt) => BasebackupOutcome::Completed { source, receipt },
        Err(error) => {
            if source
                .native
                .as_ref()
                .is_some_and(|n| !n.physically_closed())
            {
                BasebackupOutcome::Closing {
                    owner: source,
                    error,
                }
            } else {
                BasebackupOutcome::FailedClosed { source, error }
            }
        }
    }
}
async fn native_backup(
    source: &mut OwnedFixtureSource,
    request: &BasebackupRequest,
) -> Result<NativeReceipt, MaintenanceError> {
    source.clock.permit_effect()?;
    source.capacity_check()?;
    if source
        .postmasters
        .get(request.postmaster)
        .is_none_or(|p| p.stopped)
        || request.output.exists()
        || !request.output.starts_with(source.root_path()?)
        || request.socket != source.source_socket()?
    {
        return Err(MaintenanceError::InvalidArguments);
    }
    let mut command = source.bundle.checked_command(Program::BaseBackup)?;
    command.current_dir(source.root_path()?);
    for (name, value) in [
        ("owner-protocol", "1".to_owned()),
        ("operation", bundle::encode_hex(&source.operation)),
        ("t0-ns", source.clock.t0().to_string()),
        ("effect-deadline-ns", source.clock.effect().to_string()),
        (
            "convergence-deadline-ns",
            source.clock.convergence().to_string(),
        ),
    ] {
        command.arg(format!("--wrokbot-{name}={value}"));
    }
    for (name, value) in source.profile.fields().native_fields() {
        command.arg(format!("--wrokbot-{name}={value}"));
    }
    command.args([
        "--format=plain",
        "--wal-method=stream",
        "--manifest-checksums=SHA256",
        "--checkpoint=fast",
        "--no-password",
        "--no-clean",
        "--no-slot",
    ]);
    for (name, value) in [
        ("--pgdata", request.output.as_os_str().to_owned()),
        ("--host", request.socket.as_os_str().to_owned()),
        ("--port", OsString::from(PORT.to_string())),
        ("--username", OsString::from(ROLE)),
        (
            "--label",
            OsString::from(format!(
                "wrokbot-maintenance-{}",
                bundle::encode_hex(&source.operation)
            )),
        ),
    ] {
        let mut argument = OsString::from(name);
        argument.push("=");
        argument.push(value);
        command.arg(argument);
    }
    source.check_owned_fd_budget(3)?;
    let args_env_clean = command_secret_absent(&command, source.secret.expose());
    if !args_env_clean {
        return Err(MaintenanceError::SecretInvalid);
    }
    source.clock.permit_effect()?;
    let mut child = command.spawn()?;
    let pid = child.id().unwrap_or(0);
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (control, commands) = mpsc::channel(2);
    let (start_tx, start_rx) = oneshot::channel();
    let (events, mut event_reader) = mpsc::channel(8);
    source.native = Some(NativeOwner {
        child,
        pid,
        args_env_clean,
        writer: None,
        reader: None,
        stderr: None,
        control,
        wait: None,
        wait_ns: None,
        wait_errors: 0,
        pipes_closed_ns: None,
        writer_joined: false,
        reader_joined: false,
        stderr_joined: false,
        trail: None,
        drain: None,
        join_error: None,
    });
    let owner = source
        .native
        .as_mut()
        .ok_or(MaintenanceError::HelperWaitUnknown)?;
    let (stdin, stdout, stderr) = match (stdin, stdout, stderr) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Err(MaintenanceError::PipeJoinUnknown),
    };
    let p = source.profile.fields();
    let (op, t0, e, c) = (
        source.operation,
        source.clock.t0(),
        source.clock.effect(),
        source.clock.convergence(),
    );
    let (secret, max_secret, max_status, max_records, max_stderr) = (
        Arc::clone(&source.secret),
        p.max_source_secret_bytes,
        p.max_status_bytes,
        p.max_status_records,
        p.max_stderr_bytes,
    );
    owner.reader = Some(tokio::spawn(async move {
        read_status(
            stdout,
            StatusTrail::new(op, pid, t0, max_records, max_status),
            events,
        )
        .await
    }));
    owner.stderr = Some(tokio::spawn(drain_pipe(
        stderr,
        max_stderr,
        Some(Arc::clone(&source.secret)),
        false,
    )));
    owner.writer = Some(tokio::spawn(control_writer(
        stdin,
        commands,
        start_rx,
        secret,
        op,
        max_secret,
        (e, c),
    )));
    // All original owners have been installed and the two readers are resident before START.
    #[cfg(test)]
    if source.scenario == OwnedNativeTestScenario::ConnectionBeforeStart {
        source.stop_postmaster(request.postmaster).await?;
    }
    start_tx
        .send(())
        .map_err(|_| MaintenanceError::PipeJoinUnknown)?;
    let mut events_open = true;
    #[cfg(test)]
    let mut fault_issued = false;
    let mut capacity_error = None;
    loop {
        if capacity_error.is_none()
            && let Err(error) = source.capacity_check()
        {
            capacity_error = Some(error);
            if let Some(owner) = source.native.as_ref() {
                let _requested = owner.control.try_send(Control::Cancel(c));
            }
            // Stop our still-owned source through its original shutdown/wait path.
            // The native helper is never killed to satisfy the capacity or C boundary.
            source.stop_postmaster(request.postmaster).await?;
        }
        enum Observed {
            Wait(std::io::Result<ExitStatus>),
            Event(Option<u16>),
            CapacityTick,
        }
        let observed = {
            let owner = source
                .native
                .as_mut()
                .ok_or(MaintenanceError::HelperWaitUnknown)?;
            tokio::select! {
                biased;
                event=event_reader.recv(),if events_open=>Observed::Event(event),
                status=owner.child.wait()=>Observed::Wait(status),
                _=tokio::time::sleep(Duration::from_millis(100))=>Observed::CapacityTick,
            }
        };
        match observed {
            Observed::CapacityTick => {}
            Observed::Wait(Ok(status)) => {
                let owner = source
                    .native
                    .as_mut()
                    .ok_or(MaintenanceError::HelperWaitUnknown)?;
                owner.wait = Some(status);
                match source.clock.observed() {
                    Ok(now) => owner.wait_ns = Some(now),
                    Err(error) => {
                        owner.join_error.get_or_insert(error);
                    }
                }
                break;
            }
            Observed::Wait(Err(_)) => {
                let owner = source
                    .native
                    .as_mut()
                    .ok_or(MaintenanceError::HelperWaitUnknown)?;
                owner.wait_errors = owner.wait_errors.saturating_add(1);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Observed::Event(None) => events_open = false,
            Observed::Event(Some(event)) => {
                #[cfg(not(test))]
                let _observed_event = event;
                #[cfg(test)]
                if event == 3 && !fault_issued {
                    fault_issued = true;
                    match source.scenario {
                        OwnedNativeTestScenario::CancelAfterWorker => {
                            if let Some(owner) = source.native.as_ref() {
                                let _sent = owner.control.try_send(Control::Cancel(c));
                            }
                        }
                        OwnedNativeTestScenario::EofAfterWorker => {
                            if let Some(owner) = source.native.as_ref() {
                                let _sent = owner.control.try_send(Control::TestEof);
                            }
                        }
                        OwnedNativeTestScenario::TightDeadlineAfterWorker => {
                            // A valid current-time tighter C is already due when the helper
                            // receives it. The IPC itself is still bounded by the original C.
                            let tighter = source.clock.observed()?.min(c);
                            source.test_tighter_c = Some(tighter);
                            if let Some(owner) = source.native.as_ref() {
                                let _sent = owner.control.try_send(Control::Cancel(tighter));
                            }
                        }
                        OwnedNativeTestScenario::DisconnectAfterWorker => {
                            let sql = source
                                .sql
                                .iter()
                                .position(|sql| {
                                    sql.postmaster == request.postmaster
                                        && sql.client.is_some()
                                        && sql.query.is_none()
                                        && !sql.driver_joined
                                })
                                .ok_or(MaintenanceError::ConnectionFailed)?;
                            let rows = source
                                .query_owned(
                                    sql,
                                    "SELECT pid, pg_catalog.pg_terminate_backend(pid) AS requested FROM pg_catalog.pg_stat_activity WHERE backend_type = 'walsender' AND usename = current_user AND application_name = 'wrokbot-pg-basebackup' AND client_addr IS NULL AND pid <> pg_catalog.pg_backend_pid()".to_owned(),
                                    false,
                                )
                                .await?;
                            if !(1..=2).contains(&rows.len()) {
                                return Err(MaintenanceError::ConnectionFailed);
                            }
                            let mut server_walsender_pids = Vec::with_capacity(rows.len());
                            for row in rows {
                                let pid: i32 = row
                                    .try_get("pid")
                                    .map_err(|_| MaintenanceError::ConnectionFailed)?;
                                let requested: bool = row
                                    .try_get("requested")
                                    .map_err(|_| MaintenanceError::ConnectionFailed)?;
                                if pid <= 0 || !requested {
                                    return Err(MaintenanceError::ConnectionFailed);
                                }
                                server_walsender_pids.push(pid);
                            }
                            let _diagnostic = writeln!(
                                std::io::stderr().lock(),
                                "WROKBOT_PG_MAINTENANCE_TEST_DISCONNECT_REQUESTED postmaster={} server_walsender_pids={server_walsender_pids:?}",
                                request.postmaster
                            );
                            source.stop_postmaster(request.postmaster).await?;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    let owner = source
        .native
        .as_mut()
        .ok_or(MaintenanceError::HelperWaitUnknown)?;
    settle_native(owner, &source.clock).await;
    if let Some(error) = capacity_error {
        return Err(error);
    }
    if let Some(error) = owner.join_error {
        return Err(error);
    }
    let status = owner.wait.ok_or(MaintenanceError::HelperWaitUnknown)?;
    let trail = owner
        .trail
        .as_ref()
        .ok_or(MaintenanceError::PipeJoinUnknown)?;
    let stderr = owner
        .drain
        .as_ref()
        .ok_or(MaintenanceError::PipeJoinUnknown)?;
    let closed_before = owner.wait_ns.is_some_and(|now| now < c)
        && owner.pipes_closed_ns.is_some_and(|now| now < c)
        && trail
            .terminal()
            .is_some_and(|r| r.observed_ns < c && r.worker_wait_ns < c);
    let receipt = NativeReceipt {
        pid,
        original_child_wait: true,
        exit_code: status.code(),
        signal: status.signal(),
        wait_observed_ns: owner.wait_ns,
        all_pipe_joins_observed_ns: owner.pipes_closed_ns,
        stdin_writer_joined: owner.writer_joined,
        stdout_reader_joined: owner.reader_joined,
        stderr_reader_joined: owner.stderr_joined,
        statuses: trail.records().to_vec(),
        stderr: stderr.report.clone(),
        worker_created: trail.worker_created(),
        worker_wait_observed: trail.worker_wait_observed(),
        original_wait_errors: owner.wait_errors,
        closed_late: !closed_before,
        secret_absent_from_argv_env: owner.args_env_clean,
        data_complete_before_effect_deadline: trail
            .records()
            .iter()
            .any(|r| r.event == 4 && r.observed_ns < e),
        closed_before_convergence_deadline: closed_before,
    };
    if receipt.stderr.limit_exceeded {
        return Err(MaintenanceError::CapacityExceeded);
    }
    if receipt.stderr.secret_found {
        return Err(MaintenanceError::SecretInvalid);
    }
    if !owner.physically_closed() {
        return Err(MaintenanceError::WalWorkerWaitUnknown);
    }
    if !status.success() || !trail.closed_success() {
        if !trail.closed_success() && !trail.closed_failure() {
            return Err(MaintenanceError::ProtocolInvalid);
        }
        let error = match trail.terminal().map(|r| r.error) {
            Some(1) => MaintenanceError::InvalidArguments,
            Some(2) => MaintenanceError::SecretInvalid,
            Some(3) => MaintenanceError::ProtocolInvalid,
            Some(4) => MaintenanceError::ClockUnavailable,
            Some(5 | 12) => MaintenanceError::DeadlineExpired,
            Some(6) => MaintenanceError::Cancelled,
            Some(7) => MaintenanceError::CapacityExceeded,
            Some(8) => MaintenanceError::ConnectionFailed,
            Some(10) => MaintenanceError::WalWorkerFailed,
            Some(11) => MaintenanceError::IoFailure,
            _ => MaintenanceError::BackupFailed,
        };
        return Err(error);
    }
    if !receipt.data_complete_before_effect_deadline || !receipt.closed_before_convergence_deadline
    {
        return Err(MaintenanceError::DeadlineExpired);
    }
    Ok(receipt)
}

async fn settle_native(owner: &mut NativeOwner, clock: &OperationClock) {
    if owner.wait.is_none() {
        let (status, errors) = wait_original_child(&mut owner.child).await;
        owner.wait = Some(status);
        owner.wait_errors = owner.wait_errors.saturating_add(errors);
        match clock.observed() {
            Ok(now) => owner.wait_ns = Some(now),
            Err(error) => {
                owner.join_error.get_or_insert(error);
            }
        }
    }
    // Only after observing the same original leader wait may normal closure send EOF.
    // Do not lose EOF closure when cancellation notifications briefly fill the bounded queue.
    // This is the same original writer; no new pipe/task, timeout budget or native retry.
    let _requested = owner.control.send(Control::FinishAfterWait).await;
    if let Some(handle) = owner.writer.take() {
        let result = handle.await;
        owner.writer_joined = true;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                owner.join_error.get_or_insert(error);
            }
            Err(_) => {
                owner
                    .join_error
                    .get_or_insert(MaintenanceError::PipeJoinUnknown);
            }
        }
    }
    if let Some(handle) = owner.reader.take() {
        let result = handle.await;
        owner.reader_joined = true;
        match result {
            Ok(Ok(trail)) => owner.trail = Some(trail),
            Ok(Err(error)) => {
                owner.join_error.get_or_insert(error);
            }
            Err(_) => {
                owner
                    .join_error
                    .get_or_insert(MaintenanceError::PipeJoinUnknown);
            }
        }
    }
    if let Some(handle) = owner.stderr.take() {
        let result = handle.await;
        owner.stderr_joined = true;
        match result {
            Ok(Ok(drain)) => owner.drain = Some(drain),
            Ok(Err(error)) => {
                owner.join_error.get_or_insert(error);
            }
            Err(_) => {
                owner
                    .join_error
                    .get_or_insert(MaintenanceError::PipeJoinUnknown);
            }
        }
    }
    if owner.writer_joined
        && owner.reader_joined
        && owner.stderr_joined
        && owner.pipes_closed_ns.is_none()
    {
        match clock.observed() {
            Ok(now) => owner.pipes_closed_ns = Some(now),
            Err(error) => {
                owner.join_error.get_or_insert(error);
            }
        }
    }
    if owner.wait_errors != 0 {
        owner
            .join_error
            .get_or_insert(MaintenanceError::HelperWaitUnknown);
    }
}

pub(super) async fn control_writer<W: AsyncWrite + Unpin>(
    mut stdin: W,
    mut commands: mpsc::Receiver<Control>,
    start: oneshot::Receiver<()>,
    secret: Arc<SecretBytes>,
    operation: [u8; 16],
    max_secret: u64,
    (e, c): (u64, u64),
) -> Result<(), MaintenanceError> {
    start.await.map_err(|_| MaintenanceError::PipeJoinUnknown)?;
    let frame = protocol::secret_frame(&operation, secret.expose(), max_secret)?;
    write_before(&mut stdin, &frame, e).await?;
    drop(frame);
    drop(secret);
    write_before(&mut stdin, &protocol::start_frame(&operation), e).await?;
    let mut cancelled = false;
    loop {
        let now = clock::monotonic_ns()?;
        let command = if cancelled {
            commands.recv().await
        } else {
            tokio::select! {
                command=commands.recv()=>command,
                _=tokio::time::sleep(Duration::from_nanos(e.saturating_sub(now)))=>Some(Control::Cancel(c)),
            }
        };
        match command {
            Some(Control::FinishAfterWait) => {
                return stdin
                    .shutdown()
                    .await
                    .map_err(|_| MaintenanceError::PipeJoinUnknown);
            }
            #[cfg(test)]
            Some(Control::TestEof) => {
                return stdin
                    .shutdown()
                    .await
                    .map_err(|_| MaintenanceError::PipeJoinUnknown);
            }
            Some(Control::Cancel(tighter)) if !cancelled => {
                let frame = protocol::cancel_frame(&operation, tighter, c)?;
                let result = write_before(&mut stdin, &frame, c).await;
                cancelled = true;
                if result.is_err() {
                    return Err(MaintenanceError::ClosingPending);
                }
            }
            Some(Control::Cancel(_)) => {
                // The timer and failure owner may race to request the same cancellation. Emit
                // at most one frame; no request can replenish the original effect/convergence.
            }
            None => return Err(MaintenanceError::Cancelled),
        }
    }
}
async fn write_before<W: AsyncWrite + Unpin>(
    stdin: &mut W,
    bytes: &[u8],
    deadline: u64,
) -> Result<(), MaintenanceError> {
    let now = clock::monotonic_ns()?;
    if now >= deadline {
        return Err(MaintenanceError::DeadlineExpired);
    }
    tokio::time::timeout(Duration::from_nanos(deadline - now), stdin.write_all(bytes))
        .await
        .map_err(|_| MaintenanceError::DeadlineExpired)?
        .map_err(|_| MaintenanceError::Cancelled)?;
    if clock::monotonic_ns()? > deadline {
        return Err(MaintenanceError::DeadlineExpired);
    }
    Ok(())
}
async fn read_status(
    mut stdout: tokio::process::ChildStdout,
    mut trail: StatusTrail,
    events: mpsc::Sender<u16>,
) -> Result<StatusTrail, MaintenanceError> {
    loop {
        let mut h = [0; protocol::HEADER];
        let n = stdout.read(&mut h[..1]).await?;
        if n == 0 {
            return Ok(trail);
        }
        stdout
            .read_exact(&mut h[1..])
            .await
            .map_err(|_| MaintenanceError::ProtocolInvalid)?;
        let mut p = Zeroizing::new([0; protocol::STATUS]);
        stdout
            .read_exact(&mut p[..])
            .await
            .map_err(|_| MaintenanceError::ProtocolInvalid)?;
        let status = trail.push(&h, &p, clock::monotonic_ns()?)?;
        let _notification = events.try_send(status.event);
    }
}
async fn drain_pipe<R: AsyncRead + Unpin>(
    mut pipe: R,
    limit: u64,
    secret: Option<Arc<SecretBytes>>,
    preview: bool,
) -> Result<DrainResult, MaintenanceError> {
    let mut buffer = Zeroizing::new([0_u8; 8192]);
    let mut carry = Zeroizing::new(Vec::with_capacity(128));
    let mut total = 0_u64;
    let mut exceeded = false;
    let mut found = false;
    let mut hash = Sha256::new();
    let mut sample = Zeroizing::new(Vec::new());
    loop {
        let n = pipe.read(&mut buffer[..]).await?;
        if n == 0 {
            break;
        }
        total = match total.checked_add(n as u64) {
            Some(n) => n,
            None => {
                exceeded = true;
                u64::MAX
            }
        };
        if total > limit {
            exceeded = true;
        }
        hash.update(&buffer[..n]);
        if let Some(secret) = &secret {
            let mut window = Zeroizing::new(Vec::with_capacity(carry.len() + n));
            window.extend_from_slice(&carry);
            window.extend_from_slice(&buffer[..n]);
            if !secret.is_empty() && window.windows(secret.len()).any(|w| w == secret.expose()) {
                found = true;
            }
            let keep = (secret.len().saturating_sub(1)).min(window.len());
            carry.clear();
            carry.extend_from_slice(&window[window.len() - keep..]);
        }
        if preview && sample.len() < 512 {
            let take = n.min(512 - sample.len());
            sample.extend_from_slice(&buffer[..take]);
        }
        buffer[..n].zeroize();
    }
    Ok(DrainResult {
        report: DrainReport {
            bytes: total,
            sha256: format!("{:x}", hash.finalize()),
            limit_exceeded: exceeded,
            secret_found: found,
        },
        preview: if found { Vec::new() } else { sample.to_vec() },
    })
}
fn command_secret_absent(command: &tokio::process::Command, secret: &[u8]) -> bool {
    let contains =
        |bytes: &[u8]| !secret.is_empty() && bytes.windows(secret.len()).any(|w| w == secret);
    !command.as_std().get_args().any(|v| contains(v.as_bytes()))
        && !command
            .as_std()
            .get_envs()
            .any(|(k, v)| contains(k.as_bytes()) || v.is_some_and(|v| contains(v.as_bytes())))
}
fn spawn_program(
    command: tokio::process::Command,
    role: &'static str,
    clock: &OperationClock,
    secret: Arc<SecretBytes>,
    write_secret: bool,
    limits: (u64, u64, bool),
    closing: bool,
) -> Result<ProgramOwner, MaintenanceError> {
    spawn_program_retaining_io(command, role, clock, secret, write_secret, limits, closing)
        .map_err(|failure| failure.fault)
}
fn spawn_program_retaining_io(
    mut command: tokio::process::Command,
    role: &'static str,
    clock: &OperationClock,
    secret: Arc<SecretBytes>,
    write_secret: bool,
    (out_limit, err_limit, preview): (u64, u64, bool),
    closing: bool,
) -> Result<ProgramOwner, NativeSpawnFailure> {
    let started = if closing {
        clock.permit_closing_request()?;
        clock.observed()?
    } else {
        clock.permit_effect()?
    };
    let effect_deadline = clock.effect();
    let args_env_clean = command_secret_absent(&command, secret.expose());
    if !args_env_clean {
        return Err(MaintenanceError::SecretInvalid.into());
    }
    let input = if write_secret {
        Some(Arc::clone(&secret))
    } else {
        None
    };
    let mut child = command.spawn()?;
    // No fallible return after spawn: even an unexpected absent pipe/PID stays with this owner.
    let pid = child.id().unwrap_or(0);
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let setup_error = pid == 0 || stdin.is_none() || stdout.is_none() || stderr.is_none();
    let scan = Some(secret);
    let writer = match (stdin, input) {
        (Some(mut pipe), Some(secret)) => Some(tokio::spawn(async move {
            let mut bytes = Zeroizing::new(Vec::with_capacity(secret.len() + 1));
            bytes.extend_from_slice(secret.expose());
            bytes.push(b'\n');
            let result = write_before(&mut pipe, &bytes, effect_deadline).await;
            bytes.zeroize();
            drop(secret);
            // EOF belongs to this original writer. Wait the same task even after a write error.
            let shutdown = pipe
                .shutdown()
                .await
                .map_err(|_| MaintenanceError::IoFailure);
            result.and(shutdown)
        })),
        (pipe, _) => {
            drop(pipe);
            None
        }
    };
    let output = stdout.map(|pipe| {
        tokio::spawn(drain_pipe(
            pipe,
            out_limit,
            scan.as_ref().map(Arc::clone),
            preview,
        ))
    });
    let error = stderr.map(|pipe| tokio::spawn(drain_pipe(pipe, err_limit, scan, false)));
    Ok(ProgramOwner {
        role,
        child,
        pid,
        started,
        setup_error,
        args_env_clean,
        input: writer,
        output,
        error,
    })
}

// A wait error never substitutes PID disappearance for the original Child.wait. The same owner
// remains resident across a clock failure, E/C expiry or repeated wait error.
async fn wait_original_child(child: &mut Child) -> (ExitStatus, u64) {
    let mut errors = 0_u64;
    loop {
        match child.wait().await {
            Ok(status) => return (status, errors),
            Err(_) => {
                errors = errors.saturating_add(1);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}
async fn wait_program(
    mut owner: ProgramOwner,
    capacity_monitor: &mut CapacityMonitor<'_>,
    closing: bool,
    term_on_deadline: bool,
) -> Result<ToolResult, MaintenanceError> {
    let clock = capacity_monitor.clock;
    let bound = if closing {
        clock.convergence()
    } else {
        clock.effect()
    };
    let mut capacity_error = None;
    let mut expired = false;
    let first = loop {
        let remaining = if closing {
            clock.convergence_wait()
        } else {
            clock.effect_wait()
        };
        let remaining = match remaining {
            Ok(duration) if !duration.is_zero() => duration,
            Ok(_) => {
                expired = true;
                break None;
            }
            Err(error) => {
                capacity_error.get_or_insert(error);
                break None;
            }
        };
        if capacity_error.is_none()
            && let Err(error) = capacity_monitor.observe(0)
        {
            capacity_error = Some(error);
            if !closing {
                break None;
            }
        }
        let observed = tokio::select! {
            result=owner.child.wait()=>Some(result),
            _=tokio::time::sleep(remaining.min(Duration::from_millis(100)))=>None,
        };
        if let Some(result) = observed {
            break Some(result);
        }
    };
    let initial_error = u64::from(matches!(&first, Some(Err(_))));
    let (status, additional_errors) = match first {
        Some(Ok(status)) => (status, 0),
        _ => {
            if term_on_deadline
                && clock.permit_closing_request().is_ok()
                && let Ok(raw) = i32::try_from(owner.pid)
                && let Some(pid) = rustix::process::Pid::from_raw(raw)
            {
                // Only this still-unreaped original non-helper child. Never kill the WAL
                // leader or infer wait from signal success.
                let _requested = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            }
            wait_original_child(&mut owner.child).await
        }
    };
    let now = clock.observed();
    let mut late = expired || now.as_ref().map_or(true, |t| *t >= bound);
    let input = match owner.input.take() {
        Some(handle) => Some(handle.await),
        None => None,
    };
    // All original joins occur, even when a previous task failed/panicked.
    let output = match owner.output.take() {
        Some(handle) => Some(handle.await),
        None => None,
    };
    let stderr = match owner.error.take() {
        Some(handle) => Some(handle.await),
        None => None,
    };
    let joins_now = clock.observed();
    late |= joins_now.as_ref().map_or(true, |t| *t >= bound);
    let pipe_joins_observed_ns = joins_now.ok();
    let input_joined = input.as_ref().map(|r| r.is_ok());
    let output_joined = output.as_ref().is_some_and(Result::is_ok);
    let stderr_joined = stderr.as_ref().is_some_and(Result::is_ok);
    let output = match output {
        Some(Ok(Ok(r))) => Some(r),
        _ => None,
    };
    let stderr = match stderr {
        Some(Ok(Ok(r))) => Some(r),
        _ => None,
    };
    let bad_secret = output.as_ref().is_some_and(|r| r.report.secret_found)
        || stderr.as_ref().is_some_and(|r| r.report.secret_found);
    let capacity = output.as_ref().is_some_and(|r| r.report.limit_exceeded)
        || stderr.as_ref().is_some_and(|r| r.report.limit_exceeded);
    let input_ok = input.as_ref().is_none_or(|r| matches!(r, Ok(Ok(()))));
    let failed = if bad_secret {
        Some(MaintenanceError::SecretInvalid)
    } else if capacity {
        Some(MaintenanceError::CapacityExceeded)
    } else if capacity_error.is_some() {
        capacity_error
    } else if owner.setup_error || output.is_none() || stderr.is_none() || !input_ok {
        Some(MaintenanceError::PipeJoinUnknown)
    } else if now.is_err() {
        Some(MaintenanceError::ClockUnavailable)
    } else if late {
        Some(MaintenanceError::DeadlineExpired)
    } else if initial_error != 0 || additional_errors != 0 {
        Some(MaintenanceError::HelperWaitUnknown)
    } else if !status.success() {
        Some(MaintenanceError::BuildFailed)
    } else {
        None
    };
    let preview = output
        .as_ref()
        .map(|r| r.preview.clone())
        .unwrap_or_default();
    // A clock failure retains an absent timestamp; it never fabricates an on-time observation.
    let observed = now.ok();
    Ok(ToolResult {
        observation: ToolObservation {
            role: owner.role,
            pid: owner.pid,
            started_ns: owner.started,
            wait_observed_ns: observed,
            pipe_joins_observed_ns,
            exit_code: status.code(),
            signal: status.signal(),
            original_child_wait: true,
            stdin_writer_joined: input_joined,
            stdout_reader_joined: output_joined,
            stderr_reader_joined: stderr_joined,
            original_wait_errors: initial_error.saturating_add(additional_errors),
            deadline_expired: late,
            secret_absent_from_argv_env: owner.args_env_clean,
            stdout: output.map(|r| r.report),
            stderr: stderr.map(|r| r.report),
        },
        preview,
        error: failed,
    })
}

fn validate_new_root_name(root: &Path, bundle: &Path) -> Result<(), MaintenanceError> {
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(MaintenanceError::InvalidArguments)?;
    if root.as_os_str().as_bytes() != format!("/private/tmp/{name}").as_bytes()
        || root.parent() != Some(Path::new("/private/tmp"))
        || !root.is_absolute()
        || root.to_str().is_none()
        || root.file_name().is_none()
        || root.starts_with(bundle)
        || root
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || root
            .as_os_str()
            .as_bytes()
            .iter()
            .any(|b| matches!(*b, 0 | b'\n' | b'\r' | b'\'' | b'"' | b',' | b'\\'))
    {
        return Err(MaintenanceError::InvalidArguments);
    }
    for name in ["socket", "rsock"] {
        if root
            .join(name)
            .join(".s.PGSQL.5432")
            .as_os_str()
            .as_bytes()
            .len()
            >= 104
        {
            return Err(MaintenanceError::InvalidArguments);
        }
    }
    Ok(())
}
fn create_new_owned_root(
    path: &Path,
    clock: &OperationClock,
) -> Result<OwnedRoot, MaintenanceError> {
    clock.permit_effect()?;
    let parent = path.parent().ok_or(MaintenanceError::InvalidArguments)?;
    if parent.as_os_str().as_bytes() != b"/private/tmp" {
        return Err(MaintenanceError::InvalidArguments);
    }
    let parent_fd = bundle::open_directory(parent)?;
    let parent_identity = parent_fd.metadata()?;
    let name = path.file_name().ok_or(MaintenanceError::InvalidArguments)?;
    rustix::fs::mkdirat(
        &parent_fd,
        name,
        rustix::fs::Mode::from_bits_truncate(0o700),
    )
    .map_err(|_| MaintenanceError::InvalidArguments)?;
    let fd = rustix::fs::openat(
        &parent_fd,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| MaintenanceError::InvalidArguments)?;
    let metadata = fd.metadata()?;
    let named_parent = fs::symlink_metadata(parent)?;
    let named_root = fs::symlink_metadata(path)?;
    if named_parent.file_type().is_symlink()
        || named_root.file_type().is_symlink()
        || (named_parent.dev(), named_parent.ino())
            != (parent_identity.dev(), parent_identity.ino())
        || (named_root.dev(), named_root.ino()) != (metadata.dev(), metadata.ino())
    {
        return Err(MaintenanceError::InvalidArguments);
    }
    if metadata.dev() != parent_identity.dev()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
        || metadata.nlink() != 2
    {
        return Err(MaintenanceError::InvalidArguments);
    }
    clock.permit_closing_request()?;
    fd.sync_all()?;
    clock.permit_closing_request()?;
    parent_fd.sync_all()?;
    clock.permit_closing_request()?;
    Ok(OwnedRoot {
        path: path.to_owned(),
        _directory: fd,
        _parent: parent_fd,
    })
}
fn private_directory(path: &Path, clock: &OperationClock) -> Result<(), MaintenanceError> {
    clock.permit_effect()?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    clock.permit_closing_request()?;
    File::open(path)?.sync_all()?;
    clock.permit_closing_request()?;
    Ok(())
}
fn write_owned_file(
    path: &Path,
    bytes: &[u8],
    existing: bool,
    clock: &OperationClock,
) -> Result<(), MaintenanceError> {
    clock.permit_effect()?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    if existing {
        let m = fs::symlink_metadata(path)?;
        if !m.is_file() || m.nlink() != 1 {
            return Err(MaintenanceError::IoFailure);
        }
    } else {
        options.create_new(true).mode(0o600);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != rustix::process::getuid().as_raw()
    {
        return Err(MaintenanceError::IoFailure);
    }
    clock.permit_effect()?;
    file.set_len(0)?;
    file.write_all(bytes)?;
    clock.permit_closing_request()?;
    file.sync_all()?;
    clock.permit_closing_request()?;
    Ok(())
}
fn write_fixture_config(
    data: &Path,
    socket: &Path,
    max_open_files: u64,
    clock: &OperationClock,
) -> Result<(), MaintenanceError> {
    clock.permit_effect()?;
    let path = socket.to_str().ok_or(MaintenanceError::InvalidArguments)?;
    let config = format!(
        "listen_addresses = ''\nport = {PORT}\nunix_socket_directories = '{path}'\nunix_socket_permissions = 0600\n\
        shared_preload_libraries = ''\nsession_preload_libraries = ''\nlocal_preload_libraries = ''\n\
        max_wal_senders = 2\nmax_replication_slots = 0\nwal_level = replica\narchive_mode = off\n\
        ssl = off\nlogging_collector = off\nlog_statement = 'none'\nlog_min_error_statement = panic\n\
        max_connections = 10\nmax_files_per_process = {max_open_files}\nshared_buffers = '16MB'\n"
    );
    let hba = format!(
        "local all {ROLE} scram-sha-256\nlocal replication {ROLE} scram-sha-256\nlocal all all reject\nlocal replication all reject\n"
    );
    write_owned_file(
        &data.join("postgresql.conf"),
        config.as_bytes(),
        true,
        clock,
    )?;
    write_owned_file(&data.join("pg_hba.conf"), hba.as_bytes(), true, clock)?;
    clock.permit_closing_request()?;
    File::open(data)?.sync_all()?;
    clock.permit_closing_request()?;
    Ok(())
}

#[derive(Serialize)]
struct MaterialFile {
    path: String,
    bytes: u64,
    sha256: String,
    allocated_bytes: u64,
}
#[derive(Serialize)]
struct MaterialInventory {
    files: Vec<MaterialFile>,
    counters: MaterialCounters,
    manifest_sha256: String,
    manifest_checksum_verified: bool,
    all_manifest_file_checksums_verified: bool,
    wal_range_and_headers_verified: bool,
    all_regular_files_and_directories_synced: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PgManifest {
    #[serde(rename = "PostgreSQL-Backup-Manifest-Version")]
    version: u32,
    #[serde(rename = "System-Identifier")]
    system_id: u64,
    #[serde(rename = "Files")]
    files: Vec<PgManifestFile>,
    #[serde(rename = "WAL-Ranges")]
    wal: Vec<PgWalRange>,
    #[serde(rename = "Manifest-Checksum")]
    checksum: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PgManifestFile {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Size")]
    bytes: u64,
    #[serde(rename = "Last-Modified")]
    modified: String,
    #[serde(rename = "Checksum-Algorithm")]
    algorithm: String,
    #[serde(rename = "Checksum")]
    checksum: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PgWalRange {
    #[serde(rename = "Timeline")]
    timeline: u32,
    #[serde(rename = "Start-LSN")]
    start: String,
    #[serde(rename = "End-LSN")]
    stop: String,
}

async fn finish_selftest(
    source: &mut OwnedFixtureSource,
    native: &NativeReceipt,
) -> Result<MaterialInventory, MaintenanceError> {
    let terminal = native
        .statuses
        .last()
        .copied()
        .filter(|s| s.event == 8)
        .ok_or(MaintenanceError::ManifestInvalid)?;
    let expected = source
        .identity
        .as_ref()
        .ok_or(MaintenanceError::RestoreCheckFailed)?;
    let (system_id, timeline, segment) = (
        expected.system_id,
        expected.timeline,
        expected.wal_segment_bytes,
    );
    if (
        terminal.system_id,
        terminal.timeline,
        terminal.wal_segment_bytes,
    ) != (system_id, timeline, segment)
    {
        return Err(MaintenanceError::WalRangeInvalid);
    }
    source.stop_postmaster(0).await?;
    source.clock.permit_effect()?;
    let backup = source.root_path()?.join("spool/pg");
    let material = verify_physical_material(&backup, &source.profile, &source.clock, &terminal)?;
    source.capacity_check()?;
    let restore = source.root_path()?.join("restore-check");
    source.clock.permit_effect()?;
    private_directory(&restore, &source.clock)?;
    copy_physical_material(
        &backup,
        &restore,
        &material,
        &mut source.capacity_monitor()?,
    )?;
    // Reopen the copied stored bytes and the original manifest before applying the owned-only
    // source/socket isolation overlay. The original backup and its expected checksums never change.
    let copied = verify_physical_material(&restore, &source.profile, &source.clock, &terminal)?;
    if copied.manifest_sha256 != material.manifest_sha256
        || copied.files.len() != material.files.len()
        || copied
            .files
            .iter()
            .zip(&material.files)
            .any(|(a, b)| a.path != b.path || a.bytes != b.bytes || a.sha256 != b.sha256)
    {
        return Err(MaintenanceError::RestoreCheckFailed);
    }
    let rsock = source.restore_socket()?;
    write_fixture_config(
        &restore,
        &rsock,
        source.profile.fields().max_open_files,
        &source.clock,
    )?;
    let index = source
        .start_postmaster(restore.clone(), rsock.clone())
        .await?;
    let connection = source.connect_ready(index).await?;
    let recovered = source.read_identity(connection).await?;
    check_restored_identity(&recovered, system_id, timeline, segment)?;
    source.stop_postmaster(index).await?;
    source.clock.permit_effect()?;
    let restarted = source.start_postmaster(restore, rsock).await?;
    let connection = source.connect_ready(restarted).await?;
    let recovered = source.read_identity(connection).await?;
    check_restored_identity(&recovered, system_id, timeline, segment)?;
    source.stop_postmaster(restarted).await?;
    source.close_original_sources().await?;
    source.capacity_check()?;
    scan_owned_plaintext_secret(
        source.root_path()?,
        source.secret.expose(),
        &source.profile,
        &source.clock,
    )?;
    Ok(material)
}
fn check_restored_identity(
    value: &SourceIdentity,
    system: u64,
    timeline: u32,
    segment: u32,
) -> Result<(), MaintenanceError> {
    if value.system_id != system
        || value.timeline != timeline
        || value.wal_segment_bytes != segment
        || value.sentinel_rows != 1
        || value.rollback_rows != 0
        || !value.data_checksums
    {
        return Err(MaintenanceError::RestoreCheckFailed);
    }
    Ok(())
}
fn parse_lsn(value: &str) -> Result<u64, MaintenanceError> {
    let (a, b) = value
        .split_once('/')
        .ok_or(MaintenanceError::WalRangeInvalid)?;
    if a.is_empty()
        || b.is_empty()
        || a.len() > 8
        || b.len() > 8
        || !a.bytes().chain(b.bytes()).all(|c| c.is_ascii_hexdigit())
    {
        return Err(MaintenanceError::WalRangeInvalid);
    }
    let high = u32::from_str_radix(a, 16).map_err(|_| MaintenanceError::WalRangeInvalid)?;
    let low = u32::from_str_radix(b, 16).map_err(|_| MaintenanceError::WalRangeInvalid)?;
    Ok((u64::from(high) << 32) | u64::from(low))
}
fn verify_physical_material(
    root: &Path,
    profile: &MaintenanceProfile,
    clock: &OperationClock,
    status: &StatusRecord,
) -> Result<MaterialInventory, MaintenanceError> {
    let p = profile.fields();
    clock.permit_effect()?;
    let manifest_bytes =
        bundle::read_input_file(&root.join("backup_manifest"), p.max_backup_manifest_bytes)?;
    let parsed: PgManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| MaintenanceError::ManifestInvalid)?;
    if parsed.version != 2
        || parsed.system_id != status.system_id
        || parsed.wal.len() != 1
        || parsed.files.len() as u64 > p.max_material_files
    {
        return Err(MaintenanceError::ManifestInvalid);
    }
    // PostgreSQL17 parse_manifest.c hashes through the penultimate newline; the final line carries
    // Manifest-Checksum. Match the original byte rule, not a reserialized JSON representation.
    let newlines = manifest_bytes
        .iter()
        .enumerate()
        .filter_map(|(i, b)| (*b == b'\n').then_some(i))
        .collect::<Vec<_>>();
    if newlines.len() < 2 || newlines.last().copied() != manifest_bytes.len().checked_sub(1) {
        return Err(MaintenanceError::ManifestInvalid);
    }
    let checksum_end = newlines[newlines.len() - 2] + 1;
    let actual_manifest_checksum = format!("{:x}", Sha256::digest(&manifest_bytes[..checksum_end]));
    if parsed.checksum != actual_manifest_checksum {
        return Err(MaintenanceError::ManifestInvalid);
    }
    let range = &parsed.wal[0];
    let start = parse_lsn(&range.start)?;
    let stop = parse_lsn(&range.stop)?;
    if (range.timeline, start, stop) != (status.timeline, status.start_lsn, status.stop_lsn) {
        return Err(MaintenanceError::WalRangeInvalid);
    }
    let required_segments =
        limits::validate_wal_range(p, status.timeline, status.wal_segment_bytes, start, stop)?;
    let mut inventory = MaterialInventory {
        files: Vec::new(),
        counters: MaterialCounters::default(),
        manifest_sha256: format!("{:x}", Sha256::digest(&manifest_bytes)),
        manifest_checksum_verified: true,
        all_manifest_file_checksums_verified: false,
        wal_range_and_headers_verified: false,
        all_regular_files_and_directories_synced: false,
    };
    walk_material(root, Path::new(""), 0, &mut inventory, profile, clock)?;
    inventory.files.sort_by(|a, b| a.path.cmp(&b.path));
    let actual = inventory
        .files
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect::<BTreeMap<_, _>>();
    let mut expected = BTreeSet::new();
    for row in &parsed.files {
        bundle::relative(&row.path).map_err(|_| MaintenanceError::ManifestInvalid)?;
        if !expected.insert(row.path.as_str())
            || row.modified.is_empty()
            || row.modified.len() > 64
            || row.algorithm != "SHA256"
            || row.checksum.len() != 64
        {
            return Err(MaintenanceError::ManifestInvalid);
        }
        let actual = actual
            .get(row.path.as_str())
            .ok_or(MaintenanceError::ManifestInvalid)?;
        if actual.bytes != row.bytes || actual.sha256 != row.checksum {
            return Err(MaintenanceError::ManifestInvalid);
        }
    }
    let mut actual_wal = BTreeSet::new();
    let segment = u64::from(status.wal_segment_bytes);
    for row in &inventory.files {
        if row.path == "backup_manifest" || expected.contains(row.path.as_str()) {
            continue;
        }
        if let Some(name) = row.path.strip_prefix("pg_wal/") {
            if name.len() == 24
                && name
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
            {
                let tli = u32::from_str_radix(&name[..8], 16)
                    .map_err(|_| MaintenanceError::WalRangeInvalid)?;
                let log = u64::from_str_radix(&name[8..16], 16)
                    .map_err(|_| MaintenanceError::WalRangeInvalid)?;
                let seg = u64::from_str_radix(&name[16..], 16)
                    .map_err(|_| MaintenanceError::WalRangeInvalid)?;
                let per_log = (1_u64 << 32)
                    .checked_div(segment)
                    .ok_or(MaintenanceError::WalRangeInvalid)?;
                if seg >= per_log {
                    return Err(MaintenanceError::WalRangeInvalid);
                }
                let number = log
                    .checked_mul(per_log)
                    .and_then(|n| n.checked_add(seg))
                    .ok_or(MaintenanceError::WalRangeInvalid)?;
                if tli != status.timeline || row.bytes != segment || !actual_wal.insert(number) {
                    return Err(MaintenanceError::WalRangeInvalid);
                }
                verify_wal_header(&root.join(&row.path), status, number)?;
                continue;
            }
            if let Some(name) = name.strip_prefix("archive_status/")
                && row.bytes == 0
                && name.len() == 29
                && name.ends_with(".done")
                && name[..24]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
            {
                continue;
            }
        }
        return Err(MaintenanceError::ManifestInvalid);
    }
    let first = start / segment;
    let last = (stop - 1) / segment;
    if (actual_wal.len() as u64) < required_segments
        || (first..=last).any(|n| !actual_wal.contains(&n))
    {
        return Err(MaintenanceError::WalRangeInvalid);
    }
    if inventory.counters.bytes != status.material_bytes
        || inventory.counters.files != status.material_files
        || inventory.counters.wal_bytes != status.wal_bytes
        || inventory.counters.wal_segments != status.wal_segments
    {
        return Err(MaintenanceError::ManifestInvalid);
    }
    inventory.all_manifest_file_checksums_verified = true;
    inventory.wal_range_and_headers_verified = true;
    inventory.all_regular_files_and_directories_synced = true;
    Ok(inventory)
}
fn walk_material(
    root: &Path,
    relative: &Path,
    depth: u64,
    out: &mut MaterialInventory,
    profile: &MaintenanceProfile,
    clock: &OperationClock,
) -> Result<(), MaintenanceError> {
    let p = profile.fields();
    if depth > p.max_depth {
        return Err(MaintenanceError::CapacityExceeded);
    }
    out.counters.directory(p)?;
    let mut entries = fs::read_dir(root.join(relative))?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        clock.permit_effect()?;
        let path = relative.join(entry.file_name());
        let s = path.to_str().ok_or(MaintenanceError::ManifestInvalid)?;
        if s.len() as u64 > p.max_path_bytes {
            return Err(MaintenanceError::CapacityExceeded);
        }
        bundle::relative(s).map_err(|_| MaintenanceError::ManifestInvalid)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(MaintenanceError::ManifestInvalid);
        }
        if metadata.is_dir() {
            walk_material(
                root,
                &path,
                depth
                    .checked_add(1)
                    .ok_or(MaintenanceError::CapacityExceeded)?,
                out,
                profile,
                clock,
            )?;
        } else if metadata.is_file() && metadata.nlink() == 1 {
            let wal = s
                .strip_prefix("pg_wal/")
                .is_some_and(|n| n.len() == 24 && n.bytes().all(|b| b.is_ascii_hexdigit()));
            let allocated = metadata
                .blocks()
                .checked_mul(512)
                .ok_or(MaintenanceError::CapacityExceeded)?;
            out.counters.file(p, metadata.len(), allocated, wal)?;
            let sha = hash_owned_file(
                &entry.path(),
                metadata.len(),
                p.copy_block_bytes,
                clock,
                true,
            )?;
            out.files.push(MaterialFile {
                path: s.to_owned(),
                bytes: metadata.len(),
                sha256: sha,
                allocated_bytes: allocated,
            });
        } else {
            return Err(MaintenanceError::ManifestInvalid);
        }
    }
    clock.permit_closing_request()?;
    File::open(root.join(relative))?.sync_all()?;
    Ok(())
}
fn hash_owned_file(
    path: &Path,
    len: u64,
    block: u64,
    clock: &OperationClock,
    sync: bool,
) -> Result<String, MaintenanceError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    if sync {
        options.write(true);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() != len {
        return Err(MaintenanceError::ManifestInvalid);
    }
    let mut buffer = Zeroizing::new(vec![
        0;
        usize::try_from(block)
            .map_err(|_| MaintenanceError::CapacityExceeded)?
    ]);
    let mut read = 0_u64;
    let mut hash = Sha256::new();
    loop {
        clock.permit_effect()?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        read = read
            .checked_add(n as u64)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if read > len {
            return Err(MaintenanceError::ManifestInvalid);
        }
        hash.update(&buffer[..n]);
        buffer[..n].zeroize();
    }
    let after = file.metadata()?;
    if read != len
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            1,
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.nlink(),
        )
    {
        return Err(MaintenanceError::ManifestInvalid);
    }
    if sync {
        clock.permit_closing_request()?;
        file.sync_all()?;
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn verify_wal_header(
    path: &Path,
    status: &StatusRecord,
    number: u64,
) -> Result<(), MaintenanceError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let mut bytes = [0_u8; 40];
    file.read_exact(&mut bytes)?;
    let u16at = |i| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
    let u32at = |i| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    let u64at = |i| {
        u64::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7],
        ])
    };
    let address = number
        .checked_mul(u64::from(status.wal_segment_bytes))
        .ok_or(MaintenanceError::WalRangeInvalid)?;
    if u16at(0) != 0xD116
        || u16at(2) & 2 == 0
        || u32at(4) != status.timeline
        || u64at(8) != address
        || u64at(24) != status.system_id
        || u32at(32) != status.wal_segment_bytes
        || u32at(36) != 8192
    {
        return Err(MaintenanceError::WalRangeInvalid);
    }
    Ok(())
}
fn copy_physical_material(
    from: &Path,
    to: &Path,
    inventory: &MaterialInventory,
    capacity: &mut CapacityMonitor<'_>,
) -> Result<(), MaintenanceError> {
    let profile = capacity.profile;
    let clock = capacity.clock;
    let p = profile.fields();
    let mut copied = 0_u64;
    for row in &inventory.files {
        clock.permit_effect()?;
        copied = copied
            .checked_add(row.bytes)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if copied > p.max_restore_check_bytes {
            return Err(MaintenanceError::CapacityExceeded);
        }
        let target = to.join(&row.path);
        if let Some(parent) = target.parent() {
            create_owned_copy_parents(to, parent, capacity)?;
        }
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(from.join(&row.path))?;
        let before = input.metadata()?;
        if !before.is_file() || before.nlink() != 1 || before.len() != row.bytes {
            return Err(MaintenanceError::ManifestInvalid);
        }
        capacity.observe(0)?;
        clock.permit_effect()?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&target)?;
        let mut buffer = Zeroizing::new(vec![
            0;
            usize::try_from(p.copy_block_bytes)
                .map_err(|_| MaintenanceError::CapacityExceeded)?
        ]);
        let mut count = 0_u64;
        let mut hash = Sha256::new();
        loop {
            clock.permit_effect()?;
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n as u64)
                .ok_or(MaintenanceError::CapacityExceeded)?;
            if count > row.bytes {
                return Err(MaintenanceError::ManifestInvalid);
            }
            capacity.observe(n as u64)?;
            clock.permit_effect()?;
            output.write_all(&buffer[..n])?;
            hash.update(&buffer[..n]);
            buffer[..n].zeroize();
        }
        if count != row.bytes || format!("{:x}", hash.finalize()) != row.sha256 {
            return Err(MaintenanceError::ManifestInvalid);
        }
        clock.permit_closing_request()?;
        output.sync_all()?;
        File::open(target.parent().ok_or(MaintenanceError::IoFailure)?)?.sync_all()?;
    }
    // Empty PG directories are real material too; they must survive the physical copy.
    let mut directories = 0;
    copy_empty_directories(
        from,
        to,
        p.max_directories,
        p.max_depth,
        0,
        &mut directories,
        capacity,
    )?;
    File::open(to)?.sync_all()?;
    Ok(())
}
fn create_owned_copy_parents(
    root: &Path,
    parent: &Path,
    capacity: &mut CapacityMonitor<'_>,
) -> Result<(), MaintenanceError> {
    let clock = capacity.clock;
    clock.permit_effect()?;
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| MaintenanceError::ManifestInvalid)?;
    let mut current = root.to_owned();
    for c in relative.components() {
        let Component::Normal(name) = c else {
            return Err(MaintenanceError::ManifestInvalid);
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                capacity.observe(0)?;
                private_directory(&current, clock)?
            }
            _ => return Err(MaintenanceError::ManifestInvalid),
        }
    }
    Ok(())
}
fn copy_empty_directories(
    from: &Path,
    to: &Path,
    max: u64,
    depth_max: u64,
    depth: u64,
    count: &mut u64,
    capacity: &mut CapacityMonitor<'_>,
) -> Result<(), MaintenanceError> {
    let clock = capacity.clock;
    clock.permit_effect()?;
    if depth > depth_max {
        return Err(MaintenanceError::CapacityExceeded);
    }
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(MaintenanceError::ManifestInvalid);
        }
        if metadata.is_dir() {
            *count = count
                .checked_add(1)
                .ok_or(MaintenanceError::CapacityExceeded)?;
            if *count > max {
                return Err(MaintenanceError::CapacityExceeded);
            }
            let target = to.join(entry.file_name());
            match fs::symlink_metadata(&target) {
                Ok(m)
                    if m.is_dir()
                        && !m.file_type().is_symlink()
                        && m.uid() == rustix::process::getuid().as_raw()
                        && m.mode() & 0o777 == 0o700 => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    capacity.observe(0)?;
                    private_directory(&target, clock)?
                }
                _ => return Err(MaintenanceError::ManifestInvalid),
            }
            copy_empty_directories(
                &entry.path(),
                &target,
                max,
                depth_max,
                depth + 1,
                count,
                capacity,
            )?;
            clock.permit_closing_request()?;
            File::open(target)?.sync_all()?;
        }
    }
    Ok(())
}
fn allocated_tree(root: &Path, max_files: u64) -> Result<u64, MaintenanceError> {
    fn walk(
        path: &Path,
        count: &mut u64,
        max: u64,
        total: &mut u64,
    ) -> Result<(), MaintenanceError> {
        let m = match fs::symlink_metadata(path) {
            Ok(m) => m,
            // An owned live PG may unlink a descendant after readdir. The accounting root
            // itself must remain; missing children have no allocated bytes to reserve twice.
            Err(error) if *count != 0 && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if m.file_type().is_symlink() {
            return Err(MaintenanceError::CapacityExceeded);
        }
        *count = count
            .checked_add(1)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if *count > max {
            return Err(MaintenanceError::CapacityExceeded);
        }
        *total = total
            .checked_add(
                m.blocks()
                    .checked_mul(512)
                    .ok_or(MaintenanceError::CapacityExceeded)?,
            )
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if m.is_dir() {
            for e in fs::read_dir(path)? {
                walk(&e?.path(), count, max, total)?;
            }
        }
        Ok(())
    }
    let mut count = 0;
    let mut total = 0;
    walk(root, &mut count, max_files, &mut total)?;
    Ok(total)
}
fn scan_owned_plaintext_secret(
    root: &Path,
    secret: &[u8],
    profile: &MaintenanceProfile,
    clock: &OperationClock,
) -> Result<(), MaintenanceError> {
    fn walk(
        path: &Path,
        secret: &[u8],
        profile: &MaintenanceProfile,
        count: &mut u64,
        total: &mut u64,
        clock: &OperationClock,
    ) -> Result<(), MaintenanceError> {
        clock.permit_closing_request()?;
        let p = profile.fields();
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(MaintenanceError::SecretInvalid);
        }
        if metadata.is_dir() {
            for item in fs::read_dir(path)? {
                walk(&item?.path(), secret, profile, count, total, clock)?;
            }
            return Ok(());
        }
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(MaintenanceError::SecretInvalid);
        }
        *count = count
            .checked_add(1)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        *total = total
            .checked_add(metadata.len())
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if *count
            > p.max_material_files
                .checked_mul(3)
                .ok_or(MaintenanceError::CapacityExceeded)?
            || *total
                > p.max_material_plain_bytes
                    .checked_mul(3)
                    .and_then(|n| n.checked_add(p.max_journal_bytes))
                    .ok_or(MaintenanceError::CapacityExceeded)?
        {
            return Err(MaintenanceError::CapacityExceeded);
        }
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)?;
        let mut buffer = Zeroizing::new(vec![
            0;
            usize::try_from(p.copy_block_bytes)
                .map_err(|_| MaintenanceError::CapacityExceeded)?
        ]);
        let mut carry = Zeroizing::new(Vec::with_capacity(secret.len()));
        loop {
            clock.permit_closing_request()?;
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            let mut window = Zeroizing::new(Vec::with_capacity(carry.len() + n));
            window.extend_from_slice(&carry);
            window.extend_from_slice(&buffer[..n]);
            if !secret.is_empty() && window.windows(secret.len()).any(|b| b == secret) {
                return Err(MaintenanceError::SecretInvalid);
            }
            let keep = secret.len().saturating_sub(1).min(window.len());
            carry.clear();
            carry.extend_from_slice(&window[window.len() - keep..]);
            buffer[..n].zeroize();
        }
        Ok(())
    }
    let mut count = 0;
    let mut total = 0;
    walk(root, secret, profile, &mut count, &mut total, clock)
}

#[cfg(test)]
#[derive(Serialize)]
pub(super) struct OwnedTestObservation {
    pub(super) scenario: &'static str,
    pub(super) error: Option<MaintenanceError>,
    pub(super) native_started: bool,
    pub(super) original_child_wait: bool,
    pub(super) all_original_pipe_joins: bool,
    pub(super) all_original_sources_closed: bool,
    pub(super) worker_created: bool,
    pub(super) worker_wait_observed: bool,
    pub(super) terminal_error: Option<u16>,
    pub(super) worker_wait_ns: Option<u64>,
    pub(super) native_closed_success: bool,
    pub(super) native_usable: bool,
    pub(super) restore_and_restart_checked: bool,
    pub(super) plaintext_secret_scan_pass: bool,
    pub(super) argv_env_secret_scan_pass: bool,
    pub(super) requested_tighter_c: Option<u64>,
    pub(super) original_t0_ns: u64,
    pub(super) original_effect_ns: u64,
    pub(super) original_convergence_ns: u64,
    pub(super) platform_signature_verified: bool,
    pub(super) production_release_authorized: bool,
    pub(super) existing_capture_or_ready: bool,
}

#[cfg(test)]
pub(super) fn prepare_owned_test_parent(path: &Path) -> Result<(), MaintenanceError> {
    // Root freezes a nonexistent direct-child namespace prefix. It is not a directory grant
    // and is never created; every scenario independently creates a suffixed direct tmp child.
    validate_new_root_name(path, Path::new("/__not_a_bundle_root__"))?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(MaintenanceError::InvalidArguments),
    }
}
#[cfg(test)]
pub(super) async fn owned_test_case(
    bundle: VerifiedMaintenanceBundle,
    root: PathBuf,
    profile: MaintenanceProfile,
    scenario: OwnedNativeTestScenario,
) -> Result<OwnedTestObservation, MaintenanceError> {
    let profile = if scenario == OwnedNativeTestScenario::Capacity {
        let mut value: serde_json::Value = serde_json::from_slice(&profile.encoded()?)
            .map_err(|_| MaintenanceError::ProfileInvalid)?;
        // An explicit test-only tighter material bound. It applies to the actual helper copy,
        // not a fake ENOSPC claim or a change to the existing source initialization command.
        value["maxTotalCopyBlocks"] = serde_json::json!(1);
        limits::parse_profile(
            &serde_json::to_vec(&value).map_err(|_| MaintenanceError::ProfileInvalid)?,
        )?
    } else {
        profile
    };
    let mut source = OwnedFixtureSource::new(bundle, root, profile)?;
    source.scenario = scenario;
    let result: Result<(), MaintenanceError> = async {
        source.initialize().await?;
        let request = BasebackupRequest {
            output: source.root_path()?.join("spool/pg"),
            socket: source.source_socket()?,
            postmaster: 0,
        };
        let native = native_backup(&mut source, &request).await?;
        if matches!(
            scenario,
            OwnedNativeTestScenario::TamperManifest | OwnedNativeTestScenario::TamperWal
        ) {
            source.stop_postmaster(0).await?;
            let backup = source.root_path()?.join("spool/pg");
            let path = if scenario == OwnedNativeTestScenario::TamperManifest {
                backup.join("backup_manifest")
            } else {
                let mut selected = None;
                for entry in fs::read_dir(backup.join("pg_wal"))? {
                    let entry = entry?;
                    let name = entry.file_name();
                    let name = name.to_str().ok_or(MaintenanceError::WalRangeInvalid)?;
                    if name.len() == 24
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
                    {
                        selected = Some(entry.path());
                        break;
                    }
                }
                selected.ok_or(MaintenanceError::WalRangeInvalid)?
            };
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(path)?;
            let mut first = [0];
            file.read_exact(&mut first)?;
            first[0] ^= 0x80;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&first)?;
            file.sync_all()?;
        }
        finish_selftest(&mut source, &native).await?;
        Ok(())
    }
    .await;
    let mut error = result.err();
    let _diagnostic = writeln!(
        std::io::stderr().lock(),
        "WROKBOT_PG_MAINTENANCE_TEST_RESULT result_error={error:?}"
    );
    if let Err(close_error) = source.close_original_sources().await {
        if error.is_none() {
            error = Some(close_error);
        }
    }
    if !source.original_owners_closed() {
        let native = source.native.as_ref();
        let wait = native.and_then(|owner| owner.wait.as_ref());
        let trail = native.and_then(|owner| owner.trail.as_ref());
        let stderr = native.and_then(|owner| owner.drain.as_ref());
        let mut prestatus = None;
        if let Some(stderr) = stderr
            && stderr.report.bytes == 13
            && !stderr.report.limit_exceeded
            && !stderr.report.secret_found
        {
            'closed_codes: for stage in 1_u8..=18 {
                for failure in 1_u8..=12 {
                    let mut code = *b"W44PRE:00:00\n";
                    code[7] = b'0' + stage / 10;
                    code[8] = b'0' + stage % 10;
                    code[10] = b'0' + failure / 10;
                    code[11] = b'0' + failure % 10;
                    let known_sha = Sha256::digest(code);
                    let observed = stderr.report.sha256.as_bytes();
                    let known = observed.len() == 64
                        && known_sha
                            .iter()
                            .zip(observed.chunks_exact(2))
                            .all(|(byte, pair)| {
                                const HEX: &[u8; 16] = b"0123456789abcdef";
                                pair[0] == HEX[usize::from(*byte >> 4)]
                                    && pair[1] == HEX[usize::from(*byte & 15)]
                            });
                    if known {
                        prestatus = Some((stage, failure));
                        break 'closed_codes;
                    }
                }
            }
        }
        let _diagnostic = writeln!(
            std::io::stderr().lock(),
            concat!(
                "WROKBOT_PG_MAINTENANCE_TEST_RETAINED ",
                "native={} helper_wait={} helper_exit_code={:?} helper_signal={:?} ",
                "stdin_joined={:?} stdout_joined={:?} stderr_joined={:?} ",
                "trail_records={:?} terminal_error={:?} worker_created={:?} worker_wait={:?} ",
                "postmasters_total={} postmasters_stopped={} ",
                "connecting_pending={} connecting_started={} connecting_joined={} ",
                "sql_total={} queries_pending={} drivers_joined={} ",
                "native_stderr_bytes={:?} native_stderr_limit_exceeded={:?} ",
                "native_stderr_secret_found={:?} prestatus_stage={:?} prestatus_first_error={:?}"
            ),
            native.is_some(),
            wait.is_some(),
            wait.and_then(ExitStatus::code),
            wait.and_then(ExitStatus::signal),
            native.map(|owner| owner.writer_joined),
            native.map(|owner| owner.reader_joined),
            native.map(|owner| owner.stderr_joined),
            trail.map(|trail| trail.records().len()),
            trail
                .and_then(StatusTrail::terminal)
                .map(|record| record.error),
            trail.map(StatusTrail::worker_created),
            trail.map(StatusTrail::worker_wait_observed),
            source.postmasters.len(),
            source
                .postmasters
                .iter()
                .filter(|owner| owner.stopped)
                .count(),
            source.connecting.is_some(),
            source.connection_attempts,
            source.connection_attempts_joined,
            source.sql.len(),
            source
                .sql
                .iter()
                .filter(|owner| owner.query.is_some())
                .count(),
            source
                .sql
                .iter()
                .filter(|owner| owner.driver_joined)
                .count(),
            stderr.map(|stderr| stderr.report.bytes),
            stderr.map(|stderr| stderr.report.limit_exceeded),
            stderr.map(|stderr| stderr.report.secret_found),
            prestatus.map(|(stage, _)| stage),
            prestatus.map(|(_, failure)| failure)
        );
    }
    // A negative assertion is evaluated only after the original owners have closed. If the
    // trusted helper never supplies its original worker wait, keep the same source/roots resident.
    while !source.original_owners_closed() {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let _closure = source.close_original_sources().await;
    }
    let plaintext = if let Some(root) = &source.root {
        scan_owned_plaintext_secret(
            &root.path,
            source.secret.expose(),
            &source.profile,
            &source.clock,
        )
        .is_ok()
    } else {
        false
    };
    if !plaintext && error.is_none() {
        error = Some(MaintenanceError::SecretInvalid);
    }
    let native = source.native.as_ref();
    let trail = native.and_then(|n| n.trail.as_ref());
    let terminal = trail.and_then(StatusTrail::terminal);
    if source
        .clock
        .observed()
        .is_ok_and(|now| now >= source.clock.convergence())
        && error.is_none()
    {
        error = Some(MaintenanceError::DeadlineExpired);
    }
    let restored = error.is_none();
    let scenario_name = match scenario {
        OwnedNativeTestScenario::Normal => "normal",
        OwnedNativeTestScenario::CancelAfterWorker => "cancel-after-real-worker",
        OwnedNativeTestScenario::EofAfterWorker => "eof-after-real-worker",
        OwnedNativeTestScenario::TightDeadlineAfterWorker => "tight-C-after-real-worker",
        OwnedNativeTestScenario::ConnectionBeforeStart => "owned-source-closed-before-start",
        OwnedNativeTestScenario::DisconnectAfterWorker => "owned-source-closed-after-real-worker",
        OwnedNativeTestScenario::TamperManifest => "new-manifest-byte-tamper",
        OwnedNativeTestScenario::TamperWal => "new-WAL-header-byte-tamper",
        OwnedNativeTestScenario::Capacity => "actual-helper-single-file-bound-one-byte",
    };
    let argv_env = source.tools.iter().all(|o| o.secret_absent_from_argv_env)
        && native.is_some_and(|n| n.args_env_clean);
    let observation = OwnedTestObservation {
        scenario: scenario_name,
        error,
        native_started: native.is_some(),
        original_child_wait: native.is_some_and(|n| n.wait.is_some()),
        all_original_pipe_joins: native
            .is_some_and(|n| n.writer_joined && n.reader_joined && n.stderr_joined),
        all_original_sources_closed: source.original_owners_closed(),
        worker_created: trail.is_some_and(StatusTrail::worker_created),
        worker_wait_observed: trail.is_some_and(StatusTrail::worker_wait_observed),
        terminal_error: terminal.map(|t| t.error),
        worker_wait_ns: terminal
            .filter(|t| t.flags & protocol::WORKER_WAITED != 0)
            .map(|t| t.worker_wait_ns),
        native_closed_success: trail.is_some_and(StatusTrail::closed_success),
        native_usable: restored,
        restore_and_restart_checked: restored,
        plaintext_secret_scan_pass: plaintext,
        argv_env_secret_scan_pass: argv_env,
        requested_tighter_c: source.test_tighter_c,
        original_t0_ns: source.clock.t0(),
        original_effect_ns: source.clock.effect(),
        original_convergence_ns: source.clock.convergence(),
        platform_signature_verified: false,
        production_release_authorized: false,
        existing_capture_or_ready: false,
    };
    let encoded = serde_json::to_vec(&observation).map_err(|_| MaintenanceError::IoFailure)?;
    if encoded.len() as u64 > source.profile.fields().max_journal_bytes {
        return Err(MaintenanceError::CapacityExceeded);
    }
    // Numeric/closed-code receipt only. Do not print user paths, secret or server diagnostics.
    println!(
        "{}",
        String::from_utf8(encoded).map_err(|_| MaintenanceError::IoFailure)?
    );
    Ok(observation)
}
