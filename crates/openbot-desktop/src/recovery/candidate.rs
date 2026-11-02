//! The original operation's exclusively created candidate generation.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;
use zeroize::Zeroizing;

use openbot_infra::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging;
use openbot_infra::recovery_control::{
    RecoveryControlError, RestoreCandidateIsolationInput, RestoreCapacityReservation, RestoreCapacityResource, RestoreControlSession, RestoreNewChildKind,
    RestoreStorageKind,
};
use rustix::fs::{Mode, OFlags};

use crate::postgres_maintenance::MaintenanceError;
use crate::postgres_maintenance::clock::OperationClock;
use crate::postgres_maintenance::runner::{self, RestoreProgramFailure, RestoreProgramOwner, RestoreProgramResult};

use super::DesktopRestoreError;

const GENERATION_CHILDREN: [&str; 5] = ["data", "wal", "temp", "uds", "materials"];

// PG17's directory skeleton is not represented by a file-only base-backup
// inventory. In particular pg_tblspc remains an empty directory, never a link.
const PG17_DIRECTORIES: [&str; 24] = [
    "base", "base/1", "global", "pg_commit_ts", "pg_dynshmem", "pg_logical",
    "pg_logical/mappings", "pg_logical/snapshots", "pg_multixact",
    "pg_multixact/members", "pg_multixact/offsets", "pg_notify", "pg_replslot",
    "pg_serial", "pg_snapshots", "pg_stat", "pg_stat_tmp", "pg_subtrans",
    "pg_tblspc", "pg_twophase", "pg_wal", "pg_xact", "pg_wal/archive_status", "pg_wal/summaries",
];

struct CandidateDirectory {
    relative: String,
    file: File,
}

type OriginalWaitResult = (RestoreProgramResult, RestoreControlSession, OperationClock, Option<RecoveryControlError>);
type OriginalWait = Pin<Box<dyn Future<Output = OriginalWaitResult> + Send>>;

/// Keeps each original creation/open result even when the next observation is late.
pub(super) struct CandidateGeneration {
    staging: VerifiedWholePgRestoreStaging,
    paths: [PathBuf; 6],
    directories: [Option<File>; 6],
    clock: Option<OperationClock>,
    effect_deadline: Option<Instant>,
    convergence_deadline: Option<Instant>,
    space: Option<rustix::io::Result<rustix::fs::StatVfs>>,
    created: Option<rustix::io::Result<()>>,
    opened: Option<io::Result<File>>,
    synced: Option<io::Result<()>>,
    control_error: Option<RecoveryControlError>,
    clock_error: Option<MaintenanceError>,
    first_fault: Option<DesktopRestoreError>,
    copied_directories: Vec<CandidateDirectory>,
    copied_files: Vec<File>,
    copy_buffer: Zeroizing<Vec<u8>>,
    read: Option<io::Result<usize>>,
    written: Option<io::Result<usize>>,
    prepared: bool,
    config: String,
    program: Option<RestoreProgramOwner>,
    program_failure: Option<RestoreProgramFailure>,
    program_result: Option<RestoreProgramResult>,
    waiting: Option<OriginalWait>,
    wait_memory: Option<RestoreCapacityReservation>,
    returned_session: Option<RestoreControlSession>,
    metadata: Option<io::Result<std::fs::Metadata>>,
    isolation: Option<RestoreCandidateIsolationInput>,
    wait_capacity_error: Option<RecoveryControlError>,
    // Self's existing body fee includes this pointer; the concrete work heap
    // and every returned secret allocation are paid by the same session.
    target_slots: Option<Box<super::slots::RestoreTargetSlotWork>>,
}

impl CandidateGeneration {
    pub(super) fn new(staging: VerifiedWholePgRestoreStaging) -> Self {
        Self {
            staging,
            paths: std::array::from_fn(|_| PathBuf::new()),
            directories: std::array::from_fn(|_| None),
            clock: None,
            effect_deadline: None,
            convergence_deadline: None,
            space: None,
            created: None,
            opened: None,
            synced: None,
            control_error: None,
            clock_error: None,
            first_fault: None,
            copied_directories: Vec::new(),
            copied_files: Vec::new(),
            copy_buffer: Zeroizing::new(Vec::new()),
            read: None,
            written: None,
            prepared: false,
            config: String::new(),
            program: None,
            program_failure: None,
            program_result: None,
            waiting: None,
            wait_memory: None,
            returned_session: None,
            metadata: None,
            isolation: None,
            wait_capacity_error: None,
            target_slots: None,
        }
    }

    /// Prepare the four candidate write roots under the original verified staging owner.
    pub(super) fn prepare_directories(
        &mut self,
        session: &mut RestoreControlSession,
    ) -> Result<(), DesktopRestoreError> {
        if self.clock.is_some()
            || self.first_fault.is_some()
            || self.staging.candidate_plan().operation_id() != session.operation_id()
        {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        let result = (|| {
            match OperationClock::from_restore_session(session) {
                Ok(clock) => self.clock = Some(clock),
                Err(error) => {
                    self.clock_error = Some(error);
                    return Err(DesktopRestoreError::OwnerLost);
                }
            }
            let clock = self
                .clock
                .as_ref()
                .expect("original session clock retained");
            // Instant is sampled first, so these projections do not extend the
            // native deadline. The session also rechecks its clock before effects.
            let projection = Instant::now();
            let observed = clock.observed().map_err(|error| {
                self.clock_error = Some(error);
                DesktopRestoreError::OwnerLost
            })?;
            let effect_remaining = clock
                .effect()
                .checked_sub(observed)
                .ok_or(DesktopRestoreError::EffectExpired)?;
            let convergence_remaining = clock
                .convergence()
                .checked_sub(observed)
                .ok_or(DesktopRestoreError::ConvergenceExpired)?;
            let effect = projection
                .checked_add(std::time::Duration::from_nanos(effect_remaining))
                .ok_or(DesktopRestoreError::ProfileInvalid)?;
            let convergence = projection
                .checked_add(std::time::Duration::from_nanos(convergence_remaining))
                .ok_or(DesktopRestoreError::ProfileInvalid)?;
            self.effect_deadline = Some(effect);
            self.convergence_deadline = Some(convergence);
            self.isolation = Some(session.begin_candidate_isolation_before(&self.staging, effect).map_err(|error| {
                let fault = DesktopRestoreError::from_control(&error);
                self.control_error = Some(error);
                fault
            })?);
            // Closing must still be able to start the original wait after E.
            // Reserve its exact heap body now, before any candidate effect.
            self.wait_memory = Some(session.admit_capacity(
                RestoreCapacityResource::MetadataBytes,
                original_wait_size(original_wait).ok_or(DesktopRestoreError::CapacityExceeded)? as u64,
            ).map_err(|error| {
                let fault = DesktopRestoreError::from_control(&error);
                self.control_error = Some(error);
                fault
            })?);
            let original_clock_error = &mut self.clock_error;
            let mut require_effect = || {
                clock.permit_effect().map_err(|error| {
                    *original_clock_error = Some(error);
                    match error {
                        MaintenanceError::DeadlineExpired => DesktopRestoreError::EffectExpired,
                        _ => DesktopRestoreError::OwnerLost,
                    }
                })
            };
            let root_length = self
                .staging
                .candidate_plan()
                .parent_path()
                .as_os_str()
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_add(self.staging.candidate_plan().component().len()))
                .ok_or(DesktopRestoreError::CapacityExceeded)?;
            let paths_length = GENERATION_CHILDREN
                .iter()
                .try_fold(root_length, |n, child| {
                    n.checked_add(root_length)?
                        .checked_add(1)?
                        .checked_add(child.len())
                })
                .ok_or(DesktopRestoreError::CapacityExceeded)?;
            let planned_memory = paths_length
                .checked_mul(2)
                .and_then(|n| {
                    n.checked_add(
                        (std::mem::size_of::<Self>()
                            - std::mem::size_of::<VerifiedWholePgRestoreStaging>()
                            - std::mem::size_of::<RestoreCandidateIsolationInput>()),
                    )
                })
                .ok_or(DesktopRestoreError::CapacityExceeded)?;
            let original_error = &mut self.control_error;
            let mut retain = |error: RecoveryControlError| {
                let fault = DesktopRestoreError::from_control(&error);
                *original_error = Some(error);
                fault
            };
            let memory = session
                .admit_capacity(
                    RestoreCapacityResource::MetadataBytes,
                    planned_memory as u64,
                )
                .map_err(&mut retain)?;
            self.paths[0] = self
                .staging
                .candidate_plan()
                .parent_path()
                .join(self.staging.candidate_plan().component());
            for (index, child) in GENERATION_CHILDREN.iter().enumerate() {
                self.paths[index + 1] = self.paths[0].join(child);
            }
            let actual_memory = self
                .paths
                .iter()
                .try_fold(
                    (std::mem::size_of::<Self>()
                        - std::mem::size_of::<VerifiedWholePgRestoreStaging>()
                        - std::mem::size_of::<RestoreCandidateIsolationInput>()),
                    |n, path| n.checked_add(path.capacity()),
                )
                .ok_or(DesktopRestoreError::CapacityExceeded)?;
            session
                .settle_capacity(memory, actual_memory as u64)
                .map_err(&mut retain)?;
            // The verified staging owner already exclusively created the root
            // and materials directories; only the four candidate write roots
            // are created here. The same owner keeps staging read-only inputs.
            for index in 1..=4 {
                let parent = self.staging.generation_root();
                let name = std::ffi::OsStr::new(GENERATION_CHILDREN[index - 1]);
                require_effect()?;
                self.space = Some(rustix::fs::fstatvfs(parent));
                require_effect()?;
                let space = self
                    .space
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(DesktopRestoreError::IoFailure)?;
                let allocation = space.f_frsize.max(space.f_bsize);
                if allocation == 0 {
                    return Err(DesktopRestoreError::CapacityExceeded);
                }
                let count = session
                    .admit_capacity(RestoreCapacityResource::MaterialDirectories, 1)
                    .map_err(&mut retain)?;
                let parent_growth = session
                    .admit_storage_before(parent, allocation, RestoreStorageKind::Working, effect)
                    .map_err(&mut retain)?;
                let storage = session
                    .admit_new_child_before(
                        parent,
                        name,
                        allocation,
                        RestoreNewChildKind::Directory,
                        effect,
                    )
                    .map_err(&mut retain)?;
                require_effect()?;
                self.created = Some(rustix::fs::mkdirat(
                    parent,
                    name,
                    Mode::from_bits_truncate(0o700),
                ));
                require_effect()?;
                if !matches!(self.created, Some(Ok(()))) {
                    return Err(DesktopRestoreError::InputInvalid);
                }
                self.opened = Some(
                    rustix::fs::openat(
                        parent,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map(File::from)
                    .map_err(io::Error::from),
                );
                require_effect()?;
                let child = self
                    .opened
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(DesktopRestoreError::IoFailure)?;
                session
                    .settle_new_child_before(storage, parent, child, effect)
                    .map_err(&mut retain)?;
                session
                    .settle_storage_before(parent_growth, parent, effect)
                    .map_err(&mut retain)?;
                self.synced = Some(child.sync_all());
                require_effect()?;
                if !matches!(self.synced, Some(Ok(()))) {
                    return Err(DesktopRestoreError::IoFailure);
                }
                self.synced = Some(parent.sync_all());
                require_effect()?;
                if !matches!(self.synced, Some(Ok(()))) {
                    return Err(DesktopRestoreError::IoFailure);
                }
                self.directories[index] = Some(
                    self.opened
                        .take()
                        .expect("original candidate directory open observed")
                        .expect("original candidate directory open checked"),
                );
                session.settle_capacity(count, 1).map_err(&mut retain)?;
            }
            Ok(())
        })();
        if let Err(fault) = result {
            self.first_fault.get_or_insert(fault);
        }
        result
    }

    /// Copy only the authenticated PostgreSQL files. Captured executable
    /// configuration is never installed in the candidate.
    pub(super) fn prepare_postgres(
        &mut self,
        session: &mut RestoreControlSession,
    ) -> Result<(), DesktopRestoreError> {
        if self.prepared || self.first_fault.is_some() || self.directories[1].is_none() || self.isolation.is_none() {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        let result = (|| {
            use openbot_domain::backup::WholePgMaterialKind as K;
            let materials = self.staging.manifest().materials();
            let mut directories = PG17_DIRECTORIES.len();
            let mut path_bytes = 0usize;
            for material in materials {
                if matches!(material.kind, K::PostgresBase | K::WalSegment) {
                    let depth = material.relative_path.bytes().filter(|b| *b == b'/').count();
                    directories = directories.checked_add(depth).ok_or(DesktopRestoreError::CapacityExceeded)?;
                    path_bytes = material.relative_path.len().checked_mul(depth + 1)
                        .and_then(|n| path_bytes.checked_add(n)).ok_or(DesktopRestoreError::CapacityExceeded)?;
                }
            }
            let files = materials.len().checked_add(4).ok_or(DesktopRestoreError::CapacityExceeded)?;
            let config_bytes = self.paths[4].as_os_str().len().checked_mul(4)
                .and_then(|n| n.checked_add(2048)).ok_or(DesktopRestoreError::CapacityExceeded)?;
            let memory = directories.checked_mul(std::mem::size_of::<CandidateDirectory>())
                .and_then(|n| n.checked_add(files.checked_mul(std::mem::size_of::<File>())?))
                .and_then(|n| n.checked_add(path_bytes.checked_mul(4)?))
                .and_then(|n| n.checked_add(config_bytes))
                .and_then(|n| n.checked_add(65536 + 4096))
                .ok_or(DesktopRestoreError::CapacityExceeded)?;
            let reservation = session.admit_capacity(RestoreCapacityResource::MetadataBytes, memory as u64)
                .map_err(|e| self.keep_control(e))?;
            self.copied_directories.try_reserve_exact(directories).map_err(|_| DesktopRestoreError::CapacityExceeded)?;
            self.copied_files.try_reserve_exact(files).map_err(|_| DesktopRestoreError::CapacityExceeded)?;
            self.copy_buffer.try_reserve_exact(65536).map_err(|_| DesktopRestoreError::CapacityExceeded)?;
            self.copy_buffer.resize(65536, 0);
            self.config.try_reserve_exact(config_bytes).map_err(|_| DesktopRestoreError::CapacityExceeded)?;
            let allocated = self.copied_directories.capacity().checked_mul(std::mem::size_of::<CandidateDirectory>())
                .and_then(|n| n.checked_add(self.copied_files.capacity().checked_mul(std::mem::size_of::<File>())?))
                .and_then(|n| n.checked_add(self.copy_buffer.capacity()))
                .and_then(|n| n.checked_add(self.config.capacity()))
                .and_then(|n| n.checked_add(path_bytes.checked_mul(4)?))
                .and_then(|n| n.checked_add(4096))
                .ok_or(DesktopRestoreError::CapacityExceeded)?;
            if allocated > memory { return Err(DesktopRestoreError::CapacityExceeded); }
            // The UDS path comes from the original generated component. Quote
            // it as a PostgreSQL literal, without accepting any restored GUC.
            let socket = self.paths[4].to_str().ok_or(DesktopRestoreError::EntryInvalid)?;
            use std::fmt::Write;
            self.config.push_str("listen_addresses = ''\nport = 5432\nunix_socket_directories = '");
            for c in socket.chars() {
                if matches!(c, '\'' | '\\') { self.config.push(c); }
                self.config.push(c);
            }
            self.config.push_str("'\nunix_socket_permissions = 0600\nshared_preload_libraries = ''\nsession_preload_libraries = ''\nlocal_preload_libraries = ''\narchive_mode = off\narchive_command = ''\narchive_library = ''\nrestore_command = ''\nrecovery_end_command = ''\narchive_cleanup_command = ''\nprimary_conninfo = ''\nprimary_slot_name = ''\nssl = off\nlogging_collector = off\nlog_statement = 'none'\nlog_min_error_statement = panic\nshared_memory_type = mmap\ndynamic_shared_memory_type = mmap\n");
            writeln!(&mut self.config, "temp_tablespaces = ''").map_err(|_| DesktopRestoreError::CapacityExceeded)?;
            for relative in PG17_DIRECTORIES {
                self.ensure_directory(relative, session)?;
            }
            for ordinal in 0..self.staging.manifest().materials().len() {
                let material = &self.staging.manifest().materials()[ordinal];
                if !matches!(material.kind, K::PostgresBase | K::WalSegment) { continue; }
                let length = material.plain_len;
                // S17 parsed/closed this path once. This strips its fixed
                // authenticated namespace; it does not re-authorize a path.
                let relative = material.relative_path.strip_prefix("pgdata/").expect("authenticated PG material namespace").to_owned();
                if ["standby.signal", "recovery.signal", "recovery.conf"].contains(&relative.as_str())
                    || (relative == "tablespace_map" && length != 0)
                {
                    return Err(DesktopRestoreError::InputInvalid);
                }
                self.write_file(&relative, Some(ordinal), &[], session)?;
            }
            // Move the same allocation across the mutable I/O borrow, including
            // failure, rather than allocating another configuration copy.
            let config = std::mem::take(&mut self.config);
            let written = self.write_file("postgresql.conf", None, config.as_bytes(), session);
            self.config = config;
            written?;
            self.write_file("pg_hba.conf", None, b"local all desktop_admin scram-sha-256\nlocal all all reject\nlocal replication all reject\n", session)?;
            self.write_file("pg_ident.conf", None, b"", session)?;
            self.write_file("postgresql.auto.conf", None, b"", session)?;
            let actual = self.copied_directories.capacity().checked_mul(std::mem::size_of::<CandidateDirectory>())
                .and_then(|n| n.checked_add(self.copied_files.capacity().checked_mul(std::mem::size_of::<File>())?))
                .and_then(|n| n.checked_add(self.copy_buffer.capacity()))
                .and_then(|n| n.checked_add(self.config.capacity()))
                .and_then(|n| self.copied_directories.iter().try_fold(n, |n, d| n.checked_add(d.relative.capacity())))
                .ok_or(DesktopRestoreError::CapacityExceeded)?;
            session.settle_capacity(reservation, actual as u64).map_err(|e| self.keep_control(e))?;
            self.prepared = true;
            Ok(())
        })();
        if let Err(fault) = result { self.first_fault.get_or_insert(fault); }
        result
    }

    fn keep_control(&mut self, error: RecoveryControlError) -> DesktopRestoreError {
        let fault = DesktopRestoreError::from_control(&error);
        self.control_error = Some(error);
        fault
    }

    /// Receive the runner's original owner only after matching the actual
    /// generation inode. This retains failures together with the live Child;
    /// it does not mint an Infra candidate binding.
    pub(super) fn retain_program(
        &mut self,
        original: &mut Option<RestoreProgramOwner>,
    ) -> Result<(), DesktopRestoreError> {
        if !self.prepared || self.program.is_some() || self.waiting.is_some() || self.program_result.is_some() {
            // The caller still holds its original owner on this refusal.
            return Err(DesktopRestoreError::EntryInvalid);
        }
        self.program = Some(original.take().ok_or(DesktopRestoreError::EntryInvalid)?);
        let result = (|| {
            self.effect()?;
            self.metadata = Some(self.staging.generation_root().metadata());
            self.effect()?;
            let metadata = self.metadata.as_ref().and_then(|r| r.as_ref().ok()).ok_or(DesktopRestoreError::IoFailure)?;
            let original = self.program.as_ref().expect("original program retained");
            if original.generation_identity() != &[metadata.dev(), metadata.ino(), u64::from(metadata.uid())]
                || original.original_identity().is_err()
                || original.post_directories().is_err()
                || original.post_software().is_err()
            { return Err(DesktopRestoreError::IsolationUnproven); }
            Ok(())
        })();
        if let Err(fault) = result { self.first_fault.get_or_insert(fault); }
        result
    }

    pub(super) fn request_stop(&mut self) -> Result<(), DesktopRestoreError> {
        let clock = self.clock.as_ref().ok_or(DesktopRestoreError::EntryInvalid)?;
        let original = self.program.as_mut().ok_or(DesktopRestoreError::EntryInvalid)?;
        match runner::request_restore_stop(original, clock) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.program_failure = Some(error);
                self.first_fault.get_or_insert(DesktopRestoreError::ClosureUnproven);
                Err(DesktopRestoreError::ClosureUnproven)
            }
        }
    }

    /// Move the same session and clock into the resident original wait future.
    /// Cancelling observe_wait leaves that future and all original handles here.
    pub(super) fn begin_wait(&mut self, session: &mut Option<RestoreControlSession>) -> Result<(), DesktopRestoreError> {
        if self.program.is_none()
            || self.clock.is_none() || self.waiting.is_some() || self.returned_session.is_some() {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        let deadline = self.convergence_deadline.ok_or(DesktopRestoreError::EntryInvalid)?;
        let session_ref = session.as_mut().ok_or(DesktopRestoreError::EntryInvalid)?;
        if session_ref.operation_id() != self.staging.candidate_plan().operation_id() {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        if self.wait_memory.is_none() { return Err(DesktopRestoreError::EntryInvalid); }
        let future = original_wait(
            self.program.take().expect("original program checked"),
            self.clock.take().expect("original clock checked"),
            session.take().expect("original session checked"),
            deadline,
        );
        self.waiting = Some(Box::pin(future));
        Ok(())
    }

    pub(super) async fn observe_wait(&mut self) -> Result<&RestoreProgramResult, DesktopRestoreError> {
        let (result, session, clock, error) = self.waiting.as_mut().ok_or(DesktopRestoreError::EntryInvalid)?.as_mut().await;
        self.program_result = Some(result);
        self.returned_session = Some(session);
        self.wait_capacity_error = error;
        self.clock = Some(clock);
        self.waiting = None;
        let actual = original_wait_size(original_wait)
            .and_then(|bytes| bytes.checked_sub(runner::RESTORE_JOIN_RETAINED_BYTES))
            .and_then(|bytes| bytes.checked_add(self.program_result.as_ref()?.retained_join_bytes()?))
            .ok_or(DesktopRestoreError::CapacityExceeded)?;
        let reservation = self.wait_memory.take().expect("original wait admission retained");
        let settled = self.returned_session.as_mut().expect("original session returned")
            .settle_capacity(reservation, actual as u64);
        if let Err(error) = settled {
            let fault = self.keep_control(error);
            self.first_fault.get_or_insert(fault);
            return Err(fault);
        }
        if let Some(error) = self.wait_capacity_error.as_ref() {
            let fault = DesktopRestoreError::from_control(error);
            self.first_fault.get_or_insert(fault);
            return Err(fault);
        }
        // The raw wait/pipe result remains resident. Its arrival alone is not
        // a successful closure receipt or authority for a later effect.
        Ok(self.program_result.as_ref().expect("original wait result retained"))
    }

    pub(super) fn take_wait_session(&mut self) -> Option<RestoreControlSession> {
        self.returned_session.take()
    }

    pub(super) fn original_program(&self) -> Option<&RestoreProgramOwner> {
        self.program.as_ref()
    }

    pub(super) fn staging(&self) -> &VerifiedWholePgRestoreStaging {
        &self.staging
    }

    pub(super) fn isolation_input(&self) -> Option<&RestoreCandidateIsolationInput> {
        self.isolation.as_ref()
    }

    pub(super) fn install_target_slots(
        &mut self,
        session: &mut RestoreControlSession,
        store: &dyn crate::os_secret_store::OsSecretStore,
    ) -> Result<(), DesktopRestoreError> {
        if !self.prepared || self.first_fault.is_some() { return Err(DesktopRestoreError::EntryInvalid); }
        // This does not clear a Pending Isolation. The original KeySlot
        // adapter must admit this stage, or retain/refuse it before store IO.
        super::slots::install_target_slots_before(&mut self.target_slots, &self.staging, session, store)
    }

    pub(super) fn data_directory(&self) -> Option<(&File, &std::path::Path)> {
        self.directories[1].as_ref().map(|file| (file, self.paths[1].as_path()))
    }

    pub(super) fn socket_directory(&self) -> Option<(&File, &std::path::Path)> {
        self.directories[4].as_ref().map(|file| (file, self.paths[4].as_path()))
    }

    fn effect(&mut self) -> Result<Instant, DesktopRestoreError> {
        if let Err(error) = self.clock.as_ref().ok_or(DesktopRestoreError::EntryInvalid)?.permit_effect() {
            let fault = if matches!(error, MaintenanceError::DeadlineExpired) { DesktopRestoreError::EffectExpired } else { DesktopRestoreError::OwnerLost };
            self.clock_error = Some(error);
            return Err(fault);
        }
        self.effect_deadline.ok_or(DesktopRestoreError::EntryInvalid)
    }

    fn ensure_directory(&mut self, relative: &str, session: &mut RestoreControlSession) -> Result<Option<usize>, DesktopRestoreError> {
        let mut parent = None;
        let mut end = 0;
        for component in relative.split('/') {
            end += component.len();
            let path = &relative[..end];
            if let Some(index) = self.copied_directories.iter().position(|d| d.relative == path) {
                parent = Some(index);
                end += 1;
                continue;
            }
            let deadline = self.effect()?;
            let directory = candidate_parent(&self.directories, &self.copied_directories, parent);
            self.space = Some(rustix::fs::fstatvfs(directory));
            let grain = self.space.as_ref().and_then(|r| r.as_ref().ok()).map(|s| s.f_frsize.max(s.f_bsize)).filter(|n| *n > 0).ok_or(DesktopRestoreError::IoFailure)?;
            let count = session.admit_capacity(RestoreCapacityResource::MaterialDirectories, 1).map_err(|e| self.keep_control(e))?;
            let directory = candidate_parent(&self.directories, &self.copied_directories, parent);
            let growth = session.admit_storage_before(directory, grain, RestoreStorageKind::Working, deadline);
            let growth = match growth { Ok(growth) => growth, Err(error) => return Err(self.keep_control(error)) };
            let child = session.admit_new_child_before(directory, std::ffi::OsStr::new(component), grain, RestoreNewChildKind::Directory, deadline);
            let child = match child { Ok(child) => child, Err(error) => return Err(self.keep_control(error)) };
            self.created = Some(rustix::fs::mkdirat(directory, component, Mode::from_bits_truncate(0o700)));
            self.effect()?;
            if !matches!(self.created, Some(Ok(()))) { return Err(DesktopRestoreError::IoFailure); }
            let directory = candidate_parent(&self.directories, &self.copied_directories, parent);
            self.opened = Some(rustix::fs::openat(directory, component, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map(File::from).map_err(io::Error::from));
            self.effect()?;
            let directory = candidate_parent(&self.directories, &self.copied_directories, parent);
            let file = self.opened.as_ref().and_then(|r| r.as_ref().ok()).ok_or(DesktopRestoreError::IoFailure)?;
            let settled = session.settle_new_child_before(child, directory, file, deadline).and_then(|_| session.settle_storage_before(growth, directory, deadline));
            if let Err(error) = settled { return Err(self.keep_control(error)); }
            self.synced = Some(file.sync_all().and_then(|_| directory.sync_all()));
            self.effect()?;
            if !matches!(self.synced, Some(Ok(()))) { return Err(DesktopRestoreError::IoFailure); }
            self.copied_directories.push(CandidateDirectory { relative: path.to_owned(), file: self.opened.take().expect("retained original directory open").expect("observed directory open") });
            parent = Some(self.copied_directories.len() - 1);
            session.settle_capacity(count, 1).map_err(|e| self.keep_control(e))?;
            end += 1;
        }
        Ok(parent)
    }

    fn write_file(&mut self, relative: &str, ordinal: Option<usize>, bytes: &[u8], session: &mut RestoreControlSession) -> Result<(), DesktopRestoreError> {
        let (parent, name) = match relative.rsplit_once('/') {
            Some((parent, name)) => (self.ensure_directory(parent, session)?, name),
            None => (None, relative),
        };
        let length = ordinal.map_or(bytes.len() as u64, |ordinal| self.staging.manifest().materials()[ordinal].plain_len);
        let deadline = self.effect()?;
        let resource = if ordinal.is_some_and(|ordinal| self.staging.manifest().materials()[ordinal].kind == openbot_domain::backup::WholePgMaterialKind::WalSegment) {
            RestoreCapacityResource::CandidateWalBytes
        } else { RestoreCapacityResource::CandidateDataBytes };
        let capacity = session.admit_capacity(resource, length).map_err(|e| self.keep_control(e))?;
        let directory = candidate_parent(&self.directories, &self.copied_directories, parent);
        self.space = Some(rustix::fs::fstatvfs(directory));
        let grain = self.space.as_ref().and_then(|r| r.as_ref().ok()).map(|s| s.f_frsize.max(s.f_bsize)).filter(|n| *n > 0).ok_or(DesktopRestoreError::IoFailure)?;
        let allocation = length.checked_add(grain - 1).and_then(|n| n.checked_div(grain)).and_then(|n| n.checked_mul(grain)).and_then(|n| n.checked_add(grain)).ok_or(DesktopRestoreError::CapacityExceeded)?;
        let count = session.admit_capacity(RestoreCapacityResource::MaterialFiles, 1).map_err(|e| self.keep_control(e))?;
        let directory = candidate_parent(&self.directories, &self.copied_directories, parent);
        let storage = session.admit_new_child_before(directory, std::ffi::OsStr::new(name), allocation, RestoreNewChildKind::File, deadline);
        let storage = match storage { Ok(storage) => storage, Err(error) => return Err(self.keep_control(error)) };
        let directory = candidate_parent(&self.directories, &self.copied_directories, parent);
        let growth = session.admit_storage_before(directory, grain, RestoreStorageKind::Working, deadline);
        let growth = match growth { Ok(growth) => growth, Err(error) => return Err(self.keep_control(error)) };
        self.opened = Some(rustix::fs::openat(directory, name, OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::from_bits_truncate(0o600)).map(File::from).map_err(io::Error::from));
        self.effect()?;
        let mut offset = 0u64;
        while offset < length {
            self.effect()?;
            let count = (length - offset).min(self.copy_buffer.len() as u64) as usize;
            if let Some(ordinal) = ordinal {
                let source = self.staging.material_file(ordinal).expect("authenticated nonsecret staging FD");
                self.read = Some(source.read_at(&mut self.copy_buffer[..count], offset));
                self.effect()?;
            } else {
                self.copy_buffer[..count].copy_from_slice(&bytes[offset as usize..offset as usize + count]);
                self.read = Some(Ok(count));
            }
            let count = *self.read.as_ref().and_then(|r| r.as_ref().ok()).filter(|n| **n != 0).ok_or(DesktopRestoreError::IoFailure)?;
            let mut at = 0usize;
            while at < count {
                let file = self.opened.as_ref().and_then(|r| r.as_ref().ok()).ok_or(DesktopRestoreError::IoFailure)?;
                self.written = Some(file.write_at(&self.copy_buffer[at..count], offset + at as u64));
                self.effect()?;
                at += *self.written.as_ref().and_then(|r| r.as_ref().ok()).filter(|n| **n != 0).ok_or(DesktopRestoreError::IoFailure)?;
            }
            offset += count as u64;
        }
        let file = self.opened.as_ref().and_then(|r| r.as_ref().ok()).ok_or(DesktopRestoreError::IoFailure)?;
        self.synced = Some(file.sync_all());
        self.effect()?;
        if !matches!(self.synced, Some(Ok(()))) { return Err(DesktopRestoreError::IoFailure); }
        let directory = candidate_parent(&self.directories, &self.copied_directories, parent);
        let file = self.opened.as_ref().and_then(|r| r.as_ref().ok()).expect("retained file observed");
        let settled = session.settle_new_child_before(storage, directory, file, deadline).and_then(|_| session.settle_storage_before(growth, directory, deadline));
        if let Err(error) = settled { return Err(self.keep_control(error)); }
        self.synced = Some(directory.sync_all());
        self.effect()?;
        if !matches!(self.synced, Some(Ok(()))) { return Err(DesktopRestoreError::IoFailure); }
        self.copied_files.push(self.opened.take().expect("retained candidate file").expect("observed candidate file"));
        session.settle_capacity(count, 1).map_err(|e| self.keep_control(e))?;
        session.settle_capacity(capacity, length).map_err(|e| self.keep_control(e))?;
        Ok(())
    }
}

fn candidate_parent<'a>(roots: &'a [Option<File>; 6], directories: &'a [CandidateDirectory], parent: Option<usize>) -> &'a File {
    match parent { Some(index) => &directories[index].file, None => roots[1].as_ref().expect("original candidate data root") }
}

fn original_wait_size<F: Future>(_: fn(RestoreProgramOwner, OperationClock, RestoreControlSession, Instant) -> F) -> Option<usize> {
    std::mem::size_of::<F>().checked_add(runner::RESTORE_JOIN_RETAINED_BYTES)
}

async fn original_wait(original: RestoreProgramOwner, clock: OperationClock, mut session: RestoreControlSession, deadline: Instant) -> OriginalWaitResult {
    let mut error = None;
    let result = runner::wait_restore_program(original, &clock, || {
        session.check_capacity_before(deadline).map_err(|original| {
            error = Some(original);
            MaintenanceError::CapacityExceeded
        })
    }, true).await;
    (result, session, clock, error)
}
