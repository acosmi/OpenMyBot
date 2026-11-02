//! The original operation's exclusively created candidate generation.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::Instant;

use openbot_infra::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging;
use openbot_infra::recovery_control::{
    RecoveryControlError, RestoreCapacityResource, RestoreControlSession, RestoreNewChildKind,
    RestoreStorageKind,
};
use rustix::fs::{Mode, OFlags};

use crate::postgres_maintenance::MaintenanceError;
use crate::postgres_maintenance::clock::OperationClock;

use super::DesktopRestoreError;

const GENERATION_CHILDREN: [&str; 5] = ["data", "wal", "temp", "uds", "materials"];

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
                            - std::mem::size_of::<VerifiedWholePgRestoreStaging>()),
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
                        - std::mem::size_of::<VerifiedWholePgRestoreStaging>()),
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
}
