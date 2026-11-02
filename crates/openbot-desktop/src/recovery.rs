//! Release-bound, pre-window restoration and current-installation confirmation.

mod candidate;
mod entry;
pub(crate) mod input;
#[cfg(test)]
mod tests;

pub use input::VerifiedRestoreEntry;

/// Fixed restoration failures; original resources and errors remain with their owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DesktopRestoreError {
    /// The original release, request or host entry could not be authenticated.
    #[error("wrok_bot_restore_entry_invalid")]
    EntryInvalid,
    /// An original runtime or writer still owns the installation.
    #[error("wrok_bot_restore_owner_busy")]
    OwnerBusy,
    /// The installation has no usable external initialization binding.
    #[error("wrok_bot_restore_initialization_required")]
    InitializationRequired,
    /// The held external control records are invalid or inconsistent.
    #[error("wrok_bot_restore_control_invalid")]
    ControlInvalid,
    /// The original carrier, key medium or material inventory is invalid.
    #[error("wrok_bot_restore_input_invalid")]
    InputInvalid,
    /// The explicit finite request profile is invalid.
    #[error("wrok_bot_restore_profile_invalid")]
    ProfileInvalid,
    /// An actual or planned resource exceeds the original capacity.
    #[error("wrok_bot_restore_capacity_exceeded")]
    CapacityExceeded,
    /// The original effect deadline has passed.
    #[error("wrok_bot_restore_effect_expired")]
    EffectExpired,
    /// The original convergence deadline has passed.
    #[error("wrok_bot_restore_convergence_expired")]
    ConvergenceExpired,
    /// The original native process, clock or held control owner was lost.
    #[error("wrok_bot_restore_owner_lost")]
    OwnerLost,
    /// The actual candidate process sandbox could not be established.
    #[error("wrok_bot_restore_isolation_unproven")]
    IsolationUnproven,
    /// The original database effect or acknowledgement is unknown.
    #[error("wrok_bot_restore_database_unknown")]
    DatabaseUnknown,
    /// The original secret-store operation or readback is unknown.
    #[error("wrok_bot_restore_key_store_unknown")]
    KeyStoreUnknown,
    /// An original process, pipe, driver or native observer has not closed.
    #[error("wrok_bot_restore_closure_unproven")]
    ClosureUnproven,
    /// The selected generation or descriptor publication is not proven.
    #[error("wrok_bot_restore_switch_unknown")]
    SwitchUnknown,
    /// A retained original file operation failed.
    #[error("wrok_bot_restore_io_failure")]
    IoFailure,
}

impl DesktopRestoreError {
    fn from_control(error: &openbot_infra::recovery_control::RecoveryControlError) -> Self {
        use openbot_infra::recovery_control::RecoveryControlFault as Fault;
        match error.fault() {
            Fault::EntryInvalid => Self::EntryInvalid,
            Fault::OwnerBusy => Self::OwnerBusy,
            Fault::InitializationRequired => Self::InitializationRequired,
            Fault::ControlInvalid => Self::ControlInvalid,
            Fault::InputInvalid => Self::InputInvalid,
            Fault::ProfileInvalid => Self::ProfileInvalid,
            Fault::CapacityExceeded => Self::CapacityExceeded,
            Fault::EffectExpired => Self::EffectExpired,
            Fault::ConvergenceExpired => Self::ConvergenceExpired,
            Fault::OwnerLost => Self::OwnerLost,
            Fault::ClosureUnproven => Self::ClosureUnproven,
            Fault::DatabaseUnknown => Self::DatabaseUnknown,
            Fault::IoFailure => Self::IoFailure,
            Fault::KeyUnverified => Self::KeyStoreUnknown,
        }
    }
}
