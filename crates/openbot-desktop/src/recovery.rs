//! Release-bound, pre-window restoration and current-installation confirmation.

mod candidate;
pub(crate) mod entry;
pub(crate) mod input;
mod slots;
#[cfg(test)]
pub(crate) mod tests;

pub use input::VerifiedRestoreEntry;
pub use entry::OwnedDesktopRestore;

/// Completed work or read-only descriptor DATA; never runtime authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreExecutionObservation {
    /// The verified descriptor is RestoreCurrent.
    Current,
    /// The original operation remains Pending.
    Pending,
    /// The original legacy adoption and its resource closure completed.
    OrdinaryAdopted,
    /// The original current-binding confirmation and closure completed.
    BindingReconfirmed,
}

impl RestoreExecutionObservation {
    /// Fixed public launcher result code without input or secret material.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "wrok_bot_restore_current",
            Self::Pending => "wrok_bot_restore_pending",
            Self::OrdinaryAdopted => "wrok_bot_ordinary_adopted",
            Self::BindingReconfirmed => "wrok_bot_binding_reconfirmed",
        }
    }
}

/// Run one verified request before any ordinary setup or window construction.
/// `actual` comes from the same App's Manager. The native branch consumes its
/// original AppHandle lazily; its main event loop remains alive through cleanup.
pub async fn run_restore_request(
    mut release: crate::desktop_release::VerifiedDesktopRelease,
    request_path: &std::path::Path,
    actual: openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot,
    app: impl FnOnce() -> tauri::AppHandle<tauri::Wry>,
) -> Result<RestoreExecutionObservation, DesktopRestoreError> {
    use openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthorityStore;
    use openbot_infra::recovery_control::{RecoveryRequestPurpose, RuntimeOwner};
    use openbot_infra::restore_reconfirmation::CancellationToken;
    let mut original = input::RestoreEntryInput::new();
    let program = std::env::current_exe().map_err(|_| DesktopRestoreError::EntryInvalid)?;
    let (control, intent) = original.verify(&mut release, actual.clone(), &program, request_path)?;
    let mut verified = VerifiedRestoreEntry { control, intent, original };
    match verified.intent.purpose() {
        RecoveryRequestPurpose::RestoreSameInstallation | RecoveryRequestPurpose::RestoreNewInstallation => {
            let mut owner = release.begin_restore(verified)?;
            match owner.execute().await {
                Err(DesktopRestoreError::OwnerLost) => owner.observe_original().await,
                outcome => outcome,
            }
        }
        RecoveryRequestPurpose::AdoptOrdinaryLegacy => {
            let config = release.into_runtime_config().map_err(|_| DesktopRestoreError::EntryInvalid)?;
            crate::tauri_background::execute_local_legacy_adoption(actual, config, verified).await
                .map(|_| RestoreExecutionObservation::OrdinaryAdopted)
                .map_err(|error| match error {
                    crate::tauri_background::DesktopLocalRuntimeError::RecoveryControl(error) => DesktopRestoreError::from_control(&error),
                    crate::tauri_background::DesktopLocalRuntimeError::ClosureUnproven
                    | crate::tauri_background::DesktopLocalRuntimeError::FailureCleanup => DesktopRestoreError::ClosureUnproven,
                    _ => DesktopRestoreError::EntryInvalid,
                })
        }
        RecoveryRequestPurpose::ReconfirmCurrentBinding => {
            let cancel = CancellationToken::new();
            let owners = [RuntimeOwner::PostgresSidecar, RuntimeOwner::SqlDriver,
                RuntimeOwner::ApplicationAssembly, RuntimeOwner::DesktopAgentRelay, RuntimeOwner::DesktopAgent];
            let (runtime, sql, convergence) = verified.control.enter_current_reconfirmation(
                &mut verified.intent, &DesktopLocalAuthorityStore::new(actual.clone()), &owners, cancel.clone(),
            ).map_err(|error| DesktopRestoreError::from_control(&error))?;
            let current = entry::OwnedVerifiedCurrentReconfirmationEntry::new(actual, runtime)?;
            let native = entry::MacLocalReconfirmation::new(app(), wrok_bot_macos_local_auth::ConfirmationLocale::English);
            let request = entry::OriginalLocalConfirmationRequest::new(native, sql.deadline(), convergence, cancel, sql)?;
            let result = release.reconfirm_restored_local_owner(current, request).await;
            // Keep the original request's held FD and complete bytes until all
            // native/PG results and the runtime close have returned.
            drop(verified);
            result.map(|_| RestoreExecutionObservation::BindingReconfirmed)
        }
    }
}

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
    pub(crate) fn from_control(error: &openbot_infra::recovery_control::RecoveryControlError) -> Self {
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
