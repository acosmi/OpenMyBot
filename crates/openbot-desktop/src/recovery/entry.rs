//! Original restoration stages and the pre-window native confirmation owner.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::oneshot;
use wrok_bot_macos_local_auth::{
    ConfirmationLocale, LocalAuthAttempt, LocalAuthConfirmation, LocalAuthOutcome,
    LocalAuthStartError, MacLocalAuthOwner,
    session::{self, CleanupReceipt, Invalidation, MonitorError, MonitorHandle},
};

use openbot_infra::auth::single_user::desktop_local::{CurrentOsUserAppDataRoot, RestoredLocalSite};
use openbot_infra::recovery_control::RecoveryRuntimeOwner;
use openbot_infra::restore_reconfirmation::CancellationToken;

use super::DesktopRestoreError;

/// Linear owner of one release-bound restore and all original stage results.
/// Reopened operations carry only their bounded read-only observer.
pub struct OwnedDesktopRestore {
    bundle: crate::postgres_sidecar::VerifiedPostgresBundle,
    #[cfg(test)]
    test_store: Option<Arc<dyn crate::os_secret_store::OsSecretStore>>,
    #[cfg(test)]
    test_publication: Option<Arc<super::tests::PublicationTest>>,
    entry: Option<super::VerifiedRestoreEntry>,
    original: Option<super::input::RestoreEntryInput>,
    control: Option<openbot_infra::recovery_control::RecoveryControl>,
    session: Option<openbot_infra::recovery_control::RestoreControlSession>,
    reader: Option<openbot_infra::recovery_control::ReadOnlyRestoreOwner>,
    candidate: Option<super::candidate::CandidateGeneration>,
    input_failure: Option<openbot_infra::backup::whole_pg_restore_stream::RetainedRestoreInputFailure>,
    control_error: Option<openbot_infra::recovery_control::RecoveryControlError>,
    observer_error: Option<openbot_infra::recovery_control::RecoveryControlError>,
    first_fault: Option<DesktopRestoreError>,
    scram: Option<openbot_infra::backup::whole_pg_restore_stream::RestoreScramAcknowledged>,
    readbacks: Option<openbot_infra::backup::whole_pg_restore_stream::RestoreInstallationReadbacks>,
    completed: Option<super::RestoreExecutionObservation>,
}

impl OwnedDesktopRestore {
    pub(crate) fn new(
        release: crate::desktop_release::VerifiedDesktopRelease,
        entry: super::VerifiedRestoreEntry,
    ) -> Result<Self, DesktopRestoreError> {
        use openbot_infra::recovery_control::RecoveryRequestPurpose;
        let bootstrap = release.recovery.as_ref().ok_or(DesktopRestoreError::InitializationRequired)?;
        if !matches!(entry.intent.purpose(), RecoveryRequestPurpose::RestoreSameInstallation | RecoveryRequestPurpose::RestoreNewInstallation)
            || crate::desktop_release::decode_digest(entry.intent.expected().reviewed_release_digest()) != Some(bootstrap.release_digest)
        { return Err(DesktopRestoreError::EntryInvalid); }
        // Only the verified PG resources are needed after this transfer. UI,
        // tenant and normal-capture inputs retire before the restore's t0;
        // the verified entry retains the original release FD and pin.
        Ok(Self { bundle: release.postgres,
            #[cfg(test)]
            test_store: release.restore_test_store,
            #[cfg(test)]
            test_publication: release.restore_test_publication,
            entry: Some(entry), original: None, control: None, session: None,
            reader: None, candidate: None, input_failure: None, control_error: None, observer_error: None,
            first_fault: None, scram: None, readbacks: None, completed: None })
    }

    /// Execute once under the original session's E/C and finite capacity.
    /// Every failure retains its original resources and leaves publication Pending.
    pub async fn execute(&mut self) -> Result<super::RestoreExecutionObservation, DesktopRestoreError> {
        #[cfg(test)]
        if let Some(store) = self.test_store.as_ref().map(Arc::clone) {
            return self.execute_with_store(store.as_ref()).await;
        }
        let store = crate::desktop_release::DeferredCurrentUserKeychain::default();
        self.execute_with_store(&store).await
    }

    async fn execute_with_store(
        &mut self,
        store: &dyn crate::os_secret_store::OsSecretStore,
    ) -> Result<super::RestoreExecutionObservation, DesktopRestoreError> {
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as InputFault;
        use openbot_infra::backup::whole_pg_restore_stream::{RestoredClosedHistoryRequest, verify_whole_pg_restore_input};
        use openbot_infra::recovery_control::RestoreCapacityResource;
        if self.reader.is_some() { return Err(DesktopRestoreError::OwnerLost); }
        if let Some(done) = self.completed { return Ok(done); }
        if let Some(fault) = self.first_fault { return Err(fault); }
        let super::VerifiedRestoreEntry { control, intent, original } = self.entry.take().ok_or(DesktopRestoreError::OwnerLost)?;
        self.control = Some(control);
        self.original = Some(original);
        let profile = intent.restore_profile().ok_or(DesktopRestoreError::EntryInvalid)?.clone();
        let claimed = self.control.as_mut().expect("original control retained").claim_restore(intent, profile);
        match claimed {
            Ok(session) => self.session = Some(session),
            Err(error) => {
                let fault = DesktopRestoreError::from_control(&error);
                self.control_error = Some(error);
                if fault == DesktopRestoreError::OwnerBusy {
                    // Reuse the same once-parsed request. A live writer or an
                    // incomplete/mismatched journal still refuses this reader.
                    match self.control.as_mut().expect("original control retained").observe_unclaimed_restore() {
                        Ok(reader) => {
                            self.reader = Some(reader);
                            return Err(DesktopRestoreError::OwnerLost);
                        }
                        Err(error) => self.observer_error = Some(error),
                    }
                }
                self.first_fault = Some(fault);
                return Err(fault);
            }
        }
        let prepare = async {
            let session = self.session.as_mut().expect("original restore session");
            let original_error = &mut self.control_error;
            let mut retain = |error| {
                let fault = DesktopRestoreError::from_control(&error);
                *original_error = Some(error);
                fault
            };
            // The candidate, input and session account for their own bodies.
            // Pay the remaining driver custody before its first effect.
            let bytes = (std::mem::size_of::<Self>()
                - std::mem::size_of::<super::candidate::CandidateGeneration>()
                - std::mem::size_of::<openbot_infra::recovery_control::RestoreControlSession>()) as u64;
            let _memory = session.admit_capacity(RestoreCapacityResource::MetadataBytes, bytes).map_err(&mut retain)?;
            let (input, intent) = session.frozen_input().map_err(&mut retain)?;
            let staging = match verify_whole_pg_restore_input(input, intent, session).await {
                Ok(staging) => staging,
                Err(error) => {
                    let fault = match error.fault() {
                        InputFault::CapacityExceeded | InputFault::BoundsOverflow => DesktopRestoreError::CapacityExceeded,
                        InputFault::DeadlineExpired => DesktopRestoreError::EffectExpired,
                        InputFault::ClockUnavailable | InputFault::Cancelled => DesktopRestoreError::OwnerLost,
                        InputFault::IoFailure => DesktopRestoreError::IoFailure,
                        InputFault::ProfileMissing | InputFault::ProfileInvalid => DesktopRestoreError::ProfileInvalid,
                        _ => DesktopRestoreError::InputInvalid,
                    };
                    self.input_failure = Some(error);
                    return Err(fault);
                }
            };
            #[cfg(test)]
            if let Some(test) = &self.test_publication { test.observe_staging(&staging); }
            self.candidate = Some(super::candidate::CandidateGeneration::new(staging));
            let candidate = self.candidate.as_mut().expect("original candidate retained");
            candidate.prepare_directories(session)?;
            candidate.prepare_postgres(session)?;
            candidate.start_postgres(session, &self.bundle)?;
            candidate.bind_postgres(session, &self.bundle).await?;
            let deadline = candidate.effect_deadline()?;
            session.upgrade_candidate_schema_before(deadline).await.map_err(&mut retain)?;
            session.retire_cohort_before(deadline).await.map_err(&mut retain)?;
            session.clear_restored_closed_history_before(RestoredClosedHistoryRequest::new(deadline)).await.map_err(&mut retain)?;
            candidate.restore_artifacts(session, deadline).await?;
            candidate.install_target_slots(session, store)?;
            self.scram = Some(candidate.rotate_candidate_scram(session, deadline).await?);
            self.readbacks = Some(candidate.verify_target_installation(session, deadline).await?);
            candidate.release_candidate(session, deadline).await?;
            Ok(())
        }.await;
        if let Err(fault) = prepare { self.first_fault.get_or_insert(fault); }

        // Cleanup is driven by actual ownership, including a Child retained
        // after failed spawn post-checks. It never substitutes a fresh process.
        if let Some(candidate) = self.candidate.as_mut()
            && candidate.original_program().is_some() {
                if self.first_fault.is_some() {
                    self.session.as_mut().expect("original session before wait").abandon_candidate_connections();
                }
                if let Err(fault) = candidate.request_stop() { self.first_fault.get_or_insert(fault); }
                match candidate.begin_wait(&mut self.session) {
                    Ok(()) => {
                        if let Err(fault) = candidate.observe_wait().await { self.first_fault.get_or_insert(fault); }
                        self.session = candidate.take_wait_session();
                    }
                    Err(fault) => { self.first_fault.get_or_insert(fault); }
                }
            }
        if let Some(fault) = self.first_fault { return Err(fault); }
        let candidate = self.candidate.as_ref().ok_or(DesktopRestoreError::ClosureUnproven)?;
        let exit = candidate.program_result().and_then(|result| result.candidate_exit())
            .ok_or(DesktopRestoreError::ClosureUnproven)?;
        let deadline = candidate.effect_deadline()?;
        #[cfg(test)]
        if let Some(test) = &self.test_publication { test.before_publish(); }
        let published = self.session.as_mut().ok_or(DesktopRestoreError::ClosureUnproven)?
            .publish_restore_current_before(self.scram.take().ok_or(DesktopRestoreError::ClosureUnproven)?,
                self.readbacks.take().ok_or(DesktopRestoreError::ClosureUnproven)?, exit, deadline).await;
        #[cfg(test)]
        if let Some(test) = &self.test_publication { test.observe(self); }
        if let Err(error) = published {
            let fault = DesktopRestoreError::from_control(&error);
            self.control_error = Some(error);
            self.first_fault = Some(fault);
            return Err(fault);
        }
        self.completed = Some(super::RestoreExecutionObservation::Current);
        Ok(super::RestoreExecutionObservation::Current)
    }

    /// Original cumulative resource DATA, available only on the live owner.
    /// Reopened read-only handles never recreate a ledger.
    pub fn capacity_observation(&self, resource: openbot_infra::recovery_control::RestoreCapacityResource)
        -> Result<openbot_infra::recovery_control::RestoreCapacityObservation, DesktopRestoreError>
    {
        self.session.as_ref().ok_or(DesktopRestoreError::OwnerLost)?.capacity_observation(resource)
            .map_err(|error| DesktopRestoreError::from_control(&error))
    }

    /// Observe the original journal within the original host admission period.
    /// This never renews the restore budget or starts a candidate stage.
    pub async fn observe_original(&mut self) -> Result<super::RestoreExecutionObservation, DesktopRestoreError> {
        use openbot_infra::recovery_control::ActivationPhase;
        let reader = self.reader.as_mut().ok_or(DesktopRestoreError::OwnerLost)?;
        match reader.observe_original() {
            Ok(observation) => match observation.phase() {
                ActivationPhase::RestoreCurrent => Ok(super::RestoreExecutionObservation::Current),
                ActivationPhase::RestorePending | ActivationPhase::SwitchedPending => Ok(super::RestoreExecutionObservation::Pending),
                _ => Err(DesktopRestoreError::EntryInvalid),
            },
            Err(error) => {
                let fault = DesktopRestoreError::from_control(&error);
                self.control_error = Some(error);
                Err(fault)
            }
        }
    }
}

// The original native adapter observes retirement at this interval; it is not a deadline.
const NATIVE_OBSERVATION_INTERVAL: Duration = Duration::from_millis(25);

struct OriginalMainObservation {
    monitor: Option<Result<MonitorHandle, MonitorError>>,
    cleanup: Option<Result<CleanupReceipt, MonitorError>>,
    installation_expired: bool,
}

/// The verified entry of one `reconfirm_current_binding` request: the current
/// OS user's app-data root and the runtime its Current head enrolled, with the
/// restored generation that head selects (spec revision R484 ¶8087).
pub(crate) struct OwnedVerifiedCurrentReconfirmationEntry {
    pub(crate) runtime: RecoveryRuntimeOwner,
    pub(crate) site: RestoredLocalSite,
}

impl OwnedVerifiedCurrentReconfirmationEntry {
    /// Only a runtime whose published head is a restored Current forms an entry.
    pub(crate) fn new(
        app_data_root: CurrentOsUserAppDataRoot,
        runtime: RecoveryRuntimeOwner,
    ) -> Result<Self, DesktopRestoreError> {
        let site = runtime
            .restored_local_site(&app_data_root)
            .map_err(|error| DesktopRestoreError::from_control(&error))?
            .ok_or(DesktopRestoreError::EntryInvalid)?;
        Ok(Self { runtime, site })
    }
}

/// The two clocks of the one Confirmed proof an original request consumed.
#[derive(Clone, Copy)]
pub(crate) struct ConfirmedLocalOwner {
    pub(crate) at: Instant,
    pub(crate) wall: SystemTime,
}

/// One original OS confirmation: it runs once, closes its own native
/// resources before returning, and its Confirmed proof is taken at most once.
pub(crate) trait OriginalLocalConfirmation {
    async fn confirm_once(&mut self, effect: Instant, convergence: Instant) -> Result<(), DesktopRestoreError>;
    fn take_confirmation(&mut self) -> Result<ConfirmedLocalOwner, DesktopRestoreError>;
}

/// The real `MacLocalAuthOwner` owner, dispatched on the application's main
/// thread, with no window, AuthContext or token wrapper.
pub(crate) struct MacLocalReconfirmation {
    native: LocalReconfirmationNative,
    app: tauri::AppHandle<tauri::Wry>,
    locale: ConfirmationLocale,
}

impl MacLocalReconfirmation {
    pub(crate) fn new(app: tauri::AppHandle<tauri::Wry>, locale: ConfirmationLocale) -> Self {
        Self { native: LocalReconfirmationNative::new(), app, locale }
    }
}

impl OriginalLocalConfirmation for MacLocalReconfirmation {
    async fn confirm_once(&mut self, effect: Instant, convergence: Instant) -> Result<(), DesktopRestoreError> {
        self.native.confirm_once(&self.app, self.locale, effect, convergence).await
    }

    fn take_confirmation(&mut self) -> Result<ConfirmedLocalOwner, DesktopRestoreError> {
        let proof = self.native.take_confirmation()?;
        Ok(ConfirmedLocalOwner { at: proof.confirmed_at(), wall: proof.confirmed_at_wall() })
    }
}

/// One bounded original confirmation request: its native owner, its effect
/// and convergence deadlines and its cancellation.
pub(crate) struct OriginalLocalConfirmationRequest<N> {
    pub(crate) native: N,
    pub(crate) effect: Instant,
    pub(crate) convergence: Instant,
    pub(crate) cancel: CancellationToken,
    pub(crate) sql: openbot_infra::restore_reconfirmation::OriginalReconfirmationRequest,
}

impl<N: OriginalLocalConfirmation> OriginalLocalConfirmationRequest<N> {
    pub(crate) fn new(
        native: N,
        effect: Instant,
        convergence: Instant,
        cancel: CancellationToken,
        sql: openbot_infra::restore_reconfirmation::OriginalReconfirmationRequest,
    ) -> Result<Self, DesktopRestoreError> {
        if effect >= convergence {
            return Err(DesktopRestoreError::ProfileInvalid);
        }
        if Instant::now() >= effect {
            return Err(DesktopRestoreError::EffectExpired);
        }
        if sql.deadline() != effect { return Err(DesktopRestoreError::ProfileInvalid); }
        Ok(Self { native, effect, convergence, cancel, sql })
    }
}

/// Resources of one held confirmation request, never a fresh-actor token.
pub(super) struct LocalReconfirmationNative {
    owner: Option<Result<Arc<MacLocalAuthOwner>, LocalAuthStartError>>,
    attempt: Option<Result<LocalAuthAttempt, LocalAuthStartError>>,
    outcome: Option<LocalAuthOutcome>,
    main: Arc<Mutex<OriginalMainObservation>>,
    installation: Option<oneshot::Receiver<()>>,
    installation_observed: bool,
    cleanup: Option<oneshot::Receiver<()>>,
    install_dispatch: Option<Result<(), tauri::Error>>,
    cleanup_dispatch: Option<Result<(), tauri::Error>>,
    invalidated: Arc<AtomicBool>,
    first_fault: Option<DesktopRestoreError>,
}

impl LocalReconfirmationNative {
    pub(super) fn new() -> Self {
        Self {
            owner: None,
            attempt: None,
            outcome: None,
            main: Arc::new(Mutex::new(OriginalMainObservation {
                monitor: None,
                cleanup: None,
                installation_expired: false,
            })),
            installation: None,
            installation_observed: false,
            cleanup: None,
            install_dispatch: None,
            cleanup_dispatch: None,
            invalidated: Arc::new(AtomicBool::new(false)),
            first_fault: None,
        }
    }

    /// These deadlines project this request's original clock. Its intent is
    /// is still held and the caller holds the original Current enrollment.
    pub(super) async fn confirm_once(
        &mut self,
        app: &tauri::AppHandle<tauri::Wry>,
        locale: ConfirmationLocale,
        effect: Instant,
        convergence: Instant,
    ) -> Result<(), DesktopRestoreError> {
        if self.owner.is_some() || self.first_fault.is_some() {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        let original_start = Instant::now();
        let original_wall = SystemTime::now();
        let duration = effect
            .checked_duration_since(original_start)
            .ok_or(DesktopRestoreError::EffectExpired)?;
        if effect >= convergence {
            return Err(DesktopRestoreError::ProfileInvalid);
        }
        self.owner = Some(MacLocalAuthOwner::new().map(Arc::new));
        let observed = async {
            let owner = self
                .owner
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(DesktopRestoreError::ClosureUnproven)?;
            let main = Arc::clone(&self.main);
            let invalidated = Arc::clone(&self.invalidated);
            let native = Arc::downgrade(owner);
            let (sender, receiver) = oneshot::channel();
            self.installation = Some(receiver);
            self.install_dispatch = Some(app.run_on_main_thread(move || {
                if let Ok(mut observation) = main.lock() {
                    if Instant::now() >= effect {
                        observation.installation_expired = true;
                    } else {
                        observation.monitor = Some(session::start(move |event| {
                            // Focus loss clears existing grants in the original adapter;
                            // this pre-window request has no existing grant to clear.
                            if event.invalidation() == Invalidation::InvalidateAll {
                                invalidated.store(true, Ordering::SeqCst);
                                if let Some(owner) = native.upgrade() {
                                    owner.stop();
                                }
                            }
                        }));
                    }
                }
                let _ = sender.send(());
            }));
            if !matches!(self.install_dispatch, Some(Ok(()))) {
                return Err(DesktopRestoreError::ClosureUnproven);
            }
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(effect),
                self.installation
                    .as_mut()
                    .expect("original installation wait"),
            )
            .await
            .map_err(|_| DesktopRestoreError::EffectExpired)?
            .map_err(|_| DesktopRestoreError::ClosureUnproven)?;
            self.installation_observed = true;
            {
                let main = self
                    .main
                    .lock()
                    .map_err(|_| DesktopRestoreError::OwnerLost)?;
                if main.installation_expired
                    || !main
                        .monitor
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .is_some_and(MonitorHandle::is_live)
                    || self.invalidated.load(Ordering::SeqCst)
                {
                    return Err(DesktopRestoreError::ClosureUnproven);
                }
            }
            if Instant::now() >= effect {
                return Err(DesktopRestoreError::EffectExpired);
            }
            self.attempt = Some(owner.begin(locale));
            let attempt = self
                .attempt
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(DesktopRestoreError::ClosureUnproven)?;
            let mut previous = (original_start, original_wall);
            loop {
                let now = (Instant::now(), SystemTime::now());
                let mono = now
                    .0
                    .checked_duration_since(original_start)
                    .ok_or(DesktopRestoreError::OwnerLost)?;
                let wall = now
                    .1
                    .duration_since(original_wall)
                    .map_err(|_| DesktopRestoreError::OwnerLost)?;
                if now.0 < previous.0 || now.1 < previous.1 {
                    return Err(DesktopRestoreError::OwnerLost);
                }
                previous = now;
                if mono.max(wall) >= duration || now.0 >= effect {
                    return Err(DesktopRestoreError::EffectExpired);
                }
                if self.invalidated.load(Ordering::SeqCst) {
                    return Err(DesktopRestoreError::OwnerLost);
                }
                if let Some(outcome) = attempt.try_take_outcome() {
                    self.outcome = Some(outcome);
                    match self.outcome.as_ref() {
                        Some(LocalAuthOutcome::Confirmed(proof))
                            if proof.attempt_id() == attempt.id()
                                && proof.confirmed_at() >= original_start
                                && proof.confirmed_at() <= now.0
                                && proof.confirmed_at_wall() >= original_wall
                                && proof.confirmed_at_wall() <= now.1 =>
                        {
                            return Ok(());
                        }
                        _ => return Err(DesktopRestoreError::ClosureUnproven),
                    }
                }
                tokio::time::sleep_until(tokio::time::Instant::from_std(
                    effect.min(now.0 + NATIVE_OBSERVATION_INTERVAL),
                ))
                .await;
            }
        }
        .await;
        if let Err(fault) = observed {
            self.first_fault.get_or_insert(fault);
        }
        let closed = self.close_original(app, convergence).await;
        if let Err(fault) = closed {
            self.first_fault.get_or_insert(fault);
        }
        if self.invalidated.load(Ordering::SeqCst) {
            self.first_fault
                .get_or_insert(DesktopRestoreError::OwnerLost);
        }
        let final_mono = Instant::now();
        let final_wall = SystemTime::now();
        if final_mono >= effect
            || final_wall
                .duration_since(original_wall)
                .map_or(true, |elapsed| elapsed >= duration)
            || self.outcome.as_ref().is_some_and(|outcome| {
                matches!(outcome,
                LocalAuthOutcome::Confirmed(proof) if final_wall < proof.confirmed_at_wall())
            })
        {
            self.first_fault
                .get_or_insert(DesktopRestoreError::EffectExpired);
        }
        self.first_fault.map_or(Ok(()), Err)
    }

    async fn close_original(
        &mut self,
        app: &tauri::AppHandle<tauri::Wry>,
        convergence: Instant,
    ) -> Result<(), DesktopRestoreError> {
        if let Some(Ok(attempt)) = &self.attempt
            && !attempt.is_stopped() {
                attempt.cancel();
            }
        if let Some(Ok(owner)) = &self.owner {
            owner.stop();
        }
        if !self.installation_observed
            && matches!(self.install_dispatch, Some(Ok(())))
            && let Some(receiver) = &mut self.installation
        {
            tokio::time::timeout_at(tokio::time::Instant::from_std(convergence), receiver)
                .await
                .map_err(|_| DesktopRestoreError::ConvergenceExpired)?
                .map_err(|_| DesktopRestoreError::ClosureUnproven)?;
            self.installation_observed = true;
        }
        loop {
            if Instant::now() >= convergence {
                return Err(DesktopRestoreError::ConvergenceExpired);
            }
            let ticket = {
                let main = self
                    .main
                    .lock()
                    .map_err(|_| DesktopRestoreError::OwnerLost)?;
                if matches!(main.cleanup, None | Some(Err(MonitorError::Busy))) {
                    main.monitor
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .map(|monitor| {
                            monitor.close_callbacks();
                            monitor.cleanup_ticket()
                        })
                } else {
                    None
                }
            };
            if let Some(ticket) = ticket {
                let main = Arc::clone(&self.main);
                let (sender, receiver) = oneshot::channel();
                self.cleanup = Some(receiver);
                self.cleanup_dispatch = Some(app.run_on_main_thread(move || {
                    let result = ticket.cleanup_on_main_thread();
                    if let Ok(mut observation) = main.lock() {
                        observation.cleanup = Some(result);
                    }
                    let _ = sender.send(());
                }));
                if !matches!(self.cleanup_dispatch, Some(Ok(()))) {
                    return Err(DesktopRestoreError::ClosureUnproven);
                }
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(convergence),
                    self.cleanup.as_mut().expect("original cleanup wait"),
                )
                .await
                .map_err(|_| DesktopRestoreError::ConvergenceExpired)?
                .map_err(|_| DesktopRestoreError::ClosureUnproven)?;
            }
            let native_stopped = self.owner.as_ref().is_none_or(|result| match result {
                Ok(owner) => owner.is_stopped(),
                Err(_) => true,
            });
            let attempt_stopped = self.attempt.as_ref().is_none_or(|result| match result {
                Ok(attempt) => attempt.is_stopped(),
                Err(_) => true,
            });
            let removed = {
                let main = self
                    .main
                    .lock()
                    .map_err(|_| DesktopRestoreError::OwnerLost)?;
                match &main.monitor {
                    Some(Ok(monitor)) => {
                        monitor.is_removed() && matches!(main.cleanup, Some(Ok(_)))
                    }
                    Some(Err(_)) | None => true,
                }
            };
            if native_stopped && attempt_stopped {
                let main = self
                    .main
                    .lock()
                    .map_err(|_| DesktopRestoreError::OwnerLost)?;
                if matches!(main.cleanup, Some(Err(error)) if error != MonitorError::Busy) {
                    return Err(DesktopRestoreError::ClosureUnproven);
                }
                if removed {
                    return Ok(());
                }
            }
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                convergence.min(Instant::now() + NATIVE_OBSERVATION_INTERVAL),
            ))
            .await;
        }
    }

    pub(super) fn take_confirmation(
        &mut self,
    ) -> Result<LocalAuthConfirmation, DesktopRestoreError> {
        if self.first_fault.is_some() || self.invalidated.load(Ordering::SeqCst) {
            return Err(self.first_fault.unwrap_or(DesktopRestoreError::OwnerLost));
        }
        match self.outcome.take() {
            Some(LocalAuthOutcome::Confirmed(proof)) => Ok(proof),
            other => {
                self.outcome = other;
                Err(DesktopRestoreError::ClosureUnproven)
            }
        }
    }
}
