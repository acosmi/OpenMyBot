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

use super::DesktopRestoreError;

// The original native adapter observes retirement at this interval; it is not a deadline.
const NATIVE_OBSERVATION_INTERVAL: Duration = Duration::from_millis(25);

struct OriginalMainObservation {
    monitor: Option<Result<MonitorHandle, MonitorError>>,
    cleanup: Option<Result<CleanupReceipt, MonitorError>>,
    installation_expired: bool,
}

/// Resources of one persisted confirmation request, never a fresh-actor token.
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
    /// already durable and the caller still holds the original Current writer.
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
        if let Some(Ok(attempt)) = &self.attempt {
            if !attempt.is_stopped() {
                attempt.cancel();
            }
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
