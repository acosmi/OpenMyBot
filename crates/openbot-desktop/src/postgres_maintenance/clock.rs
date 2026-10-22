//! Original same-process, same-boot CLOCK_MONOTONIC operation deadlines.
use std::time::Duration;

use super::MaintenanceError;

pub(crate) struct OperationClock {
    owner_pid: u32,
    t0: u64,
    effect: u64,
    convergence: u64,
}

pub(crate) fn monotonic_ns() -> Result<u64, MaintenanceError> {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(t.tv_sec).map_err(|_| MaintenanceError::ClockUnavailable)?;
    let nanos = u64::try_from(t.tv_nsec).map_err(|_| MaintenanceError::ClockUnavailable)?;
    if nanos >= 1_000_000_000 {
        return Err(MaintenanceError::ClockUnavailable);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or(MaintenanceError::ClockOverflow)
}

impl OperationClock {
    pub(crate) fn start(effect_ns: u64, convergence_ns: u64) -> Result<Self, MaintenanceError> {
        if effect_ns == 0 || convergence_ns == 0 {
            return Err(MaintenanceError::ProfileInvalid);
        }
        let t0 = monotonic_ns()?;
        let effect = t0
            .checked_add(effect_ns)
            .ok_or(MaintenanceError::ClockOverflow)?;
        let convergence = effect
            .checked_add(convergence_ns)
            .ok_or(MaintenanceError::ClockOverflow)?;
        Ok(Self {
            owner_pid: std::process::id(),
            t0,
            effect,
            convergence,
        })
    }
    pub(crate) fn observed(&self) -> Result<u64, MaintenanceError> {
        let now = monotonic_ns()?;
        self.check_observation(std::process::id(), now)?;
        Ok(now)
    }
    pub(crate) fn check_observation(&self, pid: u32, now: u64) -> Result<(), MaintenanceError> {
        if pid != self.owner_pid || now < self.t0 {
            return Err(MaintenanceError::ClockUnavailable);
        }
        Ok(())
    }
    pub(crate) fn permit_effect(&self) -> Result<u64, MaintenanceError> {
        let now = self.observed()?;
        if now >= self.effect {
            return Err(MaintenanceError::DeadlineExpired);
        }
        Ok(now)
    }
    pub(crate) fn permit_closing_request(&self) -> Result<(), MaintenanceError> {
        if self.observed()? >= self.convergence {
            return Err(MaintenanceError::ClosingPending);
        }
        Ok(())
    }
    pub(crate) fn effect_wait(&self) -> Result<Duration, MaintenanceError> {
        Ok(Duration::from_nanos(
            self.effect.saturating_sub(self.observed()?),
        ))
    }
    pub(crate) fn convergence_wait(&self) -> Result<Duration, MaintenanceError> {
        Ok(Duration::from_nanos(
            self.convergence.saturating_sub(self.observed()?),
        ))
    }
    pub(crate) fn t0(&self) -> u64 {
        self.t0
    }
    pub(crate) fn effect(&self) -> u64 {
        self.effect
    }
    pub(crate) fn convergence(&self) -> u64 {
        self.convergence
    }
    #[cfg(test)]
    pub(crate) fn from_test_observation(pid: u32, t0: u64, e: u64, c: u64) -> Self {
        Self {
            owner_pid: pid,
            t0,
            effect: e,
            convergence: c,
        }
    }
}
