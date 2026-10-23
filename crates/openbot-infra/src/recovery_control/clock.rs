//! One original live monotonic clock. Persisted observations cannot revive it.

use std::time::{Duration, Instant};

use super::{RecoveryControlError, RecoveryControlFault};

fn monotonic_ns() -> Result<u64, RecoveryControlError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
    let nanos = u64::try_from(now.tv_nsec)
        .map_err(|_| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
    if nanos >= 1_000_000_000 {
        return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))
}

/// Private live owner. It is deliberately not Clone, Serde or reconstructible.
pub(super) struct OperationClock {
    started: Instant,
    effect: Instant,
    convergence: Instant,
    t0_ns: u64,
    effect_ns: u64,
    convergence_ns: u64,
}

impl OperationClock {
    /// Called once after the original locks, frozen intent and profile.
    pub(super) fn start(
        effect_ns: u64,
        convergence_ns: u64,
    ) -> Result<Self, RecoveryControlError> {
        if effect_ns == 0 || convergence_ns == 0 {
            return Err(RecoveryControlError::new(RecoveryControlFault::ProfileInvalid));
        }
        let t0_ns = monotonic_ns()?;
        let effect_absolute = t0_ns
            .checked_add(effect_ns)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
        let convergence_absolute = effect_absolute
            .checked_add(convergence_ns)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
        let started = Instant::now();
        let effect = started
            .checked_add(Duration::from_nanos(effect_ns))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
        let convergence = effect
            .checked_add(Duration::from_nanos(convergence_ns))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
        Ok(Self {
            started,
            effect,
            convergence,
            t0_ns,
            effect_ns: effect_absolute,
            convergence_ns: convergence_absolute,
        })
    }

    pub(super) fn require_effect(&self) -> Result<(), RecoveryControlError> {
        self.require(false)
    }

    pub(super) fn require_convergence(&self) -> Result<(), RecoveryControlError> {
        self.require(true)
    }

    fn require(&self, closing: bool) -> Result<(), RecoveryControlError> {
        let now = monotonic_ns()?;
        if now < self.t0_ns || Instant::now() < self.started {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        let (native, portable) = if closing {
            (self.convergence_ns, self.convergence)
        } else {
            (self.effect_ns, self.effect)
        };
        if now >= native || Instant::now() >= portable {
            return Err(RecoveryControlError::new(if closing {
                RecoveryControlFault::ConvergenceExpired
            } else {
                RecoveryControlFault::EffectExpired
            }));
        }
        Ok(())
    }

    pub(super) fn effect_before(
        &self,
        original: Instant,
    ) -> Result<Instant, RecoveryControlError> {
        self.require_effect()?;
        if Instant::now() >= original {
            return Err(RecoveryControlError::new(RecoveryControlFault::EffectExpired));
        }
        Ok(original.min(self.effect))
    }

    pub(super) fn observations(&self) -> (u64, u64, u64) {
        (self.t0_ns, self.effect_ns, self.convergence_ns)
    }
}
