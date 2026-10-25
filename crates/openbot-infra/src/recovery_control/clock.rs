//! One original live monotonic clock. Persisted observations cannot revive it.

use std::time::{Duration, Instant};

use wrok_bot_macos_process::{ProcessIdentity, ProcessObservationError};

use super::{RecoveryControlError, RecoveryControlFault};

pub(super) fn monotonic_ns() -> Result<u64, RecoveryControlError> {
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

/// Capture the existing native observer once for the original control owner.
/// This does not start an operation, create E/C, or grant initialization.
pub(super) fn capture_original_process() -> Result<ProcessIdentity, ProcessObservationError> {
    ProcessIdentity::capture(std::process::id())
}

/// evidence_bytes revalidates this same non-Clone observer before returning.
/// The original control owner retains this raw result before checking time.
pub(super) fn original_process_evidence(
    original: &ProcessIdentity,
) -> Result<[u8; 32], ProcessObservationError> {
    original.evidence_bytes()
}

/// Decode only the registered fixed native evidence. Configuration, a random
/// nonce and persisted DATA cannot provide process birth or a boot session.
pub(super) fn verify_process_evidence(
    evidence: &[u8; 32],
    expected: Option<(&str, u32, &super::journal::ProcessStart)>,
) -> Result<(), RecoveryControlError> {
    let pid = u32::from_be_bytes(evidence[..4].try_into().expect("fixed pid evidence"));
    let seconds = u64::from_be_bytes(evidence[4..12].try_into().expect("fixed seconds evidence"));
    let micros = u32::from_be_bytes(evidence[12..16].try_into().expect("fixed micros evidence"));
    let nanos = micros.checked_mul(1_000)
        .filter(|value| micros < 1_000_000 && *value < 1_000_000_000)
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
    if pid == 0 || pid != std::process::id() {
        return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
    }
    let mut boot = [0u8; 32];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in evidence[16..].iter().enumerate() {
        boot[2 * index] = HEX[usize::from(byte >> 4)];
        boot[2 * index + 1] = HEX[usize::from(byte & 15)];
    }
    if let Some((boot_identity, original_pid, start)) = expected {
        if boot_identity.as_bytes() != boot || original_pid != pid
            || start.seconds != seconds || start.nanos != nanos
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
        }
    }
    Ok(())
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
