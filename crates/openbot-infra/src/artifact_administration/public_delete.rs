//! Public deletion of one explicitly saved artifact by its current saving owner. Every call arms
//! the deletion (first call or the exact no-op replay), removes the stored bytes and completes the
//! tombstone with its one refund. A call never sleeps or polls: an unfinished step is answered
//! `Pending`, and the owner resumes it by sending the same deletion again, which that call's own
//! arm authorises again. Nothing here runs without it.
//!
//! Every receipt discloses that artifact text already injected into Run history stays until that
//! Thread's history is cleared. No other Thread is scanned, and `Deleted` claims no erasure of
//! database WAL or backups.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use openbot_contracts::artifacts::{
    ArtifactDeletionReceipt, ArtifactDeletionState, ArtifactInjectedCopies,
    canonical_artifact_uuid_v7,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::HostRequestBindingError;

use super::{
    ArmedArtifactCleanupIntent, ArtifactCleanupArmError as ArmError,
    ArtifactCleanupPhysicalError as PhysicalError, ArtifactCleanupPhysicalState,
    ArtifactCleanupTerminalError as TerminalError, PostgresArtifactAdministration,
};

/// The whole budget of one call. The arm, the removal and the completion keep their own 5 s caps
/// inside it.
const DELETION_BUDGET: Duration = Duration::from_secs(15);

/// This call's claim on advancing one artifact's deletion; dropping it, also on cancellation,
/// releases the artifact to the next call.
struct Advancing<'a> {
    deleting: &'a Mutex<HashSet<String>>,
    artifact_id: &'a str,
}

impl Drop for Advancing<'_> {
    fn drop(&mut self) {
        self.deleting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(self.artifact_id);
    }
}

/// Where one call stopped: at its arm, or after its confirmed arm.
enum Stop {
    Arm(ArmError),
    Remove(PhysicalError),
    Finalize(TerminalError),
}

impl PostgresArtifactAdministration {
    pub(super) async fn delete_explicit_saved(
        self: &Arc<Self>,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<ArtifactDeletionReceipt, AppError> {
        let artifact_id =
            canonical_artifact_uuid_v7(artifact_id).ok_or(AppError::MalformedPayload {
                field: "artifactId",
            })?;
        let deadline =
            Instant::now()
                .checked_add(DELETION_BUDGET)
                .ok_or(AppError::DependencyUnavailable {
                    dependency: "artifacts",
                })?;
        let state = match self
            .arm_explicit_saved_delete_before(auth, &artifact_id, deadline)
            .await
        {
            Ok(intent) => {
                // One call of this instance advances an artifact at a time. A second one would
                // collide with the first one's physical or terminal slot, which answers it unproven
                // and poisons an armed capture gate, so it answers Pending without a slot. This
                // call's own arm has authorised it before anything is answered.
                let claimed = self
                    .deleting
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(artifact_id.clone());
                if claimed {
                    let _advancing = Advancing {
                        deleting: &self.deleting,
                        artifact_id: &artifact_id,
                    };
                    self.advance_deletion(auth, &intent, deadline).await
                } else {
                    Ok(ArtifactDeletionState::Pending)
                }
            }
            Err(error) => Err(Stop::Arm(error)),
        }
        .or_else(deletion_outcome)?;
        Ok(ArtifactDeletionReceipt {
            artifact_id,
            state,
            injected_copies: ArtifactInjectedCopies::RetainedUntilThreadHistoryClear,
        })
    }

    /// Everything after this call's confirmed arm. The fence is durable here, so only corruption
    /// is final; every other stop is resumed by the same deletion.
    async fn advance_deletion(
        self: &Arc<Self>,
        auth: &AuthContext,
        intent: &ArmedArtifactCleanupIntent,
        deadline: Instant,
    ) -> Result<ArtifactDeletionState, Stop> {
        // The observation is dropped here: completion registers its own claim on the same key.
        let removed = self
            .remove_armed_explicit_saved_bytes_before(auth, intent, deadline)
            .await
            .map_err(Stop::Remove)?
            .state();
        if removed != ArtifactCleanupPhysicalState::DurableAbsent {
            return Ok(ArtifactDeletionState::Pending);
        }
        // Committed and AlreadyCompleted are both this deletion's completed tombstone.
        self.finalize_armed_explicit_saved_before(auth, intent, deadline)
            .await
            .map_err(Stop::Finalize)?;
        Ok(ArtifactDeletionState::Deleted)
    }
}

/// The public outcome of a refused step. Before a confirmed arm each refusal maps on its own;
/// after it only corruption is final and every other stop is `Pending`.
fn deletion_outcome(stop: Stop) -> Result<ArtifactDeletionState, AppError> {
    let unavailable = AppError::DependencyUnavailable {
        dependency: "artifacts",
    };
    match stop {
        Stop::Remove(PhysicalError::Corrupt { .. })
        | Stop::Finalize(TerminalError::Corrupt { .. }) => Err(unavailable),
        Stop::Remove(_) | Stop::Finalize(_) => Ok(ArtifactDeletionState::Pending),
        Stop::Arm(ArmError::InvalidInput { .. }) => Err(AppError::MalformedPayload {
            field: "artifactId",
        }),
        // The existing Host binding projection: a closed Host is unauthenticated, a missing or
        // unavailable binding is an unavailable dependency.
        Stop::Arm(ArmError::Host(HostRequestBindingError::NotCurrent)) => {
            Err(AppError::Unauthenticated)
        }
        Stop::Arm(ArmError::Host(
            HostRequestBindingError::Missing | HostRequestBindingError::Unavailable,
        )) => Err(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        }),
        Stop::Arm(ArmError::NotVisible) => Err(AppError::NotVisible),
        // Also a completed deletion: its record is no longer available.
        Stop::Arm(ArmError::Conflict) => Err(AppError::RequestConflict {
            resource: "artifact",
        }),
        // The fence is stored; this call stops here and a resend resumes it.
        Stop::Arm(ArmError::CommitAcknowledgedAfterDeadline) => Ok(ArtifactDeletionState::Pending),
        // The arm is idempotent per artifact, so a resend after an unknown commit is safe.
        Stop::Arm(
            ArmError::Unavailable
            | ArmError::Corrupt { .. }
            | ArmError::CommitUnknown
            | ArmError::RollbackAcknowledgedAfterDeadline,
        ) => Err(unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: [HostRequestBindingError; 3] = [
        HostRequestBindingError::Missing,
        HostRequestBindingError::NotCurrent,
        HostRequestBindingError::Unavailable,
    ];

    fn unavailable() -> Result<ArtifactDeletionState, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }

    #[test]
    fn arm_refusals_map_to_the_public_outcome_table() {
        let every = [
            ArmError::InvalidInput {
                field: "artifact_id",
            },
            ArmError::Host(HOST[0]),
            ArmError::Host(HOST[1]),
            ArmError::Host(HOST[2]),
            ArmError::NotVisible,
            ArmError::Conflict,
            ArmError::Unavailable,
            ArmError::Corrupt {
                field: "workspace_quota",
            },
            ArmError::CommitUnknown,
            ArmError::CommitAcknowledgedAfterDeadline,
            ArmError::RollbackAcknowledgedAfterDeadline,
        ];
        let host_unavailable = Err(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        });
        let expected = [
            Err(AppError::MalformedPayload {
                field: "artifactId",
            }),
            host_unavailable.clone(),
            Err(AppError::Unauthenticated),
            host_unavailable,
            Err(AppError::NotVisible),
            Err(AppError::RequestConflict {
                resource: "artifact",
            }),
            unavailable(),
            unavailable(),
            unavailable(),
            Ok(ArtifactDeletionState::Pending),
            unavailable(),
        ];
        for (error, expected) in every.into_iter().zip(expected) {
            assert_eq!(deletion_outcome(Stop::Arm(error)), expected, "{error:?}");
        }
        let statuses = every
            .into_iter()
            .map(|error| match deletion_outcome(Stop::Arm(error)) {
                Ok(_) => 202,
                Err(error) => error.http_status(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            statuses,
            [400, 503, 401, 503, 404, 409, 503, 503, 503, 202, 503]
        );
    }

    #[test]
    fn after_a_confirmed_arm_only_corruption_is_final() {
        let remove = [
            PhysicalError::InvalidInput {
                field: "artifact_id",
            },
            PhysicalError::Host(HOST[0]),
            PhysicalError::Host(HOST[1]),
            PhysicalError::Host(HOST[2]),
            PhysicalError::NotVisible,
            PhysicalError::Conflict,
            PhysicalError::Unavailable,
            PhysicalError::Corrupt {
                field: "record_pair",
            },
            PhysicalError::PhysicalUnproven,
            PhysicalError::RollbackAcknowledgedAfterDeadline,
        ];
        for error in remove {
            let expected = if matches!(error, PhysicalError::Corrupt { .. }) {
                unavailable()
            } else {
                Ok(ArtifactDeletionState::Pending)
            };
            assert_eq!(deletion_outcome(Stop::Remove(error)), expected, "{error:?}");
        }
        let finalize = [
            TerminalError::Host(HOST[0]),
            TerminalError::Host(HOST[1]),
            TerminalError::Host(HOST[2]),
            TerminalError::NotVisible,
            TerminalError::Conflict,
            TerminalError::Corrupt {
                field: "workspace_quota",
            },
            TerminalError::ReadsUnproven,
            TerminalError::PhysicalUnproven,
            TerminalError::Unavailable,
            TerminalError::DeadlineExpired,
            TerminalError::CommitUnknown,
            TerminalError::CommitAcknowledgedAfterDeadline,
            TerminalError::RollbackAcknowledgedAfterDeadline,
        ];
        for error in finalize {
            let expected = if matches!(error, TerminalError::Corrupt { .. }) {
                unavailable()
            } else {
                Ok(ArtifactDeletionState::Pending)
            };
            assert_eq!(
                deletion_outcome(Stop::Finalize(error)),
                expected,
                "{error:?}"
            );
        }
    }
}
