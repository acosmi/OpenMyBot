//! Held recovery admission ports of the original enrolled request host.
//!
//! These ports carry an original owner's short admission lock. Implementing a
//! trait does not enroll a host, confirm a restored binding, or grant restore
//! authority. The registered HostRequestBindingGuard must still authenticate
//! the same original binding and invoke its own RecoveryReadGate adapter.

use std::time::Instant;

use crate::auth::AuthContext;
use crate::request_binding::{HostRequestBindingError, VerifiedHostRequestBinding};

/// Closed use of a short held admission lease; neither variant grants restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAdmissionPurpose {
    /// The original request's final issue, send, commit or publication.
    Normal,
    /// Only the separately authenticated named restored-binding confirmation.
    Reconfirmation,
}

/// The restored cohort named by the runtime's published RestoreCurrent binding:
/// the external operation and epoch that requirement rows are compared under.
/// It is comparison DATA, not a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreCohortRef {
    /// Restore operation UUID bytes.
    pub operation_id: [u8; 16],
    /// External restore epoch.
    pub epoch: [u8; 32],
}

/// Original held admission owner, not a serialized or persistent permission.
///
/// A production implementation retains its actual admission lock and original
/// runtime observation until Drop, and verifies the same attachment and
/// deadline again at the final effect boundary. There is no success default.
pub trait RecoveryAdmissionWitness: Send + Sync {
    /// The exact closed purpose frozen when the original lease was borrowed.
    fn purpose(&self) -> RecoveryAdmissionPurpose;

    /// Synchronous final check of the original held resources and attachment.
    fn verify_current_before(
        &self,
        binding: &VerifiedHostRequestBinding,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError>;

    /// The cohort frozen when this lease was borrowed: `Some` only when its
    /// runtime publishes RestoreCurrent. There is no default implementation.
    fn restore_cohort(&self) -> Option<RestoreCohortRef>;
}

/// Opaque, non-Clone owned lease. Dropping it is not a Current/closure receipt.
pub type RecoveryAdmissionLease<'a> = Box<dyn RecoveryAdmissionWitness + 'a>;
