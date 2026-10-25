//! Held recovery admission ports of the original enrolled request host.
//!
//! These ports carry an original owner's short admission lock. Implementing a
//! trait does not enroll a host, confirm a restored binding, or grant restore
//! authority. The registered HostRequestBindingGuard must still authenticate
//! the same original binding and invoke its own RecoveryReadGate adapter.

use std::future::Future;
use std::pin::Pin;
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
}

/// Opaque, non-Clone owned lease. Dropping it is not a Current/closure receipt.
pub type RecoveryAdmissionLease<'a> = Box<dyn RecoveryAdmissionWitness + 'a>;

/// Read port installed only by the actual registered original host issuer.
///
/// No factory, path, caller AuthContext or arbitrary implementation of this
/// port can mint a restore session. The enclosing original request-binding
/// guard owns enrollment and rejects unsupported composition.
pub trait RecoveryHostReadPort: Send + Sync {
    /// Borrow original admission under one unchanged use-case deadline.
    fn borrow_before<'a>(
        &'a self,
        binding: &'a VerifiedHostRequestBinding,
        auth: &'a AuthContext,
        deadline: Instant,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<RecoveryAdmissionLease<'a>, HostRequestBindingError>>
                + Send
                + 'a,
        >,
    >;
}
