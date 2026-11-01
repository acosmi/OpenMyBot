//! Test-only request binding for contexts outside every recovery domain.
//!
//! The guard lends a Normal admission with no restore cohort that re-checks
//! the same context and deadline; reconfirmation keeps the closed default.
//! Tests that prove request-lease gating must not use it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use openbot_contracts::auth::AuthContext;
use openbot_contracts::recovery::{
    RecoveryAdmissionLease, RecoveryAdmissionPurpose, RecoveryAdmissionWitness, RestoreCohortRef,
};
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
    RequestBindingOwnerLease, ServerSessionBindingIdentity, VerifiedHostRequestBinding,
};

/// Bind `auth` to a synthetic outside-domain session; the guard owns the issuer.
pub fn outside_domain(auth: AuthContext) -> AuthContext {
    let (owner, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let identity = ServerSessionBindingIdentity::from_verified_row(
        "recovery-admission-test-session".into(),
        auth.actor().clone(),
        "recovery-admission-test-column".into(),
        time::OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let guard = Arc::new(OutsideDomainGuard {
        auth: auth.clone(),
        _owner: owner,
    });
    let binding = issuer
        .bind_server_session(&auth, identity, guard)
        .expect("the synthetic session matches its own context");
    auth.with_verified_request_binding(binding)
        .expect("the synthetic binding matches its own context")
}

struct OutsideDomainGuard {
    auth: AuthContext,
    _owner: RequestBindingOwnerLease,
}

struct OutsideDomainAdmission(AuthContext);

impl OutsideDomainAdmission {
    fn check(&self, auth: &AuthContext, deadline: Instant) -> Result<(), HostRequestBindingError> {
        if Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        if auth == &self.0 {
            Ok(())
        } else {
            Err(HostRequestBindingError::NotCurrent)
        }
    }
}

impl RecoveryAdmissionWitness for OutsideDomainAdmission {
    fn purpose(&self) -> RecoveryAdmissionPurpose {
        RecoveryAdmissionPurpose::Normal
    }

    fn verify_current_before(
        &self,
        _binding: &VerifiedHostRequestBinding,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        self.check(auth, deadline)
    }

    fn restore_cohort(&self) -> Option<RestoreCohortRef> {
        None
    }
}

impl HostRequestBindingGuard for OutsideDomainGuard {
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            if auth == &self.auth {
                Ok(())
            } else {
                Err(HostRequestBindingError::NotCurrent)
            }
        })
    }

    fn borrow_recovery_admission_before<'a>(
        &'a self,
        _binding: &'a VerifiedHostRequestBinding,
        auth: &'a AuthContext,
        deadline: Instant,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<RecoveryAdmissionLease<'a>, HostRequestBindingError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let admission = OutsideDomainAdmission(self.auth.clone());
            admission.check(auth, deadline)?;
            Ok(Box::new(admission) as RecoveryAdmissionLease<'a>)
        })
    }
}
