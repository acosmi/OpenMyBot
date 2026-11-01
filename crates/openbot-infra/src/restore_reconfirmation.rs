//! Reconfirmation of a restored cohort's subjects and credential roots.
//!
//! A requirement row names one logical source of the restored cohort. Until
//! its latest in-cohort generation has a receipt, consumers of that source do
//! not open a Vault value or send over the network (Appendix A, class 9).

use std::time::Instant;

use openbot_contracts::recovery::RestoreCohortRef;

/// The closed logical source kinds of `restore_reconfirm_requirements`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequirementKind {
    Subject,
    Credential,
    ModelSecret,
    SdkSecret,
    SsoProvider,
    ConfigSlot,
}

impl RequirementKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Credential => "credential",
            Self::ModelSecret => "model_secret",
            Self::SdkSecret => "sdk_secret",
            Self::SsoProvider => "sso_provider",
            Self::ConfigSlot => "config_slot",
        }
    }
}

/// One consumer's logical source, compared under the cohort frozen in the
/// admission the consumer already holds (`None` outside a restored binding).
pub(crate) struct RequirementSource<'a> {
    pub(crate) cohort: Option<RestoreCohortRef>,
    pub(crate) kind: RequirementKind,
    pub(crate) source_ref: &'a str,
}

/// Closed failure of the requirement gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreReconfirmationError {
    /// The latest in-cohort requirement of this source has no receipt.
    NotConfirmed,
    /// The observation failed or the original deadline passed.
    Unavailable,
}

/// Reject when the latest in-cohort generation of this source has no receipt.
/// No cohort, or a source absent from the cohort, passes. Runs on the
/// consumer's own connection or transaction, before any Vault-open or send.
pub(crate) async fn require_confirmed_before<C: tokio_postgres::GenericClient + Sync>(
    client: &C,
    source: RequirementSource<'_>,
    deadline: Instant,
) -> Result<(), RestoreReconfirmationError> {
    let Some(cohort) = source.cohort else {
        return Ok(());
    };
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(RestoreReconfirmationError::Unavailable)?;
    let row = tokio::time::timeout(
        remaining,
        client.query_opt(
            "SELECT EXISTS(SELECT 1 FROM openbot_internal.restore_reconfirm_receipts c \
             WHERE c.requirement_id=r.requirement_id) \
             FROM openbot_internal.restore_reconfirm_requirements r \
             WHERE r.operation_id=$1 AND r.epoch=$2 AND r.source_kind=$3 AND r.source_ref=$4 \
             ORDER BY r.binding_generation DESC LIMIT 1",
            &[
                &uuid::Uuid::from_bytes(cohort.operation_id),
                &cohort.epoch.as_slice(),
                &source.kind.as_str(),
                &source.source_ref,
            ],
        ),
    )
    .await
    .map_err(|_| RestoreReconfirmationError::Unavailable)?
    .map_err(|_| RestoreReconfirmationError::Unavailable)?;
    match row {
        None => Ok(()),
        Some(row) => match row.try_get::<_, bool>(0) {
            Ok(true) => Ok(()),
            Ok(false) => Err(RestoreReconfirmationError::NotConfirmed),
            Err(_) => Err(RestoreReconfirmationError::Unavailable),
        },
    }
}
