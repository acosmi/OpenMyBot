//! Reconfirmation of a restored cohort's subjects and credential roots.
//!
//! A requirement row names one logical source of the restored cohort. Until
//! its latest in-cohort generation has a receipt, consumers of that source do
//! not open a Vault value or send over the network (Appendix A, class 9).

use std::time::Instant;

#[cfg(feature = "server-runtime")]
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
#[cfg(feature = "server-runtime")]
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
#[cfg(feature = "server-runtime")]
use openbot_contracts::recovery::RecoveryAdmissionLease;
use openbot_contracts::recovery::RestoreCohortRef;
#[cfg(feature = "server-runtime")]
use openbot_contracts::request_binding::{
    HostRequestBindingError, RequestBindingIssuer, VerifiedHostRequestBinding,
};
#[cfg(feature = "server-runtime")]
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
#[cfg(feature = "server-runtime")]
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
#[cfg(feature = "server-runtime")]
use openbot_domain::identity::roles::resolve_effective_role;
#[cfg(feature = "server-runtime")]
use openbot_domain::identity::session::{SessionLifetimePolicy, SessionState, evaluate_session};
#[cfg(feature = "server-runtime")]
use openbot_domain::vault::SecretBytes;
#[cfg(feature = "server-runtime")]
use std::{str::FromStr, sync::OnceLock};
#[cfg(feature = "server-runtime")]
use time::OffsetDateTime;
#[cfg(feature = "server-runtime")]
use tokio_postgres::Transaction;
/// The cancellation an original reconfirmation request observes.
#[cfg(feature = "server-runtime")]
pub use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[cfg(feature = "server-runtime")]
use crate::db::pool::{DatabasePool, TransactionOwnerError};
#[cfg(feature = "server-runtime")]
use crate::recovery_control::RecoveryReadGate;
#[cfg(feature = "server-runtime")]
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

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
    /// The source is absent, superseded, or belongs to another owner.
    NotVisible,
    /// The original session is no longer current and fresh.
    NotFresh,
    /// COMMIT began but its acknowledgement is unknown.
    CommitUnknown,
    /// COMMIT was acknowledged after the original deadline.
    CommitAcknowledgedAfterDeadline,
}

impl std::fmt::Display for RestoreReconfirmationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotConfirmed => "restore_binding_not_confirmed",
            Self::Unavailable => "restore_reconfirmation_unavailable",
            Self::NotVisible => "restore_requirement_not_visible",
            Self::NotFresh => "restore_reconfirmation_not_fresh",
            Self::CommitUnknown => "restore_reconfirmation_commit_unknown",
            Self::CommitAcknowledgedAfterDeadline => {
                "restore_reconfirmation_commit_ack_after_deadline"
            }
        })
    }
}
impl std::error::Error for RestoreReconfirmationError {}

/// One original HTTP intent, for exactly one named requirement.
#[cfg(feature = "server-runtime")]
pub struct OriginalReconfirmationRequest {
    deadline: Instant,
    cancel: CancellationToken,
    confirmation_id: Uuid,
    proof_ref: Uuid,
    confirmations_left: u8,
}
#[cfg(feature = "server-runtime")]
impl OriginalReconfirmationRequest {
    /// Freeze the entry budget; this value carries no fresh-actor authority.
    pub fn new(deadline: Instant, cancel: CancellationToken) -> Self {
        Self {
            deadline,
            cancel,
            confirmation_id: Uuid::now_v7(),
            proof_ref: Uuid::now_v7(),
            confirmations_left: 1,
        }
    }
    /// The original absolute deadline, never a renewed restore budget.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    #[cfg(feature = "desktop-local")]
    pub(crate) fn for_current_local(
        deadline: Instant,
        cancel: CancellationToken,
        request_id: Uuid,
    ) -> Self {
        Self {
            deadline,
            cancel,
            confirmation_id: Uuid::now_v7(),
            proof_ref: request_id,
            confirmations_left: 1,
        }
    }
}
#[cfg(feature = "server-runtime")]
impl std::fmt::Debug for OriginalReconfirmationRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OriginalReconfirmationRequest(<one-current-request>)")
    }
}

/// The enrolled Server binding and its held narrow Current admission.
/// Its private fields are neither a DTO nor a reusable fresh proof.
#[cfg(feature = "server-runtime")]
pub struct CurrentRestoredBindingConfirmation<'a> {
    authority: &'a RestoreReconfirmation,
    auth: &'a AuthContext,
    binding: &'a VerifiedHostRequestBinding,
    admission: RecoveryAdmissionLease<'a>,
    requirement_id: Uuid,
    cohort: RestoreCohortRef,
    deadline: Instant,
}
#[cfg(feature = "server-runtime")]
impl CurrentRestoredBindingConfirmation<'_> {
    pub(crate) fn auth(&self) -> &AuthContext {
        self.auth
    }
    pub(crate) fn check_before(&self, deadline: Instant) -> Result<(), RestoreReconfirmationError> {
        if deadline > self.deadline
            || !self.authority.issuer.get().is_some_and(|issuer| {
                issuer.observation().is_current() && issuer.owns_identity(self.binding.identity())
            })
        {
            return Err(RestoreReconfirmationError::Unavailable);
        }
        self.admission
            .verify_current_before(self.binding, self.auth, deadline)
            .map_err(|_| RestoreReconfirmationError::Unavailable)
    }
}
#[cfg(feature = "server-runtime")]
impl std::fmt::Debug for CurrentRestoredBindingConfirmation<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentRestoredBindingConfirmation(<original-server-binding>)")
    }
}

/// A single acknowledged and read-back receipt, not a credential grant.
#[derive(Debug)]
pub struct ReconfirmationCommitFact {
    requirement_id: Uuid,
    confirmation_id: Uuid,
}
impl ReconfirmationCommitFact {
    /// The exact named requirement observed after its acknowledged transaction.
    #[must_use]
    pub fn requirement_id(&self) -> Uuid {
        self.requirement_id
    }
    /// The durable receipt's own confirmation identity.
    #[must_use]
    pub fn confirmation_id(&self) -> Uuid {
        self.confirmation_id
    }
}

#[cfg(feature = "server-runtime")]
pub(crate) struct LockedRestoreRequirement {
    pub(crate) id: Uuid,
    pub(crate) kind: RequirementKind,
    pub(crate) source_ref: String,
    pub(crate) source_created_at: Option<OffsetDateTime>,
    pub(crate) source_revision: Option<i64>,
}

/// Same-pool confirmation service installed once in its real Server session resolver.
#[cfg(feature = "server-runtime")]
pub struct RestoreReconfirmation {
    pool: DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    lifetime: SessionLifetimePolicy,
    audit_key: SecretBytes,
    vault: crate::vault::CredentialRecordVault,
    issuer: OnceLock<RequestBindingIssuer>,
}
#[cfg(feature = "server-runtime")]
impl std::fmt::Debug for RestoreReconfirmation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RestoreReconfirmation(<original-server-owner>)")
    }
}

#[cfg(feature = "server-runtime")]
impl RestoreReconfirmation {
    /// Bind the actual Server pool, namespace and audit key without granting confirmation.
    pub fn new(
        pool: DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
        lifetime: SessionLifetimePolicy,
        audit_key: SecretBytes,
        vault: crate::vault::CredentialRecordVault,
        gate: &RecoveryReadGate,
    ) -> Result<Self, RestoreReconfirmationError> {
        if audit_key.is_empty()
            || !gate.matches_server_scope(&pool, deployment.as_str(), tenant.as_str())
        {
            return Err(RestoreReconfirmationError::Unavailable);
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            lifetime,
            audit_key,
            vault,
            issuer: OnceLock::new(),
        })
    }

    /// Enroll the original resolver issuer without retaining its lifecycle lease.
    pub fn enroll_host_issuer(
        &self,
        issuer: &RequestBindingIssuer,
    ) -> Result<(), HostRequestBindingError> {
        if !issuer.observation().is_current() || self.pool.is_closed() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.issuer
            .set(issuer.clone())
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// Produce one named confirmation from the installed live issuer and fresh host guard.
    /// Final same-transaction source and owner checks remain mandatory.
    pub async fn prepare_server_confirmation<'a>(
        &'a self,
        auth: &'a AuthContext,
        requirement_id: Uuid,
        deadline: Instant,
    ) -> Result<CurrentRestoredBindingConfirmation<'a>, RestoreReconfirmationError> {
        let binding = auth
            .request_binding()
            .ok_or(RestoreReconfirmationError::NotFresh)?;
        let issuer = self
            .issuer
            .get()
            .ok_or(RestoreReconfirmationError::Unavailable)?;
        if requirement_id.is_nil()
            || auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !issuer.owns_identity(binding.identity())
        {
            return Err(RestoreReconfirmationError::NotVisible);
        }
        issuer
            .borrow_server_session_epoch(binding.identity())
            .map_err(|_| RestoreReconfirmationError::NotFresh)?;
        let admission = binding
            .borrow_restore_reconfirmation_before(auth, deadline)
            .await
            .map_err(|_| RestoreReconfirmationError::NotFresh)?;
        let cohort = admission
            .restore_cohort()
            .ok_or(RestoreReconfirmationError::Unavailable)?;
        Ok(CurrentRestoredBindingConfirmation {
            authority: self,
            auth,
            binding,
            admission,
            requirement_id,
            cohort,
            deadline,
        })
    }

    async fn lock_original_session(
        &self,
        tx: &Transaction<'_>,
        confirmation: &CurrentRestoredBindingConfirmation<'_>,
    ) -> Result<OffsetDateTime, RestoreReconfirmationError> {
        let issuer = self
            .issuer
            .get()
            .ok_or(RestoreReconfirmationError::Unavailable)?;
        let epoch = issuer
            .borrow_server_session_epoch(confirmation.binding.identity())
            .map_err(|_| RestoreReconfirmationError::NotFresh)?;
        let row = tx.query_opt(
            "SELECT s.id,s.user_id,s.token,s.created_at,s.updated_at,s.expires_at,s.auth_generation, \
             coalesce(u.auth_generation,0) AS current_generation,u.created_at AS actor_created_at, \
             EXISTS(SELECT 1 FROM public.revoked_access r WHERE r.email=lower(u.email)) AS revoked, \
             ARRAY(SELECT r.role::text FROM public.user_roles r WHERE r.user_id=u.id ORDER BY r.role::text) AS roles \
             FROM public.sessions s JOIN public.users u ON u.id=s.user_id WHERE s.id=$1 FOR SHARE OF s,u",
            &[&epoch.lookup_id()],
        ).await.map_err(|_| RestoreReconfirmationError::Unavailable)?.ok_or(RestoreReconfirmationError::NotFresh)?;
        let id: String = row
            .try_get("id")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let user: String = row
            .try_get("user_id")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let token: String = row
            .try_get("token")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let created: OffsetDateTime = row
            .try_get("created_at")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let updated: OffsetDateTime = row
            .try_get("updated_at")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let expires: OffsetDateTime = row
            .try_get("expires_at")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let generation: Option<i64> = row
            .try_get("auth_generation")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let current: i64 = row
            .try_get("current_generation")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let revoked: bool = row
            .try_get("revoked")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let generation = generation.ok_or(RestoreReconfirmationError::NotFresh)?;
        let now = OffsetDateTime::now_utc();
        if revoked
            || now >= expires
            || generation != current
            || now - created > self.lifetime.fresh()
            || !epoch.matches_raw_row(&id, &user, &token, created, generation)
        {
            return Err(RestoreReconfirmationError::NotFresh);
        }
        let current = u64::try_from(current).map_err(|_| RestoreReconfirmationError::NotFresh)?;
        let _current_session = evaluate_session(
            self.lifetime,
            SessionState::rehydrate(created, updated, AuthGeneration::new(current)),
            AuthGeneration::new(current),
            now,
        )
        .map_err(|_| RestoreReconfirmationError::NotFresh)?;
        let roles: Vec<String> = row
            .try_get("roles")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let roles = roles
            .iter()
            .map(|role| Role::from_str(role))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RestoreReconfirmationError::NotFresh)?;
        let role =
            resolve_effective_role(roles).map_err(|_| RestoreReconfirmationError::NotFresh)?;
        let actual = AuthContextBuilder::from_verified_session(
            self.deployment.clone(),
            self.tenant.clone(),
            ActorId::new(user),
            AuthGeneration::new(current),
            false,
        )
        .with_role(role)
        .build();
        if &actual != confirmation.auth {
            return Err(RestoreReconfirmationError::NotFresh);
        }
        row.try_get("actor_created_at")
            .map_err(|_| RestoreReconfirmationError::Unavailable)
    }
}

#[cfg(feature = "server-runtime")]
impl RestoreReconfirmation {
    /// Confirm only the named current source, then acknowledge and read back its one receipt.
    pub async fn confirm_current_binding(
        &self,
        confirmation: CurrentRestoredBindingConfirmation<'_>,
        mut request: OriginalReconfirmationRequest,
    ) -> Result<ReconfirmationCommitFact, RestoreReconfirmationError> {
        let deadline = request.deadline;
        if !std::ptr::eq(self, confirmation.authority)
            || request.confirmations_left != 1
            || request.cancel.is_cancelled()
        {
            return Err(RestoreReconfirmationError::Unavailable);
        }
        request.confirmations_left = 0;
        confirmation.check_before(deadline)?;
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let owner = client
            .begin_read_committed()
            .await
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let tx = owner.as_transaction();
        let prepare = async {
            let actor_birth = self.lock_original_session(tx, &confirmation).await?;
            let row = tx.query_opt(
                "SELECT requirement_id,source_kind,source_ref,source_created_at,source_revision,owner_kind,owner_id,owner_created_at \
                 FROM openbot_internal.restore_reconfirm_requirements r \
                 WHERE requirement_id=$1 AND operation_id=$2 AND epoch=$3 \
                 AND NOT EXISTS(SELECT 1 FROM openbot_internal.restore_reconfirm_requirements newer \
                    WHERE newer.operation_id=r.operation_id AND newer.source_kind=r.source_kind \
                    AND newer.source_ref=r.source_ref AND newer.binding_generation>r.binding_generation) FOR UPDATE",
                &[&confirmation.requirement_id,&Uuid::from_bytes(confirmation.cohort.operation_id),&confirmation.cohort.epoch.as_slice()],
            ).await.map_err(|_| RestoreReconfirmationError::Unavailable)?.ok_or(RestoreReconfirmationError::NotVisible)?;
            let owner_kind: String = row
                .try_get("owner_kind")
                .map_err(|_| RestoreReconfirmationError::Unavailable)?;
            let owner_id: String = row
                .try_get("owner_id")
                .map_err(|_| RestoreReconfirmationError::Unavailable)?;
            let owner_birth: Option<OffsetDateTime> = row
                .try_get("owner_created_at")
                .map_err(|_| RestoreReconfirmationError::Unavailable)?;
            if owner_kind != "actor"
                || owner_id != confirmation.auth.actor().as_str()
                || owner_birth != Some(actor_birth)
            {
                return Err(RestoreReconfirmationError::NotVisible);
            }
            let kind: String = row
                .try_get("source_kind")
                .map_err(|_| RestoreReconfirmationError::Unavailable)?;
            let kind = match kind.as_str() {
                "subject" => RequirementKind::Subject,
                "credential" => RequirementKind::Credential,
                "model_secret" => RequirementKind::ModelSecret,
                "sdk_secret" => RequirementKind::SdkSecret,
                "sso_provider" => RequirementKind::SsoProvider,
                "config_slot" => RequirementKind::ConfigSlot,
                _ => return Err(RestoreReconfirmationError::Unavailable),
            };
            let requirement = LockedRestoreRequirement {
                id: confirmation.requirement_id,
                kind,
                source_ref: row
                    .try_get("source_ref")
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?,
                source_created_at: row
                    .try_get("source_created_at")
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?,
                source_revision: row
                    .try_get("source_revision")
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?,
            };
            if kind == RequirementKind::SdkSecret {
                crate::gateway_authority::reconfirm_ready_binding(
                    tx,
                    &confirmation,
                    &requirement,
                    &self.vault,
                    self.audit_key.expose(),
                    &request.cancel,
                    deadline,
                )
                .await
                .map_err(|_| RestoreReconfirmationError::Unavailable)?;
            } else {
                self.lock_source(tx, &confirmation, &requirement, actor_birth)
                    .await?;
                let (id, created_at) = next_event_coordinates(tx)
                    .await
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?;
                let event = AuditEvent {
                    id,
                    actor: Some(confirmation.auth.actor().clone()),
                    event_type: AuditEventType::parse("configuration.changed")
                        .ok_or(RestoreReconfirmationError::Unavailable)?,
                    target_kind: AuditLabel::new("restore_requirement"),
                    target_id: Some(
                        AuditIdentifier::new(requirement.id.to_string())
                            .map_err(|_| RestoreReconfirmationError::Unavailable)?,
                    ),
                    payload: AuditPayload::from_facts([AuditFact::ConfigurationChange(
                        AuditLabel::new("restore_binding_reconfirmed"),
                    )])
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?,
                    created_at,
                };
                append_event_in_transaction(tx, &event, self.audit_key.expose())
                    .await
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?;
            }
            confirmation.check_before(deadline)?;
            tx.execute(
                "INSERT INTO openbot_internal.restore_reconfirm_receipts \
                 (operation_id,epoch,requirement_id,confirmation_id,proof_ref,confirmed_by,proof_kind) \
                 VALUES($1,$2,$3,$4,$5,$6,'fresh_actor') ON CONFLICT(requirement_id) DO NOTHING",
                &[&Uuid::from_bytes(confirmation.cohort.operation_id),&confirmation.cohort.epoch.as_slice(),&requirement.id,&request.confirmation_id,&request.proof_ref,&confirmation.auth.actor().as_str()],
            ).await.map_err(|_| RestoreReconfirmationError::Unavailable)?;
            Ok::<_, RestoreReconfirmationError>(requirement)
        };
        let requirement = tokio::select! {
            biased;
            _ = request.cancel.cancelled() => return Err(RestoreReconfirmationError::Unavailable),
            result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),prepare) => result.map_err(|_| RestoreReconfirmationError::Unavailable)??,
        };
        confirmation.check_before(deadline)?;
        if request.cancel.is_cancelled() {
            return Err(RestoreReconfirmationError::Unavailable);
        }
        // GuardedRC owns COMMIT's deadline and its exact ACK/Unknown classification.
        owner.commit().await.map_err(|error| match error {
            TransactionOwnerError::CommitUnknown => RestoreReconfirmationError::CommitUnknown,
            TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
                RestoreReconfirmationError::CommitAcknowledgedAfterDeadline
            }
            _ => RestoreReconfirmationError::Unavailable,
        })?;
        confirmation.check_before(deadline)?;
        let operation_id = Uuid::from_bytes(confirmation.cohort.operation_id);
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &requirement.id,
            &operation_id,
            &confirmation.cohort.epoch.as_slice(),
        ];
        let readback = client.as_client().query_one(
            "SELECT confirmation_id,confirmed_by FROM openbot_internal.restore_reconfirm_receipts \
             WHERE requirement_id=$1 AND operation_id=$2 AND epoch=$3",
            parameters,
        );
        let row = tokio::select! {
            biased;
            _ = request.cancel.cancelled() => return Err(RestoreReconfirmationError::Unavailable),
            result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),readback) => result.map_err(|_| RestoreReconfirmationError::Unavailable)?.map_err(|_| RestoreReconfirmationError::Unavailable)?,
        };
        let confirmed_by: String = row
            .try_get("confirmed_by")
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        if confirmed_by != confirmation.auth.actor().as_str() {
            return Err(RestoreReconfirmationError::NotVisible);
        }
        confirmation.check_before(deadline)?;
        Ok(ReconfirmationCommitFact {
            requirement_id: requirement.id,
            confirmation_id: row
                .try_get("confirmation_id")
                .map_err(|_| RestoreReconfirmationError::Unavailable)?,
        })
    }
}

/// The Local actor's subject receipt of one restored Current runtime, after
/// its host consumed one OS confirmation (spec revision R484 ¶8087–8089):
/// the actor row and the latest in-cohort subject requirement are locked, the
/// audit event and the `fresh_local_os` receipt commit in one GuardedRC, the
/// ACK is required, and the readback consumers use must accept the receipt.
#[cfg(all(feature = "server-runtime", feature = "desktop-local"))]
pub(crate) async fn confirm_restored_local_subject(
    lease: &crate::recovery_control::RecoveryWorkerLease<'_>,
    pool: &DatabasePool,
    actor: &str,
    audit_key: &[u8],
    mut request: OriginalReconfirmationRequest,
) -> Result<ReconfirmationCommitFact, RestoreReconfirmationError> {
    let deadline = request.deadline;
    let cohort = lease
        .restore_cohort()
        .ok_or(RestoreReconfirmationError::Unavailable)?;
    if request.confirmations_left != 1
        || request.cancel.is_cancelled()
        || deadline > lease.deadline()
    {
        return Err(RestoreReconfirmationError::Unavailable);
    }
    request.confirmations_left = 0;
    let current = || {
        lease
            .verify_current_before(deadline)
            .map_err(|_| RestoreReconfirmationError::Unavailable)
    };
    current()?;
    let operation_id = Uuid::from_bytes(cohort.operation_id);
    let mut client = pool
        .get_guarded(deadline)
        .await
        .map_err(|_| RestoreReconfirmationError::Unavailable)?;
    let owner = client
        .begin_read_committed()
        .await
        .map_err(|_| RestoreReconfirmationError::Unavailable)?;
    let tx = owner.as_transaction();
    let prepare = async {
        let birth: OffsetDateTime = tx
            .query_opt(
                "SELECT created_at FROM public.users WHERE id=$1 FOR SHARE",
                &[&actor],
            )
            .await
            .map_err(|_| RestoreReconfirmationError::Unavailable)?
            .ok_or(RestoreReconfirmationError::NotVisible)?
            .try_get(0)
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let requirement: Uuid = tx.query_opt(
            "SELECT requirement_id FROM openbot_internal.restore_reconfirm_requirements r \
             WHERE operation_id=$1 AND epoch=$2 AND source_kind='subject' AND source_ref=$3 \
             AND owner_kind='actor' AND owner_id=$3 AND source_created_at=$4 AND owner_created_at=$4 \
             AND NOT EXISTS(SELECT 1 FROM openbot_internal.restore_reconfirm_requirements newer \
                WHERE newer.operation_id=r.operation_id AND newer.source_kind=r.source_kind \
                AND newer.source_ref=r.source_ref AND newer.binding_generation>r.binding_generation) FOR UPDATE",
            &[&operation_id, &cohort.epoch.as_slice(), &actor, &birth],
        ).await.map_err(|_| RestoreReconfirmationError::Unavailable)?
            .ok_or(RestoreReconfirmationError::NotVisible)?
            .try_get(0)
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let (id, created_at) = next_event_coordinates(tx)
            .await
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        let event = AuditEvent {
            id,
            actor: Some(ActorId::new(actor)),
            event_type: AuditEventType::parse("configuration.changed")
                .ok_or(RestoreReconfirmationError::Unavailable)?,
            target_kind: AuditLabel::new("restore_requirement"),
            target_id: Some(
                AuditIdentifier::new(requirement.to_string())
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?,
            ),
            payload: AuditPayload::from_facts([AuditFact::ConfigurationChange(AuditLabel::new(
                "restore_binding_reconfirmed",
            ))])
            .map_err(|_| RestoreReconfirmationError::Unavailable)?,
            created_at,
        };
        append_event_in_transaction(tx, &event, audit_key)
            .await
            .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        current()?;
        tx.execute(
            "INSERT INTO openbot_internal.restore_reconfirm_receipts \
             (operation_id,epoch,requirement_id,confirmation_id,proof_ref,confirmed_by,proof_kind) \
             VALUES($1,$2,$3,$4,$5,$6,'fresh_local_os') ON CONFLICT(requirement_id) DO NOTHING",
            &[
                &operation_id,
                &cohort.epoch.as_slice(),
                &requirement,
                &request.confirmation_id,
                &request.proof_ref,
                &actor,
            ],
        )
        .await
        .map_err(|_| RestoreReconfirmationError::Unavailable)?;
        Ok::<_, RestoreReconfirmationError>(requirement)
    };
    let requirement = tokio::select! {
        biased;
        _ = request.cancel.cancelled() => return Err(RestoreReconfirmationError::Unavailable),
        result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), prepare) => result.map_err(|_| RestoreReconfirmationError::Unavailable)??,
    };
    current()?;
    if request.cancel.is_cancelled() {
        return Err(RestoreReconfirmationError::Unavailable);
    }
    // GuardedRC owns COMMIT's deadline and its exact ACK/Unknown classification.
    owner.commit().await.map_err(|error| match error {
        TransactionOwnerError::CommitUnknown => RestoreReconfirmationError::CommitUnknown,
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            RestoreReconfirmationError::CommitAcknowledgedAfterDeadline
        }
        _ => RestoreReconfirmationError::Unavailable,
    })?;
    current()?;
    let readback = async {
        let row = client
            .as_client()
            .query_opt(
                "SELECT confirmation_id FROM openbot_internal.restore_reconfirm_receipts \
                 WHERE requirement_id=$1 AND operation_id=$2 AND epoch=$3 AND confirmed_by=$4 AND proof_kind='fresh_local_os'",
                &[&requirement, &operation_id, &cohort.epoch.as_slice(), &actor],
            )
            .await
            .map_err(|_| RestoreReconfirmationError::Unavailable)?
            .ok_or(RestoreReconfirmationError::NotVisible)?;
        // The consumers' own readback must accept this receipt as confirming.
        require_confirmed_before(
            client.as_client(),
            RequirementSource {
                cohort: Some(cohort),
                kind: RequirementKind::Subject,
                source_ref: actor,
            },
            deadline,
        )
        .await?;
        row.try_get::<_, Uuid>(0)
            .map_err(|_| RestoreReconfirmationError::Unavailable)
    };
    let confirmation_id = tokio::select! {
        biased;
        _ = request.cancel.cancelled() => return Err(RestoreReconfirmationError::Unavailable),
        result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), readback) => result.map_err(|_| RestoreReconfirmationError::Unavailable)??,
    };
    current()?;
    Ok(ReconfirmationCommitFact {
        requirement_id: requirement,
        confirmation_id,
    })
}

#[cfg(feature = "server-runtime")]
impl RestoreReconfirmation {
    async fn lock_source(
        &self,
        tx: &Transaction<'_>,
        confirmation: &CurrentRestoredBindingConfirmation<'_>,
        requirement: &LockedRestoreRequirement,
        actor_birth: OffsetDateTime,
    ) -> Result<(), RestoreReconfirmationError> {
        match requirement.kind {
            RequirementKind::Subject => {
                if requirement.source_ref != confirmation.auth.actor().as_str()
                    || requirement.source_created_at != Some(actor_birth)
                {
                    return Err(RestoreReconfirmationError::NotVisible);
                }
            }
            RequirementKind::Credential => {
                let id = Uuid::parse_str(&requirement.source_ref)
                    .map_err(|_| RestoreReconfirmationError::NotVisible)?;
                tx.query("SELECT s.id FROM public.mcp_servers s WHERE s.credential_id=$1 OR EXISTS(SELECT 1 FROM public.mcp_user_credentials u WHERE u.server_id=s.id AND u.credential_id=$1) ORDER BY s.id FOR SHARE OF s", &[&id]).await.map_err(|_| RestoreReconfirmationError::Unavailable)?;
                tx.query("SELECT server_id,user_id FROM public.mcp_user_credentials WHERE credential_id=$1 ORDER BY server_id,user_id FOR SHARE", &[&id]).await.map_err(|_| RestoreReconfirmationError::Unavailable)?;
                let row = tx.query_opt("SELECT created_at FROM public.credentials WHERE id=$1 AND revoked_at IS NULL FOR SHARE", &[&id]).await.map_err(|_| RestoreReconfirmationError::Unavailable)?.ok_or(RestoreReconfirmationError::NotVisible)?;
                let birth: OffsetDateTime = row
                    .try_get(0)
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?;
                if requirement.source_created_at != Some(birth) {
                    return Err(RestoreReconfirmationError::NotVisible);
                }
            }
            RequirementKind::ModelSecret => {
                let id = Uuid::parse_str(&requirement.source_ref)
                    .map_err(|_| RestoreReconfirmationError::NotVisible)?;
                let row = tx.query_opt("SELECT c.created_at,c.revision FROM public.model_connections c JOIN public.model_connection_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id AND s.deployment_id=c.deployment_id AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4 AND c.enabled AND c.deleted_at IS NULL AND s.retired_at IS NULL FOR SHARE OF c,s", &[&id,&self.deployment.as_str(),&self.tenant.as_str(),&confirmation.auth.actor().as_str()]).await.map_err(|_| RestoreReconfirmationError::Unavailable)?.ok_or(RestoreReconfirmationError::NotVisible)?;
                if requirement.source_created_at
                    != Some(
                        row.try_get(0)
                            .map_err(|_| RestoreReconfirmationError::Unavailable)?,
                    )
                    || requirement.source_revision
                        != Some(
                            row.try_get(1)
                                .map_err(|_| RestoreReconfirmationError::Unavailable)?,
                        )
                {
                    return Err(RestoreReconfirmationError::NotVisible);
                }
            }
            RequirementKind::SsoProvider => {
                let row = tx
                    .query_opt(
                        "SELECT id FROM public.sso_providers WHERE id=$1 AND user_id=$2 FOR SHARE",
                        &[&requirement.source_ref, &confirmation.auth.actor().as_str()],
                    )
                    .await
                    .map_err(|_| RestoreReconfirmationError::Unavailable)?;
                if row.is_none() {
                    return Err(RestoreReconfirmationError::NotVisible);
                }
            }
            // These are respectively a Local/service producer and the dedicated same-tx SDK seam.
            RequirementKind::ConfigSlot | RequirementKind::SdkSecret => {
                return Err(RestoreReconfirmationError::NotVisible);
            }
        }
        Ok(())
    }
}

// Observe the original public binding. Confirmed model roots retain their snapshot revision;
// semantic successors still need the old receipt and the ordinary writer/consumer authority.
// This request reads only its named source; no ciphertext is read or decrypted.
const CONFIRMATION_READBACK_SQL: &str = r#"WITH requirement AS (
 SELECT * FROM openbot_internal.restore_reconfirm_requirements
 WHERE operation_id=$1 AND epoch=$2 AND source_kind=$3 AND source_ref=$4
 ORDER BY binding_generation DESC LIMIT 1
), operation AS (
 SELECT deployment_id,tenant_id FROM openbot_internal.restore_pg_operations WHERE operation_id=$1 AND epoch=$2
), credential_references AS (
   SELECT c.id,pg_catalog.jsonb_agg(ref.value ORDER BY ref.value::text COLLATE pg_catalog."C") AS refs,
    pg_catalog.min(ref.actor) AS actor,pg_catalog.count(DISTINCT ref.actor) AS actors,
    pg_catalog.bool_or(ref.actor IS NULL) AS service_reference
   FROM public.credentials c LEFT JOIN LATERAL (
    SELECT pg_catalog.jsonb_build_array('mcp_user',s.id,pg_catalog.to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),s.url,u.user_id,u.scope) AS value,u.user_id AS actor
     FROM public.mcp_user_credentials u JOIN public.mcp_servers s ON s.id=u.server_id WHERE u.credential_id=c.id
    UNION ALL SELECT pg_catalog.jsonb_build_array('mcp_client',s.id,pg_catalog.to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),s.url,s.added_by),s.added_by
     FROM public.mcp_servers s WHERE s.credential_id=c.id
   ) ref ON true WHERE c.id::text=$4 GROUP BY c.id
  ), inventory(kind,ref,birth,revision,owner_kind,owner_id,owner_birth,public_fields) AS (
   SELECT 'subject',u.id,u.created_at,NULL::bigint,'actor',u.id,u.created_at,
    pg_catalog.jsonb_build_array(u.id,pg_catalog.to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM public.users u WHERE u.id=$4
   UNION ALL SELECT 'credential',c.id::text,c.created_at,NULL::bigint,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN 'actor' ELSE 'service' END,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN r.actor ELSE (SELECT deployment_id FROM operation) END,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN u.created_at ELSE NULL END,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.kind,c.provider,r.refs)
    FROM public.credentials c JOIN credential_references r ON r.id=c.id LEFT JOIN public.users u ON u.id=r.actor
    WHERE c.id::text=$4 AND r.actors<=1 AND NOT (r.actors=1 AND r.service_reference)
   UNION ALL SELECT 'model_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),(SELECT source_revision FROM requirement),c.deployment_id,c.tenant_id,c.owner_user_id,c.protocol,c.endpoint,c.model)
    FROM public.model_connections c JOIN public.users u ON u.id=c.owner_user_id
    JOIN public.model_connection_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id
     AND s.deployment_id=c.deployment_id AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id AND s.retired_at IS NULL
    WHERE c.id::text=$4 AND c.deployment_id=(SELECT deployment_id FROM operation) AND c.tenant_id=(SELECT tenant_id FROM operation) AND c.deleted_at IS NULL
   UNION ALL SELECT 'sdk_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.revision,c.deployment_id,c.tenant_id,c.owner_user_id,c.issuer,c.client_id,c.account_id,c.organization_id)
    FROM public.sdk_gateway_connections c JOIN public.users u ON u.id=c.owner_user_id
    WHERE c.id::text=$4 AND c.deployment_id=(SELECT deployment_id FROM operation) AND c.tenant_id=(SELECT tenant_id FROM operation) AND
     (c.current_secret_id IS NULL OR EXISTS(SELECT 1 FROM public.sdk_gateway_secrets s
      WHERE s.id=c.current_secret_id AND s.connection_id=c.id AND s.deployment_id=c.deployment_id
       AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id AND s.credential_generation=c.credential_generation))
   UNION ALL SELECT 'sso_provider',s.id,NULL::timestamptz,NULL::bigint,
    CASE WHEN s.user_id IS NULL THEN 'service' ELSE 'actor' END,coalesce(s.user_id,(SELECT deployment_id FROM operation)),u.created_at,
    pg_catalog.jsonb_build_array(s.id,s.provider_id,s.issuer,s.organization_id,s.domain,s.user_id)
    FROM public.sso_providers s LEFT JOIN public.users u ON u.id=s.user_id WHERE s.id=$4
  )
SELECT EXISTS(
 SELECT 1 FROM openbot_internal.restore_reconfirm_receipts c
 WHERE c.requirement_id=r.requirement_id AND c.operation_id=r.operation_id AND c.epoch=r.epoch
 AND c.confirmed_by=r.owner_id
 AND (c.proof_kind=CASE r.owner_kind WHEN 'actor' THEN 'fresh_actor' WHEN 'installation' THEN 'fresh_local_os' WHEN 'service' THEN 'fresh_service_operator' END
  OR (r.owner_kind='actor' AND r.source_kind='subject' AND c.proof_kind='fresh_local_os'))
) AND EXISTS(
 SELECT 1 FROM inventory i WHERE i.kind=r.source_kind AND i.ref=r.source_ref
 AND CASE WHEN r.source_kind='model_secret' THEN
  ROW(r.owner_kind,r.owner_id,r.owner_created_at) IS NOT DISTINCT FROM ROW(i.owner_kind,i.owner_id,i.owner_birth)
  AND r.source_created_at IS NOT NULL AND r.source_revision IS NOT NULL
  AND ((i.birth=r.source_created_at AND i.revision>=r.source_revision
    AND r.public_binding=pg_catalog.sha256(pg_catalog.convert_to('wrokbot.restore.public-binding.v1'||chr(10)||pg_catalog.jsonb_build_array(i.kind,i.public_fields)::text,'UTF8')))
   OR (i.birth<>r.source_created_at AND i.revision>r.source_revision))
 ELSE
  ROW(r.source_created_at,r.source_revision,r.owner_kind,r.owner_id,r.owner_created_at,r.public_binding)
  IS NOT DISTINCT FROM ROW(i.birth,i.revision,i.owner_kind,i.owner_id,i.owner_birth,
  pg_catalog.sha256(pg_catalog.convert_to('wrokbot.restore.public-binding.v1'||chr(10)||pg_catalog.jsonb_build_array(i.kind,i.public_fields)::text,'UTF8')))
 END
)
FROM requirement r"#;

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
            CONFIRMATION_READBACK_SQL,
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
    if Instant::now() >= deadline {
        return Err(RestoreReconfirmationError::Unavailable);
    }
    match row {
        None => Ok(()),
        Some(row) => match row.try_get::<_, bool>(0) {
            Ok(true) => Ok(()),
            Ok(false) => Err(RestoreReconfirmationError::NotConfirmed),
            Err(_) => Err(RestoreReconfirmationError::Unavailable),
        },
    }
}

#[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
pub(crate) mod tests {
    use crate::recovery_control::tests::restore_current::RestoreCurrentFixture;

    /// The requirement the retirement producer would write for one live
    /// source of the fixture's cohort: birth, revision, owner and public
    /// binding come from the same inventory the readback compares, so one
    /// receipt confirms it. That producer is not these tests' subject, so its
    /// insert guard is suspended as in the fixture's own `requirement`.
    pub(crate) async fn bound_requirement(
        restored: &RestoreCurrentFixture,
        kind: &str,
        source: &str,
    ) -> uuid::Uuid {
        let (inventory, _) = super::CONFIRMATION_READBACK_SQL
            .split_once("\nSELECT EXISTS(")
            .unwrap();
        let requirement = uuid::Uuid::now_v7();
        let client = restored.pool.get().await.unwrap();
        client.batch_execute("ALTER TABLE openbot_internal.restore_reconfirm_requirements DISABLE TRIGGER restore_reconfirm_requirements_insert").await.unwrap();
        let inserted = client.execute(
            &format!("{inventory}
             INSERT INTO openbot_internal.restore_reconfirm_requirements(operation_id,epoch,requirement_id,requirement_seq,
               source_kind,source_ref,binding_generation,source_created_at,source_revision,public_binding,owner_kind,owner_id,owner_created_at)
             SELECT $1,$2,$5,(SELECT coalesce(max(requirement_seq),0)+1 FROM openbot_internal.restore_reconfirm_requirements WHERE operation_id=$1),
               i.kind,i.ref,0,i.birth,i.revision,
               pg_catalog.sha256(pg_catalog.convert_to('wrokbot.restore.public-binding.v1'||chr(10)||pg_catalog.jsonb_build_array(i.kind,
                 CASE WHEN i.kind='model_secret' THEN pg_catalog.jsonb_set(i.public_fields,'{{2}}',pg_catalog.to_jsonb(i.revision)) ELSE i.public_fields END)::text,'UTF8')),
               i.owner_kind,i.owner_id,i.owner_birth
             FROM inventory i WHERE i.kind=$3 AND i.ref=$4"),
            &[&uuid::Uuid::from_bytes(restored.cohort.operation_id), &restored.cohort.epoch.as_slice(), &kind, &source, &requirement],
        ).await;
        client.batch_execute("ALTER TABLE openbot_internal.restore_reconfirm_requirements ENABLE TRIGGER restore_reconfirm_requirements_insert").await.unwrap();
        assert_eq!(inserted.unwrap(), 1, "the source is in the live inventory");
        requirement
    }

    /// One enabled personal model connection of `owner` in the fixture's
    /// namespace and its sealed current key. The connection writer needs a
    /// host request binding these worker-side tests do not have, so the rows
    /// are the writer's own two INSERTs.
    pub(crate) async fn model_connection(
        restored: &RestoreCurrentFixture,
        vault: &crate::vault::CredentialRecordVault,
        owner: &str,
    ) -> uuid::Uuid {
        use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
        let (connection, secret) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
        let sealed = vault
            .seal(
                &secret,
                SecretKind::Model,
                SecretPrincipal::Actor(openbot_contracts::ids::ActorId::new(owner)),
                SecretPrincipal::Service(ServiceId::new(connection.to_string())),
                &SecretBytes::new(b"RESTORED_MODEL_KEY_CANARY".to_vec()),
            )
            .unwrap();
        let config = openbot_application::model_connections::normalize_model_configuration(
            "Restored choice",
            openbot_contracts::model_connections::CustomModelProtocol::OpenaiChatCompletions,
            "https://restored-no-network.example.test/v1",
            "restored-model",
            true,
        )
        .unwrap();
        let mut client = restored.pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        tx.execute("INSERT INTO public.model_connections(id,deployment_id,tenant_id,owner_user_id,name,protocol,endpoint,model,enabled,revision,current_secret_id,created_at,updated_at)
            VALUES($1,'dep','ten',$2,$3,'openai_chat_completions',$4,$5,true,1,$6,clock_timestamp(),clock_timestamp())",
            &[&connection, &owner, &config.name, &config.endpoint, &config.model, &secret]).await.unwrap();
        tx.execute("INSERT INTO public.model_connection_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at)
            VALUES($1,$2,'dep','ten',$3,$4,clock_timestamp())", &[&secret, &connection, &owner, &sealed]).await.unwrap();
        tx.commit().await.unwrap();
        connection
    }
}

/// The Local subject producer on a published RestoreCurrent (spec revision
/// R484 ¶8087–8089, ¶8024): before its receipt the Current installation gate
/// stays closed, a cancelled request writes nothing, one request commits one
/// `fresh_local_os` receipt with its audit event, and only then does the
/// gate form the Current binding. The host's OS confirmation is not modelled
/// here; this proves the database side the host drives after it.
#[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
mod local_subject {
    use super::*;
    use crate::auth::single_user::desktop_local::{
        DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL, VerifiedRestoreInstallationBinding,
    };
    use crate::recovery_control::tests::restore_current::RestoreCurrentFixture;

    #[tokio::test]
    #[ignore = "requires OPENBOT_TEST_PG_BIN PostgreSQL 17.11 for an owned candidate"]
    async fn local_subject_receipt_commits_once_and_opens_the_current_binding_gate() {
        let restored = RestoreCurrentFixture::publish(
            &format!(
                "INSERT INTO public.users(id,email,email_verified,auth_generation) VALUES('{DESKTOP_LOCAL_ACTOR_ID}','{DESKTOP_LOCAL_EMAIL}',true,0);
                 INSERT INTO public.user_roles(user_id,role) VALUES('{DESKTOP_LOCAL_ACTOR_ID}','admin');"
            ),
            async |_| {},
        )
        .await;
        let client = restored.pool.get().await.unwrap();
        // The target's own restore row and cluster identity, read back.
        let row = client
            .query_one(
                "SELECT o.target_installation_id,o.deployment_id,o.tenant_id,o.dataset_id,
                        (SELECT system_identifier FROM pg_control_system()),
                        (SELECT oid FROM pg_database WHERE datname=current_database()),
                        current_setting('data_directory')
                   FROM openbot_internal.restore_pg_operations o WHERE o.operation_id=$1",
                &[&Uuid::from_bytes(restored.cohort.operation_id)],
            )
            .await
            .unwrap();
        let pending = |oid: u32| {
            VerifiedRestoreInstallationBinding::from_readback(
                [0, 1, 2, 3].map(|index| row.get::<_, String>(index)),
                std::path::PathBuf::from(row.get::<_, String>(6)),
                row.get::<_, i64>(4) as u64,
                oid,
            )
        };
        let oid: u32 = row.get(5);
        let audit_key = openbot_domain::vault::derive_application_key(
            &SecretBytes::new(vec![0x41; 32]),
            openbot_domain::vault::ApplicationKeyPurpose::AuditCheckpoint,
        )
        .unwrap();
        // One original deadline per request: its admission and its receipt share it.
        let due = Instant::now() + std::time::Duration::from_secs(60);
        let request = |cancel: CancellationToken| OriginalReconfirmationRequest::new(due, cancel);
        let deadline = || due;
        let receipts = || async {
            client
                .query_one(
                    "SELECT count(*)::bigint FROM openbot_internal.restore_reconfirm_receipts
                      WHERE confirmed_by=$1 AND proof_kind='fresh_local_os'",
                    &[&DESKTOP_LOCAL_ACTOR_ID],
                )
                .await
                .unwrap()
                .get::<_, i64>(0)
        };

        assert!(matches!(
            restored
                .runtime
                .current_restore_installation_before(&restored.pool, pending(oid), deadline())
                .await,
            Err(RestoreReconfirmationError::NotConfirmed)
        ));
        let other =
            restored
                .runtime
                .admit_restored_local_subject_before(&pending(oid + 1), 0, deadline());
        assert!(
            matches!(other, Err(RestoreReconfirmationError::NotVisible)),
            "another installation's facts"
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        let cancelled = restored
            .runtime
            .admit_restored_local_subject_before(&pending(oid), 0, deadline())
            .unwrap()
            .confirm_before(&restored.pool, audit_key.expose(), request(cancel))
            .await;
        assert!(matches!(
            cancelled,
            Err(RestoreReconfirmationError::Unavailable)
        ));
        assert_eq!(receipts().await, 0, "a cancelled request wrote a receipt");

        let fact = restored
            .runtime
            .admit_restored_local_subject_before(&pending(oid), 0, deadline())
            .unwrap()
            .confirm_before(
                &restored.pool,
                audit_key.expose(),
                request(CancellationToken::new()),
            )
            .await
            .unwrap();
        assert_eq!(receipts().await, 1);
        let audited: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM public.audit_events WHERE actor_user_id=$1 AND target_id=$2",
                &[&DESKTOP_LOCAL_ACTOR_ID, &fact.requirement_id().to_string()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            audited, 1,
            "the receipt's audit event is in its transaction"
        );
        // A second request adds no receipt and reads back the first.
        let again = restored
            .runtime
            .admit_restored_local_subject_before(&pending(oid), 0, deadline())
            .unwrap()
            .confirm_before(
                &restored.pool,
                audit_key.expose(),
                request(CancellationToken::new()),
            )
            .await
            .unwrap();
        assert_eq!(again.confirmation_id(), fact.confirmation_id());
        assert_eq!(receipts().await, 1);
        restored
            .runtime
            .current_restore_installation_before(&restored.pool, pending(oid), deadline())
            .await
            .unwrap();
    }
}
