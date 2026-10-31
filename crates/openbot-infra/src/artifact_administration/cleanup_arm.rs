//! Current original saved-owner arming on one guarded connection and one absolute budget.
//! Arming preserves the available record, charge and bytes; its private value is not a delete grant.

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use openbot_contracts::artifacts::{
    ArtifactGoneStatus, canonical_artifact_uuid_v7, is_valid_artifact_identity,
    is_valid_artifact_sha256,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::request_binding::{
    ArtifactCleanupHostObservation, ArtifactCleanupHostTailWitness, ArtifactCleanupHostTarget,
    ArtifactCleanupSessionFacts, HostRequestBindingError, HostRequestBindingKind,
};
use openbot_domain::artifact_cleanup::{ArtifactCleanupFence, ArtifactCleanupFenceKey};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::identity::roles::resolve_effective_role;
use serde_json::Value;
use time::OffsetDateTime;
use tokio_postgres::types::FromSql;
use tokio_postgres::{Row, Transaction};

use super::{PostgresArtifactAdministration, verify_artifact_read_schema_on};
use crate::artifact_bytes::ArtifactBlob;
use crate::artifact_store::{
    ArtifactReadControlledBarrier, ArtifactStoreError, DatasetBoundArtifactStore,
};
use crate::auth::single_user::desktop_local::{DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL};
use crate::db::pool::TransactionOwnerError;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

/// Closed trusted-port errors, without storage identities, SQL, paths or host secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactCleanupArmError {
    /// The selector violates the existing artifact input shape.
    #[error("artifact_cleanup_input_invalid:{field}")]
    InvalidInput {
        /// A registered static field, never the caller's text.
        field: &'static str,
    },
    /// The actual original trusted host cannot attest this request.
    #[error("artifact_cleanup_host_invalid")]
    Host(HostRequestBindingError),
    /// The original owner lacks current management authority.
    #[error("artifact_cleanup_not_visible")]
    NotVisible,
    /// Existing state or an immutable intent contradicts this arm.
    #[error("artifact_cleanup_conflict")]
    Conflict,
    /// A dependency or the original absolute budget is unavailable.
    #[error("artifact_cleanup_unavailable")]
    Unavailable,
    /// Real retained facts violate the registered internal invariant.
    #[error("artifact_cleanup_stored_facts_invalid:{field}")]
    Corrupt {
        /// A registered static field, without identifiers or SQL.
        field: &'static str,
    },
    /// The actual original COMMIT started without a confirmed ACK.
    #[error("artifact_cleanup_commit_unknown")]
    CommitUnknown,
    /// The original COMMIT ACK is known but arrived after its budget.
    #[error("artifact_cleanup_commit_acknowledged_after_deadline")]
    CommitAcknowledgedAfterDeadline,
    /// The original ROLLBACK ACK is known but arrived after its budget.
    #[error("artifact_cleanup_rollback_acknowledged_after_deadline")]
    RollbackAcknowledgedAfterDeadline,
}

type Error = ArtifactCleanupArmError;

enum OriginalConfirmation {
    CommitAcknowledged,
    NoopRollbackAcknowledged,
}

/// A confirmed immutable intent bound to this exact original Store. Private construction is
/// restricted to the original transaction ACK path; it supplies no physical deletion authority.
pub struct ArmedArtifactCleanupIntent {
    store: Arc<DatasetBoundArtifactStore>,
    fence: ArtifactCleanupFence,
    _confirmation: OriginalConfirmation,
}

impl core::fmt::Debug for ArmedArtifactCleanupIntent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ArmedArtifactCleanupIntent([redacted confirmed intent])")
    }
}

/// Mechanical original locator only. No confirmation or current host grant is copied.
pub(super) struct OwnedCleanupPhysicalBinding {
    original_store: Arc<DatasetBoundArtifactStore>,
    original_key: ArtifactCleanupFenceKey,
}

impl OwnedCleanupPhysicalBinding {
    pub(super) fn into_original_parts(
        self,
    ) -> (Arc<DatasetBoundArtifactStore>, ArtifactCleanupFenceKey) {
        (self.original_store, self.original_key)
    }
}

impl ArmedArtifactCleanupIntent {
    // The terminal producer borrows only the same checked mechanical locator. The original
    // armed confirmation supplies neither current permission nor a terminal/IO grant.
    pub(super) fn validated_terminal_binding(
        &self,
        administration: &PostgresArtifactAdministration,
    ) -> Result<OwnedCleanupPhysicalBinding, ArtifactStoreError> {
        self.validated_physical_binding(administration)
    }

    pub(super) fn validated_physical_binding(
        &self,
        administration: &PostgresArtifactAdministration,
    ) -> Result<OwnedCleanupPhysicalBinding, ArtifactStoreError> {
        if !Arc::ptr_eq(&administration.store, &self.store)
            || !administration
                .store
                .matches_registry_owner(&administration.registry)
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let key = self.fence.key();
        let binding = administration.registry.binding();
        let strict = ArtifactCleanupFenceKey::from_stored(
            key.deployment_id().clone(),
            key.tenant_id().clone(),
            key.dataset_id(),
            key.operation_id().as_str(),
            key.artifact_id(),
        )
        .map_err(|_| ArtifactStoreError::BindingMismatch)?;
        if strict != *key
            || key.deployment_id().as_str() != binding.deployment_id()
            || key.tenant_id().as_str() != binding.tenant_id()
            || key.dataset_id() != binding.dataset_id()
            || self.fence.terminal_status() != ArtifactGoneStatus::Deleted
            || self.fence.phase()
                != openbot_domain::artifact_cleanup::ArtifactCleanupFencePhase::Armed
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        Ok(OwnedCleanupPhysicalBinding {
            original_store: Arc::clone(&self.store),
            original_key: strict,
        })
    }
}

impl PostgresArtifactAdministration {
    /// Arm only an available explicitly saved artifact owned by the actual current requester.
    /// Source deletion does not remove this retained owner's management right or reopen reads.
    ///
    /// # Errors
    /// Refuses a foreign original host, revoked owner, bad retained pair or uncertain original ACK.
    pub async fn arm_explicit_saved_delete_before(
        self: &Arc<Self>,
        auth: &AuthContext,
        artifact_id: &str,
        original_deadline: Instant,
    ) -> Result<ArmedArtifactCleanupIntent, Error> {
        let capture_operation = self
            .store
            .begin_capture_mutation()
            .map_err(|_| Error::Unavailable)?;
        let result = async {
            let entry_limit = Instant::now()
                .checked_add(Duration::from_secs(5))
                .ok_or(Error::Unavailable)?;
            let deadline = original_deadline.min(entry_limit);
            remaining(deadline)?;
            let artifact_id =
                canonical_artifact_uuid_v7(artifact_id).ok_or(Error::InvalidInput {
                    field: "artifact_id",
                })?;
            self.check_namespace(auth).map_err(|_| Error::NotVisible)?;
            if !self.store.matches_registry_owner(&self.registry) {
                return Err(corrupt("store_binding"));
            }
            let authority = self.read_authority();
            let target = authority.cleanup_host_target(auth);
            let binding = auth
                .request_binding()
                .ok_or(Error::Host(HostRequestBindingError::Missing))?;
            let host = binding
                .borrow_artifact_cleanup_host_before(auth, &target, deadline)
                .map_err(Error::Host)?;
            let current = CurrentRequest {
                administration: self,
                auth,
                host,
            };
            current.check_attachment(deadline)?;
            let mut client = self
                .registry
                .pool()
                .get_guarded(deadline)
                .await
                .map_err(|_| Error::Unavailable)?;
            // All native/public/0041/0042/0044 observations occur before BEGIN on this original
            // guarded client. Failure here retires it; no begun-transaction rollback is claimed.
            let schema = bounded(deadline, async {
                Ok::<_, core::convert::Infallible>(
                    verify_artifact_read_schema_on(client.as_client()).await,
                )
            })
            .await?;
            schema.map_err(|error| match error {
                openbot_application::ArtifactAdministrationError::Unavailable => Error::Unavailable,
                _ => corrupt("schema"),
            })?;
            let transaction = client.begin_read_committed().await.map_err(owner_error)?;
            let result = current
                .operate(transaction.as_transaction(), &artifact_id, deadline)
                .await;
            let (fence, confirmation, witness) = match result {
                Ok((fence, true, witness)) => {
                    transaction.commit().await.map_err(owner_error)?;
                    (fence, OriginalConfirmation::CommitAcknowledged, witness)
                }
                result => {
                    // Refusals and exact no-op observations require the real original ROLLBACK ACK.
                    transaction.rollback().await.map_err(owner_error)?;
                    let (fence, inserted, witness) = result?;
                    debug_assert!(!inserted);
                    (
                        fence,
                        OriginalConfirmation::NoopRollbackAcknowledged,
                        witness,
                    )
                }
            };
            // A Host/window may close while the original protocol ACK is in flight. Preserve the
            // same statement's original witness across that await and recheck before publishing.
            // Failure after a known COMMIT retains the armed fact; it is never recast as Unknown.
            witness
                .verify_current(auth, deadline)
                .map_err(Error::Host)?;
            Ok(ArmedArtifactCleanupIntent {
                store: Arc::clone(&self.store),
                fence,
                _confirmation: confirmation,
            })
        }
        .await;
        if !matches!(&result, Err(Error::Unavailable | Error::CommitUnknown)) {
            capture_operation.complete();
        }
        result
    }

    /// Permanently close this original Store's controlled read inventory for a confirmed arm.
    /// A barrier ACK neither proves physical absence nor authorizes unlink or a quota refund.
    ///
    /// # Errors
    /// A foreign Store, registry owner or malformed original five-key is refused.
    pub fn close_armed_artifact_reads(
        self: &Arc<Self>,
        intent: &ArmedArtifactCleanupIntent,
    ) -> Result<ArtifactReadControlledBarrier, ArtifactStoreError> {
        let (_, strict) = intent
            .validated_physical_binding(self)?
            .into_original_parts();
        self.store.close_artifact_reads(strict)
    }
}

struct CurrentRequest<'a> {
    administration: &'a PostgresArtifactAdministration,
    auth: &'a AuthContext,
    host: ArtifactCleanupHostObservation<'a>,
}

/// Only the existing enrolled original Host factory is borrowed. Terminal decoding and quota
/// access remain in its sibling producer, without changing the original available-only arm.
pub(super) struct TerminalCurrentRequest<'a> {
    current: CurrentRequest<'a>,
}

pub(super) struct TerminalCurrentFailure {
    pub(super) error: ArtifactCleanupArmError,
    pub(super) query_unproven: bool,
}

impl TerminalCurrentFailure {
    fn known(error: ArtifactCleanupArmError) -> Self {
        Self {
            error,
            query_unproven: false,
        }
    }

    fn unavailable() -> Self {
        Self {
            error: Error::Unavailable,
            query_unproven: true,
        }
    }
}

impl<'a> TerminalCurrentRequest<'a> {
    pub(super) fn borrow_before(
        administration: &'a PostgresArtifactAdministration,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactCleanupHostTarget,
        deadline: Instant,
    ) -> Result<Self, Error> {
        PhysicalCurrentRequest::borrow_before(administration, auth, target, deadline).map(
            |original| Self {
                current: original.current,
            },
        )
    }

    // Exactly one registered terminal joint statement, never caller-provided SQL. In particular
    // it never joins quota, so a completed tombstone cannot reconstruct/access its old payload.
    pub(super) async fn observe_before(
        &self,
        tx: &Transaction<'_>,
        key: &ArtifactCleanupFenceKey,
        deadline: Instant,
    ) -> Result<(Row, Box<dyn ArtifactCleanupHostTailWitness>), TerminalCurrentFailure> {
        remaining(deadline).map_err(|_| TerminalCurrentFailure::unavailable())?;
        self.current
            .check_attachment(deadline)
            .map_err(TerminalCurrentFailure::known)?;
        let administration = self.current.administration;
        let binding = administration.registry.binding();
        let physical = administration.store.physical_binding();
        let epoch = self.current.host.server_session_epoch();
        let session_lookup = epoch.as_ref().map(|value| value.lookup_id());
        let store_id = administration.store.store_id().to_string();
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            tx.query_one(
                super::cleanup_terminal::current_joint_sql(
                    self.current.host.kind() == HostRequestBindingKind::DesktopWindow,
                ),
                &[
                    &binding.deployment_id(),
                    &binding.tenant_id(),
                    &binding.dataset_id(),
                    &key.artifact_id(),
                    &self.current.auth.actor().as_str(),
                    &session_lookup,
                    &binding.binding_schema(),
                    &binding.initial_origin(),
                    &binding.created_at(),
                    &store_id,
                    &physical.device(),
                    &physical.inode(),
                    &physical.uid(),
                ],
            ),
        )
        .await
        .map_err(|_| TerminalCurrentFailure::unavailable())?;
        remaining(deadline).map_err(|_| TerminalCurrentFailure::unavailable())?;
        let row = result.map_err(|error| TerminalCurrentFailure {
            error: Error::Unavailable,
            // A true server ErrorResponse is known statement failure; its original transaction
            // must still really rollback. Connection/driver/protocol loss is never that proof.
            query_unproven: error.as_db_error().is_none(),
        })?;
        self.current
            .check_attachment(deadline)
            .map_err(TerminalCurrentFailure::known)?;
        let facts = self
            .current
            .decode_host(&row)
            .map_err(TerminalCurrentFailure::known)?;
        let witness = self
            .current
            .host
            .witness(self.current.auth, facts, deadline)
            .map_err(|error| TerminalCurrentFailure::known(Error::Host(error)))?;
        witness
            .verify_current(self.current.auth, deadline)
            .map_err(|error| TerminalCurrentFailure::known(Error::Host(error)))?;
        remaining(deadline).map_err(|_| TerminalCurrentFailure::unavailable())?;
        Ok((row, witness))
    }
}

/// Borrowed original factory; its explicit original target lives in the owned supervisor.
pub(super) struct PhysicalCurrentRequest<'a> {
    current: CurrentRequest<'a>,
}

/// Immutable original comparison and a current statement's owned tail, neither an IO grant.
pub(super) struct PhysicalCurrentSnapshot {
    snapshot: Snapshot,
    blob: ArtifactBlob,
}

impl<'a> PhysicalCurrentRequest<'a> {
    pub(super) fn borrow_before(
        administration: &'a PostgresArtifactAdministration,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactCleanupHostTarget,
        deadline: Instant,
    ) -> Result<Self, Error> {
        remaining(deadline)?;
        administration
            .check_namespace(auth)
            .map_err(|_| Error::NotVisible)?;
        if !administration
            .store
            .matches_registry_owner(&administration.registry)
        {
            return Err(corrupt("store_binding"));
        }
        let binding = auth
            .request_binding()
            .ok_or(Error::Host(HostRequestBindingError::Missing))?;
        let host = binding
            .borrow_artifact_cleanup_host_before(auth, target, deadline)
            .map_err(Error::Host)?;
        let current = CurrentRequest {
            administration,
            auth,
            host,
        };
        current.check_attachment(deadline)?;
        Ok(Self { current })
    }

    pub(super) async fn lock_before(
        &self,
        tx: &Transaction<'_>,
        key: &ArtifactCleanupFenceKey,
        deadline: Instant,
    ) -> Result<PhysicalCurrentSnapshot, Error> {
        let snapshot = self
            .current
            .lock_current(tx, key.artifact_id(), deadline)
            .await?;
        PhysicalCurrentSnapshot::from_current(snapshot, key)
    }

    pub(super) async fn refresh_before(
        &self,
        tx: &Transaction<'_>,
        original: &PhysicalCurrentSnapshot,
        deadline: Instant,
    ) -> Result<PhysicalCurrentSnapshot, Error> {
        let snapshot = self
            .current
            .observe(tx, original.snapshot.candidate.key.artifact_id(), deadline)
            .await?;
        snapshot.require_same(&original.snapshot.candidate)?;
        PhysicalCurrentSnapshot::from_current(snapshot, &original.snapshot.candidate.key)
    }
}

impl PhysicalCurrentSnapshot {
    fn from_current(snapshot: Snapshot, key: &ArtifactCleanupFenceKey) -> Result<Self, Error> {
        if snapshot.candidate.key != *key
            || snapshot.candidate.fence.as_ref()
                != Some(&ArtifactCleanupFence::armed(
                    key.clone(),
                    ArtifactGoneStatus::Deleted,
                ))
        {
            return Err(Error::Conflict);
        }
        let id = uuid::Uuid::parse_str(key.artifact_id()).map_err(|_| corrupt("stored_uuid"))?;
        let length = number(&snapshot.candidate.record, "byte_length", "record_pair")?;
        let length = u64::try_from(length).map_err(|_| corrupt("record_pair"))?;
        let digest =
            super::parse_digest(text(&snapshot.candidate.record, "sha256", "record_pair")?)
                .map_err(|_| corrupt("record_pair"))?;
        let blob =
            ArtifactBlob::from_record(id, length, digest).map_err(|_| corrupt("record_pair"))?;
        Ok(Self { snapshot, blob })
    }

    pub(super) fn blob(&self) -> &ArtifactBlob {
        &self.blob
    }

    pub(super) fn into_witness(self) -> Box<dyn ArtifactCleanupHostTailWitness> {
        self.snapshot.witness
    }
}

impl CurrentRequest<'_> {
    fn check_attachment(&self, deadline: Instant) -> Result<(), Error> {
        remaining(deadline)?;
        let binding = self
            .auth
            .request_binding()
            .ok_or(Error::Host(HostRequestBindingError::Missing))?;
        if self.host.kind() != binding.kind()
            || !self.host.identity().same_binding(binding.identity())
            || !matches!(
                self.host.kind(),
                HostRequestBindingKind::ServerSession | HostRequestBindingKind::DesktopWindow
            )
        {
            return Err(Error::Host(HostRequestBindingError::NotCurrent));
        }
        Ok(())
    }

    async fn observe(
        &self,
        tx: &Transaction<'_>,
        artifact: &str,
        deadline: Instant,
    ) -> Result<Snapshot, Error> {
        self.check_attachment(deadline)?;
        let binding = self.administration.registry.binding();
        let physical = self.administration.store.physical_binding();
        let epoch = self.host.server_session_epoch();
        let session_lookup = epoch.as_ref().map(|value| value.lookup_id());
        let row = bounded(
            deadline,
            tx.query_one(
                current_sql(self.host.kind() == HostRequestBindingKind::DesktopWindow),
                &[
                    &binding.deployment_id(),
                    &binding.tenant_id(),
                    &binding.dataset_id(),
                    &artifact,
                    &self.auth.actor().as_str(),
                    &session_lookup,
                    &binding.binding_schema(),
                    &binding.initial_origin(),
                    &binding.created_at(),
                    &self.administration.store.store_id().to_string(),
                    &physical.device(),
                    &physical.inode(),
                    &physical.uid(),
                ],
            ),
        )
        .await?;
        self.check_attachment(deadline)?;
        let facts = self.decode_host(&row)?;
        let witness = self
            .host
            .witness(self.auth, facts, deadline)
            .map_err(Error::Host)?;
        let candidate = Candidate::decode(&row, self.administration, self.auth, artifact)?;
        witness
            .verify_current(self.auth, deadline)
            .map_err(Error::Host)?;
        Ok(Snapshot { candidate, witness })
    }

    fn decode_host(&self, row: &Row) -> Result<Option<ArtifactCleanupSessionFacts>, Error> {
        let actor: Option<String> = column(row, "current_actor")?;
        let raw_generation: Option<i64> = column(row, "current_generation")?;
        let generation = raw_generation
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(Error::NotVisible)?;
        if actor.as_deref() != Some(self.auth.actor().as_str())
            || generation != self.auth.auth_generation().get()
            || column::<bool>(row, "denied")?
        {
            return Err(Error::NotVisible);
        }
        let roles: Vec<String> = column(row, "current_roles")?;
        let parsed = roles
            .iter()
            .map(|value| value.parse::<Role>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::NotVisible)?;
        if !parsed
            .iter()
            .any(|role| matches!(role, Role::User | Role::Admin))
        {
            return Err(Error::NotVisible);
        }
        let facts = match self.host.kind() {
            HostRequestBindingKind::ServerSession => {
                if self.auth.is_single_user() {
                    return Err(Error::NotVisible);
                }
                let epoch = self.host.server_session_epoch().ok_or(Error::NotVisible)?;
                let (
                    Some(id),
                    Some(user),
                    Some(token),
                    Some(created),
                    Some(updated),
                    Some(expires),
                    Some(issued),
                ) = (
                    column::<Option<String>>(row, "session_id")?,
                    column::<Option<String>>(row, "session_user")?,
                    column::<Option<String>>(row, "session_token")?,
                    column::<Option<OffsetDateTime>>(row, "session_created")?,
                    column::<Option<OffsetDateTime>>(row, "session_updated")?,
                    column::<Option<OffsetDateTime>>(row, "session_expires")?,
                    column::<Option<i64>>(row, "session_generation")?,
                )
                else {
                    return Err(Error::NotVisible);
                };
                if !epoch.matches_raw_row(&id, &user, &token, created, issued)
                    || Some(issued) != raw_generation
                {
                    return Err(Error::NotVisible);
                }
                let role = resolve_effective_role(parsed).map_err(|_| Error::NotVisible)?;
                let current = AuthContextBuilder::from_verified_session(
                    self.auth.deployment().clone(),
                    self.auth.tenant().clone(),
                    self.auth.actor().clone(),
                    AuthGeneration::new(generation),
                    false,
                )
                .with_role(role)
                .build();
                if current != *self.auth {
                    return Err(Error::NotVisible);
                }
                Some(ArtifactCleanupSessionFacts {
                    created_at: created,
                    updated_at: updated,
                    expires_at: expires,
                    observed_wall: OffsetDateTime::now_utc(),
                    observed_monotonic: Instant::now(),
                })
            }
            HostRequestBindingKind::DesktopWindow => {
                if !self.auth.is_single_user()
                    || self.host.server_session_epoch().is_some()
                    || self.auth.actor().as_str() != DESKTOP_LOCAL_ACTOR_ID
                    || column::<Option<String>>(row, "current_email")?.as_deref()
                        != Some(DESKTOP_LOCAL_EMAIL)
                    || roles.as_slice() != ["admin"]
                    || !self
                        .administration
                        .registry
                        .matches_desktop_read_current_row(row)
                        .map_err(|_| Error::Unavailable)?
                {
                    return Err(Error::NotVisible);
                }
                let current = AuthContextBuilder::from_verified_session(
                    self.auth.deployment().clone(),
                    self.auth.tenant().clone(),
                    self.auth.actor().clone(),
                    AuthGeneration::new(generation),
                    true,
                )
                .with_roles([Role::Admin, Role::User])
                .build();
                if current != *self.auth {
                    return Err(Error::NotVisible);
                }
                None
            }
            HostRequestBindingKind::ServerSingleUserOwner => {
                return Err(Error::Host(HostRequestBindingError::NotCurrent));
            }
        };
        Ok(facts)
    }

    async fn lock_current(
        &self,
        tx: &Transaction<'_>,
        artifact: &str,
        deadline: Instant,
    ) -> Result<Snapshot, Error> {
        self.check_attachment(deadline)?;
        if bounded(
            deadline,
            tx.query_opt(
                "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
                &[&self.auth.actor().as_str()],
            ),
        )
        .await?
        .is_none()
        {
            return Err(Error::NotVisible);
        }
        // Fresh joint RC observation AFTER the only first actor lock; it includes the real Host.
        let original = self.observe(tx, artifact, deadline).await?;
        let role_rows = bounded(deadline, tx.query("SELECT role FROM public.user_roles WHERE user_id=$1 AND role IN ('user','admin') FOR SHARE NOWAIT", &[&self.auth.actor().as_str()])).await?;
        if role_rows.is_empty() {
            return Err(Error::NotVisible);
        }
        let binding = self.administration.registry.binding();
        let candidate = &original.candidate;
        if bounded(deadline, tx.query_opt("SELECT charged_bytes FROM openbot_internal.artifact_workspace_quotas WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 AND workspace_id=$5 FOR UPDATE", &[
            &binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id(), &candidate.workspace_kind, &candidate.workspace_id,
        ])).await?.is_none() { return Err(corrupt("workspace_quota")); }
        self.observe(tx, artifact, deadline)
            .await?
            .require_same(candidate)?;
        if bounded(deadline, tx.query_opt("SELECT operation_id FROM openbot_internal.artifact_save_operations WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 FOR UPDATE", &[
            &binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id(), &candidate.operation_id,
        ])).await?.is_none() { return Err(corrupt("operation_pair")); }
        self.observe(tx, artifact, deadline)
            .await?
            .require_same(candidate)?;
        if bounded(deadline, tx.query_opt("SELECT artifact_id FROM openbot_internal.artifact_records WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 FOR UPDATE", &[
            &binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id(), &artifact,
        ])).await?.is_none() { return Err(corrupt("record_pair")); }
        self.observe(tx, artifact, deadline)
            .await?
            .require_same(candidate)?;
        bounded(deadline, tx.query_opt("SELECT artifact_id FROM openbot_internal.artifact_cleanup_fences WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 FOR UPDATE", &[
            &binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id(), &artifact,
        ])).await?;
        let locked = self.observe(tx, artifact, deadline).await?;
        locked.require_same(candidate)?;
        Ok(locked)
    }

    async fn operate(
        &self,
        tx: &Transaction<'_>,
        artifact: &str,
        deadline: Instant,
    ) -> Result<
        (
            ArtifactCleanupFence,
            bool,
            Box<dyn ArtifactCleanupHostTailWitness>,
        ),
        Error,
    > {
        let locked = self.lock_current(tx, artifact, deadline).await?;
        let candidate = &locked.candidate;
        let binding = self.administration.registry.binding();
        if let Some(fence) = &locked.candidate.fence {
            locked.verify_tail(self.auth, deadline)?;
            return Ok((fence.clone(), false, locked.witness));
        }
        let fence = ArtifactCleanupFence::armed(candidate.key.clone(), ArtifactGoneStatus::Deleted);
        let inserted = bounded(deadline, tx.execute("INSERT INTO openbot_internal.artifact_cleanup_fences (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) VALUES($1,$2,$3,$4,$5,'deleted','armed') ON CONFLICT DO NOTHING", &[
            &binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id(), &candidate.operation_id, &artifact,
        ])).await?;
        let after_insert = self.observe(tx, artifact, deadline).await?;
        after_insert.require_same(candidate)?;
        if after_insert.candidate.fence.as_ref() != Some(&fence) {
            return Err(Error::Conflict);
        }
        if inserted == 0 {
            after_insert.verify_tail(self.auth, deadline)?;
            return Ok((fence, false, after_insert.witness));
        }
        if inserted != 1 {
            return Err(corrupt("cleanup_fence"));
        }
        let (id, created_at) = bounded(deadline, next_event_coordinates(tx)).await?;
        // Coordinate allocation and hash-chain append may wait; both are followed by a fresh
        // joint statement. No source locks, idle touch, quota repair or replacement Pool occur.
        let after_coordinates = self.observe(tx, artifact, deadline).await?;
        after_coordinates.require_same(candidate)?;
        let artifact_id = AuditIdentifier::new(artifact).map_err(|_| corrupt("stored_uuid"))?;
        let operation_id =
            AuditIdentifier::new(&candidate.operation_id).map_err(|_| corrupt("stored_uuid"))?;
        let event = AuditEvent {
            id,
            actor: Some(self.auth.actor().clone()),
            event_type: AuditEventType::ARTIFACT_CLEANUP_ARMED,
            target_kind: AuditLabel::new("artifact"),
            target_id: Some(artifact_id.clone()),
            payload: AuditPayload::from_facts([
                AuditFact::ArtifactId(artifact_id),
                AuditFact::ArtifactOperationId(operation_id),
            ])
            .map_err(|_| corrupt("cleanup_fence"))?,
            created_at,
        };
        bounded(
            deadline,
            append_event_in_transaction(tx, &event, self.administration.audit_key.expose()),
        )
        .await?;
        let final_snapshot = self.observe(tx, artifact, deadline).await?;
        final_snapshot.require_same(candidate)?;
        if final_snapshot.candidate.fence.as_ref() != Some(&fence) {
            return Err(Error::Conflict);
        }
        final_snapshot.verify_tail(self.auth, deadline)?;
        Ok((fence, true, final_snapshot.witness))
    }
}

struct Snapshot {
    candidate: Candidate,
    witness: Box<dyn ArtifactCleanupHostTailWitness>,
}

impl Snapshot {
    fn require_same(&self, original: &Candidate) -> Result<(), Error> {
        if self.candidate.record == original.record
            && self.candidate.operation == original.operation
            && self.candidate.receipt == original.receipt
            && self.candidate.key == original.key
        {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }

    fn verify_tail(&self, auth: &AuthContext, deadline: Instant) -> Result<(), Error> {
        remaining(deadline)?;
        self.witness
            .verify_current(auth, deadline)
            .map_err(Error::Host)
    }
}

struct Candidate {
    record: Value,
    operation: Value,
    receipt: Value,
    key: ArtifactCleanupFenceKey,
    operation_id: String,
    workspace_kind: String,
    workspace_id: String,
    fence: Option<ArtifactCleanupFence>,
}

impl Candidate {
    fn decode(
        row: &Row,
        administration: &PostgresArtifactAdministration,
        auth: &AuthContext,
        artifact: &str,
    ) -> Result<Self, Error> {
        if !column::<bool>(row, "store_matches")?
            || !administration
                .store
                .matches_registry_owner(&administration.registry)
        {
            return Err(corrupt("store_binding"));
        }
        let record = column::<Option<Value>>(row, "record_row")?.ok_or(Error::NotVisible)?;
        let operation =
            column::<Option<Value>>(row, "operation_row")?.ok_or(corrupt("operation_pair"))?;
        let receipt =
            column::<Option<Value>>(row, "receipt_row")?.ok_or(corrupt("positive_receipt"))?;
        let quota = column::<Option<Value>>(row, "quota_row")?.ok_or(corrupt("workspace_quota"))?;
        let binding = administration.registry.binding();
        let operation_id = text(&record, "operation_id", "record_pair")?.to_owned();
        for (field, expected) in [
            ("deployment_id", binding.deployment_id()),
            ("tenant_id", binding.tenant_id()),
            ("dataset_id", binding.dataset_id()),
            ("artifact_id", artifact),
            ("operation_id", operation_id.as_str()),
        ] {
            for (value, tag) in [
                (&record, "record_pair"),
                (&operation, "operation_pair"),
                (&receipt, "positive_receipt"),
            ] {
                if text(value, field, tag)? != expected {
                    return Err(corrupt(tag));
                }
            }
        }
        for field in [
            "request_id",
            "owner_actor_id",
            "source_thread_id",
            "source_run_id",
            "source_message_id",
            "source_call_seq",
            "source_attempt_seq",
        ] {
            let expected = member(&record, field, "record_pair")?;
            if member(&operation, field, "operation_pair")? != expected
                || member(&receipt, field, "positive_receipt")? != expected
            {
                return Err(corrupt("positive_receipt"));
            }
        }
        if text(&record, "owner_actor_id", "record_pair")? != auth.actor().as_str() {
            return Err(Error::NotVisible);
        }
        if text(&record, "status", "record_pair")? != "available"
            || text(&operation, "state", "operation_pair")? != "available"
        {
            return Err(Error::Conflict);
        }
        for field in ["request_id", "operation_id", "artifact_id"] {
            let value = text(&record, field, "record_pair")?;
            if canonical_artifact_uuid_v7(value).as_deref() != Some(value) {
                return Err(corrupt("stored_uuid"));
            }
        }
        for field in [
            "owner_actor_id",
            "source_thread_id",
            "source_run_id",
            "source_message_id",
        ] {
            if !is_valid_artifact_identity(text(&record, field, "record_pair")?) {
                return Err(corrupt("record_pair"));
            }
        }
        match (
            member(&record, "source_call_seq", "record_pair")?,
            member(&record, "source_attempt_seq", "record_pair")?,
        ) {
            (Value::Null, Value::Null) => {}
            (call, attempt)
                if call.as_i64().is_some_and(|n| n >= 0)
                    && attempt.as_i64().is_some_and(|n| n >= 0) => {}
            _ => return Err(corrupt("record_pair")),
        }
        if text(&record, "retention_class", "record_pair")? != "explicit_saved"
            || text(&record, "saved_by", "record_pair")? != auth.actor().as_str()
            || text(&record, "media_type", "record_pair")? != "text/plain; charset=utf-8"
            || !member(&record, "saved_at", "record_pair")?.is_string()
        {
            return Err(corrupt("record_pair"));
        }
        let workspace_kind = text(&record, "workspace_kind", "record_pair")?.to_owned();
        let workspace_id = text(&record, "workspace_id", "record_pair")?.to_owned();
        if !matches!(workspace_kind.as_str(), "thread" | "channel")
            || !is_valid_artifact_identity(&workspace_id)
        {
            return Err(corrupt("record_pair"));
        }
        for (field, expected) in [
            ("workspace_kind", workspace_kind.as_str()),
            ("workspace_id", workspace_id.as_str()),
        ] {
            if text(&operation, field, "operation_pair")? != expected
                || text(&quota, field, "workspace_quota")? != expected
            {
                return Err(corrupt("workspace_quota"));
            }
        }
        for (field, expected) in [
            ("deployment_id", binding.deployment_id()),
            ("tenant_id", binding.tenant_id()),
            ("dataset_id", binding.dataset_id()),
        ] {
            if text(&quota, field, "workspace_quota")? != expected {
                return Err(corrupt("workspace_quota"));
            }
        }
        let store_id = text(&operation, "store_id", "operation_pair")?;
        if canonical_artifact_uuid_v7(store_id).as_deref() != Some(store_id)
            || store_id != administration.store.store_id().to_string()
        {
            return Err(corrupt("store_binding"));
        }
        let bytes = number(&record, "byte_length", "record_pair")?;
        let digest = text(&record, "sha256", "record_pair")?;
        if !(1..=67_108_864).contains(&bytes)
            || !is_valid_artifact_sha256(digest)
            || number(&operation, "expected_bytes", "operation_pair")? != bytes
            || number(&operation, "charged_bytes", "operation_pair")? != bytes
            || number(&operation, "actual_byte_length", "operation_pair")? != bytes
            || text(&operation, "expected_sha256", "operation_pair")? != digest
            || text(&operation, "actual_sha256", "operation_pair")? != digest
            || member(&operation, "actual_absent", "operation_pair")? != &Value::Bool(false)
            || text(&operation, "actual_location", "operation_pair")? != "object"
            || text(&operation, "observation_phase", "operation_pair")? != "installed"
            || !member(&operation, "created_at", "operation_pair")?.is_string()
        {
            return Err(corrupt("operation_pair"));
        }
        let charged = number(&quota, "charged_bytes", "workspace_quota")?;
        if charged < bytes || charged > 17_179_869_184 {
            return Err(corrupt("workspace_quota"));
        }
        let key = ArtifactCleanupFenceKey::from_stored(
            auth.deployment().clone(),
            auth.tenant().clone(),
            binding.dataset_id(),
            &operation_id,
            artifact,
        )
        .map_err(|_| corrupt("stored_uuid"))?;
        let fence = if let Some(value) = column::<Option<Value>>(row, "fence_row")? {
            let actual_key = ArtifactCleanupFenceKey::from_stored(
                openbot_contracts::ids::DeploymentId::new(text(
                    &value,
                    "deployment_id",
                    "cleanup_fence",
                )?),
                openbot_contracts::ids::TenantId::new(text(&value, "tenant_id", "cleanup_fence")?),
                text(&value, "dataset_id", "cleanup_fence")?,
                text(&value, "operation_id", "cleanup_fence")?,
                text(&value, "artifact_id", "cleanup_fence")?,
            )
            .map_err(|_| corrupt("cleanup_fence"))?;
            let actual = ArtifactCleanupFence::from_stored(
                actual_key,
                text(&value, "terminal_status", "cleanup_fence")?,
                text(&value, "phase", "cleanup_fence")?,
            )
            .map_err(|_| corrupt("cleanup_fence"))?;
            if actual != ArtifactCleanupFence::armed(key.clone(), ArtifactGoneStatus::Deleted) {
                return Err(Error::Conflict);
            }
            Some(actual)
        } else {
            None
        };
        Ok(Self {
            record,
            operation,
            receipt,
            key,
            operation_id,
            workspace_kind,
            workspace_id,
            fence,
        })
    }
}

fn current_sql(desktop: bool) -> &'static str {
    static SERVER: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    (if desktop { &DESKTOP } else { &SERVER }).get_or_init(|| {
        let (canary_columns, canary_joins) = if desktop { (
            ",pcs.system_identifier::text AS read_database_system_identifier,d.oid AS read_database_oid, \
             CASE WHEN octet_length(c.dataset_id)=32 THEN c.dataset_id END AS read_canary_dataset, \
             CASE WHEN octet_length(c.deployment_id) BETWEEN 1 AND 512 THEN c.deployment_id END AS read_canary_deployment, \
             CASE WHEN octet_length(c.tenant_id) BETWEEN 1 AND 512 THEN c.tenant_id END AS read_canary_tenant, \
             CASE WHEN octet_length(c.key_id)=32 THEN c.key_id END AS read_canary_key, \
             c.key_version AS read_canary_key_version,c.canary_schema AS read_canary_schema, \
             CASE WHEN octet_length(c.encrypted_canary) BETWEEN 1 AND 4096 THEN c.encrypted_canary END AS read_canary_encrypted",
            " LEFT JOIN pg_control_system() pcs ON true LEFT JOIN pg_database d ON d.datname=current_database() \
              LEFT JOIN openbot_internal.desktop_vault_canaries c ON c.deployment_id=$1 AND c.tenant_id=$2 AND c.key_version=1",
        ) } else { ("", "") };
        format!("/* artifact_cleanup_arm_current_joint */ SELECT to_jsonb(r) AS record_row,to_jsonb(o) AS operation_row, \
          to_jsonb(p) AS receipt_row,to_jsonb(q) AS quota_row,to_jsonb(f) AS fence_row, \
          u.id AS current_actor,u.auth_generation AS current_generation,u.email AS current_email, \
          EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied, \
          ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS current_roles, \
          s.id AS session_id,s.user_id AS session_user,s.token AS session_token,s.created_at AS session_created, \
          s.updated_at AS session_updated,s.expires_at AS session_expires,s.auth_generation AS session_generation, \
          EXISTS(SELECT 1 FROM openbot_internal.artifact_dataset_bindings db \
            JOIN openbot_internal.artifact_store_bindings sb USING(deployment_id,tenant_id,dataset_id) \
            WHERE db.deployment_id=$1 AND db.tenant_id=$2 AND db.dataset_id=$3 AND db.binding_schema=$7 \
              AND db.initial_origin=$8 AND db.created_at=$9 AND sb.store_id=$10 \
              AND sb.root_device=$11 AND sb.root_inode=$12 AND sb.root_uid=$13) AS store_matches {canary_columns} \
          FROM (SELECT 1) anchor LEFT JOIN public.users u ON u.id=$5 \
          LEFT JOIN public.sessions s ON s.id=$6 AND s.user_id=u.id \
          LEFT JOIN openbot_internal.artifact_records r ON r.deployment_id=$1 AND r.tenant_id=$2 AND r.dataset_id=$3 AND r.artifact_id=$4 \
          LEFT JOIN openbot_internal.artifact_save_operations o ON o.deployment_id=r.deployment_id AND o.tenant_id=r.tenant_id AND o.dataset_id=r.dataset_id AND o.operation_id=r.operation_id \
          LEFT JOIN openbot_internal.artifact_saved_receipts p ON p.deployment_id=r.deployment_id AND p.tenant_id=r.tenant_id AND p.dataset_id=r.dataset_id AND p.operation_id=r.operation_id \
          LEFT JOIN openbot_internal.artifact_workspace_quotas q ON q.deployment_id=r.deployment_id AND q.tenant_id=r.tenant_id AND q.dataset_id=r.dataset_id AND q.workspace_kind=r.workspace_kind AND q.workspace_id=r.workspace_id \
          LEFT JOIN openbot_internal.artifact_cleanup_fences f ON f.deployment_id=r.deployment_id AND f.tenant_id=r.tenant_id AND f.dataset_id=r.dataset_id AND f.artifact_id=r.artifact_id {canary_joins}")
    })
}

fn remaining(deadline: Instant) -> Result<(), Error> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

async fn bounded<T, E>(
    deadline: Instant,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, Error> {
    remaining(deadline)?;
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| Error::Unavailable)?;
    remaining(deadline)?;
    result.map_err(|_| Error::Unavailable)
}

fn owner_error(error: TransactionOwnerError) -> Error {
    match error {
        TransactionOwnerError::CommitUnknown => Error::CommitUnknown,
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            Error::CommitAcknowledgedAfterDeadline
        }
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            Error::RollbackAcknowledgedAfterDeadline
        }
        _ => Error::Unavailable,
    }
}

fn corrupt(field: &'static str) -> Error {
    Error::Corrupt { field }
}

fn column<'a, T: FromSql<'a>>(row: &'a Row, field: &str) -> Result<T, Error> {
    row.try_get(field).map_err(|_| corrupt("record_pair"))
}

fn member<'a>(
    value: &'a Value,
    field: &str,
    error_field: &'static str,
) -> Result<&'a Value, Error> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .ok_or(corrupt(error_field))
}

fn text<'a>(value: &'a Value, field: &str, error_field: &'static str) -> Result<&'a str, Error> {
    member(value, field, error_field)?
        .as_str()
        .ok_or(corrupt(error_field))
}

fn number(value: &Value, field: &str, error_field: &'static str) -> Result<i64, Error> {
    member(value, field, error_field)?
        .as_i64()
        .ok_or(corrupt(error_field))
}
