//! Private original-host first-chunk consumer. The final own-Pool RC statement observes host
//! and source together; the original FD and initialized RAII buffer survive every final await.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use crate::db::pool::DatabasePool as Pool;
use openbot_application::{ArtifactAdministrationError, CurrentArtifactReadChunk};
use openbot_contracts::artifact_read::PendingArtifactReadBuffer;
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, ArtifactWorkspace};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    ArtifactCleanupHostTarget, ArtifactReadCurrentError, ArtifactReadCurrentTarget,
    ArtifactReadRecordFacts, ArtifactReadTailWitness, BorrowedServerSessionEpoch,
    HostRequestBindingError, HostRequestBindingIdentity, HostRequestBindingKind,
};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::roles::resolve_effective_role;
use openbot_domain::identity::session::{SessionLifetimePolicy, SessionState, evaluate_session};
use time::OffsetDateTime;
use tokio_postgres::Row;
use tracing::instrument::WithSubscriber;

use super::artifact_read_lifecycle::{
    AllocationLease, ArtifactReadLifecycle, LifecycleReadOperation, PendingReadOwnership,
    PhysicalResourceLease, ReadOperationState, ReadPhase,
};

use super::{ObservedArtifactReadRecord, PostgresArtifactAdministration};
use crate::artifact_store::{
    DatasetBoundArtifactStore, StoreBoundArtifactReader, StoreReadQueryReservation,
};
use crate::auth::single_user::desktop_local::{
    DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL, DesktopLocalAuthority,
};
use crate::auth::single_user::{
    SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL, VerifiedSingleUserPrincipal,
};

#[path = "artifact_read_authority/public_read_prepare.rs"]
pub(super) mod public_read_prepare;
#[path = "artifact_read_authority/save_receipt.rs"]
mod save_receipt;
#[path = "artifact_read_authority/source_run_ids.rs"]
mod source_run_ids;

/// One actual administration identity, with weak ownership back to that real adapter.
/// It neither accepts a caller Pool/transaction nor prolongs any real host-owner lease.
pub struct PostgresArtifactReadAuthority {
    administration: Weak<PostgresArtifactAdministration>,
    identity: Arc<()>,
    lifecycle: Arc<ArtifactReadLifecycle>,
    run_input_metadata_targets: Mutex<Vec<Weak<RequestedRunInputMetadataTarget>>>,
    #[cfg(test)]
    save_receipt_rollback_gate: Mutex<Option<save_receipt::SaveReceiptRollbackGate>>,
    #[cfg(test)]
    source_run_ids_rollback_gate: Mutex<Option<source_run_ids::SourceRunIdsRollbackGate>>,
    #[cfg(test)]
    public_prepare_probe: Mutex<Option<Arc<public_read_prepare::PublicPrepareProbe>>>,
    #[cfg(test)]
    final_query_gate: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

impl PostgresArtifactReadAuthority {
    /// Match the actual enrolled administration authority and original request attachment.
    /// This comparison supplies no current database authorization or cleanup grant.
    #[must_use]
    pub fn matches_cleanup_host_target(
        &self,
        target: &dyn ArtifactCleanupHostTarget,
        auth: &AuthContext,
    ) -> bool {
        target.matches_authority(&self.identity)
            && target.matches_auth(auth)
            && self.administration.upgrade().is_some_and(|administration| {
                administration.check_namespace(auth).is_ok()
                    && administration
                        .store
                        .matches_registry_owner(&administration.registry)
            })
    }

    // Only the real administration producer can borrow this original identity. No public
    // identity getter, source snapshot, caller-supplied five-key or new Host lease is exposed.
    pub(super) fn cleanup_host_target(&self, auth: &AuthContext) -> impl ArtifactCleanupHostTarget {
        OriginalCleanupHostTarget {
            identity: Arc::clone(&self.identity),
            auth: auth.clone(),
        }
    }

    pub(super) fn read_store(
        &self,
    ) -> Result<Arc<DatasetBoundArtifactStore>, ArtifactReadCurrentError> {
        self.administration
            .upgrade()
            .map(|administration| Arc::clone(&administration.store))
            .ok_or(ArtifactReadCurrentError::Unavailable)
    }

    pub(super) async fn classify_requested_refusal(
        self: &Arc<Self>,
        state: &Arc<ReadOperationState>,
    ) -> Result<(), AppError> {
        let auth = &state.auth;
        let original = auth
            .request_binding()
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        let phase = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let deadline = state
            .original_deadline
            .map_or(phase, |value| value.min(phase));
        let target = RequestedArtifactReadTarget {
            id: state.artifact_id.clone(),
            auth: auth.clone(),
            identity: Arc::clone(&self.identity),
            state: Some(Arc::downgrade(state)),
        };
        let query = state.begin_query()?;
        let result = original
            .verify_artifact_read_current_before(auth, &target, deadline)
            .await;
        // The concrete joint port has either no original PG resource or its true rollback
        // ACK. Unacknowledged schema/transaction exits mark this same target on guard Drop;
        // completing this additional reservation never clears that permanent poison.
        query.complete();
        result?;
        Err(ArtifactReadCurrentError::Unavailable.into())
    }

    async fn observe_state_record(
        self: &Arc<Self>,
        administration: &PostgresArtifactAdministration,
        state: &Arc<ReadOperationState>,
    ) -> Result<ObservedArtifactReadRecord, ArtifactReadCurrentError> {
        let deadline = if state.original_deadline.is_some() {
            state.joint_deadline()?
        } else {
            // Preserve the legacy original overall limit and its existing five-second phases.
            Instant::now()
                .checked_add(super::PG_PHASE)
                .ok_or(ArtifactReadCurrentError::Unavailable)?
        };
        let query = state.begin_query()?;
        match administration
            .observe_read_record_before_inner(&state.auth, &state.artifact_id, deadline)
            .await
        {
            Ok(record) => {
                query.complete();
                state.bind_observed_record(&record)?;
                Ok(record)
            }
            Err(failure) => {
                if failure.rollback_unproven {
                    state.mark_closure_unproven();
                } else {
                    // The original guarded owner acknowledged this observed result/error.
                    query.complete();
                }
                Err(source_error(failure.error))
            }
        }
    }

    pub(super) fn from_administration(
        administration: &Arc<PostgresArtifactAdministration>,
    ) -> Self {
        Self {
            administration: Arc::downgrade(administration),
            identity: Arc::new(()),
            lifecycle: ArtifactReadLifecycle::new(),
            run_input_metadata_targets: Mutex::new(Vec::new()),
            #[cfg(test)]
            save_receipt_rollback_gate: Mutex::new(None),
            #[cfg(test)]
            source_run_ids_rollback_gate: Mutex::new(None),
            #[cfg(test)]
            public_prepare_probe: Mutex::new(None),
            #[cfg(test)]
            final_query_gate: Mutex::new(None),
        }
    }

    /// The exact same authority/root inventory, never a request-created tracker.
    pub fn read_lifecycle(&self) -> Arc<ArtifactReadLifecycle> {
        Arc::clone(&self.lifecycle)
    }

    /// A Requested-only observation; the original Host control protocol never asks for a FD.
    pub(super) async fn run_input_metadata_current(
        self: &Arc<Self>,
        auth: &AuthContext,
        artifact_id: &str,
        deadline: Instant,
    ) -> Result<openbot_application::artifacts::RunInputArtifactMetadataObservation, AppError> {
        remaining(deadline)?;
        if openbot_contracts::artifacts::canonical_artifact_uuid_v7(artifact_id).as_deref()
            != Some(artifact_id)
        {
            return Err(ArtifactReadCurrentError::Unavailable.into());
        }
        let original = auth.request_binding().ok_or_else(host_unavailable)?;
        let recovery_admission = original
            .borrow_recovery_admission_before(auth, deadline)
            .await
            .map_err(ArtifactReadCurrentError::Host)?;
        let target = Arc::new(RequestedRunInputMetadataTarget {
            id: artifact_id.to_owned(),
            auth: auth.clone(),
            identity: Arc::clone(&self.identity),
            result: Mutex::new(None),
            closure_unproven: AtomicBool::new(false),
        });
        {
            let mut targets = self
                .run_input_metadata_targets
                .try_lock()
                .map_err(|_| host_unavailable())?;
            targets.retain(|target| target.strong_count() != 0);
            targets.push(Arc::downgrade(&target));
        }
        let _registration = RunInputMetadataRegistration {
            authority: self,
            target: Arc::downgrade(&target),
        };
        // A filled inner result is never a substitute for complete outer Host/control success.
        recovery_admission
            .verify_current_before(original, auth, deadline)
            .map_err(ArtifactReadCurrentError::Host)?;
        let witness_result = original
            .verify_artifact_read_control_current_before(auth, target.as_ref(), deadline)
            .await;
        recovery_admission
            .verify_current_before(original, auth, deadline)
            .map_err(ArtifactReadCurrentError::Host)?;
        let witness = witness_result?;
        original.verify_artifact_read_control_tail(auth, witness.as_ref(), deadline)?;
        remaining(deadline)?;
        if target.closure_unproven.load(Ordering::SeqCst) {
            return Err(ArtifactReadCurrentError::Unavailable.into());
        }
        let result = target
            .result
            .try_lock()
            .map_err(|_| host_unavailable())?
            .take()
            .ok_or_else(host_unavailable)?;
        original.verify_artifact_read_control_tail(auth, witness.as_ref(), deadline)?;
        remaining(deadline)?;
        if target.closure_unproven.load(Ordering::SeqCst) {
            return Err(ArtifactReadCurrentError::Unavailable.into());
        }
        recovery_admission
            .verify_current_before(original, auth, deadline)
            .map_err(ArtifactReadCurrentError::Host)?;
        result.map_err(Into::into)
    }

    fn run_input_metadata_target(
        &self,
        target: &dyn ArtifactReadCurrentTarget,
    ) -> Result<Option<Arc<RequestedRunInputMetadataTarget>>, ArtifactReadCurrentError> {
        let mut targets = self
            .run_input_metadata_targets
            .try_lock()
            .map_err(|_| host_unavailable())?;
        targets.retain(|target| target.strong_count() != 0);
        Ok(targets.iter().filter_map(Weak::upgrade).find(|candidate| {
            // Compare the actual upgraded Arc's data, never a codegen-dependent trait vtable.
            std::ptr::addr_eq(candidate.as_ref() as &dyn ArtifactReadCurrentTarget, target)
                && candidate.matches_authority(&self.identity)
                && candidate.matches_auth(&candidate.auth)
                && candidate.lookup_id() == target.lookup_id()
                && target.matches_auth(&candidate.auth)
        }))
    }

    pub(super) async fn prepare_host_bound_artifact_read(
        self: &Arc<Self>,
        auth: &AuthContext,
        artifact_id: &str,
        original_deadline: Instant,
        observer: Arc<
            dyn openbot_application::artifact_read_protocol::ArtifactReadPreparationObserver,
        >,
    ) -> Result<openbot_application::artifact_read_protocol::PreparedArtifactRead, AppError> {
        public_read_prepare::prepare(self, auth, artifact_id, original_deadline, observer).await
    }

    pub(super) async fn open_host_bound_read_operation(
        self: &Arc<Self>,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<openbot_application::CurrentArtifactReadOperation, AppError> {
        let state = ReadOperationState::new(Arc::clone(self), auth.clone(), artifact_id.to_owned());
        state.enroll_store(self.read_store()?, None)?;
        self.lifecycle.register(&state)?;
        openbot_application::CurrentArtifactReadOperation::from_trusted_operation(
            auth.clone(),
            Box::new(LifecycleReadOperation { state }),
        )
    }

    /// Prove enrollment in this adapter's actual Pool manager and original namespace.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &Pool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        self.administration.upgrade().is_some_and(|administration| {
            administration
                .registry
                .matches_pool_scope(pool, deployment, tenant)
        })
    }

    /// Observe an original positive receipt and real Session epoch in one current own-Pool statement.
    pub async fn observe_artifact_save_receipt_server_session(
        &self,
        auth: &AuthContext,
        target: &dyn openbot_contracts::request_binding::ArtifactSaveReceiptCurrentTarget,
        epoch: BorrowedServerSessionEpoch<'_>,
        lifetime: SessionLifetimePolicy,
        deadline: Instant,
    ) -> openbot_contracts::request_binding::ArtifactSaveReceiptCurrentOutcome {
        save_receipt::observe(
            self,
            auth,
            target,
            CurrentHost::Session { epoch, lifetime },
            deadline,
        )
        .await
    }

    /// Observe an original receipt only through the enrolled Local installation and same Pool.
    pub async fn observe_artifact_save_receipt_desktop_local(
        &self,
        auth: &AuthContext,
        target: &dyn openbot_contracts::request_binding::ArtifactSaveReceiptCurrentTarget,
        installation: &DesktopLocalAuthority,
        deadline: Instant,
    ) -> openbot_contracts::request_binding::ArtifactSaveReceiptCurrentOutcome {
        save_receipt::observe(
            self,
            auth,
            target,
            CurrentHost::Desktop(installation),
            deadline,
        )
        .await
    }

    pub(super) async fn artifact_save_receipt_current(
        self: &Arc<Self>,
        auth: &AuthContext,
        input: &openbot_contracts::artifacts::GetArtifactSaveReceipt,
        deadline: Instant,
    ) -> openbot_contracts::request_binding::ArtifactSaveReceiptCurrentOutcome {
        save_receipt::current(self, auth, input, deadline).await
    }

    /// Observe IDs and the original real Session epoch in one own-Pool current statement.
    pub async fn observe_source_run_ids_server_session(
        &self,
        auth: &AuthContext,
        target: &dyn openbot_contracts::request_binding::SourceRunArtifactIdsCurrentTarget,
        epoch: BorrowedServerSessionEpoch<'_>,
        lifetime: SessionLifetimePolicy,
        deadline: Instant,
    ) -> openbot_contracts::request_binding::SourceRunArtifactIdsCurrentOutcome {
        source_run_ids::observe(
            self,
            auth,
            target,
            CurrentHost::Session { epoch, lifetime },
            deadline,
        )
        .await
    }

    /// Observe IDs only with the original real Local installation and its current sealed canary.
    pub async fn observe_source_run_ids_desktop_local(
        &self,
        auth: &AuthContext,
        target: &dyn openbot_contracts::request_binding::SourceRunArtifactIdsCurrentTarget,
        installation: &DesktopLocalAuthority,
        deadline: Instant,
    ) -> openbot_contracts::request_binding::SourceRunArtifactIdsCurrentOutcome {
        source_run_ids::observe(
            self,
            auth,
            target,
            CurrentHost::Desktop(installation),
            deadline,
        )
        .await
    }

    pub(super) async fn source_run_artifact_ids_current(
        self: &Arc<Self>,
        auth: &AuthContext,
        input: &openbot_contracts::artifacts::GetSourceRunArtifactIds,
        deadline: Instant,
    ) -> openbot_contracts::request_binding::SourceRunArtifactIdsCurrentOutcome {
        source_run_ids::current(self, auth, input, deadline).await
    }

    /// Observe the original real Session epoch and unchanged source predicate in one statement.
    pub async fn observe_server_session(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        epoch: BorrowedServerSessionEpoch<'_>,
        lifetime: SessionLifetimePolicy,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        self.observe(
            auth,
            target,
            CurrentHost::Session { epoch, lifetime },
            deadline,
        )
        .await
    }

    /// Reobserve the real canonical Server owner and source in the same original guarded query.
    pub async fn observe_server_single_user(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        principal: &VerifiedSingleUserPrincipal,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        if principal.auth_context() != auth || !principal.matches_artifact_read_authority(self) {
            return Err(host_not_current());
        }
        self.observe(auth, target, CurrentHost::SingleUser(principal), deadline)
            .await
    }

    /// Require actual Desktop canary adoption and current original installation/row facts.
    pub async fn observe_desktop_local(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        installation: &DesktopLocalAuthority,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        self.observe(auth, target, CurrentHost::Desktop(installation), deadline)
            .await
    }

    pub(super) async fn read_host_bound_chunk(
        self: &Arc<Self>,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        let state = ReadOperationState::new(Arc::clone(self), auth.clone(), artifact_id.to_owned());
        state.enroll_store(self.read_store()?, None)?;
        self.lifecycle.register(&state)?;
        if state.body_is_admitted().is_err() {
            self.classify_requested_refusal(&state).await?;
            return Err(ArtifactReadCurrentError::Unavailable.into());
        }
        let job = match self.lifecycle.admit_operation(&state) {
            Ok(job) => job,
            Err(_) => {
                self.classify_requested_refusal(&state).await?;
                return Err(ArtifactReadCurrentError::Unavailable.into());
            }
        };
        if state.begin().is_err() {
            self.classify_requested_refusal(&state).await?;
            return Err(ArtifactReadCurrentError::Unavailable.into());
        }
        let dispatcher = tracing::dispatcher::get_default(Clone::clone);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let authority = Arc::clone(self);
        let collected = Arc::clone(&state);
        tokio::spawn(
            async move {
                let mut result = authority
                    .read_first_chunk_collected(&collected, dispatcher)
                    .await;
                if result.is_ok() {
                    let pending_recorded = match collected.data.lock() {
                        Ok(mut data) => {
                            data.phase = ReadPhase::Pending;
                            true
                        }
                        Err(_) => false,
                    };
                    if !pending_recorded {
                        result = Err(ArtifactReadCurrentError::Unavailable.into());
                    }
                }
                if result.is_err() {
                    collected.finish_failed();
                }
                drop(sender.send(result));
                drop(job);
            }
            .with_current_subscriber(),
        );
        let mut attempt = LegacyReadAttempt {
            state,
            completed: false,
        };
        let result = receiver
            .await
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        attempt.completed = true;
        result
    }

    async fn read_first_chunk_collected(
        self: &Arc<Self>,
        state: &Arc<ReadOperationState>,
        dispatcher: tracing::Dispatch,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        let auth = &state.auth;
        let artifact_id = state.artifact_id.as_str();
        let original = auth
            .request_binding()
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        if !matches!(
            original.kind(),
            HostRequestBindingKind::ServerSession
                | HostRequestBindingKind::ServerSingleUserOwner
                | HostRequestBindingKind::DesktopWindow
        ) {
            return Err(host_unavailable().into());
        }
        // The initial check only protects expensive physical work; it is never the final proof.
        let phase = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let deadline = state
            .original_deadline
            .map_or(phase, |value| value.min(phase));
        let target = RequestedArtifactReadTarget {
            id: state.artifact_id.clone(),
            auth: auth.clone(),
            identity: Arc::clone(&self.identity),
            state: Some(Arc::downgrade(state)),
        };
        let query = state.begin_query()?;
        let host = original
            .verify_artifact_read_control_current_before(auth, &target, deadline)
            .await;
        // A normal control-port result has no original resource or a genuine joint ACK.
        // Its independent original guard already keeps every unacknowledged exit poisoned.
        query.complete();
        drop(host?);
        let administration = self
            .administration
            .upgrade()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let snapshot = self.observe_state_record(&administration, state).await;
        let worker = match snapshot {
            Ok(snapshot) => {
                let identity = Arc::clone(&self.identity);
                let store = Arc::clone(&administration.store);
                let state = Arc::clone(state);
                let resource = self.lifecycle.resource();
                tokio::task::spawn_blocking(move || {
                    tracing::dispatcher::with_default(&dispatcher, || {
                        let resource = resource;
                        state.body_is_admitted()?;
                        // Every initialized byte, including the unread suffix, remains owned by
                        // this RAII value on worker error, abandoned JoinHandle and cancelled await.
                        let mut pending = PendingArtifactReadBuffer::new_initialized()?;
                        let mut reader = store
                            .open_observed_record(snapshot)
                            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
                        read_segments(&mut reader, &mut pending, &state, 0)?;
                        let target: Arc<dyn ArtifactReadCurrentTarget> =
                            Arc::new(TrackedArtifactReadTarget {
                                inner: Arc::new(ActualArtifactReadTarget::from_reader(
                                    identity, reader,
                                )),
                                state: Arc::clone(&state),
                                _resource: resource,
                            });
                        Ok::<_, ArtifactReadCurrentError>(ArtifactReadWorkerResult {
                            pending,
                            target,
                        })
                    })
                })
                .await
                .map_err(|_| ArtifactReadCurrentError::Unavailable)
                .and_then(|value| value)
            }
            Err(error) => Err(error),
        };
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        let request_target;
        let target: &dyn ArtifactReadCurrentTarget = match &worker {
            Ok(result) => {
                tracing::trace!(
                    artifact_read_phase = "actual_io_completed_before_joint",
                    "artifact_read_current_phase"
                );
                result.target.as_ref()
            }
            Err(_) => {
                // Missing/invisible/gone and physical errors still execute the real anchored
                // final statement. No request-only target can release any bytes.
                request_target = RequestedArtifactReadTarget {
                    id: artifact_id.to_owned(),
                    auth: auth.clone(),
                    identity: Arc::clone(&self.identity),
                    state: Some(Arc::downgrade(state)),
                };
                &request_target
            }
        };
        let query = state.begin_query()?;
        let observed = original
            .verify_artifact_read_current_before(auth, target, deadline)
            .await;
        query.complete();
        let witness = observed?;
        let result = worker?;
        let target: Arc<dyn ArtifactReadCurrentTarget> = result.target;
        CurrentArtifactReadChunk::from_trusted_observation(
            result.pending,
            auth.clone(),
            target,
            witness,
            deadline,
        )
    }

    pub(super) async fn read_operation_block(
        self: &Arc<Self>,
        state: &Arc<ReadOperationState>,
    ) -> Result<openbot_application::CurrentArtifactReadBlock, AppError> {
        if state.body_is_admitted().is_err() {
            self.classify_requested_refusal(state).await?;
            return Err(ArtifactReadCurrentError::Unavailable.into());
        }
        let auth = &state.auth;
        let original = auth
            .request_binding()
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        let host_deadline = if state.original_deadline.is_some() {
            state.joint_deadline()?
        } else {
            Instant::now()
                .checked_add(Duration::from_secs(5))
                .ok_or(ArtifactReadCurrentError::Unavailable)?
        };
        let target = RequestedArtifactReadTarget {
            id: state.artifact_id.clone(),
            auth: auth.clone(),
            identity: Arc::clone(&self.identity),
            state: Some(Arc::downgrade(state)),
        };
        let query = state.begin_query()?;
        let host = original
            .verify_artifact_read_control_current_before(auth, &target, host_deadline)
            .await;
        // Completing this outer reservation never clears the concrete joint guard's poison.
        query.complete();
        drop(host?);
        if state.body_is_admitted().is_err() {
            self.classify_requested_refusal(state).await?;
            return Err(ArtifactReadCurrentError::Unavailable.into());
        }
        let administration = self
            .administration
            .upgrade()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let (reader, position) = {
            let mut data = state
                .data
                .try_lock()
                .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
            (data.reader.take(), data.position)
        };
        let input = match reader {
            Some(reader) => Ok(ReadInput::Retained(Box::new(reader))),
            None => self
                .observe_state_record(&administration, state)
                .await
                .map(|record| ReadInput::Fresh(Box::new(record))),
        };
        let worker = match input {
            Ok(input) => {
                {
                    let mut data = state
                        .data
                        .try_lock()
                        .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
                    if data.resource.is_none() {
                        data.resource = Some(self.lifecycle.resource());
                    }
                }
                let worker_state = Arc::clone(state);
                let dispatcher = tracing::dispatcher::get_default(Clone::clone);
                let store = Arc::clone(&administration.store);
                tokio::task::spawn_blocking(move || {
                    tracing::dispatcher::with_default(&dispatcher, || {
                        worker_state.body_is_admitted()?;
                        if worker_state.original_deadline.is_some() {
                            #[cfg(test)]
                            public_read_prepare::worker_entered(&worker_state)?;
                            worker_state.check_current()?;
                        }
                        let mut pending = PendingArtifactReadBuffer::new_initialized()?;
                        if worker_state.original_deadline.is_some() {
                            worker_state.check_current()?;
                        }
                        let mut reader = match input {
                            ReadInput::Retained(reader) => *reader,
                            ReadInput::Fresh(snapshot) => {
                                if worker_state.original_deadline.is_some() {
                                    let mut is_current = |after_sha_segment| {
                                        #[cfg(test)]
                                        if public_read_prepare::hash_guard(
                                            &worker_state,
                                            after_sha_segment,
                                        )
                                        .is_err()
                                        {
                                            return false;
                                        }
                                        #[cfg(not(test))]
                                        let _ = after_sha_segment;
                                        !worker_state.is_stopped()
                                    };
                                    store.open_observed_record_guarded(*snapshot, &mut is_current)
                                } else {
                                    store.open_observed_record(*snapshot)
                                }
                                .map_err(|_| ArtifactReadCurrentError::Unavailable)?
                            }
                        };
                        if worker_state.original_deadline.is_some() {
                            worker_state.check_current()?;
                        }
                        let read =
                            read_segments(&mut reader, &mut pending, &worker_state, position);
                        #[cfg(test)]
                        if worker_state.original_deadline.is_some() && read.is_ok() {
                            public_read_prepare::observe_prefix(&worker_state, &mut pending)?;
                        }
                        Ok::<_, ArtifactReadCurrentError>(OperationWorkerResult {
                            pending,
                            reader,
                            read,
                        })
                    })
                })
                .await
                .map_err(|_| ArtifactReadCurrentError::Unavailable)
                .and_then(|result| result)
            }
            Err(error) => Err(error),
        };
        let mut owned = match worker {
            Ok(result) => {
                let mut data = state
                    .data
                    .try_lock()
                    .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
                data.reader = Some(result.reader);
                data.phase = ReadPhase::FinalJoint;
                if let Ok(position) = &result.read {
                    data.position = *position;
                }
                data.eof = result.pending.actual_length() == Some(0);
                drop(data);
                (
                    Some(PendingReadOwnership {
                        pending: Some(result.pending),
                        lease: Some(Box::new(AllocationLease::new(Arc::clone(state)))),
                    }),
                    result.read.map(|_| ()),
                )
            }
            Err(error) => (None, Err(error)),
        };
        let phase = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        let deadline = state
            .original_deadline
            .map_or(phase, |value| value.min(phase));
        let target: Arc<dyn ArtifactReadCurrentTarget> = if owned.0.is_some() {
            tracing::trace!(
                artifact_read_phase = "actual_io_completed_before_joint",
                "artifact_read_current_phase"
            );
            Arc::new(RetainedOperationTarget::from_state(
                Arc::clone(&self.identity),
                state,
            )?)
        } else {
            Arc::new(RequestedArtifactReadTarget {
                id: state.artifact_id.clone(),
                auth: auth.clone(),
                identity: Arc::clone(&self.identity),
                state: Some(Arc::downgrade(state)),
            })
        };
        // Missing/physical errors use this same anchored host-first statement, never early404.
        let query = state.begin_query()?;
        let observed = original
            .verify_artifact_read_current_before(auth, target.as_ref(), deadline)
            .await;
        query.complete();
        let witness = observed?;
        owned.1?;
        let owner = owned
            .0
            .as_mut()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        {
            let mut data = state
                .data
                .try_lock()
                .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
            if state.is_stopped() {
                return Err(ArtifactReadCurrentError::Unavailable.into());
            }
            data.phase = ReadPhase::Pending;
        }
        let pending = owner
            .pending
            .take()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let lease = owner
            .lease
            .take()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        openbot_application::CurrentArtifactReadBlock::from_trusted_observation(
            pending,
            auth.clone(),
            target,
            witness,
            deadline,
            lease,
        )
    }

    async fn observe(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        host: CurrentHost<'_>,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        remaining(deadline)?;
        if !target.matches_authority(&self.identity) || !target.matches_auth(auth) {
            return Err(host_not_current());
        }
        let administration = self.administration.upgrade().ok_or_else(host_unavailable)?;
        administration
            .check_namespace(auth)
            .map_err(|_| host_not_current())?;
        if let CurrentHost::Desktop(installation) = &host
            && !administration
                .registry
                .matches_desktop_read_installation(installation)
        {
            return Err(host_unavailable());
        }
        let limit = tokio::time::Instant::from_std(deadline);
        // Cached first and Ack/Close tails also enter here without an active byte allocation.
        // Keep this original Store query reserved until its actual rollback ACK, even when
        // Entry cleanup has already released the State's reader and complete allocation.
        let query = administration
            .store
            .begin_read_query(target.lookup_id())
            .map_err(|_| host_unavailable())?;
        let rollback_guard = JointRollbackGuard::new(target, query);
        tokio::time::timeout_at(
            limit,
            self.observe_inner(
                &administration,
                auth,
                target,
                host,
                deadline,
                &rollback_guard,
            ),
        )
        .await
        .map_err(|_| host_unavailable())?
    }

    async fn observe_inner(
        &self,
        administration: &PostgresArtifactAdministration,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        host: CurrentHost<'_>,
        deadline: Instant,
        rollback_guard: &JointRollbackGuard<'_>,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        let run_input_metadata = self.run_input_metadata_target(target)?;
        rollback_guard.schema_started();
        let mut client = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.min(Instant::now() + super::WAIT)),
            administration.registry.pool().get_guarded(deadline),
        )
        .await
        .map_err(|_| host_unavailable())?
        .map_err(|_| host_unavailable())?;
        // All native/public/registration/fence schema queries run before BEGIN on this same
        // original guarded owner. Any cancellation or unacknowledged exit retires that owner.
        let schema = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.min(Instant::now() + super::PG_PHASE)),
            super::verify_artifact_read_schema_on(client.as_client()),
        )
        .await
        .map_err(|_| host_unavailable())?;
        if let Err(error) = schema {
            let failure = super::PublicReadRecordFailure::schema(error, deadline);
            if !failure.rollback_unproven {
                rollback_guard.acknowledged();
            }
            return Err(host_unavailable());
        }
        rollback_guard.transaction_started();
        remaining(deadline)?;
        let original_transaction = client
            .begin_read_committed_read_only()
            .await
            .map_err(|_| host_unavailable())?;
        let outcome = async {
            let tx = original_transaction.as_transaction();
            let millis = remaining(deadline)?.as_millis().clamp(1, 5000);
            tx.batch_execute(&format!("SET LOCAL statement_timeout='{millis}ms'; SET LOCAL lock_timeout='{millis}ms'"))
                .await.map_err(|_| host_unavailable())?;
            let binding = administration.registry.binding();
            let seed = tx.query_opt(
                "SELECT source_thread_id,source_run_id FROM openbot_internal.artifact_records \
                 WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 AND owner_actor_id=$5",
                &[&binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id(), &target.lookup_id(), &auth.actor().as_str()],
            ).await.map_err(|_| host_unavailable())?;
            let thread: Option<String> = seed.as_ref().map(|row| super::value(row, "source_thread_id")).transpose().map_err(source_error)?;
            let run: Option<String> = seed.as_ref().map(|row| super::value(row, "source_run_id")).transpose().map_err(source_error)?;
            let generation = i64::try_from(auth.auth_generation().get()).map_err(|_| host_not_current())?;
            let physical = administration.store.physical_binding();
            let session_id = match &host {
                CurrentHost::Session { epoch, .. } => Some(epoch.lookup_id()),
                CurrentHost::SingleUser(_) | CurrentHost::Desktop(_) => None,
            };
            #[cfg(test)]
            {
                let gate = self.final_query_gate.lock().map_err(|_| host_unavailable())?.take();
                if let Some((reached, proceed)) = gate {
                    reached.send(()).map_err(|_| host_unavailable())?;
                    proceed.await.map_err(|_| host_unavailable())?;
                }
            }
            remaining(deadline)?;
            tracing::trace!(artifact_read_phase = "joint_statement_ready", "artifact_read_current_phase");
            let row = tx.query_one(
                current_read_sql(matches!(&host, CurrentHost::Desktop(_))),
                &[&thread, &run, &auth.actor().as_str(), &auth.deployment().as_str(), &auth.tenant().as_str(),
                    &generation, &target.lookup_id(), &binding.dataset_id(), &binding.binding_schema(),
                    &binding.initial_origin(), &binding.created_at(), &administration.store.store_id().to_string(),
                    &physical.device(), &physical.inode(), &physical.uid(), &session_id],
            ).await.map_err(|_| host_unavailable())?;
            // Host classification is first even for a missing/invisible/gone source. Retain the
            // current host witness on error paths, so rollback cannot outlive its clock/owner.
            let witness = decode_host(administration, auth, &row, &host)?;
            if let Some(collected) = &run_input_metadata {
                let observation = (|| {
                    let id: Option<String> = super::value(&row, "artifact_id").map_err(source_error)?;
                    if id.is_none() { return Err(ArtifactReadCurrentError::NotVisible); }
                    administration.decode_run_input_metadata(auth, &row).map_err(source_error)
                })();
                return Ok::<_, ArtifactReadCurrentError>((witness,
                    CurrentSourceObservation::RunInput { target: Arc::clone(collected), observation: Box::new(observation) }));
            }
            let source = (|| {
                let id: Option<String> = super::value(&row, "artifact_id").map_err(source_error)?;
                if id.is_none() { return Err(ArtifactReadCurrentError::NotVisible); }
                let record = administration.decode_read_record(auth, &row).map_err(source_error)?;
                let workspace = workspace(&record);
                let sha256 = Sha256Digest::from_bytes(*record.blob().sha256()).to_hex();
                if !target.matches_current_record(ArtifactReadRecordFacts {
                    artifact_id: &record.source_snapshot.artifact_id, sha256: &sha256,
                    byte_length: record.blob().byte_length(), source: &record.source_snapshot, workspace: &workspace,
                }) { return Err(ArtifactReadCurrentError::Unavailable); }
                Ok(())
            })();
            Ok::<_, ArtifactReadCurrentError>((witness, CurrentSourceObservation::Body(source)))
        }.await;
        // Every real statement result, including host/source errors, awaits explicit rollback.
        // A dropped/timeout future is not reported as acknowledged rollback or worker completion.
        let rollback = original_transaction
            .rollback()
            .await
            .map_err(|_| host_unavailable());
        if rollback.is_ok() {
            // Record the real ACK before a pure clock/owner tail can refuse the result.
            rollback_guard.acknowledged();
        }
        if let Ok((witness, _)) = &outcome {
            witness.verify_current(auth, deadline)?;
        }
        remaining(deadline)?;
        rollback?;
        let (witness, source) = outcome?;
        match source {
            CurrentSourceObservation::Body(source) => source?,
            CurrentSourceObservation::RunInput {
                target,
                observation,
            } => target.publish(*observation)?,
        }
        Ok(Box::new(witness))
    }
}

/// Tracks only this original joint future's unacknowledged PG work; it mints no positive proof.
struct JointRollbackGuard<'a> {
    target: &'a dyn ArtifactReadCurrentTarget,
    phase: AtomicU8,
    query: Mutex<Option<StoreReadQueryReservation>>,
}
impl<'a> JointRollbackGuard<'a> {
    fn new(target: &'a dyn ArtifactReadCurrentTarget, query: StoreReadQueryReservation) -> Self {
        Self {
            target,
            phase: AtomicU8::new(0),
            query: Mutex::new(Some(query)),
        }
    }
    fn schema_started(&self) {
        self.phase.store(1, Ordering::SeqCst);
    }
    fn transaction_started(&self) {
        self.phase.store(2, Ordering::SeqCst);
    }
    fn acknowledged(&self) {
        if let Ok(mut original_query) = self.query.lock()
            && let Some(query) = original_query.take()
        {
            query.complete();
            self.phase.store(3, Ordering::SeqCst);
        }
    }
}
impl Drop for JointRollbackGuard<'_> {
    fn drop(&mut self) {
        if matches!(self.phase.load(Ordering::SeqCst), 1 | 2) {
            self.target.mark_rollback_unproven();
        }
    }
}

enum CurrentHost<'a> {
    Session {
        epoch: BorrowedServerSessionEpoch<'a>,
        lifetime: SessionLifetimePolicy,
    },
    SingleUser(&'a VerifiedSingleUserPrincipal),
    Desktop(&'a DesktopLocalAuthority),
}

struct ArtifactReadWorkerResult {
    pending: PendingArtifactReadBuffer,
    target: Arc<dyn ArtifactReadCurrentTarget>,
}

struct LegacyReadAttempt {
    state: Arc<ReadOperationState>,
    completed: bool,
}
impl Drop for LegacyReadAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.state.close();
        }
    }
}
struct TrackedArtifactReadTarget {
    inner: Arc<ActualArtifactReadTarget>,
    state: Arc<ReadOperationState>,
    _resource: PhysicalResourceLease,
}
impl ArtifactReadCurrentTarget for TrackedArtifactReadTarget {
    fn mark_rollback_unproven(&self) {
        self.state.mark_closure_unproven();
    }

    fn lookup_id(&self) -> &str {
        self.inner.lookup_id()
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        self.inner.matches_authority(identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        self.inner.matches_auth(auth)
    }
    fn matches_current_record(&self, facts: ArtifactReadRecordFacts<'_>) -> bool {
        self.inner.matches_current_record(facts)
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        if self._resource.is_closed() || self.state.is_stopped() {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        self.inner.verify_physical_current()
    }
}
enum ReadInput {
    Fresh(Box<ObservedArtifactReadRecord>),
    Retained(Box<StoreBoundArtifactReader>),
}
struct OperationWorkerResult {
    pending: PendingArtifactReadBuffer,
    reader: StoreBoundArtifactReader,
    read: Result<u64, ArtifactReadCurrentError>,
}
fn read_segments(
    reader: &mut StoreBoundArtifactReader,
    pending: &mut PendingArtifactReadBuffer,
    state: &ReadOperationState,
    mut position: u64,
) -> Result<u64, ArtifactReadCurrentError> {
    const SEGMENT: usize = 64 * 1024;
    let expected = reader.record_snapshot().blob().byte_length();
    let mut actual = 0;
    while actual < openbot_contracts::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES {
        if state.is_stopped() {
            pending.wipe();
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        let end =
            (actual + SEGMENT).min(openbot_contracts::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES);
        let count = reader
            .read_observed_chunk(&mut pending.initialized_mut()[actual..end])
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        if state.original_deadline.is_some() && state.is_stopped() {
            pending.wipe();
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        actual += count;
        position = position
            .checked_add(count as u64)
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        if count == 0 {
            break;
        }
        if actual == SEGMENT && position < expected {
            tracing::trace!(
                artifact_read_lifecycle_phase = "physical_segment_completed_before_more_io",
                "artifact_read_lifecycle_phase"
            );
        }
    }
    if state.is_stopped() {
        pending.wipe();
        return Err(ArtifactReadCurrentError::Unavailable);
    }
    pending.record_actual_length(actual)?;
    Ok(position)
}

struct RetainedOperationTarget {
    identity: Arc<()>,
    auth: AuthContext,
    source: ArtifactRegistrationReceipt,
    workspace: ArtifactWorkspace,
    sha256: String,
    byte_length: u64,
    state: Weak<ReadOperationState>,
}
impl RetainedOperationTarget {
    fn from_state(
        identity: Arc<()>,
        state: &Arc<ReadOperationState>,
    ) -> Result<Self, ArtifactReadCurrentError> {
        let data = state
            .data
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        let reader = data
            .reader
            .as_ref()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let record = reader.record_snapshot();
        Ok(Self {
            identity,
            auth: record.auth_snapshot.clone(),
            source: record.source_snapshot.clone(),
            workspace: workspace(record),
            sha256: Sha256Digest::from_bytes(*record.blob().sha256()).to_hex(),
            byte_length: record.blob().byte_length(),
            state: Arc::downgrade(state),
        })
    }
}
impl ArtifactReadCurrentTarget for RetainedOperationTarget {
    fn mark_rollback_unproven(&self) {
        if let Some(state) = self.state.upgrade() {
            state.mark_closure_unproven();
        }
    }
    fn lookup_id(&self) -> &str {
        &self.source.artifact_id
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
    fn matches_current_record(&self, actual: ArtifactReadRecordFacts<'_>) -> bool {
        actual.artifact_id == self.source.artifact_id
            && actual.sha256 == self.sha256
            && actual.byte_length == self.byte_length
            && actual.source == &self.source
            && actual.workspace == &self.workspace
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        let state = self
            .state
            .upgrade()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        if state.is_stopped() {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        let data = state
            .data
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        data.reader
            .as_ref()
            .ok_or(ArtifactReadCurrentError::Unavailable)?
            .verify_physical_current()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)
    }
}

struct ActualArtifactReadTarget {
    identity: Arc<()>,
    auth: AuthContext,
    source: ArtifactRegistrationReceipt,
    workspace: ArtifactWorkspace,
    sha256: String,
    byte_length: u64,
    reader: Mutex<StoreBoundArtifactReader>,
}
impl ActualArtifactReadTarget {
    fn from_reader(identity: Arc<()>, reader: StoreBoundArtifactReader) -> Self {
        let record = reader.record_snapshot();
        Self {
            identity,
            auth: record.auth_snapshot.clone(),
            source: record.source_snapshot.clone(),
            workspace: workspace(record),
            sha256: Sha256Digest::from_bytes(*record.blob().sha256()).to_hex(),
            byte_length: record.blob().byte_length(),
            reader: Mutex::new(reader),
        }
    }
}
impl ArtifactReadCurrentTarget for ActualArtifactReadTarget {
    fn lookup_id(&self) -> &str {
        &self.source.artifact_id
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
    fn matches_current_record(&self, actual: ArtifactReadRecordFacts<'_>) -> bool {
        actual.artifact_id == self.source.artifact_id
            && actual.sha256 == self.sha256
            && actual.byte_length == self.byte_length
            && actual.source == &self.source
            && actual.workspace == &self.workspace
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        self.reader
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?
            .verify_physical_current()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)
    }
}

enum CurrentSourceObservation {
    Body(Result<(), ArtifactReadCurrentError>),
    RunInput {
        target: Arc<RequestedRunInputMetadataTarget>,
        observation: Box<
            Result<
                openbot_application::artifacts::RunInputArtifactMetadataObservation,
                ArtifactReadCurrentError,
            >,
        >,
    },
}

struct RequestedRunInputMetadataTarget {
    id: String,
    auth: AuthContext,
    identity: Arc<()>,
    result: Mutex<
        Option<
            Result<
                openbot_application::artifacts::RunInputArtifactMetadataObservation,
                ArtifactReadCurrentError,
            >,
        >,
    >,
    closure_unproven: AtomicBool,
}
impl RequestedRunInputMetadataTarget {
    fn publish(
        &self,
        observation: Result<
            openbot_application::artifacts::RunInputArtifactMetadataObservation,
            ArtifactReadCurrentError,
        >,
    ) -> Result<(), ArtifactReadCurrentError> {
        if self.closure_unproven.load(Ordering::SeqCst) {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        let mut result = self.result.try_lock().map_err(|_| host_unavailable())?;
        if result.is_some() {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        *result = Some(observation);
        Ok(())
    }
}
impl ArtifactReadCurrentTarget for RequestedRunInputMetadataTarget {
    fn mark_rollback_unproven(&self) {
        self.closure_unproven.store(true, Ordering::SeqCst);
    }
    fn lookup_id(&self) -> &str {
        &self.id
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
    fn matches_current_record(&self, _actual: ArtifactReadRecordFacts<'_>) -> bool {
        false
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        Err(ArtifactReadCurrentError::Unavailable)
    }
}

struct RunInputMetadataRegistration<'a> {
    authority: &'a PostgresArtifactReadAuthority,
    target: Weak<RequestedRunInputMetadataTarget>,
}
impl Drop for RunInputMetadataRegistration<'_> {
    fn drop(&mut self) {
        // No wait during cancellation. A missed removal leaves only a Weak pruned on next use.
        if let Ok(mut targets) = self.authority.run_input_metadata_targets.try_lock() {
            targets
                .retain(|target| !Weak::ptr_eq(target, &self.target) && target.strong_count() != 0);
        }
    }
}

struct RequestedArtifactReadTarget {
    id: String,
    auth: AuthContext,
    identity: Arc<()>,
    state: Option<Weak<ReadOperationState>>,
}
impl ArtifactReadCurrentTarget for RequestedArtifactReadTarget {
    fn mark_rollback_unproven(&self) {
        if let Some(state) = self.state.as_ref().and_then(Weak::upgrade) {
            state.mark_closure_unproven();
        }
    }
    fn lookup_id(&self) -> &str {
        &self.id
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
    fn matches_current_record(&self, actual: ArtifactReadRecordFacts<'_>) -> bool {
        actual.artifact_id == self.id
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        Err(ArtifactReadCurrentError::Unavailable)
    }
}

struct OriginalCleanupHostTarget {
    identity: Arc<()>,
    auth: AuthContext,
}

impl ArtifactCleanupHostTarget for OriginalCleanupHostTarget {
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }

    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
}

fn same_original_auth(original: &AuthContext, current: &AuthContext) -> bool {
    original == current
        && original
            .request_binding()
            .zip(current.request_binding())
            .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
}
fn workspace(record: &ObservedArtifactReadRecord) -> ArtifactWorkspace {
    match record.workspace_snapshot.kind().as_str() {
        "channel" => ArtifactWorkspace::Channel {
            id: record.workspace_snapshot.id().to_owned(),
        },
        _ => ArtifactWorkspace::Thread {
            id: record.workspace_snapshot.id().to_owned(),
        },
    }
}
fn remaining(deadline: Instant) -> Result<Duration, ArtifactReadCurrentError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(host_unavailable)
}
fn host_unavailable() -> ArtifactReadCurrentError {
    ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable)
}
fn host_not_current() -> ArtifactReadCurrentError {
    ArtifactReadCurrentError::Host(HostRequestBindingError::NotCurrent)
}
fn source_error(error: ArtifactAdministrationError) -> ArtifactReadCurrentError {
    match error {
        ArtifactAdministrationError::NotVisible => ArtifactReadCurrentError::NotVisible,
        ArtifactAdministrationError::Gone { status } => ArtifactReadCurrentError::Gone(status),
        _ => ArtifactReadCurrentError::Unavailable,
    }
}

struct CurrentReadTail {
    auth: AuthContext,
    identity: HostRequestBindingIdentity,
    observed_wall: OffsetDateTime,
    observed_monotonic: Instant,
    session: Option<(
        OffsetDateTime,
        OffsetDateTime,
        OffsetDateTime,
        SessionLifetimePolicy,
    )>,
}
impl ArtifactReadTailWitness for CurrentReadTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        remaining(deadline)?;
        if auth != &self.auth
            || !auth
                .request_binding()
                .is_some_and(|binding| self.identity.same_binding(binding.identity()))
        {
            return Err(host_not_current());
        }
        let now = OffsetDateTime::now_utc();
        if now < self.observed_wall || Instant::now() < self.observed_monotonic {
            return Err(host_not_current());
        }
        if let Some((created, updated, expires, lifetime)) = self.session
            && (now >= expires
                || evaluate_session(
                    lifetime,
                    SessionState::rehydrate(created, updated, auth.auth_generation()),
                    auth.auth_generation(),
                    now,
                )
                .is_err())
        {
            return Err(host_not_current());
        }
        Ok(())
    }
}

fn decode_host(
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    row: &Row,
    host: &CurrentHost<'_>,
) -> Result<CurrentReadTail, ArtifactReadCurrentError> {
    fn field<T: for<'a> tokio_postgres::types::FromSql<'a>>(
        row: &Row,
        name: &'static str,
    ) -> Result<T, ArtifactReadCurrentError> {
        row.try_get(name).map_err(|_| host_unavailable())
    }
    let user: Option<String> = field(row, "read_host_user")?;
    let raw_generation: Option<i64> = field(row, "read_host_generation")?;
    let generation = raw_generation
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(host_not_current)?;
    if user.as_deref() != Some(auth.actor().as_str())
        || generation != auth.auth_generation().get()
        || field::<bool>(row, "read_host_revoked")?
    {
        return Err(host_not_current());
    }
    let roles: Vec<String> = field(row, "read_host_roles")?;
    let parsed = roles
        .iter()
        .map(|role| role.parse::<Role>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| host_not_current())?;
    let now = OffsetDateTime::now_utc();
    let session = match host {
        CurrentHost::Session { epoch, lifetime } => {
            if auth.is_single_user()
                || auth
                    .request_binding()
                    .is_none_or(|value| value.kind() != HostRequestBindingKind::ServerSession)
            {
                return Err(host_not_current());
            }
            let (
                Some(id),
                Some(user),
                Some(token),
                Some(created),
                Some(updated),
                Some(expires),
                Some(issued),
            ) = (
                field::<Option<String>>(row, "read_session_id")?,
                field::<Option<String>>(row, "read_session_user")?,
                field::<Option<String>>(row, "read_session_token")?,
                field::<Option<OffsetDateTime>>(row, "read_session_created")?,
                field::<Option<OffsetDateTime>>(row, "read_session_updated")?,
                field::<Option<OffsetDateTime>>(row, "read_session_expires")?,
                field::<Option<i64>>(row, "read_session_generation")?,
            )
            else {
                return Err(host_not_current());
            };
            if !epoch.matches_raw_row(&id, &user, &token, created, issued)
                || issued < 0
                || issued != raw_generation.unwrap_or(-1)
                || now >= expires
                || evaluate_session(
                    *lifetime,
                    SessionState::rehydrate(created, updated, AuthGeneration::new(generation)),
                    AuthGeneration::new(generation),
                    now,
                )
                .is_err()
            {
                return Err(host_not_current());
            }
            let role = resolve_effective_role(parsed).map_err(|_| host_not_current())?;
            let current = AuthContextBuilder::from_verified_session(
                auth.deployment().clone(),
                auth.tenant().clone(),
                auth.actor().clone(),
                AuthGeneration::new(generation),
                false,
            )
            .with_role(role)
            .build();
            if current != *auth {
                return Err(host_not_current());
            }
            Some((created, updated, expires, *lifetime))
        }
        CurrentHost::SingleUser(principal) => {
            if !auth.is_single_user()
                || auth.actor().as_str() != SINGLE_USER_ACTOR_ID
                || field::<Option<String>>(row, "read_host_email")?.as_deref()
                    != Some(SINGLE_USER_EMAIL)
                || roles.as_slice() != ["admin"]
                || auth.request_binding().is_none_or(|value| {
                    value.kind() != HostRequestBindingKind::ServerSingleUserOwner
                })
                || principal.auth_context() != auth
                || !principal.matches_pool_scope(administration.registry.pool())
            {
                return Err(host_not_current());
            }
            None
        }
        CurrentHost::Desktop(installation) => {
            if !auth.is_single_user()
                || auth.actor().as_str() != DESKTOP_LOCAL_ACTOR_ID
                || field::<Option<String>>(row, "read_host_email")?.as_deref()
                    != Some(DESKTOP_LOCAL_EMAIL)
                || roles.as_slice() != ["admin"]
                || auth
                    .request_binding()
                    .is_none_or(|value| value.kind() != HostRequestBindingKind::DesktopWindow)
                || installation.auth_context().deployment() != auth.deployment()
                || installation.auth_context().tenant() != auth.tenant()
                || !administration
                    .registry
                    .matches_desktop_read_current_row(row)
                    .map_err(|_| ArtifactReadCurrentError::Unavailable)?
            {
                return Err(host_not_current());
            }
            let current = AuthContextBuilder::from_verified_session(
                auth.deployment().clone(),
                auth.tenant().clone(),
                auth.actor().clone(),
                AuthGeneration::new(generation),
                true,
            )
            .with_roles([Role::Admin, Role::User])
            .build();
            if current != *auth {
                return Err(host_not_current());
            }
            None
        }
    };
    Ok(CurrentReadTail {
        auth: auth.clone(),
        identity: auth
            .request_binding()
            .ok_or_else(host_not_current)?
            .identity()
            .clone(),
        observed_wall: now,
        observed_monotonic: Instant::now(),
        session,
    })
}

fn current_read_sql(desktop: bool) -> &'static str {
    static SESSION: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    let sql = if desktop { &DESKTOP } else { &SESSION };
    sql.get_or_init(|| {
        // Embed the unchanged original CTE and snapshot SELECT. The outer anchor always
        // supplies a host row, including when no visible artifact/source row remains.
        let visible = crate::thread_directory::reconciliation_visibility::VISIBLE_RUN;
        let source = super::observed_read_sql().strip_prefix(visible).expect("original artifact CTE prefix");
        let (canary_columns, canary_joins) = if desktop {
            (
                ",pcs.system_identifier::text AS read_database_system_identifier,d.oid AS read_database_oid, \
                 CASE WHEN octet_length(c.dataset_id)=32 THEN c.dataset_id END AS read_canary_dataset, \
                 CASE WHEN octet_length(c.deployment_id) BETWEEN 1 AND 512 THEN c.deployment_id END AS read_canary_deployment, \
                 CASE WHEN octet_length(c.tenant_id) BETWEEN 1 AND 512 THEN c.tenant_id END AS read_canary_tenant, \
                 CASE WHEN octet_length(c.key_id)=32 THEN c.key_id END AS read_canary_key, \
                 c.key_version AS read_canary_key_version,c.canary_schema AS read_canary_schema, \
                 CASE WHEN octet_length(c.encrypted_canary) BETWEEN 1 AND 4096 THEN c.encrypted_canary END AS read_canary_encrypted",
                " LEFT JOIN pg_control_system() pcs ON true \
                  LEFT JOIN pg_database d ON d.datname=current_database() \
                  LEFT JOIN openbot_internal.desktop_vault_canaries c ON c.deployment_id=$4 AND c.tenant_id=$5 AND c.key_version=1",
            )
        } else { ("", "") };
        format!("/* artifact_current_host_joint_read_after_io */ {visible}, current_artifact AS ({source}) \
          SELECT a.*,u.id AS read_host_user,u.auth_generation AS read_host_generation, \
            CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS read_host_email, \
            EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS read_host_revoked, \
            ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS read_host_roles, \
            s.id AS read_session_id,s.user_id AS read_session_user,s.token AS read_session_token, \
            s.created_at AS read_session_created,s.updated_at AS read_session_updated,s.expires_at AS read_session_expires, \
            s.auth_generation AS read_session_generation {canary_columns} \
          FROM (SELECT 1) anchor LEFT JOIN public.users u ON u.id=$3 \
          LEFT JOIN public.sessions s ON s.id=$16 AND s.user_id=u.id \
          LEFT JOIN current_artifact a ON true {canary_joins}")
    })
}

#[cfg(test)]
#[path = "artifact_read_authority/tests.rs"]
mod tests;
