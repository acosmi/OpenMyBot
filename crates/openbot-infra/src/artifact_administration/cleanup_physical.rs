//! Current original-owner physical work. No terminal write, refund, audit or external erasure ACK.

use std::future::Future;
use std::os::fd::RawFd;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use openbot_contracts::auth::AuthContext;
use openbot_contracts::request_binding::{ArtifactCleanupHostTailWitness, HostRequestBindingError};
use openbot_domain::artifact_cleanup::ArtifactCleanupFenceKey;
use tokio::sync::oneshot;
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::cleanup_arm::{
    ArmedArtifactCleanupIntent, ArtifactCleanupArmError, PhysicalCurrentRequest,
};
use super::{PostgresArtifactAdministration, verify_artifact_read_schema_on};
use crate::artifact_bytes::{
    ArtifactBlob, ArtifactByteError, ArtifactByteProbe, ArtifactByteStorageLocation,
};
use crate::artifact_store::{
    ArtifactPhysicalUnlinkError, ArtifactReadBridgeError, ArtifactStoreError,
    DatasetBoundArtifactStore, PhysicalInvocationClaim, PhysicalInvocationQueryOwner,
    PhysicalWorkerLease,
};
use crate::db::pool::TransactionOwnerError;

/// Limited current physical facts. None of these states authorizes a terminal write or refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactCleanupPhysicalState {
    /// The actual original names were absent after the guarded three directory syncs.
    DurableAbsent,
    /// Actual installed bytes still match the original expected binding.
    Retained,
    /// Physical completion cannot be proved; never substitute expected facts for actual bytes.
    Indeterminate,
}

/// Private same-Store observation after the actual worker ended and original query ACKed.
/// No Serde, grant conversion, persistent terminal transition or external byte destruction ACK.
pub struct ArtifactCleanupPhysicalObservation {
    claim: Arc<PhysicalInvocationClaim>,
    _original_store: Arc<DatasetBoundArtifactStore>,
    _original_key: ArtifactCleanupFenceKey,
    actual: ArtifactByteProbe,
    _actually_unlinked: bool,
    original_tail: Box<dyn ArtifactCleanupHostTailWitness>,
    deadline: Instant,
}

impl core::fmt::Debug for ArtifactCleanupPhysicalObservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .write_str("ArtifactCleanupPhysicalObservation([redacted original physical facts])")
    }
}

impl ArtifactCleanupPhysicalObservation {
    /// Observe only this limited physical state, without a cleanup or refund grant.
    #[must_use]
    pub const fn state(&self) -> ArtifactCleanupPhysicalState {
        match &self.actual {
            ArtifactByteProbe::Absent => ArtifactCleanupPhysicalState::DurableAbsent,
            ArtifactByteProbe::Retained { .. } => ArtifactCleanupPhysicalState::Retained,
            ArtifactByteProbe::Indeterminate => ArtifactCleanupPhysicalState::Indeterminate,
        }
    }

    fn verify_delivery(&self, auth: &AuthContext) -> Result<(), Error> {
        registered_remaining(&self.claim, self.deadline)?;
        let tail = self.original_tail.verify_current(auth, self.deadline);
        registered_remaining(&self.claim, self.deadline)?;
        tail.map_err(Error::Host)?;
        let published = self.claim.verify_publish();
        registered_remaining(&self.claim, self.deadline)?;
        published.map_err(|_| Error::PhysicalUnproven)
    }
}

/// Closed trusted-port failures without identifiers, paths, body bytes or SQL details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactCleanupPhysicalError {
    /// The original selector is invalid.
    #[error("artifact_cleanup_physical_input_invalid:{field}")]
    InvalidInput {
        /// Registered static field only.
        field: &'static str,
    },
    /// The original enrolled Host/window cannot attest this request.
    #[error("artifact_cleanup_physical_host_invalid")]
    Host(HostRequestBindingError),
    /// The actual original saved owner lacks current authority.
    #[error("artifact_cleanup_physical_not_visible")]
    NotVisible,
    /// The current immutable pair or armed intent contradicts this invocation.
    #[error("artifact_cleanup_physical_conflict")]
    Conflict,
    /// The original dependency or absolute budget is unavailable.
    #[error("artifact_cleanup_physical_unavailable")]
    Unavailable,
    /// Actual retained facts violate a registered invariant.
    #[error("artifact_cleanup_physical_facts_invalid:{field}")]
    Corrupt {
        /// Registered static field only, never data or an OS message.
        field: &'static str,
    },
    /// Applicable original resources, physical effects or the original query remain unproved.
    #[error("artifact_cleanup_physical_unproven")]
    PhysicalUnproven,
    /// A real original ROLLBACK ACK arrived after the unchanged absolute deadline.
    #[error("artifact_cleanup_physical_rollback_acknowledged_after_deadline")]
    RollbackAcknowledgedAfterDeadline,
}

type Error = ArtifactCleanupPhysicalError;

/// Exactly four trusted worker cutpoints. A label supplies neither authorization nor closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactCleanupPhysicalIoPhase {
    /// The actual worker holds its original preflight FD and continuous IO guard.
    PreflightReady,
    /// Before the original execution rechecks identities and consumes the Started permission.
    BeforeFirstUnlink,
    /// Actual unlink returned; the original FD is still held before the guarded directory syncs.
    AfterUnlinkBeforeSync,
    /// Worker-local leaf/temporary FDs and its IO guard have actually dropped.
    WorkerEnded,
}

/// Trusted Rust fixture instrumentation only. Callbacks run outside gate/permission locks.
pub trait ArtifactCleanupPhysicalObserver: Send + Sync {
    /// Observe a real cutpoint; an optional original FD remains a nongrant tracing input.
    fn on_phase(
        &self,
        phase: ArtifactCleanupPhysicalIoPhase,
        artifact_id: Uuid,
        original_leaf_fd: Option<RawFd>,
    );
}

enum PhysicalIoPermission {
    Pending,
    Granted {
        claim: Arc<PhysicalInvocationClaim>,
        deadline: Instant,
        tail: Box<dyn ArtifactCleanupHostTailWitness>,
    },
    // Stop requests here never undo an already entered syscall or relabel its effects.
    Started {
        stop_requested: bool,
    },
    Cancelled,
}

struct WorkerPermission {
    capture_operation: crate::artifact_store::CaptureMutationLease,
    state: Mutex<PhysicalIoPermission>,
    changed: Condvar,
}

impl Drop for WorkerPermission {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.capture_operation.record_returned();
        }
    }
}

impl WorkerPermission {
    fn new(capture_operation: crate::artifact_store::CaptureMutationLease) -> Arc<Self> {
        Arc::new(Self {
            capture_operation,
            state: Mutex::new(PhysicalIoPermission::Pending),
            changed: Condvar::new(),
        })
    }

    fn cancel(&self) {
        let retired = if let Ok(mut state) = self.state.lock() {
            match &mut *state {
                PhysicalIoPermission::Pending | PhysicalIoPermission::Granted { .. } => Some(
                    std::mem::replace(&mut *state, PhysicalIoPermission::Cancelled),
                ),
                PhysicalIoPermission::Started { stop_requested } => {
                    *stop_requested = true;
                    None
                }
                PhysicalIoPermission::Cancelled => None,
            }
        } else {
            None
        };
        // A tail or its original owners can drop only after the permission lock is released.
        drop(retired);
        self.changed.notify_all();
    }

    fn should_stop(&self, deadline: Instant) -> bool {
        Instant::now() >= deadline
            || self.state.lock().map_or(true, |state| {
                matches!(
                    *state,
                    PhysicalIoPermission::Cancelled
                        | PhysicalIoPermission::Started {
                            stop_requested: true
                        }
                )
            })
    }

    fn grant(
        &self,
        claim: &Arc<PhysicalInvocationClaim>,
        tail: Box<dyn ArtifactCleanupHostTailWitness>,
        deadline: Instant,
    ) -> Result<(), Error> {
        remaining(deadline)?;
        let mut state = self.state.lock().map_err(|_| Error::PhysicalUnproven)?;
        if !matches!(*state, PhysicalIoPermission::Pending) {
            return Err(Error::Unavailable);
        }
        *state = PhysicalIoPermission::Granted {
            claim: Arc::clone(claim),
            deadline,
            tail,
        };
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    fn wait_granted(&self, deadline: Instant) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::PhysicalUnproven)?;
        loop {
            let wait = remaining(deadline)?;
            match &*state {
                PhysicalIoPermission::Granted { .. } => return Ok(()),
                PhysicalIoPermission::Cancelled | PhysicalIoPermission::Started { .. } => {
                    return Err(Error::Unavailable);
                }
                PhysicalIoPermission::Pending => {
                    let (next, _) = self
                        .changed
                        .wait_timeout(state, wait)
                        .map_err(|_| Error::PhysicalUnproven)?;
                    state = next;
                }
            }
        }
    }

    fn start(
        &self,
        claim: &Arc<PhysicalInvocationClaim>,
        worker: &PhysicalWorkerLease,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::PhysicalUnproven)?;
        let PhysicalIoPermission::Granted {
            claim: granted,
            deadline: granted_deadline,
            tail,
        } = &*state
        else {
            return Err(Error::Unavailable);
        };
        if !Arc::ptr_eq(claim, granted) || *granted_deadline != deadline {
            return Err(Error::Corrupt {
                field: "controlled_resources",
            });
        }
        remaining(deadline)?;
        tail.verify_current(auth, deadline).map_err(Error::Host)?;
        // The only nested order is permission -> gate. No IO/await or observer callback occurs.
        claim
            .try_start_worker(worker)
            .map_err(|_| Error::PhysicalUnproven)?;
        let retired = std::mem::replace(
            &mut *state,
            PhysicalIoPermission::Started {
                stop_requested: false,
            },
        );
        drop(state);
        drop(retired);
        Ok(())
    }
}

struct CallerWaiter {
    permission: Arc<WorkerPermission>,
    claim: Arc<PhysicalInvocationClaim>,
    deadline: Instant,
    completed: bool,
}
impl Drop for CallerWaiter {
    fn drop(&mut self) {
        if !self.completed {
            self.permission.cancel();
        }
        // A true ACK and ended worker remain facts, but expiry cannot retire a clean slot.
        let _ = registered_remaining(&self.claim, self.deadline);
    }
}

struct MainQueryOwner {
    permission: Arc<WorkerPermission>,
    query: Option<PhysicalInvocationQueryOwner>,
    claim: Arc<PhysicalInvocationClaim>,
    deadline: Instant,
}
impl Drop for MainQueryOwner {
    fn drop(&mut self) {
        // No gate lock is held. Cancellation precedes the query field's unacknowledged Drop.
        self.permission.cancel();
        // Also covers every post-ACK return, including a known work or synchronous tail error.
        let _ = registered_remaining(&self.claim, self.deadline);
    }
}

struct WorkerObservation {
    actual: ArtifactByteProbe,
    actually_unlinked: bool,
}

struct WorkFailure {
    error: Error,
    query_unproven: bool,
}
impl WorkFailure {
    fn known(error: Error) -> Self {
        Self {
            error,
            query_unproven: false,
        }
    }
    fn current(error: ArtifactCleanupArmError) -> Self {
        Self {
            query_unproven: matches!(error, ArtifactCleanupArmError::Unavailable),
            error: arm_error(error),
        }
    }
    fn elapsed() -> Self {
        Self {
            error: Error::Unavailable,
            query_unproven: true,
        }
    }
}

impl PostgresArtifactAdministration {
    /// Attach trusted four-phase instrumentation before sharing the original administration.
    #[must_use]
    pub fn with_cleanup_physical_observer(
        self,
        observer: Arc<dyn ArtifactCleanupPhysicalObserver>,
    ) -> Self {
        // The constructor owns this original object; the same once field serves live Arc setup.
        let _ = self.cleanup_physical_observer.set(observer);
        self
    }

    /// Install once on the already enrolled original Arc without replacing its host authority.
    ///
    /// # Errors
    /// A second installation is refused.
    pub fn install_cleanup_physical_observer(
        self: &Arc<Self>,
        observer: Arc<dyn ArtifactCleanupPhysicalObserver>,
    ) -> Result<(), ArtifactStoreError> {
        self.cleanup_physical_observer
            .set(observer)
            .map_err(|_| ArtifactStoreError::BindingMismatch)
    }

    /// Remove only the original armed explicitly saved storage object under fresh authority.
    /// Retained pair, charge, intent and fence remain unchanged.
    ///
    /// # Errors
    /// Refuses foreign/current-invalid inputs, unknown owners or an unproved original outcome.
    pub async fn remove_armed_explicit_saved_bytes_before(
        self: &Arc<Self>,
        auth: &AuthContext,
        intent: &ArmedArtifactCleanupIntent,
        original_deadline: Instant,
    ) -> Result<ArtifactCleanupPhysicalObservation, Error> {
        self.physical_before(auth, intent, original_deadline, true)
            .await
    }

    /// Reobserve and directory-sync the same original armed object without attempting unlink.
    /// A new known observation never clears an earlier unknown query or expiry.
    ///
    /// # Errors
    /// Refuses foreign/current-invalid inputs and any retained original resource uncertainty.
    pub async fn observe_armed_explicit_saved_bytes_before(
        self: &Arc<Self>,
        auth: &AuthContext,
        intent: &ArmedArtifactCleanupIntent,
        original_deadline: Instant,
    ) -> Result<ArtifactCleanupPhysicalObservation, Error> {
        self.physical_before(auth, intent, original_deadline, false)
            .await
    }

    async fn physical_before(
        self: &Arc<Self>,
        auth: &AuthContext,
        intent: &ArmedArtifactCleanupIntent,
        original_deadline: Instant,
        remove: bool,
    ) -> Result<ArtifactCleanupPhysicalObservation, Error> {
        let capture_operation = self
            .store
            .begin_capture_mutation()
            .map_err(|_| Error::Unavailable)?;
        let result = async {
            let deadline = original_deadline.min(
                Instant::now()
                    .checked_add(Duration::from_secs(5))
                    .ok_or(Error::Unavailable)?,
            );
            remaining(deadline)?;
            let (store, key) = intent
                .validated_physical_binding(self)
                .map_err(|_| Error::Conflict)?
                .into_original_parts();
            // Pure original attachment refusals precede any invocation or PG resource registration.
            let authority = self.read_authority();
            let target = authority.cleanup_host_target(auth);
            let _current = PhysicalCurrentRequest::borrow_before(self, auth, &target, deadline)
                .map_err(arm_error)?;
            let (claim, query) =
                PhysicalInvocationClaim::register(Arc::clone(&store), key.clone(), deadline)
                    .map_err(|_| Error::PhysicalUnproven)?;
            let permission = WorkerPermission::new(capture_operation.delegated());
            let mut waiter = CallerWaiter {
                permission: Arc::clone(&permission),
                claim: Arc::clone(&claim),
                deadline,
                completed: false,
            };
            let (sender, receiver) = oneshot::channel();
            let administration = Arc::clone(self);
            let original_auth = auth.clone();
            // This owned main task retains the original query when only its caller waiter drops.
            // Runtime/task Drop instead drops the real query owner and permanently poisons the key.
            self.store
                .spawn_capture_mutation(async move {
                    let result = supervise(
                        administration,
                        original_auth,
                        store,
                        key,
                        claim,
                        query,
                        permission,
                        deadline,
                        remove,
                    )
                    .await;
                    let _ = sender.send(result);
                })
                .map_err(|_| Error::Unavailable)?;
            let received = before(deadline, receiver).await;
            registered_remaining(&waiter.claim, deadline)?;
            let observation = received
                .map_err(|failure| failure.error)?
                .map_err(|_| Error::PhysicalUnproven)??;
            let delivery = observation.verify_delivery(auth);
            registered_remaining(&waiter.claim, deadline)?;
            delivery?;
            waiter.completed = true;
            Ok(observation)
        }
        .await;
        if !matches!(&result, Err(Error::Unavailable | Error::PhysicalUnproven)) {
            capture_operation.complete();
        }
        result
    }
}

#[allow(clippy::too_many_arguments)] // One exact original invocation, no independently minted owner.
async fn supervise(
    administration: Arc<PostgresArtifactAdministration>,
    auth: AuthContext,
    store: Arc<DatasetBoundArtifactStore>,
    key: ArtifactCleanupFenceKey,
    claim: Arc<PhysicalInvocationClaim>,
    query: PhysicalInvocationQueryOwner,
    permission: Arc<WorkerPermission>,
    deadline: Instant,
    remove: bool,
) -> Result<ArtifactCleanupPhysicalObservation, Error> {
    let mut main = MainQueryOwner {
        permission: Arc::clone(&permission),
        query: Some(query),
        claim: Arc::clone(&claim),
        deadline,
    };
    let authority = administration.read_authority();
    let target = authority.cleanup_host_target(&auth);
    // Reborrow the actual enrolled factory inside this owned task. Even a raced pure refusal
    // is followed by the claimed original schema/BEGIN/true rollback, never a fabricated ACK.
    let current = PhysicalCurrentRequest::borrow_before(&administration, &auth, &target, deadline);
    let mut client = administration
        .registry
        .pool()
        .get_guarded(deadline)
        .await
        .map_err(|_| Error::Unavailable)?;
    let schema = before(deadline, verify_artifact_read_schema_on(client.as_client()))
        .await
        .map_err(|failure| failure.error)?;
    schema.map_err(|error| match error {
        openbot_application::ArtifactAdministrationError::Unavailable => Error::Unavailable,
        _ => Error::Corrupt { field: "schema" },
    })?;
    let transaction = client.begin_read_committed().await.map_err(owner_error)?;
    let result = match current {
        Ok(current) => {
            work_before(
                &administration,
                &auth,
                &store,
                &key,
                &claim,
                &permission,
                &current,
                transaction.as_transaction(),
                deadline,
                remove,
            )
            .await
        }
        Err(error) => Err(WorkFailure::known(arm_error(error))),
    };
    if let Err(failure) = &result {
        permission.cancel();
        if failure.query_unproven {
            claim.mark_unproven();
        }
    }
    // No business COMMIT or DML: only this original guarded ROLLBACK can prove its query ACK.
    transaction.rollback().await.map_err(owner_error)?;
    main.query
        .take()
        .ok_or(Error::PhysicalUnproven)?
        .acknowledge_rollback()
        .map_err(|_| Error::PhysicalUnproven)?;
    // Check before mapping a known work error: the real ACK owner has already been consumed.
    registered_remaining(&claim, deadline)?;
    let (worker, tail) = result.map_err(|failure| failure.error)?;
    registered_remaining(&claim, deadline)?;
    let current_tail = tail.verify_current(&auth, deadline);
    registered_remaining(&claim, deadline)?;
    current_tail.map_err(Error::Host)?;
    let published = claim.verify_publish();
    registered_remaining(&claim, deadline)?;
    published.map_err(|_| Error::PhysicalUnproven)?;
    Ok(ArtifactCleanupPhysicalObservation {
        claim,
        _original_store: store,
        _original_key: key,
        actual: worker.actual,
        _actually_unlinked: worker.actually_unlinked,
        original_tail: tail,
        deadline,
    })
}

#[allow(clippy::too_many_arguments)] // Borrow only this invocation's original current transaction.
async fn work_before(
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    store: &Arc<DatasetBoundArtifactStore>,
    key: &ArtifactCleanupFenceKey,
    claim: &Arc<PhysicalInvocationClaim>,
    permission: &Arc<WorkerPermission>,
    current: &PhysicalCurrentRequest<'_>,
    transaction: &Transaction<'_>,
    deadline: Instant,
    remove: bool,
) -> Result<(WorkerObservation, Box<dyn ArtifactCleanupHostTailWitness>), WorkFailure> {
    let original = current
        .lock_before(transaction, key, deadline)
        .await
        .map_err(WorkFailure::current)?;
    claim
        .wait_original_reads_before()
        .await
        .map_err(|_| WorkFailure::known(Error::PhysicalUnproven))?;
    // Resource waits are followed by another actual RC statement before any worker or grant.
    current
        .refresh_before(transaction, &original, deadline)
        .await
        .map_err(WorkFailure::current)?;
    let lease = claim
        .reserve_worker()
        .map_err(|_| WorkFailure::known(Error::PhysicalUnproven))?;
    let (ready_sender, ready) = oneshot::channel();
    let original_store = Arc::clone(store);
    let original_claim = Arc::clone(claim);
    let original_permission = Arc::clone(permission);
    let original_auth = auth.clone();
    let blob = original.blob().clone();
    let observer = administration
        .cleanup_physical_observer
        .get()
        .map(Arc::clone);
    let mut worker = store.capture_blocking(move || {
        run_worker(
            original_store,
            original_claim,
            lease,
            original_permission,
            original_auth,
            blob,
            deadline,
            remove,
            ready_sender,
            observer,
        )
    });
    let preflight = before(deadline, ready).await?;
    let preflight = match preflight {
        Ok(preflight) => preflight,
        Err(_) => {
            permission.cancel();
            let _ = before(deadline, &mut worker).await?;
            return Err(WorkFailure::known(Error::PhysicalUnproven));
        }
    };
    if let Err(error) = preflight {
        permission.cancel();
        let _ = before(deadline, &mut worker).await?;
        return Err(WorkFailure::known(error));
    }
    // A preflight FD is not a permit. This new statement sees controller commits after it.
    let fresh = match current
        .refresh_before(transaction, &original, deadline)
        .await
    {
        Ok(fresh) => fresh,
        Err(error) => {
            permission.cancel();
            let _ = before(deadline, &mut worker).await?;
            return Err(WorkFailure::current(error));
        }
    };
    if let Err(error) = permission.grant(claim, fresh.into_witness(), deadline) {
        permission.cancel();
        let _ = before(deadline, &mut worker).await?;
        return Err(WorkFailure::known(error));
    }
    let result = before(deadline, &mut worker)
        .await?
        .map_err(|_| WorkFailure::known(Error::PhysicalUnproven))?;
    // Preserve the immutable original pair after moving a separate fresh tail into the worker.
    let post = current
        .refresh_before(transaction, &original, deadline)
        .await
        .map_err(WorkFailure::current)?;
    let actual = result.map_err(WorkFailure::known)?;
    if matches!(actual.actual, ArtifactByteProbe::Indeterminate) {
        return Err(WorkFailure::known(Error::PhysicalUnproven));
    }
    Ok((actual, post.into_witness()))
}

#[allow(clippy::too_many_arguments)] // One original worker and its registered nongrant inputs.
fn run_worker(
    store: Arc<DatasetBoundArtifactStore>,
    claim: Arc<PhysicalInvocationClaim>,
    lease: PhysicalWorkerLease,
    permission: Arc<WorkerPermission>,
    auth: AuthContext,
    blob: ArtifactBlob,
    deadline: Instant,
    remove: bool,
    ready: oneshot::Sender<Result<(), Error>>,
    observer: Option<Arc<dyn ArtifactCleanupPhysicalObserver>>,
) -> Result<WorkerObservation, Error> {
    // Declare the lease before all worker-local FD/io owners. Error/unwind drops those first.
    let original_lease = lease;
    let mut ready = Some(ready);
    let result = (|| {
        let io = store
            .try_physical_io_before_admitted(deadline, &permission.capture_operation)
            .map_err(store_error)?;
        let mut stop = |_| permission.should_stop(deadline);
        let original = io
            .preflight_installed_guarded(&blob, &mut stop)
            .map_err(bridge_error)?;
        observe(
            &observer,
            ArtifactCleanupPhysicalIoPhase::PreflightReady,
            blob.id(),
            original.original_leaf_fd(),
        );
        remaining(deadline)?;
        ready
            .take()
            .ok_or(Error::PhysicalUnproven)?
            .send(Ok(()))
            .map_err(|_| Error::Unavailable)?;
        permission.wait_granted(deadline)?;
        if remove && original.original_leaf_fd().is_some() {
            observe(
                &observer,
                ArtifactCleanupPhysicalIoPhase::BeforeFirstUnlink,
                blob.id(),
                original.original_leaf_fd(),
            );
        }
        let mut start = || permission.start(&claim, &original_lease, &auth, deadline);
        let actually_unlinked = io
            .execute_installed_guarded(&original, remove, &mut stop, &mut start)
            .map_err(|error| match error {
                ArtifactPhysicalUnlinkError::Check(error) => bridge_error(error),
                ArtifactPhysicalUnlinkError::Start(error) => error,
            })?;
        if actually_unlinked {
            observe(
                &observer,
                ArtifactCleanupPhysicalIoPhase::AfterUnlinkBeforeSync,
                blob.id(),
                original.original_leaf_fd(),
            );
        }
        // Continuous same guard. Never call the ordinary Store wrapper that would try_lock again.
        let actual = io.probe_actual_guarded(blob.id(), &mut stop);
        if let ArtifactByteProbe::Retained {
            location,
            byte_length,
            sha256,
        } = &actual
            && (*location != ArtifactByteStorageLocation::Object
                || *byte_length != blob.byte_length()
                || sha256 != blob.sha256())
        {
            return Err(Error::Corrupt { field: "object" });
        }
        drop(original);
        drop(io);
        Ok(WorkerObservation {
            actual,
            actually_unlinked,
        })
    })();
    if let Some(ready) = ready {
        let _ = ready.send(Err(result
            .as_ref()
            .err()
            .copied()
            .unwrap_or(Error::PhysicalUnproven)));
    }
    // The inner scope has already dropped the original leaf and all temporary FD/io owners.
    original_lease.finish_after_resources();
    observe(
        &observer,
        ArtifactCleanupPhysicalIoPhase::WorkerEnded,
        blob.id(),
        None,
    );
    result
}

fn observe(
    observer: &Option<Arc<dyn ArtifactCleanupPhysicalObserver>>,
    phase: ArtifactCleanupPhysicalIoPhase,
    artifact_id: Uuid,
    original_leaf_fd: Option<RawFd>,
) {
    if let Some(observer) = observer {
        observer.on_phase(phase, artifact_id, original_leaf_fd);
    }
}

async fn before<T>(deadline: Instant, future: impl Future<Output = T>) -> Result<T, WorkFailure> {
    remaining(deadline).map_err(|_| WorkFailure::elapsed())?;
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| WorkFailure::elapsed())?;
    remaining(deadline).map_err(|_| WorkFailure::elapsed())?;
    Ok(result)
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(Error::Unavailable)
}

fn registered_remaining(
    claim: &PhysicalInvocationClaim,
    deadline: Instant,
) -> Result<Duration, Error> {
    let remaining = remaining(deadline);
    if remaining.is_err() {
        claim.mark_unproven();
    }
    remaining
}

fn arm_error(error: ArtifactCleanupArmError) -> Error {
    match error {
        ArtifactCleanupArmError::InvalidInput { field } => Error::InvalidInput { field },
        ArtifactCleanupArmError::Host(error) => Error::Host(error),
        ArtifactCleanupArmError::NotVisible => Error::NotVisible,
        ArtifactCleanupArmError::Conflict => Error::Conflict,
        ArtifactCleanupArmError::Corrupt { field } => Error::Corrupt { field },
        ArtifactCleanupArmError::RollbackAcknowledgedAfterDeadline => {
            Error::RollbackAcknowledgedAfterDeadline
        }
        ArtifactCleanupArmError::Unavailable
        | ArtifactCleanupArmError::CommitUnknown
        | ArtifactCleanupArmError::CommitAcknowledgedAfterDeadline => Error::Unavailable,
    }
}

fn owner_error(error: TransactionOwnerError) -> Error {
    match error {
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            Error::RollbackAcknowledgedAfterDeadline
        }
        _ => Error::Unavailable,
    }
}

fn store_error(error: ArtifactStoreError) -> Error {
    match error {
        ArtifactStoreError::UnsafeRoot | ArtifactStoreError::BindingMismatch => Error::Corrupt {
            field: "store_binding",
        },
        ArtifactStoreError::Unavailable | ArtifactStoreError::Busy => Error::Unavailable,
    }
}

fn bridge_error(error: ArtifactReadBridgeError) -> Error {
    match error {
        ArtifactReadBridgeError::Store(error) => store_error(error),
        ArtifactReadBridgeError::Bytes(
            ArtifactByteError::Io | ArtifactByteError::CleanupFailed,
        ) => Error::PhysicalUnproven,
        ArtifactReadBridgeError::Bytes(_) => Error::Corrupt { field: "object" },
    }
}
