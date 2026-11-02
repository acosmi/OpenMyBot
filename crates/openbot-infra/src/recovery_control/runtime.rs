//! Original runtime SH ownership and short held admission.
//!
//! No parsed DATA, missing head, dropped File, PID observation or Weak expiry
//! becomes a runtime-close receipt. The actual close adapters are supplied by
//! the separately registered original resource-consumer hunks.

use std::fs::File;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use openbot_contracts::auth::AuthContext;
use openbot_contracts::recovery::{
    RecoveryAdmissionLease, RecoveryAdmissionPurpose, RecoveryAdmissionWitness, RestoreCohortRef,
};
use openbot_contracts::request_binding::{HostRequestBindingError, VerifiedHostRequestBinding};
use rustix::fs::FlockOperation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::activation::ActivationBinding;
use super::entry::{self, ControlFiles, ControlOwner, OwnedRecord, RuntimeEntry};
use super::journal::ProcessStart;
use super::journal::{NativeExit, PipeJoin};
use super::{
    RecoveryControlError, RecoveryControlFault, RecoveryFileIdentity, before, hex, hex_array, id,
};
use std::ops::{Deref, DerefMut};

/// Private original startup input, not a parser, public constructor or proof
/// inferred from a caller's process identifiers. The actual host producer owns
/// the enclosing RuntimeEntry.
pub(super) struct OriginalRuntimeEnrollment {
    pub(super) boot_identity: String,
    pub(super) pid: u32,
    pub(super) process_start: ProcessStart,
    pub(super) resource_model: ResourceModel,
    pub(super) original_owner_set: Vec<RuntimeOwner>,
}

/// The closed set of original runtime owners that may produce an effect;
/// each has one fixed id in the enrollment (spec 8364).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeOwner {
    PostgresSidecar,
    SqlDriver,
    ApplicationAssembly,
    DesktopAgentRelay,
    DesktopAgent,
    RunRelay,
    BuiltInAgent,
    McpRevocationReconciler,
    ScreenHub,
}

/// The observed result of awaiting an original task.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RuntimeTaskOutcome {
    Returned,
    Panicked,
    JoinUnknown,
}

/// An original database transaction's acknowledged terminal state.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RuntimePgAck {
    CommitAck,
    RollbackAck,
}

/// Passive resources whose original adapters have proved no remaining worker.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "data")]
pub enum PassiveObjectKind {
    SqlDriver(#[serde(serialize_with = "serialize_destructions")] Vec<crate::db::pool::ConnectionDestruction>),
    ScreenHub,
    NeverStarted(RuntimeOwner),
}

fn serialize_destructions<S: serde::Serializer>(
    facts: &[crate::db::pool::ConnectionDestruction],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use crate::db::pool::ConnectionDestruction;
    use serde::ser::SerializeSeq;
    let mut sequence = serializer.serialize_seq(Some(facts.len()))?;
    for fact in facts {
        sequence.serialize_element(match fact {
            ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart => "connecting_owner_destroyed_before_start",
            ConnectionDestruction::ConnectingFutureDestroyed => "connecting_future_destroyed",
            ConnectionDestruction::ConnectionDestroyed => "connection_destroyed",
        })?;
    }
    sequence.end()
}

/// Original resource observations. A fact is data, never restore authority.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all_fields = "camelCase")]
pub enum RuntimeCloseFact {
    NativeWait {
        original_program_id: RuntimeOwner,
        original_pid: u32,
        original_start_identity: ProcessStart,
        exit: NativeExit,
        observed_ns: u64,
        pipes: [PipeJoin; 3],
    },
    TaskJoin {
        original_task_id: RuntimeOwner,
        outcome: RuntimeTaskOutcome,
        observed_ns: u64,
    },
    PgAck {
        original_owner: RuntimeOwner,
        disposition: RuntimePgAck,
    },
    PassiveRetirement { object: PassiveObjectKind },
}

impl RuntimeCloseFact {
    fn owner(&self) -> RuntimeOwner {
        match self {
            Self::NativeWait { original_program_id, .. } => *original_program_id,
            Self::TaskJoin { original_task_id, .. } => *original_task_id,
            Self::PgAck { original_owner, .. } => *original_owner,
            Self::PassiveRetirement { object } => match object {
                PassiveObjectKind::SqlDriver(_) => RuntimeOwner::SqlDriver,
                PassiveObjectKind::ScreenHub => RuntimeOwner::ScreenHub,
                PassiveObjectKind::NeverStarted(owner) => *owner,
            },
        }
    }

    fn observed_closed(&self, now: u64) -> bool {
        match self {
            Self::NativeWait { original_pid, original_start_identity, observed_ns, pipes, .. } => {
                *original_pid != 0 && original_start_identity.nanos < 1_000_000_000
                    && *observed_ns != 0 && *observed_ns <= now
                    && pipes.iter().all(|pipe| match pipe {
                        PipeJoin::Null => true,
                        PipeJoin::Returned { observed_ns } => *observed_ns != 0 && *observed_ns <= now,
                        PipeJoin::Panicked { .. } | PipeJoin::JoinUnknown => false,
                    })
            }
            Self::TaskJoin { outcome, observed_ns, .. } => {
                matches!(outcome, RuntimeTaskOutcome::Returned) && *observed_ns != 0 && *observed_ns <= now
            }
            Self::PgAck { .. } | Self::PassiveRetirement { .. } => true,
        }
    }
}

/// The original host's complete owner observations for one runtime.
pub struct RuntimeCloseResources {
    facts: Vec<RuntimeCloseFact>,
}

impl RuntimeCloseResources {
    /// Preserve the actual adapter results for enrollment reconciliation.
    pub fn new(facts: Vec<RuntimeCloseFact>) -> Self {
        Self { facts }
    }
}

/// A held, durable close record produced by the original runtime owner.
pub struct RuntimeCloseReceipt {
    _record: OwnedRecord,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CloseRecord<'a> {
    record_type: &'static str,
    version: u32,
    same_identity_tuple: Enrollment<'a>,
    enrollment_digest: String,
    original_resource_facts: &'a [RuntimeCloseFact],
    retained_unknown_effect_refs: [(); 0],
    clock_observations: [u64; 1],
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum ResourceModel {
    Local,
    Server,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RootAndLockIdentities {
    control_root: RecoveryFileIdentity,
    admission_lock: RecoveryFileIdentity,
    runtime_lock: RecoveryFileIdentity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Enrollment<'a> {
    record_type: &'static str,
    version: u32,
    control_id: &'a str,
    nonce: &'a str,
    boot_identity: &'a str,
    pid: u32,
    process_start: &'a ProcessStart,
    activation_digest: &'a str,
    authorization_epoch: &'a str,
    business_install_binding: &'a ActivationBinding,
    root_and_lock_identities: RootAndLockIdentities,
    resource_model: ResourceModel,
    original_owner_set: &'a [RuntimeOwner],
}

fn enrollment<'a>(
    original: &'a RuntimeEntry,
    root: RecoveryFileIdentity,
    admission: RecoveryFileIdentity,
    runtime: RecoveryFileIdentity,
) -> Enrollment<'a> {
    Enrollment {
        record_type: "wrokbot-runtime-enrollment",
        version: 1,
        control_id: original.published.control_id(),
        nonce: &original.runtime_nonce,
        boot_identity: &original.enrollment.boot_identity,
        pid: original.enrollment.pid,
        process_start: &original.enrollment.process_start,
        activation_digest: original.published.digest(),
        authorization_epoch: original.published.binding().authorization_epoch(),
        business_install_binding: original.published.binding(),
        root_and_lock_identities: RootAndLockIdentities {
            control_root: root,
            admission_lock: admission,
            runtime_lock: runtime,
        },
        resource_model: original.enrollment.resource_model,
        original_owner_set: &original.enrollment.original_owner_set,
    }
}

/// The actual SH and the original enrollment FD have a single strong owner.
/// A read gate only holds Weak. There is intentionally no Clone or Drop close.
pub struct RecoveryRuntimeOwner {
    state: RuntimeOwnerBook,
    handle_alive: Arc<AtomicBool>,
}

pub(super) struct RuntimeState {
    control: ControlOwner,
    runtime_lock: File,
    runtime_directory: File,
    enrollment_file: OwnedRecord,
    original: RuntimeEntry,
    root: RecoveryFileIdentity,
    runtime_identity: RecoveryFileIdentity,
    handle_alive: Arc<AtomicBool>,
    close_resources: Option<RuntimeCloseResources>,
}

pub(super) type RuntimeOwnerBook = Arc<Mutex<Option<RuntimeState>>>;

/// The same original state is checked out for IO, without a bookkeeping
/// guard. All actual SH/enrollment/control/live-observer owners stay resident.
struct RuntimeAccess {
    owner: RuntimeOwnerBook,
    state: Option<RuntimeState>,
}
impl Deref for RuntimeAccess {
    type Target = RuntimeState;
    fn deref(&self) -> &RuntimeState {
        self.state.as_ref().expect("original runtime access")
    }
}
impl DerefMut for RuntimeAccess {
    fn deref_mut(&mut self) -> &mut RuntimeState {
        self.state.as_mut().expect("original runtime access")
    }
}
impl Drop for RuntimeAccess {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        let mut book = match self.owner.lock() {
            Ok(book) => book,
            Err(poisoned) => {
                state.handle_alive.store(false, Ordering::SeqCst);
                poisoned.into_inner()
            }
        };
        // lock_runtime is the sole taker and this is the sole put-back path.
        // Poison preserves original resources and does not produce a close.
        *book = Some(state);
    }
}
fn lock_runtime(owner: &RuntimeOwnerBook) -> Result<RuntimeAccess, RecoveryControlError> {
    let mut access = RuntimeAccess {
        owner: Arc::clone(owner),
        state: None,
    };
    let mut book = owner.lock().map_err(|poisoned| {
        let book = poisoned.into_inner();
        if let Some(state) = book.as_ref() {
            state.handle_alive.store(false, Ordering::SeqCst);
        }
        RecoveryControlError::new(RecoveryControlFault::OwnerLost)
    })?;
    access.state = Some(
        book.take()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerBusy))?,
    );
    drop(book);
    Ok(access)
}

/// Admission source for request and worker consumers. Clones share the same
/// weak runtime observation or the same outside-domain scope; neither is a lease.
#[derive(Clone)]
pub struct RecoveryReadGate {
    source: GateSource,
}

#[derive(Clone)]
enum GateSource {
    Runtime(Weak<Mutex<Option<RuntimeState>>>),
    /// A database that belongs to no recovery domain.
    OutsideRecoveryDomain(ServerScope),
}

#[derive(Clone)]
struct ServerScope {
    pool: crate::db::pool::DatabasePool,
    deployment: openbot_contracts::ids::DeploymentId,
    tenant: openbot_contracts::ids::TenantId,
}

impl RecoveryRuntimeOwner {
    /// Observe the original monotonic clock immediately after an original close result.
    /// This is observation data only; it does not close an owner or grant a lease.
    pub fn observe_close_ns(&self) -> Result<u64, RecoveryControlError> {
        super::clock::monotonic_ns()
    }

    /// Bind the original ordinary Local pool only after its actual site and canary match.
    #[cfg(feature = "desktop-local")]
    pub async fn verify_local_before(
        &mut self,
        authority: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
        database: &crate::db::desktop_local::DesktopLocalDatabase,
        canary: &crate::db::desktop_vault_canary::VerifiedDesktopVaultCanary,
        services: [&str; 2],
    ) -> Result<(), RecoveryControlError> {
        let (control, binding, deadline) = {
            let state = lock_runtime(&self.state)?;
            (Arc::clone(&state.control), state.original.published.binding().clone(), state.original.original_deadline)
        };
        entry::verify_local_binding_before(&control, &binding, authority, database, canary, services, deadline).await
            .map_err(|error| error.retain(&control))
    }

    #[must_use]
    pub fn read_gate(&self) -> RecoveryReadGate {
        RecoveryReadGate {
            source: GateSource::Runtime(Arc::downgrade(&self.state)),
        }
    }

    /// Reconcile the original owner results and durably close this exact enrollment.
    /// Unknown or incomplete observations keep the enrollment and runtime lock resident.
    pub async fn close_before(
        &mut self,
        original: RuntimeCloseResources,
        deadline: Instant,
    ) -> Result<RuntimeCloseReceipt, RecoveryControlError> {
        let mut state = lock_runtime(&self.state)?;
        let control = Arc::clone(&state.control);
        let result = (|| {
            if state.close_resources.is_some() {
                return Err(RecoveryControlError::new(RecoveryControlFault::ClosureUnproven));
            }
            state.close_resources = Some(original);
            before(deadline)?;
            let observed_ns = super::clock::monotonic_ns()?;
            let facts = &state.close_resources.as_ref().expect("original close facts retained").facts;
            let owners = &state.original.enrollment.original_owner_set;
            if facts.len() != owners.len()
                || owners.iter().any(|owner| facts.iter().filter(|fact| fact.owner() == *owner).count() != 1)
                || facts.iter().any(|fact| !fact.observed_closed(observed_ns))
            {
                return Err(RecoveryControlError::new(RecoveryControlFault::ClosureUnproven));
            }
            self.handle_alive.store(false, Ordering::SeqCst);
            let mut files = entry::lock(&control)?;
            files.verify_enrollment_before(&state.original.enrollment, deadline)?;
            files.verify_runtime_enrollment(
                &state.runtime_directory,
                &state.original.runtime_nonce,
                &state.enrollment_file,
                deadline,
            )?;
            files.pending_owner = Some(files.acquire(
                "owner.lock", b"WBRCOWN1", FlockOperation::NonBlockingLockExclusive, deadline,
            )?);
            files.pending_admission = Some(files.acquire(
                "admission.lock", b"WBRCADM1", FlockOperation::NonBlockingLockExclusive, deadline,
            )?);
            let admission = files.held_lock_identity(true, deadline)?;
            files.verify_head_digest(state.original.published.digest(), deadline)?;
            let record = CloseRecord {
                record_type: "wrokbot-runtime-close",
                version: 1,
                same_identity_tuple: enrollment(&state.original, state.root, admission, state.runtime_identity),
                enrollment_digest: format!("{:x}", Sha256::digest(&state.enrollment_file.bytes)),
                original_resource_facts: facts,
                retained_unknown_effect_refs: [],
                clock_observations: [observed_ns],
            };
            let cap = usize::try_from(files.limits.max_runtime_record_bytes)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            let mut count = Count { used: 0, cap };
            serde_json::to_writer(&mut count, &record)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            let backing = count.used.checked_mul(2)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            files.prepay(backing as u64, 0)?;
            let mut output = FixedBytes { bytes: Vec::new(), cap: count.used };
            output.bytes.try_reserve_exact(count.used)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            serde_json::to_writer(&mut output, &record)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
            files.runtime_input = output.bytes;
            files.post(deadline)?;
            let input = std::mem::take(&mut files.runtime_input);
            let published = files.publish_runtime_close_record(&state.runtime_directory, &input, deadline);
            files.runtime_input = input;
            let receipt = published?;
            files.pending_admission = None;
            files.pending_owner = None;
            files.retained_runtime = None;
            Ok(RuntimeCloseReceipt { _record: receipt })
        })();
        match result {
            Ok(receipt) => {
                drop(state.state.take());
                Ok(receipt)
            }
            Err(error) => Err(error.retain(&control)),
        }
    }
}

impl RecoveryReadGate {
    /// Typed admission for a database outside every recovery domain, such as
    /// the OpenMyBot daemon's own engine cluster. Its leases hold no lock and
    /// never admit restored-binding reconfirmation.
    #[must_use]
    pub fn outside_recovery_domain(
        pool: &crate::db::pool::DatabasePool,
        deployment: &openbot_contracts::ids::DeploymentId,
        tenant: &openbot_contracts::ids::TenantId,
    ) -> RecoveryReadGate {
        RecoveryReadGate {
            source: GateSource::OutsideRecoveryDomain(ServerScope {
                pool: pool.clone(),
                deployment: deployment.clone(),
                tenant: tenant.clone(),
            }),
        }
    }
}

/// The five closed purposes keyed by the runtime's external epoch (spec 8007).
#[cfg(feature = "server-runtime")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationPurpose {
    Session,
    OidcState,
    SsoState,
    McpState,
    RunAssertion,
}

#[cfg(feature = "server-runtime")]
impl RecoveryRuntimeOwner {
    /// HKDF-SHA256 over `parent` with this owner's published epoch as salt and
    /// its deployment/tenant in the info. Audit, master, ciphertext and SCRAM
    /// parents are never passed here.
    ///
    /// # Errors
    ///
    /// `OwnerLost` (or `OwnerBusy` while another call holds the state) once the
    /// runtime state is no longer available.
    pub fn derive_authorization_key(
        &self,
        purpose: AuthorizationPurpose,
        parent: &[u8],
    ) -> Result<openbot_domain::vault::SecretBytes, RecoveryControlError> {
        let state = lock_runtime(&self.state)?;
        if !state.handle_alive.load(Ordering::SeqCst) {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        let binding = state.original.published.binding();
        let epoch: [u8; 32] = hex_array(binding.authorization_epoch());
        let label: &[u8] = match purpose {
            AuthorizationPurpose::Session => b"session",
            AuthorizationPurpose::OidcState => b"oidc-state",
            AuthorizationPurpose::SsoState => b"sso-state",
            AuthorizationPurpose::McpState => b"mcp-state",
            AuthorizationPurpose::RunAssertion => b"run-assertion",
        };
        let (deployment, tenant) = binding.scope();
        // Descriptor decoding bounds deployment/tenant to u16 lengths.
        let length = |bytes: &[u8]| {
            u16::try_from(bytes.len())
                .expect("decoded ID fits u16")
                .to_be_bytes()
        };
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&epoch), parent)
            .expand_multi_info(
                &[
                    b"wrokbot.restore.authorization.v1",
                    &1u16.to_be_bytes(),
                    &length(label),
                    label,
                    &length(deployment.as_bytes()),
                    deployment.as_bytes(),
                    &length(tenant.as_bytes()),
                    tenant.as_bytes(),
                ],
                &mut key[..],
            )
            .expect("HKDF-SHA256 expands 32 bytes");
        Ok(openbot_domain::vault::SecretBytes::new(key.to_vec()))
    }
}

impl Drop for RecoveryRuntimeOwner {
    fn drop(&mut self) {
        // Loss of this handle only closes its read gate. The original control
        // owner retains the actual runtime SH and enrollment until the future
        // original stop/ACK/wait/join adapter supplies a real durable receipt.
        // This is not a close fact and never writes, waits, aborts or replays.
        self.handle_alive.store(false, Ordering::SeqCst);
    }
}

// Local codec writers: no maps, intermediate JSON Values or automatically
// growing payload buffers. The count pass opens no resource and emits nothing.
struct Count {
    used: usize,
    cap: usize,
}
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WriteZero))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct FixedBytes {
    bytes: Vec<u8>,
    cap: usize,
}
impl Write for FixedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WriteZero))?;
        if end > self.bytes.capacity() {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn enqueue_enrollment(
    files: &mut ControlFiles,
    root: RecoveryFileIdentity,
    admission: RecoveryFileIdentity,
    runtime: RecoveryFileIdentity,
    deadline: Instant,
) -> Result<(), RecoveryControlError> {
    let fixed = std::mem::size_of::<Enrollment<'_>>()
        .checked_add(std::mem::size_of::<Count>())
        .and_then(|n| n.checked_add(std::mem::size_of::<FixedBytes>()))
        .and_then(|n| n.checked_add(2 * std::mem::size_of::<serde_json::Serializer<Count>>()))
        .and_then(|n| n.checked_add(2 * std::mem::size_of::<serde_json::Serializer<FixedBytes>>()))
        .and_then(|n| n.checked_add(4 * std::mem::size_of::<Result<(), serde_json::Error>>()))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    files.prepay(fixed as u64, 0)?;
    files.verify_pending_enrollment_before(deadline)?;
    let cap = usize::try_from(files.limits.max_runtime_record_bytes)
        .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    let mut count = Count { used: 0, cap };
    let original = files
        .pending_startup
        .as_ref()
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
    files.raw_encoding = Some(serde_json::to_writer(
        &mut count,
        &enrollment(original, root, admission, runtime),
    ));
    files.post(deadline)?;
    match files.raw_encoding.as_ref() {
        Some(Ok(())) => (),
        _ => {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
    }
    let backing = count
        .used
        .checked_mul(2)
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    files.prepay(backing as u64, 0)?;
    let mut writer = FixedBytes {
        bytes: Vec::new(),
        cap: count.used,
    };
    writer
        .bytes
        .try_reserve_exact(count.used)
        .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    if writer.bytes.capacity() > backing {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::CapacityExceeded,
        ));
    }
    let original = files
        .pending_startup
        .as_ref()
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
    files.raw_encoding = Some(serde_json::to_writer(
        &mut writer,
        &enrollment(original, root, admission, runtime),
    ));
    files.runtime_input = writer.bytes;
    files.post(deadline)?;
    if !matches!(files.raw_encoding.as_ref(), Some(Ok(())))
        || files.runtime_input.len() != count.used
    {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::ControlInvalid,
        ));
    }
    Ok(())
}

pub(super) fn enter_runtime(
    control: &ControlOwner,
    intent: RuntimeEntry,
    deadline: Instant,
) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
    let mut registration_effect_may_have_started = false;
    let result = (|| {
        let mut files = entry::lock(control)?;
        // The caller's branch already holds admission and runtime: SH from a
        // shared-lock head read, or the writer's admissionEX and downgraded SH.
        let writer = files.holds_writer();
        if files.retained_runtime.is_some()
            || files.pending_startup.is_some()
            || !(writer || files.holds_existing_read_locks())
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
        }
        let known = std::mem::size_of::<RuntimeState>()
            .checked_add(std::mem::size_of::<Mutex<Option<RuntimeState>>>())
            .and_then(|n| n.checked_add(std::mem::size_of::<RuntimeAccess>()))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<
                    Result<RuntimeAccess, RecoveryControlError>,
                >())
            })
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()))
            .and_then(|n| n.checked_add(2 * std::mem::align_of::<RuntimeState>()))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<[u8; 64]>() + std::mem::size_of::<[u8; 32]>())
            })
            .and_then(|n| n.checked_add(3 * std::mem::size_of::<RecoveryFileIdentity>()))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<
                    Result<RecoveryRuntimeOwner, RecoveryControlError>,
                >())
            })
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let alive_layout = std::alloc::Layout::new::<[AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<AtomicBool>())
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?
            .0
            .pad_to_align()
            .size();
        let known = known
            .checked_add(alive_layout)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        files.prepay(known as u64, 0)?;
        let deadline = deadline.min(intent.original_deadline);
        before(deadline)?;
        if !intent.runtime_nonce.is_empty() {
            hex(&intent.runtime_nonce, 32, true)?;
        }
        id(&intent.enrollment.boot_identity, files.limits.max_id_bytes)?;
        files.verify_enrollment_before(&intent.enrollment, deadline)?;
        if intent.enrollment.pid != std::process::id()
            || intent.enrollment.process_start.nanos >= 1_000_000_000
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        }
        files.pending_startup = Some(intent);
        let admission_identity = files.held_lock_identity(true, deadline)?;
        // This is the original short registration writer, not a new lock or
        // restore session. Never wait for it while holding either SH.
        if !writer {
            files.pending_owner = Some(files.acquire(
                "owner.lock",
                b"WBRCOWN1",
                FlockOperation::NonBlockingLockExclusive,
                deadline,
            )?);
        }
        if files
            .pending_startup
            .as_ref()
            .is_some_and(|original| original.runtime_nonce.is_empty())
        {
            files.fill_runtime_nonce(deadline)?;
        }
        files.verify_registration_capacity(deadline)?;
        let root = files.root_identity(deadline)?;
        let original = files
            .pending_startup
            .as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        if root != original.control_root {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        // Borrowed digest remains in the original intent throughout IO.
        let expected = original.published.digest().as_bytes();
        let mut fixed_digest = [0u8; 64];
        fixed_digest.copy_from_slice(expected);
        let expected = std::str::from_utf8(&fixed_digest)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        files.verify_head_digest(expected, deadline)?;
        let runtime_identity = files.held_lock_identity(false, deadline)?;
        enqueue_enrollment(
            &mut files,
            root,
            admission_identity,
            runtime_identity,
            deadline,
        )?;
        let nonce = files
            .pending_startup
            .as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?
            .runtime_nonce
            .as_bytes();
        let mut fixed_nonce = [0u8; 32];
        fixed_nonce.copy_from_slice(nonce);
        let nonce = std::str::from_utf8(&fixed_nonce)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        registration_effect_may_have_started = true;
        files.create_runtime_directory(nonce, deadline)?;
        let input = std::mem::take(&mut files.runtime_input);
        // Keep the original input resident even when the publication fails.
        let publication = files.publish_runtime_record("enrollment-v1", &input, deadline);
        files.runtime_input = input;
        publication?;
        files.verify_head_digest(expected, deadline)?;
        files.post(deadline)?;
        let runtime_lock = files
            .pending_runtime
            .take()
            .expect("actual runtime SH remains resident");
        let runtime_directory = files
            .runtime_work
            .take()
            .expect("actual runtime directory remains resident");
        let enrollment_file = files
            .runtime_record
            .take()
            .expect("actual durable enrollment remains resident");
        let original = files
            .pending_startup
            .take()
            .expect("original startup seal remains resident");
        let handle_alive = Arc::new(AtomicBool::new(true));
        let owner = RecoveryRuntimeOwner {
            handle_alive: Arc::clone(&handle_alive),
            state: Arc::new(Mutex::new(Some(RuntimeState {
                control: Arc::clone(control),
                runtime_lock,
                runtime_directory,
                enrollment_file,
                original,
                root,
                runtime_identity,
                handle_alive,
                close_resources: None,
            }))),
        };
        // Intentional same-owner failure retention, not a global registry or
        // another runtime. Only the original true close adapter may retire it.
        files.retained_runtime = Some(Arc::clone(&owner.state));
        files.pending_owner = None;
        files.pending_admission = None;
        files.existing_read_locks_retired();
        Ok(owner)
    })();
    result.map_err(|error: RecoveryControlError| {
        if let Ok(mut files) = entry::lock(control) {
            if !registration_effect_may_have_started
                && files.retained_runtime.is_none()
                && error.fault() == RecoveryControlFault::OwnerBusy
            {
                files.release_registration_attempt();
            }
            if error.fault() != RecoveryControlFault::OwnerBusy {
                files.latch(error.fault());
            }
        }
        error.retain(control)
    })
}

fn unavailable(_: RecoveryControlError) -> HostRequestBindingError {
    HostRequestBindingError::Unavailable
}

/// One short admission SH on the runtime's control and the weak runtime
/// observation; request and worker leases both hold exactly this.
struct AdmissionHold {
    runtime: Weak<Mutex<Option<RuntimeState>>>,
    cohort: Option<RestoreCohortRef>,
    original_lock: Option<File>,
    control: ControlOwner,
    header_reservation: u64,
    retire_known: bool,
}

struct Admission<'a> {
    hold: AdmissionHold,
    original_binding: &'a VerifiedHostRequestBinding,
    original_auth: &'a AuthContext,
    deadline: Instant,
    purpose: RecoveryAdmissionPurpose,
}

impl Drop for AdmissionHold {
    fn drop(&mut self) {
        // This releases only the short admission File, never a runtime SH or
        // a Native/PG/task owner. It produces no close/Current receipt.
        drop(self.original_lock.take());
        if self.retire_known {
            entry::retire_ordinary_lease(&self.control, self.header_reservation);
        }
    }
}

impl RecoveryAdmissionWitness for Admission<'_> {
    fn purpose(&self) -> RecoveryAdmissionPurpose {
        self.purpose
    }

    fn verify_current_before(
        &self,
        binding: &VerifiedHostRequestBinding,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        if deadline > self.deadline
            || !same_request(self.original_binding, self.original_auth, binding, auth)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.hold.verify_runtime_before(deadline)
    }

    fn restore_cohort(&self) -> Option<RestoreCohortRef> {
        self.hold.cohort
    }
}

impl AdmissionHold {
    /// Take the admission SH under the live runtime's control, or keep the
    /// known busy FD resident; nothing here crosses an await.
    fn acquire(
        state: &Weak<Mutex<Option<RuntimeState>>>,
        reservation: u64,
        deadline: Instant,
    ) -> Result<Self, HostRequestBindingError> {
        let (hold, acquired) = {
            let runtime = state.upgrade().ok_or(HostRequestBindingError::NotCurrent)?;
            let runtime_state = lock_runtime(&runtime).map_err(unavailable)?;
            if !runtime_state.handle_alive.load(Ordering::SeqCst) {
                return Err(HostRequestBindingError::NotCurrent);
            }
            let mut files = entry::lock(&runtime_state.control).map_err(unavailable)?;
            files.prepay(reservation, 0).map_err(unavailable)?;
            let mut hold = AdmissionHold {
                runtime: state.clone(),
                cohort: runtime_state.original.published.restore_cohort(),
                original_lock: None,
                control: Arc::clone(&runtime_state.control),
                header_reservation: reservation,
                retire_known: false,
            };
            let acquired = match files.acquire(
                "admission.lock",
                b"WBRCADM1",
                FlockOperation::NonBlockingLockShared,
                deadline,
            ) {
                Ok(file) => {
                    hold.original_lock = Some(file);
                    hold.retire_known = true;
                    Ok(())
                }
                Err(error) => {
                    if error.fault() == RecoveryControlFault::OwnerBusy {
                        if let Some(file) = files.take_known_busy_admission() {
                            hold.original_lock = Some(file);
                            hold.retire_known = true;
                        } else {
                            files.latch(RecoveryControlFault::OwnerLost);
                        }
                    } else {
                        // The raw FD/result and its charge remain resident;
                        // do not let a later attempt overwrite an unknown IO.
                        files.latch(error.fault());
                    }
                    Err(error)
                }
            };
            (hold, acquired)
        };
        // The original control guard is gone before either this error or a
        // later await can drop the hold and retire a known attempt.
        acquired.map_err(unavailable)?;
        Ok(hold)
    }

    fn verify_runtime_before(&self, deadline: Instant) -> Result<(), HostRequestBindingError> {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let state = lock_runtime(&runtime).map_err(unavailable)?;
        if !state.handle_alive.load(Ordering::SeqCst) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let mut files = entry::lock(&state.control).map_err(unavailable)?;
        files
            .verify_enrollment_before(&state.original.enrollment, deadline)
            .map_err(unavailable)?;
        before(deadline).map_err(unavailable)?;
        if files.root_identity(deadline).map_err(unavailable)? != state.root {
            return Err(HostRequestBindingError::NotCurrent);
        }
        files
            .verify_head_digest(state.original.published.digest(), deadline)
            .map_err(unavailable)?;
        let admission = self
            .original_lock
            .as_ref()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        files
            .verify_held_lock(admission, "admission.lock", deadline)
            .map_err(unavailable)?;
        if files
            .verify_held_lock(&state.runtime_lock, "runtime.lock", deadline)
            .map_err(unavailable)?
            != state.runtime_identity
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        files
            .verify_runtime_enrollment(
                &state.runtime_directory,
                &state.original.runtime_nonce,
                &state.enrollment_file,
                deadline,
            )
            .map_err(unavailable)?;
        if !state.handle_alive.load(Ordering::SeqCst) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        files.post(deadline).map_err(unavailable)
    }
}

/// Lock-free lease for the outside-domain source: it rechecks only the same
/// binding, auth context and deadline.
struct OutsideAdmission<'a> {
    original_binding: &'a VerifiedHostRequestBinding,
    original_auth: &'a AuthContext,
    deadline: Instant,
}

impl RecoveryAdmissionWitness for OutsideAdmission<'_> {
    fn purpose(&self) -> RecoveryAdmissionPurpose {
        RecoveryAdmissionPurpose::Normal
    }

    fn verify_current_before(
        &self,
        binding: &VerifiedHostRequestBinding,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        if deadline > self.deadline
            || Instant::now() >= deadline
            || !same_request(self.original_binding, self.original_auth, binding, auth)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(())
    }

    fn restore_cohort(&self) -> Option<RestoreCohortRef> {
        None
    }
}

fn same_request(
    original_binding: &VerifiedHostRequestBinding,
    original_auth: &AuthContext,
    binding: &VerifiedHostRequestBinding,
    auth: &AuthContext,
) -> bool {
    original_binding.identity().same_binding(binding.identity())
        && original_auth.deployment() == auth.deployment()
        && original_auth.tenant() == auth.tenant()
        && original_auth.actor() == auth.actor()
        && original_auth.roles() == auth.roles()
        && original_auth.auth_generation() == auth.auth_generation()
        && original_auth.is_single_user() == auth.is_single_user()
        && auth
            .request_binding()
            .is_some_and(|b| binding.identity().same_binding(b.identity()))
}

impl RecoveryReadGate {
    /// Same actual retained Pool and namespace, before installing an original
    /// host guard. Both sources compare the pool and the deployment/tenant scope.
    pub fn matches_server_scope(
        &self,
        pool: &crate::db::pool::DatabasePool,
        deployment: &str,
        tenant: &str,
    ) -> bool {
        match &self.source {
            GateSource::OutsideRecoveryDomain(scope) => {
                std::ptr::eq(scope.pool.manager(), pool.manager())
                    && scope.deployment.as_str() == deployment
                    && scope.tenant.as_str() == tenant
            }
            GateSource::Runtime(state) => {
                let Some(runtime) = state.upgrade() else {
                    return false;
                };
                let Ok(state) = lock_runtime(&runtime) else {
                    return false;
                };
                if !state.handle_alive.load(Ordering::SeqCst) {
                    return false;
                }
                let Ok(files) = entry::lock(&state.control) else {
                    return false;
                };
                files.existing_scope(pool, deployment, tenant)
            }
        }
    }

    /// Match the original pool already bound by this admission source.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn matches_pool(&self, pool: &crate::db::pool::DatabasePool) -> bool {
        if pool.is_closed() {
            return false;
        }
        match &self.source {
            GateSource::OutsideRecoveryDomain(scope) => {
                std::ptr::eq(scope.pool.manager(), pool.manager())
            }
            GateSource::Runtime(runtime) => {
                let Some(runtime) = runtime.upgrade() else {
                    return false;
                };
                let Ok(state) = lock_runtime(&runtime) else {
                    return false;
                };
                if !state.handle_alive.load(Ordering::SeqCst) {
                    return false;
                }
                let Ok(files) = entry::lock(&state.control) else {
                    return false;
                };
                files.matches_bound_pool(pool)
            }
        }
    }

    pub async fn borrow_before<'a>(
        &'a self,
        binding: &'a VerifiedHostRequestBinding,
        auth: &'a AuthContext,
        deadline: Instant,
    ) -> Result<RecoveryAdmissionLease<'a>, HostRequestBindingError> {
        self.borrow_with_purpose_before(binding, auth, deadline, RecoveryAdmissionPurpose::Normal)
            .await
    }

    /// Borrow the current restored cohort solely for a fresh named confirmation request.
    /// The actual host and final requirement owner must still be verified by its producer.
    pub async fn borrow_reconfirmation_before<'a>(
        &'a self,
        binding: &'a VerifiedHostRequestBinding,
        auth: &'a AuthContext,
        deadline: Instant,
    ) -> Result<RecoveryAdmissionLease<'a>, HostRequestBindingError> {
        self.borrow_with_purpose_before(
            binding,
            auth,
            deadline,
            RecoveryAdmissionPurpose::Reconfirmation,
        )
        .await
    }

    async fn borrow_with_purpose_before<'a>(
        &'a self,
        binding: &'a VerifiedHostRequestBinding,
        auth: &'a AuthContext,
        deadline: Instant,
        purpose: RecoveryAdmissionPurpose,
    ) -> Result<RecoveryAdmissionLease<'a>, HostRequestBindingError> {
        let state = match &self.source {
            GateSource::Runtime(state) => state,
            GateSource::OutsideRecoveryDomain(scope) => {
                if purpose == RecoveryAdmissionPurpose::Reconfirmation {
                    return Err(HostRequestBindingError::Unavailable);
                }
                if auth.deployment() != &scope.deployment || auth.tenant() != &scope.tenant {
                    return Err(HostRequestBindingError::NotCurrent);
                }
                binding.verify_current_before(auth, deadline).await?;
                let lease = OutsideAdmission {
                    original_binding: binding,
                    original_auth: auth,
                    deadline,
                };
                lease.verify_current_before(binding, auth, deadline)?;
                return Ok(Box::new(lease));
            }
        };
        binding.verify_current_before(auth, deadline).await?;
        let reservation = std::mem::size_of::<Admission<'_>>()
            .checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<RecoveryAdmissionLease<'_>>()))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<
                    Result<RecoveryAdmissionLease<'_>, HostRequestBindingError>,
                >())
            })
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<(
                    Admission<'_>,
                    Result<(), RecoveryControlError>,
                )>())
            })
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<File, RecoveryControlError>>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<File>>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<File>()))
            .ok_or(HostRequestBindingError::Unavailable)? as u64;
        let hold = AdmissionHold::acquire(state, reservation, deadline)?;
        if purpose == RecoveryAdmissionPurpose::Reconfirmation && hold.cohort.is_none() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let lease = Admission {
            hold,
            original_binding: binding,
            original_auth: auth,
            deadline,
            purpose,
        };
        lease.verify_current_before(binding, auth, deadline)?;
        // No upgraded runtime Arc or MutexGuard crosses either original await.
        binding.verify_current_before(auth, deadline).await?;
        lease.verify_current_before(binding, auth, deadline)?;
        Ok(Box::new(lease))
    }
}

/// Admission held by a consumer without an AuthContext (MCP callback, token
/// refresh, revocation/reconciliation and artifact body-read workers).
pub(crate) struct RecoveryWorkerLease<'a> {
    hold: Option<AdmissionHold>,
    deadline: Instant,
    _gate: std::marker::PhantomData<&'a RecoveryReadGate>,
}

fn worker_fault(error: HostRequestBindingError) -> RecoveryControlError {
    RecoveryControlError::new(match error {
        HostRequestBindingError::NotCurrent => RecoveryControlFault::OwnerLost,
        _ => RecoveryControlFault::ControlInvalid,
    })
}

impl RecoveryReadGate {
    /// The same admission SH and runtime observation as a request lease; the
    /// outside-domain source returns a lease that holds no lock.
    /// The lease owns its admission lock and only a `Weak` runtime observation,
    /// so it never extends the runtime owner and may live in an owned permit.
    pub(crate) async fn borrow_worker_before(
        &self,
        deadline: Instant,
    ) -> Result<RecoveryWorkerLease<'static>, RecoveryControlError> {
        let hold = match &self.source {
            GateSource::OutsideRecoveryDomain(_) => None,
            GateSource::Runtime(state) => {
                let reservation = std::mem::size_of::<RecoveryWorkerLease<'_>>()
                    .checked_mul(2)
                    .and_then(|n| {
                        n.checked_add(std::mem::size_of::<Result<File, RecoveryControlError>>())
                    })
                    .and_then(|n| n.checked_add(std::mem::size_of::<File>()))
                    .ok_or_else(|| {
                        RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                    })? as u64;
                Some(AdmissionHold::acquire(state, reservation, deadline).map_err(worker_fault)?)
            }
        };
        let lease = RecoveryWorkerLease {
            hold,
            deadline,
            _gate: std::marker::PhantomData,
        };
        lease.verify_current_before(deadline)?;
        Ok(lease)
    }
}

impl RecoveryWorkerLease<'_> {
    /// The original deadline this lease was borrowed with.
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// The cohort frozen at borrow; none outside the recovery domain.
    pub(crate) fn restore_cohort(&self) -> Option<RestoreCohortRef> {
        self.hold.as_ref().and_then(|hold| hold.cohort)
    }

    pub(crate) fn verify_current_before(
        &self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        if deadline > self.deadline || Instant::now() >= deadline {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        match &self.hold {
            None => Ok(()),
            Some(hold) => hold.verify_runtime_before(deadline).map_err(worker_fault),
        }
    }
}
