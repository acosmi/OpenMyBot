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
use serde::Serialize;

use super::activation::ActivationBinding;
use super::entry::{self, ControlFiles, ControlOwner, OwnedRecord, VerifiedOrdinaryStartupIntent};
use super::journal::ProcessStart;
use super::{
    RecoveryControlError, RecoveryControlFault, RecoveryFileIdentity, before, hex, hex_array, id,
};
use std::ops::{Deref, DerefMut};

/// Private original startup input, not a parser, public constructor or proof
/// inferred from a caller's process identifiers. The actual host producer owns
/// the enclosing VerifiedOrdinaryStartupIntent.
pub(super) struct OriginalRuntimeEnrollment {
    pub(super) boot_identity: String,
    pub(super) pid: u32,
    pub(super) process_start: ProcessStart,
    pub(super) resource_model: ResourceModel,
    pub(super) original_owner_set: Vec<String>,
}

#[derive(Clone, Copy, Serialize)]
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
    original_owner_set: &'a [String],
}

fn enrollment<'a>(
    original: &'a VerifiedOrdinaryStartupIntent,
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
    original: VerifiedOrdinaryStartupIntent,
    root: RecoveryFileIdentity,
    runtime_identity: RecoveryFileIdentity,
    handle_alive: Arc<AtomicBool>,
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
    #[must_use]
    pub fn read_gate(&self) -> RecoveryReadGate {
        RecoveryReadGate {
            source: GateSource::Runtime(Arc::downgrade(&self.state)),
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
    intent: VerifiedOrdinaryStartupIntent,
    deadline: Instant,
) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
    let mut registration_effect_may_have_started = false;
    let result = (|| {
        let mut files = entry::lock(control)?;
        let existing_read_locks = files.holds_existing_read_locks();
        if files.retained_runtime.is_some()
            || files.pending_startup.is_some()
            || (!existing_read_locks
                && (files.pending_admission.is_some() || files.pending_runtime.is_some()))
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
            || intent.enrollment.original_owner_set.is_empty()
            || u64::try_from(intent.enrollment.original_owner_set.len())
                .map_or(true, |n| n > files.limits.max_runtime_resource_facts)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        }
        for (i, original) in intent.enrollment.original_owner_set.iter().enumerate() {
            id(original, files.limits.max_id_bytes)?;
            if intent.enrollment.original_owner_set[..i].contains(original) {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EntryInvalid,
                ));
            }
        }
        files.pending_startup = Some(intent);
        if !existing_read_locks {
            let admission = files.acquire(
                "admission.lock",
                b"WBRCADM1",
                FlockOperation::NonBlockingLockShared,
                deadline,
            )?;
            files.pending_admission = Some(admission);
        }
        let admission_identity = files.held_lock_identity(true, deadline)?;
        if !existing_read_locks {
            let runtime = match files.acquire(
                "runtime.lock",
                b"WBRCRUN1",
                FlockOperation::NonBlockingLockShared,
                deadline,
            ) {
                Ok(file) => file,
                Err(error) => {
                    files.pending_admission = None;
                    return Err(error);
                }
            };
            files.pending_runtime = Some(runtime);
        }
        // This is the original short registration writer, not a new lock or
        // restore session. Never wait for it while holding either SH.
        files.pending_owner = Some(files.acquire(
            "owner.lock",
            b"WBRCOWN1",
            FlockOperation::NonBlockingLockExclusive,
            deadline,
        )?);
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
            }))),
        };
        // Intentional same-owner failure retention, not a global registry or
        // another runtime. Only the original true close adapter may retire it.
        files.retained_runtime = Some(Arc::clone(&owner.state));
        files.pending_owner = None;
        files.pending_admission = None;
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
        RecoveryAdmissionPurpose::Normal
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

    pub async fn borrow_before<'a>(
        &'a self,
        binding: &'a VerifiedHostRequestBinding,
        auth: &'a AuthContext,
        deadline: Instant,
    ) -> Result<RecoveryAdmissionLease<'a>, HostRequestBindingError> {
        let state = match &self.source {
            GateSource::Runtime(state) => state,
            GateSource::OutsideRecoveryDomain(scope) => {
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
        let lease = Admission {
            hold,
            original_binding: binding,
            original_auth: auth,
            deadline,
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
