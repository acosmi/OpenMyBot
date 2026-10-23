//! Original runtime SH ownership and short held admission.
//!
//! No parsed DATA, missing head, dropped File, PID observation or Weak expiry
//! becomes a runtime-close receipt. The actual close adapters are supplied by
//! the separately registered original resource-consumer hunks.

use std::fs::File;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use openbot_contracts::auth::AuthContext;
use openbot_contracts::recovery::{
    RecoveryAdmissionLease, RecoveryAdmissionPurpose, RecoveryAdmissionWitness,
};
use openbot_contracts::request_binding::{HostRequestBindingError, VerifiedHostRequestBinding};
use rustix::fs::FlockOperation;
use serde::Serialize;

use super::activation::{ActivationBinding, PublishedActivation};
use super::entry::{self, ControlFiles, ControlOwner, OwnedRecord, VerifiedOrdinaryStartupIntent};
use std::ops::{Deref, DerefMut};
use super::journal::ProcessStart;
use super::{RecoveryControlError, RecoveryControlFault, RecoveryFileIdentity, before, hex, id};

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
pub(super) enum ResourceModel { Local, Server }

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
    original: &'a VerifiedOrdinaryStartupIntent, root: RecoveryFileIdentity,
    admission: RecoveryFileIdentity, runtime: RecoveryFileIdentity,
) -> Enrollment<'a> {
    Enrollment {
        record_type: "wrokbot-runtime-enrollment", version: 1,
        control_id: original.published.control_id(), nonce: &original.runtime_nonce,
        boot_identity: &original.enrollment.boot_identity, pid: original.enrollment.pid,
        process_start: &original.enrollment.process_start,
        activation_digest: original.published.digest(),
        authorization_epoch: original.published.binding().authorization_epoch(),
        business_install_binding: original.published.binding(),
        root_and_lock_identities: RootAndLockIdentities { control_root: root, admission_lock: admission, runtime_lock: runtime },
        resource_model: original.enrollment.resource_model,
        original_owner_set: &original.enrollment.original_owner_set,
    }
}

/// The actual SH and the original enrollment FD have a single strong owner.
/// A read gate only holds Weak. There is intentionally no Clone or Drop close.
pub struct RecoveryRuntimeOwner { state: RuntimeOwnerBook, handle_alive: Arc<AtomicBool> }

pub(super) struct RuntimeState {
    control: ControlOwner,
    runtime_lock: File,
    runtime_directory: File,
    enrollment_file: OwnedRecord,
    original: VerifiedOrdinaryStartupIntent,
    root: RecoveryFileIdentity,
    runtime_identity: RecoveryFileIdentity,
    handle_alive: Arc<AtomicBool>,
    #[cfg(feature = "server-runtime")]
    authorization_derivation: Option<AuthorizationDerivation>,
}

pub(super) type RuntimeOwnerBook = Arc<Mutex<Option<RuntimeState>>>;

/// The same original state is checked out for IO, without a bookkeeping
/// guard. All actual SH/enrollment/control/live-observer owners stay resident.
struct RuntimeAccess { owner: RuntimeOwnerBook, state: Option<RuntimeState> }
impl Deref for RuntimeAccess {
    type Target = RuntimeState;
    fn deref(&self) -> &RuntimeState { self.state.as_ref().expect("original runtime access") }
}
impl DerefMut for RuntimeAccess {
    fn deref_mut(&mut self) -> &mut RuntimeState { self.state.as_mut().expect("original runtime access") }
}
impl Drop for RuntimeAccess {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else { return; };
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
    let mut access = RuntimeAccess { owner: Arc::clone(owner), state: None };
    let mut book = owner.lock().map_err(|poisoned| {
        let book = poisoned.into_inner();
        if let Some(state) = book.as_ref() { state.handle_alive.store(false, Ordering::SeqCst); }
        RecoveryControlError::new(RecoveryControlFault::OwnerLost)
    })?;
    access.state = Some(book.take().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerBusy))?);
    drop(book);
    Ok(access)
}

/// Clone only the original owner's weak observation, never its runtime lease.
#[derive(Clone)]
pub struct RecoveryReadGate { state: Weak<Mutex<Option<RuntimeState>>> }

impl RecoveryRuntimeOwner {
    #[must_use]
    pub fn read_gate(&self) -> RecoveryReadGate { RecoveryReadGate { state: Arc::downgrade(&self.state) } }
}


/// Startup-only, domain-separated keys from one original verified runtime.
/// Fields are private; there is no constructor, Clone, Serde or epoch override.
#[cfg(feature = "server-runtime")]
pub struct ServerRuntimeAuthorizationKeys {
    keys: [Option<openbot_domain::vault::SecretBytes>; 5],
}
#[cfg(feature = "server-runtime")]
impl ServerRuntimeAuthorizationKeys {
    fn login_key(&self, index: usize) -> Result<&[u8], RecoveryControlError> {
        self.keys[index].as_ref().map(openbot_domain::vault::SecretBytes::expose)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::InitializationRequired))
    }
    /// Borrow the same session key for the original issuer and resolver.
    pub fn session_key(&self) -> Result<&[u8], RecoveryControlError> { self.login_key(0) }
    /// Borrow only the original OIDC attempt-store key.
    pub fn oidc_state_key(&self) -> Result<&[u8], RecoveryControlError> { self.login_key(1) }
    /// Borrow the original shared SSO route/SAML/dynamic-OIDC state key.
    pub fn sso_state_key(&self) -> Result<&[u8], RecoveryControlError> { self.login_key(2) }
    /// Borrow the MCP state key; this never replaces its persistent parent.
    #[must_use]
    pub fn mcp_state_key(&self) -> &[u8] {
        self.keys[3].as_ref().expect("successful original MCP derivation").expose()
    }
    /// Borrow the key for the unchanged remote assertion signer and verifier.
    #[must_use]
    pub fn run_assertion_key(&self) -> &[u8] {
        self.keys[4].as_ref().expect("successful original assertion derivation").expose()
    }
}

#[cfg(feature = "server-runtime")]
struct AuthorizationDerivation {
    keys: [Option<openbot_domain::vault::SecretBytes>; 5],
    raw_expand: [Option<Result<(), hkdf::InvalidLength>>; 5],
    raw_allocation: [Option<Result<(), std::collections::TryReserveError>>; 5],
    scratch: zeroize::Zeroizing<[u8; 32]>,
    backing: zeroize::Zeroizing<Vec<u8>>,
    admission: Option<File>,
    handed_off: bool,
}
#[cfg(feature = "server-runtime")]
impl AuthorizationDerivation {
    fn empty() -> Self {
        Self { keys: std::array::from_fn(|_| None), raw_expand: std::array::from_fn(|_| None),
            raw_allocation: std::array::from_fn(|_| None), scratch: zeroize::Zeroizing::new([0; 32]),
            backing: zeroize::Zeroizing::new(Vec::new()), admission: None, handed_off: false }
    }
}

#[cfg(feature = "server-runtime")]
fn verify_key_owner_before(
    state: &RuntimeState, files: &mut ControlFiles, deadline: Instant,
) -> Result<(), RecoveryControlError> {
    if !state.handle_alive.load(Ordering::SeqCst) {
        return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
    }
    files.verify_enrollment_before(&state.original.enrollment, deadline)?;
    if files.root_identity(deadline)? != state.root {
        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
    }
    files.verify_head_digest(state.original.published.digest(), deadline)?;
    if files.verify_held_lock(&state.runtime_lock, "runtime.lock", deadline)? != state.runtime_identity {
        return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
    }
    files.verify_runtime_enrollment(&state.runtime_directory, &state.original.runtime_nonce,
        &state.enrollment_file, deadline)?;
    if let Some(admission) = state.authorization_derivation.as_ref().and_then(|p| p.admission.as_ref()) {
        files.verify_held_lock(admission, "admission.lock", deadline)?;
    }
    if !state.handle_alive.load(Ordering::SeqCst) {
        return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
    }
    files.post(deadline)
}

#[cfg(feature = "server-runtime")]
impl RecoveryRuntimeOwner {
    /// Derive the five closed authorization purposes once, from this live
    /// owner's actual held head and original parents. No copied epoch grants
    /// this operation. Absence of configured login keeps all login keys absent.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_server_authorization_keys_before(
        &mut self,
        pool: &crate::db::pool::DatabasePool,
        deployment: &str,
        tenant: &str,
        session_parent: Option<&[u8]>,
        mcp_state_parent: &openbot_domain::vault::SecretBytes,
        run_assertion_parent: &[u8],
        deadline: Instant,
    ) -> Result<ServerRuntimeAuthorizationKeys, RecoveryControlError> {
        use zeroize::Zeroize as _;
        let mut state = lock_runtime(&self.state)?;
        let control = Arc::clone(&state.control);
        let result = (|| {
            let mut files = entry::lock(&control)?;
            if state.authorization_derivation.is_some() {
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
            }
            if !files.existing_scope(pool, deployment, tenant) || mcp_state_parent.is_empty()
                || run_assertion_parent.is_empty() || session_parent.is_some_and(<[u8]>::is_empty) {
                return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
            }
            let deployment_len = u16::try_from(deployment.len())
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?.to_be_bytes();
            let tenant_len = u16::try_from(tenant.len())
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?.to_be_bytes();
            let key_count = if session_parent.is_some() { 5usize } else { 2usize };
            // RuntimeState already prepaid its resident Option/packet layout.
            // Charge only the additional return/match/crypto locals and the
            // actual Vec capacity ceiling (64 per 32-byte returned key).
            let known = key_count.checked_mul(64)
                .and_then(|n| n.checked_add(2 * std::mem::size_of::<ServerRuntimeAuthorizationKeys>()))
                .and_then(|n| n.checked_add(2 * std::mem::size_of::<Result<ServerRuntimeAuthorizationKeys, RecoveryControlError>>()))
                .and_then(|n| n.checked_add(2 * std::mem::size_of::<hkdf::Hkdf<sha2::Sha256>>()))
                .and_then(|n| n.checked_add(std::mem::size_of::<[u8; 32]>() + std::mem::size_of::<[&[u8]; 8]>() + 8))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            files.prepay(u64::try_from(known)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?, 0)?;
            verify_key_owner_before(&state, &mut files, deadline)?;
            state.authorization_derivation = Some(AuthorizationDerivation::empty());
            let admission = files.acquire("admission.lock", b"WBRCADM1",
                FlockOperation::NonBlockingLockShared, deadline)?;
            state.authorization_derivation.as_mut().expect("resident original key packet").admission = Some(admission);
            verify_key_owner_before(&state, &mut files, deadline)?;
            let epoch_text = state.original.published.binding().authorization_epoch().as_bytes();
            let mut epoch = [0u8; 32];
            if epoch_text.len() != 64 {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            let nibble = |byte| -> Result<u8, RecoveryControlError> {
                match byte { b'0'..=b'9' => Ok(byte - b'0'), b'a'..=b'f' => Ok(byte - b'a' + 10),
                    _ => Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)) }
            };
            for (index, pair) in epoch_text.chunks_exact(2).enumerate() {
                epoch[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
            }
            const PURPOSES: [&[u8]; 5] = [b"session", b"oidc-state", b"sso-state", b"mcp-state", b"run-assertion"];
            let version = 1u16.to_be_bytes();
            for (index, purpose) in PURPOSES.iter().enumerate() {
                let parent = match index { 0..=2 => match session_parent { Some(key) => key, None => continue },
                    3 => mcp_state_parent.expose(), 4 => run_assertion_parent, _ => unreachable!() };
                let purpose_len = u16::try_from(purpose.len())
                    .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?.to_be_bytes();
                let packet = state.authorization_derivation.as_mut().expect("resident original key packet");
                let kdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&epoch), parent);
                packet.raw_expand[index] = Some(kdf.expand_multi_info(&[
                    b"wrokbot.restore.authorization.v1", &version, &purpose_len, purpose,
                    &deployment_len, deployment.as_bytes(), &tenant_len, tenant.as_bytes(),
                ], &mut packet.scratch[..]));
                files.post(deadline)?;
                if !matches!(packet.raw_expand[index], Some(Ok(()))) {
                    return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
                }
                packet.raw_allocation[index] = Some(packet.backing.try_reserve_exact(32));
                files.post(deadline)?;
                if !matches!(packet.raw_allocation[index], Some(Ok(())))
                    || packet.backing.capacity() < 32 || packet.backing.capacity() > 64 {
                    return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
                }
                packet.backing.extend_from_slice(&packet.scratch[..]);
                packet.keys[index] = Some(openbot_domain::vault::SecretBytes::new(std::mem::take(&mut *packet.backing)));
                packet.scratch.zeroize();
                files.post(deadline)?;
            }
            verify_key_owner_before(&state, &mut files, deadline)?;
            let packet = state.authorization_derivation.as_mut().expect("resident original key packet");
            if packet.handed_off || packet.keys[3].is_none() || packet.keys[4].is_none()
                || (session_parent.is_some() && packet.keys[..3].iter().any(Option::is_none)) {
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
            }
            // This is a known short admission File release, never a runtime
            // close fact. None on error stays with the original packet/owner.
            drop(packet.admission.take());
            entry::retire_ordinary_lease(&control, 0);
            files.post(deadline)?;
            let packet = state.authorization_derivation.as_mut().expect("resident original key packet");
            packet.handed_off = true;
            Ok(ServerRuntimeAuthorizationKeys { keys: std::array::from_fn(|i| packet.keys[i].take()) })
        })();
        result.map_err(|error: RecoveryControlError| error.retain(&control))
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
struct Count { used: usize, cap: usize }
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self.used.checked_add(bytes.len()).filter(|n| *n <= self.cap)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WriteZero))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
struct FixedBytes { bytes: Vec<u8>, cap: usize }
impl Write for FixedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self.bytes.len().checked_add(bytes.len()).filter(|n| *n <= self.cap)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WriteZero))?;
        if end > self.bytes.capacity() { return Err(io::Error::from(io::ErrorKind::WriteZero)); }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn enqueue_enrollment(
    files: &mut ControlFiles, root: RecoveryFileIdentity,
    admission: RecoveryFileIdentity, runtime: RecoveryFileIdentity, deadline: Instant,
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
    let original = files.pending_startup.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
    files.raw_encoding = Some(serde_json::to_writer(&mut count, &enrollment(original, root, admission, runtime)));
    files.post(deadline)?;
    match files.raw_encoding.as_ref() {
        Some(Ok(())) => (),
        _ => return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)),
    }
    let backing = count.used.checked_mul(2).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    files.prepay(backing as u64, 0)?;
    let mut writer = FixedBytes { bytes: Vec::new(), cap: count.used };
    writer.bytes.try_reserve_exact(count.used).map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    if writer.bytes.capacity() > backing { return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)); }
    let original = files.pending_startup.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
    files.raw_encoding = Some(serde_json::to_writer(&mut writer, &enrollment(original, root, admission, runtime)));
    files.runtime_input = writer.bytes;
    files.post(deadline)?;
    if !matches!(files.raw_encoding.as_ref(), Some(Ok(()))) || files.runtime_input.len() != count.used {
        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
    }
    Ok(())
}

pub(super) fn enter_runtime(
    control: &ControlOwner, intent: VerifiedOrdinaryStartupIntent, deadline: Instant,
) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
    let mut registration_effect_may_have_started = false;
    let result = (|| {
        let mut files = entry::lock(control)?;
        let existing_read_locks = files.holds_existing_read_locks();
        if files.retained_runtime.is_some() || files.pending_startup.is_some()
            || (!existing_read_locks && (files.pending_admission.is_some() || files.pending_runtime.is_some()))
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
        }
        let known = std::mem::size_of::<RuntimeState>()
            .checked_add(std::mem::size_of::<Mutex<Option<RuntimeState>>>())
            .and_then(|n| n.checked_add(std::mem::size_of::<RuntimeAccess>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<RuntimeAccess, RecoveryControlError>>()))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()))
            .and_then(|n| n.checked_add(2 * std::mem::align_of::<RuntimeState>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<[u8; 64]>() + std::mem::size_of::<[u8; 32]>() ))
            .and_then(|n| n.checked_add(3 * std::mem::size_of::<RecoveryFileIdentity>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<RecoveryRuntimeOwner, RecoveryControlError>>()))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let alive_layout = std::alloc::Layout::new::<[AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<AtomicBool>())
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?.0.pad_to_align().size();
        let known = known.checked_add(alive_layout)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        files.prepay(known as u64, 0)?;
        let deadline = deadline.min(intent.original_deadline);
        before(deadline)?;
        if !intent.runtime_nonce.is_empty() { hex(&intent.runtime_nonce, 32, true)?; }
        id(&intent.enrollment.boot_identity, files.limits.max_id_bytes)?;
        files.verify_enrollment_before(&intent.enrollment, deadline)?;
        if intent.enrollment.pid != std::process::id() || intent.enrollment.process_start.nanos >= 1_000_000_000
            || intent.enrollment.original_owner_set.is_empty()
            || u64::try_from(intent.enrollment.original_owner_set.len()).map_or(true, |n| n > files.limits.max_runtime_resource_facts)
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
        }
        for (i, original) in intent.enrollment.original_owner_set.iter().enumerate() {
            id(original, files.limits.max_id_bytes)?;
            if intent.enrollment.original_owner_set[..i].contains(original) {
                return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
            }
        }
        files.pending_startup = Some(intent);
        if !existing_read_locks {
            let admission = files.acquire("admission.lock", b"WBRCADM1", FlockOperation::NonBlockingLockShared, deadline)?;
            files.pending_admission = Some(admission);
        }
        let admission_identity = files.held_lock_identity(true, deadline)?;
        if !existing_read_locks {
            let runtime = match files.acquire("runtime.lock", b"WBRCRUN1", FlockOperation::NonBlockingLockShared, deadline) {
                Ok(file) => file,
                Err(error) => { files.pending_admission = None; return Err(error); }
            };
            files.pending_runtime = Some(runtime);
        }
        // This is the original short registration writer, not a new lock or
        // restore session. Never wait for it while holding either SH.
        files.pending_owner = Some(files.acquire("owner.lock", b"WBRCOWN1", FlockOperation::NonBlockingLockExclusive, deadline)?);
        if files.pending_startup.as_ref().is_some_and(|original| original.runtime_nonce.is_empty()) {
            files.fill_runtime_nonce(deadline)?;
        }
        files.verify_registration_capacity(deadline)?;
        let root = files.root_identity(deadline)?;
        let original = files.pending_startup.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        if root != original.control_root { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
        // Borrowed digest remains in the original intent throughout IO.
        let expected = original.published.digest().as_bytes();
        let mut fixed_digest = [0u8; 64]; fixed_digest.copy_from_slice(expected);
        let expected = std::str::from_utf8(&fixed_digest).map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        files.verify_head_digest(expected, deadline)?;
        let runtime_identity = files.held_lock_identity(false, deadline)?;
        enqueue_enrollment(&mut files, root, admission_identity, runtime_identity, deadline)?;
        let nonce = files.pending_startup.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?.runtime_nonce.as_bytes();
        let mut fixed_nonce = [0u8; 32]; fixed_nonce.copy_from_slice(nonce);
        let nonce = std::str::from_utf8(&fixed_nonce).map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        registration_effect_may_have_started = true;
        files.create_runtime_directory(nonce, deadline)?;
        let input = std::mem::take(&mut files.runtime_input);
        // Keep the original input resident even when the publication fails.
        let publication = files.publish_runtime_record("enrollment-v1", &input, deadline);
        files.runtime_input = input;
        publication?;
        files.verify_head_digest(expected, deadline)?;
        files.post(deadline)?;
        let runtime_lock = files.pending_runtime.take().expect("actual runtime SH remains resident");
        let runtime_directory = files.runtime_work.take().expect("actual runtime directory remains resident");
        let enrollment_file = files.runtime_record.take().expect("actual durable enrollment remains resident");
        let original = files.pending_startup.take().expect("original startup seal remains resident");
        let handle_alive = Arc::new(AtomicBool::new(true));
        let owner = RecoveryRuntimeOwner { handle_alive: Arc::clone(&handle_alive), state: Arc::new(Mutex::new(Some(RuntimeState {
            control: Arc::clone(control), runtime_lock, runtime_directory, enrollment_file, original, root, runtime_identity,
            handle_alive,
            #[cfg(feature = "server-runtime")]
            authorization_derivation: None,
        }))) };
        // Intentional same-owner failure retention, not a global registry or
        // another runtime. Only the original true close adapter may retire it.
        files.retained_runtime = Some(Arc::clone(&owner.state));
        files.pending_owner = None;
        files.pending_admission = None;
        Ok(owner)
    })();
    result.map_err(|error: RecoveryControlError| {
        if let Ok(mut files) = entry::lock(control) {
            if !registration_effect_may_have_started && files.retained_runtime.is_none()
                && error.fault() == RecoveryControlFault::OwnerBusy
            {
                files.release_registration_attempt();
            }
            if error.fault() != RecoveryControlFault::OwnerBusy { files.latch(error.fault()); }
        }
        error.retain(control)
    })
}

fn unavailable(_: RecoveryControlError) -> HostRequestBindingError { HostRequestBindingError::Unavailable }

struct Admission<'a> {
    runtime: Weak<Mutex<Option<RuntimeState>>>,
    original_binding: &'a VerifiedHostRequestBinding,
    original_auth: &'a AuthContext,
    deadline: Instant,
    original_lock: Option<File>,
    control: ControlOwner,
    header_reservation: u64,
    retire_known: bool,
}

impl Drop for Admission<'_> {
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
    fn purpose(&self) -> RecoveryAdmissionPurpose { RecoveryAdmissionPurpose::Normal }

    fn verify_current_before(&self, binding: &VerifiedHostRequestBinding, auth: &AuthContext, deadline: Instant) -> Result<(), HostRequestBindingError> {
        if deadline > self.deadline || !self.original_binding.identity().same_binding(binding.identity())
            || self.original_auth.deployment() != auth.deployment() || self.original_auth.tenant() != auth.tenant()
            || self.original_auth.actor() != auth.actor() || self.original_auth.roles() != auth.roles()
            || self.original_auth.auth_generation() != auth.auth_generation() || self.original_auth.is_single_user() != auth.is_single_user()
            || !auth.request_binding().is_some_and(|b| binding.identity().same_binding(b.identity()))
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let runtime = self.runtime.upgrade().ok_or(HostRequestBindingError::NotCurrent)?;
        let state = lock_runtime(&runtime).map_err(unavailable)?;
        if !state.handle_alive.load(Ordering::SeqCst) { return Err(HostRequestBindingError::NotCurrent); }
        let mut files = entry::lock(&state.control).map_err(unavailable)?;
        files.verify_enrollment_before(&state.original.enrollment, deadline).map_err(unavailable)?;
        before(deadline).map_err(unavailable)?;
        if files.root_identity(deadline).map_err(unavailable)? != state.root {
            return Err(HostRequestBindingError::NotCurrent);
        }
        files.verify_head_digest(state.original.published.digest(), deadline).map_err(unavailable)?;
        let admission = self.original_lock.as_ref().ok_or(HostRequestBindingError::NotCurrent)?;
        files.verify_held_lock(admission, "admission.lock", deadline).map_err(unavailable)?;
        if files.verify_held_lock(&state.runtime_lock, "runtime.lock", deadline).map_err(unavailable)? != state.runtime_identity {
            return Err(HostRequestBindingError::NotCurrent);
        }
        files.verify_runtime_enrollment(&state.runtime_directory, &state.original.runtime_nonce, &state.enrollment_file, deadline).map_err(unavailable)?;
        if !state.handle_alive.load(Ordering::SeqCst) { return Err(HostRequestBindingError::NotCurrent); }
        files.post(deadline).map_err(unavailable)
    }
}

impl RecoveryReadGate {
    /// Same actual retained Pool and namespace, before installing an original
    /// host guard. No gate constructor, new runtime or second owner is exposed.
    pub fn matches_server_scope(&self, pool: &crate::db::pool::DatabasePool, deployment: &str, tenant: &str) -> bool {
        let Some(runtime) = self.state.upgrade() else { return false; };
        let Ok(state) = lock_runtime(&runtime) else { return false; };
        if !state.handle_alive.load(Ordering::SeqCst) { return false; }
        let Ok(files) = entry::lock(&state.control) else { return false; };
        files.existing_scope(pool, deployment, tenant)
    }

    pub async fn borrow_before<'a>(&'a self, binding: &'a VerifiedHostRequestBinding, auth: &'a AuthContext, deadline: Instant) -> Result<RecoveryAdmissionLease<'a>, HostRequestBindingError> {
        binding.verify_current_before(auth, deadline).await?;
        let reservation = std::mem::size_of::<Admission<'_>>().checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<RecoveryAdmissionLease<'_>>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<RecoveryAdmissionLease<'_>, HostRequestBindingError>>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<(Admission<'_>, Result<(), RecoveryControlError>)>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<File, RecoveryControlError>>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<File>>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<File>()))
            .ok_or(HostRequestBindingError::Unavailable)? as u64;
        let (lease, acquired) = {
            let runtime = self.state.upgrade().ok_or(HostRequestBindingError::NotCurrent)?;
            let state = lock_runtime(&runtime).map_err(unavailable)?;
            if !state.handle_alive.load(Ordering::SeqCst) { return Err(HostRequestBindingError::NotCurrent); }
            let mut files = entry::lock(&state.control).map_err(unavailable)?;
            files.prepay(reservation, 0).map_err(unavailable)?;
            let mut lease = Admission { runtime: self.state.clone(), original_binding: binding, original_auth: auth, deadline,
                original_lock: None, control: Arc::clone(&state.control), header_reservation: reservation, retire_known: false };
            let acquired = match files.acquire("admission.lock", b"WBRCADM1", FlockOperation::NonBlockingLockShared, deadline) {
                Ok(file) => {
                    lease.original_lock = Some(file);
                    lease.retire_known = true;
                    Ok(())
                }
                Err(error) => {
                    if error.fault() == RecoveryControlFault::OwnerBusy {
                        if let Some(file) = files.take_known_busy_admission() {
                            lease.original_lock = Some(file);
                            lease.retire_known = true;
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
            (lease, acquired)
        };
        // The original control guard is gone before either this error or the
        // later awaits can drop the RAII lease and retire a known attempt.
        acquired.map_err(unavailable)?;
        lease.verify_current_before(binding, auth, deadline)?;
        // No upgraded runtime Arc or MutexGuard crosses either original await.
        binding.verify_current_before(auth, deadline).await?;
        lease.verify_current_before(binding, auth, deadline)?;
        Ok(Box::new(lease))
    }
}
