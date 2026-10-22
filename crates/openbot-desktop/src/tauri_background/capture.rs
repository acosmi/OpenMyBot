//! Same-owner normal-exit capture. Configuration and durable observations are not capabilities.
use std::sync::{Arc, Mutex, Weak};

use openbot_domain::backup::whole_pg_carrier::{WholePgCarrierBounds, WholePgCarrierFault as Fault};
use openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck;
use openbot_infra::db::desktop_local::{
    DesktopCaptureDrivers, OriginalDriverJoinFact, OriginalDriverJoinOutcome,
};
use wrok_bot_macos_process::ProcessIdentity;

use crate::desktop_release::{CaptureProfile, ReviewedNormalCaptureRequest};
use crate::postgres_maintenance::clock::OperationClock;

/// One process/boot and one original E/C clock. No constructor is exposed outside this module.
// Pure counters attached to the one original Armed -> Operation owner. This DATA is neither
// a source capability nor another profile. No successful reservation is ever refunded.
#[derive(Clone, Copy, PartialEq, Eq)]
struct OriginalControlObjectFact {
    device: u64,
    inode: u64,
    allocation: u64,
    retained_prior: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalControlRootObservation {
    Unobserved,
    Absent,
    Present { device: u64, inode: u64 },
}

struct OriginalControlStorageFacts {
    objects: Vec<OriginalControlObjectFact>,
    original_owner: [u8; 16],
    roots: [OriginalControlRootObservation; 4],
    classified: bool,
    max_total_allocation_bytes: u64,
    max_retained_prior_bytes: u64,
    growth_ready: bool,
    allocation_admitted: u64,
    allocation_observed_peak: u64,
    allocation_update_pending: bool,
    object_slots_admitted: usize,
}

impl OriginalControlStorageFacts {
    fn observe(&mut self, device: u64, inode: u64, blocks: u64, retained_prior: u64) -> Result<(), Fault> {
        let fact = OriginalControlObjectFact {
            device,
            inode,
            allocation: blocks.checked_mul(512).ok_or(Fault::BoundsOverflow)?,
            retained_prior,
        };
        if let Some(prior) = self.objects.iter().find(|prior| prior.device == device && prior.inode == inode) {
            return if *prior == fact { Ok(()) } else { Err(Fault::SourceChanged) };
        }
        if self.objects.len() >= self.objects.capacity() {
            return Err(Fault::CapacityExceeded);
        }
        self.objects.push(fact);
        Ok(())
    }
}

pub(crate) struct CaptureResourceTotals {
    owner_instance: [u8; 16],
    max_fds: u64,
    max_metadata: u64,
    fd_admissions: u64,
    metadata_reserved: u64,
    original_control_storage: OriginalControlStorageFacts,
}

pub(super) fn prepare_original_capture_resources(
    bounds: &WholePgCarrierBounds,
) -> Result<Arc<Mutex<CaptureResourceTotals>>, Fault> {
    let bounds = (*bounds).check()?;
    // Pinned Rust 1.98.0 ArcInner is repr(C): two atomic usize headers followed by T.
    // This accounts for its requested layout and the original startup/Armed/Operation Arc
    // words. It does not claim an allocator-internal or whole-operation peak measurement.
    let allocation = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .extend(std::alloc::Layout::new::<Mutex<CaptureResourceTotals>>())
        .map_err(|_| Fault::BoundsOverflow)?
        .0
        .pad_to_align()
        .size();
    let references = core::mem::size_of::<Arc<Mutex<CaptureResourceTotals>>>()
        .checked_mul(3)
        .ok_or(Fault::BoundsOverflow)?;
    let control_fixed = control::original_control_data_fixed_bytes()?;
    let metadata_reserved = u64::try_from(
        allocation.checked_add(references).and_then(|n| n.checked_add(control_fixed))
            .ok_or(Fault::BoundsOverflow)?,
    )
    .map_err(|_| Fault::BoundsOverflow)?;
    if metadata_reserved > bounds.max_metadata_bytes {
        return Err(Fault::CapacityExceeded);
    }
    let owner_instance = fresh_uuid()?;
    Ok(Arc::new(Mutex::new(CaptureResourceTotals {
        owner_instance,
        max_fds: bounds.max_open_files,
        max_metadata: bounds.max_metadata_bytes,
        fd_admissions: 0,
        metadata_reserved,
        original_control_storage: OriginalControlStorageFacts {
            objects: Vec::new(), original_owner: owner_instance,
            roots: [OriginalControlRootObservation::Unobserved; 4], classified: false,
            max_total_allocation_bytes: bounds.max_total_allocation_bytes,
            max_retained_prior_bytes: bounds.max_retained_prior_bytes,
            growth_ready: false, allocation_admitted: 0, allocation_observed_peak: 0,
            allocation_update_pending: false, object_slots_admitted: 0,
        },
    })))
}

fn original_capture_resource_identity(
    resources: &Arc<Mutex<CaptureResourceTotals>>,
    bounds: &WholePgCarrierBounds,
) -> Result<[u8; 16], Fault> {
    let totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
    if totals.owner_instance == [0; 16]
        || totals.max_fds != bounds.max_open_files
        || totals.max_metadata != bounds.max_metadata_bytes
        || totals.original_control_storage.original_owner != totals.owner_instance
        || totals.original_control_storage.max_total_allocation_bytes != bounds.max_total_allocation_bytes
        || totals.original_control_storage.max_retained_prior_bytes != bounds.max_retained_prior_bytes
        || totals.fd_admissions > totals.max_fds
        || totals.metadata_reserved > totals.max_metadata
    {
        return Err(Fault::IntentMismatch);
    }
    Ok(totals.owner_instance)
}

pub(crate) fn reserve_capture_resources(
    resources: &Arc<Mutex<CaptureResourceTotals>>,
    fd_delta: u64,
    metadata_delta: u64,
) -> Result<(), Fault> {
    let mut totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
    if totals.owner_instance == [0; 16] || totals.max_fds == 0 || totals.max_metadata == 0 {
        return Err(Fault::IntentMismatch);
    }
    let fds = totals.fd_admissions.checked_add(fd_delta).ok_or(Fault::BoundsOverflow)?;
    let metadata = totals.metadata_reserved.checked_add(metadata_delta).ok_or(Fault::BoundsOverflow)?;
    if fds > totals.max_fds || metadata > totals.max_metadata {
        return Err(Fault::CapacityExceeded);
    }
    // Both dimensions have passed before either mutation; one component lock always precedes
    // this book lock. No I/O, await, reverse getter, source acquisition or refund here.
    totals.fd_admissions = fds;
    totals.metadata_reserved = metadata;
    Ok(())
}

pub(crate) fn remaining_capture_resources(
    resources: &Arc<Mutex<CaptureResourceTotals>>,
) -> Result<(u64, u64), Fault> {
    let totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
    if totals.owner_instance == [0; 16] || totals.max_fds == 0 || totals.max_metadata == 0 {
        return Err(Fault::IntentMismatch);
    }
    Ok((
        totals.max_fds.checked_sub(totals.fd_admissions).ok_or(Fault::CapacityExceeded)?,
        totals.max_metadata.checked_sub(totals.metadata_reserved).ok_or(Fault::CapacityExceeded)?,
    ))
}

// Pure same-owner DATA staging. The empty book header freezes these limits before IO.
fn prepare_original_control_storage(
    resources: &Arc<Mutex<CaptureResourceTotals>>,
    bounds: &WholePgCarrierBounds,
    maximum: usize,
) -> Result<OriginalControlStorageFacts, Fault> {
    let owner = original_capture_resource_identity(resources, bounds)?;
    let frozen = {
        let totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
        if totals.original_control_storage.classified
            || !totals.original_control_storage.objects.is_empty()
        {
            return Err(Fault::IntentMismatch);
        }
        (totals.original_control_storage.max_total_allocation_bytes,
            totals.original_control_storage.max_retained_prior_bytes)
    };
    let bytes = maximum.checked_mul(core::mem::size_of::<OriginalControlObjectFact>())
        .and_then(|n| u64::try_from(n).ok()).ok_or(Fault::BoundsOverflow)?;
    reserve_capture_resources(resources, 0, bytes)?;
    let mut objects = Vec::new();
    objects.try_reserve_exact(maximum).map_err(|_| Fault::CapacityExceeded)?;
    if objects.capacity() != maximum { return Err(Fault::CapacityExceeded); }
    Ok(OriginalControlStorageFacts {
        objects,
        original_owner: owner,
        roots: [OriginalControlRootObservation::Unobserved; 4],
        classified: false,
        max_total_allocation_bytes: frozen.0,
        max_retained_prior_bytes: frozen.1,
        growth_ready: false, allocation_admitted: 0, allocation_observed_peak: 0,
        allocation_update_pending: false, object_slots_admitted: 0,
    })
}

fn install_original_control_storage(
    resources: &Arc<Mutex<CaptureResourceTotals>>,
    mut facts: OriginalControlStorageFacts,
) -> Result<(), Fault> {
    let mut totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
    let original = &totals.original_control_storage;
    if facts.original_owner != totals.owner_instance || !facts.classified
        || original.classified || !original.objects.is_empty()
        || facts.growth_ready || facts.allocation_update_pending
        || facts.allocation_admitted != 0 || facts.allocation_observed_peak != 0
        || facts.object_slots_admitted != 0
        || facts.max_total_allocation_bytes != original.max_total_allocation_bytes
        || facts.max_retained_prior_bytes != original.max_retained_prior_bytes
        || !matches!(facts.roots[0], OriginalControlRootObservation::Present { .. })
        || !matches!(facts.roots[1], OriginalControlRootObservation::Present { .. } | OriginalControlRootObservation::Absent)
        || !matches!(facts.roots[2], OriginalControlRootObservation::Present { .. })
        || !matches!(facts.roots[3], OriginalControlRootObservation::Present { .. })
    {
        return Err(Fault::IntentMismatch);
    }
    let mut allocation = 0u64;
    let mut retained = 0u64;
    for (index, fact) in facts.objects.iter().enumerate() {
        if facts.objects[..index].iter().any(|prior| prior.device == fact.device && prior.inode == fact.inode) {
            return Err(Fault::IntentMismatch);
        }
        allocation = allocation.checked_add(fact.allocation).ok_or(Fault::BoundsOverflow)?;
        retained = retained.checked_add(fact.retained_prior).ok_or(Fault::BoundsOverflow)?;
    }
    for root in facts.roots {
        if let OriginalControlRootObservation::Present { device, inode } = root {
            if !facts.objects.iter().any(|fact| fact.device == device && fact.inode == inode) {
                return Err(Fault::IntentMismatch);
            }
        }
    }
    if allocation > original.max_total_allocation_bytes || retained > original.max_retained_prior_bytes {
        return Err(Fault::CapacityExceeded);
    }
    facts.allocation_admitted = allocation;
    facts.allocation_observed_peak = allocation;
    facts.object_slots_admitted = facts.objects.len();
    // All actual finite-set checks precede the one whole-Vec move. No IO or grant.
    totals.original_control_storage = facts;
    Ok(())
}

// FS01 is pure DATA on the original book, not an OS reservation or another owner.
fn mark_original_control_growth_after_history(
    resources: &Arc<Mutex<CaptureResourceTotals>>,
    owner_instance: [u8;16],
) -> Result<(), Fault> {
    let mut totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
    if totals.owner_instance != owner_instance || owner_instance == [0;16] {
        return Err(Fault::IntentMismatch);
    }
    let facts = &mut totals.original_control_storage;
    if facts.original_owner != owner_instance || !facts.classified || facts.growth_ready
        || facts.allocation_update_pending || facts.object_slots_admitted != facts.objects.len()
    { return Err(Fault::IntentMismatch); }
    let mut allocation = 0u64;
    for object in &facts.objects {
        allocation = allocation.checked_add(object.allocation).ok_or(Fault::BoundsOverflow)?;
    }
    if allocation != facts.allocation_admitted || allocation != facts.allocation_observed_peak
        || allocation > facts.max_total_allocation_bytes
    { return Err(Fault::SourceChanged); }
    facts.growth_ready = true;
    Ok(())
}

fn reserve_original_control_growth(
    resources: &Arc<Mutex<CaptureResourceTotals>>,
    owner_instance: [u8;16],
    parent_device: u64,
    parent_inode: u64,
    increment_plan: u64,
    new_objects: usize,
) -> Result<u64, Fault> {
    let mut totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
    if totals.owner_instance != owner_instance || owner_instance == [0;16] {
        return Err(Fault::IntentMismatch);
    }
    let facts = &mut totals.original_control_storage;
    if facts.original_owner != owner_instance || !facts.classified || !facts.growth_ready {
        return Err(Fault::IntentMismatch);
    }
    if facts.allocation_update_pending { return Err(Fault::ClosingPending); }
    if increment_plan == 0 || facts.allocation_observed_peak > facts.allocation_admitted
        || !facts.objects.iter().any(|object|
            object.device == parent_device && object.inode == parent_inode)
    { return Err(Fault::SourceChanged); }
    let admitted = facts.allocation_admitted.checked_add(increment_plan)
        .ok_or(Fault::BoundsOverflow)?;
    let slots = facts.object_slots_admitted.checked_add(new_objects)
        .ok_or(Fault::BoundsOverflow)?;
    if admitted > facts.max_total_allocation_bytes || slots > facts.objects.capacity() {
        return Err(Fault::CapacityExceeded);
    }
    // Neither dimension commits unless both have passed. Unknown completion never refunds.
    facts.allocation_admitted = admitted;
    facts.object_slots_admitted = slots;
    facts.allocation_update_pending = true;
    Ok(admitted)
}

fn observe_original_control_allocation(
    resources: &Arc<Mutex<CaptureResourceTotals>>,
    owner_instance: [u8;16],
    observations: [(u64,u64,u64);2],
) -> Result<(), Fault> {
    let mut totals = resources.lock().map_err(|_| Fault::ClosingPending)?;
    if totals.owner_instance != owner_instance || owner_instance == [0;16] {
        return Err(Fault::IntentMismatch);
    }
    let facts = &mut totals.original_control_storage;
    if facts.original_owner != owner_instance || !facts.classified || !facts.growth_ready
        || !facts.allocation_update_pending
    { return Err(Fault::IntentMismatch); }
    let actual = [
        (observations[0].0, observations[0].1,
            observations[0].2.checked_mul(512).ok_or(Fault::BoundsOverflow)?),
        (observations[1].0, observations[1].1,
            observations[1].2.checked_mul(512).ok_or(Fault::BoundsOverflow)?),
    ];
    if actual[0].0 != actual[1].0 || actual.iter().any(|row| row.0 == 0 || row.1 == 0)
        || ((actual[0].0, actual[0].1) == (actual[1].0, actual[1].1) && actual[0].2 != actual[1].2)
    { return Err(Fault::SourceChanged); }
    let mut allocation = 0u64;
    let mut additional = 0usize;
    for object in &facts.objects {
        let amount = actual.iter().find(|row|
            row.0 == object.device && row.1 == object.inode)
            .map_or(object.allocation, |row| row.2);
        allocation = allocation.checked_add(amount).ok_or(Fault::BoundsOverflow)?;
    }
    for index in 0..2 {
        if index == 1 && (actual[0].0, actual[0].1) == (actual[1].0, actual[1].1) { continue; }
        if !facts.objects.iter().any(|object|
            object.device == actual[index].0 && object.inode == actual[index].1)
        {
            additional = additional.checked_add(1).ok_or(Fault::BoundsOverflow)?;
            allocation = allocation.checked_add(actual[index].2).ok_or(Fault::BoundsOverflow)?;
        }
    }
    let length = facts.objects.len().checked_add(additional).ok_or(Fault::BoundsOverflow)?;
    if length > facts.object_slots_admitted || length > facts.objects.capacity() {
        return Err(Fault::CapacityExceeded);
    }
    // Keep the observed breach too; the full pair remains in the original Work on Err.
    facts.allocation_observed_peak = facts.allocation_observed_peak.max(allocation);
    if facts.allocation_observed_peak > facts.max_total_allocation_bytes {
        return Err(Fault::CapacityExceeded);
    }
    let admitted = facts.allocation_admitted.max(facts.allocation_observed_peak);
    for index in 0..2 {
        if index == 1 && (actual[0].0, actual[0].1) == (actual[1].0, actual[1].1) { continue; }
        if let Some(object) = facts.objects.iter_mut().find(|object|
            object.device == actual[index].0 && object.inode == actual[index].1)
        {
            object.allocation = actual[index].2;
        } else {
            // Original fixed capacity and charged slots were checked before any mutation.
            facts.objects.push(OriginalControlObjectFact {
                device: actual[index].0, inode: actual[index].1,
                allocation: actual[index].2, retained_prior: 0,
            });
        }
    }
    facts.allocation_admitted = admitted;
    facts.allocation_update_pending = false;
    Ok(())
}

pub(crate) struct CaptureOperation {
    clock: OperationClock,
    process: ProcessIdentity,
    process_observation: [u8; 32],
    request: ReviewedNormalCaptureRequest,
    self_reference: Weak<CaptureOperation>,
    operation: [u8; 16],
    bundle: [u8; 16],
    owner_instance: [u8; 16],
    resources: Arc<Mutex<CaptureResourceTotals>>,
    normal_close_deadline: u64,
}

impl CaptureOperation {
    fn start(
        request: ReviewedNormalCaptureRequest,
        owner_instance: [u8; 16],
        resources: &Arc<Mutex<CaptureResourceTotals>>,
        original_shutdown_deadline: std::time::Instant,
    ) -> Result<Arc<Self>, (ReviewedNormalCaptureRequest, Fault)> {
        // Before the unique request moves, preserve it on every fallible preparation path.
        let prepared = (|| {
            request
                .profile
                .validate()
                .map_err(|_| Fault::ProfileInvalid)?;
            request
                .profile
                .validate_master_retention()
                .map_err(|_| Fault::ProfileInvalid)?;
            if owner_instance == [0; 16] {
                return Err(Fault::ProfileInvalid);
            }
            // The original pre-t0 ledger is carried, never reconstructed at t0. Refuse a
            // different owner or profile before starting the one original E/C clock.
            if original_capture_resource_identity(resources, &request.profile.carrier_bounds()?)?
                != owner_instance
            {
                return Err(Fault::IntentMismatch);
            }
            let clock = OperationClock::start(
                request.profile.native.effect_ns,
                request.profile.native.convergence_ns,
            )
            .map_err(map_clock)?;
            let process = ProcessIdentity::capture(std::process::id())
                .map_err(|_| Fault::ClockUnavailable)?;
            let observation = process
                .evidence_bytes()
                .map_err(|_| Fault::ClockUnavailable)?;
            let operation = fresh_uuid()?;
            let bundle = fresh_uuid()?;
            // The auxiliary Instant can only shorten the original deadline: pair a monotonic
            // sample before reading the remaining original Instant budget, then cap by E.
            let observed = clock.observed().map_err(map_clock)?;
            let remaining = original_shutdown_deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or(Fault::DeadlineExpired)?;
            let remaining =
                u64::try_from(remaining.as_nanos()).map_err(|_| Fault::BoundsOverflow)?;
            if remaining == 0 {
                return Err(Fault::DeadlineExpired);
            }
            let normal_close_deadline = observed
                .checked_add(remaining)
                .ok_or(Fault::BoundsOverflow)?
                .min(clock.effect());
            clock.permit_effect().map_err(map_clock)?;
            Ok((
                clock,
                process,
                observation,
                operation,
                bundle,
                normal_close_deadline,
            ))
        })();
        let (clock, process, process_observation, operation, bundle, normal_close_deadline) =
            match prepared {
                Ok(values) => values,
                Err(fault) => return Err((request, fault)),
            };
        // No fallible operation follows this move; the caller installs the Arc before checking E.
        Ok(Arc::new_cyclic(|self_reference| Self {
            clock,
            process,
            process_observation,
            request,
            self_reference: self_reference.clone(),
            operation,
            bundle,
            owner_instance,
            resources: Arc::clone(resources),
            normal_close_deadline,
        }))
    }

    pub(crate) fn profile(&self) -> &CaptureProfile {
        &self.request.profile
    }
    pub(crate) fn reserve_original_resources(
        &self,
        fd_delta: u64,
        metadata_delta: u64,
    ) -> Result<(), Fault> {
        self.require_effect()?;
        reserve_capture_resources(&self.resources, fd_delta, metadata_delta)
    }

    pub(crate) fn reviewed(&self) -> &ReviewedNormalCaptureRequest {
        &self.request
    }

    pub(crate) fn shared_original(&self) -> Result<Arc<Self>, Fault> {
        self.self_reference.upgrade().ok_or(Fault::ClockUnavailable)
    }

    pub(crate) fn pid(&self) -> u32 {
        std::process::id()
    }

    pub(crate) fn original_t0_ns(&self) -> u64 {
        self.clock.t0()
    }
    pub(crate) fn effect_deadline_ns(&self) -> u64 {
        self.clock.effect()
    }
    pub(crate) fn closing_deadline_ns(&self) -> u64 {
        self.clock.convergence()
    }
    pub(crate) fn operation_id(&self) -> [u8; 16] {
        self.operation
    }
    pub(crate) fn bundle_id(&self) -> [u8; 16] {
        self.bundle
    }
    pub(crate) fn owner_instance(&self) -> [u8; 16] {
        self.owner_instance
    }
    pub(crate) fn original_clock(&self) -> &OperationClock {
        &self.clock
    }

    pub(crate) fn clock_view(self: &Arc<Self>) -> Arc<dyn CaptureClockCheck> {
        Arc::clone(self) as Arc<dyn CaptureClockCheck>
    }

    pub(crate) fn require_normal_closing(&self) -> Result<(), Fault> {
        self.require_effect()?;
        if self.observed_ns()? >= self.normal_close_deadline {
            return Err(Fault::DeadlineExpired);
        }
        Ok(())
    }

    pub(crate) fn normal_closing_remaining_ns(&self) -> Result<u64, Fault> {
        self.require_normal_closing()?;
        self.normal_close_deadline
            .checked_sub(self.observed_ns()?)
            .ok_or(Fault::DeadlineExpired)
    }

    fn original_owner_current(&self) -> Result<(), Fault> {
        self.process
            .revalidate()
            .map_err(|_| Fault::ClockUnavailable)?;
        if self
            .process
            .evidence_bytes()
            .map_err(|_| Fault::ClockUnavailable)?
            != self.process_observation
        {
            return Err(Fault::ClockUnavailable);
        }
        Ok(())
    }
}

impl CaptureClockCheck for CaptureOperation {
    fn require_effect(&self) -> Result<(), Fault> {
        self.original_owner_current()?;
        self.clock.permit_effect().map(|_| ()).map_err(map_clock)
    }
    fn require_closing(&self) -> Result<(), Fault> {
        self.original_owner_current()?;
        self.clock.permit_closing_request().map_err(map_clock)
    }
    fn effect_remaining_ns(&self) -> Result<u64, Fault> {
        self.require_effect()?;
        self.clock
            .effect()
            .checked_sub(self.clock.observed().map_err(map_clock)?)
            .ok_or(Fault::DeadlineExpired)
    }
    fn closing_remaining_ns(&self) -> Result<u64, Fault> {
        self.require_closing()?;
        self.clock
            .convergence()
            .checked_sub(self.clock.observed().map_err(map_clock)?)
            .ok_or(Fault::ClosingPending)
    }
    fn observed_ns(&self) -> Result<u64, Fault> {
        self.original_owner_current()?;
        self.clock.observed().map_err(map_clock)
    }
}

fn map_clock(error: crate::postgres_maintenance::MaintenanceError) -> Fault {
    use crate::postgres_maintenance::MaintenanceError;
    match error {
        MaintenanceError::DeadlineExpired => Fault::DeadlineExpired,
        MaintenanceError::ClosingPending => Fault::ClosingPending,
        MaintenanceError::ClockOverflow => Fault::BoundsOverflow,
        _ => Fault::ClockUnavailable,
    }
}

fn fresh_uuid() -> Result<[u8; 16], Fault> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Fault::IoFailure)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes)
}

/// Actual original joins are distinct from proxy-future destruction. Proxy joins stay Unknown.
pub(crate) struct DriverClosureFacts {
    joined_before_freeze: u64,
    original_joins: Vec<OriginalDriverJoinFact>,
    live_proxy_futures: u64,
}
impl DriverClosureFacts {
    pub(crate) fn joined_before_freeze(&self) -> u64 {
        self.joined_before_freeze
    }
    pub(crate) fn original_joins(&self) -> &[OriginalDriverJoinFact] {
        &self.original_joins
    }
    pub(crate) fn live_proxy_futures(&self) -> u64 {
        self.live_proxy_futures
    }
}

async fn join_original_drivers(
    drivers: &mut DesktopCaptureDrivers,
    operation: &CaptureOperation,
    facts: &mut DriverClosureFacts,
) -> Result<(), Fault> {
    let configured = usize::try_from(operation.profile().drivers.max_unjoined_original_tasks)
        .map_err(|_| Fault::BoundsOverflow)?;
    let limit = drivers.original_tasks_remaining();
    if limit > configured {
        return Err(Fault::CapacityExceeded);
    }
    let metadata = limit
        .checked_mul(std::mem::size_of::<OriginalDriverJoinFact>())
        .ok_or(Fault::BoundsOverflow)?;
    if u64::try_from(metadata).map_err(|_| Fault::BoundsOverflow)?
        > operation.profile().drivers.max_owner_metadata_bytes
    {
        return Err(Fault::CapacityExceeded);
    }
    facts.joined_before_freeze = drivers.joined_before_freeze();
    if facts.original_joins.capacity() < limit {
        facts
            .original_joins
            .try_reserve_exact(limit.saturating_sub(facts.original_joins.len()))
            .map_err(|_| Fault::CapacityExceeded)?;
    }
    while let Some(retirement) = drivers.next_retirement() {
        operation.require_closing()?;
        retirement.request();
    }
    loop {
        if drivers.original_tasks_remaining() == 0 {
            break;
        }
        if facts.original_joins.len() >= limit {
            return Err(Fault::CapacityExceeded);
        }
        operation.require_closing()?;
        let remaining = operation.closing_remaining_ns()?;
        // Only a borrowed, cancel-safe join future is timed out. The actual sets remain resident.
        let fact = tokio::time::timeout(
            std::time::Duration::from_nanos(remaining),
            drivers.join_next_original(),
        )
        .await
        .map_err(|_| Fault::ClosingPending)?
        .ok_or(Fault::SourceChanged)?;
        operation.require_closing()?;
        if fact.destruction().is_none() || fact.outcome() == OriginalDriverJoinOutcome::Panicked {
            facts.original_joins.push(fact);
            return Err(Fault::SourceChanged);
        }
        facts.original_joins.push(fact);
    }
    if drivers.original_destructions_missing() != 0 {
        return Err(Fault::SourceChanged);
    }
    while drivers.live_proxy_future_count() != 0 {
        operation.require_normal_closing()?;
        tokio::task::yield_now().await;
    }
    operation.require_normal_closing()?;
    facts.live_proxy_futures = drivers.live_proxy_future_count();
    Ok(())
}

pub(crate) mod control;
pub(super) mod materials;
pub(crate) use crate::postgres_maintenance::capture::CaptureMaterialsClosed;
pub(crate) use control::{CaptureControlOwner, CaptureIntentWitness, ControlSourceIdentity};
pub(crate) use materials::{
    CaptureMaterialsClosed as CapturedNormalMaterials, ClosedMaterialParts, NormalCaptureMaterials,
    OriginalDriverMaterial, original_closed_driver_material,
};

pub(crate) async fn finish_original_capture_materials(
    source: &mut crate::postgres_maintenance::capture::CaptureSourceOwner,
    operation: &Arc<CaptureOperation>,
) -> Result<CapturedNormalMaterials, Fault> {
    materials::finish_capture_materials(source, operation).await
}

/// Prepared at bootstrap while original roots, master, audit key and Store are all owned.
/// No operation clock exists until the genuine native Ready exit consumes it.
pub(super) struct ArmedNormalCapture {
    request: Option<ReviewedNormalCaptureRequest>,
    control: CaptureControlOwner,
    vault: crate::desktop_vault::ArmedCaptureVault,
    artifact_store: Arc<openbot_infra::artifact_store::DatasetBoundArtifactStore>,
    capture_audit: openbot_infra::repo::audit::AuditEventRepo,
    capture_audit_key: openbot_domain::vault::SecretBytes,
    owner_instance: [u8; 16],
    resources: Arc<Mutex<CaptureResourceTotals>>,
    materials: NormalCaptureMaterials,
}
impl ArmedNormalCapture {
    pub(super) fn from_original_startup(
        request: ReviewedNormalCaptureRequest,
        control: CaptureControlOwner,
        vault: crate::desktop_vault::ArmedCaptureVault,
        artifact_store: Arc<openbot_infra::artifact_store::DatasetBoundArtifactStore>,
        capture_audit: openbot_infra::repo::audit::AuditEventRepo,
        capture_audit_key: openbot_domain::vault::SecretBytes,
        materials: NormalCaptureMaterials,
        resources: Arc<Mutex<CaptureResourceTotals>>,
    ) -> Result<Self, Fault> {
        request
            .profile
            .validate()
            .map_err(|_| Fault::ProfileInvalid)?;
        request
            .profile
            .validate_master_retention()
            .map_err(|_| Fault::ProfileInvalid)?;
        let owner_instance = original_capture_resource_identity(
            &resources, &request.profile.carrier_bounds()?,
        )?;
        control.revalidate_original_storage_owner(&resources, &request.profile.carrier_bounds()?)?;
        vault.revalidate().map_err(|_| Fault::SourceChanged)?;
        if capture_audit_key.len() != 32 {
            return Err(Fault::SecretInvalid);
        }
        Ok(Self {
            request: Some(request),
            control,
            vault,
            artifact_store,
            capture_audit,
            capture_audit_key,
            owner_instance,
            resources,
            materials,
        })
    }
}

/// Original closing-job custody, including opaque worker failures and all original inputs.
pub(super) struct CaptureJobCustody {
    armed: Option<ArmedNormalCapture>,
    operation: Option<Arc<CaptureOperation>>,
    control: Option<CaptureControlOwner>,
    phase: Option<CaptureOwnerPhase>,
    last_fault: Option<Fault>,
    stream_task: Option<
        tokio::task::JoinHandle<
            openbot_infra::backup::whole_pg_capture_stream::OwnedCaptureStreamResult,
        >,
    >,
    stream_result: Option<openbot_infra::backup::whole_pg_capture_stream::OwnedCaptureStreamResult>,
    stream_join_failure: Option<tokio::task::JoinError>,
    stream_input_failure:
        Option<openbot_infra::backup::whole_pg_capture_stream::OwnedCaptureStreamFailure>,
    stream_inputs: Option<openbot_infra::backup::whole_pg_capture_stream::OwnedCaptureStreamInputs>,
    original_sources: Vec<openbot_infra::backup::whole_pg_capture_stream::WholePgOwnedSourceInput>,
    material_claims: Vec<openbot_domain::backup::whole_pg_carrier::WholePgMaterialClaim>,
    retained_materials: Option<ClosedMaterialParts>,
    original_master_journal: Option<std::fs::File>,
    original_master_journal_bytes: Option<zeroize::Zeroizing<Vec<u8>>>,
    stream_output_directory: Option<std::fs::File>,
    stream_key_medium_directory: Option<std::fs::File>,
}
enum CaptureOwnerPhase {
    Normal(Box<NormalCaptureClosingOwner>),
    Closed(Box<NormalClosedToken>),
    Permit(Box<CaptureStartPermit>),
    Source(Box<crate::postgres_maintenance::capture::CaptureSourceOwner>),
    Materials(Box<CaptureMaterialsClosed>),
    Failed(RetainedCaptureFailure),
}
impl CaptureJobCustody {
    fn new(armed: ArmedNormalCapture) -> Self {
        Self {
            armed: Some(armed),
            operation: None,
            control: None,
            phase: None,
            last_fault: None,
            stream_task: None,
            stream_result: None,
            stream_join_failure: None,
            stream_input_failure: None,
            stream_inputs: None,
            original_sources: Vec::new(),
            material_claims: Vec::new(),
            retained_materials: None,
            original_master_journal: None,
            original_master_journal_bytes: None,
            stream_output_directory: None,
            stream_key_medium_directory: None,
        }
    }
    fn pending(&mut self, fault: Fault) -> CaptureClosingPending {
        self.last_fault = Some(fault);
        CaptureClosingPending { fault }
    }
    fn retained_failure(&mut self, retained: RetainedCaptureFailure) -> CaptureClosingPending {
        let fault = retained.fault();
        self.phase = Some(CaptureOwnerPhase::Failed(retained));
        self.pending(fault)
    }
}
/// Only the final original owner may construct this after publication and control closure.
pub(super) struct CaptureCompleted {
    operation: [u8; 16],
}
/// This is a result tag only; the original job retains every unclosed owner and input.
pub(super) struct CaptureClosingPending {
    fault: Fault,
}

// Only the original phase owner stays outside this borrowed future. Catch an ordinary
// unwind from polling this local step; process abort, runtime loss, and a panicking
// destructor are not turned into resource-closure or success evidence.
async fn await_resident_capture_step<T>(
    step: impl std::future::Future<Output = Result<T, Fault>>,
) -> Result<T, Fault> {
    let mut step = std::pin::pin!(step);
    std::future::poll_fn(|context| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::future::Future::poll(step.as_mut(), context)
        })) {
            Ok(polled) => polled,
            Err(_) => std::task::Poll::Ready(Err(Fault::ClosingPending)),
        }
    })
    .await
}

/// The original resident ClosingJob alone may complete a normal-exit capture.
pub(super) async fn run_normal_exit_capture(
    job: &mut super::DesktopLocalClosingJob,
    ready: NormalReadyExitToken,
) -> Result<CaptureCompleted, CaptureClosingPending> {
    fn original_witness(phase: &CaptureOwnerPhase) -> Result<&CaptureIntentWitness, Fault> {
        match phase {
            CaptureOwnerPhase::Normal(normal) => normal.intent.as_ref().ok_or(Fault::IntentMismatch),
            CaptureOwnerPhase::Closed(closed) => closed.normal.intent.as_ref().ok_or(Fault::IntentMismatch),
            CaptureOwnerPhase::Permit(permit) => permit.intent_witness(),
            CaptureOwnerPhase::Source(source) => source.intent_witness(),
            CaptureOwnerPhase::Materials(materials) => materials.intent_witness(),
            CaptureOwnerPhase::Failed(failure) => match &failure.retained {
                RetainedCaptureOwners::Normal(normal) => normal.intent.as_ref().ok_or(Fault::IntentMismatch),
                RetainedCaptureOwners::Closed(closed) => closed.normal.intent.as_ref().ok_or(Fault::IntentMismatch),
                RetainedCaptureOwners::Permit(permit) => permit.intent_witness(),
                RetainedCaptureOwners::Source(source) => source.intent_witness(),
            },
        }
    }
    fn original_source(
        phase: &CaptureOwnerPhase,
    ) -> Result<&crate::postgres_maintenance::capture::CaptureSourceOwner, Fault> {
        match phase {
            CaptureOwnerPhase::Source(source) => Ok(source),
            CaptureOwnerPhase::Materials(materials) => Ok(&materials.source),
            CaptureOwnerPhase::Failed(RetainedCaptureFailure {
                retained: RetainedCaptureOwners::Source(source),
                ..
            }) => Ok(source),
            _ => Err(Fault::ClosingPending),
        }
    }
    async fn append_original(
        custody: &mut CaptureJobCustody,
        operation: &Arc<CaptureOperation>,
        stage: control::ControlStage,
        facts: control::ControlStageFacts,
    ) -> Result<(), Fault> {
        let phase = custody.phase.as_ref().ok_or(Fault::ClosingPending)?;
        let witness = original_witness(phase)?;
        let control = custody.control.as_mut().ok_or(Fault::ClosingPending)?;
        // This future only borrows the original resident source and journal owners.
        await_resident_capture_step(control.append(witness, operation, stage, facts)).await
    }
    fn original_facts(
        custody: &CaptureJobCustody,
        normal: (u64, u64, u64),
        stream_requested: bool,
        output: Option<(u64, [u8; 32])>,
    ) -> Result<control::ControlStageFacts, Fault> {
        let source = original_source(custody.phase.as_ref().ok_or(Fault::ClosingPending)?)?;
        let (source_original, source_joined, source_proxies) =
            source.original_source_task_observations()?;
        let (stream_original, stream_joined) = if stream_requested {
            if custody.stream_result.is_some() {
                // Only join_original_stream_worker installs the original awaited result.
                (1u64, 1u64)
            } else if custody.stream_task.is_some() {
                // A retained handle proves issuance, never a wait/join or successful result.
                (1u64, 0u64)
            } else {
                // A failed handoff with no observed original result is not guessed as zero.
                return Err(Fault::ClosingPending);
            }
        } else {
            // This program point precedes the only call that can spawn the stream.
            if custody.stream_task.is_some() || custody.stream_result.is_some()
                || custody.stream_join_failure.is_some() || custody.stream_input_failure.is_some()
                || custody.stream_inputs.is_some()
            {
                return Err(Fault::IntentMismatch);
            }
            (0u64, 0u64)
        };
        let original = normal.0.checked_add(source_original)
            .and_then(|n| n.checked_add(stream_original)).ok_or(Fault::BoundsOverflow)?;
        let joined = normal.1.checked_add(source_joined)
            .and_then(|n| n.checked_add(stream_joined)).ok_or(Fault::BoundsOverflow)?;
        let proxies = normal.2.checked_add(source_proxies).ok_or(Fault::BoundsOverflow)?;
        if joined > original {
            return Err(Fault::IntentMismatch);
        }
        let mut facts = actual_stage_facts(original, joined, proxies);
        // Count actually issued original task effects, including the normal stop task.
        // This finite task-effect observation is not a count of helper-internal syscalls.
        facts.issued_effects = source_original.checked_add(stream_original)
            .and_then(|n| n.checked_add(1)).ok_or(Fault::BoundsOverflow)?;
        if let Some((wire_bytes, digest)) = output {
            if wire_bytes == 0 {
                return Err(Fault::ReadbackFailed);
            }
            // One ordinary SHA text is newly requested by this call, before Control owns it.
            let known = (std::mem::size_of::<String>() as u64)
                .checked_add(64)
                .and_then(|n| n.checked_add(std::mem::size_of::<std::array::IntoIter<u8, 32>>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<Option<u8>>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), std::collections::TryReserveError>>() as u64))
                .ok_or(Fault::BoundsOverflow)?;
            custody.operation.as_ref().ok_or(Fault::IntentMismatch)?
                .reserve_original_resources(0, known)?;
            let mut text = String::new();
            text.try_reserve_exact(64).map_err(|_| Fault::CapacityExceeded)?;
            if text.capacity() != 64 { return Err(Fault::CapacityExceeded); }
            let alphabet = b"0123456789abcdef";
            for byte in digest {
                text.push(char::from(alphabet[usize::from(byte >> 4)]));
                text.push(char::from(alphabet[usize::from(byte & 15)]));
            }
            facts.output_bytes = Some(wire_bytes);
            facts.output_sha256 = Some(text);
        }
        Ok(facts)
    }

    // Preparation borrows this job; every resource is installed in it before a real await.
    let prepared = await_resident_capture_step(async {
        prepare_original_capture_source_permit(job, ready).await.map_err(|pending| pending.fault)
    }).await;
    let custody = match job.capture.as_mut() {
        Some(custody) => custody,
        None => return Err(CaptureClosingPending {
            fault: prepared.err().unwrap_or(Fault::IntentMismatch),
        }),
    };
    let operation = match custody.operation.as_ref() {
        Some(operation) => Arc::clone(operation),
        None => return Err(custody.pending(prepared.err().unwrap_or(Fault::IntentMismatch))),
    };
    let mut normal_facts = None;
    let mut stream_requested = false;
    let result: Result<CaptureCompleted, Fault> = match prepared {
        Err(fault) => Err(fault),
        Ok(()) => async {
            operation.require_effect()?;
            let normal = match custody.phase.as_ref() {
                Some(CaptureOwnerPhase::Permit(permit)) => {
                    let normal = &permit.closed.normal;
                    if normal.stopped.is_none() || normal.stop_task.is_some()
                        || normal.retained_stop_failure.is_some() || normal.stop_join_failure.is_some()
                    {
                        return Err(Fault::ClosingPending);
                    }
                    let facts = permit.closed_driver_facts()?;
                    if facts.live_proxy_futures != 0
                        || facts.original_joins.iter().any(|fact|
                            fact.destruction().is_none()
                                || fact.outcome() == OriginalDriverJoinOutcome::Panicked)
                    {
                        return Err(Fault::ClosingPending);
                    }
                    // The extra task is the actual stop_for_capture result retained in stopped.
                    let count = facts.joined_before_freeze
                        .checked_add(u64::try_from(facts.original_joins.len()).map_err(|_| Fault::BoundsOverflow)?)
                        .and_then(|n| n.checked_add(1)).ok_or(Fault::BoundsOverflow)?;
                    (count, count, facts.live_proxy_futures)
                }
                _ => return Err(Fault::IntentMismatch),
            };
            normal_facts = Some(normal);
            let permit = match custody.phase.take() {
                Some(CaptureOwnerPhase::Permit(permit)) => permit,
                other => {
                    custody.phase = other;
                    return Err(Fault::IntentMismatch);
                }
            };
            // R472 permits this owning, linear await in the original resident job.
            // No consumptive timeout or detached substitute owns the permit/source.
            match crate::postgres_sidecar::start_capture_source(*permit, operation.as_ref()).await {
                Ok(source) => custody.phase = Some(CaptureOwnerPhase::Source(Box::new(source))),
                Err(retained) => {
                    let fault = retained.fault();
                    custody.phase = Some(CaptureOwnerPhase::Failed(retained));
                    return Err(fault);
                }
            }
            let mut facts = original_facts(custody, normal, false, None)?;
            let (parent, entry) = original_source(
                custody.phase.as_ref().ok_or(Fault::ClosingPending)?,
            )?.original_socket_directory_observations()?;
            facts.parent_device = Some(parent.0);
            facts.parent_inode = Some(parent.1);
            facts.entry_device = Some(entry.0);
            facts.entry_inode = Some(entry.1);
            append_original(custody, &operation, control::ControlStage::SourceStarted, facts).await?;
            operation.require_effect()?;
            let source = match custody.phase.take() {
                Some(CaptureOwnerPhase::Source(source)) => source,
                other => {
                    custody.phase = other;
                    return Err(Fault::IntentMismatch);
                }
            };
            match crate::postgres_maintenance::capture::run_capture(*source, operation.as_ref()).await {
                Ok(materials) => custody.phase = Some(CaptureOwnerPhase::Materials(Box::new(materials))),
                Err(retained) => {
                    let fault = retained.fault();
                    custody.phase = Some(CaptureOwnerPhase::Failed(retained));
                    return Err(fault);
                }
            }
            original_source(custody.phase.as_ref().ok_or(Fault::ClosingPending)?)?
                .require_sources_closed()?;
            // These records observe the genuine returned full material/closed-source pair.
            // A missing real producer or a late/unknown owner has already returned Err.
            for stage in [control::ControlStage::MaterialsFrozen, control::ControlStage::SourceClosed] {
                let facts = if stage == control::ControlStage::MaterialsFrozen {
                    let control = custody.control.as_ref().ok_or(Fault::IntentMismatch)?;
                    let materials = match custody.phase.as_ref() {
                        Some(CaptureOwnerPhase::Materials(closed)) => &closed.materials,
                        _ => return Err(Fault::MaterialMissing),
                    };
                    let (parent, entry, bytes, sha256) =
                        materials.original_audit_record_observations(
                            control.operation_directory()?, &operation,
                        )?;
                    let mut facts = original_facts(custody, normal, false, Some((bytes, sha256)))?;
                    facts.parent_device = Some(parent.0);
                    facts.parent_inode = Some(parent.1);
                    facts.entry_device = Some(entry.0);
                    facts.entry_inode = Some(entry.1);
                    facts
                } else {
                    original_facts(custody, normal, false, None)?
                };
                if facts.original_tasks != facts.joined_original_tasks || facts.live_proxy_futures != 0 {
                    return Err(Fault::ClosingPending);
                }
                append_original(custody, &operation, stage, facts).await?;
            }
            prepare_original_owned_stream(custody)?;
            stream_requested = true;
            await_resident_capture_step(join_original_stream_worker(custody)).await?;
            let output = match custody.stream_result.as_ref() {
                Some(Ok(receipt)) if receipt.key_medium_verified()
                    && receipt.temporary_verified() && receipt.published_verified() =>
                    (receipt.wire_bytes(), *receipt.carrier_sha256()),
                _ => return Err(Fault::ReadbackFailed),
            };
            // The whole real receipt stays resident while its original journal ACKs run.
            for stage in [
                control::ControlStage::KeyMediumVerified,
                control::ControlStage::TemporaryVerified,
                control::ControlStage::PublishedVerified,
                control::ControlStage::Closed,
            ] {
                let facts = original_facts(custody, normal, true, Some(output))?;
                if facts.original_tasks != facts.joined_original_tasks || facts.live_proxy_futures != 0 {
                    return Err(Fault::ClosingPending);
                }
                append_original(custody, &operation, stage, facts).await?;
            }
            // Successful original join + receipt + final ACK are the closure evidence;
            // empty slots alone never confer completion.
            if custody.stream_task.is_some() || custody.stream_join_failure.is_some()
                || custody.stream_input_failure.is_some() || custody.stream_inputs.is_some()
                || !custody.original_sources.is_empty() || !custody.material_claims.is_empty()
                || custody.stream_output_directory.is_some() || custody.stream_key_medium_directory.is_some()
            {
                return Err(Fault::ClosingPending);
            }
            operation.require_closing()?;
            drop(custody.original_master_journal.take());
            operation.require_closing()?;
            drop(custody.original_master_journal_bytes.take());
            operation.require_closing()?;
            drop(custody.retained_materials.take());
            operation.require_closing()?;
            // Every journal worker has actually ACKed; only its passive original files remain.
            drop(custody.control.take());
            operation.require_closing()?;
            // This closes the original source's passive FDs and outer continuous kernel lease last.
            drop(custody.phase.take());
            operation.require_closing()?;
            Ok(CaptureCompleted { operation: operation.operation_id() })
        }.await,
    };
    match result {
        Ok(completed) => Ok(completed),
        Err(fault) => {
            let first = *custody.last_fault.get_or_insert(fault);
            // No record is manufactured when genuine current owner observations are unavailable.
            // A failed/late log cannot replace the first original fault or discard its owners.
            if operation.require_closing().is_ok() {
                if let Some(normal) = normal_facts {
                    if let Ok(mut facts) = original_facts(custody, normal, stream_requested, None) {
                        facts.outcome = control::ControlOutcome::Unknown;
                        facts.fault = Some(String::from(match first {
                            Fault::InvalidArgument => "InvalidArgument",
                            Fault::UnsupportedVersion => "UnsupportedVersion",
                            Fault::ProfileMissing => "ProfileMissing",
                            Fault::ProfileInvalid => "ProfileInvalid",
                            Fault::BoundsOverflow => "BoundsOverflow",
                            Fault::CapacityExceeded => "CapacityExceeded",
                            Fault::ClockUnavailable => "ClockUnavailable",
                            Fault::DeadlineExpired => "DeadlineExpired",
                            Fault::Cancelled => "Cancelled",
                            Fault::IntentMismatch => "IntentMismatch",
                            Fault::ManifestInvalid => "ManifestInvalid",
                            Fault::NonCanonical => "NonCanonical",
                            Fault::MaterialMissing => "MaterialMissing",
                            Fault::ExtraMaterial => "ExtraMaterial",
                            Fault::SourceChanged => "SourceChanged",
                            Fault::PathUnsafe => "PathUnsafe",
                            Fault::SecretInvalid => "SecretInvalid",
                            Fault::NonceExhausted => "NonceExhausted",
                            Fault::FrameInvalid => "FrameInvalid",
                            Fault::AuthenticationFailed => "AuthenticationFailed",
                            Fault::ShortRead => "ShortRead",
                            Fault::ExtraTail => "ExtraTail",
                            Fault::TerminalMissing => "TerminalMissing",
                            Fault::KeyMediumInvalid => "KeyMediumInvalid",
                            Fault::ReadbackFailed => "ReadbackFailed",
                            Fault::PublishUnknown => "PublishUnknown",
                            Fault::IoFailure => "IoFailure",
                            Fault::ClosingPending => "ClosingPending",
                        }));
                        let _observed = append_original(
                            custody, &operation, control::ControlStage::ClosingPending, facts,
                        ).await;
                    }
                }
            }
            Err(CaptureClosingPending { fault: first })
        }
    }
}

/// The real normal barrier and independent consumer, stopping at the source-start capability.
/// It produces no capture-completion or runtime qualification.
async fn prepare_original_capture_source_permit(
    job: &mut super::DesktopLocalClosingJob,
    ready: NormalReadyExitToken,
) -> Result<(), CaptureClosingPending> {
    let background = job.owner.as_ref().ok_or(CaptureClosingPending {
        fault: Fault::IntentMismatch,
    })?;
    if !Arc::ptr_eq(&background.lifecycle, &ready.lifecycle) || job.capture.is_some() {
        return Err(CaptureClosingPending {
            fault: Fault::IntentMismatch,
        });
    }
    let armed = job
        .owner
        .as_mut()
        .and_then(|owner| owner.capture_armed.take())
        .ok_or(CaptureClosingPending {
            fault: Fault::ProfileMissing,
        })?;
    job.capture = Some(CaptureJobCustody::new(armed));
    let custody = job
        .capture
        .as_mut()
        .expect("original capture custody was installed");
    let armed = custody
        .armed
        .as_mut()
        .expect("original armed state retained");
    let request = armed.request.take().ok_or(CaptureClosingPending {
        fault: Fault::IntentMismatch,
    })?;
    let operation = match CaptureOperation::start(request, armed.owner_instance, &armed.resources, job.deadline) {
        Ok(operation) => operation,
        Err((request, fault)) => {
            armed.request = Some(request);
            return Err(custody.pending(fault));
        }
    };
    custody.operation = Some(Arc::clone(&operation));
    if armed.materials.original_decode_budget()
        .bind_original_clock(operation.clock_view()).is_err()
    {
        return Err(custody.pending(Fault::IntentMismatch));
    }
    if let Err(fault) = operation.require_normal_closing() {
        return Err(custody.pending(fault));
    }
    let ArmedNormalCapture {
        request: _,
        control,
        vault,
        artifact_store,
        capture_audit,
        capture_audit_key,
        owner_instance: _,
        resources: _,
        materials,
    } = custody.armed.take().expect("original armed state retained");
    custody.control = Some(control);
    let background = job
        .owner
        .take()
        .expect("the checked original background remains in this job");
    custody.phase = Some(CaptureOwnerPhase::Normal(Box::new(
        NormalCaptureClosingOwner {
            background,
            vault: Some(vault),
            artifact_store,
            capture_audit,
            capture_audit_key: Some(capture_audit_key),
            materials: Some(materials),
            driver_custody: None,
            driver_facts: None,
            stopped: None,
            stop_task: None,
            retained_stop_failure: None,
            stop_join_failure: None,
            intent: None,
            operation: Arc::downgrade(&operation),
        },
    )));
    let normal = match custody.phase.as_mut() {
        Some(CaptureOwnerPhase::Normal(normal)) => normal,
        _ => return Err(custody.pending(Fault::IntentMismatch)),
    };
    let source_identity = match materials::prepare_intent_source(normal, &operation).await {
        Ok(source) => source,
        Err(fault) => return Err(custody.pending(fault)),
    };
    let witness = match custody
        .control
        .as_mut()
        .expect("original control retained")
        .begin(&operation, source_identity)
        .await
    {
        Ok(witness) => witness,
        Err(fault) => return Err(custody.pending(fault)),
    };
    match custody.phase.as_mut() {
        Some(CaptureOwnerPhase::Normal(normal)) => normal.intent = Some(witness),
        _ => return Err(custody.pending(Fault::IntentMismatch)),
    }
    let closed_result = match (custody.phase.as_mut(), custody.control.as_mut()) {
        (Some(CaptureOwnerPhase::Normal(normal)), Some(control)) => {
            await_resident_capture_step(close_normal_originals(normal, &operation, control)).await
        }
        _ => Err(Fault::IntentMismatch),
    };
    if let Err(fault) = closed_result {
        return Err(custody.pending(fault));
    }
    // The borrowed original step really succeeded. No fallible call or await separates
    // taking this still-resident owner from its genuine closed-token custody.
    let normal = match custody.phase.take() {
        Some(CaptureOwnerPhase::Normal(normal)) => *normal,
        other => {
            custody.phase = other;
            return Err(custody.pending(Fault::IntentMismatch));
        }
    };
    custody.phase = Some(CaptureOwnerPhase::Closed(Box::new(NormalClosedToken {
        normal,
        retained_consumer_directory: None,
    })));
    let confirmed = match (custody.phase.as_mut(), custody.control.as_mut()) {
        (Some(CaptureOwnerPhase::Closed(closed)), Some(control)) => {
            await_resident_capture_step(confirm_closed_original(closed, &operation, control)).await
        }
        _ => Err(Fault::IntentMismatch),
    };
    let (operation_directory, operation_path) = match confirmed {
        Ok(originals) => originals,
        Err(fault) => return Err(custody.pending(fault)),
    };
    // These are the actual consumer's returned originals; keep Closed resident until
    // that real Ok, then move it directly into the existing unique permit.
    let closed = match custody.phase.take() {
        Some(CaptureOwnerPhase::Closed(closed)) => *closed,
        other => {
            custody.phase = other;
            return Err(custody.pending(Fault::IntentMismatch));
        }
    };
    custody.phase = Some(CaptureOwnerPhase::Permit(Box::new(CaptureStartPermit {
        closed,
        operation_directory,
        operation_path,
    })));
    Ok(())
}

/// The real closed source and original material FDs are moved into one bounded stream input.
/// No key generation, filesystem publication, or completion claim occurs in this preparation.
fn prepare_original_owned_stream(custody: &mut CaptureJobCustody) -> Result<(), Fault> {
    use openbot_domain::backup::whole_pg_carrier::{
        FrozenWholePgManifest, WholePgBarrierClaim, WholePgCoverageClaim, WholePgManifestClaim,
        WholePgMaterialClaim, WholePgMaterialKind, WholePgPresence, WholePgSourceClaim,
    };
    use openbot_infra::backup::whole_pg_capture_stream::{
        OwnedCaptureStreamInputs, WholePgOwnedDirectoryInput, WholePgOwnedSourceInput,
        WholePgOwnedStreamParts,
    };
    use sha2::{Digest, Sha256};
    let operation = Arc::clone(custody.operation.as_ref().ok_or(Fault::IntentMismatch)?);
    operation.require_effect()?;
    if custody.retained_materials.is_some()
        || custody.stream_inputs.is_some()
        || custody.stream_task.is_some()
        || custody.stream_result.is_some()
        || custody.stream_input_failure.is_some()
        || custody.stream_output_directory.is_some()
        || custody.stream_key_medium_directory.is_some()
        || !custody.original_sources.is_empty()
        || !custody.material_claims.is_empty()
    {
        return Err(Fault::IntentMismatch);
    }
    let closed = match custody.phase.take() {
        Some(CaptureOwnerPhase::Materials(closed)) => *closed,
        other => {
            custody.phase = other;
            return Err(Fault::IntentMismatch);
        }
    };
    let CaptureMaterialsClosed { source, materials } = closed;
    custody.phase = Some(CaptureOwnerPhase::Source(Box::new(source)));
    custody.retained_materials = Some(materials.into_parts());
    let source = match custody.phase.as_mut() {
        Some(CaptureOwnerPhase::Source(source)) => source,
        _ => return Err(Fault::IntentMismatch),
    };
    source.require_sources_closed()?;
    // The original source already authenticated this one-shot projection before encoding.
    // Borrow its retained claim here; no second source IO or second projection is performed.
    let materials = custody
        .retained_materials
        .as_ref()
        .ok_or(Fault::MaterialMissing)?;
    let provenance = materials.provenance.as_ref().ok_or(Fault::MaterialMissing)?;
    let tool = materials.files.iter()
        .find(|file| file.material_id == provenance.tool_inventory_material_id)
        .ok_or(Fault::MaterialMissing)?;
    if (tool.plain_len, tool.plain_sha256) != materials.tool_inventory_identity {
        return Err(Fault::SourceChanged);
    }
    let bounds = operation.profile().carrier_bounds()?;
    let secret_bounds = operation.profile().secret_bounds()?;
    let count = materials
        .files
        .len()
        .checked_add(2)
        .ok_or(Fault::BoundsOverflow)?;
    if count as u64 > bounds.max_material_files || count as u64 > bounds.max_open_files {
        return Err(Fault::CapacityExceeded);
    }
    let metadata = (count as u64)
        .checked_mul(
            (std::mem::size_of::<WholePgOwnedSourceInput>() as u64)
                .checked_add(std::mem::size_of::<WholePgMaterialClaim>() as u64)
                .and_then(|n| n.checked_add(bounds.max_path_bytes.checked_mul(2)?))
                .ok_or(Fault::BoundsOverflow)?,
        )
        .ok_or(Fault::BoundsOverflow)?;
    if metadata > bounds.max_metadata_bytes {
        return Err(Fault::CapacityExceeded);
    }
    custody
        .original_sources
        .try_reserve_exact(count)
        .map_err(|_| Fault::CapacityExceeded)?;
    custody
        .material_claims
        .try_reserve_exact(count)
        .map_err(|_| Fault::CapacityExceeded)?;
    while let Some(file) = custody
        .retained_materials
        .as_ref()
        .and_then(|state| state.files.last())
    {
        operation.require_effect()?;
        if file.kind.is_secret() {
            return Err(Fault::SecretInvalid);
        }
        let chunks = material_chunks(file.plain_len, bounds.max_chunk_plain_bytes)?;
        let claim = WholePgMaterialClaim {
            material_id: file.material_id.clone(),
            kind: file.kind,
            relative_path: file.relative_path.clone(),
            plain_len: file.plain_len,
            plain_sha256: file.plain_sha256,
            chunk_count: chunks,
        };
        // No fallible work follows taking this actual descriptor from the resident original.
        let file = custody
            .retained_materials
            .as_mut()
            .expect("original material state retained")
            .files
            .pop()
            .expect("checked original file remains resident");
        custody
            .original_sources
            .push(WholePgOwnedSourceInput::File {
                material_id: file.material_id,
                file: file.file,
            });
        custody.material_claims.push(claim);
    }
    let source = match custody.phase.as_mut() {
        Some(CaptureOwnerPhase::Source(source)) => source,
        _ => return Err(Fault::IntentMismatch),
    };
    // All fallible count/reservation work preceded moving the two actual original allocations.
    let (master, scram, journal, journal_bytes) = source.take_original_secrets()?;
    custody.original_master_journal = Some(journal);
    custody.original_master_journal_bytes = Some(journal_bytes);
    for (material_id, relative_path, kind, secret) in [
        (
            "master-secret",
            "secrets/master",
            WholePgMaterialKind::MasterSecret,
            master,
        ),
        (
            "scram-secret",
            "secrets/scram",
            WholePgMaterialKind::ScramSecret,
            scram,
        ),
    ] {
        let length = secret.len() as u64;
        // profile validation established a positive u32-sized chunk bound. Length is 32 or 64.
        let chunks = length.div_ceil(bounds.max_chunk_plain_bytes) as u32;
        custody.material_claims.push(WholePgMaterialClaim {
            material_id: material_id.into(),
            kind,
            relative_path: relative_path.into(),
            plain_len: length,
            plain_sha256: Sha256::digest(secret.expose()).into(),
            chunk_count: chunks,
        });
        custody
            .original_sources
            .push(WholePgOwnedSourceInput::Secret {
                material_id: material_id.into(),
                secret,
            });
    }
    custody.material_claims.sort_by(|a, b| {
        (a.kind, a.relative_path.as_str(), a.material_id.as_str()).cmp(&(
            b.kind,
            b.relative_path.as_str(),
            b.material_id.as_str(),
        ))
    });
    let original = custody
        .retained_materials
        .as_ref()
        .ok_or(Fault::MaterialMissing)?;
    let source = &original.source;
    let mut coverage: Vec<WholePgCoverageClaim> = original
        .coverage
        .iter()
        .map(|item| WholePgCoverageClaim {
            kind: item.kind,
            presence: item.presence,
            evidence_material_id: item.evidence_material_id.clone(),
        })
        .collect();
    coverage.push(WholePgCoverageClaim {
        kind: WholePgMaterialKind::MasterSecret,
        presence: WholePgPresence::Present,
        evidence_material_id: "master-secret".into(),
    });
    coverage.push(WholePgCoverageClaim {
        kind: WholePgMaterialKind::ScramSecret,
        presence: WholePgPresence::Present,
        evidence_material_id: "scram-secret".into(),
    });
    coverage.sort_by_key(|item| item.kind);
    let manifest = FrozenWholePgManifest::check(
        WholePgManifestClaim {
            schema: "wrokbot-whole-pg-capture".into(),
            version: 1,
            operation_id: uuid_text(operation.operation_id()),
            bundle_id: uuid_text(operation.bundle_id()),
            request_id: operation.reviewed().request_id.clone(),
            source: WholePgSourceClaim {
                instance_id: source.instance_id.clone(),
                dataset_id: source.dataset_id.clone(),
                deployment_id: source.deployment_id.clone(),
                tenant_id: source.tenant_id.clone(),
                system_identifier: source.system_identifier.clone(),
                database_oid: source.database_oid,
                key_id: source.key_id.clone(),
                key_version: source.key_version,
                canary_material_id: source.canary_material_id.clone(),
                schema_material_id: source.schema_material_id.clone(),
                migration_material_id: source.migration_material_id.clone(),
                compatibility_material_id: source.compatibility_material_id.clone(),
            },
            barrier: WholePgBarrierClaim {
                normal_closed_operation_id: uuid_text(operation.operation_id()),
                audit_checkpoint_material_id: "audit-checkpoint".into(),
                receipt_frontier_material_id: "receipt-frontier".into(),
                host_inventory_material_id: "host-inventory".into(),
                driver_facts_material_id: "driver-facts".into(),
                source_start_lsn: original.backup_range.0.clone(),
                source_end_lsn: original.backup_range.1.clone(),
                timeline: original.backup_range.2,
                wal_segment_bytes: original.backup_range.3,
            },
            coverage,
            materials: std::mem::take(&mut custody.material_claims),
            // Last: all earlier source/tool/preparation checks preserve this exact DATA owner.
            // The existing pure check consumes its claim on Err; original Source/FDs stay retained.
            provenance: custody.retained_materials.as_mut()
                .expect("checked original material custody remains resident")
                .provenance.take().expect("checked original provenance remains resident"),
        },
        bounds,
    )?;
    operation.require_effect()?;
    let control = custody.control.as_ref().ok_or(Fault::IntentMismatch)?;
    let (output, key_medium) = control.destinations();
    operation.require_effect()?;
    let cloned_output = output.try_clone();
    match cloned_output {
        Ok(file) => custody.stream_output_directory = Some(file),
        Err(_) => {
            operation.require_effect()?;
            return Err(Fault::IoFailure);
        }
    }
    operation.require_effect()?;
    operation.require_effect()?;
    let cloned_key_medium = key_medium.try_clone();
    match cloned_key_medium {
        Ok(file) => custody.stream_key_medium_directory = Some(file),
        Err(_) => {
            operation.require_effect()?;
            return Err(Fault::IoFailure);
        }
    }
    operation.require_effect()?;
    let reviewed = operation.reviewed();
    if custody.stream_output_directory.is_none() || custody.stream_key_medium_directory.is_none() {
        return Err(Fault::IntentMismatch);
    }
    // All required fallible work is over. No fallible call or await lies between taking
    // either actual retained FD and the existing parts constructor that keeps Err inputs.
    let output = custody
        .stream_output_directory
        .take()
        .expect("checked original output directory remains resident");
    let key_medium = custody
        .stream_key_medium_directory
        .take()
        .expect("checked original key-medium directory remains resident");
    let parts = WholePgOwnedStreamParts {
        manifest,
        sources: std::mem::take(&mut custody.original_sources),
        output: WholePgOwnedDirectoryInput {
            directory: output,
            expected_device: reviewed.output.device,
            expected_inode: reviewed.output.inode,
            expected_uid: reviewed.output.uid,
        },
        independent_key_medium: WholePgOwnedDirectoryInput {
            directory: key_medium,
            expected_device: reviewed.key_medium.device,
            expected_inode: reviewed.key_medium.inode,
            expected_uid: reviewed.key_medium.uid,
        },
        carrier_bounds: bounds,
        secret_bounds,
    };
    match OwnedCaptureStreamInputs::from_owned_parts(parts) {
        Ok(inputs) => {
            custody.stream_inputs = Some(inputs);
            Ok(())
        }
        Err(retained) => {
            custody.stream_input_failure = Some(retained);
            // Retain the R473 opaque error without guessing its unexposed fault classification.
            Err(Fault::ClosingPending)
        }
    }
}

async fn join_original_stream_worker(custody: &mut CaptureJobCustody) -> Result<(), Fault> {
    use openbot_infra::backup::whole_pg_capture_stream::run_owned_stream;
    let operation = Arc::clone(custody.operation.as_ref().ok_or(Fault::IntentMismatch)?);
    operation.require_effect()?;
    if custody.stream_task.is_some() || custody.stream_result.is_some() {
        return Err(Fault::IntentMismatch);
    }
    let inputs = custody.stream_inputs.take().ok_or(Fault::MaterialMissing)?;
    let clock = operation.clock_view();
    custody.stream_task = Some(tokio::task::spawn_blocking(move || {
        run_owned_stream(inputs, clock)
    }));
    // Bound only the borrowed wait by the original remaining C. The original
    // worker and inputs stay resident on timeout or an ordinary local poll unwind.
    let waited = await_resident_capture_step(async {
        let remaining = operation
            .closing_remaining_ns()
            .map_err(|_| Fault::ClosingPending)?;
        Ok(tokio::time::timeout(
            std::time::Duration::from_nanos(remaining),
            custody
                .stream_task
                .as_mut()
                .expect("original stream handle retained"),
        )
        .await)
    })
    .await;
    let failed = match waited {
        Ok(Ok(Ok(result))) => {
            let failed = result.is_err();
            // Preserve the actual result before the fallible original-clock postcheck.
            custody.stream_result = Some(result);
            // This original handle really joined; only its completed handle is removed.
            custody.stream_task.take();
            failed
        }
        Ok(Ok(Err(error))) => {
            custody.stream_join_failure = Some(error);
            true
        }
        Ok(Err(_)) | Err(_) => true,
    };
    let closing = operation.require_closing();
    if failed || closing.is_err() {
        return Err(Fault::ClosingPending);
    }
    operation.require_effect()
}
fn material_chunks(length: u64, chunk: u64) -> Result<u32, Fault> {
    if chunk == 0 {
        return Err(Fault::ProfileInvalid);
    }
    u32::try_from(length.div_ceil(chunk)).map_err(|_| Fault::BoundsOverflow)
}
fn uuid_text(bytes: [u8; 16]) -> String {
    let hex = b"0123456789abcdef";
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        output.push(char::from(hex[usize::from(byte >> 4)]));
        output.push(char::from(hex[usize::from(byte & 15)]));
    }
    output
}

/// Only the original native lifecycle transition can construct this non-Clone token.
pub(crate) struct NormalReadyExitToken {
    lifecycle: Arc<crate::DesktopWindowLifecycle>,
}
impl NormalReadyExitToken {
    pub(super) fn from_original_native_ready(
        inner: &super::RuntimeStateInner,
    ) -> Result<Self, super::DesktopLocalRuntimeError> {
        if inner.phase != super::DesktopLocalRuntimePhase::Ready || inner.owner.is_none() {
            return Err(super::DesktopLocalRuntimeError::State);
        }
        Ok(Self {
            lifecycle: inner
                .lifecycle
                .as_ref()
                .map(Arc::clone)
                .ok_or(super::DesktopLocalRuntimeError::State)?,
        })
    }
}

/// The real normal owners remain resident through every awaited subphase.
pub(crate) struct NormalCaptureClosingOwner {
    background: Box<super::DesktopLocalBackgroundOwner>,
    vault: Option<crate::desktop_vault::ArmedCaptureVault>,
    artifact_store: Arc<openbot_infra::artifact_store::DatasetBoundArtifactStore>,
    capture_audit: openbot_infra::repo::audit::AuditEventRepo,
    capture_audit_key: Option<openbot_domain::vault::SecretBytes>,
    materials: Option<materials::NormalCaptureMaterials>,
    driver_custody: Option<DesktopCaptureDrivers>,
    driver_facts: Option<DriverClosureFacts>,
    stopped: Option<crate::postgres_sidecar::CaptureStoppedPostgres>,
    stop_task: Option<
        tokio::task::JoinHandle<
            Result<
                crate::postgres_sidecar::CaptureStoppedPostgres,
                crate::postgres_sidecar::RetainedSidecarCaptureFailure,
            >,
        >,
    >,
    retained_stop_failure: Option<crate::postgres_sidecar::RetainedSidecarCaptureFailure>,
    stop_join_failure: Option<tokio::task::JoinError>,
    intent: Option<CaptureIntentWitness>,
    operation: Weak<CaptureOperation>,
}

/// Created only after all mandatory real normal owners and the original postmaster close.
pub(crate) struct NormalClosedToken {
    normal: NormalCaptureClosingOwner,
    retained_consumer_directory: Option<std::fs::File>,
}

/// Only the independent post-stop consumer can create this unique source-start capability.
pub(crate) struct CaptureStartPermit {
    closed: NormalClosedToken,
    operation_directory: std::fs::File,
    operation_path: std::path::PathBuf,
}
impl CaptureStartPermit {
    /// Borrow only the original begin/ACK witness retained by this permit's normal owner.
    pub(crate) fn intent_witness(&self) -> Result<&CaptureIntentWitness, Fault> {
        self.closed.normal.intent.as_ref().ok_or(Fault::IntentMismatch)
    }
    pub(crate) fn revalidate_original(
        &self,
        operation: &Arc<CaptureOperation>,
    ) -> Result<(), Fault> {
        operation.require_effect()?;
        let normal = &self.closed.normal;
        let original = normal.operation.upgrade().ok_or(Fault::ClockUnavailable)?;
        if !Arc::ptr_eq(&original, operation)
            || normal.intent.is_none()
            || normal
                .driver_facts
                .as_ref()
                .is_none_or(|facts| facts.live_proxy_futures != 0)
        {
            return Err(Fault::IntentMismatch);
        }
        operation.require_effect()?;
        normal
            .vault
            .as_ref()
            .ok_or(Fault::SecretInvalid)?
            .revalidate_before(operation.as_ref())?;
        self.stopped()?.revalidate(operation.as_ref())?;
        materials::revalidate_original_source_config(
            normal.materials.as_ref().ok_or(Fault::MaterialMissing)?,
            self.stopped()?, operation.as_ref(),
        )?;
        use std::os::unix::fs::MetadataExt as _;
        operation.require_effect()?;
        let held = self.operation_directory.metadata();
        operation.require_effect()?;
        let held = held.map_err(|_| Fault::IoFailure)?;
        operation.require_effect()?;
        let named = std::fs::symlink_metadata(&self.operation_path);
        operation.require_effect()?;
        let named = named.map_err(|_| Fault::IoFailure)?;
        if !held.is_dir()
            || !named.is_dir()
            || (held.dev(), held.ino(), held.uid()) != (named.dev(), named.ino(), named.uid())
        {
            return Err(Fault::SourceChanged);
        }
        operation.require_effect()
    }
    pub(crate) fn stopped(
        &self,
    ) -> Result<&crate::postgres_sidecar::CaptureStoppedPostgres, Fault> {
        self.closed
            .normal
            .stopped
            .as_ref()
            .ok_or(Fault::IntentMismatch)
    }
    pub(crate) fn stopped_mut(
        &mut self,
    ) -> Result<&mut crate::postgres_sidecar::CaptureStoppedPostgres, Fault> {
        self.closed
            .normal
            .stopped
            .as_mut()
            .ok_or(Fault::IntentMismatch)
    }
    pub(crate) fn vault(&self) -> Result<&crate::desktop_vault::ArmedCaptureVault, Fault> {
        self.closed
            .normal
            .vault
            .as_ref()
            .ok_or(Fault::SecretInvalid)
    }
    pub(crate) fn take_vault(&mut self) -> Result<crate::desktop_vault::ArmedCaptureVault, Fault> {
        self.closed.normal.vault.take().ok_or(Fault::SecretInvalid)
    }
    pub(crate) fn restore_vault(
        &mut self,
        vault: crate::desktop_vault::ArmedCaptureVault,
    ) -> Result<(), crate::desktop_vault::ArmedCaptureVault> {
        if self.closed.normal.vault.is_some() {
            return Err(vault);
        }
        self.closed.normal.vault = Some(vault);
        Ok(())
    }
    pub(crate) fn closed_driver_facts(&self) -> Result<&DriverClosureFacts, Fault> {
        let facts = self
            .closed
            .normal
            .driver_facts
            .as_ref()
            .ok_or(Fault::MaterialMissing)?;
        if facts.live_proxy_futures != 0
            || self
                .closed
                .normal
                .driver_custody
                .as_ref()
                .is_none_or(|drivers| {
                    drivers.original_tasks_remaining() != 0
                        || drivers.original_destructions_missing() != 0
                        || drivers.live_proxy_future_count() != 0
                })
        {
            return Err(Fault::ClosingPending);
        }
        Ok(facts)
    }
    pub(crate) fn operation_directory(&self) -> &std::fs::File {
        &self.operation_directory
    }
    pub(crate) fn operation_path(&self) -> &std::path::Path {
        &self.operation_path
    }
    pub(crate) fn materials_mut(&mut self) -> Result<&mut materials::NormalCaptureMaterials, Fault> {
        self.closed.normal.materials.as_mut().ok_or(Fault::MaterialMissing)
    }
    pub(crate) fn restore_materials(
        &mut self, materials: materials::NormalCaptureMaterials,
    ) -> Result<(), materials::NormalCaptureMaterials> {
        if self.closed.normal.materials.is_some() { return Err(materials); }
        self.closed.normal.materials = Some(materials);
        Ok(())
    }
    pub(crate) fn take_materials(&mut self) -> Result<materials::NormalCaptureMaterials, Fault> {
        self.closed
            .normal
            .materials
            .take()
            .ok_or(Fault::MaterialMissing)
    }
}

pub(crate) struct RetainedCaptureFailure {
    fault: Fault,
    retained: RetainedCaptureOwners,
}
enum RetainedCaptureOwners {
    Normal(Box<NormalCaptureClosingOwner>),
    Closed(Box<NormalClosedToken>),
    Permit(Box<CaptureStartPermit>),
    Source(Box<crate::postgres_maintenance::capture::CaptureSourceOwner>),
}

impl RetainedCaptureFailure {
    pub(crate) fn fault(&self) -> Fault {
        self.fault
    }
    fn from_normal(normal: NormalCaptureClosingOwner, fault: Fault) -> Self {
        Self {
            fault,
            retained: RetainedCaptureOwners::Normal(Box::new(normal)),
        }
    }
    fn from_closed(closed: NormalClosedToken, fault: Fault) -> Self {
        Self {
            fault,
            retained: RetainedCaptureOwners::Closed(Box::new(closed)),
        }
    }
    pub(crate) fn from_permit(permit: CaptureStartPermit, fault: Fault) -> Self {
        Self {
            fault,
            retained: RetainedCaptureOwners::Permit(Box::new(permit)),
        }
    }
    pub(crate) fn from_source(
        source: crate::postgres_maintenance::capture::CaptureSourceOwner,
        fault: Fault,
    ) -> Self {
        Self {
            fault,
            retained: RetainedCaptureOwners::Source(Box::new(source)),
        }
    }
}

/// A read-only lookup of the existing host app-data root. Absence grants no capture right.
pub(crate) fn open_app_data_read_only(
    path: &std::path::Path,
) -> Result<Option<std::fs::File>, Fault> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(
        (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC)
            .bits() as i32,
    );
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Fault::PathUnsafe),
    };
    let held = file.metadata().map_err(|_| Fault::IoFailure)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| Fault::IoFailure)?;
    if !held.is_dir()
        || !named.is_dir()
        || held.uid() != rustix::process::geteuid().as_raw()
        || held.mode() & 0o077 != 0
        || (held.dev(), held.ino(), held.uid()) != (named.dev(), named.ino(), named.uid())
    {
        return Err(Fault::PathUnsafe);
    }
    Ok(Some(file))
}

pub(crate) async fn close_normal_for_capture(
    mut normal: NormalCaptureClosingOwner,
    operation: &CaptureOperation,
    control: &mut CaptureControlOwner,
) -> Result<NormalClosedToken, RetainedCaptureFailure> {
    let result = close_normal_originals(&mut normal, operation, control).await;
    match result {
        Ok(()) => Ok(NormalClosedToken {
            normal,
            retained_consumer_directory: None,
        }),
        Err(fault) => Err(RetainedCaptureFailure::from_normal(normal, fault)),
    }
}

async fn close_normal_originals(
    normal: &mut NormalCaptureClosingOwner,
    operation: &CaptureOperation,
    control: &mut CaptureControlOwner,
) -> Result<(), Fault> {
    let op = operation.shared_original()?;
    let original = normal.operation.upgrade().ok_or(Fault::ClockUnavailable)?;
    if !Arc::ptr_eq(&original, &op) || normal.intent.is_none() {
        return Err(Fault::IntentMismatch);
    }
    operation.require_normal_closing()?;
    // The original Intent has already been durably read back before this first close effect.
    normal
        .background
        .lifecycle
        .shutdown_authority()
        .map_err(|_| Fault::ClosingPending)?;
    normal.background.read_lifecycle.close();
    let remaining = operation.normal_closing_remaining_ns()?;
    tokio::time::timeout(
        std::time::Duration::from_nanos(remaining),
        normal
            .background
            .lifecycle
            .wait_local_confirmation_stopped(),
    )
    .await
    .map_err(|_| Fault::ClosingPending)?;
    operation.require_normal_closing()?;
    materials::stop_normal_writers(normal, &op).await?;
    operation.require_normal_closing()?;
    let remaining = operation.normal_closing_remaining_ns()?;
    let wait_deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_nanos(remaining))
        .ok_or(Fault::BoundsOverflow)?;
    normal
        .background
        .read_lifecycle
        .drain_before(wait_deadline)
        .await
        .map_err(|_| Fault::ClosingPending)?;
    operation.require_normal_closing()?;
    materials::freeze_original_preferences_for_normal(normal, control, &op).await?;
    operation.require_normal_closing()?;
    materials::collect_normal_materials(normal, &op).await?;
    operation.require_normal_closing()?;
    if normal.driver_custody.is_some()
        || normal.driver_facts.is_some()
        || normal.stop_task.is_some()
    {
        return Err(Fault::IntentMismatch);
    }
    let plane = normal
        .background
        .data_plane
        .as_mut()
        .ok_or(Fault::MaterialMissing)?;
    normal.driver_custody = Some(
        plane
            .capture_custody_mut()
            .ok_or(Fault::IntentMismatch)?
            .freeze()
            .map_err(|_| Fault::SourceChanged)?,
    );
    normal.driver_facts = Some(DriverClosureFacts {
        joined_before_freeze: 0,
        original_joins: Vec::new(),
        live_proxy_futures: u64::MAX,
    });
    join_original_drivers(
        normal
            .driver_custody
            .as_mut()
            .ok_or(Fault::MaterialMissing)?,
        operation,
        normal.driver_facts.as_mut().ok_or(Fault::MaterialMissing)?,
    )
    .await?;
    operation.require_normal_closing()?;
    let sidecar = normal
        .background
        .data_plane
        .as_mut()
        .ok_or(Fault::MaterialMissing)?
        .take_sidecar_for_capture()
        .ok_or(Fault::IntentMismatch)?;
    let clock = op.clock_view();
    // The real original task is retained before the first observer await.
    normal.stop_task = Some(tokio::spawn(async move {
        sidecar.stop_for_capture(clock.as_ref()).await
    }));
    let remaining = operation.normal_closing_remaining_ns()?;
    let joined = tokio::time::timeout(
        std::time::Duration::from_nanos(remaining),
        normal.stop_task.as_mut().ok_or(Fault::ClosingPending)?,
    )
    .await
    .map_err(|_| Fault::ClosingPending)?;
    let result = match joined {
        Ok(result) => result,
        Err(error) => {
            normal.stop_join_failure = Some(error);
            return Err(Fault::ClosingPending);
        }
    };
    normal.stop_task.take();
    match result {
        Ok(stopped) => normal.stopped = Some(stopped),
        Err(retained) => {
            let fault = retained.fault();
            normal.retained_stop_failure = Some(retained);
            return Err(fault);
        }
    }
    operation.require_normal_closing()?;
    normal
        .stopped
        .as_ref()
        .ok_or(Fault::ClosingPending)?
        .revalidate(operation)?;
    let facts = normal.driver_facts.as_ref().ok_or(Fault::MaterialMissing)?;
    let all = facts
        .joined_before_freeze
        .checked_add(facts.original_joins.len() as u64)
        .ok_or(Fault::BoundsOverflow)?;
    control
        .append(
            normal.intent.as_ref().ok_or(Fault::IntentMismatch)?,
            &op,
            control::ControlStage::NormalClosed,
            actual_stage_facts(all, all, facts.live_proxy_futures),
        )
        .await?;
    operation.require_normal_closing()
}

pub(crate) async fn consume_before_source_start(
    mut closed: NormalClosedToken,
    operation: &CaptureOperation,
    control: &mut CaptureControlOwner,
) -> Result<CaptureStartPermit, RetainedCaptureFailure> {
    let result = confirm_closed_original(&mut closed, operation, control).await;
    match result {
        Ok((operation_directory, operation_path)) => Ok(CaptureStartPermit {
            closed,
            operation_directory,
            operation_path,
        }),
        Err(fault) => Err(RetainedCaptureFailure::from_closed(closed, fault)),
    }
}
async fn confirm_closed_original(
    closed: &mut NormalClosedToken,
    operation: &CaptureOperation,
    control: &mut CaptureControlOwner,
) -> Result<(std::fs::File, std::path::PathBuf), Fault> {
    if closed.retained_consumer_directory.is_some() {
        return Err(Fault::IntentMismatch);
    }
    let op = operation.shared_original()?;
    let original = closed
        .normal
        .operation
        .upgrade()
        .ok_or(Fault::ClockUnavailable)?;
    if !Arc::ptr_eq(&original, &op) {
        return Err(Fault::IntentMismatch);
    }
    operation.require_effect()?;
    let normal = &closed.normal;
    normal
        .stopped
        .as_ref()
        .ok_or(Fault::ClosingPending)?
        .revalidate(operation)?;
    operation.require_effect()?;
    normal
        .vault
        .as_ref()
        .ok_or(Fault::SecretInvalid)?
        .revalidate_before(operation)?;
    let drivers = normal
        .driver_custody
        .as_ref()
        .ok_or(Fault::MaterialMissing)?;
    let facts = normal.driver_facts.as_ref().ok_or(Fault::MaterialMissing)?;
    if drivers.original_tasks_remaining() != 0
        || drivers.original_destructions_missing() != 0
        || drivers.live_proxy_future_count() != 0
        || facts.live_proxy_futures != 0
        || facts.original_joins.iter().any(|f| {
            f.destruction().is_none() || f.outcome() == OriginalDriverJoinOutcome::Panicked
        })
    {
        return Err(Fault::ClosingPending);
    }
    let witness = normal.intent.as_ref().ok_or(Fault::IntentMismatch)?;
    // This actual independent consumer runs after the original Child wait and before any source.
    control.confirm_before_source_start(witness, &op).await?;
    operation.require_effect()?;
    let all = facts
        .joined_before_freeze
        .checked_add(facts.original_joins.len() as u64)
        .ok_or(Fault::BoundsOverflow)?;
    control
        .append(
            witness,
            &op,
            control::ControlStage::ConsumerConfirmed,
            actual_stage_facts(all, all, 0),
        )
        .await?;
    operation.require_effect()?;
    let directory = control.operation_directory()?;
    let operation_path = control.operation_path()?.to_owned();
    operation.require_effect()?;
    let cloned = directory.try_clone();
    match cloned {
        Ok(file) => closed.retained_consumer_directory = Some(file),
        Err(_) => {
            operation.require_effect()?;
            return Err(Fault::IoFailure);
        }
    }
    operation.require_effect()?;
    // The original closed token retains this actual FD on every fallible path.
    // Nothing fallible or awaited follows the unique move into the permit tuple.
    Ok((
        closed
            .retained_consumer_directory
            .take()
            .expect("actual consumer directory remains resident"),
        operation_path,
    ))
}

fn actual_stage_facts(original: u64, joined: u64, proxies: u64) -> control::ControlStageFacts {
    control::ControlStageFacts {
        outcome: control::ControlOutcome::Actual,
        fault: None,
        issued_effects: 0,
        original_tasks: original,
        joined_original_tasks: joined,
        live_proxy_futures: proxies,
        parent_device: None,
        parent_inode: None,
        entry_device: None,
        entry_inode: None,
        output_bytes: None,
        output_sha256: None,
    }
}

#[cfg(test)]
mod resident_capture_step_tests {
    use super::{Fault, await_resident_capture_step};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    // A plain borrowed test allocation, not a capture job, source, clock, or capability.
    struct DropProbe {
        polls: usize,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    async fn panic_while_borrowing(probe: &mut DropProbe) -> Result<(), Fault> {
        probe.polls += 1;
        panic!("expected ordinary borrowed-step poll panic");
    }

    #[test]
    fn ordinary_poll_unwind_leaves_the_borrowed_probe_with_its_caller() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut probe = DropProbe {
            polls: 0,
            dropped: Arc::clone(&dropped),
        };
        {
            let mut step = std::pin::pin!(await_resident_capture_step(panic_while_borrowing(
                &mut probe
            )));
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(
                std::future::Future::poll(step.as_mut(), &mut context),
                Poll::Ready(Err(Fault::ClosingPending))
            ));
        }
        assert_eq!(probe.polls, 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(probe);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_only_a_pending_borrowed_step_does_not_drop_the_callers_probe() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut probe = DropProbe {
            polls: 0,
            dropped: Arc::clone(&dropped),
        };
        {
            let borrowed = std::future::poll_fn(|_| {
                probe.polls += 1;
                Poll::<Result<(), Fault>>::Pending
            });
            let mut step = std::pin::pin!(await_resident_capture_step(borrowed));
            let mut context = Context::from_waker(Waker::noop());
            assert!(std::future::Future::poll(step.as_mut(), &mut context).is_pending());
        }
        assert_eq!(probe.polls, 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(probe);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
pub(crate) fn original_capture_resources_for_test(
    bounds: &WholePgCarrierBounds,
) -> Result<Arc<Mutex<CaptureResourceTotals>>, Fault> {
    prepare_original_capture_resources(bounds)
}

#[cfg(test)]
mod original_capture_resource_tests {
    use super::*;

    fn book(fds: u64, metadata: u64) -> Arc<Mutex<CaptureResourceTotals>> {
        Arc::new(Mutex::new(CaptureResourceTotals {
            owner_instance: [1; 16], max_fds: fds, max_metadata: metadata,
            fd_admissions: 0, metadata_reserved: 0,
            original_control_storage: OriginalControlStorageFacts {
                objects: Vec::new(), original_owner: [1; 16],
                roots: [OriginalControlRootObservation::Unobserved; 4], classified: false,
                max_total_allocation_bytes: u64::MAX, max_retained_prior_bytes: u64::MAX,
                growth_ready: false, allocation_admitted: 0, allocation_observed_peak: 0,
                allocation_update_pending: false, object_slots_admitted: 0,
            },
        }))
    }

    #[test]
    fn a_two_dimension_rejection_never_partially_spends_or_refunds() {
        let resources = book(2, 10);
        reserve_capture_resources(&resources, 1, 7).unwrap();
        assert_eq!(reserve_capture_resources(&resources, 1, 4), Err(Fault::CapacityExceeded));
        assert_eq!(remaining_capture_resources(&resources), Ok((1, 3)));
        let carried = Arc::clone(&resources);
        drop(resources);
        assert_eq!(remaining_capture_resources(&carried), Ok((1, 3)));
        reserve_capture_resources(&carried, 1, 3).unwrap();
        assert_eq!(remaining_capture_resources(&carried), Ok((0, 0)));
        assert_eq!(reserve_capture_resources(&carried, 1, 0), Err(Fault::CapacityExceeded));
    }

    #[test]
    fn two_real_concurrent_callers_share_one_atomic_remaining_allowance() {
        let resources = book(1, 9);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let callers: Vec<_> = (0..2).map(|_| {
            let resources = Arc::clone(&resources);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                reserve_capture_resources(&resources, 1, 9)
            })
        }).collect();
        barrier.wait();
        let successes = callers.into_iter().map(|caller| caller.join().unwrap()).filter(|outcome| outcome.is_ok()).count();
        assert_eq!(successes, 1);
        assert_eq!(remaining_capture_resources(&resources), Ok((0, 0)));
    }

    #[test]
    fn arithmetic_overflow_and_poison_do_not_clear_original_counters() {
        let resources = book(u64::MAX, 10);
        resources.lock().unwrap().fd_admissions = u64::MAX - 1;
        assert_eq!(reserve_capture_resources(&resources, 2, 1), Err(Fault::BoundsOverflow));
        assert_eq!(remaining_capture_resources(&resources), Ok((1, 10)));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held_original = resources.lock().unwrap();
            panic!("original-capture-resource-book-poison");
        }));
        assert!(panic.is_err());
        assert_eq!(reserve_capture_resources(&resources, 0, 0), Err(Fault::ClosingPending));
        assert_eq!(remaining_capture_resources(&resources), Err(Fault::ClosingPending));
        let retained = match resources.lock() {
            Err(poisoned) => poisoned.into_inner(),
            Ok(_) => panic!("original poison must not be cleared"),
        };
        assert_eq!(retained.fd_admissions, u64::MAX - 1);
        assert_eq!(retained.metadata_reserved, 0);
    }


    fn original_storage_fixture(
        allocation_limit: u64,
        prior_limit: u64,
    ) -> (Arc<Mutex<CaptureResourceTotals>>, OriginalControlStorageFacts) {
        let resources = book(8, u64::MAX);
        {
            let mut totals = resources.lock().unwrap();
            totals.original_control_storage.max_total_allocation_bytes = allocation_limit;
            totals.original_control_storage.max_retained_prior_bytes = prior_limit;
        }
        let mut facts = OriginalControlStorageFacts {
            objects: Vec::with_capacity(8),
            original_owner: [1; 16],
            roots: [
                OriginalControlRootObservation::Present { device: 7, inode: 1 },
                OriginalControlRootObservation::Present { device: 7, inode: 2 },
                OriginalControlRootObservation::Present { device: 8, inode: 3 },
                OriginalControlRootObservation::Present { device: 8, inode: 4 },
            ],
            classified: true,
            max_total_allocation_bytes: allocation_limit,
            max_retained_prior_bytes: prior_limit,
            growth_ready: false, allocation_admitted: 0, allocation_observed_peak: 0,
            allocation_update_pending: false, object_slots_admitted: 0,
        };
        for (device, inode) in [(7, 1), (7, 2), (8, 3), (8, 4)] {
            facts.observe(device, inode, 1, 0).unwrap();
        }
        (resources, facts)
    }

    #[test]
    fn repeated_control_and_payload_inodes_keep_one_allocation_and_prior_charge() {
        let (resources, mut facts) = original_storage_fixture(3072, 800);
        facts.observe(7, 20, 2, 800).unwrap();
        facts.observe(7, 20, 2, 800).unwrap();
        facts.observe(7, 2, 1, 0).unwrap();
        assert_eq!(facts.objects.len(), 5);
        install_original_control_storage(&resources, facts).unwrap();
        let totals = resources.lock().unwrap();
        assert!(totals.original_control_storage.classified);
        assert_eq!(totals.original_control_storage.objects.len(), 5);
        assert_eq!(totals.fd_admissions, 0);
        assert_eq!(totals.metadata_reserved, 0);
    }

    #[test]
    fn device_subtotals_do_not_get_independent_global_caps_or_prior_allowances() {
        for (allocation_limit, prior_limit) in [(3071, 800), (3072, 799)] {
            let (resources, mut facts) = original_storage_fixture(allocation_limit, prior_limit);
            facts.observe(7, 20, 2, 800).unwrap();
            assert_eq!(install_original_control_storage(&resources, facts), Err(Fault::CapacityExceeded));
            let totals = resources.lock().unwrap();
            assert!(!totals.original_control_storage.classified);
            assert!(totals.original_control_storage.objects.is_empty());
            assert_eq!(totals.original_control_storage.max_total_allocation_bytes, allocation_limit);
            assert_eq!(totals.original_control_storage.max_retained_prior_bytes, prior_limit);
        }
    }

    #[test]
    fn conflicting_inode_or_substituted_owner_never_replaces_original_charged_state() {
        let (resources, mut facts) = original_storage_fixture(3072, 800);
        reserve_capture_resources(&resources, 1, 9).unwrap();
        facts.observe(7, 20, 2, 800).unwrap();
        assert_eq!(facts.observe(7, 20, 3, 800), Err(Fault::SourceChanged));
        assert_eq!(facts.objects.len(), 5);
        assert_eq!(facts.objects[4].allocation, 1024);
        facts.original_owner = [2; 16];
        assert_eq!(install_original_control_storage(&resources, facts), Err(Fault::IntentMismatch));
        let carried = Arc::clone(&resources);
        drop(resources);
        let totals = carried.lock().unwrap();
        assert!(!totals.original_control_storage.classified);
        assert!(totals.original_control_storage.objects.is_empty());
        assert_eq!(totals.fd_admissions, 1);
        assert_eq!(totals.metadata_reserved, 9);
    }

    #[test]
    fn frozen_storage_bounds_and_checked_allocation_overflow_refuse_partial_install() {
        for changed_bound in 0..2 {
            let (resources, mut facts) = original_storage_fixture(3072, 800);
            if changed_bound == 0 {
                facts.max_total_allocation_bytes += 1;
            } else {
                facts.max_retained_prior_bytes += 1;
            }
            assert_eq!(install_original_control_storage(&resources, facts), Err(Fault::IntentMismatch));
            let totals = resources.lock().unwrap();
            assert!(!totals.original_control_storage.classified);
            assert!(totals.original_control_storage.objects.is_empty());
        }
        let (resources, mut facts) = original_storage_fixture(u64::MAX, u64::MAX);
        facts.observe(9, 99, u64::MAX / 512, 0).unwrap();
        assert_eq!(install_original_control_storage(&resources, facts), Err(Fault::BoundsOverflow));
        let totals = resources.lock().unwrap();
        assert!(!totals.original_control_storage.classified);
        assert!(totals.original_control_storage.objects.is_empty());
    }

    #[test]
    fn control_growth_rejects_full_original_allocation_before_effect() {
        let (resources, facts) = original_storage_fixture(2048, 800);
        install_original_control_storage(&resources, facts).unwrap();
        mark_original_control_growth_after_history(&resources, [1;16]).unwrap();
        assert_eq!(reserve_original_control_growth(&resources, [1;16], 7, 2, 512, 1),
            Err(Fault::CapacityExceeded));
        let totals = resources.lock().unwrap();
        let facts = &totals.original_control_storage;
        assert!(facts.growth_ready);
        assert!(!facts.allocation_update_pending);
        assert_eq!(facts.allocation_admitted, 2048);
        assert_eq!(facts.allocation_observed_peak, 2048);
        assert_eq!(facts.object_slots_admitted, 4);
        assert_eq!(facts.objects.len(), 4);
        assert_eq!((totals.fd_admissions, totals.metadata_reserved), (0, 0));
    }

    #[test]
    fn control_growth_counts_alias_once_and_keeps_unknown_pending() {
        let (resources, facts) = original_storage_fixture(8192, 800);
        install_original_control_storage(&resources, facts).unwrap();
        mark_original_control_growth_after_history(&resources, [1;16]).unwrap();
        reserve_original_control_growth(&resources, [1;16], 7, 2, 512, 1).unwrap();
        observe_original_control_allocation(&resources, [1;16], [(7,2,1),(7,20,2)]).unwrap();
        {
            let totals = resources.lock().unwrap();
            let facts = &totals.original_control_storage;
            assert_eq!(facts.objects.len(), 5);
            assert_eq!(facts.allocation_admitted, 3072);
            assert_eq!(facts.allocation_observed_peak, 3072);
            assert!(!facts.allocation_update_pending);
        }
        reserve_original_control_growth(&resources, [1;16], 7, 2, 512, 0).unwrap();
        observe_original_control_allocation(&resources, [1;16], [(7,20,2),(7,20,2)]).unwrap();
        {
            let totals = resources.lock().unwrap();
            let facts = &totals.original_control_storage;
            assert_eq!(facts.objects.len(), 5);
            assert_eq!(facts.object_slots_admitted, 5);
            assert_eq!(facts.allocation_admitted, 3584);
            assert_eq!(facts.allocation_observed_peak, 3072);
        }
        reserve_original_control_growth(&resources, [1;16], 7, 2, 512, 0).unwrap();
        assert_eq!(observe_original_control_allocation(&resources, [1;16],
            [(7,2,1),(7,20,20)]), Err(Fault::CapacityExceeded));
        assert_eq!(reserve_original_control_growth(&resources, [1;16], 7, 2, 512, 0),
            Err(Fault::ClosingPending));
        {
            let totals = resources.lock().unwrap();
            let facts = &totals.original_control_storage;
            assert!(facts.allocation_update_pending);
            assert_eq!(facts.allocation_admitted, 4096);
            assert_eq!(facts.allocation_observed_peak, 12288);
            assert_eq!(facts.objects.len(), 5);
        }
        let (unknown, facts) = original_storage_fixture(8192, 800);
        install_original_control_storage(&unknown, facts).unwrap();
        mark_original_control_growth_after_history(&unknown, [1;16]).unwrap();
        reserve_original_control_growth(&unknown, [1;16], 7, 2, 512, 1).unwrap();
        assert_eq!(reserve_original_control_growth(&unknown, [1;16], 7, 2, 512, 1),
            Err(Fault::ClosingPending));
        let totals = unknown.lock().unwrap();
        assert!(totals.original_control_storage.allocation_update_pending);
        assert_eq!(totals.original_control_storage.allocation_admitted, 2560);
        assert_eq!(totals.original_control_storage.object_slots_admitted, 5);
    }
}
