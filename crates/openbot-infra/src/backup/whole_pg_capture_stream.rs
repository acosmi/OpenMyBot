//! Owned transport boundary for the independent capture carrier.
//! Construction is pure. Actual descriptors, clock, secrets, I/O and final publication
//! must all be checked by the original synchronous stream worker before a receipt exists.
use openbot_domain::backup::whole_pg_carrier::{
    WholePgOpenCodec, WholePgSealCodec, whole_pg_secret_matches,
};
use openbot_domain::backup::{
    FrozenWholePgManifest, WholePgCarrierBounds, WholePgCarrierFault, WholePgMaterialKind,
    WholePgSecretBounds,
};
use openbot_domain::vault::SecretBytes;
use rustix::fs::{AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub trait CaptureClockCheck: Send + Sync {
    fn require_effect(&self) -> Result<(), WholePgCarrierFault>;
    fn require_closing(&self) -> Result<(), WholePgCarrierFault>;
    fn effect_remaining_ns(&self) -> Result<u64, WholePgCarrierFault>;
    fn closing_remaining_ns(&self) -> Result<u64, WholePgCarrierFault>;
    fn observed_ns(&self) -> Result<u64, WholePgCarrierFault>;
}

pub enum WholePgOwnedSourceInput {
    File {
        material_id: String,
        file: File,
    },
    Secret {
        material_id: String,
        secret: SecretBytes,
    },
}
impl WholePgOwnedSourceInput {
    fn material_id(&self) -> &str {
        match self {
            Self::File { material_id, .. } | Self::Secret { material_id, .. } => material_id,
        }
    }
    fn is_secret(&self) -> bool {
        matches!(self, Self::Secret { .. })
    }
}

pub struct WholePgOwnedDirectoryInput {
    pub directory: File,
    pub expected_device: u64,
    pub expected_inode: u64,
    pub expected_uid: u32,
}
pub struct WholePgOwnedStreamParts {
    pub manifest: FrozenWholePgManifest,
    pub sources: Vec<WholePgOwnedSourceInput>,
    pub output: WholePgOwnedDirectoryInput,
    pub independent_key_medium: WholePgOwnedDirectoryInput,
    pub carrier_bounds: WholePgCarrierBounds,
    pub secret_bounds: WholePgSecretBounds,
}
pub struct OwnedCaptureStreamInputs {
    parts: WholePgOwnedStreamParts,
}
pub struct OwnedCaptureStreamFailure {
    fault: WholePgCarrierFault,
    // Before release, retain the genuine original FD/secret values on every failure.
    // After release, None and the recorded stage preserve that irreversible fact.
    retained: Option<WholePgOwnedStreamParts>,
    io: RetainedStreamIo,
    release_stage: StreamReleaseStage,
}
#[derive(Debug, PartialEq, Eq)]
enum StreamReleaseStage {
    Retained,
    // The original worker's concrete safe owned destructors returned. This is not a task join.
    Released,
}
pub struct CarrierReadbackReceipt {
    // A receipt cannot be manufactured by callers; only the actual worker may fill these.
    wire_bytes: u64,
    carrier_sha256: [u8; 32],
    key_verified: bool,
    temporary_verified: bool,
    published_verified: bool,
}
impl CarrierReadbackReceipt {
    /// Original authenticated carrier wire length; this observation grants no completion.
    pub fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }

    /// Original authenticated ciphertext digest; no resource or source capability is exposed.
    pub fn carrier_sha256(&self) -> &[u8; 32] {
        &self.carrier_sha256
    }

    /// Original key-medium verification observation; this grants no outer owner completion.
    pub fn key_medium_verified(&self) -> bool {
        self.key_verified
    }

    /// Original temporary readback observation; this grants no outer owner completion.
    pub fn temporary_verified(&self) -> bool {
        self.temporary_verified
    }

    /// Original published readback observation; this does not assert task or owner closure.
    pub fn published_verified(&self) -> bool {
        self.published_verified
    }
}

pub type OwnedCaptureStreamResult = Result<CarrierReadbackReceipt, OwnedCaptureStreamFailure>;

impl OwnedCaptureStreamInputs {
    pub fn from_owned_parts(
        parts: WholePgOwnedStreamParts,
    ) -> Result<Self, OwnedCaptureStreamFailure> {
        match check_parts(&parts) {
            Ok(_) => Ok(Self { parts }),
            Err(fault) => Err(OwnedCaptureStreamFailure {
                fault,
                retained: Some(parts),
                io: RetainedStreamIo::empty(),
                release_stage: StreamReleaseStage::Retained,
            }),
        }
    }
}
fn checked_add(a: u64, b: u64) -> Result<u64, WholePgCarrierFault> {
    a.checked_add(b).ok_or(WholePgCarrierFault::BoundsOverflow)
}
fn checked_mul(a: u64, b: u64) -> Result<u64, WholePgCarrierFault> {
    a.checked_mul(b).ok_or(WholePgCarrierFault::BoundsOverflow)
}
fn check_parts(parts: &WholePgOwnedStreamParts) -> Result<u64, WholePgCarrierFault> {
    let bounds = parts.carrier_bounds.check()?;
    parts.secret_bounds.check()?;
    if parts.sources.len() != parts.manifest.materials().len()
        || parts.sources.len() as u64 > bounds.max_material_files
    {
        return Err(WholePgCarrierFault::MaterialMissing);
    }
    let mut memory = checked_add(
        parts.manifest.metadata_bytes(),
        checked_add(
            checked_mul(
                parts.sources.capacity() as u64,
                std::mem::size_of::<WholePgOwnedSourceInput>() as u64,
            )?,
            checked_mul(parts.sources.len() as u64, 128)?,
        )?,
    )?;
    for source in &parts.sources {
        memory = checked_add(
            memory,
            match source {
                WholePgOwnedSourceInput::File { material_id, .. }
                | WholePgOwnedSourceInput::Secret { material_id, .. } => {
                    material_id.capacity() as u64
                }
            },
        )?;
    }
    if memory > bounds.max_metadata_bytes {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    // IDs are nonsecret bounded metadata. No descriptor metadata/read/open/random call here.
    let metadata_remaining = bounds
        .max_metadata_bytes
        .checked_sub(memory)
        .ok_or(WholePgCarrierFault::CapacityExceeded)?;
    memory = checked_add(
        memory,
        check_manifest_profile(&parts.manifest, bounds, metadata_remaining)?,
    )?;
    if memory > bounds.max_metadata_bytes {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    check_secret_inventory(
        parts,
        bounds
            .max_manifest_bytes
            .max(bounds.max_chunk_plain_bytes)
            .max(84),
    )?;
    let mut seen = BTreeSet::new();
    let mut secret_count = 0u64;
    let mut secret_total = 0u64;
    for source in &parts.sources {
        let id = source.material_id();
        if id.is_empty() || id.len() > 128 || !seen.insert(id) {
            return Err(WholePgCarrierFault::ManifestInvalid);
        }
        let material = parts
            .manifest
            .materials()
            .iter()
            .find(|entry| entry.material_id == id)
            .ok_or(WholePgCarrierFault::ExtraMaterial)?;
        if material.kind.is_secret() != source.is_secret() {
            return Err(WholePgCarrierFault::SecretInvalid);
        }
        if let WholePgOwnedSourceInput::Secret { secret, .. } = source {
            let expected = match material.kind {
                WholePgMaterialKind::MasterSecret => 32,
                WholePgMaterialKind::ScramSecret => 64,
                _ => return Err(WholePgCarrierFault::SecretInvalid),
            };
            if secret.len() != expected
                || secret.len() as u64 > parts.secret_bounds.max_one_source_secret_bytes
            {
                return Err(WholePgCarrierFault::SecretInvalid);
            }
            secret_count = checked_add(secret_count, 1)?;
            secret_total = checked_add(secret_total, secret.len() as u64)?;
        }
    }
    if secret_count != 2
        || secret_count > parts.secret_bounds.max_source_secret_count
        || secret_total > parts.secret_bounds.max_total_source_secret_bytes
    {
        return Err(WholePgCarrierFault::SecretInvalid);
    }
    Ok(memory)
}

fn check_manifest_profile(
    m: &FrozenWholePgManifest,
    b: WholePgCarrierBounds,
    metadata_remaining: u64,
) -> Result<u64, WholePgCarrierFault> {
    use WholePgCarrierFault as F;
    let h = m.header();
    let manifest = u32::from_be_bytes(h[28..32].try_into().map_err(|_| F::ManifestInvalid)?) as u64;
    let chunk = u32::from_be_bytes(h[32..36].try_into().map_err(|_| F::ManifestInvalid)?) as u64;
    let count = u32::from_be_bytes(h[36..40].try_into().map_err(|_| F::ManifestInvalid)?) as u64;
    let total = u64::from_be_bytes(h[40..48].try_into().map_err(|_| F::ManifestInvalid)?);
    if chunk != b.max_chunk_plain_bytes
        || manifest > b.max_manifest_bytes
        || count > b.max_data_chunks
        || total > b.max_material_plain_bytes
        || m.wire_bytes()? > b.max_wire_bytes
    {
        return Err(F::ProfileInvalid);
    }
    let mut lengths = 0u64;
    let mut chunks = 0u64;
    let mut directories = BTreeSet::new();
    for material in m.materials() {
        if material.plain_len > b.max_single_plain_bytes
            || material.relative_path.len() as u64 > b.max_path_bytes
            || material.relative_path.split('/').count() as u64 > b.max_path_depth
        {
            return Err(F::ProfileInvalid);
        }
        let n = if material.plain_len == 0 {
            0
        } else {
            checked_add(material.plain_len, chunk - 1)? / chunk
        };
        if n != material.chunk_count as u64 {
            return Err(F::ProfileInvalid);
        }
        lengths = checked_add(lengths, material.plain_len)?;
        chunks = checked_add(chunks, n)?;
        for (at, _) in material.relative_path.match_indices('/') {
            let parent = &material.relative_path[..at];
            if !directories.contains(parent) {
                let next = checked_add(directories.len() as u64, 1)?;
                // Debit the caller's shared remaining metadata before BTreeSet can
                // allocate; manifest, source containers and IDs are already resident.
                if next > b.max_directories || checked_mul(next, 128)? > metadata_remaining {
                    return Err(F::CapacityExceeded);
                }
                directories.insert(parent);
            }
        }
    }
    if lengths != total || chunks != count {
        return Err(F::ManifestInvalid);
    }
    checked_mul(directories.len() as u64, 128)
}
fn check_secret_inventory(
    parts: &WholePgOwnedStreamParts,
    frame: u64,
) -> Result<(), WholePgCarrierFault> {
    use WholePgCarrierFault as F;
    let s = parts.secret_bounds;
    let c = s.classes;
    if c.master_source.max_count < 1
        || c.master_source.max_one_bytes < 32
        || c.scram_source.max_count < 1
        || c.scram_source.max_one_bytes < 64
        || c.recovery_key.max_count < 1
        || c.recovery_key.max_one_bytes < 32
        || c.stream_key.max_count < 1
        || c.stream_key.max_one_bytes < 32
        || c.key_medium_readback.max_count < 2
        || c.key_medium_readback.max_one_bytes < 104
        || c.decode_crypto_temporary.max_count < 2
        || c.decode_crypto_temporary.max_one_bytes < 4096
    {
        return Err(F::CapacityExceeded);
    }
    let mut reserved = 0u64;
    for class in [
        c.master_source,
        c.credential_wrapping,
        c.remote_assertion_signing,
        c.application_derived,
        c.scram_source,
        c.pg_config_passwords,
        c.native_secret_frames,
        c.recovery_key,
        c.stream_key,
        c.key_medium_readback,
        c.decode_crypto_temporary,
    ] {
        reserved = checked_add(reserved, checked_mul(class.max_count, class.max_one_bytes)?)?;
    }
    // All eleven potentially resident classes share one maximum. K/codec/104B arrays/64B
    // secret accumulator are already inside those class reservations; count them once.
    // The unique frame and the sensitive manifest/container structure are additional.
    let structures = checked_add(
        parts.manifest.metadata_bytes(),
        checked_mul(
            parts.sources.capacity() as u64,
            std::mem::size_of::<WholePgOwnedSourceInput>() as u64,
        )?,
    )?;
    if structures > s.max_secret_structure_bytes
        || checked_add(reserved, checked_add(frame, structures)?)? > s.max_secret_memory_bytes
    {
        return Err(F::CapacityExceeded);
    }
    Ok(())
}
fn require_frame_capacity(
    parts: &WholePgOwnedStreamParts,
    len: u32,
    kind: u8,
    capacity: usize,
) -> Result<(), WholePgCarrierFault> {
    let maximum = match kind {
        0 => parts.carrier_bounds.max_manifest_bytes,
        1 => parts.carrier_bounds.max_chunk_plain_bytes,
        2 => 84,
        _ => return Err(WholePgCarrierFault::FrameInvalid),
    };
    if len as u64 > maximum || len as usize > capacity {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    Ok(())
}
fn allocation_grain(dir: &File, clock: &dyn CaptureClockCheck) -> Result<u64, WholePgCarrierFault> {
    clock.require_effect()?;
    let observed = rustix::fs::fstatvfs(dir);
    clock.require_effect()?;
    let st = observed.map_err(|_| WholePgCarrierFault::IoFailure)?;
    Ok(st.f_frsize.max(st.f_bsize).max(512))
}
fn rounded_allocation(bytes: u64, grain: u64) -> Result<u64, WholePgCarrierFault> {
    checked_mul(checked_add(bytes, grain - 1)? / grain, grain)
}
fn allocated_blocks(m: &Metadata) -> Result<u64, WholePgCarrierFault> {
    checked_mul(m.blocks(), 512)
}
fn directory_blocks(dir: &File, clock: &dyn CaptureClockCheck) -> Result<u64, WholePgCarrierFault> {
    clock.require_effect()?;
    let observed = dir.metadata();
    clock.require_effect()?;
    let m = observed.map_err(io_fault)?;
    allocated_blocks(&m)
}

// Original worker-owned resources survive every ordinary failure. No public constructor or Clone.
struct RetainedStreamIo {
    key: Option<SecretBytes>,
    files: Vec<File>,
    key_verified: bool,
    temporary_verified: bool,
    published_verified: bool,
}
impl RetainedStreamIo {
    fn empty() -> Self {
        Self {
            key: None,
            files: Vec::new(),
            key_verified: false,
            temporary_verified: false,
            published_verified: false,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl FileIdentity {
    fn from(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            mode: m.mode(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}

/// Synchronous single original stream worker. It owns all source FDs and secrets; its caller
/// must store the original blocking JoinHandle before awaiting and retain it on cancellation.
pub fn run_owned_stream(
    inputs: OwnedCaptureStreamInputs,
    clock: Arc<dyn CaptureClockCheck + Send + Sync>,
) -> OwnedCaptureStreamResult {
    let mut retained = Some(inputs.parts);
    let mut io = RetainedStreamIo::empty();
    let mut release_stage = StreamReleaseStage::Retained;
    // The closure borrows the original resident owners. A caught ordinary panic cannot
    // discard live inputs, or turn an irreversible release followed by a clock fault into success.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let verified = stream(
            retained
                .as_mut()
                .ok_or(WholePgCarrierFault::ClosingPending)?,
            &mut io,
            clock.as_ref(),
        )?;
        clock.require_closing()?;
        // Concrete File/SecretBytes and owned manifest/Vec drops are safe and non-fallible here.
        // No resource-owning local, callback, allocation or await interrupts this release.
        drop(retained.take());
        drop(std::mem::take(&mut io.files));
        drop(io.key.take());
        release_stage = StreamReleaseStage::Released;
        clock.require_closing()?;
        Ok(verified)
    }))
    .unwrap_or(Err(WholePgCarrierFault::ClosingPending));
    match result {
        Ok((wire_bytes, carrier_sha256)) => Ok(CarrierReadbackReceipt {
            wire_bytes,
            carrier_sha256,
            key_verified: io.key_verified,
            temporary_verified: io.temporary_verified,
            published_verified: io.published_verified,
        }),
        Err(fault) => Err(OwnedCaptureStreamFailure {
            fault,
            retained,
            io,
            release_stage,
        }),
    }
}
fn stream(
    parts: &mut WholePgOwnedStreamParts,
    io: &mut RetainedStreamIo,
    clock: &dyn CaptureClockCheck,
) -> Result<(u64, [u8; 32]), WholePgCarrierFault> {
    use WholePgCarrierFault as F;
    let parts_metadata = check_parts(parts)?;
    clock.require_effect()?;
    let b = parts.carrier_bounds;
    let s = parts.secret_bounds;
    let frame_capacity = b.max_manifest_bytes.max(b.max_chunk_plain_bytes).max(84);
    if frame_capacity > 4 * 1024 * 1024
        || parts.manifest.metadata_bytes() > b.max_metadata_bytes
        || checked_add(
            parts.manifest.metadata_bytes(),
            checked_mul(parts.sources.len() as u64, 256)?,
        )? > b.max_metadata_bytes
    {
        return Err(F::CapacityExceeded);
    }
    // Every acquired original stays resident, including the fixed two-name checks.
    // This is the local simultaneous inventory, not an operation-wide FD remainder.
    let created_files = 2u64; // independent key and temporary output
    let fresh_key_reads = 1u64;
    let full_readbacks = 2u64; // temporary and final, one new FD each
    let linked_name_reads = checked_mul(2, 2)?; // two calls, both [temporary, final]
    let final_entry_reads = 3u64; // final inode, final key, final binding
    let new_files = [
        created_files,
        fresh_key_reads,
        full_readbacks,
        linked_name_reads,
        final_entry_reads,
    ]
    .into_iter()
    .try_fold(0u64, checked_add)?;
    let source_files = parts.sources.iter().try_fold(0u64, |count, source| {
        if matches!(source, WholePgOwnedSourceInput::File { .. }) {
            checked_add(count, 1)
        } else {
            Ok(count)
        }
    })?;
    let planned_files = checked_add(io.files.len() as u64, new_files)?;
    if checked_add(source_files, checked_add(2, planned_files)?)? > b.max_open_files {
        return Err(F::CapacityExceeded);
    }
    let planned_files = usize::try_from(planned_files).map_err(|_| F::CapacityExceeded)?;
    let parts_metadata = checked_add(
        parts_metadata,
        checked_add(
            std::mem::size_of::<RetainedStreamIo>() as u64,
            std::mem::size_of::<Vec<Option<FileIdentity>>>() as u64,
        )?,
    )?;
    let requested_identity_bytes = checked_mul(
        parts.sources.len() as u64,
        std::mem::size_of::<Option<FileIdentity>>() as u64,
    )?;
    let file_metadata_remaining = b
        .max_metadata_bytes
        .checked_sub(checked_add(parts_metadata, requested_identity_bytes)?)
        .ok_or(F::CapacityExceeded)?;
    if checked_mul(
        io.files.capacity().max(planned_files) as u64,
        std::mem::size_of::<File>() as u64,
    )? > file_metadata_remaining
    {
        return Err(F::CapacityExceeded);
    }
    io.files
        .try_reserve_exact(usize::try_from(new_files).map_err(|_| F::CapacityExceeded)?)
        .map_err(|_| F::CapacityExceeded)?;
    let file_metadata_bytes = checked_mul(
        io.files.capacity() as u64,
        std::mem::size_of::<File>() as u64,
    )?;
    if file_metadata_bytes > file_metadata_remaining {
        return Err(F::CapacityExceeded);
    }
    let mut identities = Vec::new();
    identities
        .try_reserve_exact(parts.sources.len())
        .map_err(|_| F::CapacityExceeded)?;
    if checked_add(
        parts_metadata,
        checked_add(
            file_metadata_bytes,
            checked_mul(
                identities.capacity() as u64,
                std::mem::size_of::<Option<FileIdentity>>() as u64,
            )?,
        )?,
    )? > b.max_metadata_bytes
    {
        return Err(F::CapacityExceeded);
    }
    check_secret_inventory(parts, frame_capacity)?;
    verify_directory(&parts.output, clock)?;
    verify_directory(&parts.independent_key_medium, clock)?;
    if parts.output.expected_device == parts.independent_key_medium.expected_device
        && parts.output.expected_inode == parts.independent_key_medium.expected_inode
    {
        return Err(F::PathUnsafe);
    }
    let wire = parts.manifest.wire_bytes()?;
    if wire > b.max_wire_bytes {
        return Err(F::CapacityExceeded);
    }
    // Include both new names of the same sealed inode once, all retained source/spool allocation,
    // old output reserve, journal reserve and explicit capacity margin on the actual device.
    let output_grain = allocation_grain(&parts.output.directory, clock)?;
    let key_grain = allocation_grain(&parts.independent_key_medium.directory, clock)?;
    let output_file_limit = rounded_allocation(wire, output_grain)?;
    let key_file_limit = rounded_allocation(104, key_grain)?;
    let output_parent_before = directory_blocks(&parts.output.directory, clock)?;
    let key_parent_before = directory_blocks(&parts.independent_key_medium.directory, clock)?;
    let output_parent_limit = checked_mul(output_grain, 2)?;
    let key_parent_limit = key_grain;
    let prior_reservation = checked_add(
        b.max_retained_prior_bytes,
        checked_add(
            b.max_snapshot_bytes,
            checked_add(b.max_spool_bytes, b.max_journal_bytes)?,
        )?,
    )?;
    let output_need = checked_add(
        prior_reservation,
        checked_add(output_file_limit, output_parent_limit)?,
    )?;
    let key_need = checked_add(key_file_limit, key_parent_limit)?;
    let total_need = checked_add(output_need, key_need)?;
    if total_need > b.max_total_allocation_bytes || key_need > b.max_key_medium_allocation_bytes {
        return Err(F::CapacityExceeded);
    }
    let same_device = parts.output.expected_device == parts.independent_key_medium.expected_device;
    ensure_space(
        &parts.output.directory,
        if same_device { total_need } else { output_need },
        b.capacity_reserve_bytes,
        b.free_floor_bytes,
        clock,
    )?;
    ensure_space(
        &parts.independent_key_medium.directory,
        if same_device { total_need } else { key_need },
        b.key_medium_reserve_bytes.max(if same_device {
            b.capacity_reserve_bytes
        } else {
            0
        }),
        b.key_medium_free_floor_bytes
            .max(if same_device { b.free_floor_bytes } else { 0 }),
        clock,
    )?;
    let mut buffer = Zeroizing::new(Vec::new());
    buffer
        .try_reserve_exact(usize::try_from(frame_capacity).map_err(|_| F::CapacityExceeded)?)
        .map_err(|_| F::CapacityExceeded)?;
    if buffer.capacity() as u64 > frame_capacity {
        return Err(F::CapacityExceeded);
    }
    for source in &parts.sources {
        identities.push(match source {
            WholePgOwnedSourceInput::File { file, .. } => Some(source_metadata(file, clock)?),
            _ => None,
        });
    }
    verify_sources(parts, &identities, &mut buffer, clock)?;
    let bundle =
        uuid::Uuid::parse_str(&parts.manifest.claim().bundle_id).map_err(|_| F::ManifestInvalid)?;
    let op = uuid::Uuid::parse_str(&parts.manifest.claim().operation_id)
        .map_err(|_| F::ManifestInvalid)?;
    let bundle32 = bundle.simple().to_string();
    let key_name = format!("wrokbot-capture-{bundle32}.key");
    let temporary = format!(".wrokbot-capture-{bundle32}.partial");
    let final_name = format!("wrokbot-capture-{bundle32}.wbpg");
    let mut random = Zeroizing::new(vec![0u8; 32]);
    clock.require_effect()?;
    let generated = getrandom::fill(random.as_mut_slice());
    if generated.is_ok() {
        io.key = Some(SecretBytes::new(std::mem::take(&mut *random)));
    }
    clock.require_effect()?;
    generated.map_err(|_| F::IoFailure)?;
    let key = io.key.as_ref().ok_or(F::SecretInvalid)?;
    let mut key_bytes = Zeroizing::new([0u8; 104]);
    key_bytes[..8].copy_from_slice(b"WBPGKEY1");
    key_bytes[8..24].copy_from_slice(bundle.as_bytes());
    key_bytes[24..40].copy_from_slice(op.as_bytes());
    key_bytes[40..72].copy_from_slice(&parts.manifest.header()[48..80]);
    key_bytes[72..104].copy_from_slice(key.expose());
    let key_fd = create_new(&parts.independent_key_medium.directory, &key_name, clock)?;
    io.files.push(key_fd);
    clock.require_effect()?;
    let key_index = io.files.len() - 1;
    write_all_at(&io.files[key_index], 0, key_bytes.as_slice(), clock)?;
    synced(&io.files[key_index], clock)?;
    synced(&parts.independent_key_medium.directory, clock)?;
    let key_original = private_regular(&io.files[key_index], 1, clock)?;
    if allocated_blocks(&key_original)? > key_file_limit {
        return Err(F::CapacityExceeded);
    }
    if key_original.len() != 104 {
        return Err(F::KeyMediumInvalid);
    }
    let fresh_key = open_read(
        &parts.independent_key_medium.directory,
        &key_name,
        &mut io.files,
        clock,
    )?;
    let read_meta = private_regular(&io.files[fresh_key], 1, clock)?;
    if FileIdentity::from(&read_meta) != FileIdentity::from(&key_original) {
        return Err(F::KeyMediumInvalid);
    }
    let mut observed = Zeroizing::new([0u8; 104]);
    read_exact_at(&io.files[fresh_key], 0, observed.as_mut_slice(), clock)?;
    eof_at(&io.files[fresh_key], 104, clock)?;
    // Compare all 104 bytes with a constant-time fold, including K and every public binding.
    let mut difference = 0u8;
    for (a, b) in observed.iter().zip(key_bytes.iter()) {
        difference |= a ^ b;
    }
    if difference != 0 {
        return Err(F::KeyMediumInvalid);
    }
    observed.zeroize();
    key_bytes.zeroize();
    verify_directory(&parts.independent_key_medium, clock)?;
    io.key_verified = true;
    let output = create_new(&parts.output.directory, &temporary, clock)?;
    io.files.push(output);
    clock.require_effect()?;
    let output_index = io.files.len() - 1;
    let output_file = &io.files[output_index];
    let mut codec =
        WholePgSealCodec::new(io.key.as_ref().ok_or(F::SecretInvalid)?, &parts.manifest)?;
    let header = parts.manifest.header();
    write_all_at(output_file, 0, &header, clock)?;
    let mut at = 80u64;
    let mut frame_count = 0u64;
    let mut terminal = false;
    while let Some(spec) = codec.next_frame() {
        clock.require_effect()?;
        buffer.zeroize();
        buffer.clear();
        require_frame_capacity(parts, spec.plain_len(), spec.kind(), buffer.capacity())?;
        match spec.kind() {
            0 => parts.manifest.encode_manifest_into(&mut buffer)?,
            1 => {
                let material = parts
                    .manifest
                    .materials()
                    .get(spec.material_ordinal() as usize)
                    .ok_or(F::MaterialMissing)?;
                let source = parts
                    .sources
                    .iter()
                    .find(|v| v.material_id() == material.material_id)
                    .ok_or(F::MaterialMissing)?;
                buffer.resize(spec.plain_len() as usize, 0);
                match source {
                    WholePgOwnedSourceInput::File { file, .. } => {
                        read_exact_at(file, spec.offset(), buffer.as_mut_slice(), clock)?
                    }
                    WholePgOwnedSourceInput::Secret { secret, .. } => {
                        let offset =
                            usize::try_from(spec.offset()).map_err(|_| F::BoundsOverflow)?;
                        let end = offset.checked_add(buffer.len()).ok_or(F::BoundsOverflow)?;
                        buffer.copy_from_slice(
                            secret.expose().get(offset..end).ok_or(F::SecretInvalid)?,
                        );
                    }
                }
            }
            2 => {
                parts.manifest.encode_terminal_into(&mut buffer)?;
                terminal = true;
            }
            _ => return Err(F::FrameInvalid),
        }
        let sealed = codec.seal_next_in_place(&mut buffer)?;
        write_all_at(output_file, at, &sealed.header, clock)?;
        at = checked_add(at, 21)?;
        write_all_at(output_file, at, buffer.as_slice(), clock)?;
        at = checked_add(at, buffer.len() as u64)?;
        write_all_at(output_file, at, &sealed.tag, clock)?;
        at = checked_add(at, 16)?;
        buffer.zeroize();
        buffer.clear();
        frame_count = checked_add(frame_count, 1)?;
        if at > b.max_wire_bytes || frame_count > b.max_data_chunks + 2 {
            return Err(F::CapacityExceeded);
        }
    }
    drop(codec);
    if !terminal || at != wire {
        return Err(F::TerminalMissing);
    }
    synced(output_file, clock)?;
    let temp_identity = FileIdentity::from(&private_regular(output_file, 1, clock)?);
    if allocated_blocks(&private_regular(output_file, 1, clock)?)? > output_file_limit {
        return Err(F::CapacityExceeded);
    }
    if temp_identity.len != wire {
        return Err(F::ShortRead);
    }
    verify_sources(parts, &identities, &mut buffer, clock)?;
    let temporary_hash = readback(
        parts,
        &temporary,
        io.key.as_ref().ok_or(F::SecretInvalid)?,
        temp_identity,
        1,
        &mut buffer,
        &mut io.files,
        clock,
    )?;
    io.temporary_verified = true;
    verify_sources(parts, &identities, &mut buffer, clock)?;
    verify_directory(&parts.output, clock)?;
    // Exact no-replace transaction. An EEXIST or an uncertain result retains all names and K.
    clock.require_effect()?;
    let linked = rustix::fs::linkat(
        &parts.output.directory,
        temporary.as_str(),
        &parts.output.directory,
        final_name.as_str(),
        AtFlags::empty(),
    );
    clock.require_effect()?;
    linked.map_err(|_| F::PublishUnknown)?;
    verify_named_pair(
        &parts.output.directory,
        &temporary,
        &final_name,
        temp_identity,
        2,
        &mut io.files,
        clock,
    )?;
    synced(&parts.output.directory, clock)?;
    verify_named_pair(
        &parts.output.directory,
        &temporary,
        &final_name,
        temp_identity,
        2,
        &mut io.files,
        clock,
    )?;
    clock.require_effect()?;
    let unlinked = rustix::fs::unlinkat(
        &parts.output.directory,
        temporary.as_str(),
        AtFlags::empty(),
    );
    clock.require_effect()?;
    unlinked.map_err(|_| F::PublishUnknown)?;
    synced(&parts.output.directory, clock)?;
    let final_fd = open_read(&parts.output.directory, &final_name, &mut io.files, clock)?;
    let final_meta = private_regular(&io.files[final_fd], 1, clock)?;
    if !same_inode(temp_identity, FileIdentity::from(&final_meta)) {
        return Err(F::PublishUnknown);
    }
    verify_sources(parts, &identities, &mut buffer, clock)?;
    let final_hash = readback(
        parts,
        &final_name,
        io.key.as_ref().ok_or(F::SecretInvalid)?,
        FileIdentity::from(&final_meta),
        1,
        &mut buffer,
        &mut io.files,
        clock,
    )?;
    if temporary_hash != final_hash {
        return Err(F::ReadbackFailed);
    }
    verify_sources(parts, &identities, &mut buffer, clock)?;
    verify_directory(&parts.output, clock)?;
    verify_directory(&parts.independent_key_medium, clock)?;
    buffer.zeroize();
    buffer.clear();
    // Publication must leave the already verified independent key entry bound to its original FD.
    let key_final = open_read(
        &parts.independent_key_medium.directory,
        &key_name,
        &mut io.files,
        clock,
    )?;
    if FileIdentity::from(&private_regular(&io.files[key_final], 1, clock)?)
        != FileIdentity::from(&key_original)
        || FileIdentity::from(&private_regular(&io.files[key_index], 1, clock)?)
            != FileIdentity::from(&key_original)
    {
        return Err(F::KeyMediumInvalid);
    }
    let final_binding = open_read(&parts.output.directory, &final_name, &mut io.files, clock)?;
    if FileIdentity::from(&private_regular(&io.files[final_binding], 1, clock)?)
        != FileIdentity::from(&final_meta)
    {
        return Err(F::PublishUnknown);
    }
    let out_growth =
        directory_blocks(&parts.output.directory, clock)?.saturating_sub(output_parent_before);
    let key_growth = directory_blocks(&parts.independent_key_medium.directory, clock)?
        .saturating_sub(key_parent_before);
    let out_actual = allocated_blocks(&private_regular(&io.files[final_binding], 1, clock)?)?;
    let key_actual = allocated_blocks(&private_regular(&io.files[key_final], 1, clock)?)?;
    if out_growth > output_parent_limit
        || key_growth > key_parent_limit
        || out_actual > output_file_limit
        || key_actual > key_file_limit
        || checked_add(
            prior_reservation,
            checked_add(
                checked_add(out_actual, out_growth)?,
                checked_add(key_actual, key_growth)?,
            )?,
        )? > b.max_total_allocation_bytes
        || checked_add(key_actual, key_growth)? > b.max_key_medium_allocation_bytes
    {
        return Err(F::CapacityExceeded);
    }
    io.published_verified = true;
    clock.require_effect()?;
    Ok((wire, final_hash))
}
fn source_metadata(
    file: &File,
    clock: &dyn CaptureClockCheck,
) -> Result<FileIdentity, WholePgCarrierFault> {
    let m = private_regular(file, 1, clock)?;
    Ok(FileIdentity::from(&m))
}
fn private_regular(
    file: &File,
    links: u64,
    clock: &dyn CaptureClockCheck,
) -> Result<Metadata, WholePgCarrierFault> {
    clock.require_effect()?;
    let observed = file.metadata();
    clock.require_effect()?;
    let m = observed.map_err(io_fault)?;
    if !m.is_file()
        || m.nlink() != links
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7077 != 0
    {
        return Err(WholePgCarrierFault::PathUnsafe);
    }
    Ok(m)
}
fn verify_sources(
    parts: &WholePgOwnedStreamParts,
    identities: &[Option<FileIdentity>],
    buffer: &mut Zeroizing<Vec<u8>>,
    clock: &dyn CaptureClockCheck,
) -> Result<(), WholePgCarrierFault> {
    use WholePgCarrierFault as F;
    for (source, id) in parts.sources.iter().zip(identities) {
        clock.require_effect()?;
        let material = parts
            .manifest
            .materials()
            .iter()
            .find(|v| v.material_id == source.material_id())
            .ok_or(F::MaterialMissing)?;
        let mut sha = Sha256::new();
        match source {
            WholePgOwnedSourceInput::File { file, .. } => {
                let expected = id.ok_or(F::SourceChanged)?;
                if source_metadata(file, clock)? != expected || expected.len != material.plain_len {
                    return Err(F::SourceChanged);
                }
                let mut at = 0u64;
                while at < expected.len {
                    buffer.zeroize();
                    buffer.clear();
                    let count = (expected.len - at).min(parts.carrier_bounds.max_chunk_plain_bytes)
                        as usize;
                    buffer.resize(count, 0);
                    read_exact_at(file, at, buffer.as_mut_slice(), clock)?;
                    sha.update(buffer.as_slice());
                    at = checked_add(at, count as u64)?;
                }
                eof_at(file, expected.len, clock)?;
                if source_metadata(file, clock)? != expected {
                    return Err(F::SourceChanged);
                }
            }
            WholePgOwnedSourceInput::Secret { secret, .. } => {
                if secret.len() as u64 != material.plain_len {
                    return Err(F::SecretInvalid);
                }
                sha.update(secret.expose());
            }
        }
        let mut digest: [u8; 32] = sha.finalize().into();
        let matches = digest == material.plain_sha256;
        digest.zeroize();
        if !matches {
            return Err(F::SourceChanged);
        }
    }
    buffer.zeroize();
    buffer.clear();
    Ok(())
}
fn readback(
    parts: &WholePgOwnedStreamParts,
    name: &str,
    key: &SecretBytes,
    expected: FileIdentity,
    nlink: u64,
    buffer: &mut Zeroizing<Vec<u8>>,
    files: &mut Vec<File>,
    clock: &dyn CaptureClockCheck,
) -> Result<[u8; 32], WholePgCarrierFault> {
    use WholePgCarrierFault as F;
    verify_directory(&parts.output, clock)?;
    let file_index = open_read(&parts.output.directory, name, files, clock)?;
    let file = &files[file_index];
    let before = FileIdentity::from(&private_regular(file, nlink, clock)?);
    if before != expected {
        return Err(F::SourceChanged);
    }
    let mut header = [0u8; 80];
    read_exact_at(file, 0, &mut header, clock)?;
    let mut wire_hash = Sha256::new();
    wire_hash.update(header);
    let mut codec = WholePgOpenCodec::new(key, &parts.manifest, &header)?;
    let mut at = 80u64;
    let mut terminal = false;
    let mut count = 0u64;
    let mut ordinal = 0usize;
    let mut material_hash = Sha256::new();
    let mut material_len = 0u64;
    let mut decoded_secret = Zeroizing::new([0u8; 64]);
    // Empty ordinary files have no data frames; account for them at each ordinal transition.
    let finish_material = |ordinal: usize, hash: Sha256, len: u64| -> Result<(), F> {
        let claim = parts
            .manifest
            .materials()
            .get(ordinal)
            .ok_or(F::MaterialMissing)?;
        let mut digest: [u8; 32] = hash.finalize().into();
        let matches = digest == claim.plain_sha256 && len == claim.plain_len;
        digest.zeroize();
        if !matches {
            return Err(F::ReadbackFailed);
        }
        Ok(())
    };
    while let Some(spec) = codec.next_frame() {
        clock.require_effect()?;
        let mut frame_header = [0u8; 21];
        read_exact_at(file, at, &mut frame_header, clock)?;
        at = checked_add(at, 21)?;
        wire_hash.update(frame_header);
        buffer.zeroize();
        buffer.clear();
        require_frame_capacity(parts, spec.plain_len(), spec.kind(), buffer.capacity())?;
        buffer.resize(spec.plain_len() as usize, 0);
        read_exact_at(file, at, buffer.as_mut_slice(), clock)?;
        at = checked_add(at, buffer.len() as u64)?;
        wire_hash.update(buffer.as_slice());
        let mut tag = [0u8; 16];
        read_exact_at(file, at, &mut tag, clock)?;
        at = checked_add(at, 16)?;
        wire_hash.update(tag);
        codec.open_next_in_place(&frame_header, &tag, buffer)?;
        if spec.kind() == 1 {
            let target = spec.material_ordinal() as usize;
            while ordinal < target {
                finish_material(
                    ordinal,
                    std::mem::replace(&mut material_hash, Sha256::new()),
                    material_len,
                )?;
                ordinal += 1;
                material_len = 0;
            }
            let material = parts
                .manifest
                .materials()
                .get(ordinal)
                .ok_or(F::MaterialMissing)?;
            if spec.offset() != material_len {
                return Err(F::FrameInvalid);
            }
            if material.kind.is_secret() {
                let source = parts
                    .sources
                    .iter()
                    .find(|v| v.material_id() == material.material_id)
                    .ok_or(F::MaterialMissing)?;
                let WholePgOwnedSourceInput::Secret { secret, .. } = source else {
                    return Err(F::SecretInvalid);
                };
                let begin = usize::try_from(spec.offset()).map_err(|_| F::BoundsOverflow)?;
                let end = begin.checked_add(buffer.len()).ok_or(F::BoundsOverflow)?;
                decoded_secret
                    .get_mut(begin..end)
                    .ok_or(F::SecretInvalid)?
                    .copy_from_slice(buffer.as_slice());
                if end as u64 == material.plain_len {
                    if !whole_pg_secret_matches(secret, &decoded_secret[..end]) {
                        return Err(F::SecretInvalid);
                    }
                    decoded_secret.zeroize();
                }
            }
            material_hash.update(buffer.as_slice());
            material_len = checked_add(material_len, buffer.len() as u64)?;
        } else if spec.kind() == 2 {
            terminal = true;
        }
        buffer.zeroize();
        buffer.clear();
        count = checked_add(count, 1)?;
    }
    while ordinal < parts.manifest.materials().len() {
        finish_material(
            ordinal,
            std::mem::replace(&mut material_hash, Sha256::new()),
            material_len,
        )?;
        ordinal += 1;
        material_len = 0;
    }
    if !terminal
        || at != parts.manifest.wire_bytes()?
        || count > parts.carrier_bounds.max_data_chunks + 2
    {
        return Err(F::TerminalMissing);
    }
    eof_at(file, at, clock)?;
    if FileIdentity::from(&private_regular(file, nlink, clock)?) != before {
        return Err(F::SourceChanged);
    }
    verify_directory(&parts.output, clock)?;
    Ok(wire_hash.finalize().into())
}
fn same_inode(a: FileIdentity, b: FileIdentity) -> bool {
    a.dev == b.dev && a.ino == b.ino && a.uid == b.uid && a.mode == b.mode && a.len == b.len
}
fn verify_named_pair(
    parent: &File,
    a: &str,
    b: &str,
    expected: FileIdentity,
    links: u64,
    files: &mut Vec<File>,
    clock: &dyn CaptureClockCheck,
) -> Result<(), WholePgCarrierFault> {
    for name in [a, b] {
        let index = open_read(parent, name, files, clock)?;
        let actual = FileIdentity::from(&private_regular(&files[index], links, clock)?);
        if !same_inode(actual, expected) {
            return Err(WholePgCarrierFault::PublishUnknown);
        }
    }
    Ok(())
}
fn verify_directory(
    input: &WholePgOwnedDirectoryInput,
    clock: &dyn CaptureClockCheck,
) -> Result<(), WholePgCarrierFault> {
    clock.require_effect()?;
    let observed = input.directory.metadata();
    clock.require_effect()?;
    let m = observed.map_err(io_fault)?;
    if !m.is_dir()
        || m.dev() != input.expected_device
        || m.ino() != input.expected_inode
        || m.uid() != input.expected_uid
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o700
    {
        return Err(WholePgCarrierFault::PathUnsafe);
    }
    Ok(())
}
fn ensure_space(
    dir: &File,
    needed: u64,
    reserve: u64,
    floor: u64,
    clock: &dyn CaptureClockCheck,
) -> Result<(), WholePgCarrierFault> {
    clock.require_effect()?;
    let observed = rustix::fs::fstatvfs(dir);
    clock.require_effect()?;
    let stat = observed.map_err(|_| WholePgCarrierFault::IoFailure)?;
    let free = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
    if free < checked_add(needed, reserve.max(floor))? {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    Ok(())
}
fn create_new(
    parent: &File,
    name: &str,
    clock: &dyn CaptureClockCheck,
) -> Result<File, WholePgCarrierFault> {
    clock.require_effect()?;
    // On success the caller retains the returned FD before the post-call clock check.
    let opened = rustix::fs::openat(
        parent,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map(File::from);
    match opened {
        Ok(file) => Ok(file),
        Err(_) => {
            clock.require_effect()?;
            Err(WholePgCarrierFault::IoFailure)
        }
    }
}
fn open_read(
    parent: &File,
    name: &str,
    files: &mut Vec<File>,
    clock: &dyn CaptureClockCheck,
) -> Result<usize, WholePgCarrierFault> {
    // The original worker reserved every acquisition before its first I/O. Refuse
    // before opening if no slot remains; Ok -> push cannot allocate or fail.
    if files.len() == files.capacity() {
        return Err(WholePgCarrierFault::CapacityExceeded);
    }
    clock.require_effect()?;
    let opened = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from);
    match opened {
        Ok(file) => {
            let index = files.len();
            files.push(file);
            clock.require_effect()?;
            Ok(index)
        }
        Err(_) => {
            clock.require_effect()?;
            Err(WholePgCarrierFault::IoFailure)
        }
    }
}
fn read_exact_at(
    file: &File,
    mut at: u64,
    mut out: &mut [u8],
    clock: &dyn CaptureClockCheck,
) -> Result<(), WholePgCarrierFault> {
    while !out.is_empty() {
        clock.require_effect()?;
        let observed = file.read_at(out, at);
        clock.require_effect()?;
        let n = observed.map_err(io_fault)?;
        if n == 0 {
            return Err(WholePgCarrierFault::ShortRead);
        }
        at = checked_add(at, n as u64)?;
        out = &mut out[n..];
    }
    Ok(())
}
fn write_all_at(
    file: &File,
    mut at: u64,
    mut bytes: &[u8],
    clock: &dyn CaptureClockCheck,
) -> Result<(), WholePgCarrierFault> {
    while !bytes.is_empty() {
        clock.require_effect()?;
        let observed = file.write_at(bytes, at);
        clock.require_effect()?;
        let n = observed.map_err(io_fault)?;
        if n == 0 {
            return Err(WholePgCarrierFault::IoFailure);
        }
        at = checked_add(at, n as u64)?;
        bytes = &bytes[n..];
    }
    Ok(())
}
fn eof_at(file: &File, at: u64, clock: &dyn CaptureClockCheck) -> Result<(), WholePgCarrierFault> {
    let mut tail = Zeroizing::new([0u8; 1]);
    clock.require_effect()?;
    let observed = file.read_at(&mut *tail, at);
    clock.require_effect()?;
    let n = observed.map_err(io_fault)?;
    tail.zeroize();
    if n != 0 {
        return Err(WholePgCarrierFault::ExtraTail);
    }
    Ok(())
}
fn synced(file: &File, clock: &dyn CaptureClockCheck) -> Result<(), WholePgCarrierFault> {
    clock.require_effect()?;
    let synced = file.sync_all();
    clock.require_effect()?;
    synced.map_err(io_fault)
}
fn io_fault(_: io::Error) -> WholePgCarrierFault {
    WholePgCarrierFault::IoFailure
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_domain::backup::whole_pg_carrier::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    struct Always;
    impl CaptureClockCheck for Always {
        fn require_effect(&self) -> Result<(), WholePgCarrierFault> {
            Ok(())
        }
        fn require_closing(&self) -> Result<(), WholePgCarrierFault> {
            Ok(())
        }
        fn effect_remaining_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Ok(1_000_000)
        }
        fn closing_remaining_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Ok(2_000_000)
        }
        fn observed_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Ok(1)
        }
    }
    struct Expired;
    impl CaptureClockCheck for Expired {
        fn require_effect(&self) -> Result<(), WholePgCarrierFault> {
            Err(WholePgCarrierFault::DeadlineExpired)
        }
        fn require_closing(&self) -> Result<(), WholePgCarrierFault> {
            Err(WholePgCarrierFault::ClosingPending)
        }
        fn effect_remaining_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Err(WholePgCarrierFault::DeadlineExpired)
        }
        fn closing_remaining_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Err(WholePgCarrierFault::ClosingPending)
        }
        fn observed_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Ok(2)
        }
    }
    fn directory(path: &std::path::Path) -> File {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        File::open(path).unwrap()
    }
    fn input_dir(file: File) -> WholePgOwnedDirectoryInput {
        let m = file.metadata().unwrap();
        WholePgOwnedDirectoryInput {
            directory: file,
            expected_device: m.dev(),
            expected_inode: m.ino(),
            expected_uid: m.uid(),
        }
    }
    fn fixture(chunk: u64) -> (std::path::PathBuf, WholePgOwnedStreamParts) {
        // Only this newly O_EXCL-created private test root is used; no installed/user PG exists.
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let name = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let root = std::path::PathBuf::from(format!("/private/tmp/wb45-carrier-test-{name}"));
        let _root_fd = directory(&root);
        let output = input_dir(directory(&root.join("output")));
        let independent_key_medium = input_dir(directory(&root.join("key")));
        let _source_fd = directory(&root.join("source"));
        let bounds = WholePgCarrierBounds {
            max_material_files: 128,
            max_directories: 128,
            max_path_bytes: 4096,
            max_path_depth: 16,
            max_single_plain_bytes: 1_000_000,
            max_material_plain_bytes: 4_000_000,
            max_manifest_bytes: 16384,
            max_header_bytes: 80,
            max_data_chunks: 4096,
            max_chunk_plain_bytes: chunk,
            max_wire_bytes: 8_000_000,
            max_metadata_bytes: 1_000_000,
            max_open_files: 256,
            max_snapshot_bytes: 8_000_000,
            max_spool_bytes: 8_000_000,
            max_retained_prior_bytes: 8_000_000,
            max_journal_bytes: 1_000_000,
            max_total_allocation_bytes: 64_000_000,
            capacity_reserve_bytes: 4096,
            free_floor_bytes: 4096,
            max_key_medium_allocation_bytes: 2_097_152,
            key_medium_reserve_bytes: 4096,
            key_medium_free_floor_bytes: 4096,
        };
        let c = WholePgSecretClassBounds {
            max_count: 32,
            max_one_bytes: 4096,
        };
        let secret_bounds = WholePgSecretBounds {
            max_source_secret_count: 2,
            max_one_source_secret_bytes: 64,
            max_total_source_secret_bytes: 96,
            max_secret_structure_bytes: 1_000_000,
            max_secret_memory_bytes: 8_000_000,
            classes: WholePgSecretClasses {
                master_source: c,
                credential_wrapping: c,
                remote_assertion_signing: c,
                application_derived: c,
                scram_source: c,
                pg_config_passwords: c,
                native_secret_frames: c,
                recovery_key: c,
                stream_key: c,
                key_medium_readback: c,
                decode_crypto_temporary: c,
            },
        };
        let mut sources = Vec::new();
        let materials = WholePgMaterialKind::ALL
            .into_iter()
            .enumerate()
            .map(|(i, kind)| {
                let id = format!("m{i}");
                let (path, len) = match kind {
                    WholePgMaterialKind::MasterSecret => ("secrets/master".to_string(), 32usize),
                    WholePgMaterialKind::ScramSecret => ("secrets/scram".to_string(), 64usize),
                    _ => (format!("data/{i}"), 1usize),
                };
                if kind.is_secret() {
                    sources.push(WholePgOwnedSourceInput::Secret {
                        material_id: id.clone(),
                        secret: SecretBytes::new(vec![i as u8; len]),
                    });
                } else {
                    let f = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(root.join("source").join(&id))
                        .unwrap();
                    f.write_at(&[i as u8], 0).unwrap();
                    f.sync_all().unwrap();
                    sources.push(WholePgOwnedSourceInput::File {
                        material_id: id.clone(),
                        file: f,
                    });
                }
                WholePgMaterialClaim {
                    material_id: id,
                    kind,
                    relative_path: path,
                    plain_len: len as u64,
                    plain_sha256: Sha256::digest(vec![i as u8; len]).into(),
                    chunk_count: ((len as u64).div_ceil(chunk)) as u32,
                }
            })
            .collect();
        let claim = WholePgManifestClaim {
            schema: "wrokbot-whole-pg-capture".into(),
            version: 1,
            operation_id: "00000000-0000-4000-8000-000000000001".into(),
            bundle_id: "00000000-0000-4000-8000-000000000002".into(),
            request_id: "a".repeat(64),
            provenance: WholePgProvenanceClaim {
                release_sha256: [1; 32],
                maintenance_sha256: [2; 32],
                upstream_source_sha256: [3; 32],
                derived_patch_sha256: [4; 32],
                build_recipe_sha256: [5; 32],
                tool_inventory_material_id: "m14".into(),
            },
            source: WholePgSourceClaim {
                instance_id: "instance".into(),
                dataset_id: "dataset".into(),
                deployment_id: "deployment".into(),
                tenant_id: "tenant".into(),
                system_identifier: "42".into(),
                database_oid: 16384,
                key_id: "key".into(),
                key_version: 1,
                canary_material_id: "m11".into(),
                schema_material_id: "m3".into(),
                migration_material_id: "m4".into(),
                compatibility_material_id: "m14".into(),
            },
            barrier: WholePgBarrierClaim {
                normal_closed_operation_id: "00000000-0000-4000-8000-000000000001".into(),
                audit_checkpoint_material_id: "m8".into(),
                receipt_frontier_material_id: "m9".into(),
                host_inventory_material_id: "m10".into(),
                driver_facts_material_id: "m10".into(),
                source_start_lsn: "0/1000".into(),
                source_end_lsn: "0/2000".into(),
                timeline: 1,
                wal_segment_bytes: 16 * 1024 * 1024,
            },
            coverage: WholePgMaterialKind::ALL
                .into_iter()
                .enumerate()
                .map(|(i, kind)| WholePgCoverageClaim {
                    kind,
                    presence: WholePgPresence::Present,
                    evidence_material_id: format!("m{i}"),
                })
                .collect(),
            materials,
        };
        let manifest = FrozenWholePgManifest::check(claim, bounds).unwrap();
        (
            root,
            WholePgOwnedStreamParts {
                manifest,
                sources,
                output,
                independent_key_medium,
                carrier_bounds: bounds,
                secret_bounds,
            },
        )
    }
    const FINAL: &str = "wrokbot-capture-00000000000040008000000000000002.wbpg";
    const TEMP: &str = ".wrokbot-capture-00000000000040008000000000000002.partial";
    const KEY: &str = "wrokbot-capture-00000000000040008000000000000002.key";
    fn finish(root: std::path::PathBuf) {
        // Every caller drops all original input/result handles before this exact test-root cleanup.
        std::fs::remove_dir_all(root).unwrap();
    }
    struct SecondEffectUnavailable(std::sync::atomic::AtomicUsize);
    impl SecondEffectUnavailable {
        fn new() -> Self {
            Self(std::sync::atomic::AtomicUsize::new(0))
        }
        fn calls(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl CaptureClockCheck for SecondEffectUnavailable {
        fn require_effect(&self) -> Result<(), WholePgCarrierFault> {
            if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(WholePgCarrierFault::ClockUnavailable)
            }
        }
        fn require_closing(&self) -> Result<(), WholePgCarrierFault> {
            Always.require_closing()
        }
        fn effect_remaining_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Always.effect_remaining_ns()
        }
        fn closing_remaining_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Always.closing_remaining_ns()
        }
        fn observed_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Always.observed_ns()
        }
    }
    #[test]
    fn owned_carrier_failed_reads_and_writes_still_observe_original_clock() {
        let (root, parts) = fixture(64);
        let path = root.join("source").join("clock-error-probe");
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        created.write_at(b"data", 0).unwrap();
        drop(created);
        let read_only = File::open(&path).unwrap();
        let write_only = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let mut byte = [0u8; 1];
        let clock = SecondEffectUnavailable::new();
        assert_eq!(
            read_exact_at(&write_only, 0, &mut byte, &clock),
            Err(WholePgCarrierFault::ClockUnavailable)
        );
        assert_eq!(clock.calls(), 2);
        assert_eq!(
            read_exact_at(&write_only, 0, &mut byte, &Always),
            Err(WholePgCarrierFault::IoFailure)
        );
        let clock = SecondEffectUnavailable::new();
        assert_eq!(
            write_all_at(&read_only, 0, b"x", &clock),
            Err(WholePgCarrierFault::ClockUnavailable)
        );
        assert_eq!(clock.calls(), 2);
        assert_eq!(
            write_all_at(&read_only, 0, b"x", &Always),
            Err(WholePgCarrierFault::IoFailure)
        );
        let clock = SecondEffectUnavailable::new();
        assert_eq!(
            eof_at(&write_only, 0, &clock),
            Err(WholePgCarrierFault::ClockUnavailable)
        );
        assert_eq!(clock.calls(), 2);
        assert_eq!(
            eof_at(&write_only, 0, &Always),
            Err(WholePgCarrierFault::IoFailure)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
        drop((read_only, write_only, parts));
        finish(root);
    }
    #[test]
    fn owned_carrier_failed_opens_still_observe_original_clock() {
        let (root, parts) = fixture(64);
        let parent = &parts.output.directory;
        let mut files = Vec::with_capacity(1);
        let created = create_new(parent, "clock-open-probe", &Always).unwrap();
        created.write_at(b"data", 0).unwrap();
        drop(created);
        let clock = SecondEffectUnavailable::new();
        assert_eq!(
            create_new(parent, "clock-open-probe", &clock).unwrap_err(),
            WholePgCarrierFault::ClockUnavailable
        );
        assert_eq!(clock.calls(), 2);
        assert_eq!(
            create_new(parent, "clock-open-probe", &Always).unwrap_err(),
            WholePgCarrierFault::IoFailure
        );
        let clock = SecondEffectUnavailable::new();
        assert_eq!(
            open_read(parent, "missing-clock-open-probe", &mut files, &clock).unwrap_err(),
            WholePgCarrierFault::ClockUnavailable
        );
        assert_eq!(clock.calls(), 2);
        assert_eq!(
            open_read(parent, "missing-clock-open-probe", &mut files, &Always).unwrap_err(),
            WholePgCarrierFault::IoFailure
        );
        assert_eq!(
            std::fs::read(root.join("output").join("clock-open-probe")).unwrap(),
            b"data"
        );
        assert!(
            !root
                .join("output")
                .join("missing-clock-open-probe")
                .exists()
        );
        drop(parts);
        finish(root);
    }
    #[test]
    fn owned_carrier_publishes_both_full_readbacks_with_sub_secret_chunks() {
        let (root, parts) = fixture(17);
        let wire = parts.manifest.wire_bytes().unwrap();
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        let receipt = match run_owned_stream(input, Arc::new(Always)) {
            Ok(v) => v,
            Err(v) => panic!("{}", v.fault),
        };
        assert!(
            receipt.key_verified
                && receipt.temporary_verified
                && receipt.published_verified
        );
        assert_eq!(receipt.wire_bytes, wire);
        let bytes = std::fs::read(root.join("output").join(FINAL)).unwrap();
        assert_eq!(&bytes[..8], b"WBPGCAP1");
        assert_eq!(
            receipt.carrier_sha256,
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        assert!(!root.join("output").join(TEMP).exists());
        assert_eq!(
            std::fs::metadata(root.join("key").join(KEY)).unwrap().len(),
            104
        );
        drop(receipt);
        finish(root);
    }
    #[test]
    fn owned_carrier_final_conflict_preserves_old_final_key_and_partial() {
        let (root, parts) = fixture(64);
        let final_path = root.join("output").join(FINAL);
        std::fs::write(&final_path, b"old-backup").unwrap();
        std::fs::set_permissions(&final_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        let failed = match run_owned_stream(input, Arc::new(Always)) {
            Err(v) => v,
            Ok(_) => panic!("overwrite"),
        };
        assert_eq!(failed.fault, WholePgCarrierFault::PublishUnknown);
        assert_eq!(std::fs::read(&final_path).unwrap(), b"old-backup");
        assert!(
            failed.io.key.is_some()
                && failed.io.key_verified
                && failed.io.temporary_verified
                && !failed.io.published_verified
        );
        assert!(root.join("output").join(TEMP).exists());
        assert_eq!(failed.retained.as_ref().unwrap().sources.len(), 15);
        drop(failed);
        finish(root);
    }
    #[test]
    fn owned_carrier_existing_key_is_never_overwritten() {
        let (root, parts) = fixture(64);
        let key_path = root.join("key").join(KEY);
        std::fs::write(&key_path, b"old-key").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        let failed = match run_owned_stream(input, Arc::new(Always)) {
            Err(v) => v,
            Ok(_) => panic!("overwrite"),
        };
        assert_eq!(std::fs::read(&key_path).unwrap(), b"old-key");
        assert!(!failed.io.key_verified && failed.io.key.is_some());
        assert!(!root.join("output").join(TEMP).exists());
        drop(failed);
        finish(root);
    }
    #[test]
    fn owned_carrier_expired_original_clock_keeps_all_input_handles_and_secrets() {
        let (root, parts) = fixture(64);
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        let failed = match run_owned_stream(input, Arc::new(Expired)) {
            Err(v) => v,
            Ok(_) => panic!("expired"),
        };
        assert_eq!(failed.fault, WholePgCarrierFault::DeadlineExpired);
        assert_eq!(failed.retained.as_ref().unwrap().sources.len(), 15);
        assert_eq!(
            failed
                .retained
                .as_ref()
                .unwrap()
                .sources
                .iter()
                .filter(|v| v.is_secret())
                .count(),
            2
        );
        assert!(failed.io.files.is_empty() && failed.io.key.is_none());
        drop(failed);
        finish(root);
    }
    #[test]
    fn owned_carrier_changed_original_source_refuses_before_key_effect() {
        let (root, parts) = fixture(64);
        let WholePgOwnedSourceInput::File { file, .. } = &parts.sources[0] else {
            panic!("file")
        };
        file.write_at(&[255], 0).unwrap();
        file.sync_all().unwrap();
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        let failed = match run_owned_stream(input, Arc::new(Always)) {
            Err(v) => v,
            Ok(_) => panic!("source"),
        };
        assert_eq!(failed.fault, WholePgCarrierFault::SourceChanged);
        assert!(!root.join("key").join(KEY).exists());
        assert!(failed.io.files.is_empty());
        drop(failed);
        finish(root);
    }
    #[test]
    fn owned_carrier_final_authenticated_readback_rejects_modified_ciphertext() {
        let (root, parts) = fixture(64);
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        // Exercise the same original kernel while retaining its owned test inputs;
        // the public producer now releases them before a successful receipt exists.
        let mut parts = input.parts;
        let mut io = RetainedStreamIo::empty();
        match stream(&mut parts, &mut io, &Always) {
            Ok(_) => (),
            Err(fault) => panic!("{fault}"),
        };
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("output").join(FINAL))
            .unwrap();
        let mut one = [0u8; 1];
        f.read_at(&mut one, 101).unwrap();
        one[0] ^= 1;
        f.write_at(&one, 101).unwrap();
        f.sync_all().unwrap();
        let identity = FileIdentity::from(&f.metadata().unwrap());
        let mut frame = Zeroizing::new(Vec::with_capacity(16384));
        io.files.try_reserve_exact(1).unwrap();
        assert_eq!(
            readback(
                &parts,
                FINAL,
                io.key.as_ref().unwrap(),
                identity,
                1,
                &mut frame,
                &mut io.files,
                &Always
            )
            .unwrap_err(),
            WholePgCarrierFault::AuthenticationFailed
        );
        assert!(frame.is_empty() && frame.iter().all(|b| *b == 0));
        drop(f);
        drop((parts, io));
        finish(root);
    }

    struct ClosingCheckFails {
        at: usize,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl ClosingCheckFails {
        fn at(at: usize) -> Self {
            Self {
                at,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }
    impl CaptureClockCheck for ClosingCheckFails {
        fn require_effect(&self) -> Result<(), WholePgCarrierFault> {
            Always.require_effect()
        }
        fn require_closing(&self) -> Result<(), WholePgCarrierFault> {
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == self.at {
                Err(WholePgCarrierFault::ClosingPending)
            } else {
                Always.require_closing()
            }
        }
        fn effect_remaining_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Always.effect_remaining_ns()
        }
        fn closing_remaining_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Always.closing_remaining_ns()
        }
        fn observed_ns(&self) -> Result<u64, WholePgCarrierFault> {
            Always.observed_ns()
        }
    }
    #[test]
    fn owned_carrier_success_closes_inputs_before_receipt() {
        let (root, parts) = fixture(64);
        let WholePgOwnedSourceInput::File { file, .. } = &parts.sources[0] else {
            panic!("file")
        };
        rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let probe = File::open(root.join("source").join("m0")).unwrap();
        assert_eq!(
            rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        let receipt = match run_owned_stream(input, Arc::new(Always)) {
            Ok(v) => v,
            Err(v) => panic!("{}", v.fault),
        };
        rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        assert!(receipt.published_verified());
        drop(receipt);
        drop(probe);
        finish(root);

        let (root, parts) = fixture(64);
        let WholePgOwnedSourceInput::File { file, .. } = &parts.sources[0] else {
            panic!("file")
        };
        rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let probe = File::open(root.join("source").join("m0")).unwrap();
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        let failure = match run_owned_stream(input, Arc::new(ClosingCheckFails::at(0))) {
            Err(v) => v,
            Ok(_) => panic!("closing"),
        };
        assert_eq!(failure.fault, WholePgCarrierFault::ClosingPending);
        assert_eq!(failure.release_stage, StreamReleaseStage::Retained);
        assert!(failure.retained.is_some() && failure.io.key.is_some());
        assert_eq!(
            rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        drop(failure);
        rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        drop(probe);
        finish(root);
    }
    #[test]
    fn owned_carrier_release_keeps_actual_stage_when_closing_clock_expires() {
        let (root, parts) = fixture(64);
        let WholePgOwnedSourceInput::File { file, .. } = &parts.sources[0] else {
            panic!("file")
        };
        rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let probe = File::open(root.join("source").join("m0")).unwrap();
        assert_eq!(
            rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(_) => panic!("input"),
        };
        let clock = Arc::new(ClosingCheckFails::at(1));
        let failure = match run_owned_stream(input, clock.clone()) {
            Err(v) => v,
            Ok(_) => panic!("late_release"),
        };
        assert_eq!(clock.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(failure.fault, WholePgCarrierFault::ClosingPending);
        assert_eq!(failure.release_stage, StreamReleaseStage::Released);
        assert!(failure.retained.is_none());
        assert!(failure.io.files.is_empty() && failure.io.key.is_none());
        rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        drop(failure);
        drop(probe);
        finish(root);
    }

    #[test]
    fn owned_carrier_constructor_rejects_a_manifest_frozen_for_another_profile() {
        let (root, mut parts) = fixture(64);
        parts.carrier_bounds.max_chunk_plain_bytes = 16;
        let failure = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Err(v) => v,
            Ok(_) => panic!("profile"),
        };
        assert_eq!(failure.fault, WholePgCarrierFault::ProfileInvalid);
        assert!(failure.io.key.is_none() && failure.io.files.is_empty());
        drop(failure);
        finish(root);
    }
    #[test]
    fn owned_carrier_constructor_counts_two_key_copies_and_resident_class_peak() {
        let (root, mut parts) = fixture(64);
        parts.secret_bounds.classes.key_medium_readback.max_count = 1;
        let failure = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Err(v) => v,
            Ok(_) => panic!("copies"),
        };
        assert_eq!(failure.fault, WholePgCarrierFault::CapacityExceeded);
        drop(failure);
        finish(root);
        let (root, mut parts) = fixture(64);
        // Every class separately fits; their common limit leaves no room for the live frame.
        parts.secret_bounds.max_secret_memory_bytes = 11 * 32 * 4096;
        assert!(parts.secret_bounds.check().is_ok());
        let failure = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Err(v) => v,
            Ok(_) => panic!("peak"),
        };
        assert_eq!(failure.fault, WholePgCarrierFault::CapacityExceeded);
        drop(failure);
        finish(root);
    }
    #[test]
    fn owned_carrier_same_device_key_and_blocks_share_total_allocation_bound() {
        let (root, mut parts) = fixture(64);
        parts.carrier_bounds.max_total_allocation_bytes =
            25_000_000 + parts.manifest.wire_bytes().unwrap();
        let input = match OwnedCaptureStreamInputs::from_owned_parts(parts) {
            Ok(v) => v,
            Err(v) => panic!("{}", v.fault),
        };
        let failure = match run_owned_stream(input, Arc::new(Always)) {
            Err(v) => v,
            Ok(_) => panic!("allocation"),
        };
        assert_eq!(failure.fault, WholePgCarrierFault::CapacityExceeded);
        assert!(failure.io.files.is_empty() && failure.io.key.is_none());
        drop(failure);
        finish(root);
    }
}
