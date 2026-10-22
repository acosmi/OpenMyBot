//! Independent bounded whole-PG capture wire format. These are pure format/AEAD values,
//! never a source, shutdown, restore, clock or publication capability.
use crate::vault::aead::{whole_pg_open_in_place, whole_pg_seal_in_place};
use crate::vault::{ApplicationKeyPurpose, SecretBytes, derive_application_key};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: u64 = 4 * 1024 * 1024;
const AAD_PREFIX: &[u8] = b"openbot.backup.aad.whole-pg-capture.v1\0";
const RESERVED: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Closed carrier fault tags without raw I/O errors, secret bytes or panic payloads.
pub enum WholePgCarrierFault {
    /// An argument does not satisfy the carrier operation's required shape.
    InvalidArgument,
    /// The manifest schema or format version is unsupported.
    UnsupportedVersion,
    /// A required capture bounds profile was not supplied.
    ProfileMissing,
    /// A bounds profile has zero, inconsistent or out-of-range limits.
    ProfileInvalid,
    /// Checked size, count or offset arithmetic overflowed.
    BoundsOverflow,
    /// A configured byte, count or storage-capacity limit was exceeded.
    CapacityExceeded,
    /// The operation's required clock cannot provide a usable observation.
    ClockUnavailable,
    /// The original operation deadline has expired.
    DeadlineExpired,
    /// Cancellation prevents the requested carrier operation from continuing.
    Cancelled,
    /// Observed carrier identity or metadata differs from the expected capture intent.
    IntentMismatch,
    /// The manifest's identifiers, ordering, lengths or relationships are invalid.
    ManifestInvalid,
    /// Authenticated manifest bytes differ from its canonical serialization.
    NonCanonical,
    /// A required material or its nonempty coverage evidence is absent.
    MaterialMissing,
    /// An unexpected material or directory entry was encountered.
    ExtraMaterial,
    /// An original source's observed identity or contents changed.
    SourceChanged,
    /// A path or filesystem object fails the required safety checks.
    PathUnsafe,
    /// Secret bytes or their required material path and plaintext length are invalid.
    SecretInvalid,
    /// No unused frame nonce sequence remains available.
    NonceExhausted,
    /// A frame's header, position or plaintext length differs from the expected layout.
    FrameInvalid,
    /// Frame AEAD encryption or authentication failed.
    AuthenticationFailed,
    /// An input ended before all required carrier bytes were read.
    ShortRead,
    /// Bytes remain after the expected carrier terminal frame.
    ExtraTail,
    /// The required terminal frame is absent or has unexpected contents.
    TerminalMissing,
    /// The recovery-key medium fails its required representation or identity checks.
    KeyMediumInvalid,
    /// A required carrier or recovery-key readback could not be verified.
    ReadbackFailed,
    /// Publication has no established successful outcome.
    PublishUnknown,
    /// A required carrier filesystem or stream I/O operation failed.
    IoFailure,
    /// The original resource owner has not established the required closing state.
    ClosingPending,
}
impl fmt::Display for WholePgCarrierFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WholePgCarrierFault {}
type Result<T> = std::result::Result<T, WholePgCarrierFault>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Configured capture-format and storage limits; these values do not confer source authority.
pub struct WholePgCarrierBounds {
    /// Maximum number of material records admitted by the manifest.
    pub max_material_files: u64,
    /// Configured maximum number of directories in the capture snapshot.
    pub max_directories: u64,
    /// Maximum UTF-8 byte length of one material's relative path.
    pub max_path_bytes: u64,
    /// Maximum slash-separated component count for a material's relative path.
    pub max_path_depth: u64,
    /// Maximum plaintext bytes declared for any one material.
    pub max_single_plain_bytes: u64,
    /// Maximum sum of plaintext bytes declared across all materials.
    pub max_material_plain_bytes: u64,
    /// Maximum canonical manifest bytes, positive and at most 4 MiB.
    pub max_manifest_bytes: u64,
    /// Carrier-header byte limit; a valid profile must allow at least 80 bytes.
    pub max_header_bytes: u64,
    /// Maximum data-frame count, at most `u32::MAX - 1`, excluding manifest and terminal frames.
    pub max_data_chunks: u64,
    /// Maximum plaintext bytes per data chunk, positive and at most 4 MiB.
    pub max_chunk_plain_bytes: u64,
    /// Maximum total carrier bytes, including fixed headers, frame metadata and AEAD tags.
    pub max_wire_bytes: u64,
    /// Configured byte ceiling for capture metadata, including recorded claim and layout storage.
    pub max_metadata_bytes: u64,
    /// Configured maximum number of capture-owned open file descriptors.
    pub max_open_files: u64,
    /// Configured maximum plaintext bytes copied into the artifact snapshot.
    pub max_snapshot_bytes: u64,
    /// Configured maximum bytes attributed to the capture spool.
    pub max_spool_bytes: u64,
    /// Configured byte allowance for prior material retained during this capture.
    pub max_retained_prior_bytes: u64,
    /// Configured maximum bytes attributed to the capture journal.
    pub max_journal_bytes: u64,
    /// Configured byte cap for aggregate allocated capture storage.
    pub max_total_allocation_bytes: u64,
    /// Additional free-space reserve in bytes on the capture storage medium.
    pub capacity_reserve_bytes: u64,
    /// Minimum free bytes to preserve on the capture storage medium.
    pub free_floor_bytes: u64,
    /// Configured maximum allocation bytes on the recovery-key medium.
    pub max_key_medium_allocation_bytes: u64,
    /// Additional free-space reserve in bytes on the recovery-key medium.
    pub key_medium_reserve_bytes: u64,
    /// Minimum free bytes to preserve on the recovery-key medium.
    pub key_medium_free_floor_bytes: u64,
}
impl WholePgCarrierBounds {
    /// Rejects zero or inconsistent format limits and returns the unchanged valid profile.
    pub fn check(self) -> Result<Self> {
        let values = [
            self.max_material_files,
            self.max_directories,
            self.max_path_bytes,
            self.max_path_depth,
            self.max_single_plain_bytes,
            self.max_material_plain_bytes,
            self.max_manifest_bytes,
            self.max_header_bytes,
            self.max_data_chunks,
            self.max_chunk_plain_bytes,
            self.max_wire_bytes,
            self.max_metadata_bytes,
            self.max_open_files,
            self.max_snapshot_bytes,
            self.max_spool_bytes,
            self.max_retained_prior_bytes,
            self.max_journal_bytes,
            self.max_total_allocation_bytes,
            self.capacity_reserve_bytes,
            self.free_floor_bytes,
            self.max_key_medium_allocation_bytes,
            self.key_medium_reserve_bytes,
            self.key_medium_free_floor_bytes,
        ];
        if values.contains(&0)
            || self.max_manifest_bytes > MAX_FRAME
            || self.max_chunk_plain_bytes > MAX_FRAME
            || self.max_header_bytes < 80
            || self.max_data_chunks > u64::from(u32::MAX - 1)
            || self.max_single_plain_bytes > self.max_material_plain_bytes
        {
            return Err(WholePgCarrierFault::ProfileInvalid);
        }
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Configured owner-count and per-owner byte limits for one secret class.
pub struct WholePgSecretClassBounds {
    /// Maximum reserved owner count; optional secret classes may have a zero allowance.
    pub max_count: u64,
    /// Maximum bytes per owner in this class; profile validation requires a nonzero value.
    pub max_one_bytes: u64,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Separate configured allowances for source, derived, recovery and temporary secret owners.
pub struct WholePgSecretClasses {
    /// Allowance for original master-secret owners.
    pub master_source: WholePgSecretClassBounds,
    /// Allowance for credential-wrapping key owners.
    pub credential_wrapping: WholePgSecretClassBounds,
    /// Allowance for remote-assertion signing-key owners.
    pub remote_assertion_signing: WholePgSecretClassBounds,
    /// Allowance for other application-derived secret-key owners.
    pub application_derived: WholePgSecretClassBounds,
    /// Allowance for original SCRAM-secret owners.
    pub scram_source: WholePgSecretClassBounds,
    /// Allowance for password owners used by PostgreSQL connection configurations.
    pub pg_config_passwords: WholePgSecretClassBounds,
    /// Allowance for native-capture secret-frame owners.
    pub native_secret_frames: WholePgSecretClassBounds,
    /// Allowance for recovery-key owners.
    pub recovery_key: WholePgSecretClassBounds,
    /// Allowance for derived carrier stream-key owners.
    pub stream_key: WholePgSecretClassBounds,
    /// Allowance for recovery-key copies held during key-medium readback.
    pub key_medium_readback: WholePgSecretClassBounds,
    /// Allowance for temporary secret owners used during decoding and cryptography.
    pub decode_crypto_temporary: WholePgSecretClassBounds,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Configured aggregate source-secret, structure and per-class reservation limits.
pub struct WholePgSecretBounds {
    /// Maximum declared number of source-secret owners.
    pub max_source_secret_count: u64,
    /// Maximum bytes in any one declared source secret.
    pub max_one_source_secret_bytes: u64,
    /// Maximum summed bytes of all declared source secrets.
    pub max_total_source_secret_bytes: u64,
    /// Configured byte ceiling for secret-owner structures and their recorded metadata.
    pub max_secret_structure_bytes: u64,
    /// Byte ceiling checked against the sum of per-class count-times-size reservations.
    pub max_secret_memory_bytes: u64,
    /// Individual secret-class limits used when validating the aggregate reservation.
    pub classes: WholePgSecretClasses,
}
impl WholePgSecretBounds {
    /// Checks nonzero aggregate limits, mandatory classes and their checked reservation sum.
    pub fn check(self) -> Result<Self> {
        if [
            self.max_source_secret_count,
            self.max_one_source_secret_bytes,
            self.max_total_source_secret_bytes,
            self.max_secret_structure_bytes,
            self.max_secret_memory_bytes,
        ]
        .contains(&0)
        {
            return Err(WholePgCarrierFault::ProfileInvalid);
        }
        let classes = [
            self.classes.master_source,
            self.classes.credential_wrapping,
            self.classes.remote_assertion_signing,
            self.classes.application_derived,
            self.classes.scram_source,
            self.classes.pg_config_passwords,
            self.classes.native_secret_frames,
            self.classes.recovery_key,
            self.classes.stream_key,
            self.classes.key_medium_readback,
            self.classes.decode_crypto_temporary,
        ];
        let mut total = 0u64;
        for class in classes {
            if class.max_one_bytes == 0 {
                return Err(WholePgCarrierFault::ProfileInvalid);
            }
            total = add(total, mul(class.max_count, class.max_one_bytes)?)?;
        }
        if self.classes.master_source.max_count < 1
            || self.classes.scram_source.max_count < 1
            || self.classes.recovery_key.max_count < 1
            || self.classes.stream_key.max_count < 1
            || self.classes.key_medium_readback.max_count < 1
            || total > self.max_secret_memory_bytes
        {
            return Err(WholePgCarrierFault::ProfileInvalid);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
/// The fifteen material categories represented by ordered manifest coverage claims.
pub enum WholePgMaterialKind {
    /// PostgreSQL base-data material.
    PostgresBase,
    /// A PostgreSQL write-ahead-log segment.
    WalSegment,
    /// Captured PostgreSQL configuration material.
    PostgresConfig,
    /// Evidence recording the database schema checksum.
    SchemaChecksum,
    /// Evidence recording the database migration checksum.
    MigrationChecksum,
    /// Profile inventory, including evidence for an explicitly empty inventory.
    ProfileInventory,
    /// Workspace inventory, including evidence for an explicitly empty inventory.
    WorkspaceInventory,
    /// Captured artifact content or its store material.
    Artifact,
    /// Evidence for the capture's audit checkpoint.
    AuditCheckpoint,
    /// Evidence for the capture's receipt frontier.
    ReceiptFrontier,
    /// An installation record associated with the captured source.
    InstallationRecord,
    /// Key metadata, including the referenced canary material.
    KeyMetadata,
    /// The 32-byte master secret at the fixed `secrets/master` path.
    MasterSecret,
    /// The 64-byte SCRAM secret at the fixed `secrets/scram` path.
    ScramSecret,
    /// Compatibility evidence referenced by the source claim.
    CompatibilityRecord,
}
impl WholePgMaterialKind {
    /// Every material kind in the exact order required for the fifteen coverage entries.
    pub const ALL: [Self; 15] = [
        Self::PostgresBase,
        Self::WalSegment,
        Self::PostgresConfig,
        Self::SchemaChecksum,
        Self::MigrationChecksum,
        Self::ProfileInventory,
        Self::WorkspaceInventory,
        Self::Artifact,
        Self::AuditCheckpoint,
        Self::ReceiptFrontier,
        Self::InstallationRecord,
        Self::KeyMetadata,
        Self::MasterSecret,
        Self::ScramSecret,
        Self::CompatibilityRecord,
    ];
    /// Returns true only for the master-secret and SCRAM-secret material kinds.
    pub fn is_secret(self) -> bool {
        matches!(self, Self::MasterSecret | Self::ScramSecret)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// A declared material's identity, plaintext digest and chunk layout; its digest is wiped on drop.
pub struct WholePgMaterialClaim {
    /// Material identifier, unique in the manifest, with 1 to 128 bytes and no NUL.
    pub material_id: String,
    /// Material category used for coverage ordering and required-reference checks.
    pub kind: WholePgMaterialKind,
    /// Unique relative path with no absolute prefix, backslash, NUL or dot components.
    pub relative_path: String,
    /// Declared plaintext length in bytes; zero-length materials have no data chunks.
    pub plain_len: u64,
    #[serde(with = "hex32")]
    /// SHA-256 of the complete plaintext, encoded as lowercase hex by serialization.
    pub plain_sha256: [u8; 32],
    /// Number of data chunks implied by plaintext length and the configured chunk size.
    pub chunk_count: u32,
}
impl Drop for WholePgMaterialClaim {
    fn drop(&mut self) {
        self.plain_sha256.zeroize();
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// The declared presence state recorded for a material category.
pub enum WholePgPresence {
    /// The category is declared present with referenced nonempty evidence.
    Present,
    /// An explicitly empty profile or workspace inventory with nonempty evidence.
    ControlledEmpty,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// One ordered material-category coverage declaration and its evidence reference.
pub struct WholePgCoverageClaim {
    /// Category whose position must match the corresponding entry in `WholePgMaterialKind::ALL`.
    pub kind: WholePgMaterialKind,
    /// Declared presence; controlled-empty is accepted only for profile and workspace inventories.
    pub presence: WholePgPresence,
    /// Identifier of a nonempty manifest material supporting this coverage claim.
    pub evidence_material_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Claimed build-provenance digests and a tool-inventory reference; not source attestation.
pub struct WholePgProvenanceClaim {
    #[serde(with = "hex32")]
    /// Claimed release SHA-256 digest, serialized as 64 lowercase hex digits.
    pub release_sha256: [u8; 32],
    #[serde(with = "hex32")]
    /// Claimed maintenance-build SHA-256 digest, serialized as lowercase hex.
    pub maintenance_sha256: [u8; 32],
    #[serde(with = "hex32")]
    /// Claimed upstream-source SHA-256 digest, serialized as lowercase hex.
    pub upstream_source_sha256: [u8; 32],
    #[serde(with = "hex32")]
    /// Claimed derived-patch SHA-256 digest, serialized as lowercase hex.
    pub derived_patch_sha256: [u8; 32],
    #[serde(with = "hex32")]
    /// Claimed build-recipe SHA-256 digest, serialized as lowercase hex.
    pub build_recipe_sha256: [u8; 32],
    /// Identifier of a nonempty manifest material recording the tool inventory.
    pub tool_inventory_material_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Declared source identifiers and typed references; validation does not authenticate a live source.
pub struct WholePgSourceClaim {
    /// Source instance identifier, checked for nonempty bounded text without NUL.
    pub instance_id: String,
    /// Dataset identifier, checked for nonempty bounded text without NUL.
    pub dataset_id: String,
    /// Deployment identifier, checked for nonempty bounded text without NUL.
    pub deployment_id: String,
    /// Tenant identifier, checked for nonempty bounded text without NUL.
    pub tenant_id: String,
    /// Positive PostgreSQL system identifier in canonical decimal text.
    pub system_identifier: String,
    /// Nonzero PostgreSQL database object identifier.
    pub database_oid: u32,
    /// Key identifier associated with this source's key-metadata claim.
    pub key_id: String,
    /// Key version; the current manifest validator accepts only version 1.
    pub key_version: u32,
    /// Identifier of nonempty key-metadata material carrying the source canary.
    pub canary_material_id: String,
    /// Identifier of nonempty schema-checksum material.
    pub schema_material_id: String,
    /// Identifier of nonempty migration-checksum material.
    pub migration_material_id: String,
    /// Identifier of nonempty compatibility-record material.
    pub compatibility_material_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Declared barrier references and WAL range; these fields alone do not establish closure.
pub struct WholePgBarrierClaim {
    /// Normal-close operation identifier, required to equal the manifest operation identifier.
    pub normal_closed_operation_id: String,
    /// Identifier of nonempty audit-checkpoint material.
    pub audit_checkpoint_material_id: String,
    /// Identifier of nonempty receipt-frontier material.
    pub receipt_frontier_material_id: String,
    /// Identifier of nonempty host-inventory material.
    pub host_inventory_material_id: String,
    /// Identifier of nonempty original-driver-facts material.
    pub driver_facts_material_id: String,
    /// Start WAL position in canonical uppercase hexadecimal `high/low` LSN notation.
    pub source_start_lsn: String,
    /// End WAL position in canonical LSN notation, required not to precede the start.
    pub source_end_lsn: String,
    /// Nonzero PostgreSQL timeline identifier.
    pub timeline: u32,
    /// Declared WAL segment size in bytes, required to be nonzero.
    pub wal_segment_bytes: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Owned serializable capture claim; format validation alone does not establish source trust.
pub struct WholePgManifestClaim {
    /// Schema discriminator, required to be `wrokbot-whole-pg-capture`.
    pub schema: String,
    /// Manifest format version, currently required to be 1.
    pub version: u32,
    /// Capture operation identifier in the accepted hyphenated version-4 UUID shape.
    pub operation_id: String,
    /// Bundle identifier in the accepted hyphenated version-4 UUID shape.
    pub bundle_id: String,
    /// Request identifier represented by exactly 64 lowercase hexadecimal characters.
    pub request_id: String,
    /// Declared build-provenance digests and tool-inventory evidence reference.
    pub provenance: WholePgProvenanceClaim,
    /// Declared source identity, key version and required material references.
    pub source: WholePgSourceClaim,
    /// Declared normal-close, audit, host, driver and WAL barrier facts.
    pub barrier: WholePgBarrierClaim,
    /// Exactly fifteen coverage entries in material-kind order.
    pub coverage: Vec<WholePgCoverageClaim>,
    /// Material records strictly ordered by kind, relative path and identifier, with unique paths and IDs.
    pub materials: Vec<WholePgMaterialClaim>,
}

/// Checked manifest retaining a shared claim and immutable frame layout, without source authority.
pub struct FrozenWholePgManifest {
    claim: Arc<WholePgManifestClaim>,
    bounds: WholePgCarrierBounds,
    header: [u8; 80],
    terminal: [u8; 84],
    layout: Arc<Layout>,
    metadata_bytes: u64,
}
struct Layout {
    manifest_len: u32,
    chunk: u32,
    data_count: u32,
    lengths: Vec<u64>,
}
impl FrozenWholePgManifest {
    /// Checks claim structure and bounds, then freezes manifest length/digest and expected frame layout.
    pub fn check(claim: WholePgManifestClaim, bounds: WholePgCarrierBounds) -> Result<Self> {
        let bounds = bounds.check()?;
        if claim.schema != "wrokbot-whole-pg-capture" || claim.version != 1 {
            return Err(WholePgCarrierFault::UnsupportedVersion);
        }
        let operation = uuid_bytes(&claim.operation_id)?;
        let bundle = uuid_bytes(&claim.bundle_id)?;
        if !lower_hex(&claim.request_id, 64)
            || claim.barrier.normal_closed_operation_id != claim.operation_id
            || claim.materials.len() as u64 > bounds.max_material_files
            || claim.coverage.len() != 15
        {
            return Err(WholePgCarrierFault::ManifestInvalid);
        }
        let source = &claim.source;
        let barrier = &claim.barrier;
        for id in [
            &source.instance_id,
            &source.dataset_id,
            &source.deployment_id,
            &source.tenant_id,
            &source.key_id,
            &source.canary_material_id,
            &source.schema_material_id,
            &source.migration_material_id,
            &source.compatibility_material_id,
            &barrier.audit_checkpoint_material_id,
            &barrier.receipt_frontier_material_id,
            &barrier.host_inventory_material_id,
            &barrier.driver_facts_material_id,
            &claim.provenance.tool_inventory_material_id,
        ] {
            check_id(id)?;
        }
        let system_id = source
            .system_identifier
            .parse::<u64>()
            .map_err(|_| WholePgCarrierFault::ManifestInvalid)?;
        if system_id == 0
            || system_id.to_string() != source.system_identifier
            || source.database_oid == 0
            || source.key_version != 1
            || barrier.timeline == 0
            || barrier.wal_segment_bytes == 0
            || lsn(&barrier.source_start_lsn)? > lsn(&barrier.source_end_lsn)?
        {
            return Err(WholePgCarrierFault::ManifestInvalid);
        }
        let mut metadata = std::mem::size_of::<WholePgManifestClaim>() as u64;
        metadata = add(
            metadata,
            mul(
                claim.materials.capacity() as u64,
                std::mem::size_of::<WholePgMaterialClaim>() as u64,
            )?,
        )?;
        metadata = add(
            metadata,
            mul(
                claim.coverage.capacity() as u64,
                std::mem::size_of::<WholePgCoverageClaim>() as u64,
            )?,
        )?;
        let top_strings = [
            &claim.schema,
            &claim.operation_id,
            &claim.bundle_id,
            &claim.request_id,
            &source.instance_id,
            &source.dataset_id,
            &source.deployment_id,
            &source.tenant_id,
            &source.system_identifier,
            &source.key_id,
            &source.canary_material_id,
            &source.schema_material_id,
            &source.migration_material_id,
            &source.compatibility_material_id,
            &barrier.normal_closed_operation_id,
            &barrier.audit_checkpoint_material_id,
            &barrier.receipt_frontier_material_id,
            &barrier.host_inventory_material_id,
            &barrier.driver_facts_material_id,
            &barrier.source_start_lsn,
            &barrier.source_end_lsn,
            &claim.provenance.tool_inventory_material_id,
        ];
        for value in top_strings {
            metadata = add(metadata, value.capacity() as u64)?;
        }
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut previous = None;
        let mut total = 0u64;
        let mut chunks = 0u64;
        let mut lengths = Vec::new();
        let layout_allocation = mul(claim.materials.len() as u64, 8)?;
        // Charge the finite indexes and layout before their own allocation. Caller-owned claim memory
        // is already bounded by the real producer; this check does not confer source trust.
        metadata = add(
            metadata,
            add(layout_allocation, mul(claim.materials.len() as u64, 128)?)?,
        )?;
        if metadata > bounds.max_metadata_bytes {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        lengths
            .try_reserve_exact(claim.materials.len())
            .map_err(|_| WholePgCarrierFault::CapacityExceeded)?;
        for material in &claim.materials {
            check_id(&material.material_id)?;
            check_path(&material.relative_path, &bounds)?;
            metadata = add(
                metadata,
                add(
                    material.material_id.capacity() as u64,
                    material.relative_path.capacity() as u64,
                )?,
            )?;
            if metadata > bounds.max_metadata_bytes {
                return Err(WholePgCarrierFault::CapacityExceeded);
            }
            let order = (
                material.kind,
                material.relative_path.as_str(),
                material.material_id.as_str(),
            );
            if previous.is_some_and(|value| value >= order)
                || !ids.insert(material.material_id.as_str())
                || !paths.insert(material.relative_path.as_str())
            {
                return Err(WholePgCarrierFault::ManifestInvalid);
            }
            previous = Some(order);
            if material.plain_len > bounds.max_single_plain_bytes {
                return Err(WholePgCarrierFault::CapacityExceeded);
            }
            let count = if material.plain_len == 0 {
                0
            } else {
                add(material.plain_len, bounds.max_chunk_plain_bytes - 1)?
                    / bounds.max_chunk_plain_bytes
            };
            if count != u64::from(material.chunk_count) {
                return Err(WholePgCarrierFault::ManifestInvalid);
            }
            if material.plain_len == 0
                && material.plain_sha256 != <[u8; 32]>::from(Sha256::digest(b""))
            {
                return Err(WholePgCarrierFault::ManifestInvalid);
            }
            let secret_expected = match material.kind {
                WholePgMaterialKind::MasterSecret => Some(("secrets/master", 32)),
                WholePgMaterialKind::ScramSecret => Some(("secrets/scram", 64)),
                _ => None,
            };
            if let Some((path, len)) = secret_expected {
                if material.relative_path != path || material.plain_len != len {
                    return Err(WholePgCarrierFault::SecretInvalid);
                }
            }
            total = add(total, material.plain_len)?;
            chunks = add(chunks, count)?;
            lengths.push(material.plain_len);
        }
        if total > bounds.max_material_plain_bytes
            || chunks > bounds.max_data_chunks
            || chunks > u64::from(u32::MAX - 1)
        {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        for (index, coverage) in claim.coverage.iter().enumerate() {
            if coverage.kind != WholePgMaterialKind::ALL[index]
                || !claim
                    .materials
                    .iter()
                    .any(|m| m.material_id == coverage.evidence_material_id && m.plain_len > 0)
            {
                return Err(WholePgCarrierFault::MaterialMissing);
            }
            metadata = add(metadata, coverage.evidence_material_id.capacity() as u64)?;
            let count = claim
                .materials
                .iter()
                .filter(|m| m.kind == coverage.kind)
                .count();
            if count == 0
                || !claim
                    .materials
                    .iter()
                    .any(|m| m.kind == coverage.kind && m.plain_len > 0)
                || (coverage.kind.is_secret() && count != 1)
                || (coverage.presence == WholePgPresence::ControlledEmpty
                    && !matches!(
                        coverage.kind,
                        WholePgMaterialKind::ProfileInventory
                            | WholePgMaterialKind::WorkspaceInventory
                    ))
            {
                return Err(WholePgCarrierFault::MaterialMissing);
            }
        }
        for (id, kind) in [
            (&source.canary_material_id, WholePgMaterialKind::KeyMetadata),
            (
                &source.schema_material_id,
                WholePgMaterialKind::SchemaChecksum,
            ),
            (
                &source.migration_material_id,
                WholePgMaterialKind::MigrationChecksum,
            ),
            (
                &source.compatibility_material_id,
                WholePgMaterialKind::CompatibilityRecord,
            ),
            (
                &barrier.audit_checkpoint_material_id,
                WholePgMaterialKind::AuditCheckpoint,
            ),
            (
                &barrier.receipt_frontier_material_id,
                WholePgMaterialKind::ReceiptFrontier,
            ),
        ] {
            if !claim
                .materials
                .iter()
                .any(|m| &m.material_id == id && m.kind == kind && m.plain_len > 0)
            {
                return Err(WholePgCarrierFault::MaterialMissing);
            }
        }
        for id in [
            &barrier.host_inventory_material_id,
            &barrier.driver_facts_material_id,
            &claim.provenance.tool_inventory_material_id,
        ] {
            if !claim
                .materials
                .iter()
                .any(|m| &m.material_id == id && m.plain_len > 0)
            {
                return Err(WholePgCarrierFault::MaterialMissing);
            }
        }
        if metadata > bounds.max_metadata_bytes {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        let mut sink = HashSink {
            hash: Sha256::new(),
            len: 0,
            limit: bounds.max_manifest_bytes,
        };
        serde_json::to_writer(&mut sink, &claim)
            .map_err(|_| WholePgCarrierFault::CapacityExceeded)?;
        let manifest_len =
            u32::try_from(sink.len).map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
        let manifest_hash: [u8; 32] = sink.hash.finalize().into();
        let wire = add(
            add(add(80, u64::from(manifest_len))?, add(84, total)?)?,
            mul(add(chunks, 2)?, 37)?,
        )?;
        if wire > bounds.max_wire_bytes {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        let mut header = [0u8; 80];
        header[..8].copy_from_slice(b"WBPGCAP1");
        header[8..12].copy_from_slice(&1u32.to_be_bytes());
        header[12..28].copy_from_slice(&bundle);
        header[28..32].copy_from_slice(&manifest_len.to_be_bytes());
        header[32..36].copy_from_slice(&(bounds.max_chunk_plain_bytes as u32).to_be_bytes());
        header[36..40].copy_from_slice(&(chunks as u32).to_be_bytes());
        header[40..48].copy_from_slice(&total.to_be_bytes());
        header[48..].copy_from_slice(&manifest_hash);
        let mut terminal = [0u8; 84];
        terminal[..32].copy_from_slice(&manifest_hash);
        terminal[32..36].copy_from_slice(&(chunks as u32).to_be_bytes());
        terminal[36..44].copy_from_slice(&total.to_be_bytes());
        terminal[44..60].copy_from_slice(&operation);
        terminal[60..76].copy_from_slice(&bundle);
        terminal[76..].copy_from_slice(b"COMPLETE");
        Ok(Self {
            claim: Arc::new(claim),
            bounds,
            header,
            terminal,
            layout: Arc::new(Layout {
                manifest_len,
                chunk: bounds.max_chunk_plain_bytes as u32,
                data_count: chunks as u32,
                lengths,
            }),
            metadata_bytes: metadata,
        })
    }
    /// Copies the fixed 80-byte carrier header containing format, bundle, length and manifest-digest fields.
    pub fn header(&self) -> [u8; 80] {
        self.header
    }
    /// Borrows the checked material records in their frozen order.
    pub fn materials(&self) -> &[WholePgMaterialClaim] {
        &self.claim.materials
    }
    /// Borrows the shared checked claim without transferring its ownership.
    pub fn claim(&self) -> &WholePgManifestClaim {
        &self.claim
    }
    /// Returns recorded claim and layout metadata bytes, not an allocator or global-memory measurement.
    pub fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }
    /// Computes total carrier bytes, including the 80-byte header and all frame overhead.
    pub fn wire_bytes(&self) -> Result<u64> {
        add(
            add(
                add(80, u64::from(self.layout.manifest_len))?,
                add(
                    84,
                    u64::from_be_bytes(
                        self.header[40..48]
                            .try_into()
                            .map_err(|_| WholePgCarrierFault::ManifestInvalid)?,
                    ),
                )?,
            )?,
            mul(add(u64::from(self.layout.data_count), 2)?, 37)?,
        )
    }
    /// Wipes and clears the supplied buffer, then serializes the manifest within its existing capacity.
    pub fn encode_manifest_into(&self, buffer: &mut Zeroizing<Vec<u8>>) -> Result<()> {
        buffer.zeroize();
        buffer.clear();
        let mut sink = BufferSink {
            buffer,
            limit: self.layout.manifest_len as usize,
        };
        serde_json::to_writer(&mut sink, self.claim.as_ref())
            .map_err(|_| WholePgCarrierFault::CapacityExceeded)
    }
    /// Wipes and clears the supplied buffer, then writes the 84-byte terminal if capacity permits.
    pub fn encode_terminal_into(&self, buffer: &mut Zeroizing<Vec<u8>>) -> Result<()> {
        buffer.zeroize();
        buffer.clear();
        if buffer.capacity() < 84 {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        buffer.extend_from_slice(&self.terminal);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Expected frame position and plaintext size computed from the frozen material layout.
pub struct WholePgFrameSpec {
    kind: u8,
    seq: u32,
    ordinal: u32,
    offset: u64,
    len: u32,
}
impl WholePgFrameSpec {
    /// Returns frame kind: 0 for manifest, 1 for material data, or 2 for terminal.
    pub fn kind(self) -> u8 {
        self.kind
    }
    /// Returns the frame nonce sequence, starting at zero for the manifest frame.
    pub fn sequence(self) -> u32 {
        self.seq
    }
    /// Returns the zero-based data-material index, or `u32::MAX` for manifest and terminal frames.
    pub fn material_ordinal(self) -> u32 {
        self.ordinal
    }
    /// Returns the plaintext byte offset within the material; non-data frames use zero.
    pub fn offset(self) -> u64 {
        self.offset
    }
    /// Returns this frame's plaintext byte length, excluding its header and AEAD tag.
    pub fn plain_len(self) -> u32 {
        self.len
    }
    fn header(self) -> [u8; 21] {
        let mut h = [0u8; 21];
        h[0] = self.kind;
        h[1..5].copy_from_slice(&self.seq.to_be_bytes());
        h[5..9].copy_from_slice(&self.ordinal.to_be_bytes());
        h[9..17].copy_from_slice(&self.offset.to_be_bytes());
        h[17..21].copy_from_slice(&self.len.to_be_bytes());
        h
    }
}
/// Unencrypted frame metadata and authentication tag returned after successful sealing.
pub struct WholePgFrameParts {
    /// The 21-byte frame header, authenticated together with the fixed carrier header.
    pub header: [u8; 21],
    /// The 16-byte AEAD tag for ciphertext and associated carrier/frame metadata.
    pub tag: [u8; 16],
}
struct Cursor {
    layout: Arc<Layout>,
    seq: u64,
    ordinal: usize,
    offset: u64,
}
impl Cursor {
    fn next(&self) -> Option<WholePgFrameSpec> {
        let seq = u32::try_from(self.seq).ok()?;
        if self.seq == 0 {
            return Some(WholePgFrameSpec {
                kind: 0,
                seq,
                ordinal: RESERVED,
                offset: 0,
                len: self.layout.manifest_len,
            });
        }
        if self.seq == u64::from(self.layout.data_count) + 1 {
            return Some(WholePgFrameSpec {
                kind: 2,
                seq,
                ordinal: RESERVED,
                offset: 0,
                len: 84,
            });
        }
        if self.seq > u64::from(self.layout.data_count) + 1 {
            return None;
        }
        let len = self
            .layout
            .lengths
            .get(self.ordinal)?
            .checked_sub(self.offset)?
            .min(u64::from(self.layout.chunk));
        Some(WholePgFrameSpec {
            kind: 1,
            seq,
            ordinal: u32::try_from(self.ordinal).ok()?,
            offset: self.offset,
            len: u32::try_from(len).ok()?,
        })
    }
    fn advance(&mut self, spec: WholePgFrameSpec) {
        if spec.kind == 1 {
            self.offset += u64::from(spec.len);
        }
        if spec.kind != 2 {
            while self.ordinal < self.layout.lengths.len()
                && self.offset == self.layout.lengths[self.ordinal]
            {
                self.ordinal += 1;
                self.offset = 0;
            }
        }
        self.seq += 1;
    }
}
/// Stateful sealer owning a derived secret key and sharing the frozen frame layout.
pub struct WholePgSealCodec {
    key: SecretBytes,
    header: [u8; 80],
    cursor: Cursor,
    poison: bool,
}
impl WholePgSealCodec {
    /// Derives an owned stream key and starts sealing at the supplied manifest's first frame.
    pub fn new(key: &SecretBytes, manifest: &FrozenWholePgManifest) -> Result<Self> {
        Ok(Self {
            key: derive_application_key(key, ApplicationKeyPurpose::WholePgCaptureStreamV1)
                .map_err(|_| WholePgCarrierFault::SecretInvalid)?,
            header: manifest.header,
            cursor: Cursor {
                layout: Arc::clone(&manifest.layout),
                seq: 0,
                ordinal: 0,
                offset: 0,
            },
            poison: false,
        })
    }
    /// Returns the next sealing frame without advancing, or `None` after poisoning or exhaustion.
    pub fn next_frame(&self) -> Option<WholePgFrameSpec> {
        if self.poison {
            None
        } else {
            self.cursor.next()
        }
    }
    /// Encrypts the expected frame in place and advances; an error wipes the buffer and poisons the codec.
    pub fn seal_next_in_place(
        &mut self,
        buffer: &mut Zeroizing<Vec<u8>>,
    ) -> Result<WholePgFrameParts> {
        let result = (|| {
            let spec = self.next_frame().ok_or(WholePgCarrierFault::FrameInvalid)?;
            if buffer.len() != spec.len as usize {
                return Err(WholePgCarrierFault::FrameInvalid);
            }
            let header = spec.header();
            let aad = aad(&self.header, &header);
            let nonce = nonce(spec.seq);
            let tag = whole_pg_seal_in_place(&self.key, &nonce, &aad, buffer.as_mut_slice())
                .map_err(|_| WholePgCarrierFault::AuthenticationFailed)?;
            self.cursor.advance(spec);
            Ok(WholePgFrameParts { header, tag })
        })();
        if result.is_err() {
            self.poison = true;
            buffer.zeroize();
            buffer.clear();
        }
        result
    }
}
/// Stateful authenticated reader holding a derived key and shared expected manifest.
pub struct WholePgOpenCodec {
    key: SecretBytes,
    header: [u8; 80],
    cursor: Cursor,
    poison: bool,
    expected: Arc<WholePgManifestClaim>,
    terminal: [u8; 84],
    max_manifest: u64,
}
impl WholePgOpenCodec {
    /// Checks the observed carrier header, derives an owned key and retains the expected shared claim.
    pub fn new(
        key: &SecretBytes,
        expected: &FrozenWholePgManifest,
        observed_header: &[u8; 80],
    ) -> Result<Self> {
        if observed_header != &expected.header {
            return Err(WholePgCarrierFault::IntentMismatch);
        }
        Ok(Self {
            key: derive_application_key(key, ApplicationKeyPurpose::WholePgCaptureStreamV1)
                .map_err(|_| WholePgCarrierFault::SecretInvalid)?,
            header: expected.header,
            cursor: Cursor {
                layout: Arc::clone(&expected.layout),
                seq: 0,
                ordinal: 0,
                offset: 0,
            },
            poison: false,
            expected: Arc::clone(&expected.claim),
            terminal: expected.terminal,
            max_manifest: expected.bounds.max_manifest_bytes,
        })
    }
    /// Returns the next opening frame without advancing, or `None` after poisoning or exhaustion.
    pub fn next_frame(&self) -> Option<WholePgFrameSpec> {
        if self.poison {
            None
        } else {
            self.cursor.next()
        }
    }
    /// Authenticates and decrypts the expected frame; checks manifest/terminal bytes and wipes/poisons on error.
    pub fn open_next_in_place(
        &mut self,
        observed_header: &[u8; 21],
        tag: &[u8; 16],
        buffer: &mut Zeroizing<Vec<u8>>,
    ) -> Result<()> {
        let result = (|| {
            let spec = self.next_frame().ok_or(WholePgCarrierFault::FrameInvalid)?;
            if spec.header() != *observed_header || buffer.len() != spec.len as usize {
                return Err(WholePgCarrierFault::FrameInvalid);
            }
            whole_pg_open_in_place(
                &self.key,
                &nonce(spec.seq),
                &aad(&self.header, observed_header),
                tag,
                buffer.as_mut_slice(),
            )
            .map_err(|_| WholePgCarrierFault::AuthenticationFailed)?;
            if spec.kind == 0 {
                if buffer.len() as u64 > self.max_manifest {
                    return Err(WholePgCarrierFault::CapacityExceeded);
                }
                // Compare a fresh canonical serialization directly to the authenticated frame without a
                // second manifest plaintext allocation. Equality also excludes duplicate/unknown keys.
                let mut sink = CompareSink {
                    expected: buffer.as_slice(),
                    offset: 0,
                };
                serde_json::to_writer(&mut sink, self.expected.as_ref())
                    .map_err(|_| WholePgCarrierFault::NonCanonical)?;
                if sink.offset != buffer.len() {
                    return Err(WholePgCarrierFault::NonCanonical);
                }
            }
            if spec.kind == 2 && buffer.as_slice() != self.terminal {
                return Err(WholePgCarrierFault::TerminalMissing);
            }
            self.cursor.advance(spec);
            Ok(())
        })();
        if result.is_err() {
            self.poison = true;
            buffer.zeroize();
            buffer.clear();
        }
        result
    }
}

/// Fixed capture secret sizes; no copy of a plaintext frame is made for comparison.
pub fn whole_pg_secret_matches(expected: &SecretBytes, actual: &[u8]) -> bool {
    if !matches!(expected.len(), 32 | 64) || expected.len() != actual.len() {
        return false;
    }
    expected.expose().ct_eq(actual).into()
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(WholePgCarrierFault::BoundsOverflow)
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or(WholePgCarrierFault::BoundsOverflow)
}
fn check_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 || id.contains('\0') {
        Err(WholePgCarrierFault::ManifestInvalid)
    } else {
        Ok(())
    }
}
fn check_path(path: &str, b: &WholePgCarrierBounds) -> Result<()> {
    if path.is_empty()
        || path.len() as u64 > b.max_path_bytes
        || path.starts_with('/')
        || path.contains(['\\', '\0'])
        || path.split('/').count() as u64 > b.max_path_depth
        || path
            .split('/')
            .any(|v| v.is_empty() || v == "." || v == "..")
    {
        return Err(WholePgCarrierFault::PathUnsafe);
    }
    Ok(())
}
fn lower_hex(v: &str, len: usize) -> bool {
    v.len() == len
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn uuid_bytes(v: &str) -> Result<[u8; 16]> {
    if v.len() != 36 || [8, 13, 18, 23].into_iter().any(|i| v.as_bytes()[i] != b'-') {
        return Err(WholePgCarrierFault::ManifestInvalid);
    }
    let mut out = [0u8; 16];
    let mut n = 0;
    let mut high = 0;
    for (i, c) in v.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            continue;
        }
        let x = hex_digit(c).ok_or(WholePgCarrierFault::ManifestInvalid)?;
        if n % 2 == 0 {
            high = x;
        } else {
            out[n / 2] = high * 16 + x;
        }
        n += 1;
    }
    if out[6] >> 4 != 4 || out[8] >> 6 != 2 {
        return Err(WholePgCarrierFault::ManifestInvalid);
    }
    Ok(out)
}
fn lsn(s: &str) -> Result<u64> {
    let (a, b) = s
        .split_once('/')
        .ok_or(WholePgCarrierFault::ManifestInvalid)?;
    let high = u32::from_str_radix(a, 16).map_err(|_| WholePgCarrierFault::ManifestInvalid)?;
    let low = u32::from_str_radix(b, 16).map_err(|_| WholePgCarrierFault::ManifestInvalid)?;
    if format!("{high:X}/{low:X}") != s {
        return Err(WholePgCarrierFault::ManifestInvalid);
    }
    Ok((u64::from(high) << 32) | u64::from(low))
}
fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}
fn nonce(seq: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[8..].copy_from_slice(&seq.to_be_bytes());
    n
}
fn aad(header: &[u8; 80], frame: &[u8; 21]) -> [u8; AAD_PREFIX.len() + 101] {
    let mut a = [0u8; AAD_PREFIX.len() + 101];
    let n = AAD_PREFIX.len();
    a[..n].copy_from_slice(AAD_PREFIX);
    a[n..n + 80].copy_from_slice(header);
    a[n + 80..].copy_from_slice(frame);
    a
}
fn io_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "whole_pg_bounded_frame")
}
struct HashSink {
    hash: Sha256,
    len: u64,
    limit: u64,
}
impl Write for HashSink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let len = self.len.checked_add(b.len() as u64).ok_or_else(io_error)?;
        if len > self.limit {
            return Err(io_error());
        }
        self.hash.update(b);
        self.len = len;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct BufferSink<'a> {
    buffer: &'a mut Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for BufferSink<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let len = self
            .buffer
            .len()
            .checked_add(b.len())
            .ok_or_else(io_error)?;
        if len > self.limit || len > self.buffer.capacity() {
            return Err(io_error());
        }
        self.buffer.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct CompareSink<'a> {
    expected: &'a [u8],
    offset: usize,
}
impl Write for CompareSink<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let end = self.offset.checked_add(b.len()).ok_or_else(io_error)?;
        if self.expected.get(self.offset..end) != Some(b) {
            return Err(io_error());
        }
        self.offset = end;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
mod hex32 {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &[u8; 32],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        struct Hex<'a>(&'a [u8; 32]);
        impl fmt::Display for Hex<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
        s.collect_str(&Hex(value))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<[u8; 32], D::Error> {
        struct HexVisitor;
        impl serde::de::Visitor<'_> for HexVisitor {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("64 lowercase hexadecimal digits")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                if !lower_hex(v, 64) {
                    return Err(E::custom("whole_pg_digest_invalid"));
                }
                let mut out = [0u8; 32];
                for (i, p) in v.as_bytes().chunks_exact(2).enumerate() {
                    out[i] = hex_digit(p[0]).ok_or_else(|| E::custom("whole_pg_digest_invalid"))?
                        * 16
                        + hex_digit(p[1]).ok_or_else(|| E::custom("whole_pg_digest_invalid"))?;
                }
                Ok(out)
            }
        }
        d.deserialize_str(HexVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bounds() -> WholePgCarrierBounds {
        WholePgCarrierBounds {
            max_material_files: 128,
            max_directories: 128,
            max_path_bytes: 4096,
            max_path_depth: 16,
            max_single_plain_bytes: 1_000_000,
            max_material_plain_bytes: 4_000_000,
            max_manifest_bytes: 16384,
            max_header_bytes: 80,
            max_data_chunks: 4096,
            max_chunk_plain_bytes: 64,
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
            max_key_medium_allocation_bytes: 4096,
            key_medium_reserve_bytes: 4096,
            key_medium_free_floor_bytes: 4096,
        }
    }
    fn claim() -> WholePgManifestClaim {
        let materials = WholePgMaterialKind::ALL
            .into_iter()
            .enumerate()
            .map(|(i, kind)| {
                let (path, len) = match kind {
                    WholePgMaterialKind::MasterSecret => ("secrets/master".to_owned(), 32),
                    WholePgMaterialKind::ScramSecret => ("secrets/scram".to_owned(), 64),
                    _ => (format!("data/{i}"), 1),
                };
                WholePgMaterialClaim {
                    material_id: format!("m{i}"),
                    kind,
                    relative_path: path,
                    plain_len: len as u64,
                    plain_sha256: Sha256::digest(vec![i as u8; len]).into(),
                    chunk_count: 1,
                }
            })
            .collect();
        WholePgManifestClaim {
            schema: "wrokbot-whole-pg-capture".to_owned(),
            version: 1,
            operation_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            bundle_id: "00000000-0000-4000-8000-000000000002".to_owned(),
            request_id: "a".repeat(64),
            provenance: WholePgProvenanceClaim {
                release_sha256: [1; 32],
                maintenance_sha256: [2; 32],
                upstream_source_sha256: [3; 32],
                derived_patch_sha256: [4; 32],
                build_recipe_sha256: [5; 32],
                tool_inventory_material_id: "m14".to_owned(),
            },
            source: WholePgSourceClaim {
                instance_id: "instance".to_owned(),
                dataset_id: "dataset".to_owned(),
                deployment_id: "deployment".to_owned(),
                tenant_id: "tenant".to_owned(),
                system_identifier: "42".to_owned(),
                database_oid: 16384,
                key_id: "key".to_owned(),
                key_version: 1,
                canary_material_id: "m11".to_owned(),
                schema_material_id: "m3".to_owned(),
                migration_material_id: "m4".to_owned(),
                compatibility_material_id: "m14".to_owned(),
            },
            barrier: WholePgBarrierClaim {
                normal_closed_operation_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                audit_checkpoint_material_id: "m8".to_owned(),
                receipt_frontier_material_id: "m9".to_owned(),
                host_inventory_material_id: "m10".to_owned(),
                driver_facts_material_id: "m10".to_owned(),
                source_start_lsn: "0/1000".to_owned(),
                source_end_lsn: "0/2000".to_owned(),
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
        }
    }
    fn fill(frozen: &FrozenWholePgManifest, spec: WholePgFrameSpec, b: &mut Zeroizing<Vec<u8>>) {
        match spec.kind() {
            0 => frozen.encode_manifest_into(b).unwrap(),
            2 => frozen.encode_terminal_into(b).unwrap(),
            _ => {
                b.zeroize();
                b.clear();
                b.resize(spec.plain_len() as usize, spec.material_ordinal() as u8);
            }
        }
    }
    #[test]
    fn whole_pg_carrier_checked_wire_has_no_manifest_self_digest_cycle() {
        let frozen = FrozenWholePgManifest::check(claim(), bounds()).unwrap();
        let mut plain = Zeroizing::new(Vec::with_capacity(16384));
        frozen.encode_manifest_into(&mut plain).unwrap();
        let header = frozen.header();
        assert_eq!(&header[..8], b"WBPGCAP1");
        assert_eq!(
            plain.len(),
            u32::from_be_bytes(header[28..32].try_into().unwrap()) as usize
        );
        assert_eq!(&header[48..80], Sha256::digest(plain.as_slice()).as_slice());
        let n = u32::from_be_bytes(header[36..40].try_into().unwrap());
        let total = u64::from_be_bytes(header[40..48].try_into().unwrap());
        assert_eq!(
            frozen.wire_bytes().unwrap(),
            80 + plain.len() as u64 + 84 + total + (u64::from(n) + 2) * 37
        );
        let bad = WholePgCarrierBounds {
            max_wire_bytes: 1,
            ..bounds()
        };
        assert!(matches!(
            FrozenWholePgManifest::check(claim(), bad),
            Err(WholePgCarrierFault::CapacityExceeded)
        ));
    }
    #[test]
    fn whole_pg_carrier_roundtrip_preserves_the_single_frame_allocation() {
        let frozen = FrozenWholePgManifest::check(claim(), bounds()).unwrap();
        let key = SecretBytes::new(vec![7; 32]);
        let mut seal = WholePgSealCodec::new(&key, &frozen).unwrap();
        let mut open = WholePgOpenCodec::new(&key, &frozen, &frozen.header()).unwrap();
        let mut buffer = Zeroizing::new(Vec::with_capacity(16384));
        let pointer = buffer.as_ptr();
        let mut frames = 0;
        while let Some(spec) = seal.next_frame() {
            fill(&frozen, spec, &mut buffer);
            let parts = seal.seal_next_in_place(&mut buffer).unwrap();
            open.open_next_in_place(&parts.header, &parts.tag, &mut buffer)
                .unwrap();
            assert_eq!(buffer.as_ptr(), pointer);
            if spec.kind() == 1 {
                assert_eq!(
                    <[u8; 32]>::from(Sha256::digest(buffer.as_slice())),
                    frozen.materials()[spec.material_ordinal() as usize].plain_sha256
                );
            }
            buffer.zeroize();
            buffer.clear();
            frames += 1;
        }
        assert_eq!(frames, 17);
        assert!(open.next_frame().is_none());
    }
    #[test]
    fn whole_pg_carrier_reordered_frame_wipes_and_poison_is_permanent() {
        let frozen = FrozenWholePgManifest::check(claim(), bounds()).unwrap();
        let key = SecretBytes::new(vec![7; 32]);
        let mut seal = WholePgSealCodec::new(&key, &frozen).unwrap();
        let mut open = WholePgOpenCodec::new(&key, &frozen, &frozen.header()).unwrap();
        let mut buffer = Zeroizing::new(Vec::with_capacity(16384));
        frozen.encode_manifest_into(&mut buffer).unwrap();
        let mut parts = seal.seal_next_in_place(&mut buffer).unwrap();
        parts.header[4] ^= 1;
        assert_eq!(
            open.open_next_in_place(&parts.header, &parts.tag, &mut buffer),
            Err(WholePgCarrierFault::FrameInvalid)
        );
        assert!(buffer.is_empty());
        assert!(open.next_frame().is_none());
    }
    #[test]
    fn whole_pg_carrier_bad_authentication_wipes_without_exposing_partial_plaintext() {
        let frozen = FrozenWholePgManifest::check(claim(), bounds()).unwrap();
        let key = SecretBytes::new(vec![7; 32]);
        let mut seal = WholePgSealCodec::new(&key, &frozen).unwrap();
        let mut open = WholePgOpenCodec::new(&key, &frozen, &frozen.header()).unwrap();
        let mut buffer = Zeroizing::new(Vec::with_capacity(16384));
        frozen.encode_manifest_into(&mut buffer).unwrap();
        let mut parts = seal.seal_next_in_place(&mut buffer).unwrap();
        parts.tag[0] ^= 1;
        assert_eq!(
            open.open_next_in_place(&parts.header, &parts.tag, &mut buffer),
            Err(WholePgCarrierFault::AuthenticationFailed)
        );
        assert!(buffer.is_empty());
        assert!(open.next_frame().is_none());
    }
    #[test]
    fn whole_pg_carrier_closed_schema_and_coverage_reject_ambiguity() {
        let bytes = serde_json::to_string(&claim()).unwrap();
        let unknown = bytes.replacen('{', "{\"unregistered\":0,", 1);
        assert!(serde_json::from_str::<WholePgManifestClaim>(&unknown).is_err());
        let duplicate = bytes.replacen('{', "{\"version\":1,", 1);
        assert!(serde_json::from_str::<WholePgManifestClaim>(&duplicate).is_err());
        let mut broken = claim();
        broken.coverage[0].presence = WholePgPresence::ControlledEmpty;
        assert!(matches!(
            FrozenWholePgManifest::check(broken, bounds()),
            Err(WholePgCarrierFault::MaterialMissing)
        ));
        let mut broken = claim();
        broken.materials[12].relative_path = "../master".to_owned();
        assert!(matches!(
            FrozenWholePgManifest::check(broken, bounds()),
            Err(WholePgCarrierFault::PathUnsafe)
        ));
    }
    #[test]
    fn whole_pg_carrier_required_coverage_cannot_be_proved_by_an_empty_file() {
        let mut c = claim();
        c.materials[0].plain_len = 0;
        c.materials[0].chunk_count = 0;
        c.materials[0].plain_sha256 = Sha256::digest(b"").into();
        assert!(matches!(
            FrozenWholePgManifest::check(c, bounds()),
            Err(WholePgCarrierFault::MaterialMissing)
        ));
        let mut c = claim();
        c.materials[0].plain_len = 0;
        c.materials[0].chunk_count = 0;
        c.materials[0].plain_sha256 = Sha256::digest(b"").into();
        c.coverage[5].evidence_material_id = "m0".into();
        assert!(matches!(
            FrozenWholePgManifest::check(c, bounds()),
            Err(WholePgCarrierFault::MaterialMissing)
        ));
    }
}
