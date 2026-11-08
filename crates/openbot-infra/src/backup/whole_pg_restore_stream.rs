//! Authenticated whole-PG input and the same operation's private candidate.
//! Input bytes, parsed DATA and a Pool do not construct candidate authority.

use std::fs::File;
use std::path::PathBuf;
use std::time::Instant;

use crate::db::pool::{DatabasePool, GuardedClient};
use crate::recovery_control::{RecoveryControlError, RestoreStages};

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub(crate) use candidate_sql::{retire_cohort_before, upgrade_candidate_schema_before};

struct RestoreCandidateBinding {
    operation_id: uuid::Uuid,
    epoch: [u8; 32],
    candidate_generation: uuid::Uuid,
    source_bundle_id: uuid::Uuid,
    deployment_id: String,
    tenant_id: String,
    dataset_id: String,
    source_installation_id: String,
    target_installation_id: String,
    candidate_database_oid: u32,
    pg_system_identifier: String,
    profile_binding: [u8; 32],
    native_version: u32,
    max_batches: u64,
    max_requirements: u64,
}

/// Public slot DATA from the authenticated original configuration inventory.
/// No public constructor, arbitrary path or secret-derived digest is accepted.
struct RestoreConfigurationSlot {
    source_ref: String,
    binding_generation: i64,
    public_binding: [u8; 32],
    owner_kind: String,
    owner_id: String,
}

/// Only the same session's verified Child/UDS/PG binding creates this owner.
/// All SQL stages borrow its original connection custody and bound pool.
pub(crate) struct PendingRestoreCandidateAuthority {
    original_process: wrok_bot_macos_process::ProcessIdentity,
    program: File,
    socket_directory: File,
    data_directory: File,
    data_path: PathBuf,
    pool: DatabasePool,
    original_client: Option<GuardedClient>,
    binding: RestoreCandidateBinding,
    configuration_inventory: Vec<RestoreConfigurationSlot>,
    audit_key: openbot_domain::vault::SecretBytes,
    #[cfg(all(feature = "server-runtime", target_os = "macos"))]
    sql: candidate_sql::CandidateSqlState,
}

#[cfg(feature = "server-runtime")]
pub use input::{
    AuthenticatedRestoreSecrets, FrozenWholePgRestoreInput, RetainedRestoreInputFailure,
    ReviewedWholePgRestoreIntent, VerifiedWholePgRestoreStaging, verify_whole_pg_restore_input,
};

#[cfg(feature = "server-runtime")]
pub(crate) mod input {
    use super::{File, RecoveryControlError};
    // S17 authenticates the original carrier before historical secrets reach a
    // consumer. This component grants neither staging nor Current authority.
    use openbot_domain::backup::whole_pg_carrier::{
        WholePgManifestExpectation, WholePgOpenCodec, open_whole_pg_manifest_in_place,
    };
    use openbot_domain::backup::{
        CheckedWholePgCarrierBounds, FrozenWholePgManifest, WholePgCarrierFault,
        WholePgMaterialKind,
    };
    use openbot_domain::vault::SecretBytes;
    use sha2::{Digest, Sha256};
    use std::io;
    use std::os::unix::fs::{FileExt, MetadataExt};
    use zeroize::{Zeroize, Zeroizing};

    /// Independent expectations sealed from the original reviewed request.
    /// No public data constructor, Clone or Serde implementation.
    pub struct ReviewedWholePgRestoreIntent {
        operation: crate::recovery_control::Hex32,
        expected: WholePgManifestExpectation,
        deployment_id: String,
        tenant_id: String,
        dataset_id: String,
        source_installation_id: String,
    }

    /// Original files and complete observed identities. Only the original control
    /// input producer may assemble this owner after charging its finite allocations.
    pub struct FrozenWholePgRestoreInput {
        operation: crate::recovery_control::Hex32,
        carrier: File,
        key_medium: File,
        carrier_identity: RestoreInputFileIdentity,
        key_identity: RestoreInputFileIdentity,
        bounds: CheckedWholePgCarrierBounds,
        buffer: Zeroizing<Vec<u8>>,
        key_bytes: Zeroizing<[u8; 104]>,
        decoded_secrets: Zeroizing<[u8; 96]>,
        raw_read: Option<io::Result<()>>,
        raw_eof: Option<io::Result<usize>>,
        raw_metadata: Option<io::Result<std::fs::Metadata>>,
        manifest: Option<FrozenWholePgManifest>,
        authenticated_frames: u64,
        authenticated: Option<AuthenticatedRestoreSecrets>,
        staging: Option<RestoreStagingWork>,
    }

    /// Transfer only the original session's prepaid held inputs. Authentication
    /// and stable staging remain separate consumers of these bytes.
    pub(crate) fn from_original_held(
        operation: crate::recovery_control::Hex32,
        carrier: (File, std::fs::Metadata),
        key_medium: (File, std::fs::Metadata),
        bounds: CheckedWholePgCarrierBounds,
        buffer: Zeroizing<Vec<u8>>,
        expected: WholePgManifestExpectation,
        business: (String, String, String, String),
    ) -> (FrozenWholePgRestoreInput, ReviewedWholePgRestoreIntent) {
        let (carrier, carrier_metadata) = carrier;
        let (key_medium, key_metadata) = key_medium;
        let (deployment_id, tenant_id, dataset_id, source_installation_id) = business;
        // The session already checked the complete held/named file boundary.
        let identity = |value: &std::fs::Metadata| RestoreInputFileIdentity {
            device: value.dev(),
            inode: value.ino(),
            uid: value.uid(),
            mode: value.mode(),
            links: value.nlink(),
            length: value.len(),
            modified_seconds: value.mtime(),
            modified_nanos: value.mtime_nsec(),
            changed_seconds: value.ctime(),
            changed_nanos: value.ctime_nsec(),
        };
        (
            FrozenWholePgRestoreInput {
                operation,
                carrier_identity: identity(&carrier_metadata),
                key_identity: identity(&key_metadata),
                carrier,
                key_medium,
                bounds,
                buffer,
                key_bytes: Zeroizing::new([0; 104]),
                decoded_secrets: Zeroizing::new([0; 96]),
                raw_read: None,
                raw_eof: None,
                raw_metadata: None,
                manifest: None,
                authenticated_frames: 0,
                authenticated: None,
                staging: None,
            },
            ReviewedWholePgRestoreIntent {
                operation,
                expected,
                deployment_id,
                tenant_id,
                dataset_id,
                source_installation_id,
            },
        )
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct RestoreInputFileIdentity {
        device: u64,
        inode: u64,
        uid: u32,
        mode: u32,
        links: u64,
        length: u64,
        modified_seconds: i64,
        modified_nanos: i64,
        changed_seconds: i64,
        changed_nanos: i64,
    }
    impl RestoreInputFileIdentity {
        fn from_metadata(value: &std::fs::Metadata) -> Result<Self, WholePgCarrierFault> {
            if !value.is_file() || value.nlink() != 1 || value.mode() & 0o777 != 0o600 {
                return Err(WholePgCarrierFault::PathUnsafe);
            }
            Ok(Self {
                device: value.dev(),
                inode: value.ino(),
                uid: value.uid(),
                mode: value.mode(),
                links: value.nlink(),
                length: value.len(),
                modified_seconds: value.mtime(),
                modified_nanos: value.mtime_nsec(),
                changed_seconds: value.ctime(),
                changed_nanos: value.ctime_nsec(),
            })
        }
    }

    /// Full carrier authentication is the only constructor. Recovery K is never
    /// returned here and cannot be mistaken for the historical master.
    pub struct AuthenticatedRestoreSecrets {
        master: SecretBytes,
        scram: SecretBytes,
    }
    impl AuthenticatedRestoreSecrets {
        /// Original authenticated 32-byte historical master; not recovery K.
        pub fn historical_master(&self) -> &SecretBytes {
            &self.master
        }
        /// Original authenticated 64-byte PostgreSQL SCRAM material.
        pub fn postgres_scram(&self) -> &SecretBytes {
            &self.scram
        }
    }

    /// Retains original files, raw IO, frame allocation and decoded bytes at the
    /// first failure. Never exposes a partially authenticated secret or receipt.
    pub struct RetainedRestoreInputFailure {
        fault: WholePgCarrierFault,
        input: FrozenWholePgRestoreInput,
        intent: ReviewedWholePgRestoreIntent,
        control_error: Option<RecoveryControlError>,
    }
    impl RetainedRestoreInputFailure {
        pub fn fault(&self) -> WholePgCarrierFault {
            self.fault
        }
    }

    /// Authenticated carrier custody, not a stable-staging or activation receipt.
    /// Kept private until the original control owner can move its inputs here.
    struct AuthenticatedWholePgRestoreCarrier {
        input: FrozenWholePgRestoreInput,
        intent: ReviewedWholePgRestoreIntent,
        secrets: AuthenticatedRestoreSecrets,
    }

    fn authenticate_whole_pg_restore_carrier_before(
        mut input: FrozenWholePgRestoreInput,
        intent: ReviewedWholePgRestoreIntent,
        session: &mut crate::recovery_control::RestoreControlSession,
    ) -> Result<AuthenticatedWholePgRestoreCarrier, RetainedRestoreInputFailure> {
        use crate::recovery_control::RestoreCapacityResource;
        let stages = session.input_stages();
        let mut control_error = None;
        // The input producer owns/precharges the actual held descriptors and frame
        // allocation. Decode bounds and both final SecretBytes allocations are paid
        // here before they can be allocated. No second ledger or limits are minted.
        let admitted = (|| -> Result<_, RecoveryControlError> {
            // Decoder storage shares the original operation's remaining metadata,
            // rather than reserving the full profile again after the owner exists.
            let mut bounds = *input.bounds;
            bounds.max_metadata_bytes = bounds
                .max_metadata_bytes
                .min(stages.capacity_available(RestoreCapacityResource::MetadataBytes)?);
            input.bounds = bounds.check().map_err(|_| {
                RecoveryControlError::new(
                    crate::recovery_control::RecoveryControlFault::CapacityExceeded,
                )
            })?;
            let metadata = stages.admit_capacity(
                RestoreCapacityResource::MetadataBytes,
                input.bounds.max_metadata_bytes,
            )?;
            let secrets =
                stages.admit_capacity(RestoreCapacityResource::SecretMemoryBytes, 32 + 32 + 96)?;
            let structures = stages.admit_capacity(
                RestoreCapacityResource::SecretStructureBytes,
                (4 * std::mem::size_of::<SecretBytes>()) as u64,
            )?;
            let deadline = stages.convergence_deadline()?;
            stages.effect_before(deadline)?;
            Ok((metadata, secrets, structures, deadline))
        })();
        let result = match admitted {
            Ok((metadata, secrets, structures, deadline)) => {
                let mut check = || {
                    stages.effect_before(deadline).map(|_| ()).map_err(|error| {
                        let fault = restore_input_control_fault(error.fault());
                        control_error = Some(error);
                        fault
                    })
                };
                match authenticate_original_carrier(&mut input, &intent, &mut check) {
                    Ok(()) => {
                        let actual_metadata = input
                            .manifest
                            .as_ref()
                            .expect("authenticated manifest")
                            .metadata_bytes();
                        let authenticated = input
                            .authenticated
                            .as_ref()
                            .expect("complete authenticated secrets retained");
                        let settled = stages
                            .settle_capacity(metadata, actual_metadata)
                            .and_then(|()| {
                                stages.settle_capacity(
                                    secrets,
                                    authenticated.master.allocation_capacity() as u64
                                        + authenticated.scram.allocation_capacity() as u64,
                                )
                            })
                            .and_then(|()| {
                                stages.settle_capacity(
                                    structures,
                                    (2 * std::mem::size_of::<SecretBytes>()) as u64,
                                )
                            });
                        match settled {
                            Ok(()) => Ok(input
                                .authenticated
                                .take()
                                .expect("complete authenticated secrets retained")),
                            Err(error) => {
                                let fault = restore_input_control_fault(error.fault());
                                control_error = Some(error);
                                Err(fault)
                            }
                        }
                    }
                    Err(fault) => Err(fault),
                }
            }
            Err(error) => {
                let fault = restore_input_control_fault(error.fault());
                control_error = Some(error);
                Err(fault)
            }
        };
        match result {
            Ok(secrets) => Ok(AuthenticatedWholePgRestoreCarrier {
                input,
                intent,
                secrets,
            }),
            Err(fault) => Err(RetainedRestoreInputFailure {
                fault,
                input,
                intent,
                control_error,
            }),
        }
    }

    fn restore_input_control_fault(
        fault: crate::recovery_control::RecoveryControlFault,
    ) -> WholePgCarrierFault {
        use crate::recovery_control::RecoveryControlFault as F;
        match fault {
            F::EffectExpired | F::ConvergenceExpired => WholePgCarrierFault::DeadlineExpired,
            F::CapacityExceeded => WholePgCarrierFault::CapacityExceeded,
            F::IoFailure => WholePgCarrierFault::IoFailure,
            _ => WholePgCarrierFault::ClockUnavailable,
        }
    }

    // The private component takes one original-clock/owner check around every IO
    // and crypto action. Production must reserve bounds before entering; the fixture
    // calls this exact engine with actual held files and a finite real clock.
    fn authenticate_original_carrier(
        input: &mut FrozenWholePgRestoreInput,
        intent: &ReviewedWholePgRestoreIntent,
        check: &mut impl FnMut() -> Result<(), WholePgCarrierFault>,
    ) -> Result<(), WholePgCarrierFault> {
        input.check_identity(false, check)?;
        input.check_identity(true, check)?;
        if input.key_identity.length != 104 {
            return Err(WholePgCarrierFault::KeyMediumInvalid);
        }
        if input.carrier_identity.length > input.bounds.max_wire_bytes {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        check()?;
        input.raw_read = Some(
            input
                .key_medium
                .read_exact_at(input.key_bytes.as_mut_slice(), 0),
        );
        check()?;
        input
            .raw_read
            .as_ref()
            .ok_or(WholePgCarrierFault::IoFailure)?
            .as_ref()
            .map_err(read_fault)?;
        if &input.key_bytes[..8] != b"WBPGKEY1"
            || input.key_bytes[8..24] != intent.expected.bundle_id
            || input.key_bytes[24..40] != intent.expected.source_operation_id
            || input.key_bytes[40..72] != intent.expected.manifest_sha256
        {
            return Err(WholePgCarrierFault::KeyMediumInvalid);
        }
        let key = SecretBytes::new(input.key_bytes[72..104].to_vec());
        let mut header = [0u8; 80];
        input.read_at(0, &mut header, check)?;
        // The operation profile is an upper bound, not the capture's chosen
        // chunk size. This is the one header boundary; AEAD then authenticates
        // these bytes and the original codec owns the resulting exact layout.
        let chunk = u64::from(u32::from_be_bytes(
            header[32..36].try_into().expect("fixed chunk length"),
        ));
        if chunk == 0 {
            return Err(WholePgCarrierFault::FrameInvalid);
        }
        if chunk > input.bounds.max_chunk_plain_bytes {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        let mut effective = *input.bounds;
        effective.max_chunk_plain_bytes = chunk;
        input.bounds = effective.check()?;
        let manifest_len =
            u32::from_be_bytes(header[28..32].try_into().expect("fixed manifest length")) as usize;
        if manifest_len as u64 > input.bounds.max_manifest_bytes
            || manifest_len > input.buffer.capacity()
        {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        let mut frame_header = [0u8; 21];
        input.read_at(80, &mut frame_header, check)?;
        input.read_frame(101, manifest_len, check)?;
        let mut tag = [0u8; 16];
        input.read_at(101 + manifest_len as u64, &mut tag, check)?;
        check()?;
        input.manifest = Some(open_whole_pg_manifest_in_place(
            &key,
            &intent.expected,
            &header,
            &frame_header,
            &tag,
            &mut input.buffer,
            input.bounds,
        )?);
        check()?;
        let manifest = input
            .manifest
            .as_ref()
            .expect("authenticated manifest stored");
        check_original_material_inventory(manifest)?;
        let source = &manifest.claim().source;
        if source.deployment_id != intent.deployment_id
            || source.tenant_id != intent.tenant_id
            || source.dataset_id != intent.dataset_id
            || source.instance_id != intent.source_installation_id
        {
            return Err(WholePgCarrierFault::IntentMismatch);
        }
        match manifest.wire_bytes()?.cmp(&input.carrier_identity.length) {
            std::cmp::Ordering::Greater => return Err(WholePgCarrierFault::ShortRead),
            std::cmp::Ordering::Less => return Err(WholePgCarrierFault::ExtraTail),
            std::cmp::Ordering::Equal => {}
        }
        let mut codec = WholePgOpenCodec::new(&key, manifest, &header)?;
        // Authenticate seq0 again via the existing full-stream cursor. No skip.
        let mut at = 80u64;
        let mut ordinal = 0usize;
        let mut length = 0u64;
        let mut hash = Sha256::new();
        let mut terminal = false;
        while let Some(spec) = codec.next_frame() {
            check()?;
            input.read_at(at, &mut frame_header, check)?;
            at = at
                .checked_add(21)
                .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            input.read_frame(at, spec.plain_len() as usize, check)?;
            at = at
                .checked_add(u64::from(spec.plain_len()))
                .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            input.read_at(at, &mut tag, check)?;
            at = at
                .checked_add(16)
                .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            check()?;
            codec.open_next_in_place(&frame_header, &tag, &mut input.buffer)?;
            check()?;
            if spec.kind() == 1 {
                let target = spec.material_ordinal() as usize;
                while ordinal < target {
                    input.finish_material(
                        ordinal,
                        std::mem::replace(&mut hash, Sha256::new()),
                        length,
                    )?;
                    ordinal += 1;
                    length = 0;
                }
                let material = input
                    .manifest
                    .as_ref()
                    .expect("authenticated manifest stored")
                    .materials()
                    .get(ordinal)
                    .ok_or(WholePgCarrierFault::MaterialMissing)?;
                if spec.offset() != length {
                    return Err(WholePgCarrierFault::FrameInvalid);
                }
                let base = match material.kind {
                    WholePgMaterialKind::MasterSecret => Some(0usize),
                    WholePgMaterialKind::ScramSecret => Some(32usize),
                    _ => None,
                };
                if let Some(base) = base {
                    let begin = base
                        .checked_add(
                            usize::try_from(spec.offset())
                                .map_err(|_| WholePgCarrierFault::BoundsOverflow)?,
                        )
                        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
                    let end = begin
                        .checked_add(input.buffer.len())
                        .ok_or(WholePgCarrierFault::BoundsOverflow)?;
                    input
                        .decoded_secrets
                        .get_mut(begin..end)
                        .ok_or(WholePgCarrierFault::SecretInvalid)?
                        .copy_from_slice(input.buffer.as_slice());
                }
                hash.update(input.buffer.as_slice());
                length = length
                    .checked_add(input.buffer.len() as u64)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            } else if spec.kind() == 2 {
                terminal = true;
            }
            input.authenticated_frames += 1;
            // Wipe every byte written by this frame before clearing its length.
            // Earlier frames were wiped here too; spare capacity therefore
            // contains no uncleared frame plaintext. Drop still wipes it all.
            input.buffer.as_mut_slice().zeroize();
            input.buffer.clear();
        }
        let count = input
            .manifest
            .as_ref()
            .expect("authenticated manifest stored")
            .materials()
            .len();
        while ordinal < count {
            input.finish_material(ordinal, std::mem::replace(&mut hash, Sha256::new()), length)?;
            ordinal += 1;
            length = 0;
        }
        if !terminal || at != input.carrier_identity.length {
            return Err(WholePgCarrierFault::TerminalMissing);
        }
        let mut eof = [0u8; 1];
        check()?;
        input.raw_eof = Some(input.carrier.read_at(&mut eof, at));
        check()?;
        match input.raw_eof.as_ref() {
            Some(Ok(0)) => {}
            Some(Ok(_)) => return Err(WholePgCarrierFault::ExtraTail),
            _ => return Err(WholePgCarrierFault::IoFailure),
        }
        input.check_identity(false, check)?;
        input.check_identity(true, check)?;
        check()?;
        input.authenticated = Some(AuthenticatedRestoreSecrets {
            master: SecretBytes::new(input.decoded_secrets[..32].to_vec()),
            scram: SecretBytes::new(input.decoded_secrets[32..].to_vec()),
        });
        input.decoded_secrets.zeroize();
        input.key_bytes.zeroize();
        check()?;
        Ok(())
    }

    // The original 045 producer allows these thirteen metadata leaves. Keeping
    // this bounded mapping here avoids accepting a caller-selected staging path.
    fn check_original_material_inventory(
        manifest: &FrozenWholePgManifest,
    ) -> Result<(), WholePgCarrierFault> {
        use WholePgMaterialKind as K;
        let fixed = [
            (
                "audit-checkpoint",
                "metadata/audit-checkpoint.jsonl",
                K::AuditCheckpoint,
            ),
            ("schema", "metadata/schema.jsonl", K::SchemaChecksum),
            (
                "migrations",
                "metadata/migrations.jsonl",
                K::MigrationChecksum,
            ),
            (
                "receipt-frontier",
                "metadata/receipt-frontier.jsonl",
                K::ReceiptFrontier,
            ),
            (
                "installation",
                "metadata/installation.json",
                K::InstallationRecord,
            ),
            (
                "host-inventory",
                "metadata/host-inventory.json",
                K::InstallationRecord,
            ),
            (
                "compatibility",
                "metadata/compatibility.json",
                K::CompatibilityRecord,
            ),
            ("key-metadata", "metadata/key-metadata.json", K::KeyMetadata),
            (
                "driver-facts",
                "metadata/driver-facts.json",
                K::CompatibilityRecord,
            ),
            (
                "tool-inventory",
                "metadata/tool-inventory.json",
                K::CompatibilityRecord,
            ),
            (
                "profile-inventory",
                "metadata/profile-inventory.jsonl",
                K::ProfileInventory,
            ),
            (
                "workspace-inventory",
                "metadata/workspace-inventory.jsonl",
                K::WorkspaceInventory,
            ),
            (
                "ui-preferences-v1",
                "metadata/ui-preferences-v1.json",
                K::ProfileInventory,
            ),
        ];
        let mut seen = [false; 13];
        for material in manifest.materials() {
            if let Some(index) = fixed.iter().position(|(id, path, kind)| {
                material.material_id == *id
                    && material.relative_path == *path
                    && material.kind == *kind
            }) {
                if seen[index] {
                    return Err(WholePgCarrierFault::MaterialMissing);
                }
                seen[index] = true;
                continue;
            }
            let valid = match material.kind {
                K::PostgresBase => {
                    material
                        .relative_path
                        .strip_prefix("pgdata/")
                        .is_some_and(|path| {
                            !path.starts_with("pg_wal/")
                                && !path.starts_with("pg_tblspc/")
                                && ![
                                    "postgresql.conf",
                                    "postgresql.auto.conf",
                                    "pg_hba.conf",
                                    "pg_ident.conf",
                                ]
                                .contains(&path)
                        })
                }
                K::WalSegment => material
                    .relative_path
                    .strip_prefix("pgdata/pg_wal/")
                    .is_some_and(|path| !path.contains('/')),
                K::PostgresConfig => [
                    "pgdata/postgresql.conf",
                    "pgdata/postgresql.auto.conf",
                    "pgdata/pg_hba.conf",
                    "pgdata/pg_ident.conf",
                ]
                .contains(&material.relative_path.as_str()),
                K::Artifact => material
                    .relative_path
                    .strip_prefix("materials/artifact-spool/")
                    .is_some_and(|path| {
                        !path.contains('/')
                            && path.len() <= 44
                            && material.material_id.strip_prefix("artifact:") == Some(path)
                    }),
                K::MasterSecret => {
                    material.material_id == "master-secret"
                        && material.relative_path == "secrets/master"
                }
                K::ScramSecret => {
                    material.material_id == "scram-secret"
                        && material.relative_path == "secrets/scram"
                }
                _ => false,
            };
            if !valid {
                return Err(WholePgCarrierFault::ExtraMaterial);
            }
        }
        // The twelve fixed projection leaves are required. The thirteenth,
        // ui-preferences-v1, is absent for 045's AbsentOriginalSource branch
        // (the real F07 carrier uses that branch). Absence is not an empty
        // preferences snapshot; semantic host-inventory reconciliation belongs
        // to stable-staging consumption, not this cryptographic receipt.
        if !seen[..12].iter().all(|value| *value) {
            return Err(WholePgCarrierFault::MaterialMissing);
        }
        Ok(())
    }

    fn read_fault(error: &io::Error) -> WholePgCarrierFault {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            WholePgCarrierFault::ShortRead
        } else {
            WholePgCarrierFault::IoFailure
        }
    }
    impl FrozenWholePgRestoreInput {
        fn check_identity(
            &mut self,
            key: bool,
            check: &mut impl FnMut() -> Result<(), WholePgCarrierFault>,
        ) -> Result<(), WholePgCarrierFault> {
            check()?;
            self.raw_metadata = Some(if key {
                self.key_medium.metadata()
            } else {
                self.carrier.metadata()
            });
            check()?;
            let actual = self
                .raw_metadata
                .as_ref()
                .ok_or(WholePgCarrierFault::IoFailure)?
                .as_ref()
                .map_err(|_| WholePgCarrierFault::IoFailure)?;
            let expected = if key {
                self.key_identity
            } else {
                self.carrier_identity
            };
            if RestoreInputFileIdentity::from_metadata(actual)? != expected {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            Ok(())
        }
        fn read_at(
            &mut self,
            offset: u64,
            output: &mut [u8],
            check: &mut impl FnMut() -> Result<(), WholePgCarrierFault>,
        ) -> Result<(), WholePgCarrierFault> {
            check()?;
            self.raw_read = Some(self.carrier.read_exact_at(output, offset));
            check()?;
            self.raw_read
                .as_ref()
                .ok_or(WholePgCarrierFault::IoFailure)?
                .as_ref()
                .map_err(read_fault)
                .copied()
        }
        fn read_frame(
            &mut self,
            offset: u64,
            length: usize,
            check: &mut impl FnMut() -> Result<(), WholePgCarrierFault>,
        ) -> Result<(), WholePgCarrierFault> {
            if length > self.buffer.capacity()
                || length as u64
                    > self
                        .bounds
                        .max_manifest_bytes
                        .max(self.bounds.max_chunk_plain_bytes)
                        .max(84)
            {
                return Err(WholePgCarrierFault::CapacityExceeded);
            }
            self.buffer.as_mut_slice().zeroize();
            self.buffer.clear();
            self.buffer.resize(length, 0);
            check()?;
            self.raw_read = Some(
                self.carrier
                    .read_exact_at(self.buffer.as_mut_slice(), offset),
            );
            check()?;
            self.raw_read
                .as_ref()
                .ok_or(WholePgCarrierFault::IoFailure)?
                .as_ref()
                .map_err(read_fault)
                .copied()
        }
        fn finish_material(
            &self,
            ordinal: usize,
            hash: Sha256,
            length: u64,
        ) -> Result<(), WholePgCarrierFault> {
            let material = self
                .manifest
                .as_ref()
                .ok_or(WholePgCarrierFault::ManifestInvalid)?
                .materials()
                .get(ordinal)
                .ok_or(WholePgCarrierFault::MaterialMissing)?;
            let mut digest: [u8; 32] = hash.finalize().into();
            let equal = digest == material.plain_sha256 && length == material.plain_len;
            digest.zeroize();
            if !equal {
                return Err(WholePgCarrierFault::ReadbackFailed);
            }
            Ok(())
        }
    }

    use crate::recovery_control::{
        OwnedRestoreCandidatePlan, RestoreCapacityResource as Capacity, RestoreControlSession,
        RestoreNewChildKind, RestoreStorageKind,
    };
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::ffi::OsStr;
    use std::time::Instant;

    struct StagingDirectory {
        file: Option<File>,
        parent: Option<usize>,
        relative: Option<String>,
        identity: Option<(u64, u64, u32, u32)>,
    }
    struct StagingMaterial {
        file: Option<File>,
        parent: usize,
        stamp: Option<RestoreInputFileIdentity>,
    }
    struct RestoreStagingWork {
        import_intent: Option<crate::recovery_control::RestoreStageIntent>,
        plan: Option<OwnedRestoreCandidatePlan>,
        directories: Vec<StagingDirectory>,
        materials: Vec<StagingMaterial>,
        created: Option<rustix::io::Result<()>>,
        opened: Option<io::Result<File>>,
        written: Option<io::Result<()>>,
        metadata: Option<io::Result<std::fs::Metadata>>,
        named: Option<rustix::io::Result<rustix::fs::Stat>>,
        space: Option<rustix::io::Result<rustix::fs::StatVfs>>,
        synced: Option<io::Result<()>>,
        directory: Option<rustix::io::Result<rustix::fs::Dir>>,
        entry: Option<rustix::io::Result<rustix::fs::DirEntry>>,
        json_error: Option<serde_json::Error>,
    }
    impl RestoreStagingWork {
        fn new() -> Self {
            Self {
                import_intent: None,
                plan: None,
                directories: Vec::new(),
                materials: Vec::new(),
                created: None,
                opened: None,
                written: None,
                metadata: None,
                named: None,
                space: None,
                synced: None,
                directory: None,
                entry: None,
                json_error: None,
            }
        }
        fn directory_file(&self, index: usize) -> &File {
            self.directories[index]
                .file
                .as_ref()
                .expect("original staging directory retained")
        }
        fn component(&self, index: usize) -> &OsStr {
            match index {
                0 => self
                    .plan
                    .as_ref()
                    .expect("original plan retained")
                    .component(),
                1 => OsStr::new("materials"),
                2 => OsStr::new("staging"),
                _ => OsStr::new(
                    self.directories[index]
                        .relative
                        .as_deref()
                        .expect("material prefix")
                        .rsplit('/')
                        .next()
                        .expect("nonempty prefix"),
                ),
            }
        }
        fn parent(&self, index: usize) -> &File {
            match self.directories[index].parent {
                Some(parent) => self.directory_file(parent),
                None => self.plan.as_ref().expect("original plan retained").parent(),
            }
        }
        fn create_directory(
            &mut self,
            parent: Option<usize>,
            relative: Option<&str>,
            session: &mut RestoreControlSession,
            deadline: Instant,
            error: &mut Option<RecoveryControlError>,
        ) -> Result<usize, WholePgCarrierFault> {
            if self.directories.len() == self.directories.capacity() {
                return Err(WholePgCarrierFault::CapacityExceeded);
            }
            let index = self.directories.len();
            self.directories.push(StagingDirectory {
                file: None,
                parent,
                relative: relative.map(str::to_owned),
                identity: None,
            });
            stage_effect(session, deadline, error)?;
            self.space = Some(rustix::fs::fstatvfs(self.parent(index)));
            stage_effect(session, deadline, error)?;
            let grain = self
                .space
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .map(|s| s.f_frsize.max(s.f_bsize))
                .filter(|v| *v > 0)
                .ok_or(WholePgCarrierFault::IoFailure)?;
            let count = session
                .admit_capacity(Capacity::MaterialDirectories, 1)
                .map_err(|e| retain_stage_control(e, error))?;
            let growth = session
                .admit_storage_before(
                    self.parent(index),
                    grain,
                    RestoreStorageKind::Working,
                    deadline,
                )
                .map_err(|e| retain_stage_control(e, error))?;
            let child = session
                .admit_new_child_before(
                    self.parent(index),
                    self.component(index),
                    grain,
                    RestoreNewChildKind::Directory,
                    deadline,
                )
                .map_err(|e| retain_stage_control(e, error))?;
            self.created = Some(rustix::fs::mkdirat(
                self.parent(index),
                self.component(index),
                Mode::from_bits_truncate(0o700),
            ));
            stage_effect(session, deadline, error)?;
            if !matches!(self.created, Some(Ok(()))) {
                return Err(WholePgCarrierFault::PathUnsafe);
            }
            self.opened = Some(
                rustix::fs::openat(
                    self.parent(index),
                    self.component(index),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            stage_effect(session, deadline, error)?;
            let file = self
                .opened
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(WholePgCarrierFault::IoFailure)?;
            session
                .settle_new_child_before(child, self.parent(index), file, deadline)
                .map_err(|e| retain_stage_control(e, error))?;
            session
                .settle_storage_before(growth, self.parent(index), deadline)
                .map_err(|e| retain_stage_control(e, error))?;
            stage_effect(session, deadline, error)?;
            self.synced = Some(file.sync_all());
            stage_effect(session, deadline, error)?;
            if !matches!(self.synced, Some(Ok(()))) {
                return Err(WholePgCarrierFault::IoFailure);
            }
            self.metadata = Some(file.metadata());
            stage_effect(session, deadline, error)?;
            let metadata = self
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(WholePgCarrierFault::IoFailure)?;
            self.directories[index].identity = Some((
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.mode(),
            ));
            self.directories[index].file = Some(
                self.opened
                    .take()
                    .expect("raw directory open retained")
                    .expect("raw directory open checked"),
            );
            stage_effect(session, deadline, error)?;
            self.synced = Some(self.parent(index).sync_all());
            stage_effect(session, deadline, error)?;
            if !matches!(self.synced, Some(Ok(()))) {
                return Err(WholePgCarrierFault::IoFailure);
            }
            session
                .settle_capacity(count, 1)
                .map_err(|e| retain_stage_control(e, error))?;
            Ok(index)
        }
    }

    /// A complete, read-back-verified stable material tree in the one original
    /// candidate generation. The original plan, descriptors and secret custody
    /// remain private and non-Clone; this is not Current or a PG/slot grant.
    pub struct VerifiedWholePgRestoreStaging {
        carrier: AuthenticatedWholePgRestoreCarrier,
    }
    impl VerifiedWholePgRestoreStaging {
        fn work(&self) -> &RestoreStagingWork {
            self.carrier
                .input
                .staging
                .as_ref()
                .expect("verified stable owner")
        }
        pub fn candidate_plan(&self) -> &OwnedRestoreCandidatePlan {
            self.work().plan.as_ref().expect("original plan retained")
        }
        pub fn generation_root(&self) -> &File {
            self.work().directory_file(0)
        }
        pub fn materials_root(&self) -> &File {
            self.work().directory_file(1)
        }
        pub fn directory(&self) -> &File {
            self.work().directory_file(2)
        }
        pub fn manifest(&self) -> &FrozenWholePgManifest {
            self.carrier
                .input
                .manifest
                .as_ref()
                .expect("authenticated manifest retained")
        }
        /// Read-only original staging file by authenticated manifest ordinal.
        /// Secret materials stay in private memory and have no plaintext file.
        pub fn material_file(&self, ordinal: usize) -> Option<&File> {
            self.work().materials.get(ordinal)?.file.as_ref()
        }
        pub fn authenticated_secrets(&self) -> &AuthenticatedRestoreSecrets {
            &self.carrier.secrets
        }
    }

    pub async fn verify_whole_pg_restore_input(
        input: FrozenWholePgRestoreInput,
        intent: ReviewedWholePgRestoreIntent,
        session: &mut RestoreControlSession,
    ) -> Result<VerifiedWholePgRestoreStaging, RetainedRestoreInputFailure> {
        if input.operation != intent.operation || input.operation.as_str() != session.operation_id() {
            return Err(RetainedRestoreInputFailure { fault: WholePgCarrierFault::IntentMismatch, input, intent, control_error: None });
        }
        let mut carrier = authenticate_whole_pg_restore_carrier_before(input, intent, session)?;
        let mut control_error = None;
        match stage_authenticated_carrier(&mut carrier, session, &mut control_error) {
            Ok(()) => Ok(VerifiedWholePgRestoreStaging { carrier }),
            Err(fault) => {
                // Keep the authenticated secrets with the same original input
                // on every failure, including post-effect late observations.
                carrier.input.authenticated = Some(carrier.secrets);
                Err(RetainedRestoreInputFailure {
                    fault,
                    input: carrier.input,
                    intent: carrier.intent,
                    control_error,
                })
            }
        }
    }
    fn retain_stage_control(
        error: RecoveryControlError,
        retained: &mut Option<RecoveryControlError>,
    ) -> WholePgCarrierFault {
        let fault = restore_input_control_fault(error.fault());
        if retained.is_none() {
            *retained = Some(error);
        }
        fault
    }
    fn stage_effect(
        session: &mut RestoreControlSession,
        deadline: Instant,
        error: &mut Option<RecoveryControlError>,
    ) -> Result<(), WholePgCarrierFault> {
        session
            .input_stages()
            .effect_before(deadline)
            .map(|_| ())
            .map_err(|e| retain_stage_control(e, error))
    }

    fn stage_authenticated_carrier(
        carrier: &mut AuthenticatedWholePgRestoreCarrier,
        session: &mut RestoreControlSession,
        error: &mut Option<RecoveryControlError>,
    ) -> Result<(), WholePgCarrierFault> {
        let closing = session
            .input_stages()
            .convergence_deadline()
            .map_err(|e| retain_stage_control(e, error))?;
        let deadline = session
            .input_stages()
            .effect_before(closing)
            .map_err(|e| retain_stage_control(e, error))?;
        carrier.input.staging = Some(RestoreStagingWork::new());
        let input = &mut carrier.input;
        let manifest = input
            .manifest
            .as_ref()
            .expect("complete authentication precedes staging");
        let file_count = manifest.materials().len();
        let mut prefixes = 3usize;
        let mut string_bytes = 0u64;
        let mut plain_bytes = 0u64;
        let mut longest = 0u64;
        let mut deepest = 0u64;
        let mut spool = 0u64;
        for material in manifest.materials().iter().filter(|m| !m.kind.is_secret()) {
            plain_bytes = plain_bytes
                .checked_add(material.plain_len)
                .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            longest = longest.max(material.relative_path.len() as u64);
            deepest = deepest.max(material.relative_path.split('/').count() as u64);
            if material.kind == WholePgMaterialKind::Artifact {
                spool = spool
                    .checked_add(material.plain_len)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            }
            for (offset, _) in material.relative_path.match_indices('/') {
                prefixes = prefixes
                    .checked_add(1)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?;
                string_bytes = string_bytes
                    .checked_add(offset as u64)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            }
        }
        let directory_capacity = prefixes.min(
            usize::try_from(input.bounds.max_directories)
                .map_err(|_| WholePgCarrierFault::BoundsOverflow)?,
        );
        if directory_capacity < 3 {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        // Four bounded metadata views plus serde's bounded escape/error scratch;
        // all ordinary material data otherwise reuses the original frame buffer.
        let metadata_bytes = string_bytes
            .checked_add((directory_capacity * std::mem::size_of::<StagingDirectory>()) as u64)
            .and_then(|n| {
                n.checked_add((file_count * std::mem::size_of::<StagingMaterial>()) as u64)
            })
            .and_then(|n| n.checked_add(4 * 8192 + 4096))
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
        let metadata = session
            .admit_capacity(Capacity::MetadataBytes, metadata_bytes)
            .map_err(|e| retain_stage_control(e, error))?;
        let count = session
            .admit_capacity(Capacity::MaterialFiles, (file_count - 2) as u64)
            .map_err(|e| retain_stage_control(e, error))?;
        let plain = session
            .admit_capacity(Capacity::MaterialPlainBytes, plain_bytes)
            .map_err(|e| retain_stage_control(e, error))?;
        let spool_reservation = session
            .admit_capacity(Capacity::SpoolBytes, spool)
            .map_err(|e| retain_stage_control(e, error))?;
        let path = session
            .admit_capacity(Capacity::PathBytes, longest)
            .map_err(|e| retain_stage_control(e, error))?;
        let depth = session
            .admit_capacity(Capacity::PathDepth, deepest)
            .map_err(|e| retain_stage_control(e, error))?;
        let work = input.staging.as_mut().expect("staging owner retained");
        work.directories
            .try_reserve_exact(directory_capacity)
            .map_err(|_| WholePgCarrierFault::CapacityExceeded)?;
        work.materials
            .try_reserve_exact(file_count)
            .map_err(|_| WholePgCarrierFault::CapacityExceeded)?;
        if work.directories.capacity() > directory_capacity
            || work.materials.capacity() > file_count
        {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        work.import_intent = Some(session.input_stages().begin_stage_before(crate::recovery_control::RestoreStage::Import, "stable_staging", deadline).map_err(|e| retain_stage_control(e, error))?);
        work.plan = Some(
            session
                .take_candidate_plan()
                .map_err(|e| retain_stage_control(e, error))?,
        );
        work.create_directory(None, None, session, deadline, error)?;
        work.create_directory(Some(0), None, session, deadline, error)?;
        work.create_directory(Some(1), Some(""), session, deadline, error)?;
        for material in manifest.materials() {
            if material.kind.is_secret() {
                work.materials.push(StagingMaterial {
                    file: None,
                    parent: 2,
                    stamp: None,
                });
                continue;
            }
            let mut parent = 2usize;
            for (offset, _) in material.relative_path.match_indices('/') {
                let prefix = &material.relative_path[..offset];
                parent = match work
                    .directories
                    .iter()
                    .position(|d| d.relative.as_deref() == Some(prefix))
                {
                    Some(existing) => existing,
                    None => {
                        work.create_directory(Some(parent), Some(prefix), session, deadline, error)?
                    }
                };
            }
            let name = material
                .relative_path
                .rsplit('/')
                .next()
                .expect("frozen material path");
            stage_effect(session, deadline, error)?;
            work.space = Some(rustix::fs::fstatvfs(work.directory_file(parent)));
            stage_effect(session, deadline, error)?;
            let grain = work
                .space
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .map(|s| s.f_frsize.max(s.f_bsize))
                .filter(|v| *v > 0)
                .ok_or(WholePgCarrierFault::IoFailure)?;
            let growth = session
                .admit_storage_before(
                    work.directory_file(parent),
                    grain,
                    RestoreStorageKind::Working,
                    deadline,
                )
                .map_err(|e| retain_stage_control(e, error))?;
            let new = session
                .admit_new_child_before(
                    work.directory_file(parent),
                    OsStr::new(name),
                    grain,
                    RestoreNewChildKind::File,
                    deadline,
                )
                .map_err(|e| retain_stage_control(e, error))?;
            work.opened = Some(
                rustix::fs::openat(
                    work.directory_file(parent),
                    name,
                    OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::RDWR
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o600),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            stage_effect(session, deadline, error)?;
            let file = work
                .opened
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(WholePgCarrierFault::IoFailure)?;
            session
                .settle_new_child_before(new, work.directory_file(parent), file, deadline)
                .map_err(|e| retain_stage_control(e, error))?;
            session
                .settle_storage_before(growth, work.directory_file(parent), deadline)
                .map_err(|e| retain_stage_control(e, error))?;
            work.materials.push(StagingMaterial {
                file: Some(
                    work.opened
                        .take()
                        .expect("raw file open retained")
                        .expect("raw file open checked"),
                ),
                parent,
                stamp: None,
            });
        }
        write_authenticated_staging(input, session, deadline, error)?;
        readback_staging(input, session, deadline, error)?;
        verify_staged_host_semantics(input, session, deadline, error)?;
        let work = input.staging.as_ref().expect("staging owner retained");
        let actual_metadata = (work.directories.capacity()
            * std::mem::size_of::<StagingDirectory>()
            + work.materials.capacity() * std::mem::size_of::<StagingMaterial>())
            as u64
            + work
                .directories
                .iter()
                .filter_map(|d| d.relative.as_ref())
                .map(|p| p.capacity() as u64)
                .sum::<u64>();
        session
            .settle_capacity(metadata, actual_metadata)
            .map_err(|e| retain_stage_control(e, error))?;
        session
            .settle_capacity(count, (file_count - 2) as u64)
            .map_err(|e| retain_stage_control(e, error))?;
        session
            .settle_capacity(plain, plain_bytes)
            .map_err(|e| retain_stage_control(e, error))?;
        session
            .settle_capacity(spool_reservation, spool)
            .map_err(|e| retain_stage_control(e, error))?;
        session
            .settle_capacity(path, longest)
            .map_err(|e| retain_stage_control(e, error))?;
        session
            .settle_capacity(depth, deepest)
            .map_err(|e| retain_stage_control(e, error))?;
        stage_effect(session, deadline, error)?;
        let receipt_memory = session.admit_capacity(Capacity::MetadataBytes, 128 + std::mem::size_of::<crate::recovery_control::RestoreDisposition>() as u64).map_err(|e| retain_stage_control(e, error))?;
        let host = input.manifest.as_ref().expect("original manifest retained").materials().iter().position(|material| material.material_id == "host-inventory").expect("fixed host material checked");
        let digest = &input.manifest.as_ref().expect("original manifest retained").materials()[host].plain_sha256;
        let mut expected_digest = String::new();
        expected_digest.try_reserve_exact(64).map_err(|_| WholePgCarrierFault::CapacityExceeded)?;
        if expected_digest.capacity() > 64 { return Err(WholePgCarrierFault::CapacityExceeded); }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest { expected_digest.push(HEX[usize::from(byte >> 4)] as char); expected_digest.push(HEX[usize::from(byte & 15)] as char); }
        let work = input.staging.as_mut().expect("staging owner retained");
        let stamp = work.materials[host].stamp.expect("actual host file fully read back");
        let intent = work.import_intent.take().expect("original Import intent retained");
        let disposition = crate::recovery_control::RestoreDisposition::FilePublishMatched {
            intent_ref: intent.reference().clone(),
            held_file_identity: crate::recovery_control::RecoveryFileIdentity { device: stamp.device, inode: stamp.inode, uid: stamp.uid },
            expected_digest,
        };
        // This records only the actual host-inventory file publication. The
        // private complete-tree proof above cannot be replaced by this one file.
        session.input_stages().observe_stage_before(intent, disposition, closing).map_err(|e| retain_stage_control(e, error))?;
        session.settle_capacity(receipt_memory, 0).map_err(|e| retain_stage_control(e, error))?;
        Ok(())
    }

    fn write_authenticated_staging(
        input: &mut FrozenWholePgRestoreInput,
        session: &mut RestoreControlSession,
        deadline: Instant,
        error: &mut Option<RecoveryControlError>,
    ) -> Result<(), WholePgCarrierFault> {
        let key_memory = session
            .admit_capacity(Capacity::SecretMemoryBytes, 64)
            .map_err(|e| retain_stage_control(e, error))?;
        let key_structures = session
            .admit_capacity(
                Capacity::SecretStructureBytes,
                (2 * std::mem::size_of::<SecretBytes>()) as u64,
            )
            .map_err(|e| retain_stage_control(e, error))?;
        {
            let mut check = || stage_effect(session, deadline, error);
            input.check_identity(false, &mut check)?;
            input.check_identity(true, &mut check)?;
        }
        stage_effect(session, deadline, error)?;
        input.raw_read = Some(
            input
                .key_medium
                .read_exact_at(input.key_bytes.as_mut_slice(), 0),
        );
        stage_effect(session, deadline, error)?;
        input
            .raw_read
            .as_ref()
            .expect("key read retained")
            .as_ref()
            .map_err(read_fault)?;
        let key = SecretBytes::new(input.key_bytes[72..104].to_vec());
        input.key_bytes.zeroize();
        let mut header = [0u8; 80];
        input.read_at(0, &mut header, &mut || {
            stage_effect(session, deadline, error)
        })?;
        let mut codec = WholePgOpenCodec::new(
            &key,
            input.manifest.as_ref().expect("original manifest retained"),
            &header,
        )?;
        let mut at = 80u64;
        let mut material_hash = Sha256::new();
        let mut storage = None;
        let mut terminal = false;
        while let Some(spec) = codec.next_frame() {
            let mut frame_header = [0u8; 21];
            let mut tag = [0u8; 16];
            {
                let mut check = || stage_effect(session, deadline, error);
                input.read_at(at, &mut frame_header, &mut check)?;
                at = at
                    .checked_add(21)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?;
                input.read_frame(at, spec.plain_len() as usize, &mut check)?;
                at = at
                    .checked_add(u64::from(spec.plain_len()))
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?;
                input.read_at(at, &mut tag, &mut check)?;
                at = at
                    .checked_add(16)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?;
            }
            codec.open_next_in_place(&frame_header, &tag, &mut input.buffer)?;
            stage_effect(session, deadline, error)?;
            if spec.kind() == 1 {
                let ordinal = spec.material_ordinal() as usize;
                let material = &input
                    .manifest
                    .as_ref()
                    .expect("original manifest retained")
                    .materials()[ordinal];
                let work = input.staging.as_mut().expect("staging owner retained");
                if !material.kind.is_secret() {
                    let file = work.materials[ordinal]
                        .file
                        .as_ref()
                        .expect("original staged writer retained");
                    if spec.offset() == 0 {
                        work.space = Some(rustix::fs::fstatvfs(file));
                        stage_effect(session, deadline, error)?;
                        let grain = work
                            .space
                            .as_ref()
                            .and_then(|r| r.as_ref().ok())
                            .map(|s| s.f_frsize.max(s.f_bsize))
                            .filter(|n| *n > 0)
                            .ok_or(WholePgCarrierFault::IoFailure)?;
                        let allocation = material
                            .plain_len
                            .checked_add(grain - 1)
                            .and_then(|n| n.checked_div(grain))
                            .and_then(|n| n.checked_mul(grain))
                            // The real F07 WAL copy allocated one 64KiB extent
                            // beyond its aligned logical length. Prepay one
                            // actual filesystem grain; the original global
                            // cap and actual-overflow rejection still apply.
                            .and_then(|n| n.checked_add(grain))
                            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
                        storage = Some(
                            session
                                .admit_storage_before(
                                    file,
                                    allocation,
                                    RestoreStorageKind::Working,
                                    deadline,
                                )
                                .map_err(|e| retain_stage_control(e, error))?,
                        );
                    }
                    stage_effect(session, deadline, error)?;
                    work.written = Some(file.write_all_at(input.buffer.as_slice(), spec.offset()));
                    stage_effect(session, deadline, error)?;
                    work.written
                        .as_ref()
                        .expect("raw staged write retained")
                        .as_ref()
                        .map_err(|_| WholePgCarrierFault::IoFailure)?;
                }
                material_hash.update(input.buffer.as_slice());
                if spec
                    .offset()
                    .checked_add(input.buffer.len() as u64)
                    .ok_or(WholePgCarrierFault::BoundsOverflow)?
                    == material.plain_len
                {
                    let mut actual: [u8; 32] = std::mem::replace(&mut material_hash, Sha256::new())
                        .finalize()
                        .into();
                    let equal = actual == material.plain_sha256;
                    actual.zeroize();
                    if !equal {
                        return Err(WholePgCarrierFault::ReadbackFailed);
                    }
                    if !material.kind.is_secret() {
                        let file = work.materials[ordinal]
                            .file
                            .as_ref()
                            .expect("original staged writer retained");
                        stage_effect(session, deadline, error)?;
                        work.synced = Some(file.sync_all());
                        stage_effect(session, deadline, error)?;
                        if !matches!(work.synced, Some(Ok(()))) {
                            return Err(WholePgCarrierFault::IoFailure);
                        }
                        session
                            .settle_storage_before(
                                storage.take().expect("original write admitted"),
                                file,
                                deadline,
                            )
                            .map_err(|e| retain_stage_control(e, error))?;
                    }
                }
            } else if spec.kind() == 2 {
                terminal = true;
            }
            input.buffer.as_mut_slice().zeroize();
            input.buffer.clear();
        }
        if !terminal || at != input.carrier_identity.length {
            return Err(WholePgCarrierFault::TerminalMissing);
        }
        let mut eof = [0u8; 1];
        stage_effect(session, deadline, error)?;
        input.raw_eof = Some(input.carrier.read_at(&mut eof, at));
        stage_effect(session, deadline, error)?;
        if !matches!(input.raw_eof, Some(Ok(0))) {
            return Err(WholePgCarrierFault::ExtraTail);
        }
        {
            let mut check = || stage_effect(session, deadline, error);
            input.check_identity(false, &mut check)?;
            input.check_identity(true, &mut check)?;
        }
        drop(codec);
        drop(key);
        session
            .settle_capacity(key_memory, 0)
            .map_err(|e| retain_stage_control(e, error))?;
        session
            .settle_capacity(key_structures, 0)
            .map_err(|e| retain_stage_control(e, error))?;
        Ok(())
    }

    fn readback_staging(
        input: &mut FrozenWholePgRestoreInput,
        session: &mut RestoreControlSession,
        deadline: Instant,
        error: &mut Option<RecoveryControlError>,
    ) -> Result<(), WholePgCarrierFault> {
        let manifest = input.manifest.as_ref().expect("original manifest retained");
        let work = input.staging.as_mut().expect("staging owner retained");
        for (ordinal, material) in manifest.materials().iter().enumerate() {
            if material.kind.is_secret() {
                continue;
            }
            let parent = work.materials[ordinal].parent;
            let name = material
                .relative_path
                .rsplit('/')
                .next()
                .expect("original material basename");
            let writer = work.materials[ordinal]
                .file
                .as_ref()
                .expect("original staged writer retained");
            stage_effect(session, deadline, error)?;
            work.synced = Some(writer.sync_all());
            stage_effect(session, deadline, error)?;
            if !matches!(work.synced, Some(Ok(()))) {
                return Err(WholePgCarrierFault::IoFailure);
            }
            work.metadata = Some(writer.metadata());
            stage_effect(session, deadline, error)?;
            let before = RestoreInputFileIdentity::from_metadata(
                work.metadata
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or(WholePgCarrierFault::IoFailure)?,
            )?;
            if before.length != material.plain_len {
                return Err(WholePgCarrierFault::ReadbackFailed);
            }
            let extra_fd = session
                .admit_capacity(Capacity::OpenFiles, 1)
                .map_err(|e| retain_stage_control(e, error))?;
            work.opened = Some(
                rustix::fs::openat(
                    work.directory_file(parent),
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            stage_effect(session, deadline, error)?;
            let reader = work
                .opened
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(WholePgCarrierFault::IoFailure)?;
            work.metadata = Some(reader.metadata());
            stage_effect(session, deadline, error)?;
            if RestoreInputFileIdentity::from_metadata(
                work.metadata
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or(WholePgCarrierFault::IoFailure)?,
            )? != before
            {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            let mut at = 0u64;
            let mut hash = Sha256::new();
            while at < material.plain_len {
                let length =
                    (material.plain_len - at).min(input.bounds.max_chunk_plain_bytes) as usize;
                input.buffer.resize(length, 0);
                stage_effect(session, deadline, error)?;
                input.raw_read = Some(reader.read_exact_at(input.buffer.as_mut_slice(), at));
                stage_effect(session, deadline, error)?;
                input
                    .raw_read
                    .as_ref()
                    .expect("raw staging read retained")
                    .as_ref()
                    .map_err(read_fault)?;
                hash.update(input.buffer.as_slice());
                at += length as u64;
                input.buffer.as_mut_slice().zeroize();
                input.buffer.clear();
            }
            let mut digest: [u8; 32] = hash.finalize().into();
            let equal = digest == material.plain_sha256;
            digest.zeroize();
            if !equal {
                return Err(WholePgCarrierFault::ReadbackFailed);
            }
            work.metadata = Some(reader.metadata());
            stage_effect(session, deadline, error)?;
            if RestoreInputFileIdentity::from_metadata(
                work.metadata
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or(WholePgCarrierFault::IoFailure)?,
            )? != before
            {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            work.materials[ordinal].stamp = Some(before);
            let reader = work
                .opened
                .take()
                .expect("raw read-only file retained")
                .expect("raw read-only file checked");
            let writer = work.materials[ordinal].file.replace(reader);
            drop(writer);
            session
                .settle_capacity(extra_fd, 0)
                .map_err(|e| retain_stage_control(e, error))?;
        }
        verify_staging_directory_membership(input, session, deadline, error)?;
        session
            .check_capacity_before(deadline)
            .map_err(|e| retain_stage_control(e, error))
    }
    fn verify_staging_directory_membership(
        input: &mut FrozenWholePgRestoreInput,
        session: &mut RestoreControlSession,
        deadline: Instant,
        error: &mut Option<RecoveryControlError>,
    ) -> Result<(), WholePgCarrierFault> {
        let manifest = input.manifest.as_ref().expect("original manifest retained");
        let work = input.staging.as_mut().expect("staging owner retained");
        for index in (0..work.directories.len()).rev() {
            stage_effect(session, deadline, error)?;
            work.synced = Some(work.directory_file(index).sync_all());
            stage_effect(session, deadline, error)?;
            if !matches!(work.synced, Some(Ok(()))) {
                return Err(WholePgCarrierFault::IoFailure);
            }
            work.metadata = Some(work.directory_file(index).metadata());
            stage_effect(session, deadline, error)?;
            let metadata = work
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(WholePgCarrierFault::IoFailure)?;
            if !metadata.is_dir()
                || Some((
                    metadata.dev(),
                    metadata.ino(),
                    metadata.uid(),
                    metadata.mode(),
                )) != work.directories[index].identity
            {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            work.named = Some(rustix::fs::statat(
                work.parent(index),
                work.component(index),
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            stage_effect(session, deadline, error)?;
            let named = work
                .named
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(WholePgCarrierFault::IoFailure)?;
            if Some((
                named.st_dev as u64,
                named.st_ino as u64,
                named.st_uid,
                u32::from(named.st_mode),
            )) != work.directories[index].identity
            {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            let iterator_fd = session
                .admit_capacity(Capacity::OpenFiles, 1)
                .map_err(|e| retain_stage_control(e, error))?;
            work.directory = Some(rustix::fs::Dir::read_from(work.directory_file(index)));
            stage_effect(session, deadline, error)?;
            if !matches!(work.directory, Some(Ok(_))) {
                return Err(WholePgCarrierFault::IoFailure);
            }
            let mut seen = 0usize;
            loop {
                stage_effect(session, deadline, error)?;
                work.entry = work
                    .directory
                    .as_mut()
                    .and_then(|r| r.as_mut().ok())
                    .expect("original directory iterator retained")
                    .next();
                stage_effect(session, deadline, error)?;
                let Some(entry) = work.entry.as_ref() else {
                    break;
                };
                let entry = entry.as_ref().map_err(|_| WholePgCarrierFault::IoFailure)?;
                let name = entry
                    .file_name()
                    .to_str()
                    .map_err(|_| WholePgCarrierFault::PathUnsafe)?;
                if name == "." || name == ".." {
                    continue;
                }
                let directory = work
                    .directories
                    .iter()
                    .enumerate()
                    .find(|(child, dir)| {
                        dir.parent == Some(index) && work.component(*child) == OsStr::new(name)
                    })
                    .map(|(child, _)| child);
                let material = work
                    .materials
                    .iter()
                    .enumerate()
                    .find(|(ordinal, file)| {
                        file.file.is_some()
                            && file.parent == index
                            && manifest.materials()[*ordinal]
                                .relative_path
                                .rsplit('/')
                                .next()
                                == Some(name)
                    })
                    .map(|(ordinal, _)| ordinal);
                let expected = match (directory, material) {
                    (Some(child), None) => work.directories[child]
                        .identity
                        .expect("original directory identity"),
                    (None, Some(ordinal)) => {
                        let stamp = work.materials[ordinal]
                            .stamp
                            .expect("staged file read back");
                        (stamp.device, stamp.inode, stamp.uid, stamp.mode)
                    }
                    _ => return Err(WholePgCarrierFault::ExtraMaterial),
                };
                work.named = Some(rustix::fs::statat(
                    work.directory_file(index),
                    name,
                    AtFlags::SYMLINK_NOFOLLOW,
                ));
                stage_effect(session, deadline, error)?;
                let named = work
                    .named
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or(WholePgCarrierFault::IoFailure)?;
                if (
                    named.st_dev as u64,
                    named.st_ino as u64,
                    named.st_uid,
                    u32::from(named.st_mode),
                ) != expected
                    || (material.is_some() && named.st_nlink != 1)
                {
                    return Err(WholePgCarrierFault::SourceChanged);
                }
                seen += 1;
            }
            let expected_count = work
                .directories
                .iter()
                .filter(|dir| dir.parent == Some(index))
                .count()
                + work
                    .materials
                    .iter()
                    .filter(|file| file.file.is_some() && file.parent == index)
                    .count();
            if seen != expected_count {
                return Err(WholePgCarrierFault::MaterialMissing);
            }
            work.entry = None;
            work.directory = None;
            session
                .settle_capacity(iterator_fd, 0)
                .map_err(|e| retain_stage_control(e, error))?;
        }
        Ok(())
    }

    #[derive(Clone, Copy, PartialEq, Eq, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedIdentity {
        device: u64,
        inode: u64,
        uid: u32,
        mode: u32,
        links: u64,
        bytes: u64,
        mtime: i64,
        mtime_ns: i64,
    }
    #[derive(Clone, Copy, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedHostEntry<'a> {
        #[serde(borrow)]
        name: &'a str,
        #[serde(borrow)]
        kind: &'a str,
        device: u64,
        inode: u64,
        uid: u32,
        mode: u32,
        bytes: u64,
    }
    struct CapturedHostEntries<'a> {
        entries: [Option<CapturedHostEntry<'a>>; 11],
        length: usize,
    }
    impl<'de: 'a, 'a> serde::Deserialize<'de> for CapturedHostEntries<'a> {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Entries<'a>(std::marker::PhantomData<&'a ()>);
            impl<'de: 'a, 'a> serde::de::Visitor<'de> for Entries<'a> {
                type Value = CapturedHostEntries<'a>;
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("the eleven fixed original host roles")
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut sequence: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut result = CapturedHostEntries {
                        entries: [None; 11],
                        length: 0,
                    };
                    while let Some(entry) = sequence.next_element::<CapturedHostEntry<'a>>()? {
                        if result.length == result.entries.len() {
                            return Err(serde::de::Error::custom("extra host role"));
                        }
                        result.entries[result.length] = Some(entry);
                        result.length += 1;
                    }
                    Ok(result)
                }
            }
            deserializer.deserialize_seq(Entries(std::marker::PhantomData))
        }
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedHost<'a> {
        #[serde(borrow)]
        instance: &'a str,
        device: u64,
        inode: u64,
        uid: u32,
        #[serde(borrow)]
        entries: CapturedHostEntries<'a>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedInstallation<'a> {
        #[serde(borrow)]
        schema: &'a str,
        version: u8,
        installation_root: CapturedIdentity,
        #[serde(borrow)]
        deployment_id: &'a str,
        #[serde(borrow)]
        tenant_id: &'a str,
        #[serde(borrow)]
        dataset_id: &'a str,
        #[serde(borrow)]
        instance_id: &'a str,
        #[serde(borrow)]
        system_identifier: &'a str,
        database_oid: u32,
        #[serde(borrow)]
        store_id: &'a str,
        #[serde(borrow)]
        artifact_root_device: &'a str,
        #[serde(borrow)]
        artifact_root_inode: &'a str,
        #[serde(borrow)]
        artifact_root_uid: &'a str,
        #[serde(borrow, deserialize_with = "required_metadata_option")]
        key_id: Option<&'a str>,
    }
    fn required_metadata_option<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
        deserializer: D,
    ) -> Result<Option<T>, D::Error> {
        serde::Deserialize::deserialize(deserializer)
    }
    #[derive(Clone, Copy)]
    enum CapturedPreferences {
        AbsentOriginalParentEnoent,
        PresentOriginalSnapshot { byte_length: u64, sha256: [u8; 32] },
    }
    impl<'de> serde::Deserialize<'de> for CapturedPreferences {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Preference;
            impl<'de> serde::de::Visitor<'de> for Preference {
                type Value = CapturedPreferences;
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("the closed original preference fact") }
                fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                    let mut presence = None;
                    let mut byte_length = None;
                    let mut sha256 = None;
                    while let Some(key) = map.next_key::<&str>()? {
                        match key {
                            "presence" if presence.is_none() => presence = Some(map.next_value::<&str>()?),
                            "byte_length" if byte_length.is_none() => byte_length = Some(map.next_value::<u64>()?),
                            "sha256" if sha256.is_none() => sha256 = Some(map.next_value::<[u8; 32]>()?),
                            _ => return Err(serde::de::Error::custom("duplicate or unknown preference field")),
                        }
                    }
                    match (presence, byte_length, sha256) {
                        (Some("absent_original_parent_enoent"), None, None) => Ok(CapturedPreferences::AbsentOriginalParentEnoent),
                        (Some("present_original_snapshot"), Some(byte_length), Some(sha256)) => Ok(CapturedPreferences::PresentOriginalSnapshot { byte_length, sha256 }),
                        _ => Err(serde::de::Error::custom("incomplete or cross-mode preference fact")),
                    }
                }
            }
            // No internally-tagged serde Content map/Vec is allocated.
            deserializer.deserialize_map(Preference)
        }
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedRootHeader<'a> {
        #[serde(borrow)]
        schema: &'a str,
        version: u8,
        #[serde(borrow)]
        material_id: &'a str,
        #[serde(borrow)]
        construction: &'a str,
        #[serde(borrow)]
        physical_root_disposition: &'a str,
        #[serde(borrow)]
        instance_id: &'a str,
        #[serde(borrow)]
        dataset_id: &'a str,
        #[serde(borrow)]
        deployment_id: &'a str,
        #[serde(borrow)]
        tenant_id: &'a str,
        #[serde(borrow)]
        system_identifier: &'a str,
        database_oid: u32,
        installation_root: CapturedIdentity,
        #[serde(borrow)]
        host_inventory_material_id: &'a str,
        #[serde(borrow)]
        logical_projection: &'a str,
        #[serde(deserialize_with = "required_metadata_option")]
        app_local_state: Option<CapturedPreferences>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct CapturedStoreMarker<'a> {
        schema: u16,
        #[serde(borrow)]
        deployment_id: &'a str,
        #[serde(borrow)]
        tenant_id: &'a str,
        #[serde(borrow)]
        dataset_id: &'a str,
        #[serde(borrow)]
        store_id: &'a str,
    }

    // These closed original metadata records have at most eleven fixed names
    // and the manifest's <=128-byte identities; 8KiB exceeds their structural
    // encoding bound. Logical profile/workspace rows remain streamed files.
    fn staged_metadata_prefix(
        input: &mut FrozenWholePgRestoreInput,
        id: &str,
        header: bool,
        session: &mut RestoreControlSession,
        deadline: Instant,
        error: &mut Option<RecoveryControlError>,
    ) -> Result<usize, WholePgCarrierFault> {
        let manifest = input.manifest.as_ref().expect("original manifest retained");
        let ordinal = manifest
            .materials()
            .iter()
            .position(|m| m.material_id == id)
            .ok_or(WholePgCarrierFault::MaterialMissing)?;
        let length = manifest.materials()[ordinal].plain_len;
        if (!header && length > 8192)
            || length == 0
            || input.buffer.capacity() < 8192.min(length as usize)
        {
            return Err(WholePgCarrierFault::ManifestInvalid);
        }
        let read = length.min(8192) as usize;
        input.buffer.as_mut_slice().zeroize();
        input.buffer.clear();
        input.buffer.resize(read, 0);
        let file = input
            .staging
            .as_ref()
            .expect("staging owner retained")
            .materials[ordinal]
            .file
            .as_ref()
            .expect("verified read-only metadata");
        stage_effect(session, deadline, error)?;
        input.raw_read = Some(file.read_exact_at(input.buffer.as_mut_slice(), 0));
        stage_effect(session, deadline, error)?;
        input
            .raw_read
            .as_ref()
            .expect("raw metadata read retained")
            .as_ref()
            .map_err(read_fault)?;
        if header {
            input
                .buffer
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or(WholePgCarrierFault::ManifestInvalid)
        } else {
            Ok(read)
        }
    }
    fn original_host_role(name: &str, instance: &str) -> Option<(usize, &'static str, bool)> {
        let owned = |prefix: &str, suffix: &str| {
            name.strip_prefix(prefix)
                .and_then(|rest| rest.strip_prefix(instance))
                == Some(suffix)
        };
        Some(match name {
            "desktop-instance-v1" => (0, "installation", false),
            "artifacts" => (1, "artifact-store", true),
            ".wrokbot-capture-control-v1" => (6, "original-capture-control", true),
            "ui-preferences-v1" => (7, "preference-projection", false),
            _ if owned("postgresql-17-", "") => (2, "original-postgres", true),
            _ if owned(".postgresql-17-", ".scram-init-v1.json") => (3, "scram-journal", false),
            _ if owned(".desktop-vault-", ".master-init-v1.json") => (4, "master-journal", false),
            _ if owned(".postgresql-17-", ".start-lock-v1") => (5, "original-start-lock", false),
            _ if owned(".postgresql-17-", ".owner-guard-v1") => (8, "original-kernel-lock", false),
            _ if owned(".postgresql-17-", ".startup-v1.json") => (9, "startup-journal", false),
            _ if owned(".postgresql-17-", ".helper-v1.json") => (10, "helper-journal", false),
            _ => return None,
        })
    }
    fn verify_staged_host_semantics(
        input: &mut FrozenWholePgRestoreInput,
        session: &mut RestoreControlSession,
        deadline: Instant,
        error: &mut Option<RecoveryControlError>,
    ) -> Result<(), WholePgCarrierFault> {
        let length =
            staged_metadata_prefix(input, "host-inventory", false, session, deadline, error)?;
        let (root, artifact, preference_bytes) = {
            let host: CapturedHost<'_> = match serde_json::from_slice(&input.buffer[..length]) {
                Ok(value) => value,
                Err(e) => {
                    input.staging.as_mut().expect("staging owner").json_error = Some(e);
                    return Err(WholePgCarrierFault::ManifestInvalid);
                }
            };
            let source = &input
                .manifest
                .as_ref()
                .expect("original manifest retained")
                .claim()
                .source;
            if host.instance != source.instance_id || host.device == 0 || host.inode == 0 {
                return Err(WholePgCarrierFault::IntentMismatch);
            }
            let mut present = 0u16;
            let mut previous = None;
            let mut artifact = None;
            let mut preference = None;
            for entry in host.entries.entries[..host.entries.length].iter().flatten() {
                let (role, kind, directory) = original_host_role(entry.name, host.instance)
                    .ok_or(WholePgCarrierFault::ExtraMaterial)?;
                if previous.is_some_and(|name| name >= entry.name)
                    || present & (1 << role) != 0
                    || entry.kind != kind
                    || entry.uid != host.uid
                    || entry.mode & 0o077 != 0
                    || entry.mode & 0o170000 != if directory { 0o040000 } else { 0o100000 }
                    || (role >= 8 && entry.mode & 0o777 != 0o600)
                {
                    return Err(WholePgCarrierFault::PathUnsafe);
                }
                present |= 1 << role;
                previous = Some(entry.name);
                if role == 1 {
                    artifact = Some((entry.device, entry.inode, entry.uid));
                }
                if role == 7 {
                    preference = Some(entry.bytes);
                }
            }
            if present & 0x7f != 0x7f {
                return Err(WholePgCarrierFault::MaterialMissing);
            }
            (
                (host.device, host.inode, host.uid),
                artifact.expect("required artifact role"),
                preference,
            )
        };
        let length =
            staged_metadata_prefix(input, "installation", false, session, deadline, error)?;
        let (installation_root, store_id) = {
            let installation: CapturedInstallation<'_> =
                match serde_json::from_slice(&input.buffer[..length]) {
                    Ok(value) => value,
                    Err(e) => {
                        input.staging.as_mut().expect("staging owner").json_error = Some(e);
                        return Err(WholePgCarrierFault::ManifestInvalid);
                    }
                };
            let source = &input
                .manifest
                .as_ref()
                .expect("original manifest retained")
                .claim()
                .source;
            let actual_artifact = (
                installation
                    .artifact_root_device
                    .parse::<u64>()
                    .map_err(|_| WholePgCarrierFault::ManifestInvalid)?,
                installation
                    .artifact_root_inode
                    .parse::<u64>()
                    .map_err(|_| WholePgCarrierFault::ManifestInvalid)?,
                installation
                    .artifact_root_uid
                    .parse::<u32>()
                    .map_err(|_| WholePgCarrierFault::ManifestInvalid)?,
            );
            let store_id = uuid::Uuid::parse_str(installation.store_id)
                .map_err(|_| WholePgCarrierFault::ManifestInvalid)?;
            let mut canonical = [0u8; 36];
            if installation.schema != "wrokbot-capture-installation"
                || installation.version != 1
                || installation.deployment_id != source.deployment_id
                || installation.tenant_id != source.tenant_id
                || installation.dataset_id != source.dataset_id
                || installation.instance_id != source.instance_id
                || installation.system_identifier != source.system_identifier
                || installation.database_oid != source.database_oid
                || installation.key_id != Some(source.key_id.as_str())
                || (
                    installation.installation_root.device,
                    installation.installation_root.inode,
                    installation.installation_root.uid,
                ) != root
                || actual_artifact != artifact
                || store_id.get_version_num() != 7
                || store_id.get_variant() != uuid::Variant::RFC4122
                || store_id.hyphenated().encode_lower(&mut canonical) != installation.store_id
            {
                return Err(WholePgCarrierFault::IntentMismatch);
            }
            (installation.installation_root, store_id)
        };
        for (id, schema, projection) in [
            (
                "profile-inventory",
                "wrokbot-capture-profile-inventory",
                "profiles",
            ),
            (
                "workspace-inventory",
                "wrokbot-capture-workspace-inventory",
                "workspaces",
            ),
        ] {
            let length = staged_metadata_prefix(input, id, true, session, deadline, error)?;
            let header: CapturedRootHeader<'_> =
                match serde_json::from_slice(&input.buffer[..length]) {
                    Ok(value) => value,
                    Err(e) => {
                        input.staging.as_mut().expect("staging owner").json_error = Some(e);
                        return Err(WholePgCarrierFault::ManifestInvalid);
                    }
                };
            let source = &input
                .manifest
                .as_ref()
                .expect("original manifest retained")
                .claim()
                .source;
            if header.schema != schema
                || header.version != 1
                || header.material_id != id
                || header.logical_projection != projection
                || header.construction != "postgres-built-in-tools-fresh-screen"
                || header.physical_root_disposition
                    != "no-local-owner-in-original-sealed-construction"
                || header.host_inventory_material_id != "host-inventory"
                || header.instance_id != source.instance_id
                || header.dataset_id != source.dataset_id
                || header.deployment_id != source.deployment_id
                || header.tenant_id != source.tenant_id
                || header.system_identifier != source.system_identifier
                || header.database_oid != source.database_oid
                || header.installation_root != installation_root
            {
                return Err(WholePgCarrierFault::IntentMismatch);
            }
            let preferences = input
                .manifest
                .as_ref()
                .expect("original manifest retained")
                .materials()
                .iter()
                .find(|m| m.material_id == "ui-preferences-v1");
            match (id, header.app_local_state, preference_bytes, preferences) {
                ("workspace-inventory", None, _, _) => {}
                (
                    "profile-inventory",
                    Some(CapturedPreferences::AbsentOriginalParentEnoent),
                    None,
                    None,
                ) => {}
                (
                    "profile-inventory",
                    Some(CapturedPreferences::PresentOriginalSnapshot {
                        byte_length,
                        sha256,
                    }),
                    Some(host_bytes),
                    Some(material),
                ) if host_bytes == byte_length
                    && material.plain_len == byte_length
                    && material.plain_sha256 == sha256 => {}
                _ => return Err(WholePgCarrierFault::IntentMismatch),
            }
        }
        let length = staged_metadata_prefix(
            input,
            "artifact:.artifact-store-v1",
            false,
            session,
            deadline,
            error,
        )?;
        let marker: CapturedStoreMarker<'_> = match serde_json::from_slice(&input.buffer[..length])
        {
            Ok(value) => value,
            Err(e) => {
                input.staging.as_mut().expect("staging owner").json_error = Some(e);
                return Err(WholePgCarrierFault::ManifestInvalid);
            }
        };
        let source = &input
            .manifest
            .as_ref()
            .expect("original manifest retained")
            .claim()
            .source;
        let mut canonical = [0u8; 36];
        if marker.schema != 1
            || marker.deployment_id != source.deployment_id
            || marker.tenant_id != source.tenant_id
            || marker.dataset_id != source.dataset_id
            || marker.store_id != store_id.hyphenated().encode_lower(&mut canonical)
        {
            return Err(WholePgCarrierFault::IntentMismatch);
        }
        input.buffer.as_mut_slice().zeroize();
        input.buffer.clear();
        stage_effect(session, deadline, error)
    }

    #[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
    fn real_staging_request() -> (crate::recovery_control::tests::RestoreEntryFixture, serde_json::Value) {
        use std::os::unix::fs::PermissionsExt;
        let mut fixture = crate::recovery_control::tests::RestoreEntryFixture::new();
        let source = std::path::PathBuf::from(std::env::var_os("OPENBOT_TEST_WHOLE_PG_CARRIER_DIR").expect("explicit task-owned CAR"));
        for (directory, destination) in [("carrier", "carrier-medium/carrier"), ("key", "key-medium/key")] {
            let mut entries = std::fs::read_dir(source.join(directory)).expect("CAR source directory");
            let file = entries.next().expect("one fixture file").expect("fixture entry").path(); assert!(entries.next().is_none());
            std::fs::copy(file, fixture.directory.join(destination)).expect("copy into real fixture medium");
            std::fs::set_permissions(fixture.directory.join(destination), std::fs::Permissions::from_mode(0o600)).expect("private fixture medium");
        }
        std::fs::copy(source.join("expected.json"), fixture.directory.join("expected.json")).expect("copy independent expected file");
        let expected: serde_json::Value = serde_json::from_slice(&std::fs::read(fixture.directory.join("expected.json")).expect("copied expected")).expect("fixture expected JSON");
        let capacity = &mut fixture.profile.capacity;
        capacity.max_input_wire_bytes = 64 * 1024 * 1024; capacity.max_manifest_bytes = 4 * 1024 * 1024;
        capacity.max_material_files = 4096; capacity.max_material_directories = 512;
        capacity.max_single_material_bytes = 32 * 1024 * 1024; capacity.max_material_plain_bytes = 64 * 1024 * 1024;
        capacity.max_candidate_data_bytes = 64 * 1024 * 1024; capacity.max_candidate_wal_bytes = 64 * 1024 * 1024;
        capacity.max_candidate_temp_bytes = 16 * 1024 * 1024; capacity.max_spool_bytes = 64 * 1024 * 1024;
        capacity.max_retained_prior_bytes = 64 * 1024 * 1024; capacity.max_secret_memory_bytes = 8 * 1024 * 1024;
        fixture.profile.effect_ns = 120_000_000_000;
        let mut request = fixture.request();
        let mut operation = [0u8; 16]; getrandom::fill(&mut operation).expect("real fixture request producer");
        request["requestId"] = serde_json::json!(operation.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
        request["purpose"] = serde_json::json!("restore_new_installation");
        for (request_key, expected_key) in [("expectedDeploymentId","deploymentId"),("expectedTenantId","tenantId"),("expectedDatasetId","datasetId"),("expectedSourceInstallationId","sourceInstallationId")] { request[request_key] = expected[expected_key].clone(); }
        for (request_key, expected_key) in [("expectedBundleId","bundleId"),("expectedSourceOperationId","sourceOperationId"),("expectedManifestSha256","manifestSha256")] { request["trustedInputSelection"][request_key] = expected[expected_key].clone(); }
        (fixture, request)
    }
    #[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
    fn real_staging_fixture() -> (crate::recovery_control::tests::RestoreEntryFixture, crate::recovery_control::RecoveryControl, RestoreControlSession) {
        let (fixture, request) = real_staging_request();
        let (mut control, entry) = fixture.open_request(request);
        let session = control.claim_restore(entry, fixture.profile.clone()).expect("actual original FS restore claim");
        (fixture, control, session)
    }

    #[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
    #[tokio::test]
    #[ignore = "explicit CAR; real claim/frozen input and task-owned FS only"]
    async fn t046_13_real_045_same_machine_carrier_authenticates_into_staging() {
        let (fixture, _control, mut session) = real_staging_fixture();
        let (input, intent) = session.frozen_input().expect("one actual frozen input transfer");
        assert_eq!(input.bounds.max_chunk_plain_bytes, 4 * 1024 * 1024, "profile is chunk upper bound");
        let staged = verify_whole_pg_restore_input(input, intent, &mut session).await.unwrap_or_else(|failure| {
            if let Some(work) = &failure.input.staging {
                eprintln!("staging progress plan={} dirs={} materials={} readers={} import_intent={}", work.plan.is_some(), work.directories.len(), work.materials.len(), work.materials.iter().filter(|material| material.stamp.is_some()).count(), work.import_intent.is_some());
                let grain = work.space.as_ref().and_then(|value| value.as_ref().ok()).map(|space| space.f_frsize.max(space.f_bsize));
                eprintln!("actual allocation grain={grain:?}");
                for (ordinal, material) in work.materials.iter().enumerate() {
                    if let Some(file) = &material.file {
                        let metadata = file.metadata().expect("retained own fixture metadata");
                        let expected = failure.input.manifest.as_ref().expect("authenticated manifest").materials()[ordinal].plain_len;
                        if grain.is_some_and(|grain| metadata.blocks() * 512 > expected.div_ceil(grain) * grain) { eprintln!("allocation ordinal={ordinal} plain={expected} length={} allocated={}", metadata.len(), metadata.blocks() * 512); }
                    }
                }
            }
            for resource in [Capacity::MetadataBytes, Capacity::OpenFiles, Capacity::MaterialDirectories, Capacity::MaterialFiles, Capacity::MaterialPlainBytes, Capacity::SecretMemoryBytes, Capacity::JournalBytes, Capacity::JournalRecords] { eprintln!("remaining {resource:?}={:?}", session.input_stages().capacity_available(resource).map_err(|error| error.fault())); }
            panic!("real staging failed: {:?} control={:?}", failure.fault(), failure.control_error.as_ref().map(RecoveryControlError::fault));
        });
        assert_eq!(staged.candidate_plan().operation_id(), session.operation_id());
        assert_eq!(u32::from_be_bytes(staged.manifest().header()[32..36].try_into().expect("fixed chunk bytes")), 65536, "actual authenticated F07 chunk");
        assert!(fixture.directory.join("new-generation/materials/staging/pgdata").is_dir());
        assert_eq!(staged.work().materials.len(), staged.manifest().materials().len());
        assert_eq!(staged.work().materials.iter().filter(|material| material.file.is_some()).count() + 2, staged.work().materials.len());
        for (ordinal, material) in staged.manifest().materials().iter().enumerate() {
            if material.kind.is_secret() { assert!(staged.material_file(ordinal).is_none()); continue; }
            let file = staged.material_file(ordinal).expect("stable original material FD");
            assert_eq!(file.metadata().expect("stable material metadata").len(), material.plain_len);
            assert_eq!(rustix::fs::fcntl_getfl(file).expect("actual reader flags") & OFlags::ACCMODE, OFlags::RDONLY);
        }
        assert!(!fixture.directory.join("com.acosmi.wrokbot.restore-control/staging").exists());
        assert!(!fixture.directory.join("new-generation/materials/staging/secrets").exists());
    }

    #[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
    #[tokio::test]
    #[ignore = "explicit CAR; real claim/frozen input and task-owned FS only"]
    async fn t046_18_replacing_original_package_after_staging_has_no_effect() {
        let (fixture, _control, mut session) = real_staging_fixture();
        let (input, intent) = session.frozen_input().expect("actual frozen input");
        let staged = verify_whole_pg_restore_input(input, intent, &mut session).await.unwrap_or_else(|failure| panic!("real staging failed: {:?} control={:?}", failure.fault(), failure.control_error.as_ref().map(RecoveryControlError::fault)));
        std::fs::rename(fixture.directory.join("carrier-medium/carrier"), fixture.directory.join("carrier-medium/old-carrier")).expect("replace owned original name");
        std::fs::write(fixture.directory.join("carrier-medium/carrier"), b"replacement").expect("owned replacement package");
        std::fs::OpenOptions::new().write(true).open(fixture.directory.join("carrier-medium/old-carrier")).expect("original package inode").set_len(0).expect("change original package bytes");
        let mut buffer = zeroize::Zeroizing::new(vec![0u8; 65536]);
        for (ordinal, material) in staged.manifest().materials().iter().enumerate() {
            if material.kind.is_secret() { continue; }
            let file = staged.material_file(ordinal).expect("stable stage-only consumer"); let mut hash = Sha256::new(); let mut at = 0u64;
            while at < material.plain_len { let length = (material.plain_len - at).min(buffer.len() as u64) as usize; file.read_exact_at(&mut buffer[..length], at).expect("stable FD read"); hash.update(&buffer[..length]); at += length as u64; }
            let mut digest: [u8; 32] = hash.finalize().into(); let equal = digest == material.plain_sha256; digest.zeroize(); assert!(equal, "stage unaffected by original replacement");
        }
    }
    #[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
    #[tokio::test]
    #[ignore = "explicit CAR; real claim/frozen input and task-owned FS only"]
    async fn t046_15_mixed_expected_key_header_or_manifest_is_rejected() {
        for variant in 0..6 {
            let (fixture, mut request) = real_staging_request();
            match variant {
                0 => request["trustedInputSelection"]["expectedBundleId"] = serde_json::json!("01234567-89ab-4def-8123-456789abcdef"),
                1 => request["trustedInputSelection"]["expectedSourceOperationId"] = serde_json::json!("11234567-89ab-4def-8123-456789abcdef"),
                2 => request["trustedInputSelection"]["expectedManifestSha256"] = serde_json::json!("00".repeat(32)),
                _ => {
                    let (name, at) = match variant { 3 => ("key-medium/key", 72), 4 => ("carrier-medium/carrier", 12), _ => ("carrier-medium/carrier", 101) };
                    let file = std::fs::OpenOptions::new().read(true).write(true).open(fixture.directory.join(name)).expect("owned mutation input");
                    let mut byte = [0u8; 1]; file.read_exact_at(&mut byte, at).expect("mutation source byte"); byte[0] ^= 1; file.write_all_at(&byte, at).expect("change owned fixture byte");
                }
            }
            let (mut control, entry) = fixture.open_request(request);
            let mut session = control.claim_restore(entry, fixture.profile.clone()).expect("real claim before input authentication");
            let (input, intent) = session.frozen_input().expect("actual frozen mutated input");
            let failure = verify_whole_pg_restore_input(input, intent, &mut session).await.err().expect("mixed input rejected");
            assert!(matches!(failure.fault(), WholePgCarrierFault::KeyMediumInvalid | WholePgCarrierFault::IntentMismatch | WholePgCarrierFault::AuthenticationFailed));
            assert!(failure.input.staging.is_none()); assert!(failure.input.carrier.metadata().is_ok()); assert!(failure.input.key_medium.metadata().is_ok());
            assert!(!fixture.directory.join("new-generation").exists());
        }
        eprintln!("T15 original six mismatch/corruption cases rejected before staging");
        assert_valid_other_bundle_mixtures_rejected().await;
    }

    #[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
    async fn assert_valid_other_bundle_mixtures_rejected() {
        use openbot_domain::backup::whole_pg_carrier::{WholePgManifestClaim, WholePgSealCodec};
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let (source_fixture, _source_control, mut source_session) = real_staging_fixture();
        let (input, intent) = source_session.frozen_input().expect("original held CAR inputs");
        let mut source = verify_whole_pg_restore_input(input, intent, &mut source_session).await
            .unwrap_or_else(|failure| panic!("original full CAR invalid: {:?}", failure.fault()));
        let original_header = source.manifest().header();
        let bounds = source.carrier.input.bounds;
        // Reuse the original bounded single-frame allocation. Material bytes
        // come only from real authenticated stage FDs or its private secrets.
        let mut buffer = std::mem::take(&mut source.carrier.input.buffer);
        source.manifest().encode_manifest_into(&mut buffer).expect("original canonical manifest");
        let mut claim: WholePgManifestClaim = serde_json::from_slice(&buffer).expect("original typed manifest DATA");
        buffer.as_mut_slice().zeroize(); buffer.clear();
        let mut bundle_bytes = [0u8; 16]; getrandom::fill(&mut bundle_bytes).expect("independent bundle DATA");
        bundle_bytes[6] = (bundle_bytes[6] & 15) | 0x40;
        bundle_bytes[8] = (bundle_bytes[8] & 63) | 0x80;
        let other_bundle = uuid::Uuid::from_bytes(bundle_bytes);
        claim.bundle_id = other_bundle.to_string();
        let manifest = FrozenWholePgManifest::check(claim, bounds).expect("other complete frozen layout");
        let other_header = manifest.header();
        assert_ne!(original_header, other_header);
        assert_eq!(&original_header[28..48], &other_header[28..48], "same complete material lengths and chunk layout");
        let mut raw_key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut raw_key[..]).expect("fresh independent K, never reuse the capture nonce key");
        let key = SecretBytes::new(raw_key.to_vec()); raw_key.zeroize();
        let carrier_path = source_fixture.directory.join("other-complete-carrier");
        let key_path = source_fixture.directory.join("other-complete-key");
        let mut carrier = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&carrier_path).expect("owned complete carrier output");
        carrier.write_all(&other_header).expect("complete other carrier header");
        let mut codec = WholePgSealCodec::new(&key, &manifest).expect("original 045 sealing codec");
        let mut frames = 0u64;
        while let Some(spec) = codec.next_frame() {
            match spec.kind() {
                0 => manifest.encode_manifest_into(&mut buffer).expect("complete other manifest plaintext"),
                1 => {
                    buffer.resize(spec.plain_len() as usize, 0);
                    let ordinal = spec.material_ordinal() as usize;
                    match manifest.materials()[ordinal].kind {
                        WholePgMaterialKind::MasterSecret => buffer.copy_from_slice(source.authenticated_secrets().historical_master().expose()),
                        WholePgMaterialKind::ScramSecret => buffer.copy_from_slice(source.authenticated_secrets().postgres_scram().expose()),
                        _ => source.material_file(ordinal).expect("actual authenticated readonly material FD")
                            .read_exact_at(&mut buffer, spec.offset()).expect("original authenticated material frame"),
                    }
                }
                2 => manifest.encode_terminal_into(&mut buffer).expect("complete other terminal"),
                _ => unreachable!("original closed codec frame kinds"),
            }
            let parts = codec.seal_next_in_place(&mut buffer).expect("seal actual complete frame");
            carrier.write_all(&parts.header).and_then(|_| carrier.write_all(&buffer)).and_then(|_| carrier.write_all(&parts.tag)).expect("write entire original-format frame");
            buffer.as_mut_slice().zeroize(); buffer.clear(); frames += 1;
        }
        carrier.sync_all().expect("complete other carrier fsync");
        assert_eq!(carrier.metadata().expect("actual complete wire length").len(), manifest.wire_bytes().expect("full frozen wire length"));
        assert!(frames > 2, "manifest, all material frames and terminal, not a prefix");
        let mut key_medium = Zeroizing::new([0u8; 104]);
        key_medium[..8].copy_from_slice(b"WBPGKEY1");
        key_medium[8..24].copy_from_slice(other_bundle.as_bytes());
        key_medium[24..40].copy_from_slice(uuid::Uuid::parse_str(&manifest.claim().operation_id).expect("unchanged source operation").as_bytes());
        key_medium[40..72].copy_from_slice(&other_header[48..80]);
        key_medium[72..104].copy_from_slice(key.expose());
        let mut key_file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&key_path).expect("owned independent original-format key medium");
        key_file.write_all(&key_medium[..]).and_then(|_| key_file.sync_all()).expect("complete other key medium");
        drop(key_medium); drop(key_file); drop(codec); drop(key); drop(carrier); drop(buffer); drop(source);

        // The original production whole-carrier authentication checks all
        // materials, terminal and EOF. Its three inputs come from one real claim.
        let (valid_fixture, mut valid_request) = real_staging_request();
        std::fs::copy(&carrier_path, valid_fixture.directory.join("carrier-medium/carrier")).expect("other carrier verification copy");
        std::fs::copy(&key_path, valid_fixture.directory.join("key-medium/key")).expect("other key verification copy");
        valid_request["trustedInputSelection"]["expectedBundleId"] = serde_json::json!(other_bundle.to_string());
        valid_request["trustedInputSelection"]["expectedManifestSha256"] = serde_json::json!(other_header[48..80].iter().map(|byte| format!("{byte:02x}")).collect::<String>());
        let (mut valid_control, entry) = valid_fixture.open_request(valid_request);
        let mut valid_session = valid_control.claim_restore(entry, valid_fixture.profile.clone()).expect("real independent complete-carrier claim");
        let (input, intent) = valid_session.frozen_input().expect("independent original held input");
        assert_eq!(input.operation.as_str(), valid_session.operation_id());
        assert_eq!(intent.operation.as_str(), valid_session.operation_id());
        let valid = authenticate_whole_pg_restore_carrier_before(input, intent, &mut valid_session)
            .unwrap_or_else(|failure| panic!("independent complete other CAR invalid: {:?}", failure.fault()));
        assert_eq!(valid.input.manifest.as_ref().expect("complete other manifest").header(), other_header);
        assert_eq!(valid.input.authenticated_frames, frames);
        assert!(valid.input.staging.is_none());
        eprintln!("T15 independent complete alternate carrier: frames={} materials={} wire_bytes={}", frames, manifest.materials().len(), valid.input.carrier.metadata().expect("actual alternate length").len());
        drop(valid); drop(valid_session); drop(valid_control); drop(valid_fixture);

        for mix_header in [true, false] {
            let (fixture, request) = real_staging_request();
            let other = File::open(&carrier_path).expect("independently validated complete other carrier");
            let mixed = std::fs::OpenOptions::new().read(true).write(true).open(fixture.directory.join("carrier-medium/carrier")).expect("original CAR copy to mix");
            if mix_header {
                mixed.write_all_at(&other_header, 0).expect("literal entire valid-other header splice");
            } else {
                let length = u32::from_be_bytes(other_header[28..32].try_into().expect("fixed manifest length")) as usize;
                let mut frame_header = [0u8; 21]; let mut tag = [0u8; 16];
                let mut frame = Zeroizing::new(vec![0u8; length]);
                other.read_exact_at(&mut frame_header, 80).expect("valid-other manifest frame header");
                other.read_exact_at(&mut frame, 101).expect("entire valid-other manifest ciphertext");
                other.read_exact_at(&mut tag, 101 + length as u64).expect("valid-other manifest tag");
                mixed.write_all_at(&frame_header, 80).and_then(|_| mixed.write_all_at(&frame, 101)).and_then(|_| mixed.write_all_at(&tag, 101 + length as u64)).expect("literal entire valid-other manifest frame splice");
            }
            mixed.sync_all().expect("owned literal mixture fsync");
            let carrier_before = mixed.metadata().expect("actual mixed carrier identity");
            let key_before = std::fs::metadata(fixture.directory.join("key-medium/key")).expect("original independent key identity");
            let (mut control, entry) = fixture.open_request(request);
            let mut session = control.claim_restore(entry, fixture.profile.clone()).expect("real mixture claim");
            let (input, intent) = session.frozen_input().expect("original expected/key remain unchanged");
            let failure = verify_whole_pg_restore_input(input, intent, &mut session).await.err().expect("literal cross-package mixture rejected");
            assert_eq!(failure.fault(), if mix_header { WholePgCarrierFault::IntentMismatch } else { WholePgCarrierFault::AuthenticationFailed });
            let carrier_after = failure.input.carrier.metadata().expect("original rejected carrier FD retained");
            let key_after = failure.input.key_medium.metadata().expect("original independent key FD retained");
            assert_eq!((carrier_before.dev(), carrier_before.ino(), carrier_before.len()), (carrier_after.dev(), carrier_after.ino(), carrier_after.len()));
            assert_eq!((key_before.dev(), key_before.ino(), key_before.len()), (key_after.dev(), key_after.ino(), key_after.len()));
            assert!(failure.input.staging.is_none());
            assert!(!fixture.directory.join("new-generation").exists());
            eprintln!("T15 literal valid-other {} rejected with retained original FDs and zero staging", if mix_header { "header" } else { "complete manifest frame" });
        }
    }

    #[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
    #[tokio::test]
    #[ignore = "explicit CAR; real claim/frozen input and task-owned FS only"]
    async fn t046_16_truncated_tail_reordered_linked_or_traversal_input_is_rejected() {
        for variant in 0..7 {
            let (fixture, mut request) = real_staging_request();
            if variant < 3 {
                let file = std::fs::OpenOptions::new().read(true).write(true).open(fixture.directory.join("carrier-medium/carrier")).expect("owned carrier");
                match variant {
                    0 => file.set_len(file.metadata().expect("actual carrier length").len() - 1).expect("truncate owned carrier"),
                    1 => file.write_all_at(&[1], file.metadata().expect("actual carrier length").len()).expect("add owned tail"),
                    _ => {
                        let mut length = [0u8; 4]; file.read_exact_at(&mut length, 28).expect("original manifest length");
                        let first = 80 + 37 + u64::from(u32::from_be_bytes(length));
                        let mut header = [0u8; 21]; file.read_exact_at(&mut header, first).expect("first data frame");
                        let first_length = 37 + u32::from_be_bytes(header[17..21].try_into().expect("fixed frame length")) as usize;
                        file.read_exact_at(&mut header, first + first_length as u64).expect("next data frame");
                        let second_length = 37 + u32::from_be_bytes(header[17..21].try_into().expect("fixed frame length")) as usize;
                        assert!(first_length <= 4 * 1024 * 1024 + 37 && second_length <= 4 * 1024 * 1024 + 37);
                        let mut first_frame = vec![0u8; first_length]; let mut second_frame = vec![0u8; second_length];
                        file.read_exact_at(&mut first_frame, first).expect("owned first ciphertext frame"); file.read_exact_at(&mut second_frame, first + first_length as u64).expect("owned second ciphertext frame");
                        file.write_all_at(&second_frame, first).expect("swap actual ciphertext frames"); file.write_all_at(&first_frame, first + second_length as u64).expect("complete frame swap");
                    }
                }
            } else {
                match variant {
                    3 => { std::fs::remove_file(fixture.directory.join("key-medium/key")).expect("owned original key name"); std::os::unix::fs::symlink("../carrier-medium/carrier", fixture.directory.join("key-medium/key")).expect("owned symlink negative"); },
                    4 => std::fs::hard_link(fixture.directory.join("key-medium/key"), fixture.directory.join("key-medium/hard-key")).expect("owned hardlink negative"),
                    5 => request["trustedInputSelection"]["keyMedium"]["component"] = serde_json::json!("../key"),
                    _ => request["trustedInputSelection"]["keyMedium"]["component"] = serde_json::json!("key/child"),
                }
                let medium = fixture.directory.join("key-medium/key");
                let before = std::fs::symlink_metadata(&medium).expect("original medium retained before admission");
                let carrier_before = std::fs::metadata(fixture.directory.join("carrier-medium/carrier")).expect("original carrier before admission");
                if variant < 5 {
                    // The request parser seals selection DATA. The original
                    // claim then opens the actual medium with O_NOFOLLOW and
                    // checks regular/single-link shape before minting an op.
                    let (mut control, entry) = fixture.try_open_request(request).expect("closed linked selection DATA parses");
                    let error = control.claim_restore(entry, fixture.profile.clone()).err().expect("actual medium admission rejects links");
                    let expected = if variant == 3 { crate::recovery_control::RecoveryControlFault::IoFailure } else { crate::recovery_control::RecoveryControlFault::EntryInvalid };
                    assert_eq!(error.fault(), expected);
                } else {
                    let error = fixture.try_open_request(request).err().expect("closed parser rejects traversal components");
                    assert_eq!(error.fault(), crate::recovery_control::RecoveryControlFault::ControlInvalid);
                }
                let after = std::fs::symlink_metadata(&medium).expect("original medium remains after rejection");
                assert_eq!((after.dev(), after.ino(), after.mode(), after.nlink(), after.len()), (before.dev(), before.ino(), before.mode(), before.nlink(), before.len()));
                let carrier_after = std::fs::metadata(fixture.directory.join("carrier-medium/carrier")).expect("original carrier remains after rejection");
                assert_eq!((carrier_after.dev(), carrier_after.ino(), carrier_after.len()), (carrier_before.dev(), carrier_before.ino(), carrier_before.len()));
                let control_root = fixture.directory.join("com.acosmi.wrokbot.restore-control");
                let operations = control_root.join("operations");
                if operations.exists() { assert_eq!(std::fs::read_dir(operations).expect("original operation directory").count(), 0, "no operation was minted before medium admission"); }
                assert!(!control_root.join("activation-v1").exists(), "no Pending descriptor before medium admission");
                assert!(!fixture.directory.join("new-generation").exists()); continue;
            }
            let (mut control, entry) = fixture.open_request(request);
            let mut session = control.claim_restore(entry, fixture.profile.clone()).expect("real claim before carrier rejection");
            let (input, intent) = session.frozen_input().expect("actual frozen mutated carrier");
            let failure = verify_whole_pg_restore_input(input, intent, &mut session).await.err().expect("malformed carrier rejected");
            assert!(matches!(failure.fault(), WholePgCarrierFault::ShortRead | WholePgCarrierFault::ExtraTail | WholePgCarrierFault::FrameInvalid));
            assert!(failure.input.staging.is_none()); assert!(failure.input.carrier.metadata().is_ok()); assert!(!fixture.directory.join("new-generation").exists());
        }
    }

    #[cfg(test)]
    mod input_authentication_tests {
        use super::*;
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierBounds;
        use serde::Deserialize;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use std::path::{Path, PathBuf};
        use std::time::{Duration, Instant};

        // Same private owned-root convention as the existing carrier fixtures;
        // Infra has no tempfile dependency and needs none for this test boundary.
        struct FixtureRoot(PathBuf);
        impl FixtureRoot {
            fn new() -> Self {
                let path =
                    std::env::temp_dir().join(format!("wrok-s17-car-{}", uuid::Uuid::now_v7()));
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .expect("new private fixture root");
                Self(path)
            }
            fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for FixtureRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Expected {
            bundle_id: uuid::Uuid,
            source_operation_id: uuid::Uuid,
            manifest_sha256: String,
            deployment_id: String,
            tenant_id: String,
            dataset_id: String,
            source_installation_id: String,
        }
        fn only_file(path: &Path) -> PathBuf {
            let mut entries = std::fs::read_dir(path).expect("CAR directory");
            let file = entries
                .next()
                .expect("one fixture file")
                .expect("fixture entry")
                .path();
            assert!(
                entries.next().is_none(),
                "exactly one original fixture file"
            );
            file
        }
        fn fixture() -> (
            FixtureRoot,
            FrozenWholePgRestoreInput,
            ReviewedWholePgRestoreIntent,
        ) {
            let source = PathBuf::from(
                std::env::var_os("OPENBOT_TEST_WHOLE_PG_CARRIER_DIR")
                    .expect("explicit CAR copy source"),
            );
            let temp = FixtureRoot::new();
            for (directory, target) in [("carrier", "carrier"), ("key", "key")] {
                std::fs::copy(only_file(&source.join(directory)), temp.path().join(target))
                    .expect("copy fixture into owned tempdir");
                std::fs::set_permissions(
                    temp.path().join(target),
                    std::fs::Permissions::from_mode(0o600),
                )
                .expect("private file");
            }
            std::fs::copy(
                source.join("expected.json"),
                temp.path().join("expected.json"),
            )
            .expect("copy independent expectations");
            let expected: Expected = serde_json::from_slice(
                &std::fs::read(temp.path().join("expected.json")).expect("expected copy"),
            )
            .expect("closed expected fixture");
            let mut digest = [0u8; 32];
            assert_eq!(expected.manifest_sha256.len(), 64);
            for (index, byte) in digest.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&expected.manifest_sha256[index * 2..index * 2 + 2], 16)
                    .expect("public hex digest");
            }
            // F07's original capture profile has 64 KiB chunks. These explicit
            // fixture limits are not a production profile or a Session substitute.
            let bounds = WholePgCarrierBounds {
                max_material_files: 8192,
                max_directories: 8192,
                max_path_bytes: 4096,
                max_path_depth: 32,
                max_single_plain_bytes: 64 * 1024 * 1024,
                max_material_plain_bytes: 128 * 1024 * 1024,
                max_manifest_bytes: 4 * 1024 * 1024,
                max_header_bytes: 80,
                max_data_chunks: 65536,
                max_chunk_plain_bytes: 65536,
                max_wire_bytes: 128 * 1024 * 1024,
                max_metadata_bytes: 32 * 1024 * 1024,
                max_open_files: 8192,
                max_snapshot_bytes: 128 * 1024 * 1024,
                max_spool_bytes: 128 * 1024 * 1024,
                max_retained_prior_bytes: 128 * 1024 * 1024,
                max_journal_bytes: 4 * 1024 * 1024,
                max_total_allocation_bytes: 512 * 1024 * 1024,
                capacity_reserve_bytes: 4096,
                free_floor_bytes: 4096,
                max_key_medium_allocation_bytes: 4096,
                key_medium_reserve_bytes: 4096,
                key_medium_free_floor_bytes: 4096,
            }
            .check()
            .expect("finite fixture bounds");
            let carrier = File::open(temp.path().join("carrier")).expect("held carrier");
            let key_medium = File::open(temp.path().join("key")).expect("held key medium");
            let mut operation_bytes = [0u8; 16];
            getrandom::fill(&mut operation_bytes).expect("fixture operation DATA");
            let operation_text: String = operation_bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let operation = crate::recovery_control::Hex32::parse(&operation_text).expect("fixture operation DATA shape");
            let input = FrozenWholePgRestoreInput {
                operation,
                carrier_identity: RestoreInputFileIdentity::from_metadata(
                    &carrier.metadata().expect("actual carrier identity"),
                )
                .expect("private carrier"),
                key_identity: RestoreInputFileIdentity::from_metadata(
                    &key_medium.metadata().expect("actual key identity"),
                )
                .expect("private key"),
                carrier,
                key_medium,
                bounds,
                buffer: Zeroizing::new(Vec::with_capacity(4 * 1024 * 1024)),
                key_bytes: Zeroizing::new([0; 104]),
                decoded_secrets: Zeroizing::new([0; 96]),
                raw_read: None,
                raw_eof: None,
                raw_metadata: None,
                manifest: None,
                authenticated_frames: 0,
                authenticated: None,
                staging: None,
            };
            let intent = ReviewedWholePgRestoreIntent {
                operation,
                expected: WholePgManifestExpectation {
                    bundle_id: *expected.bundle_id.as_bytes(),
                    source_operation_id: *expected.source_operation_id.as_bytes(),
                    manifest_sha256: digest,
                },
                deployment_id: expected.deployment_id,
                tenant_id: expected.tenant_id,
                dataset_id: expected.dataset_id,
                source_installation_id: expected.source_installation_id,
            };
            (temp, input, intent)
        }
        fn real_finite_clock() -> impl FnMut() -> Result<(), WholePgCarrierFault> {
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(30))
                .expect("finite fixture deadline");
            move || {
                if Instant::now() < deadline {
                    Ok(())
                } else {
                    Err(WholePgCarrierFault::DeadlineExpired)
                }
            }
        }
        fn refresh_carrier_identity(input: &mut FrozenWholePgRestoreInput) {
            input.carrier_identity = RestoreInputFileIdentity::from_metadata(
                &input
                    .carrier
                    .metadata()
                    .expect("actual changed fixture metadata"),
            )
            .expect("ordinary fixture file");
        }
        #[test]
        #[ignore = "requires explicit task-owned F07 CAR copy; component boundary only"]
        fn f07_full_carrier_authenticates_every_material_before_secrets() {
            let (_temp, mut input, intent) = fixture();
            let capacity = input.buffer.capacity();
            let authenticated =
                authenticate_original_carrier(&mut input, &intent, &mut real_finite_clock());
            if authenticated.is_err() {
                eprintln!(
                    "component manifest_present={} authenticated_frames={}",
                    input.manifest.is_some(),
                    input.authenticated_frames
                );
                if let Some(manifest) = &input.manifest {
                    for material in manifest
                        .materials()
                        .iter()
                        .filter(|material| material.relative_path.starts_with("metadata/"))
                    {
                        // Public inventory only; never payload, plaintext digest or secret.
                        eprintln!(
                            "metadata id={} path={} kind={:?} bytes={}",
                            material.material_id,
                            material.relative_path,
                            material.kind,
                            material.plain_len
                        );
                    }
                }
            }
            authenticated.expect("full original carrier authentication");
            let manifest = input.manifest.as_ref().expect("authenticated manifest");
            assert_eq!(
                manifest.wire_bytes().expect("wire size"),
                input.carrier_identity.length
            );
            assert!(manifest.materials().len() > 15);
            assert!(
                !manifest
                    .materials()
                    .iter()
                    .any(|material| material.material_id == "ui-preferences-v1"),
                "F07 preserves the original absent-preference branch"
            );
            assert_eq!(
                input.authenticated_frames,
                u64::from(u32::from_be_bytes(
                    manifest.header()[36..40].try_into().expect("fixed count")
                )) + 2
            );
            let secrets = input
                .authenticated
                .as_ref()
                .expect("only complete carrier yields sealed secrets");
            assert_eq!(secrets.historical_master().len(), 32);
            assert_eq!(secrets.postgres_scram().len(), 64);
            let mut independent_key = Zeroizing::new([0u8; 104]);
            input
                .key_medium
                .read_exact_at(independent_key.as_mut_slice(), 0)
                .expect("original independent key copy");
            assert!(
                !openbot_domain::backup::whole_pg_carrier::whole_pg_secret_matches(
                    secrets.historical_master(),
                    &independent_key[72..104]
                ),
                "historical master must not be recovery K"
            );
            assert_eq!(input.buffer.capacity(), capacity);
            assert!(input.buffer.is_empty());
            assert!(input.key_bytes.iter().all(|v| *v == 0));
            assert!(input.decoded_secrets.iter().all(|v| *v == 0));
        }
        #[test]
        #[ignore = "requires explicit task-owned F07 CAR copy; component boundary only"]
        fn f07_independent_expectations_and_wrong_key_are_rejected_without_secrets() {
            for variant in 0..8 {
                let (temp, mut input, mut intent) = fixture();
                match variant {
                    0 => intent.expected.bundle_id[0] ^= 1,
                    1 => intent.expected.source_operation_id[0] ^= 1,
                    2 => intent.expected.manifest_sha256[0] ^= 1,
                    3 => intent.deployment_id.push('x'),
                    4 => intent.source_installation_id.push('x'),
                    5 => intent.tenant_id.push('x'),
                    6 => intent.dataset_id.push('x'),
                    _ => {
                        let writable = std::fs::OpenOptions::new()
                            .write(true)
                            .open(temp.path().join("key"))
                            .expect("owned fixture key");
                        writable
                            .write_all_at(&[0u8; 32], 72)
                            .expect("replace fixture K only");
                        input.key_identity = RestoreInputFileIdentity::from_metadata(
                            &input.key_medium.metadata().expect("actual key metadata"),
                        )
                        .expect("private fixture key");
                    }
                }
                let result =
                    authenticate_original_carrier(&mut input, &intent, &mut real_finite_clock());
                assert!(matches!(
                    result,
                    Err(WholePgCarrierFault::KeyMediumInvalid
                        | WholePgCarrierFault::IntentMismatch
                        | WholePgCarrierFault::AuthenticationFailed)
                ));
                assert!(input.authenticated.is_none());
                assert_eq!(
                    input
                        .carrier
                        .metadata()
                        .expect("original carrier retained")
                        .ino(),
                    input.carrier_identity.inode
                );
                assert_eq!(
                    input
                        .key_medium
                        .metadata()
                        .expect("original key retained")
                        .ino(),
                    input.key_identity.inode
                );
            }
        }
        #[test]
        #[ignore = "requires explicit task-owned F07 CAR copy; component boundary only"]
        fn f07_terminal_tamper_tail_truncation_and_frame_reorder_never_yield_secrets() {
            for variant in 0..4 {
                let (temp, mut input, intent) = fixture();
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(temp.path().join("carrier"))
                    .expect("owned fixture carrier");
                let original = input.carrier_identity.length;
                match variant {
                    0 => file
                        .write_all_at(&[0u8; 16], original - 16)
                        .expect("corrupt terminal tag"),
                    1 => file.write_all_at(&[1], original).expect("add tail"),
                    2 => file.set_len(original - 1).expect("truncate"),
                    _ => {
                        let mut length = [0u8; 4];
                        input
                            .carrier
                            .read_exact_at(&mut length, 28)
                            .expect("manifest length");
                        let next = 80 + 37 + u64::from(u32::from_be_bytes(length));
                        file.write_all_at(&2u32.to_be_bytes(), next + 1)
                            .expect("wrong second sequence");
                    }
                }
                refresh_carrier_identity(&mut input);
                assert!(
                    authenticate_original_carrier(&mut input, &intent, &mut real_finite_clock())
                        .is_err()
                );
                assert!(input.authenticated.is_none());
            }
        }
        #[test]
        #[ignore = "requires explicit task-owned F07 CAR copy; component boundary only"]
        fn f07_changed_original_identity_and_expired_clock_keep_original_owners() {
            let (temp, mut input, intent) = fixture();
            std::fs::OpenOptions::new()
                .write(true)
                .open(temp.path().join("carrier"))
                .expect("owned fixture")
                .set_len(1)
                .expect("change original inode");
            assert_eq!(
                authenticate_original_carrier(&mut input, &intent, &mut real_finite_clock()),
                Err(WholePgCarrierFault::SourceChanged)
            );
            assert!(input.authenticated.is_none());
            let mut expired = || Err(WholePgCarrierFault::DeadlineExpired);
            assert_eq!(
                authenticate_original_carrier(&mut input, &intent, &mut expired),
                Err(WholePgCarrierFault::DeadlineExpired)
            );
            assert_eq!(input.authenticated_frames, 0);
            assert!(input.raw_metadata.is_some());
            assert!(input.carrier.metadata().is_ok());
            assert!(input.key_medium.metadata().is_ok());
        }
    }
}
// BEGIN S21 candidate_sql
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub(crate) mod candidate_sql {
    use super::{PendingRestoreCandidateAuthority, RestoreCandidateBinding, RestoreStages};
    use crate::db::capture_materials::{
        CaptureSqlBudget, CaptureSqlFailure, CaptureSqlLimits,
        verify_restore_catalog_in_transaction,
    };
    use crate::db::pool::{GuardedClient, GuardedTransaction, PoolError, TransactionOwnerError};
    use crate::db::{InfraError, native};
    use crate::recovery_control::{
        RecoveryControlError, RecoveryControlFault, RestoreCapacityResource as Capacity,
        RestoreCommitAck, RestoreDisposition, RestoreRollbackAck, RestoreStage, RestoreStageIntent,
    };
    use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
    use openbot_contracts::ids::{ActorId, AuditEventId};
    use openbot_domain::audit::chain::StoredAuditRow;
    use openbot_domain::audit::event::{AuditEvent, AuditEventType};
    use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
    use std::time::Instant;
    use tokio::time::error::Elapsed;
    use tokio_postgres::{Row, Transaction, types::ToSql};

    /// Borrowed only here from a real candidate and its original guarded owner.
    /// No pool, namespace or audit-key constructor is exposed to callers.
    pub(crate) struct PendingHistoryClearSource<'a, 'transaction> {
        owner: &'a GuardedTransaction<'transaction>,
        binding: &'a RestoreCandidateBinding,
        audit_key: &'a openbot_domain::vault::SecretBytes,
        stages: &'a mut RestoreStages,
        control: &'a mut Option<Result<Result<Row, tokio_postgres::Error>, Elapsed>>,
        key_result: &'a mut Option<Result<Result<(), tokio_postgres::Error>, Elapsed>>,
    }

    impl<'transaction> PendingHistoryClearSource<'_, 'transaction> {
        pub(crate) fn parts(&mut self) -> (&Transaction<'transaction>, &str, &str, &[u8], &mut RestoreStages, &mut Option<Result<Result<Row, tokio_postgres::Error>, Elapsed>>, &mut Option<Result<Result<(), tokio_postgres::Error>, Elapsed>>) {
            (self.owner.as_transaction(), &self.binding.deployment_id, &self.binding.tenant_id, self.audit_key.expose(), self.stages, self.control, self.key_result)
        }
    }

    const BATCH_ROWS: u64 = 64;
    const INSERT_REQUIREMENTS_SQL: &str = r#"  WITH credential_references AS (
   SELECT c.id,pg_catalog.jsonb_agg(ref.value ORDER BY ref.value::text COLLATE pg_catalog."C") AS refs,
    pg_catalog.min(ref.actor) AS actor,pg_catalog.count(DISTINCT ref.actor) AS actors,
    pg_catalog.bool_or(ref.actor IS NULL) AS service_reference
   FROM public.credentials c LEFT JOIN LATERAL (
    SELECT pg_catalog.jsonb_build_array('mcp_user',s.id,pg_catalog.to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),s.url,u.user_id,u.scope) AS value,u.user_id AS actor
     FROM public.mcp_user_credentials u JOIN public.mcp_servers s ON s.id=u.server_id WHERE u.credential_id=c.id
    UNION ALL SELECT pg_catalog.jsonb_build_array('mcp_client',s.id,pg_catalog.to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),s.url,s.added_by),s.added_by
     FROM public.mcp_servers s WHERE s.credential_id=c.id
   ) ref ON true GROUP BY c.id
  ), inventory(kind,ref,birth,revision,owner_kind,owner_id,owner_birth,public_fields) AS (
   SELECT 'subject',u.id,u.created_at,NULL::bigint,'actor',u.id,u.created_at,
    pg_catalog.jsonb_build_array(u.id,pg_catalog.to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM public.users u
   UNION ALL SELECT 'credential',c.id::text,c.created_at,NULL::bigint,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN 'actor' ELSE 'service' END,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN r.actor ELSE $1::text END,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN u.created_at ELSE NULL END,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.kind,c.provider,r.refs)
    FROM public.credentials c JOIN credential_references r ON r.id=c.id LEFT JOIN public.users u ON u.id=r.actor
    WHERE r.actors<=1 AND NOT (r.actors=1 AND r.service_reference)
   UNION ALL SELECT 'model_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.revision,c.deployment_id,c.tenant_id,c.owner_user_id,c.protocol,c.endpoint,c.model)
    FROM public.model_connections c JOIN public.users u ON u.id=c.owner_user_id
    JOIN public.model_connection_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id
     AND s.deployment_id=c.deployment_id AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id
    WHERE c.deployment_id=$1::text AND c.tenant_id=$2::text
   UNION ALL SELECT 'sdk_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.revision,c.deployment_id,c.tenant_id,c.owner_user_id,c.issuer,c.client_id,c.account_id,c.organization_id)
    FROM public.sdk_gateway_connections c JOIN public.users u ON u.id=c.owner_user_id
    WHERE c.deployment_id=$1::text AND c.tenant_id=$2::text AND
     (c.current_secret_id IS NULL OR EXISTS(SELECT 1 FROM public.sdk_gateway_secrets s
      WHERE s.id=c.current_secret_id AND s.connection_id=c.id AND s.deployment_id=c.deployment_id
       AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id AND s.credential_generation=c.credential_generation))
   UNION ALL SELECT 'sso_provider',s.id,NULL::timestamptz,NULL::bigint,
    CASE WHEN s.user_id IS NULL THEN 'service' ELSE 'actor' END,coalesce(s.user_id,$1::text),u.created_at,
    pg_catalog.jsonb_build_array(s.id,s.provider_id,s.issuer,s.organization_id,s.domain,s.user_id)
    FROM public.sso_providers s LEFT JOIN public.users u ON u.id=s.user_id
  )
 , selected AS (
 SELECT * FROM inventory WHERE (kind='subject')=$6
 AND ($3::text IS NULL OR (kind COLLATE "C",ref COLLATE "C")>($3 COLLATE "C",$4 COLLATE "C"))
 ORDER BY kind COLLATE "C",ref COLLATE "C" LIMIT $5
 )
 INSERT INTO openbot_internal.restore_reconfirm_requirements
 (operation_id,epoch,requirement_id,requirement_seq,source_kind,source_ref,binding_generation,
 source_created_at,source_revision,public_binding,owner_kind,owner_id,owner_created_at)
 SELECT $7,$8,pg_catalog.gen_random_uuid(),$9+row_number() OVER(ORDER BY kind COLLATE "C",ref COLLATE "C"),
 kind,ref,0,birth,revision,pg_catalog.sha256(pg_catalog.convert_to('wrokbot.restore.public-binding.v1'||chr(10)||
 pg_catalog.jsonb_build_array(kind,public_fields)::text,'UTF8')),owner_kind,owner_id,owner_birth
 FROM selected ORDER BY kind COLLATE "C",ref COLLATE "C"
 RETURNING source_kind,source_ref,requirement_seq"#;

    // Fixed retirement queries return at most four bounded public identity
    // fields. Driver-private buffers are not claimed as owned Rust allocations.
    const PUBLIC_ROW_MEMORY: u64 =
        4 * 512 + 8 * std::mem::size_of::<String>() as u64 + 2 * std::mem::size_of::<Row>() as u64;

    type QueryResult = Result<Result<Vec<Row>, tokio_postgres::Error>, Elapsed>;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum StageResult {
        Unstarted,
        InFlight,
        Acknowledged,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RetirementAction {
        Users,
        Sessions,
        Approvals,
        Decisions,
        Leases,
        Capabilities,
        Verifications,
        Callbacks,
        Interrupts,
    }

    impl RetirementAction {
        fn name(self) -> &'static str {
            match self {
                Self::Users => "auth_generation",
                Self::Sessions => "sessions_retired",
                Self::Approvals => "approvals_cancelled",
                Self::Decisions => "human_decisions_cancelled",
                Self::Leases => "leases_expired",
                Self::Capabilities => "capabilities_aborted",
                Self::Verifications => "oauth_states_retired",
                Self::Callbacks => "callback_registrations_retired",
                Self::Interrupts => "remote_interrupts_expired",
            }
        }

        fn mutation(self) -> &'static str {
            match self {
                Self::Users => {
                    r#"WITH selected AS (
 SELECT id FROM public.users WHERE $2::text IS NULL OR id COLLATE "C">$2 COLLATE "C"
 ORDER BY id COLLATE "C" LIMIT $1 FOR UPDATE
), changed AS (
 UPDATE public.users u SET auth_generation=coalesce(u.auth_generation,0)+1,updated_at=clock_timestamp()
 FROM selected s WHERE u.id=s.id RETURNING u.id
)
SELECT CASE WHEN octet_length(id)<=512 THEN id END AS id,0::bigint AS pk_seq,
 CASE WHEN octet_length(id)<=512 THEN id END AS actor,NULL::text AS target,
 octet_length(id)<=512 AS valid FROM changed ORDER BY id COLLATE "C""#
                }
                Self::Sessions => {
                    r#"WITH selected AS (
 SELECT id FROM public.sessions WHERE $2::text IS NULL OR id COLLATE "C">$2 COLLATE "C"
 ORDER BY id COLLATE "C" LIMIT $1 FOR UPDATE
), changed AS (
 DELETE FROM public.sessions u USING selected s WHERE u.id=s.id RETURNING u.id
)
SELECT CASE WHEN octet_length(id)<=512 THEN id END AS id,0::bigint AS pk_seq,
 NULL::text AS actor,NULL::text AS target,octet_length(id)<=512 AS valid
 FROM changed ORDER BY id COLLATE "C""#
                }
                Self::Approvals => {
                    r#"WITH selected AS (
 SELECT approval_id FROM public.tool_approvals WHERE state='pending'
 AND ($2::text IS NULL OR approval_id COLLATE "C">$2 COLLATE "C")
 ORDER BY approval_id COLLATE "C" LIMIT $1 FOR UPDATE
), changed AS (
 UPDATE public.tool_approvals a SET state='cancelled',decided_at=clock_timestamp(),decided_by=NULL,
 arguments_summary=NULL,change_summary=NULL,updated_at=clock_timestamp()
 FROM selected s WHERE a.approval_id=s.approval_id RETURNING a.approval_id,a.actor_id
)
SELECT CASE WHEN octet_length(approval_id)<=512 THEN approval_id END AS id,0::bigint AS pk_seq,
 CASE WHEN octet_length(actor_id)<=512 THEN actor_id END AS actor,NULL::text AS target,
 octet_length(approval_id)<=512 AND octet_length(actor_id)<=512 AS valid
 FROM changed ORDER BY approval_id COLLATE "C""#
                }
                Self::Decisions => {
                    r#"WITH selected AS (
 SELECT decision_id FROM public.component_human_decisions WHERE state='pending'
 AND ($2::text IS NULL OR decision_id COLLATE "C">$2 COLLATE "C")
 ORDER BY decision_id COLLATE "C" LIMIT $1 FOR UPDATE
), changed AS (
 UPDATE public.component_human_decisions d SET state='cancelled',answer=NULL,resolved_at=clock_timestamp(),
 resolved_by=NULL,updated_at=clock_timestamp() FROM selected s WHERE d.decision_id=s.decision_id
 RETURNING d.decision_id,d.actor_id,d.component_name
)
SELECT CASE WHEN octet_length(decision_id)<=512 THEN decision_id END AS id,0::bigint AS pk_seq,
 CASE WHEN octet_length(actor_id)<=512 THEN actor_id END AS actor,component_name AS target,
 octet_length(decision_id)<=512 AND octet_length(actor_id)<=512 AS valid
 FROM changed ORDER BY decision_id COLLATE "C""#
                }
                Self::Leases => {
                    r#"WITH selected AS (
 SELECT thread_id FROM public.thread_leases WHERE expires_at>clock_timestamp()
 AND ($2::text IS NULL OR thread_id COLLATE "C">$2 COLLATE "C")
 ORDER BY thread_id COLLATE "C" LIMIT $1 FOR UPDATE
), changed AS (
 UPDATE public.thread_leases l SET expires_at=greatest(clock_timestamp(),l.acquired_at+interval '1 microsecond'),
 updated_at=greatest(clock_timestamp(),l.acquired_at)
 FROM selected s WHERE l.thread_id=s.thread_id RETURNING l.thread_id
)
SELECT CASE WHEN octet_length(thread_id)<=512 THEN thread_id END AS id,0::bigint AS pk_seq,
 NULL::text AS actor,NULL::text AS target,octet_length(thread_id)<=512 AS valid
 FROM changed ORDER BY thread_id COLLATE "C""#
                }
                Self::Capabilities => {
                    r#"WITH selected AS (
 SELECT a.tool_call_id,a.attempt_seq FROM public.tool_attempts a
 WHERE a.status='executing' AND a.capability_id IS NOT NULL
 AND ($2::text IS NULL OR (a.tool_call_id COLLATE "C",a.attempt_seq)>($2 COLLATE "C",$3))
 ORDER BY a.tool_call_id COLLATE "C",a.attempt_seq LIMIT $1 FOR UPDATE OF a
), changed AS (
 UPDATE public.tool_attempts a SET status='aborted',finished_at=greatest(clock_timestamp(),a.started_at)
 FROM selected s,public.tool_calls c
 WHERE a.tool_call_id=s.tool_call_id AND a.attempt_seq=s.attempt_seq AND c.tool_call_id=a.tool_call_id
 RETURNING a.tool_call_id,a.attempt_seq,c.actor_id
)
SELECT CASE WHEN octet_length(tool_call_id)<=512 THEN tool_call_id END AS id,attempt_seq AS pk_seq,
 CASE WHEN octet_length(actor_id)<=512 THEN actor_id END AS actor,NULL::text AS target,
 octet_length(tool_call_id)<=512 AND octet_length(actor_id)<=512 AS valid
 FROM changed ORDER BY tool_call_id COLLATE "C",attempt_seq"#
                }
                Self::Verifications => {
                    r#"WITH selected AS (
 SELECT id FROM public.verifications WHERE $2::text IS NULL OR id COLLATE "C">$2 COLLATE "C"
 ORDER BY id COLLATE "C" LIMIT $1 FOR UPDATE
), changed AS (
 DELETE FROM public.verifications v USING selected s WHERE v.id=s.id RETURNING v.id
)
SELECT CASE WHEN octet_length(id)<=512 THEN id END AS id,0::bigint AS pk_seq,
 NULL::text AS actor,NULL::text AS target,octet_length(id)<=512 AS valid
 FROM changed ORDER BY id COLLATE "C""#
                }
                Self::Callbacks => {
                    r#"WITH selected AS (
 SELECT agent_id FROM public.agent_profiles
 WHERE (callback_token_hash IS NOT NULL OR callback_token_issued_at IS NOT NULL)
 AND ($2::text IS NULL OR agent_id COLLATE "C">$2 COLLATE "C")
 ORDER BY agent_id COLLATE "C" LIMIT $1 FOR UPDATE
), changed AS (
 UPDATE public.agent_profiles a SET callback_token_hash=NULL,callback_token_issued_at=NULL,
 updated_at=clock_timestamp() FROM selected s WHERE a.agent_id=s.agent_id
 RETURNING a.agent_id,a.owner_user_id
)
SELECT CASE WHEN octet_length(agent_id)<=512 THEN agent_id END AS id,0::bigint AS pk_seq,
 CASE WHEN octet_length(owner_user_id)<=512 THEN owner_user_id END AS actor,NULL::text AS target,
 octet_length(agent_id)<=512 AND (owner_user_id IS NULL OR octet_length(owner_user_id)<=512) AS valid
 FROM changed ORDER BY agent_id COLLATE "C""#
                }
                Self::Interrupts => {
                    r#"WITH selected AS (
 SELECT request_id FROM public.remote_agent_interrupts WHERE state='pending'
 AND ($2::text IS NULL OR request_id COLLATE "C">$2 COLLATE "C")
 ORDER BY request_id COLLATE "C" LIMIT $1 FOR UPDATE
), changed AS (
 UPDATE public.remote_agent_interrupts r SET state='expired',response_status='cancelled',response_payload=NULL,
 resolved_at=clock_timestamp(),resolved_by=NULL,updated_at=clock_timestamp()
 FROM selected s WHERE r.request_id=s.request_id RETURNING r.request_id,r.actor_id,r.run_id
)
SELECT CASE WHEN octet_length(request_id)<=512 THEN request_id END AS id,0::bigint AS pk_seq,
 CASE WHEN octet_length(actor_id)<=512 THEN actor_id END AS actor,
 CASE WHEN octet_length(run_id)<=512 THEN run_id END AS target,
 octet_length(request_id)<=512 AND octet_length(actor_id)<=512 AND octet_length(run_id)<=512 AS valid
 FROM changed ORDER BY request_id COLLATE "C""#
                }
            }
        }

        fn residual(self) -> &'static str {
            match self {
                Self::Users => {
                    "SELECT count(*) FROM public.users WHERE auth_generation IS NULL OR auth_generation<1"
                }
                Self::Sessions => "SELECT count(*) FROM public.sessions",
                Self::Approvals => {
                    "SELECT count(*) FROM public.tool_approvals WHERE state='pending'"
                }
                Self::Decisions => {
                    "SELECT count(*) FROM public.component_human_decisions WHERE state='pending'"
                }
                Self::Leases => {
                    "SELECT count(*) FROM public.thread_leases WHERE expires_at>clock_timestamp()"
                }
                Self::Capabilities => {
                    "SELECT count(*) FROM public.tool_attempts WHERE status='executing' AND capability_id IS NOT NULL"
                }
                Self::Verifications => "SELECT count(*) FROM public.verifications",
                Self::Callbacks => {
                    "SELECT count(*) FROM public.agent_profiles WHERE callback_token_hash IS NOT NULL OR callback_token_issued_at IS NOT NULL"
                }
                Self::Interrupts => {
                    "SELECT count(*) FROM public.remote_agent_interrupts WHERE state='pending'"
                }
            }
        }
    }

    struct AuditResults {
        coordinates:
            Option<Result<Result<(AuditEventId, time::OffsetDateTime), InfraError>, Elapsed>>,
        appended: Option<Result<Result<StoredAuditRow, InfraError>, Elapsed>>,
    }

    struct SqlResults {
        begin: Option<Result<(), TransactionOwnerError>>,
        query: Option<QueryResult>,
        command: Option<Result<Result<u64, tokio_postgres::Error>, Elapsed>>,
        unit: Option<Result<Result<(), tokio_postgres::Error>, Elapsed>>,
        validation: Option<Result<Result<(), InfraError>, Elapsed>>,
        catalog: Option<Result<Result<(u64, u64), CaptureSqlFailure>, Elapsed>>,
        commit: Option<Result<(), TransactionOwnerError>>,
        rollback: Option<Result<(), TransactionOwnerError>>,
        audit: AuditResults,
        readback: Option<QueryResult>,
        history: Option<Result<crate::thread_history_authority::RestoredHistoryBatch, crate::thread_history_authority::ThreadHistoryStopClearError>>,
        history_control: Option<Result<Result<Row, tokio_postgres::Error>, Elapsed>>,
        history_keys: Option<Result<Result<(), tokio_postgres::Error>, Elapsed>>,
    }

    /// Only raw results and progress of this candidate's original SQL work.
    /// Empty state cannot construct a candidate, acknowledge SQL or resume it.
    pub(super) struct CandidateSqlState {
        schema: StageResult,
        retirement: StageResult,
        client: Option<Result<GuardedClient, PoolError>>,
        intent: Option<RestoreStageIntent>,
        raw: SqlResults,
        pending_batch: Option<(i64, &'static str)>,
        readback_rows: Option<crate::recovery_control::RestoreCapacityReservation>,
        history: StageResult,
        history_thread: Option<String>,
        history_operation: Option<String>,
        history_cursor: String,
    }

    impl CandidateSqlState {
        pub(super) fn new() -> Self {
            Self {
                schema: StageResult::Unstarted,
                retirement: StageResult::Unstarted,
                client: None,
                intent: None,
                pending_batch: None,
                readback_rows: None,
                history: StageResult::Unstarted,
                history_thread: None,
                history_operation: None,
                history_cursor: String::new(),
                raw: SqlResults {
                    begin: None,
                    query: None,
                    command: None,
                    unit: None,
                    validation: None,
                    catalog: None,
                    commit: None,
                    rollback: None,
                    audit: AuditResults {
                        coordinates: None,
                        appended: None,
                    },
                    readback: None,
                    history: None,
                    history_control: None,
                    history_keys: None,
                },
            }
        }
    }

    fn database_unknown() -> RecoveryControlError {
        RecoveryControlError::new(RecoveryControlFault::DatabaseUnknown)
    }

    fn invalid_candidate() -> RecoveryControlError {
        RecoveryControlError::new(RecoveryControlFault::InputInvalid)
    }

    fn retain_begin_failure(
        stages: &mut RestoreStages,
        intent: &mut Option<RestoreStageIntent>,
        error: TransactionOwnerError,
    ) -> RecoveryControlError {
        let fault = match error {
            TransactionOwnerError::BeginUnavailable => RecoveryControlFault::DatabaseUnknown,
            TransactionOwnerError::DeadlineExceeded => RecoveryControlFault::EffectExpired,
            _ => RecoveryControlFault::ControlInvalid,
        };
        let original = stages.failure(fault);
        if let Ok(closing) = stages.convergence_deadline() {
            if let Some(intent) = intent.take() {
                let _observed = stages.observe_stage_before(
                    intent,
                    RestoreDisposition::PgRollback(RestoreRollbackAck::RollbackUnproven),
                    closing,
                );
            }
        }
        original
    }

    fn sql_observation_error<T>(
        raw: Option<&Result<Result<T, tokio_postgres::Error>, Elapsed>>,
    ) -> RecoveryControlError {
        let fault = match raw {
            Some(Err(_)) => RecoveryControlFault::EffectExpired,
            Some(Ok(Err(error))) => match error.as_db_error() {
                None => RecoveryControlFault::DatabaseUnknown,
                Some(error) if matches!(error.code().code(), "55000" | "22003") => {
                    RecoveryControlFault::InputInvalid
                }
                Some(_) => RecoveryControlFault::IoFailure,
            },
            _ => RecoveryControlFault::ControlInvalid,
        };
        RecoveryControlError::new(fault)
    }

    fn infra_observation_error<T>(
        raw: Option<&Result<Result<T, InfraError>, Elapsed>>,
    ) -> RecoveryControlError {
        let fault = match raw {
            Some(Err(_)) => RecoveryControlFault::EffectExpired,
            Some(Ok(Err(InfraError::Connect { .. }))) => RecoveryControlFault::IoFailure,
            Some(Ok(Err(error @ InfraError::Query { .. }))) => {
                if error.sqlstate().is_none() {
                    RecoveryControlFault::DatabaseUnknown
                } else {
                    RecoveryControlFault::IoFailure
                }
            }
            Some(Ok(Err(_))) => RecoveryControlFault::InputInvalid,
            _ => RecoveryControlFault::ControlInvalid,
        };
        RecoveryControlError::new(fault)
    }

    fn catalog_observation_error(
        raw: Option<&Result<Result<(u64, u64), CaptureSqlFailure>, Elapsed>>,
    ) -> RecoveryControlError {
        let fault = match raw {
            Some(Err(_)) | Some(Ok(Err(CaptureSqlFailure::Clock))) => {
                RecoveryControlFault::EffectExpired
            }
            Some(Ok(Err(CaptureSqlFailure::Bounds))) => RecoveryControlFault::CapacityExceeded,
            Some(Ok(Err(
                CaptureSqlFailure::RowInvalid
                | CaptureSqlFailure::UnknownLayout
                | CaptureSqlFailure::SourceMismatch,
            ))) => RecoveryControlFault::InputInvalid,
            Some(Ok(Err(CaptureSqlFailure::Database))) => RecoveryControlFault::IoFailure,
            Some(Ok(Err(
                CaptureSqlFailure::CommitUnknown | CaptureSqlFailure::RollbackUnknown,
            ))) => RecoveryControlFault::DatabaseUnknown,
            _ => RecoveryControlFault::ControlInvalid,
        };
        RecoveryControlError::new(fault)
    }

    // A completed guarded lease can be returned to this exact original pool.
    // An unresolved lease remains resident and cannot authorize another batch.
    async fn checkout_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let deadline = stages.effect_before(deadline)?;
        if candidate.sql.client.is_some() {
            if !matches!(candidate.sql.raw.commit, Some(Ok(())))
                && !matches!(candidate.sql.raw.rollback, Some(Ok(())))
            {
                return Err(stages.failure(RecoveryControlFault::DatabaseUnknown));
            }
            candidate.sql.client.take();
        }
        candidate.sql.raw.begin = None;
        candidate.sql.raw.commit = None;
        candidate.sql.raw.rollback = None;
        if let Some(original) = candidate.original_client.take() {
            candidate.sql.client = Some(Ok(original));
        } else {
            let reservation = stages.admit_capacity(Capacity::PgConnections, 1)?;
            candidate.sql.client = Some(candidate.pool.get_guarded(deadline).await);
            stages.effect_before(deadline)?;
            if let Some(Err(error)) = candidate.sql.client.as_ref() {
                return Err(stages.failure(if *error == PoolError::DeadlineExceeded {
                    RecoveryControlFault::EffectExpired
                } else {
                    RecoveryControlFault::IoFailure
                }));
            }
            stages.settle_capacity(reservation, 1)?;
        }
        stages.effect_before(deadline)?;
        // Reserve one original readback before E. C cannot open a fresh
        // row/allocation allowance after an unknown ACK.
        candidate.sql.readback_rows = Some(stages.admit_capacity(Capacity::PgRows, 1)?);
        let _metadata = stages.admit_capacity(Capacity::MetadataBytes, PUBLIC_ROW_MEMORY)?;
        let _allocation =
            stages.admit_capacity(Capacity::TotalAllocationBytes, PUBLIC_ROW_MEMORY)?;
        candidate.sql.raw.readback = None;
        Ok(())
    }

    async fn rows<'a>(
        raw: &'a mut SqlResults,
        stages: &mut RestoreStages,
        transaction: &Transaction<'_>,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
        maximum: u64,
        deadline: Instant,
    ) -> Result<&'a [Row], RecoveryControlError> {
        let deadline = stages.effect_before(deadline)?;
        let row_reservation = stages.admit_capacity(Capacity::PgRows, maximum)?;
        let memory = maximum
            .checked_mul(PUBLIC_ROW_MEMORY)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        // Reserve the owned result before the query can allocate it. Keep the
        // conservative backing charge after decoding; an error is not a refund.
        let _metadata = stages.admit_capacity(Capacity::MetadataBytes, memory)?;
        let _allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, memory)?;
        raw.query = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                transaction.query(statement, parameters),
            )
            .await,
        );
        stages.effect_before(deadline)?;
        let observed = raw
            .query
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| sql_observation_error(raw.query.as_ref()))?;
        let count = u64::try_from(observed.len()).map_err(|_| invalid_candidate())?;
        stages.settle_capacity(row_reservation, count)?;
        Ok(observed)
    }

    async fn execute(
        raw: &mut SqlResults,
        stages: &mut RestoreStages,
        transaction: &Transaction<'_>,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
        deadline: Instant,
    ) -> Result<u64, RecoveryControlError> {
        let deadline = stages.effect_before(deadline)?;
        raw.command = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                transaction.execute(statement, parameters),
            )
            .await,
        );
        stages.effect_before(deadline)?;
        raw.command
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .and_then(|r| r.as_ref().ok())
            .copied()
            .ok_or_else(|| sql_observation_error(raw.command.as_ref()))
    }

    // COMMIT has its own original GuardedRC timeout. An outer timeout must not
    // turn a real late ACK into an invented CommitUnknown or cancel its owner.
    async fn finish(
        owner: GuardedTransaction<'_>,
        prepared: Result<(), RecoveryControlError>,
        raw: &mut SqlResults,
        intent: &mut Option<RestoreStageIntent>,
        stages: &mut RestoreStages,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let closing = stages.convergence_deadline()?;
        let result = match prepared {
            Ok(()) => {
                raw.commit = Some(owner.commit_before(deadline).await);
                let first = match raw
                    .commit
                    .as_ref()
                    .expect("resident original COMMIT result")
                {
                    Ok(()) => None,
                    Err(TransactionOwnerError::CommitUnknown) => {
                        Some(RecoveryControlFault::DatabaseUnknown)
                    }
                    Err(
                        TransactionOwnerError::CommitAcknowledgedAfterDeadline
                        | TransactionOwnerError::DeadlineExceeded,
                    ) => Some(RecoveryControlFault::EffectExpired),
                    Err(_) => Some(RecoveryControlFault::ControlInvalid),
                };
                if let Some(fault) = first {
                    let _original = stages.failure(fault);
                }
                let disposition = match raw
                    .commit
                    .as_ref()
                    .expect("resident original COMMIT result")
                {
                    Ok(()) => RestoreDisposition::PgCommit(RestoreCommitAck::TimelyAck),
                    Err(TransactionOwnerError::CommitAcknowledgedAfterDeadline) => {
                        RestoreDisposition::PgCommit(RestoreCommitAck::AcknowledgedAfterDeadline)
                    }
                    Err(TransactionOwnerError::DeadlineExceeded) => {
                        RestoreDisposition::PgRollback(RestoreRollbackAck::RollbackUnproven)
                    }
                    Err(TransactionOwnerError::CommitUnknown) => {
                        RestoreDisposition::PgCommit(RestoreCommitAck::CommitUnknown)
                    }
                    Err(_) => RestoreDisposition::PgRollback(RestoreRollbackAck::RollbackUnproven),
                };
                let post = stages.effect_before(deadline);
                let observation = match intent.take() {
                    Some(intent) => stages.observe_stage_before(intent, disposition, closing),
                    None => Ok(()), // A repeated read-only observation appends no stage.
                };
                match raw
                    .commit
                    .as_ref()
                    .expect("resident original COMMIT result")
                {
                    Ok(()) => post
                        .and(observation)
                        .and_then(|()| stages.check_capacity_before(closing)),
                    Err(
                        TransactionOwnerError::CommitAcknowledgedAfterDeadline
                        | TransactionOwnerError::DeadlineExceeded,
                    ) => Err(RecoveryControlError::new(
                        RecoveryControlFault::EffectExpired,
                    )),
                    Err(TransactionOwnerError::CommitUnknown) => Err(database_unknown()),
                    Err(_) => Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    )),
                }
            }
            Err(error) => {
                let _original = stages.failure(error.fault());
                raw.rollback = Some(owner.rollback_before(deadline).await);
                let disposition = match raw
                    .rollback
                    .as_ref()
                    .expect("resident original ROLLBACK result")
                {
                    Ok(()) => RestoreRollbackAck::TimelyAck,
                    Err(TransactionOwnerError::RollbackAcknowledgedAfterDeadline) => {
                        RestoreRollbackAck::AcknowledgedAfterDeadline
                    }
                    Err(_) => RestoreRollbackAck::RollbackUnproven,
                };
                if let Some(intent) = intent.take() {
                    let _observation = stages.observe_stage_before(
                        intent,
                        RestoreDisposition::PgRollback(disposition),
                        closing,
                    );
                }
                Err(error)
            }
        };
        result.map_err(|error| stages.failure(error.fault()))
    }

    async fn verify_layout(
        raw: &mut SqlResults,
        stages: &mut RestoreStages,
        transaction: &Transaction<'_>,
        binding: &RestoreCandidateBinding,
        version: u32,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let count = match version {
            52 => 40_i64,
            53 => 41_i64,
            54 => 42_i64,
            _ => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::InputInvalid,
                ));
            }
        };
        // Bound the original ledger fields before its registered validator
        // allocates them. No ledger row or missing schema is repaired here.
        let result = rows(raw, stages, transaction,
            "SELECT count(*)=$1 AND coalesce(bool_and(octet_length(name)<=512 AND octet_length(checksum)=64),false) FROM openbot_internal.schema_migrations",
            &[&count], 1, deadline).await?;
        if !result[0]
            .try_get::<_, bool>(0)
            .map_err(|_| invalid_candidate())?
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::InputInvalid,
            ));
        }
        let (_, t0, effect, _) = stages.original_native_clock()?;
        let maximum_rows = stages.capacity_available(Capacity::PgRows)?;
        let maximum_memory = stages
            .capacity_available(Capacity::MetadataBytes)?
            .min(stages.capacity_available(Capacity::TotalAllocationBytes)?);
        let reserved_rows = stages.admit_capacity(Capacity::PgRows, maximum_rows)?;
        let reserved_metadata = stages.admit_capacity(Capacity::MetadataBytes, maximum_memory)?;
        let reserved_allocation =
            stages.admit_capacity(Capacity::TotalAllocationBytes, maximum_memory)?;
        let mut budget = CaptureSqlBudget::new(
            CaptureSqlLimits {
                max_rows: maximum_rows,
                max_row_bytes: maximum_memory,
                max_field_bytes: maximum_memory,
                max_pages: maximum_rows,
                page_rows: BATCH_ROWS.min(maximum_rows),
                max_catalog_objects: maximum_rows,
                max_query_tasks: maximum_rows,
                phase_ns: effect.checked_sub(t0).ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::ControlInvalid)
                })?,
            },
            maximum_memory,
            t0,
        )
        .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        raw.catalog = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(stages.effect_before(deadline)?),
                verify_restore_catalog_in_transaction(
                    transaction,
                    version,
                    [
                        &binding.deployment_id,
                        &binding.tenant_id,
                        &binding.dataset_id,
                    ],
                    &mut budget,
                    &*stages,
                ),
            )
            .await,
        );
        stages.effect_before(deadline)?;
        let (used_rows, used_memory) = raw
            .catalog
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .and_then(|r| r.as_ref().ok())
            .copied()
            .ok_or_else(|| catalog_observation_error(raw.catalog.as_ref()))?;
        stages.settle_capacity(reserved_rows, used_rows)?;
        stages.settle_capacity(reserved_metadata, used_memory)?;
        stages.settle_capacity(reserved_allocation, used_memory)?;
        raw.validation = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(stages.effect_before(deadline)?),
                native::validate_custom_model_v2_layout_in_transaction(
                    transaction,
                    version as i32,
                    count as usize,
                ),
            )
            .await,
        );
        stages.effect_before(deadline)?;
        raw.validation
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| infra_observation_error(raw.validation.as_ref()))?;
        Ok(())
    }

    pub(crate) async fn upgrade_candidate_schema_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        // An interrupted invocation may observe its original rows but never
        // issues its migration again or upgrades a lost ACK to timely success.
        if candidate.sql.schema == StageResult::InFlight {
            return observe_unresolved_before(stages, candidate).await;
        }
        let repeated = candidate.sql.schema == StageResult::Acknowledged;
        let version = if repeated {
            54
        } else {
            candidate.binding.native_version
        };
        candidate.sql.schema = StageResult::InFlight;
        if !repeated {
            candidate.sql.intent =
                Some(stages.begin_stage_before(RestoreStage::PgUpgrade, "pg_upgrade", deadline)?);
        }
        checkout_before(stages, candidate, deadline).await?;
        let reservation = stages.admit_capacity(Capacity::PgTransactions, 1)?;
        let CandidateSqlState {
            client,
            raw,
            intent,
            ..
        } = &mut candidate.sql;
        let client = client
            .as_mut()
            .and_then(|r| r.as_mut().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        let owner = match if version == 54 {
            client.begin_read_committed_read_only().await
        } else {
            client.begin_read_committed().await
        } {
            Ok(owner) => {
                raw.begin = Some(Ok(()));
                owner
            }
            Err(error) => {
                raw.begin = Some(Err(error));
                return Err(retain_begin_failure(stages, intent, error));
            }
        };
        let prepared = async {
            stages.effect_before(deadline)?;
            stages.settle_capacity(reservation, 1)?;
            let transaction = owner.as_transaction();
            raw.validation = Some(tokio::time::timeout_at(
                tokio::time::Instant::from_std(stages.effect_before(deadline)?),
                native::lock_migrations(transaction),
            ).await);
            stages.effect_before(deadline)?;
            raw.validation.as_ref().and_then(|r| r.as_ref().ok())
                .and_then(|r| r.as_ref().ok()).ok_or_else(|| infra_observation_error(raw.validation.as_ref()))?;
            verify_layout(raw, stages, transaction, &candidate.binding, version, deadline).await?;
            // A strict prior source (52 or 53) upgrades through every registered increment up to
            // the current layout; a current source only observes.
            let pending: &[(i32, &str, &str, fn() -> String)] = match version {
                52 => &[
                    (native::NATIVE_0053_VERSION, native::NATIVE_0053_NAME, native::NATIVE_0053_SQL, native::native_0053_checksum),
                    (native::NATIVE_0054_VERSION, native::NATIVE_0054_NAME, native::NATIVE_0054_SQL, native::native_0054_checksum),
                ],
                53 => &[
                    (native::NATIVE_0054_VERSION, native::NATIVE_0054_NAME, native::NATIVE_0054_SQL, native::native_0054_checksum),
                ],
                _ => &[],
            };
            for (next, name, sql, checksum) in pending {
                raw.unit = Some(tokio::time::timeout_at(
                    tokio::time::Instant::from_std(stages.effect_before(deadline)?),
                    transaction.batch_execute(sql),
                ).await);
                stages.effect_before(deadline)?;
                raw.unit.as_ref().and_then(|r| r.as_ref().ok())
                    .and_then(|r| r.as_ref().ok()).ok_or_else(|| sql_observation_error(raw.unit.as_ref()))?;
                execute(raw, stages, transaction,
                    "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
                    &[next, name, &checksum()],
                    deadline).await?;
                verify_layout(raw, stages, transaction, &candidate.binding, u32::try_from(*next).map_err(|_| invalid_candidate())?, deadline).await?;
            }
            Ok(())
        }.await;
        finish(owner, prepared, raw, intent, stages, deadline).await?;
        candidate.sql.schema = StageResult::Acknowledged;
        Ok(())
    }

    struct RetirementAudit<'a> {
        actor: Option<&'a str>,
        event_type: AuditEventType,
        target_kind: &'static str,
        target_id: &'a str,
        change: Option<&'static str>,
    }

    async fn append_retirement_audit(
        raw: &mut AuditResults,
        stages: &mut RestoreStages,
        transaction: &Transaction<'_>,
        key: &[u8],
        data: RetirementAudit<'_>,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let bytes = data
            .actor
            .map_or(0, str::len)
            .checked_add(data.target_id.len())
            .and_then(|n| n.checked_add(data.change.map_or(0, str::len)))
            .and_then(|n| n.checked_mul(6))
            .and_then(|n| {
                n.checked_add(
                    2 * std::mem::size_of::<AuditEvent>()
                        + 2 * std::mem::size_of::<StoredAuditRow>()
                        + 1024,
                )
            })
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let _metadata = stages.admit_capacity(Capacity::MetadataBytes, bytes as u64)?;
        let _allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, bytes as u64)?;
        raw.coordinates = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(stages.effect_before(deadline)?),
                next_event_coordinates(transaction),
            )
            .await,
        );
        stages.effect_before(deadline)?;
        let (id, created_at) = raw
            .coordinates
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| infra_observation_error(raw.coordinates.as_ref()))?;
        let payload = match data.change {
            Some(change) => {
                AuditPayload::from_facts([AuditFact::ConfigurationChange(AuditLabel::new(change))])
                    .map_err(|_| invalid_candidate())?
            }
            None => AuditPayload::empty(),
        };
        let event = AuditEvent {
            id: id.clone(),
            actor: data.actor.map(ActorId::new),
            event_type: data.event_type,
            target_kind: AuditLabel::new(data.target_kind),
            target_id: Some(AuditIdentifier::new(data.target_id).map_err(|_| invalid_candidate())?),
            payload,
            created_at: *created_at,
        };
        raw.appended = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(stages.effect_before(deadline)?),
                append_event_in_transaction(transaction, &event, key),
            )
            .await,
        );
        stages.effect_before(deadline)?;
        raw.appended
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| infra_observation_error(raw.appended.as_ref()))?;
        Ok(())
    }

    async fn begin_retirement_stage(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        action: &'static str,
        sequence: i64,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let _metadata = stages.admit_capacity(Capacity::MetadataBytes, 128)?;
        let _allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, 128)?;
        let effect_id = format!("{action}:{sequence}");
        candidate.sql.pending_batch = Some((sequence, action));
        candidate.sql.intent =
            Some(stages.begin_stage_before(RestoreStage::Retire, &effect_id, deadline)?);
        checkout_before(stages, candidate, deadline).await
    }

    async fn register_operation_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        begin_retirement_stage(stages, candidate, "operation", 0, deadline).await?;
        let reservation = stages.admit_capacity(Capacity::PgTransactions, 1)?;
        let CandidateSqlState {
            client,
            raw,
            intent,
            ..
        } = &mut candidate.sql;
        let client = client
            .as_mut()
            .and_then(|r| r.as_mut().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        let owner = match client.begin_read_committed().await {
            Ok(owner) => {
                raw.begin = Some(Ok(()));
                owner
            }
            Err(error) => {
                raw.begin = Some(Err(error));
                return Err(retain_begin_failure(stages, intent, error));
            }
        };
        let prepared = async {
            stages.effect_before(deadline)?;
            stages.settle_capacity(reservation, 1)?;
            let binding = &candidate.binding;
            let max_batches = i64::try_from(binding.max_batches)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
            let max_requirements = i64::try_from(binding.max_requirements)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
            let changed = execute(raw, stages, owner.as_transaction(),
                "INSERT INTO openbot_internal.restore_pg_operations(operation_id,epoch,candidate_generation,source_bundle_id,deployment_id,tenant_id,dataset_id,source_installation_id,target_installation_id,candidate_database_oid,pg_system_identifier,profile_binding,max_batches,max_requirements) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
                &[&binding.operation_id,&binding.epoch.as_slice(),&binding.candidate_generation,&binding.source_bundle_id,
                  &binding.deployment_id,&binding.tenant_id,&binding.dataset_id,&binding.source_installation_id,
                  &binding.target_installation_id,&binding.candidate_database_oid,&binding.pg_system_identifier,
                  &binding.profile_binding.as_slice(),&max_batches,&max_requirements],
                deadline).await?;
            if changed != 1 {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            Ok(())
        }.await;
        finish(owner, prepared, raw, intent, stages, deadline).await
    }

    struct RetiredBatch {
        affected: i64,
        remaining: i64,
        cursor: Option<(String, i64)>,
        sequence: i64,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RequirementGroup {
        Subjects,
        Credentials,
    }

    impl RequirementGroup {
        fn name(self) -> &'static str {
            match self {
                Self::Subjects => "subject_requirements",
                Self::Credentials => "credential_requirements",
            }
        }
    }

    const REQUIREMENT_RESIDUAL_SQL: &str = r#"SELECT count(*) FROM (
 SELECT 'subject' AS kind,id AS ref FROM public.users
 UNION ALL SELECT 'credential',id::text FROM public.credentials
 UNION ALL SELECT 'model_secret',id::text FROM public.model_connections
 UNION ALL SELECT 'sdk_secret',id::text FROM public.sdk_gateway_connections
 UNION ALL SELECT 'sso_provider',id FROM public.sso_providers
) inventory WHERE (kind='subject')=$3 AND NOT EXISTS(
 SELECT 1 FROM openbot_internal.restore_reconfirm_requirements r
 WHERE r.operation_id=$1 AND r.epoch=$2 AND r.source_kind=inventory.kind AND r.source_ref=inventory.ref)"#;

    struct RequirementBatch {
        remaining: i64,
        cursor: Option<(String, String)>,
        sequence: i64,
        high_water: i64,
    }

    async fn retire_batch_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        action: RetirementAction,
        cursor: Option<(&str, i64)>,
        sequence: i64,
        deadline: Instant,
    ) -> Result<RetiredBatch, RecoveryControlError> {
        begin_retirement_stage(stages, candidate, action.name(), sequence, deadline).await?;
        let reservation = stages.admit_capacity(Capacity::PgTransactions, 1)?;
        let CandidateSqlState {
            client,
            raw,
            intent,
            ..
        } = &mut candidate.sql;
        let client = client
            .as_mut()
            .and_then(|r| r.as_mut().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        let owner = match client.begin_read_committed().await {
            Ok(owner) => {
                raw.begin = Some(Ok(()));
                owner
            }
            Err(error) => {
                raw.begin = Some(Err(error));
                return Err(retain_begin_failure(stages, intent, error));
            }
        };
        let mut observation = None;
        let prepared = async {
            stages.effect_before(deadline)?;
            stages.settle_capacity(reservation, 1)?;
            let transaction = owner.as_transaction();
            let limit = BATCH_ROWS as i64;
            let cursor_id = cursor.map(|v| v.0);
            let cursor_sequence = cursor.map_or(0, |v| v.1);
            let params: [&(dyn ToSql + Sync); 3] = [&limit, &cursor_id, &cursor_sequence];
            rows(raw, stages, transaction, action.mutation(),
                if action == RetirementAction::Capabilities { &params } else { &params[..2] },
                BATCH_ROWS, deadline).await?;
            let selected = raw.query.as_ref().and_then(|r| r.as_ref().ok())
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| sql_observation_error(raw.query.as_ref()))?;
            let affected = i64::try_from(selected.len()).map_err(|_| invalid_candidate())?;
            let mut last = None;
            for row in selected {
                if !row.try_get::<_, bool>("valid").map_err(|_| invalid_candidate())? {
                    return Err(invalid_candidate());
                }
                let id: &str = row.try_get("id").map_err(|_| invalid_candidate())?;
                let actor: Option<&str> = row.try_get("actor").map_err(|_| invalid_candidate())?;
                let target: Option<&str> = row.try_get("target").map_err(|_| invalid_candidate())?;
                let pk_sequence: i64 = row.try_get("pk_seq").map_err(|_| invalid_candidate())?;
                let _metadata = stages.admit_capacity(Capacity::MetadataBytes, id.len() as u64)?;
                let _allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, id.len() as u64)?;
                last = Some((id.to_owned(), pk_sequence));
                let audit = match action {
                    RetirementAction::Approvals => Some(RetirementAudit { actor,
                        event_type: AuditEventType::TOOL_APPROVAL_CANCELLED, target_kind: "tool_approval", target_id: id, change: None }),
                    RetirementAction::Decisions => Some(RetirementAudit { actor,
                        event_type: AuditEventType::COMPONENT_HUMAN_CANCELLED, target_kind: "component", target_id: target.ok_or_else(invalid_candidate)?, change: None }),
                    RetirementAction::Callbacks => Some(RetirementAudit { actor,
                        event_type: AuditEventType::parse("bot.callback_token_revoked").expect("registered event"),
                        target_kind: "agent", target_id: id, change: None }),
                    RetirementAction::Interrupts => Some(RetirementAudit { actor,
                        event_type: AuditEventType::AGENT_REMOTE_INTERRUPT_EXPIRED, target_kind: "run", target_id: target.ok_or_else(invalid_candidate)?, change: None }),
                    RetirementAction::Capabilities => Some(RetirementAudit { actor,
                        event_type: AuditEventType::parse("configuration.changed").expect("registered event"),
                        target_kind: "tool_call", target_id: id, change: Some("restore_capability_retired") }),
                    _ => None,
                };
                if let Some(audit) = audit {
                    append_retirement_audit(&mut raw.audit, stages, transaction, candidate.audit_key.expose(), audit, deadline).await?;
                }
            }
            // A later statement sees this transaction's actual mutation.
            // A sibling SELECT in the same modifying CTE sees its old snapshot.
            let residual = rows(raw, stages, transaction, action.residual(), &[], 1, deadline).await?;
            let remaining: i64 = residual[0].try_get(0).map_err(|_| invalid_candidate())?;
            let inserted = rows(raw, stages, transaction,
                "INSERT INTO openbot_internal.restore_pg_batches(operation_id,epoch,batch_seq,action,affected_count,remaining_count) VALUES($1,$2,$3,$4,$5,$6) RETURNING batch_seq",
                &[&candidate.binding.operation_id,&candidate.binding.epoch.as_slice(),&sequence,&action.name(),&affected,&remaining],
                1, deadline).await?;
            let actual_sequence: i64 = inserted[0].try_get(0).map_err(|_| invalid_candidate())?;
            let _metadata = stages.admit_capacity(Capacity::MetadataBytes, 36)?;
            let _allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, 36)?;
            let operation = candidate.binding.operation_id.to_string();
            append_retirement_audit(&mut raw.audit, stages, transaction, candidate.audit_key.expose(),
                RetirementAudit { actor: None, event_type: AuditEventType::parse("configuration.changed").expect("registered event"),
                    target_kind: "restore_operation", target_id: &operation, change: Some(action.name()) },
                deadline).await?;
            observation = Some(RetiredBatch { affected, remaining, cursor: last, sequence: actual_sequence });
            Ok(())
        }.await;
        finish(owner, prepared, raw, intent, stages, deadline).await?;
        observation.ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))
    }

    struct BatchCounts {
        sequence: i64,
        action: &'static str,
        affected: i64,
        remaining: i64,
    }

    async fn record_batch_before(
        raw: &mut SqlResults,
        stages: &mut RestoreStages,
        transaction: &Transaction<'_>,
        binding: &RestoreCandidateBinding,
        key: &[u8],
        counts: BatchCounts,
        deadline: Instant,
    ) -> Result<i64, RecoveryControlError> {
        let inserted = rows(raw, stages, transaction,
            "INSERT INTO openbot_internal.restore_pg_batches(operation_id,epoch,batch_seq,action,affected_count,remaining_count) VALUES($1,$2,$3,$4,$5,$6) RETURNING batch_seq",
            &[&binding.operation_id,&binding.epoch.as_slice(),&counts.sequence,&counts.action,&counts.affected,&counts.remaining],
            1, deadline).await?;
        let sequence: i64 = inserted[0].try_get(0).map_err(|_| invalid_candidate())?;
        let _metadata = stages.admit_capacity(Capacity::MetadataBytes, 36)?;
        let _allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, 36)?;
        let operation = binding.operation_id.to_string();
        append_retirement_audit(
            &mut raw.audit,
            stages,
            transaction,
            key,
            RetirementAudit {
                actor: None,
                event_type: AuditEventType::parse("configuration.changed")
                    .expect("registered event"),
                target_kind: "restore_operation",
                target_id: &operation,
                change: Some(counts.action),
            },
            deadline,
        )
        .await?;
        Ok(sequence)
    }

    async fn requirements_batch_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        group: RequirementGroup,
        cursor: Option<(&str, &str)>,
        sequence: i64,
        high_water: i64,
        deadline: Instant,
    ) -> Result<RequirementBatch, RecoveryControlError> {
        begin_retirement_stage(stages, candidate, group.name(), sequence, deadline).await?;
        let transaction_reservation = stages.admit_capacity(Capacity::PgTransactions, 1)?;
        let page = BATCH_ROWS.min(stages.capacity_available(Capacity::ReconfirmRequirements)?);
        let requirements_reservation =
            stages.admit_capacity(Capacity::ReconfirmRequirements, page)?;
        let CandidateSqlState {
            client,
            raw,
            intent,
            ..
        } = &mut candidate.sql;
        let client = client
            .as_mut()
            .and_then(|r| r.as_mut().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        let owner = match client.begin_read_committed().await {
            Ok(owner) => {
                raw.begin = Some(Ok(()));
                owner
            }
            Err(error) => {
                raw.begin = Some(Err(error));
                return Err(retain_begin_failure(stages, intent, error));
            }
        };
        let mut observation = None;
        let prepared = async {
            stages.effect_before(deadline)?;
            stages.settle_capacity(transaction_reservation, 1)?;
            let transaction = owner.as_transaction();
            let kind_cursor = cursor.map(|v| v.0);
            let ref_cursor = cursor.map(|v| v.1);
            let subjects = group == RequirementGroup::Subjects;
            let limit = page as i64;
            rows(
                raw,
                stages,
                transaction,
                INSERT_REQUIREMENTS_SQL,
                &[
                    &candidate.binding.deployment_id,
                    &candidate.binding.tenant_id,
                    &kind_cursor,
                    &ref_cursor,
                    &limit,
                    &subjects,
                    &candidate.binding.operation_id,
                    &candidate.binding.epoch.as_slice(),
                    &high_water,
                ],
                page,
                deadline,
            )
            .await?;
            let inserted = raw
                .query
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| sql_observation_error(raw.query.as_ref()))?;
            let affected = i64::try_from(inserted.len()).map_err(|_| invalid_candidate())?;
            stages.settle_capacity(requirements_reservation, inserted.len() as u64)?;
            let mut last: Option<(&str, &str)> = None;
            let mut actual_high_water = high_water;
            for row in inserted {
                let kind: &str = row
                    .try_get("source_kind")
                    .map_err(|_| invalid_candidate())?;
                let source: &str = row.try_get("source_ref").map_err(|_| invalid_candidate())?;
                let number: i64 = row
                    .try_get("requirement_seq")
                    .map_err(|_| invalid_candidate())?;
                actual_high_water = actual_high_water.max(number);
                if last.is_none_or(|previous| (kind, source) > previous) {
                    last = Some((kind, source));
                }
            }
            let next = if let Some((kind, source)) = last {
                let size = (kind.len() + source.len()) as u64;
                let _metadata = stages.admit_capacity(Capacity::MetadataBytes, size)?;
                let _allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, size)?;
                Some((kind.to_owned(), source.to_owned()))
            } else {
                None
            };
            let residual = rows(
                raw,
                stages,
                transaction,
                REQUIREMENT_RESIDUAL_SQL,
                &[
                    &candidate.binding.operation_id,
                    &candidate.binding.epoch.as_slice(),
                    &subjects,
                ],
                1,
                deadline,
            )
            .await?;
            let remaining: i64 = residual[0].try_get(0).map_err(|_| invalid_candidate())?;
            if affected == 0 && remaining != 0 {
                return Err(RecoveryControlError::new(if page == 0 {
                    RecoveryControlFault::CapacityExceeded
                } else {
                    RecoveryControlFault::InputInvalid
                }));
            }
            let actual_sequence = record_batch_before(
                raw,
                stages,
                transaction,
                &candidate.binding,
                candidate.audit_key.expose(),
                BatchCounts {
                    sequence,
                    action: group.name(),
                    affected,
                    remaining,
                },
                deadline,
            )
            .await?;
            observation = Some(RequirementBatch {
                remaining,
                cursor: next,
                sequence: actual_sequence,
                high_water: actual_high_water,
            });
            Ok(())
        }
        .await;
        finish(owner, prepared, raw, intent, stages, deadline).await?;
        observation.ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))
    }

    async fn configuration_slots_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        range: std::ops::Range<usize>,
        sequence: i64,
        high_water: i64,
        deadline: Instant,
    ) -> Result<(i64, i64), RecoveryControlError> {
        begin_retirement_stage(
            stages,
            candidate,
            "credential_requirements",
            sequence,
            deadline,
        )
        .await?;
        let transaction_reservation = stages.admit_capacity(Capacity::PgTransactions, 1)?;
        let selected = &candidate.configuration_inventory[range];
        let requirements_reservation =
            stages.admit_capacity(Capacity::ReconfirmRequirements, selected.len() as u64)?;
        let CandidateSqlState {
            client,
            raw,
            intent,
            ..
        } = &mut candidate.sql;
        let client = client
            .as_mut()
            .and_then(|r| r.as_mut().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        let owner = match client.begin_read_committed().await {
            Ok(owner) => {
                raw.begin = Some(Ok(()));
                owner
            }
            Err(error) => {
                raw.begin = Some(Err(error));
                return Err(retain_begin_failure(stages, intent, error));
            }
        };
        let mut observation = None;
        let prepared = async {
            stages.effect_before(deadline)?;
            stages.settle_capacity(transaction_reservation, 1)?;
            let transaction = owner.as_transaction();
            let binding = &candidate.binding;
            let mut number = high_water;
            let mut affected = 0_i64;
            for slot in selected {
                number = number.checked_add(1)
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
                let inserted = rows(raw, stages, transaction,
                    "INSERT INTO openbot_internal.restore_reconfirm_requirements(operation_id,epoch,requirement_id,requirement_seq,source_kind,source_ref,binding_generation,source_created_at,source_revision,public_binding,owner_kind,owner_id,owner_created_at) VALUES($1,$2,pg_catalog.gen_random_uuid(),$3,'config_slot',$4,$5,NULL,NULL,$6,$7,$8,NULL) RETURNING requirement_seq",
                    &[&binding.operation_id,&binding.epoch.as_slice(),&number,&slot.source_ref,
                      &slot.binding_generation,&slot.public_binding.as_slice(),&slot.owner_kind,&slot.owner_id],
                    1, deadline).await?;
                number = inserted[0].try_get(0).map_err(|_| invalid_candidate())?;
                affected += inserted.len() as i64;
            }
            stages.settle_capacity(requirements_reservation, affected as u64)?;
            let residual = rows(raw, stages, transaction, REQUIREMENT_RESIDUAL_SQL,
                &[&binding.operation_id,&binding.epoch.as_slice(),&false], 1, deadline).await?;
            let remaining: i64 = residual[0].try_get(0).map_err(|_| invalid_candidate())?;
            if remaining != 0 { return Err(invalid_candidate()); }
            let actual_sequence = record_batch_before(raw, stages, transaction, binding,
                candidate.audit_key.expose(),
                BatchCounts { sequence, action: "credential_requirements", affected, remaining }, deadline).await?;
            observation = Some((actual_sequence, number));
            Ok(())
        }.await;
        finish(owner, prepared, raw, intent, stages, deadline).await?;
        observation.ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))
    }

    async fn seal_cohort_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        sequence: i64,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        begin_retirement_stage(stages, candidate, "seal", sequence, deadline).await?;
        let reservation = stages.admit_capacity(Capacity::PgTransactions, 1)?;
        let CandidateSqlState {
            client,
            raw,
            intent,
            ..
        } = &mut candidate.sql;
        let client = client
            .as_mut()
            .and_then(|r| r.as_mut().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        let owner = match client.begin_read_committed().await {
            Ok(owner) => {
                raw.begin = Some(Ok(()));
                owner
            }
            Err(error) => {
                raw.begin = Some(Err(error));
                return Err(retain_begin_failure(stages, intent, error));
            }
        };
        let prepared = async {
            stages.effect_before(deadline)?;
            stages.settle_capacity(reservation, 1)?;
            let transaction = owner.as_transaction();
            let binding = &candidate.binding;
            let slots = rows(raw, stages, transaction,
                "SELECT count(*) FROM openbot_internal.restore_reconfirm_requirements r WHERE r.operation_id=$1 AND r.epoch=$2 AND r.source_kind='config_slot' AND NOT EXISTS(SELECT 1 FROM openbot_internal.restore_reconfirm_requirements n WHERE n.operation_id=r.operation_id AND n.epoch=r.epoch AND n.source_kind=r.source_kind AND n.source_ref=r.source_ref AND n.binding_generation>r.binding_generation)",
                &[&binding.operation_id,&binding.epoch.as_slice()], 1, deadline).await?;
            let slot_count: i64 = slots[0].try_get(0).map_err(|_| invalid_candidate())?;
            if usize::try_from(slot_count).ok() != Some(candidate.configuration_inventory.len()) {
                return Err(invalid_candidate());
            }
            // Compare the actual independent external inventory in both
            // directions; a missing input is never replaced with an empty list.
            for slot in &candidate.configuration_inventory {
                let matched = rows(raw, stages, transaction,
                    "SELECT EXISTS(SELECT 1 FROM openbot_internal.restore_reconfirm_requirements r WHERE r.operation_id=$1 AND r.epoch=$2 AND r.source_kind='config_slot' AND r.source_ref=$3 AND r.binding_generation=$4 AND r.public_binding=$5 AND r.owner_kind=$6 AND r.owner_id=$7 AND r.source_created_at IS NULL AND r.source_revision IS NULL AND r.owner_created_at IS NULL AND NOT EXISTS(SELECT 1 FROM openbot_internal.restore_reconfirm_requirements n WHERE n.operation_id=r.operation_id AND n.epoch=r.epoch AND n.source_kind=r.source_kind AND n.source_ref=r.source_ref AND n.binding_generation>r.binding_generation))",
                    &[&binding.operation_id,&binding.epoch.as_slice(),&slot.source_ref,&slot.binding_generation,
                      &slot.public_binding.as_slice(),&slot.owner_kind,&slot.owner_id], 1, deadline).await?;
                if !matched[0].try_get::<_, bool>(0).map_err(|_| invalid_candidate())? {
                    return Err(invalid_candidate());
                }
            }
            let totals = rows(raw, stages, transaction,
                "SELECT (SELECT count(*) FROM openbot_internal.restore_pg_batches WHERE operation_id=$1 AND epoch=$2),count(*) FILTER(WHERE source_kind='subject'),count(*) FILTER(WHERE source_kind<>'subject') FROM openbot_internal.restore_reconfirm_requirements WHERE operation_id=$1 AND epoch=$2",
                &[&binding.operation_id,&binding.epoch.as_slice()], 1, deadline).await?;
            let batches: i64 = totals[0].try_get(0).map_err(|_| invalid_candidate())?;
            let subjects: i64 = totals[0].try_get(1).map_err(|_| invalid_candidate())?;
            let credentials: i64 = totals[0].try_get(2).map_err(|_| invalid_candidate())?;
            let inserted = execute(raw, stages, transaction,
                "INSERT INTO openbot_internal.restore_pg_seals(operation_id,epoch,batches,subject_requirements,credential_requirements) VALUES($1,$2,$3,$4,$5)",
                &[&binding.operation_id,&binding.epoch.as_slice(),&batches,&subjects,&credentials], deadline).await?;
            if inserted != 1 {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            let _metadata = stages.admit_capacity(Capacity::MetadataBytes, 36)?;
            let _allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, 36)?;
            let operation = binding.operation_id.to_string();
            append_retirement_audit(&mut raw.audit, stages, transaction, candidate.audit_key.expose(),
                RetirementAudit { actor: None, event_type: AuditEventType::parse("configuration.changed").expect("registered event"),
                    target_kind: "restore_operation", target_id: &operation, change: Some("restore_pg_sealed") },
                deadline).await?;
            Ok(())
        }.await;
        finish(owner, prepared, raw, intent, stages, deadline).await
    }

    // BEGIN S22 original closed-history adapter
    /// Reuse the original clear algorithm on this candidate's guarded connection.
    /// Only timely original transaction acknowledgements advance the cursor.
    pub(crate) async fn clear_restored_closed_history_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        use crate::thread_history_authority::{RestoredHistoryBatch as Batch, ThreadHistoryStopClearError as ClearError};
        if candidate.sql.retirement != StageResult::Acknowledged {
            return Err(stages.failure(RecoveryControlFault::ClosureUnproven));
        }
        if candidate.sql.history == StageResult::Acknowledged {
            return stages.effect_before(deadline).map(|_| ());
        }
        if candidate.sql.history == StageResult::InFlight {
            // An unknown original batch is observed once using its original Q,
            // never dispatched again or replaced with a new clear operation.
            let closing = stages.convergence_deadline()?;
            let reservation = candidate.sql.readback_rows.take().ok_or_else(database_unknown)?;
            let client = candidate.sql.client.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(database_unknown)?;
            let thread = candidate.sql.history_thread.as_deref().ok_or_else(database_unknown)?;
            let operation = candidate.sql.history_operation.as_deref().ok_or_else(database_unknown)?;
            candidate.sql.raw.readback = Some(tokio::time::timeout_at(
                tokio::time::Instant::from_std(closing),
                client.as_client().query(
                    "SELECT q.operation_id,c.operation_id IS NOT NULL AS completed,(SELECT count(*) FROM openbot_internal.thread_history_clear_batches b WHERE b.operation_id=q.operation_id) AS batches FROM openbot_internal.thread_history_clear_intents q LEFT JOIN openbot_internal.thread_history_clear_completions c ON c.operation_id=q.operation_id WHERE q.operation_id=$1 AND q.thread_id=$2 AND q.deployment_id=$3 AND q.tenant_id=$4",
                    &[&operation,&thread,&candidate.binding.deployment_id,&candidate.binding.tenant_id],
                ),
            ).await);
            stages.convergence_deadline()?;
            if let Some(Ok(Ok(rows))) = &candidate.sql.raw.readback {
                stages.settle_capacity(reservation, rows.len() as u64)?;
            }
            return Err(stages.failure(RecoveryControlFault::DatabaseUnknown));
        }
        loop {
            let deadline = stages.effect_before(deadline)?;
            checkout_before(stages, candidate, deadline).await?;
            let reservation = stages.admit_capacity(Capacity::PgTransactions, 1)?;
            candidate.sql.intent = Some(stages.begin_stage_before(RestoreStage::HqAck2, "closed_history_ack2", deadline)?);
            let CandidateSqlState { client, raw, intent, history_thread, history_operation, history_cursor, history, .. } = &mut candidate.sql;
            let client = client.as_mut().and_then(|v| v.as_mut().ok()).ok_or_else(database_unknown)?;
            let owner = match client.begin_read_committed().await {
                Ok(owner) => { raw.begin = Some(Ok(())); owner }
                Err(error) => {
                    raw.begin = Some(Err(error));
                    return Err(retain_begin_failure(stages, intent, error));
                }
            };
            let prepared = async {
                stages.effect_before(deadline)?;
                stages.settle_capacity(reservation, 1)?;
                const NEXT_HISTORY: &str = "SELECT coalesce(h.thread_id,q.thread_id) AS thread_id,q.operation_id FROM openbot_internal.thread_history_heads h FULL JOIN openbot_internal.thread_history_clear_intents q ON q.operation_id=h.closure_operation_id AND q.thread_id=h.thread_id AND q.deployment_id=h.deployment_id AND q.tenant_id=h.tenant_id WHERE coalesce(h.deployment_id,q.deployment_id)=$1 AND coalesce(h.tenant_id,q.tenant_id)=$2 AND (h.phase='closed' OR q.operation_id IS NOT NULL) AND coalesce(h.thread_id,q.thread_id) COLLATE \"C\">$3 COLLATE \"C\" ORDER BY coalesce(h.thread_id,q.thread_id) COLLATE \"C\" LIMIT 1";
                use std::fmt::Write as _;
                use futures_util::TryStreamExt;
                let measure_size = "SELECT octet_length(thread_id)::bigint,octet_length(operation_id)::bigint FROM () selected".len().checked_add(NEXT_HISTORY.len()).ok_or_else(invalid_candidate)?;
                let measure_metadata = stages.admit_capacity(Capacity::MetadataBytes, measure_size as u64)?;
                let measure_allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, measure_size as u64)?;
                let mut measure = String::with_capacity(measure_size);
                write!(&mut measure, "SELECT octet_length(thread_id)::bigint,octet_length(operation_id)::bigint FROM ({NEXT_HISTORY}) selected").map_err(|_| invalid_candidate())?;
                stages.settle_capacity(measure_metadata, measure.capacity() as u64)?;
                stages.settle_capacity(measure_allocation, measure.capacity() as u64)?;
                let measured = rows(raw, stages, owner.as_transaction(), &measure,
                    &[&candidate.binding.deployment_id,&candidate.binding.tenant_id,&history_cursor.as_str()], 1, deadline).await?;
                let Some(row) = measured.first() else { return Ok(()); };
                let thread_bytes = row.try_get::<_, i64>(0).map_err(|_| invalid_candidate())?;
                let operation_bytes = row.try_get::<_, i64>(1).map_err(|_| invalid_candidate())?;
                let total = usize::try_from(thread_bytes).ok().and_then(|a| usize::try_from(operation_bytes).ok().and_then(|b| a.checked_add(b))).ok_or_else(invalid_candidate)?;
                let actual_sql_size = "SELECT CASE WHEN octet_length(thread_id)<=$4::bigint THEN thread_id END AS thread_id,CASE WHEN octet_length(operation_id)<=$5::bigint THEN operation_id END AS operation_id FROM () selected".len().checked_add(NEXT_HISTORY.len()).ok_or_else(invalid_candidate)?;
                let sql_metadata = stages.admit_capacity(Capacity::MetadataBytes, actual_sql_size as u64)?;
                let sql_allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, actual_sql_size as u64)?;
                let mut actual_sql = String::with_capacity(actual_sql_size);
                write!(&mut actual_sql, "SELECT CASE WHEN octet_length(thread_id)<=$4::bigint THEN thread_id END AS thread_id,CASE WHEN octet_length(operation_id)<=$5::bigint THEN operation_id END AS operation_id FROM ({NEXT_HISTORY}) selected").map_err(|_| invalid_candidate())?;
                stages.settle_capacity(sql_metadata, actual_sql.capacity() as u64)?;
                stages.settle_capacity(sql_allocation, actual_sql.capacity() as u64)?;
                // One preallocated Row vector, two range slots, two string copies,
                // and the actual measured wire field bytes; no identity length guess.
                let memory = total.checked_mul(2).and_then(|n| n.checked_add(std::mem::size_of::<Vec<Row>>() + std::mem::size_of::<Row>() + 2 * std::mem::size_of::<Option<std::ops::Range<usize>>>() + 8 + 2 * std::mem::size_of::<String>())).ok_or_else(invalid_candidate)?;
                let metadata = stages.admit_capacity(Capacity::MetadataBytes, memory as u64)?;
                let allocation = stages.admit_capacity(Capacity::TotalAllocationBytes, memory as u64)?;
                let row_reservation = stages.admit_capacity(Capacity::PgRows, 1)?;
                raw.query = Some(tokio::time::timeout_at(tokio::time::Instant::from_std(stages.effect_before(deadline)?), async {
                    let params: [&(dyn ToSql + Sync); 5] = [&candidate.binding.deployment_id, &candidate.binding.tenant_id, &history_cursor.as_str(), &thread_bytes, &operation_bytes];
                    let stream = owner.as_transaction().query_raw(&actual_sql, params).await?;
                    tokio::pin!(stream);
                    let mut selected = Vec::with_capacity(1);
                    while let Some(row) = stream.try_next().await? { selected.push(row); }
                    Ok(selected)
                }).await);
                stages.effect_before(deadline)?;
                let selected = raw.query.as_ref().and_then(|v| v.as_ref().ok()).and_then(|v| v.as_ref().ok()).ok_or_else(|| sql_observation_error(raw.query.as_ref()))?;
                let [row] = selected.as_slice() else { return Err(invalid_candidate()); };
                let thread: String = row.try_get("thread_id").map_err(|_| invalid_candidate())?;
                let operation: String = row.try_get("operation_id").map_err(|_| invalid_candidate())?;
                let actual_memory = selected.capacity().checked_mul(std::mem::size_of::<Row>()).and_then(|n| n.checked_add(std::mem::size_of::<Vec<Row>>() + 2 * std::mem::size_of::<Option<std::ops::Range<usize>>>() + 8 + 2 * std::mem::size_of::<String>())).and_then(|n| n.checked_add(thread.len() + operation.len())).and_then(|n| n.checked_add(thread.capacity() + operation.capacity())).ok_or_else(invalid_candidate)?;
                stages.settle_capacity(metadata, actual_memory as u64)?;
                stages.settle_capacity(allocation, actual_memory as u64)?;
                stages.settle_capacity(row_reservation, 1)?;
                let thread_id = openbot_contracts::ids::ThreadId::new(&thread);
                if !openbot_contracts::ids::thread::ThreadIdentity::is_plausible(&thread_id) {
                    return Err(invalid_candidate());
                }
                *history_thread = Some(thread);
                *history_operation = Some(operation);
                *history = StageResult::InFlight;
                let mut source = PendingHistoryClearSource {
                    owner: &owner,
                    binding: &candidate.binding,
                    audit_key: &candidate.audit_key,
                    stages,
                    control: &mut raw.history_control,
                    key_result: &mut raw.history_keys,
                };
                let cleared = crate::thread_history_authority::clear_restored_history_batch_before(&mut source, &thread_id, deadline).await;
                raw.history = Some(cleared);
                stages.effect_before(deadline)?;
                match raw.history.as_ref().expect("resident original clear result") {
                    Ok(Batch::Complete { operation_id } | Batch::ExistingComplete { operation_id })
                        if Some(operation_id.as_str()) != history_operation.as_deref() => Err(invalid_candidate()),
                    Ok(_) => Ok(()),
                    Err(ClearError::Unavailable) => Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
                    Err(_) => Err(invalid_candidate()),
                }
            }.await;
            let no_rows = history_thread.is_none();
            let read_only = no_rows || matches!(raw.history.as_ref(), Some(Ok(Batch::ExistingComplete { .. } | Batch::AwaitingDrain | Batch::AwaitingReaders)));
            if prepared.is_err() || !read_only {
                finish(owner, prepared, raw, intent, stages, deadline).await?;
            } else {
                raw.rollback = Some(owner.rollback_before(deadline).await);
                let disposition = match raw.rollback.as_ref().expect("resident original history rollback") {
                    Ok(()) => RestoreRollbackAck::TimelyAck,
                    Err(TransactionOwnerError::RollbackAcknowledgedAfterDeadline) => RestoreRollbackAck::AcknowledgedAfterDeadline,
                    Err(_) => RestoreRollbackAck::RollbackUnproven,
                };
                if let Some(original) = intent.take() {
                    let closing = stages.convergence_deadline()?;
                    stages.observe_stage_before(original, RestoreDisposition::PgRollback(disposition), closing)?;
                }
                if !matches!(raw.rollback, Some(Ok(()))) {
                    return Err(stages.failure(RecoveryControlFault::DatabaseUnknown));
                }
                stages.effect_before(deadline)?;
            }
            if no_rows {
                *history = StageResult::Acknowledged;
                return Ok(());
            }
            match raw.history.as_ref().expect("resident original clear decision") {
                Ok(Batch::Complete { .. } | Batch::ExistingComplete { .. }) => {
                    *history_cursor = history_thread.take().expect("observed original thread");
                    history_operation.take();
                }
                Ok(Batch::Batch { more }) => {
                    // Even an erased body still needs the original completion transaction.
                    let _original_more = more;
                    history_thread.take();
                }
                Ok(Batch::AwaitingDrain | Batch::AwaitingReaders) => {
                    *history = StageResult::Unstarted;
                    return Err(stages.failure(RecoveryControlFault::ClosureUnproven));
                }
                Err(_) => return Err(invalid_candidate()),
            }
            *history = StageResult::Unstarted;
            raw.history = None;
        }
    }
    // END S22 original closed-history adapter

    enum ExistingOperation {
        Absent,
        SameUnsealed,
        SameSealed,
    }

    async fn read_existing_operation_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        deadline: Instant,
    ) -> Result<ExistingOperation, RecoveryControlError> {
        let deadline = stages.effect_before(deadline)?;
        let row_reservation = stages.admit_capacity(Capacity::PgRows, 1)?;
        let _metadata = stages.admit_capacity(Capacity::MetadataBytes, PUBLIC_ROW_MEMORY)?;
        let _allocation =
            stages.admit_capacity(Capacity::TotalAllocationBytes, PUBLIC_ROW_MEMORY)?;
        let client = candidate
            .sql
            .client
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        let binding = &candidate.binding;
        let max_batches = i64::try_from(binding.max_batches)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
        let max_requirements = i64::try_from(binding.max_requirements)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
        candidate.sql.raw.query = Some(tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            client.as_client().query(
                "SELECT EXISTS(SELECT 1 FROM openbot_internal.restore_pg_operations WHERE operation_id=$1),EXISTS(SELECT 1 FROM openbot_internal.restore_pg_operations o WHERE operation_id=$1 AND ROW(epoch,candidate_generation,source_bundle_id,deployment_id,tenant_id,dataset_id,source_installation_id,target_installation_id,candidate_database_oid,pg_system_identifier,profile_binding,max_batches,max_requirements)=ROW($2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)),EXISTS(SELECT 1 FROM openbot_internal.restore_pg_seals s WHERE operation_id=$1 AND epoch=$2 AND batches=(SELECT count(*) FROM openbot_internal.restore_pg_batches b WHERE b.operation_id=$1 AND b.epoch=$2) AND subject_requirements=(SELECT count(*) FROM openbot_internal.restore_reconfirm_requirements r WHERE r.operation_id=$1 AND r.epoch=$2 AND r.source_kind='subject') AND credential_requirements=(SELECT count(*) FROM openbot_internal.restore_reconfirm_requirements r WHERE r.operation_id=$1 AND r.epoch=$2 AND r.source_kind<>'subject'))",
                &[&binding.operation_id,&binding.epoch.as_slice(),&binding.candidate_generation,&binding.source_bundle_id,
                  &binding.deployment_id,&binding.tenant_id,&binding.dataset_id,&binding.source_installation_id,
                  &binding.target_installation_id,&binding.candidate_database_oid,&binding.pg_system_identifier,
                  &binding.profile_binding.as_slice(),&max_batches,&max_requirements],
            ),
        ).await);
        stages.effect_before(deadline)?;
        let observed = match candidate
            .sql
            .raw
            .query
            .as_ref()
            .expect("resident original readback")
        {
            Ok(Ok(observed)) => observed,
            Ok(Err(_)) => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            Err(_) => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EffectExpired,
                ));
            }
        };
        stages.settle_capacity(row_reservation, observed.len() as u64)?;
        let exists: bool = observed[0].try_get(0).map_err(|_| invalid_candidate())?;
        let same: bool = observed[0].try_get(1).map_err(|_| invalid_candidate())?;
        let sealed: bool = observed[0].try_get(2).map_err(|_| invalid_candidate())?;
        if !exists {
            return Ok(ExistingOperation::Absent);
        }
        if !same {
            return Err(invalid_candidate());
        }
        Ok(if sealed {
            ExistingOperation::SameSealed
        } else {
            ExistingOperation::SameUnsealed
        })
    }

    pub(crate) async fn retire_cohort_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let result = async {
            if candidate.sql.schema != StageResult::Acknowledged {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ClosureUnproven,
                ));
            }
            if candidate.sql.retirement == StageResult::InFlight {
                return observe_unresolved_before(stages, candidate).await;
            }
            let existing = read_existing_operation_before(stages, candidate, deadline).await?;
            if candidate.sql.retirement == StageResult::Acknowledged {
                return match existing {
                    ExistingOperation::SameSealed => Ok(()),
                    _ => Err(invalid_candidate()),
                };
            }
            if !matches!(existing, ExistingOperation::Absent) {
                // SQL facts cannot replace a lost original timely ACK.
                return Err(database_unknown());
            }
            candidate.sql.retirement = StageResult::InFlight;
            register_operation_before(stages, candidate, deadline).await?;
            let mut sequence = 1_i64;
            for action in [
                RetirementAction::Users,
                RetirementAction::Sessions,
                RetirementAction::Approvals,
                RetirementAction::Decisions,
                RetirementAction::Leases,
                RetirementAction::Capabilities,
                RetirementAction::Verifications,
                RetirementAction::Callbacks,
                RetirementAction::Interrupts,
            ] {
                let mut cursor: Option<(String, i64)> = None;
                loop {
                    let batch = retire_batch_before(
                        stages,
                        candidate,
                        action,
                        cursor.as_ref().map(|v| (v.0.as_str(), v.1)),
                        sequence,
                        deadline,
                    )
                    .await?;
                    sequence = batch.sequence.checked_add(1).ok_or_else(|| {
                        RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                    })?;
                    if action == RetirementAction::Users {
                        // Every original user advances exactly once, including
                        // existing positive generations. The SQL residual only
                        // checks null/<1 and is not this keyset's cursor.
                        if batch.affected < BATCH_ROWS as i64 {
                            if batch.remaining != 0 {
                                return Err(invalid_candidate());
                            }
                            break;
                        }
                    } else if batch.remaining == 0 {
                        break;
                    }
                    cursor = Some(batch.cursor.ok_or_else(invalid_candidate)?);
                }
            }
            let mut high_water = 0_i64;
            for group in [RequirementGroup::Subjects, RequirementGroup::Credentials] {
                let mut cursor: Option<(String, String)> = None;
                loop {
                    let batch = requirements_batch_before(
                        stages,
                        candidate,
                        group,
                        cursor.as_ref().map(|v| (v.0.as_str(), v.1.as_str())),
                        sequence,
                        high_water,
                        deadline,
                    )
                    .await?;
                    sequence = batch.sequence.checked_add(1).ok_or_else(|| {
                        RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                    })?;
                    high_water = batch.high_water;
                    if batch.remaining == 0 {
                        break;
                    }
                    cursor = Some(batch.cursor.ok_or_else(invalid_candidate)?);
                }
            }
            let mut start = 0_usize;
            while start < candidate.configuration_inventory.len() {
                let end = start
                    .checked_add(BATCH_ROWS as usize)
                    .ok_or_else(|| {
                        RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                    })?
                    .min(candidate.configuration_inventory.len());
                let (actual_sequence, actual_high_water) = configuration_slots_before(
                    stages,
                    candidate,
                    start..end,
                    sequence,
                    high_water,
                    deadline,
                )
                .await?;
                sequence = actual_sequence.checked_add(1).ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?;
                high_water = actual_high_water;
                start = end;
            }
            seal_cohort_before(stages, candidate, sequence - 1, deadline).await?;
            candidate.sql.retirement = StageResult::Acknowledged;
            Ok(())
        }
        .await;
        result.map_err(|error| stages.failure(error.fault()))
    }

    async fn observe_unresolved_before(
        stages: &mut RestoreStages,
        candidate: &mut PendingRestoreCandidateAuthority,
    ) -> Result<(), RecoveryControlError> {
        let closing = stages.convergence_deadline()?;
        if candidate.sql.raw.readback.is_some() {
            return Err(stages.failure(RecoveryControlFault::DatabaseUnknown));
        }
        let Some(reservation) = candidate.sql.readback_rows.take() else {
            return Err(stages.failure(RecoveryControlFault::DatabaseUnknown));
        };
        let Some(Ok(client)) = candidate.sql.client.as_ref() else {
            return Err(stages.failure(RecoveryControlFault::DatabaseUnknown));
        };
        let binding = &candidate.binding;
        let epoch = binding.epoch.as_slice();
        let original = [
            &binding.operation_id as &(dyn ToSql + Sync),
            &epoch,
            &binding.candidate_generation,
        ];
        let result = match candidate.sql.pending_batch {
            Some((sequence, "seal")) => tokio::time::timeout_at(
                tokio::time::Instant::from_std(closing),
                client.as_client().query(
                    "SELECT s.batches,s.subject_requirements,s.credential_requirements FROM openbot_internal.restore_pg_seals s JOIN openbot_internal.restore_pg_operations o USING(operation_id,epoch) WHERE o.operation_id=$1 AND o.epoch=$2 AND o.candidate_generation=$3 AND s.batches=$4",
                    &[original[0],original[1],original[2],&sequence],
                ),
            ).await,
            Some((_, "operation")) => tokio::time::timeout_at(
                tokio::time::Instant::from_std(closing),
                client.as_client().query(
                    "SELECT operation_id FROM openbot_internal.restore_pg_operations WHERE operation_id=$1 AND epoch=$2 AND candidate_generation=$3",
                    &original,
                ),
            ).await,
            Some((sequence, action)) => tokio::time::timeout_at(
                tokio::time::Instant::from_std(closing),
                client.as_client().query(
                    "SELECT b.batch_seq,b.affected_count,b.remaining_count FROM openbot_internal.restore_pg_batches b JOIN openbot_internal.restore_pg_operations o USING(operation_id,epoch) WHERE o.operation_id=$1 AND o.epoch=$2 AND o.candidate_generation=$3 AND b.batch_seq=$4 AND b.action=$5",
                    &[original[0],original[1],original[2],&sequence,&action],
                ),
            ).await,
            None => {
                let checksum = native::native_0054_checksum();
                tokio::time::timeout_at(tokio::time::Instant::from_std(closing),
                    client.as_client().query(
                        "SELECT EXISTS(SELECT 1 FROM openbot_internal.schema_migrations WHERE version=54 AND checksum=$1),(SELECT system_identifier::text FROM pg_catalog.pg_control_system())=$2,(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())=$3",
                        &[&checksum,&binding.pg_system_identifier,&binding.candidate_database_oid],
                    ),
                ).await
            }
        };
        candidate.sql.raw.readback = Some(result);
        stages.convergence_deadline()?;
        if let Some(Ok(Ok(observed))) = candidate.sql.raw.readback.as_ref() {
            let _settled = stages.settle_capacity(reservation, observed.len() as u64);
        }
        // This is reconciliation of the exact original intent, never a
        // replacement for the original missing/late timely ACK.
        Err(stages.failure(RecoveryControlFault::DatabaseUnknown))
    }
}
// END S21 candidate_sql
