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
    ReviewedWholePgRestoreIntent,
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
        expected: WholePgManifestExpectation,
        deployment_id: String,
        tenant_id: String,
        dataset_id: String,
        source_installation_id: String,
    }

    /// Original files and complete observed identities. Only the original control
    /// input producer may assemble this owner after charging its finite allocations.
    pub struct FrozenWholePgRestoreInput {
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
    }

    /// Transfer only the original session's prepaid held inputs. Authentication
    /// and stable staging remain separate consumers of these bytes.
    pub(crate) fn from_original_held(
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
            },
            ReviewedWholePgRestoreIntent {
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
    pub(crate) struct AuthenticatedWholePgRestoreCarrier {
        input: FrozenWholePgRestoreInput,
        intent: ReviewedWholePgRestoreIntent,
        secrets: AuthenticatedRestoreSecrets,
    }

    pub(crate) fn authenticate_whole_pg_restore_carrier_before(
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
            let input = FrozenWholePgRestoreInput {
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
            };
            let intent = ReviewedWholePgRestoreIntent {
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
mod candidate_sql {
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
            53
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
        let owner = match if version == 53 {
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
            if version == 52 {
                raw.unit = Some(tokio::time::timeout_at(
                    tokio::time::Instant::from_std(stages.effect_before(deadline)?),
                    transaction.batch_execute(native::NATIVE_0053_SQL),
                ).await);
                stages.effect_before(deadline)?;
                raw.unit.as_ref().and_then(|r| r.as_ref().ok())
                    .and_then(|r| r.as_ref().ok()).ok_or_else(|| sql_observation_error(raw.unit.as_ref()))?;
                execute(raw, stages, transaction,
                    "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
                    &[&native::NATIVE_0053_VERSION, &native::NATIVE_0053_NAME, &native::native_0053_checksum()],
                    deadline).await?;
                verify_layout(raw, stages, transaction, &candidate.binding, 53, deadline).await?;
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
                let checksum = native::native_0053_checksum();
                tokio::time::timeout_at(tokio::time::Instant::from_std(closing),
                    client.as_client().query(
                        "SELECT EXISTS(SELECT 1 FROM openbot_internal.schema_migrations WHERE version=53 AND checksum=$1),(SELECT system_identifier::text FROM pg_catalog.pg_control_system())=$2,(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())=$3",
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
