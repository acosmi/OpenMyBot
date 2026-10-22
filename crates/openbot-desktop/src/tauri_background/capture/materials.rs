//! Actual same-owner material producers. Paths and observations never mint a source permit.
use super::{CaptureOperation, ControlSourceIdentity, NormalCaptureClosingOwner};
use crate::postgres_maintenance::capture::{CaptureOwnedMaterialFile, CaptureSourceOwner};
use openbot_domain::backup::whole_pg_carrier::{
    WholePgCarrierBounds, WholePgCarrierFault as Fault, WholePgCoverageClaim, WholePgMaterialKind,
    WholePgPresence, WholePgProvenanceClaim, WholePgSourceClaim,
};
use openbot_infra::artifact_store::capture::{
    ArtifactCaptureHold, ArtifactSnapshot, ArtifactSnapshotFailure, ArtifactSnapshotResult,
    ArtifactSnapshotFile, OwnedCaptureSpool,
};
use openbot_infra::auth::single_user::desktop_local::RetainedInstallationCapture;
use openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck;
use openbot_infra::db::capture_materials::{
    CaptureDbExpectation, CaptureSqlBudget, CaptureSqlFailure, CaptureSqlLimits, CapturedDbFacts,
};
use openbot_infra::repo::audit::CommittedCaptureCheckpoint;
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

type MaterialFault = Fault;

/// Created only beside the startup's actual ScreenHub -> ScreenSessionService move. No Hub
/// clone or Engine attachment port is exported by this factory.
pub(crate) struct CaptureScreenAssemblySeal {
    original: std::sync::Weak<dyn openbot_application::ScreenSessionAdministration>,
    assembly: Option<OriginalDesktopAssemblyBinding>,
}

/// DATA from this fixed Desktop construction, not a caller's source inventory.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalDesktopConstruction {
    PostgresBuiltInToolsFreshScreen,
}
struct OriginalDesktopAssemblyBinding {
    application: std::sync::Weak<dyn openbot_application::ApplicationService>,
    construction: OriginalDesktopConstruction,
}
impl CaptureScreenAssemblySeal {
    pub(in crate::tauri_background) fn bind_original_desktop_assembly(
        &mut self,
        assembly: &openbot_infra::application_assembly::PostgresApplicationAssembly,
    ) -> Result<(), Fault> {
        if self.assembly.is_some() {
            return Err(Fault::IntentMismatch);
        }
        let original_screen = self.original.upgrade().ok_or(Fault::SourceChanged)?;
        assembly.capture_material_layout(&original_screen)?;
        self.assembly = Some(OriginalDesktopAssemblyBinding {
            application: Arc::downgrade(&assembly.application),
            construction: OriginalDesktopConstruction::PostgresBuiltInToolsFreshScreen,
        });
        Ok(())
    }
}
pub(crate) fn capture_screen_sessions_from_startup() -> Result<
    (
        Arc<dyn openbot_application::ScreenSessionAdministration>,
        CaptureScreenAssemblySeal,
    ),
    Fault,
> {
    let hub = openbot_computer::screen::ScreenHub::new(
        openbot_computer::screen::DEFAULT_SCREEN_VIEWERS_PER_STREAM,
    )
    .map_err(|_| Fault::CapacityExceeded)?;
    let service: Arc<dyn openbot_application::ScreenSessionAdministration> =
        Arc::new(openbot_computer::screen::ScreenSessionService::new(hub));
    let seal = CaptureScreenAssemblySeal {
        original: Arc::downgrade(&service),
        assembly: None,
    };
    Ok((service, seal))
}

/// The state is installed at armed startup and is always owned by normal/source custody.
/// In-flight states deliberately have no restart path: cancellation cannot refund SQL or
/// submit another Periodic checkpoint while the original driver result is uncertain.
pub(crate) struct NormalCaptureMaterials {
    original_decode: Arc<openbot_infra::db::capture_materials::CaptureDecodeBudget>,
    installation: RetainedInstallationCapture,
    screen: CaptureScreenAssemblySeal,
    preferences: crate::preferences::RetainedPreferenceCapture,
    preference_result: Option<Result<crate::preferences::PreferenceCaptureSnapshot, Fault>>,
    preference_fact: Option<OriginalPreferenceMaterialFact>,
    budget: Option<CaptureSqlBudget>,
    expected: Option<CaptureDbExpectation>,
    key_id: Option<String>,
    key_version: Option<i32>,
    local_canary: Option<openbot_infra::db::desktop_vault_canary::DesktopVaultCanaryRow>,
    original_drivers: Option<OriginalDriverMaterial>,
    original_provenance: Option<WholePgProvenanceClaim>,
    tool_inventory: Option<Vec<u8>>,
    host: Option<HostInventory>,
    phase: ReadPhase,
    normal: Option<CapturedDbFacts>,
    original_before_observation: Option<Result<CapturedDbFacts, CaptureSqlFailure>>,
    original_after_observation: Option<Result<CapturedDbFacts, CaptureSqlFailure>>,
    original_metadata_prepared: Option<OriginalMetadataPrepared>,
    original_metadata_retirement: OriginalMetadataRetirement,
    checkpoint: Option<CommittedCaptureCheckpoint>,
    audit: AuditMaterialAttempt,
    schema_projection: AuditMaterialAttempt,
    migration_projection: AuditMaterialAttempt,
    receipt_projection: AuditMaterialAttempt,
    installation_projection: AuditMaterialAttempt,
    host_inventory_projection: AuditMaterialAttempt,
    compatibility_projection: AuditMaterialAttempt,
    key_metadata_projection: AuditMaterialAttempt,
    driver_facts_projection: AuditMaterialAttempt,
    tool_inventory_projection: AuditMaterialAttempt,
    profile_inventory_projection: AuditMaterialAttempt,
    workspace_inventory_projection: AuditMaterialAttempt,
    config: Vec<OriginalConfig>,
    original_config_directory: Option<usize>,
    artifact_hold: Option<ArtifactCaptureHold>,
    snapshot_task: Option<JoinHandle<ArtifactSnapshotResult>>,
    snapshot: Option<ArtifactSnapshot>,
    snapshot_failure: Option<ArtifactSnapshotFailure>,
    snapshot_started: bool,
    snapshot_joined: Option<OriginalSnapshotJoin>,
    snapshot_parts: Option<OriginalSnapshotParts>,
    transport: Option<crate::transport::RetainedTransportClosing>,
    writer_facts: Option<StoppedNormalWriters>,
    files: Vec<CaptureOwnedMaterialFile>,
    workspace: Option<File>,
    // Obtained originals stay in this same source owner before every fallible postcheck.
    opened: Vec<File>,
    host_directory: Option<rustix::fs::Dir>,
    // Only this owner's newly admitted FD-producing calls. This says nothing about
    // borrowed installation/native/SQL/artifact FDs or the whole-operation remainder.
    local_new_fd_admissions: u64,
    material_layout_started: bool,
    material_layout_ready: bool,
    material_layout_parent: Option<OriginalMaterialDirectoryBinding>,
    material_directory_bindings: [Option<OriginalMaterialDirectoryBinding>; 3],
    // Fixed roles: materials, artifact-spool, metadata. No generic path authority.
    material_directories: [Option<File>; 3],
    material_directory_results: [Option<Result<(), rustix::io::Errno>>; 3],
    material_directory_open_entered: [bool; 3],
}
type OriginalMaterialDirectoryBinding = (u64, u64, u32, u32);

/// Only the original Store's completed snapshot can form this ordinary DATA.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(tag = "presence", rename_all = "snake_case")]
enum OriginalPreferenceMaterialFact {
    AbsentOriginalParentEnoent,
    PresentOriginalSnapshot { byte_length: u64, sha256: [u8; 32] },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadPhase {
    Armed,
    IdentityReading,
    Identified,
    PreferencesClosing,
    PreferencesFrozen,
    AuditStarted,
    NormalReading,
    NormalCollected,
    BeforeReading,
    BeforeVerified,
    BackupStarted,
    BackupClosed,
    AfterReading,
    AfterVerified,
    SourcesClosing,
    SourcesClosed,
}

pub(crate) struct StoppedNormalWriters {
    original_agent: bool,
    original_assembly: bool,
    original_transport: bool,
}
#[derive(serde::Serialize)]
struct HostEntry {
    name: String,
    kind: &'static str,
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    bytes: u64,
}
#[derive(serde::Serialize)]
struct HostInventory {
    instance: String,
    device: u64,
    inode: u64,
    uid: u32,
    entries: Vec<HostEntry>,
}

struct OriginalConfig {
    relative: String,
    file: usize,
    identity: FileIdentity,
    sha256: [u8; 32],
}
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    mtime: i64,
    mtime_ns: i64,
}
impl FileIdentity {
    fn of(file: &File, op: &CaptureOperation) -> Result<Self, Fault> {
        op.require_effect()?;
        let observed = file.metadata();
        op.require_effect()?;
        let m = observed.map_err(|_| Fault::IoFailure)?;
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            mode: m.mode(),
            links: m.nlink(),
            bytes: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
        })
    }
}
impl NormalCaptureMaterials {
    pub(crate) fn original_decode_budget(
        &self,
    ) -> Arc<openbot_infra::db::capture_materials::CaptureDecodeBudget> {
        Arc::clone(&self.original_decode)
    }

    pub(crate) fn from_original_installation(
        installation: RetainedInstallationCapture,
        screen: CaptureScreenAssemblySeal,
        preferences: crate::preferences::RetainedPreferenceCapture,
        original_decode: Arc<openbot_infra::db::capture_materials::CaptureDecodeBudget>,
    ) -> Self {
        Self {
            original_decode,
            installation,
            screen,
            preferences,
            preference_result: None,
            preference_fact: None,
            budget: None,
            expected: None,
            key_id: None,
            key_version: None,
            local_canary: None,
            original_drivers: None,
            original_provenance: None,
            tool_inventory: None,
            host: None,
            phase: ReadPhase::Armed,
            normal: None,
            original_before_observation: None,
            original_after_observation: None,
            original_metadata_prepared: None,
            original_metadata_retirement: OriginalMetadataRetirement::Unentered,
            checkpoint: None,
            audit: AuditMaterialAttempt::new(),
            schema_projection: AuditMaterialAttempt::new(),
            migration_projection: AuditMaterialAttempt::new(),
            receipt_projection: AuditMaterialAttempt::new(),
            installation_projection: AuditMaterialAttempt::new(),
            host_inventory_projection: AuditMaterialAttempt::new(),
            compatibility_projection: AuditMaterialAttempt::new(),
            key_metadata_projection: AuditMaterialAttempt::new(),
            driver_facts_projection: AuditMaterialAttempt::new(),
            tool_inventory_projection: AuditMaterialAttempt::new(),
            profile_inventory_projection: AuditMaterialAttempt::new(),
            workspace_inventory_projection: AuditMaterialAttempt::new(),
            config: Vec::new(),
            original_config_directory: None,
            artifact_hold: None,
            snapshot_task: None,
            snapshot: None,
            snapshot_failure: None,
            snapshot_started: false,
            snapshot_joined: None,
            snapshot_parts: None,
            transport: None,
            writer_facts: None,
            files: Vec::new(),
            workspace: None,
            opened: Vec::new(),
            host_directory: None,
            local_new_fd_admissions: 0,
            material_layout_started: false,
            material_layout_ready: false,
            material_layout_parent: None,
            material_directory_bindings: [None, None, None],
            material_directories: [None, None, None],
            material_directory_results: [None, None, None],
            material_directory_open_entered: [false; 3],
        }
    }
    fn expected(&self) -> Result<&CaptureDbExpectation, Fault> {
        self.expected.as_ref().ok_or(Fault::IntentMismatch)
    }
    fn opened_file(&self, index: usize) -> Result<&File, Fault> {
        self.opened.get(index).ok_or(Fault::MaterialMissing)
    }
    fn parent_file(&self, parent: MaterialParent) -> Result<&File, Fault> {
        match parent {
            MaterialParent::Installation => Ok(self.installation.original_root()),
            MaterialParent::Opened(index) => self.opened_file(index),
        }
    }
}

#[derive(Clone, Copy)]
enum MaterialParent {
    Installation,
    Opened(usize),
}

/// The sole pre-close read uses the original already-attested Pool and the very same SQL
/// counters later used by audit, normal collection and both maintenance reads.
pub(crate) async fn prepare_intent_source(
    normal: &mut NormalCaptureClosingOwner,
    op: &Arc<CaptureOperation>,
) -> Result<ControlSourceIdentity, MaterialFault> {
    op.require_effect()?;
    let state = normal.materials.as_mut().ok_or(Fault::MaterialMissing)?;
    if state.phase != ReadPhase::Armed || state.budget.is_some() {
        return Err(Fault::IntentMismatch);
    }
    state.installation.verify_original(op.as_ref())?;
    let q = &op.profile().sql;
    state.budget = Some(
        CaptureSqlBudget::new(
            CaptureSqlLimits {
                max_rows: q.max_rows,
                max_row_bytes: q.max_row_bytes,
                max_field_bytes: q.max_field_bytes,
                max_pages: q.max_pages,
                page_rows: q.page_rows,
                max_catalog_objects: q.max_catalog_objects,
                max_query_tasks: q.max_query_tasks,
                phase_ns: q.phase_ns,
            },
            op.profile().carrier.max_metadata_bytes,
            op.original_t0_ns(),
        )
        .map_err(sql_fault)?,
    );
    state
        .budget
        .as_mut()
        .ok_or(Fault::MaterialMissing)?
        .bind_sensitive_decode_bound(Arc::clone(&state.original_decode))
        .map_err(sql_fault)?;
    state.phase = ReadPhase::IdentityReading;
    let identity = normal
        .capture_audit
        .capture_source_identity_before(
            state.budget.as_mut().ok_or(Fault::MaterialMissing)?,
            op.as_ref(),
        )
        .await
        .map_err(sql_fault)?;
    op.require_effect()?;
    let plane = normal
        .background
        .data_plane
        .as_ref()
        .ok_or(Fault::MaterialMissing)?;
    let vault = normal.vault.as_ref().ok_or(Fault::SecretInvalid)?;
    vault.revalidate_before(op.as_ref())?;
    let installation = plane.installation();
    let binding = plane.artifact_dataset_registry().binding();
    if binding.dataset_id() != vault.dataset_id()
        || binding.deployment_id() != vault.deployment_id()
        || binding.tenant_id() != vault.tenant_id()
        || binding.binding_schema() != 1
    {
        return Err(Fault::SourceChanged);
    }
    let instance = installation.authority().instance_id().to_owned();
    let cluster_name = format!("postgresql-17-{instance}");
    let cluster = open_child(state, MaterialParent::Installation, &cluster_name, true, op)?;
    let cluster_identity = FileIdentity::of(state.opened_file(cluster)?, op)?;
    let store = open_child(state, MaterialParent::Installation, "artifacts", true, op)?;
    let store_identity = FileIdentity::of(state.opened_file(store)?, op)?;
    state.expected = Some(CaptureDbExpectation {
        deployment_id: vault.deployment_id().to_owned(),
        tenant_id: vault.tenant_id().to_owned(),
        dataset_id: vault.dataset_id().to_owned(),
        instance_id: instance.clone(),
        system_identifier: identity.system_identifier().to_owned(),
        database_oid: identity.database_oid(),
        store_id: normal.artifact_store.store_id().to_string(),
        root_device: store_identity.device.to_string(),
        root_inode: store_identity.inode.to_string(),
        root_uid: store_identity.uid.to_string(),
    });
    state.key_id = Some(vault.key_id().to_owned());
    // Retain the same getter's actual value; the original Control conversion below stays in place.
    state.key_version = Some(vault.key_version());
    op.require_effect()?;
    state.phase = ReadPhase::Identified;
    Ok(ControlSourceIdentity {
        instance_id: instance,
        dataset_id: vault.dataset_id().to_owned(),
        deployment_id: vault.deployment_id().to_owned(),
        tenant_id: vault.tenant_id().to_owned(),
        system_identifier: identity.system_identifier().to_owned(),
        database_oid: identity.database_oid(),
        key_id: vault.key_id().to_owned(),
        key_version: u32::try_from(vault.key_version()).map_err(|_| Fault::SecretInvalid)?,
        source_device: cluster_identity.device,
        source_inode: cluster_identity.inode,
        source_uid: cluster_identity.uid,
        canary_material_id: "key-metadata".to_owned(),
        schema_material_id: "schema".to_owned(),
        migration_material_id: "migrations".to_owned(),
        compatibility_material_id: "compatibility".to_owned(),
    })
}

/// Each awaited stop only borrows original handles; normal owns every collection throughout.
pub(crate) async fn stop_normal_writers(
    normal: &mut NormalCaptureClosingOwner,
    op: &Arc<CaptureOperation>,
) -> Result<(), MaterialFault> {
    op.require_normal_closing()?;
    let state = normal.materials.as_mut().ok_or(Fault::MaterialMissing)?;
    if state.writer_facts.is_some() {
        return Ok(());
    }
    if state.phase != ReadPhase::Identified {
        return Err(Fault::IntentMismatch);
    }
    if state.transport.is_none() {
        state.transport = Some(
            normal
                .background
                .transport
                .begin_capture_closing()
                .map_err(|_| Fault::ClosingPending)?,
        );
    }
    let remaining = op.normal_closing_remaining_ns()?;
    tokio::time::timeout(
        std::time::Duration::from_nanos(remaining),
        state
            .transport
            .as_mut()
            .ok_or(Fault::ClosingPending)?
            .join_originals(),
    )
    .await
    .map_err(|_| Fault::ClosingPending)?
    .map_err(|_| Fault::ClosingPending)?;
    op.require_normal_closing()?;
    if let Some(agent) = normal.background.agent_host.as_mut() {
        let remaining = op.normal_closing_remaining_ns()?;
        tokio::time::timeout(
            std::time::Duration::from_nanos(remaining),
            agent.stop_for_capture(),
        )
        .await
        .map_err(|_| Fault::ClosingPending)?
        .map_err(|_| Fault::ClosingPending)?;
    }
    op.require_normal_closing()?;
    let assembly = normal
        .background
        .assembly
        .as_mut()
        .ok_or(Fault::MaterialMissing)?;
    let remaining = op.normal_closing_remaining_ns()?;
    tokio::time::timeout(
        std::time::Duration::from_nanos(remaining),
        assembly.stop_for_capture(),
    )
    .await
    .map_err(|_| Fault::ClosingPending)?
    .map_err(|_| Fault::ClosingPending)?;
    op.require_normal_closing()?;
    // The real gate, active operations, original async and blocking workers all close here.
    state.artifact_hold = Some(
        normal
            .artifact_store
            .freeze_for_capture(op.as_ref())
            .await
            .map_err(|e| e.fault())?,
    );
    op.require_normal_closing()?;
    state.writer_facts = Some(StoppedNormalWriters {
        original_agent: true,
        original_assembly: true,
        original_transport: true,
    });
    Ok(())
}

// Known requested Rust/byte allocations in the original fixed canary decoder and verifier.
// This does not expose the SQL private sensitive counter or measure opaque serde/crypto T.
fn reserve_original_canary_decode(
    state: &mut NormalCaptureMaterials, op: &CaptureOperation,
) -> Result<(), Fault> {
    if state.local_canary.is_some() { return Err(Fault::IntentMismatch); }
    let sql = &op.profile().sql;
    let class = &op.profile().secrets.classes.decode_crypto_temporary;
    // The original page path charges six buffers for (page_rows + lookahead) on each page.
    // Reserve that full cumulative ceiling, including still resident normal facts, before
    // adding this once-only local decoder's concrete buffer counts. No private count is read.
    let original_count_ceiling = sql.max_pages
        .checked_mul(sql.page_rows.checked_add(1).ok_or(Fault::BoundsOverflow)?)
        .and_then(|n| n.checked_mul(6)).ok_or(Fault::BoundsOverflow)?;
    let encoded_bound = sql.max_row_bytes.checked_mul(6)
        .and_then(|n| n.checked_add(32 * 5 + 2)).ok_or(Fault::BoundsOverflow)?;
    let aad_bound = (b"openbot.desktop.vault.canary.v1\0".len() as u64)
        .checked_add(32 * 2 + 256 * 2 + 4 * 4 + 4).ok_or(Fault::BoundsOverflow)?;
    // (allocation count, requested byte ceiling): fields backing/fields/scratch; Row's five
    // Strings; binding's four; three wire Strings/scratch; hex, AAD, plaintext and derived key.
    let allocations: [(u64, u64); 15] = [
        (1, 32 * std::mem::size_of::<Option<String>>() as u64),
        (32, sql.max_field_bytes),
        (1, encoded_bound.checked_mul(2).ok_or(Fault::BoundsOverflow)?),
        // Row::new copies these five fields before its own shape/4096 checks.
        (2, sql.max_field_bytes), (2, sql.max_field_bytes), (1, sql.max_field_bytes),
        (2, 32), (2, 256), (3, 4096), (1, 8192),
        // Both hex Vecs allocate before final 12/50-byte validation; input is at most4096.
        (1, 4096 / 2), (1, 4096 / 2),
        (1, aad_bound.checked_mul(3).ok_or(Fault::BoundsOverflow)?),
        (1, 34 + 16), (1, 32),
    ];
    let mut count = original_count_ceiling;
    let mut bytes = 0u64;
    for (copies, one) in allocations {
        count = count.checked_add(copies).ok_or(Fault::BoundsOverflow)?;
        if one > class.max_one_bytes { return Err(Fault::CapacityExceeded); }
        bytes = bytes.checked_add(copies.checked_mul(one).ok_or(Fault::BoundsOverflow)?)
            .ok_or(Fault::BoundsOverflow)?;
    }
    if count > class.max_count { return Err(Fault::CapacityExceeded); }
    state.original_decode.reserve_allocations(&allocations).map_err(sql_fault)?;
    let fixed = (std::mem::size_of::<Option<
        openbot_infra::db::desktop_vault_canary::DesktopVaultCanaryRow>>() as u64)
        .checked_add(std::mem::size_of::<openbot_domain::vault::DesktopVaultCanaryBinding>() as u64)
        .and_then(|n| n.checked_add(std::mem::size_of::<openbot_domain::vault::DesktopVaultCanaryEnvelope>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<
            openbot_infra::db::desktop_vault_canary::DesktopVaultCanaryRow, CaptureSqlFailure>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Vec<Option<String>>>() as u64))
        .and_then(|n| n.checked_add((std::mem::size_of::<String>() as u64).checked_mul(3)?))
        .and_then(|n| n.checked_add(std::mem::size_of::<u64>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<[(u64, u64); 15]>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<std::array::IntoIter<(u64, u64), 15>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Option<(u64, u64)>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<(u64, u64)>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), Fault>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), CaptureSqlFailure>>() as u64))
        .ok_or(Fault::BoundsOverflow)?;
    let new_known = fixed.checked_add(bytes).ok_or(Fault::BoundsOverflow)?;
    let normal = state.normal.as_ref().ok_or(Fault::MaterialMissing)?;
    let retained_rows = normal.row_count().checked_add(normal.sensitive_reference_count())
        .ok_or(Fault::BoundsOverflow)?;
    // The original SQL producer already charges its metadata internally. Observe its known
    // still resident requested rows in the operation book too; this is no second SQL grant.
    let row_known = sql.max_row_bytes.checked_mul(4)
        .and_then(|n| n.checked_add(32 * std::mem::size_of::<Option<String>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<(&str, Vec<Option<String>>)>() as u64))
        .ok_or(Fault::BoundsOverflow)?;
    let normal_known = (retained_rows as u64).checked_mul(row_known)
        .and_then(|n| n.checked_add(std::mem::size_of::<CapturedDbFacts>() as u64))
        .ok_or(Fault::BoundsOverflow)?;
    let aggregate_known = new_known.checked_add(normal_known).ok_or(Fault::BoundsOverflow)?;
    if aggregate_known > op.profile().carrier.max_total_allocation_bytes {
        return Err(Fault::CapacityExceeded);
    }
    state.budget.as_mut().ok_or(Fault::MaterialMissing)?
        .reserve_material_metadata(new_known, op).map_err(sql_fault)?;
    op.reserve_original_resources(0, aggregate_known)
}

/// Close the same original preference operation gate while its normal SQL owner is alive.
/// The original Intent already owns this destination; no new root/Store/clock is constructed.
pub(super) async fn freeze_original_preferences_for_normal(
    normal: &mut NormalCaptureClosingOwner,
    control: &super::CaptureControlOwner,
    op: &Arc<CaptureOperation>,
) -> Result<(), Fault> {
    op.require_normal_closing()?;
    let original = normal.operation.upgrade().ok_or(Fault::ClockUnavailable)?;
    if !Arc::ptr_eq(&original, op) || normal.intent.is_none() {
        return Err(Fault::IntentMismatch);
    }
    let parent = control.operation_directory()?;
    let parent_path = control.operation_path()?;
    let state = normal.materials.as_mut().ok_or(Fault::MaterialMissing)?;
    let stopped = state.writer_facts.as_ref().ok_or(Fault::ClosingPending)?;
    if state.phase != ReadPhase::Identified || state.preference_result.is_some()
        || state.preference_fact.is_some() || !stopped.original_agent
        || !stopped.original_assembly || !stopped.original_transport {
        return Err(Fault::IntentMismatch);
    }
    let known = (std::mem::size_of::<Option<Result<
        crate::preferences::PreferenceCaptureSnapshot, Fault>>>() as u64)
        .checked_add(std::mem::size_of::<Option<OriginalPreferenceMaterialFact>>() as u64)
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<
            crate::preferences::PreferenceCaptureSnapshot, Fault>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<Result<
            crate::preferences::PreferenceCaptureSnapshot, Fault>, tokio::time::error::Elapsed>>() as u64))
        .and_then(|n| n.checked_add((std::mem::size_of::<Arc<dyn CaptureClockCheck>>() as u64).checked_mul(2)?))
        .and_then(|n| n.checked_add((std::mem::size_of::<Result<(), Fault>>() as u64).checked_mul(2)?))
        .and_then(|n| n.checked_add(std::mem::size_of::<(Option<u64>, Option<[u8; 32]>)>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<OriginalPreferenceMaterialFact>() as u64))
        .ok_or(Fault::BoundsOverflow)?;
    // Original preference work/three FDs already use that owner's same-book admission.
    // This is only added caller DATA/continuation memory, not another component allowance.
    op.reserve_original_resources(0, known)?;
    state.phase = ReadPhase::PreferencesClosing;
    state.prepare_original_material_spool(parent, parent_path, op.as_ref())?;
    let destination = state.material_directories[2].as_ref().ok_or(Fault::MaterialMissing)?;
    let clock: Arc<dyn CaptureClockCheck> = op.clone();
    let remaining = op.normal_closing_remaining_ns()?;
    let future = state.preferences.close_and_snapshot(destination, clock);
    // Constructing this async future executes none of its body. Keep the original
    // shorter normal-close deadline; timeout only drops the borrow, never its original work.
    let future_bytes = u64::try_from(std::mem::size_of_val(&future)).map_err(|_| Fault::BoundsOverflow)?;
    let wait = tokio::time::timeout(std::time::Duration::from_nanos(remaining), future);
    let wait_bytes = u64::try_from(std::mem::size_of_val(&wait)).map_err(|_| Fault::BoundsOverflow)?;
    op.reserve_original_resources(0, future_bytes.checked_add(wait_bytes).ok_or(Fault::BoundsOverflow)?)?;
    let returned = wait.await;
    state.preference_result = Some(match returned {
        Ok(result) => result,
        // No original snapshot Result returned. PreferencesClosing and the original
        // owner's work/JoinHandle/result slots remain resident; this is not Absent.
        Err(_) => return Err(Fault::ClosingPending),
    });
    let post = op.require_effect();
    post?;
    op.require_normal_closing()?;
    let snapshot = match state.preference_result.as_ref().ok_or(Fault::MaterialMissing)? {
        Ok(snapshot) => snapshot,
        Err(fault) => return Err(*fault),
    };
    state.preference_fact = Some(match (snapshot.byte_length(), snapshot.sha256()) {
        (None, None) => OriginalPreferenceMaterialFact::AbsentOriginalParentEnoent,
        (Some(byte_length), Some(sha256)) if byte_length > 0 =>
            OriginalPreferenceMaterialFact::PresentOriginalSnapshot { byte_length, sha256 },
        _ => return Err(Fault::MaterialMissing),
    });
    state.phase = ReadPhase::PreferencesFrozen;
    Ok(())
}

/// All results stay resident before the next await. No bare material/code-only error drops
/// a snapshot handle or moves the cumulative SQL budget into a disposable timeout future.
pub(crate) async fn collect_normal_materials(
    normal: &mut NormalCaptureClosingOwner,
    op: &Arc<CaptureOperation>,
) -> Result<(), MaterialFault> {
    op.require_effect()?;
    let original_port = normal
        .background
        .data_plane
        .as_ref()
        .and_then(|plane| plane.capture_sidecar_port())
        .filter(|port| *port != 0)
        .ok_or(Fault::SourceChanged)?;
    let state = normal.materials.as_mut().ok_or(Fault::MaterialMissing)?;
    let stopped = state.writer_facts.as_ref().ok_or(Fault::ClosingPending)?;
    if !stopped.original_agent
        || !stopped.original_assembly
        || !stopped.original_transport
        || state.phase != ReadPhase::PreferencesFrozen || state.preference_fact.is_none()
    {
        return Err(Fault::ClosingPending);
    }
    let original_screen = state
        .screen
        .original
        .upgrade()
        .ok_or(Fault::SourceChanged)?;
    let original_assembly = normal
        .background
        .assembly
        .as_ref()
        .ok_or(Fault::MaterialMissing)?;
    let _original_layout = original_assembly.capture_material_layout(&original_screen)?;
    let binding = state
        .screen
        .assembly
        .as_ref()
        .ok_or(Fault::SourceChanged)?;
    if binding.construction != OriginalDesktopConstruction::PostgresBuiltInToolsFreshScreen
        || !binding
            .application
            .ptr_eq(&Arc::downgrade(&original_assembly.application))
    {
        return Err(Fault::SourceChanged);
    }
    state.host = Some(classify_host_root(state, op)?);
    state.phase = ReadPhase::AuditStarted;
    state.checkpoint = Some(
        normal
            .capture_audit
            .append_capture_periodic_before(
                normal
                    .capture_audit_key
                    .as_ref()
                    .ok_or(Fault::SecretInvalid)?
                    .expose(),
                state.budget.as_mut().ok_or(Fault::MaterialMissing)?,
                op.as_ref(),
            )
            .await
            .map_err(sql_fault)?,
    );
    // The true Periodic COMMIT ACK is resident before this derived allocation is retired.
    // A failed closing precheck retains Some; a failed postcheck preserves the actual None.
    op.require_closing()?;
    drop(normal.capture_audit_key.take());
    op.require_closing()?;
    op.require_effect()?;
    collect_original_config(state, original_port, op)?;
    op.require_effect()?;
    state.phase = ReadPhase::NormalReading;
    state.normal = Some(
        normal
            .capture_audit
            .collect_capture_materials_before(
                state.expected.as_ref().ok_or(Fault::MaterialMissing)?,
                state.budget.as_mut().ok_or(Fault::MaterialMissing)?,
                op.as_ref(),
            )
            .await
            .map_err(sql_fault)?,
    );
    reserve_original_canary_decode(state, op.as_ref())?;
    state.local_canary = Some(
        state.normal.as_ref().ok_or(Fault::MaterialMissing)?
            .capture_canary_row().map_err(sql_fault)?,
    );
    // The exact returned Row is resident before the verifier or any later E postcheck.
    normal
        .vault
        .as_ref()
        .ok_or(Fault::SecretInvalid)?
        .verify_capture_canary_before(
            state.local_canary.as_ref().ok_or(Fault::MaterialMissing)?, op.as_ref(),
        )?;
    op.require_effect()?;
    for expected in &state.config {
        if FileIdentity::of(state.opened_file(expected.file)?, op)? != expected.identity {
            return Err(Fault::SourceChanged);
        }
    }
    op.require_effect()?;
    state.phase = ReadPhase::NormalCollected;
    Ok(())
}

fn classify_host_root(
    state: &mut NormalCaptureMaterials,
    op: &CaptureOperation,
) -> Result<HostInventory, Fault> {
    let original_root = state.installation.original_root();
    let before = FileIdentity::of(original_root, op)?;
    let instance = state
        .expected
        .as_ref()
        .ok_or(Fault::IntentMismatch)?
        .instance_id
        .clone();
    let cluster = format!("postgresql-17-{instance}");
    let scram = format!(".postgresql-17-{instance}.scram-init-v1.json");
    let master = format!(".desktop-vault-{instance}.master-init-v1.json");
    let start = format!(".postgresql-17-{instance}.start-lock-v1");
    let mut entries = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    if state.host_directory.is_some() {
        return Err(Fault::IntentMismatch);
    }
    op.require_effect()?;
    reserve_local_new_material_fd(
        &mut state.local_new_fd_admissions,
        op.profile().carrier.max_open_files,
    )?;
    let directory = rustix::fs::Dir::read_from(original_root);
    match directory {
        Ok(directory) => state.host_directory = Some(directory),
        Err(_) => {
            op.require_effect()?;
            return Err(Fault::IoFailure);
        }
    }
    op.require_effect()?;
    loop {
        op.require_effect()?;
        let entry = state
            .host_directory
            .as_mut()
            .ok_or(Fault::MaterialMissing)?
            .next();
        op.require_effect()?;
        let Some(entry) = entry else {
            break;
        };
        let entry = entry.map_err(|_| Fault::IoFailure)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let text = name.to_str().map_err(|_| Fault::PathUnsafe)?;
        let (kind, is_directory) = match text {
            "desktop-instance-v1" => ("installation", false),
            "artifacts" => ("artifact-store", true),
            "ui-preferences-v1" => ("preference-projection", false),
            ".wrokbot-capture-control-v1" => ("original-capture-control", true),
            name if name == cluster => ("original-postgres", true),
            name if name == scram => ("scram-journal", false),
            name if name == master => ("master-journal", false),
            name if name == start => ("original-kernel-lock", false),
            _ => return Err(Fault::ExtraMaterial),
        };
        state
            .budget
            .as_mut()
            .ok_or(Fault::MaterialMissing)?
            .reserve_material_metadata(
                (text.len() as u64)
                    .checked_add(256)
                    .ok_or(Fault::BoundsOverflow)?,
                op,
            )
            .map_err(sql_fault)?;
        if entries.len() as u64 >= op.profile().carrier.max_material_files {
            return Err(Fault::CapacityExceeded);
        }
        op.require_effect()?;
        let observed =
            rustix::fs::statat(original_root, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
        op.require_effect()?;
        let st = observed.map_err(|_| Fault::SourceChanged)?;
        let actual = rustix::fs::FileType::from_raw_mode(st.st_mode);
        if st.st_uid != before.uid
            || st.st_mode & 0o077 != 0
            || is_directory && actual != rustix::fs::FileType::Directory
            || !is_directory && (actual != rustix::fs::FileType::RegularFile || st.st_nlink != 1)
        {
            return Err(Fault::PathUnsafe);
        }
        if !names.insert(text.to_owned()) {
            return Err(Fault::SourceChanged);
        }
        entries.push(HostEntry {
            name: text.to_owned(),
            kind,
            device: st.st_dev as u64,
            inode: st.st_ino,
            uid: st.st_uid,
            mode: u32::from(st.st_mode),
            bytes: u64::try_from(st.st_size).map_err(|_| Fault::BoundsOverflow)?,
        });
    }
    for required in [
        "desktop-instance-v1",
        "artifacts",
        cluster.as_str(),
        scram.as_str(),
        master.as_str(),
        start.as_str(),
        ".wrokbot-capture-control-v1",
    ] {
        if !names.contains(required) {
            return Err(Fault::MaterialMissing);
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    if FileIdentity::of(original_root, op)? != before {
        return Err(Fault::SourceChanged);
    }
    Ok(HostInventory {
        instance,
        device: before.device,
        inode: before.inode,
        uid: before.uid,
        entries,
    })
}

/// Observe only original resident identity facts; this never returns a root or source grant.
pub(super) fn revalidate_original_source_config(
    state: &NormalCaptureMaterials,
    stopped: &crate::postgres_sidecar::CaptureStoppedPostgres,
    op: &CaptureOperation,
) -> Result<(), Fault> {
    if !matches!(state.phase,
        ReadPhase::NormalCollected | ReadPhase::BeforeReading | ReadPhase::BeforeVerified
        | ReadPhase::BackupStarted | ReadPhase::BackupClosed | ReadPhase::AfterReading
        | ReadPhase::AfterVerified | ReadPhase::SourcesClosing | ReadPhase::SourcesClosed)
        || state.normal.is_none() || state.checkpoint.is_none() || state.config.len() != 4 {
        return Err(Fault::MaterialMissing);
    }
    let directory = state.opened_file(state.original_config_directory.ok_or(Fault::MaterialMissing)?)?;
    stopped.capture_original_data_directory_matches(directory, op)?;
    op.require_effect()?;
    let held = directory.metadata();
    op.require_effect()?;
    let held = held.map_err(|_| Fault::IoFailure)?;
    op.require_effect()?;
    let named = std::fs::symlink_metadata(stopped.data_dir());
    op.require_effect()?;
    let named = named.map_err(|_| Fault::IoFailure)?;
    if !held.is_dir() || !named.is_dir() || held.mode() & 0o777 != 0o700
        || named.mode() & 0o777 != 0o700 || held.uid() != rustix::process::geteuid().as_raw()
        || (held.dev(), held.ino(), held.uid()) != (named.dev(), named.ino(), named.uid()) {
        return Err(Fault::SourceChanged);
    }
    // Stop legitimately changes directory timestamps; only each frozen file binds timestamps.
    for (expected, basename) in state.config.iter().zip([
        "postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf",
    ]) {
        if expected.relative != format!("pgdata/{basename}")
            || FileIdentity::of(state.opened_file(expected.file)?, op)? != expected.identity {
            return Err(Fault::SourceChanged);
        }
        op.require_effect()?;
        let named = std::fs::symlink_metadata(stopped.data_dir().join(basename));
        op.require_effect()?;
        let named = named.map_err(|_| Fault::IoFailure)?;
        let observed = FileIdentity {
            device: named.dev(), inode: named.ino(), uid: named.uid(), mode: named.mode(),
            links: named.nlink(), bytes: named.len(), mtime: named.mtime(), mtime_ns: named.mtime_nsec(),
        };
        if !named.is_file() || observed != expected.identity { return Err(Fault::SourceChanged); }
    }
    op.require_effect()
}

fn collect_original_config(
    state: &mut NormalCaptureMaterials,
    original_port: u16,
    op: &CaptureOperation,
) -> Result<(), Fault> {
    if state.original_config_directory.is_some() || !state.config.is_empty() {
        return Err(Fault::IntentMismatch);
    }
    let name = format!("postgresql-17-{}", state.expected()?.instance_id);
    let cluster = open_child(state, MaterialParent::Installation, &name, true, op)?;
    state.original_config_directory = Some(cluster);
    for (name, form) in [
        ("postgresql.conf", OriginalConfigForm::Main),
        ("postgresql.auto.conf", OriginalConfigForm::Auto),
        ("pg_hba.conf", OriginalConfigForm::Hba),
        ("pg_ident.conf", OriginalConfigForm::Ident),
    ] {
        op.require_effect()?;
        let file = open_child(state, MaterialParent::Opened(cluster), name, false, op)?;
        let identity = FileIdentity::of(state.opened_file(file)?, op)?;
        if identity.mode & 0o170000 != 0o100000
            || identity.links != 1
            || identity.mode & 0o077 != 0
            || identity.bytes > op.profile().carrier.max_single_plain_bytes
        {
            return Err(Fault::PathUnsafe);
        }
        let sha256 = hash_original(state.opened_file(file)?, identity, form, original_port, op)?;
        state.config.push(OriginalConfig {
            relative: format!("pgdata/{name}"),
            file,
            identity,
            sha256,
        });
    }
    Ok(())
}

// This fixed leaf is ordinary material, never a control-stage record.
const AUDIT_MATERIAL_LEAF: &str = "audit-checkpoint.jsonl";
const AUDIT_MATERIAL_ID: &str = "audit-checkpoint";
const AUDIT_MATERIAL_PATH: &str = "metadata/audit-checkpoint.jsonl";

// Only these twelve fixed original producers may use the existing ordinary metadata writer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalMetadataProducer {
    AuditCheckpoint,
    Schema,
    Migrations,
    ReceiptFrontier,
    Installation,
    HostInventory,
    Compatibility,
    KeyMetadata,
    DriverFacts,
    ToolInventory,
    ProfileInventory,
    WorkspaceInventory,
}
impl OriginalMetadataProducer {
    fn leaf(self) -> &'static str {
        match self {
            Self::AuditCheckpoint => AUDIT_MATERIAL_LEAF,
            Self::Schema => "schema.jsonl",
            Self::Migrations => "migrations.jsonl",
            Self::ReceiptFrontier => "receipt-frontier.jsonl",
            Self::Installation => "installation.json",
            Self::HostInventory => "host-inventory.json",
            Self::Compatibility => "compatibility.json",
            Self::KeyMetadata => "key-metadata.json",
            Self::DriverFacts => "driver-facts.json",
            Self::ToolInventory => "tool-inventory.json",
            Self::ProfileInventory => "profile-inventory.jsonl",
            Self::WorkspaceInventory => "workspace-inventory.jsonl",
        }
    }
    fn material_id(self) -> &'static str {
        match self {
            Self::AuditCheckpoint => AUDIT_MATERIAL_ID,
            Self::Schema => "schema",
            Self::Migrations => "migrations",
            Self::ReceiptFrontier => "receipt-frontier",
            Self::Installation => "installation",
            Self::HostInventory => "host-inventory",
            Self::Compatibility => "compatibility",
            Self::KeyMetadata => "key-metadata",
            Self::DriverFacts => "driver-facts",
            Self::ToolInventory => "tool-inventory",
            Self::ProfileInventory => "profile-inventory",
            Self::WorkspaceInventory => "workspace-inventory",
        }
    }
    fn relative_path(self) -> &'static str {
        match self {
            Self::AuditCheckpoint => AUDIT_MATERIAL_PATH,
            Self::Schema => "metadata/schema.jsonl",
            Self::Migrations => "metadata/migrations.jsonl",
            Self::ReceiptFrontier => "metadata/receipt-frontier.jsonl",
            Self::Installation => "metadata/installation.json",
            Self::HostInventory => "metadata/host-inventory.json",
            Self::Compatibility => "metadata/compatibility.json",
            Self::KeyMetadata => "metadata/key-metadata.json",
            Self::DriverFacts => "metadata/driver-facts.json",
            Self::ToolInventory => "metadata/tool-inventory.json",
            Self::ProfileInventory => "metadata/profile-inventory.jsonl",
            Self::WorkspaceInventory => "metadata/workspace-inventory.jsonl",
        }
    }
    fn kind(self) -> WholePgMaterialKind {
        match self {
            Self::AuditCheckpoint => WholePgMaterialKind::AuditCheckpoint,
            Self::Schema => WholePgMaterialKind::SchemaChecksum,
            Self::Migrations => WholePgMaterialKind::MigrationChecksum,
            Self::ReceiptFrontier => WholePgMaterialKind::ReceiptFrontier,
            Self::Installation | Self::HostInventory => WholePgMaterialKind::InstallationRecord,
            Self::Compatibility | Self::DriverFacts | Self::ToolInventory =>
                WholePgMaterialKind::CompatibilityRecord,
            Self::KeyMetadata => WholePgMaterialKind::KeyMetadata,
            Self::ProfileInventory => WholePgMaterialKind::ProfileInventory,
            Self::WorkspaceInventory => WholePgMaterialKind::WorkspaceInventory,
        }
    }
    fn write_db_projection(
        self, facts: &CapturedDbFacts, output: &mut AuditMaterialWriter<'_>,
    ) -> Result<(), CaptureSqlFailure> {
        use std::io::Write as _;
        let (names, digest): (&[&str], [u8; 32]) = match self {
            Self::Schema => (&[
                "catalog_relations", "catalog_columns", "catalog_constraints", "catalog_indexes",
                "catalog_triggers", "catalog_rules", "catalog_functions", "catalog_enums",
                "catalog_extensions", "catalog_namespaces",
            ], facts.schema_sha256()),
            Self::Migrations => (&["migrations"], facts.migrations_sha256()),
            Self::ReceiptFrontier => (
                &["calls", "attempts", "runs", "occupancy", "run_events"],
                facts.frontier_sha256(),
            ),
            Self::AuditCheckpoint | Self::Installation | Self::HostInventory | Self::Compatibility
                | Self::KeyMetadata | Self::DriverFacts | Self::ToolInventory
                | Self::ProfileInventory | Self::WorkspaceInventory =>
                return Err(CaptureSqlFailure::UnknownLayout),
        };
        // This header describes the genuine fixed selection and its original facts digest.
        // It remains nonempty when that real selection has zero rows; it asserts no physical empty.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [0u8; 64];
        for (index, byte) in digest.iter().copied().enumerate() {
            encoded[index * 2] = HEX[usize::from(byte >> 4)];
            encoded[index * 2 + 1] = HEX[usize::from(byte & 15)];
        }
        let encoded = std::str::from_utf8(&encoded).map_err(|_| CaptureSqlFailure::RowInvalid)?;
        serde_json::to_writer(&mut *output, &(
            "wrokbot-capture-db-projection", 1u8, self.material_id(), names, encoded,
        )).map_err(|_| CaptureSqlFailure::Database)?;
        output.write_all(b"\n").map_err(|_| CaptureSqlFailure::Database)?;
        facts.write_projection(names, output)
    }

    fn write_ordinary_metadata(
        self, installation: &mut RetainedInstallationCapture,
        expected: &CaptureDbExpectation, key_id: Option<&str>,
        host: Option<&HostInventory>, output: &mut AuditMaterialWriter<'_>,
    ) -> Result<(), Fault> {
        let op = output.operation;
        installation.verify_original(op)?;
        let root = FileIdentity::of(installation.original_root(), op)?;
        match self {
            Self::Installation => {
                // These artifact-root observations belong to the original Store binding.
                // The installation root is the separate actual held descriptor above.
                let record = OriginalInstallationMaterial {
                    schema: "wrokbot-capture-installation", version: 1,
                    installation_root: root,
                    deployment_id: &expected.deployment_id, tenant_id: &expected.tenant_id,
                    dataset_id: &expected.dataset_id, instance_id: &expected.instance_id,
                    system_identifier: &expected.system_identifier, database_oid: expected.database_oid,
                    store_id: &expected.store_id,
                    artifact_root_device: &expected.root_device,
                    artifact_root_inode: &expected.root_inode,
                    artifact_root_uid: &expected.root_uid, key_id,
                };
                serde_json::to_writer(&mut *output, &record).map_err(|_| Fault::IoFailure)?;
            }
            Self::HostInventory => {
                let host = host.ok_or(Fault::MaterialMissing)?;
                if host.instance != expected.instance_id
                    || (host.device, host.inode, host.uid) != (root.device, root.inode, root.uid) {
                    return Err(Fault::SourceChanged);
                }
                // Serialize only the actual earlier classifier result. This proves no
                // absence of an independently configured external physical root.
                serde_json::to_writer(&mut *output, host).map_err(|_| Fault::IoFailure)?;
            }
            _ => return Err(Fault::IntentMismatch),
        }
        installation.verify_original(op)?;
        if FileIdentity::of(installation.original_root(), op)? != root {
            return Err(Fault::SourceChanged);
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct OriginalRootInventoryHeader<'a> {
    schema: &'static str,
    version: u8,
    material_id: &'static str,
    construction: &'static str,
    physical_root_disposition: &'static str,
    instance_id: &'a str,
    dataset_id: &'a str,
    deployment_id: &'a str,
    tenant_id: &'a str,
    system_identifier: &'a str,
    database_oid: u32,
    installation_root: FileIdentity,
    host_inventory_material_id: &'static str,
    logical_projection: &'static str,
    app_local_state: Option<OriginalPreferenceMaterialFact>,
}
fn write_original_root_inventory(
    producer: OriginalMetadataProducer,
    screen: &CaptureScreenAssemblySeal, installation: &mut RetainedInstallationCapture,
    expected: &CaptureDbExpectation, host: &HostInventory, facts: &CapturedDbFacts,
    preference: OriginalPreferenceMaterialFact, output: &mut AuditMaterialWriter<'_>,
) -> Result<(), MaterialEncodeFailure> {
    use std::io::Write as _;
    let op = output.operation;
    let binding = screen.assembly.as_ref().ok_or(MaterialEncodeFailure::Carrier(Fault::SourceChanged))?;
    let _original_application = binding.application.upgrade()
        .ok_or(MaterialEncodeFailure::Carrier(Fault::SourceChanged))?;
    let _original_screen = screen.original.upgrade()
        .ok_or(MaterialEncodeFailure::Carrier(Fault::SourceChanged))?;
    let construction = match binding.construction {
        OriginalDesktopConstruction::PostgresBuiltInToolsFreshScreen =>
            "postgres-built-in-tools-fresh-screen",
    };
    installation.verify_original(op).map_err(MaterialEncodeFailure::Carrier)?;
    let root = FileIdentity::of(installation.original_root(), op).map_err(MaterialEncodeFailure::Carrier)?;
    if host.instance != expected.instance_id || host.entries.is_empty()
        || (host.device, host.inode, host.uid) != (root.device, root.inode, root.uid)
        || facts.system_identifier() != expected.system_identifier
        || facts.database_oid() != expected.database_oid {
        return Err(MaterialEncodeFailure::Carrier(Fault::SourceChanged));
    }
    let cache = host.entries.iter().find(|entry| entry.name == "ui-preferences-v1");
    match preference {
        OriginalPreferenceMaterialFact::AbsentOriginalParentEnoent if cache.is_none() => {}
        OriginalPreferenceMaterialFact::PresentOriginalSnapshot { byte_length, .. }
            if cache.is_some_and(|entry| entry.kind == "preference-projection" && entry.bytes == byte_length) => {}
        _ => return Err(MaterialEncodeFailure::Carrier(Fault::SourceChanged)),
    }
    let (schema, logical_projection, app_local_state) = match producer {
        OriginalMetadataProducer::ProfileInventory => (
            "wrokbot-capture-profile-inventory", "profiles", Some(preference),
        ),
        OriginalMetadataProducer::WorkspaceInventory => (
            "wrokbot-capture-workspace-inventory", "workspaces", None,
        ),
        _ => return Err(MaterialEncodeFailure::Carrier(Fault::IntentMismatch)),
    };
    // This describes only the real sealed Desktop construction, not global/remote absence.
    // Logical rows follow in full; neither zero rows nor caller root lists form this proof.
    let header = OriginalRootInventoryHeader {
        schema, version: 1, material_id: producer.material_id(), construction,
        physical_root_disposition: "no-local-owner-in-original-sealed-construction",
        instance_id: &expected.instance_id, dataset_id: &expected.dataset_id,
        deployment_id: &expected.deployment_id, tenant_id: &expected.tenant_id,
        system_identifier: facts.system_identifier(), database_oid: facts.database_oid(),
        installation_root: root, host_inventory_material_id: "host-inventory",
        logical_projection, app_local_state,
    };
    serde_json::to_writer(&mut *output, &header)
        .map_err(|_| MaterialEncodeFailure::Carrier(Fault::IoFailure))?;
    output.write_all(b"\n").map_err(|_| MaterialEncodeFailure::Carrier(Fault::IoFailure))?;
    facts.write_projection(&[logical_projection], &mut *output).map_err(MaterialEncodeFailure::Sql)?;
    installation.verify_original(op).map_err(MaterialEncodeFailure::Carrier)?;
    if FileIdentity::of(installation.original_root(), op).map_err(MaterialEncodeFailure::Carrier)? != root {
        return Err(MaterialEncodeFailure::Carrier(Fault::SourceChanged));
    }
    Ok(())
}

/// Pure bounded DATA from the original joins; no owner, source or clock capability.
#[derive(serde::Serialize)]
pub(crate) struct OriginalDriverMaterial {
    schema: &'static str,
    version: u8,
    joined_before_freeze: u64,
    original_joins: Vec<OriginalDriverMaterialJoin>,
    live_proxy_futures: u64,
}
#[derive(serde::Serialize)]
struct OriginalDriverMaterialJoin {
    pool: &'static str,
    sequence: usize,
    task_id: String,
    outcome: &'static str,
    destruction: Option<&'static str>,
}
pub(crate) fn original_closed_driver_material(
    facts: &super::DriverClosureFacts, op: &CaptureOperation,
) -> Result<OriginalDriverMaterial, Fault> {
    use std::fmt::Write as _;
    use openbot_infra::db::desktop_local::OriginalDriverJoinOutcome;
    use openbot_infra::db::pool::ConnectionDestruction;
    let count = facts.original_joins().len();
    if count as u64 > op.profile().drivers.max_live_original_tasks
        || facts.live_proxy_futures() > op.profile().drivers.max_live_proxies {
        return Err(Fault::CapacityExceeded);
    }
    // Pinned Tokio1.53.1 Id is NonZeroU64 Display: at most twenty decimal bytes.
    let backing = (count as u64)
        .checked_mul((std::mem::size_of::<OriginalDriverMaterialJoin>() as u64)
            .checked_add(20).ok_or(Fault::BoundsOverflow)?)
        .ok_or(Fault::BoundsOverflow)?;
    let fixed = (std::mem::size_of::<Option<OriginalDriverMaterial>>() as u64)
        .checked_add(std::mem::size_of::<String>() as u64)
        .and_then(|n| n.checked_add(std::mem::size_of::<std::fmt::Arguments<'_>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<tokio::task::Id>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<OriginalDriverMaterialJoin>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, openbot_infra::db::desktop_local::OriginalDriverJoinFact>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Option<&openbot_infra::db::desktop_local::OriginalDriverJoinFact>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), std::fmt::Error>>() as u64))
        .ok_or(Fault::BoundsOverflow)?;
    let known = fixed.checked_add(backing).ok_or(Fault::BoundsOverflow)?;
    if known > op.profile().drivers.max_owner_metadata_bytes
        || known > op.profile().carrier.max_total_allocation_bytes {
        return Err(Fault::CapacityExceeded);
    }
    op.reserve_original_resources(0, known)?;
    let mut result = OriginalDriverMaterial {
        schema: "wrokbot-capture-driver-facts", version: 1,
        joined_before_freeze: facts.joined_before_freeze(),
        original_joins: Vec::new(), live_proxy_futures: facts.live_proxy_futures(),
    };
    result.original_joins.try_reserve_exact(count).map_err(|_| Fault::CapacityExceeded)?;
    if result.original_joins.capacity() != count { return Err(Fault::CapacityExceeded); }
    for fact in facts.original_joins() {
        let mut task_id = String::new();
        task_id.try_reserve_exact(20).map_err(|_| Fault::CapacityExceeded)?;
        if task_id.capacity() != 20 { return Err(Fault::CapacityExceeded); }
        write!(&mut task_id, "{}", fact.task_id()).map_err(|_| Fault::BoundsOverflow)?;
        if task_id.is_empty() || task_id.len() > 20 { return Err(Fault::BoundsOverflow); }
        let outcome = match fact.outcome() {
            OriginalDriverJoinOutcome::Returned => "returned",
            OriginalDriverJoinOutcome::Cancelled => "cancelled",
            OriginalDriverJoinOutcome::Panicked => "panicked",
        };
        let destruction = match fact.destruction() {
            Some(ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart) =>
                Some("connecting-owner-destroyed-before-start"),
            Some(ConnectionDestruction::ConnectingFutureDestroyed) =>
                Some("connecting-future-destroyed"),
            Some(ConnectionDestruction::ConnectionDestroyed) => Some("connection-destroyed"),
            None => None,
        };
        result.original_joins.push(OriginalDriverMaterialJoin {
            pool: fact.pool_name(), sequence: fact.sequence(), task_id, outcome, destruction,
        });
    }
    Ok(result)
}

fn write_original_key_material(
    expected: &CaptureDbExpectation, key_id: &str, key_version: i32,
    row: &openbot_infra::db::desktop_vault_canary::DesktopVaultCanaryRow,
    output: &mut AuditMaterialWriter<'_>,
) -> Result<(), Fault> {
    if row.dataset_id() != expected.dataset_id || row.deployment_id() != expected.deployment_id
        || row.tenant_id() != expected.tenant_id || row.key_id() != key_id
        || row.key_version() != key_version {
        return Err(Fault::SourceChanged);
    }
    // The original vault verifier already authenticated this same resident Row before
    // NormalCollected. No envelope, ciphertext, secret digest or new "confirmed" flag is output.
    let record = OriginalKeyMaterial {
        schema: "wrokbot-capture-key-metadata", version: 1,
        dataset_id: row.dataset_id(), deployment_id: row.deployment_id(),
        tenant_id: row.tenant_id(), key_id: row.key_id(),
        key_version: row.key_version(), canary_schema: row.canary_schema(),
        canary_material_id: "key-metadata",
    };
    serde_json::to_writer(&mut *output, &record).map_err(|_| Fault::IoFailure)
}

#[derive(serde::Serialize)]
struct OriginalKeyMaterial<'a> {
    schema: &'static str,
    version: u8,
    dataset_id: &'a str,
    deployment_id: &'a str,
    tenant_id: &'a str,
    key_id: &'a str,
    key_version: i32,
    canary_schema: i16,
    canary_material_id: &'static str,
}

#[derive(serde::Serialize)]
struct OriginalInstallationMaterial<'a> {
    schema: &'static str,
    version: u8,
    installation_root: FileIdentity,
    deployment_id: &'a str,
    tenant_id: &'a str,
    dataset_id: &'a str,
    instance_id: &'a str,
    system_identifier: &'a str,
    database_oid: u32,
    store_id: &'a str,
    artifact_root_device: &'a str,
    artifact_root_inode: &'a str,
    artifact_root_uid: &'a str,
    // The original state retains the key ID, not a separately observed key version.
    key_id: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum MaterialEncodeFailure {
    Sql(CaptureSqlFailure),
    Carrier(Fault),
}
impl MaterialEncodeFailure {
    fn fault(self) -> Fault {
        match self {
            Self::Sql(error) => sql_fault(error),
            Self::Carrier(fault) => fault,
        }
    }
}

// Fixed known requested slots of the already existing installation verifier. The
// original 32-byte instance decoder formats 64 hex bytes, not a 16-byte UUID.
// These fees cover known layouts only, never opaque allocator/serializer internals.
fn original_installation_verifier_metadata() -> Result<u64, Fault> {
    let identity = (std::mem::size_of::<FileIdentity>() as u64).checked_mul(6)
        .and_then(|n| n.checked_add((std::mem::size_of::<Result<FileIdentity, Fault>>() as u64).checked_mul(2)?))
        .ok_or(Fault::BoundsOverflow)?;
    let fixed = identity
        .checked_add(std::mem::size_of::<[u8; 128]>() as u64)
        .and_then(|n| n.checked_add(std::mem::size_of::<[u8; 1]>() as u64))
        .and_then(|n| n.checked_add((std::mem::size_of::<[u8; 32]>() as u64).checked_mul(3)?))
        .and_then(|n| n.checked_add(std::mem::size_of::<Option<[u8; 32]>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<[u8; 32],
            openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthorityError>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<std::str::Lines<'_>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Option<&str>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<&str>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<&str, std::str::Utf8Error>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<(&[[u8; 2]], &[u8])>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<std::iter::Enumerate<std::slice::Iter<'_, [u8; 2]>>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Option<(usize, &[u8; 2])>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<(usize, &[u8; 2])>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<std::array::IntoIter<u8, 32>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Option<u8>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<u8>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<String>() as u64))
        .and_then(|n| n.checked_add(64))
        .ok_or(Fault::BoundsOverflow)?;
    Ok(fixed)
}

struct AuditMaterialAttempt {
    started: bool,
    writable: Option<File>,
    readback: Option<File>,
    measured_result: Option<Result<(), MaterialEncodeFailure>>,
    written_result: Option<Result<(), MaterialEncodeFailure>>,
    measured_fault: Option<Fault>,
    written_fault: Option<Fault>,
    expected: Option<(u64, [u8; 32])>,
    material_id: Option<String>,
    relative_path: Option<String>,
}
impl AuditMaterialAttempt {
    fn new() -> Self {
        Self {
            started: false,
            writable: None,
            readback: None,
            measured_result: None,
            written_result: None,
            measured_fault: None,
            written_fault: None,
            expected: None,
            material_id: None,
            relative_path: None,
        }
    }
}

// The original encoder is used twice. No ordinary whole-payload byte Vec is made.
// A generic encoder error cannot erase the exact fault captured by its Write adapter.
struct AuditMaterialWriter<'a> {
    operation: &'a CaptureOperation,
    file: Option<&'a File>,
    maximum: u64,
    length: u64,
    sha: Sha256,
    fault: Option<Fault>,
}
impl AuditMaterialWriter<'_> {
    fn fail(&mut self, fault: Fault) -> std::io::Error {
        self.fault.get_or_insert(fault);
        std::io::Error::other("capture audit material write refused")
    }
}
impl std::io::Write for AuditMaterialWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(fault) = self.fault {
            return Err(self.fail(fault));
        }
        if let Err(fault) = self.operation.require_effect() {
            return Err(self.fail(fault));
        }
        let Some(end) = u64::try_from(bytes.len()).ok().and_then(|n| self.length.checked_add(n)) else {
            return Err(self.fail(Fault::BoundsOverflow));
        };
        if end > self.maximum {
            return Err(self.fail(Fault::CapacityExceeded));
        }
        let Some(file) = self.file else {
            self.length = end;
            self.sha.update(bytes);
            return Ok(bytes.len());
        };
        let observed = file.write_at(bytes, self.length);
        // Actual progress is recorded before the fallible same-clock postcheck.
        if let Ok(n) = &observed {
            if *n <= bytes.len() {
                self.length += *n as u64;
                self.sha.update(&bytes[..*n]);
            }
        }
        if let Err(fault) = self.operation.require_effect() {
            return Err(self.fail(fault));
        }
        match observed {
            Ok(n) if n <= bytes.len() && (n != 0 || bytes.is_empty()) => Ok(n),
            // Interrupted is also a terminal refusal; there is no hidden Write retry.
            Ok(_) | Err(_) => Err(self.fail(Fault::IoFailure)),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.operation.require_effect().map_err(|fault| self.fail(fault))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AuditFileIdentity {
    identity: FileIdentity,
    ctime: i64,
    ctime_ns: i64,
}
fn audit_held_identity(file: &File, op: &CaptureOperation) -> Result<AuditFileIdentity, Fault> {
    op.require_effect()?;
    let observed = file.metadata();
    op.require_effect()?;
    let m = observed.map_err(|_| Fault::IoFailure)?;
    if !m.is_file() || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o600 || m.nlink() != 1 {
        return Err(Fault::PathUnsafe);
    }
    Ok(AuditFileIdentity {
        identity: FileIdentity {
            device: m.dev(), inode: m.ino(), uid: m.uid(), mode: m.mode(),
            links: m.nlink(), bytes: m.len(), mtime: m.mtime(), mtime_ns: m.mtime_nsec(),
        },
        ctime: m.ctime(), ctime_ns: m.ctime_nsec(),
    })
}
fn audit_named_identity(
    parent: &File, expected: AuditFileIdentity, producer: OriginalMetadataProducer,
    op: &CaptureOperation,
) -> Result<(), Fault> {
    op.require_effect()?;
    let observed = rustix::fs::statat(parent, producer.leaf(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
    op.require_effect()?;
    let named = observed.map_err(|_| Fault::SourceChanged)?;
    let held = expected.identity;
    if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
        || (named.st_dev as u64, named.st_ino as u64, named.st_uid, named.st_mode as u32, named.st_nlink as u64)
            != (held.device, held.inode, held.uid, held.mode, held.links)
        || u64::try_from(named.st_size).ok() != Some(held.bytes) {
        return Err(Fault::SourceChanged);
    }
    Ok(())
}
fn audit_parent_identity(
    parent: &File, path: &std::path::Path, op: &CaptureOperation,
) -> Result<(u64, u64, u32, u32, u64), Fault> {
    op.require_effect()?;
    let observed = parent.metadata();
    op.require_effect()?;
    let held = observed.map_err(|_| Fault::IoFailure)?;
    op.require_effect()?;
    let observed = std::fs::symlink_metadata(path);
    op.require_effect()?;
    let named = observed.map_err(|_| Fault::IoFailure)?;
    let identity = (held.dev(), held.ino(), held.uid(), held.mode(), held.nlink());
    if !held.is_dir() || !named.is_dir()
        || held.uid() != rustix::process::geteuid().as_raw()
        || held.mode() & 0o7777 != 0o700
        || identity != (named.dev(), named.ino(), named.uid(), named.mode(), named.nlink()) {
        return Err(Fault::PathUnsafe);
    }
    // Directory mtime is intentionally not frozen across the real leaf creation.
    Ok(identity)
}

// Compare the actual directory FD with its one fixed original parent entry.
fn original_material_directory_identity(
    directory: &File, parent: &File, name: &str, op: &CaptureOperation,
) -> Result<(u64, u64, u32, u32, u64), Fault> {
    op.require_effect()?;
    let held = directory.metadata();
    op.require_effect()?;
    let held = held.map_err(|_| Fault::IoFailure)?;
    op.require_effect()?;
    let named = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
    op.require_effect()?;
    let named = named.map_err(|_| Fault::PathUnsafe)?;
    let identity = (held.dev(), held.ino(), held.uid(), held.mode(), held.nlink());
    if !held.is_dir()
        || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
        || held.uid() != rustix::process::geteuid().as_raw()
        || held.mode() & 0o7777 != 0o700
        || identity != (named.st_dev as u64, named.st_ino, named.st_uid,
            u32::from(named.st_mode), u64::from(named.st_nlink))
    {
        return Err(Fault::PathUnsafe);
    }
    Ok(identity)
}

impl NormalCaptureMaterials {
    /// Only the same post-Intent Normal owner creates this fixed operation-local layout.
    pub(crate) fn prepare_original_material_spool(
        &mut self, parent: &File, parent_path: &std::path::Path, op: &CaptureOperation,
    ) -> Result<(), Fault> {
        op.require_effect()?;
        if self.phase != ReadPhase::PreferencesClosing || self.material_layout_started
            || self.material_layout_ready
            || self.material_directories.iter().any(Option::is_some)
            || self.material_directory_results.iter().any(Option::is_some)
            || self.material_directory_open_entered.iter().any(|entered| *entered)
        {
            return Err(Fault::IntentMismatch);
        }
        let bounds = &op.profile().carrier;
        let fixed_path = "materials/artifact-spool";
        if bounds.max_directories < 3 || bounds.max_path_depth < 2
            || bounds.max_path_bytes < fixed_path.len() as u64
        {
            return Err(Fault::CapacityExceeded);
        }
        // This is one conservative prepaid slice for exactly these three new FDs.
        // The original local FD counter below cross-checks it; it must not debit it twice.
        type DirectoryIdentity = (u64, u64, u32, u32, u64);
        // Each array expression, IntoIter and current/next tuple remains a concrete
        // Rust value. Charge the larger of the two disjoint loop phases, not zero.
        let creation_loop = (std::mem::size_of::<[&str; 3]>() as u64)
            .checked_add(std::mem::size_of::<std::iter::Enumerate<std::array::IntoIter<&str, 3>>>() as u64)
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<(usize, &str)>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<(usize, &str)>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        let validation_loop = (std::mem::size_of::<[(usize, &str); 2]>() as u64)
            .checked_add(std::mem::size_of::<std::array::IntoIter<(usize, &str), 2>>() as u64)
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<(usize, &str)>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<(usize, &str)>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        // Conservative simultaneous slots: root before/after/final, loop identity,
        // held/named helper tuples and two call-return slots. Result wrappers are
        // separate values; ordinary IO results/OwnedFd temporaries are not erased.
        let identities = (std::mem::size_of::<DirectoryIdentity>() as u64).checked_mul(8)
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<DirectoryIdentity, Fault>>() as u64).checked_mul(3)?))
            .ok_or(Fault::BoundsOverflow)?;
        let original_results = (std::mem::size_of::<Result<(), rustix::io::Errno>>() as u64)
            .checked_add(std::mem::size_of::<Result<rustix::fd::OwnedFd, rustix::io::Errno>>() as u64)
            .and_then(|n| n.checked_add(std::mem::size_of::<rustix::fd::OwnedFd>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<File>() as u64))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<(), std::io::Error>>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<(), Fault>>() as u64).checked_mul(2)?))
            .ok_or(Fault::BoundsOverflow)?;
        let fixed = (std::mem::size_of::<[Option<File>; 3]>() as u64)
            .checked_add(std::mem::size_of::<[Option<Result<(), rustix::io::Errno>>; 3]>() as u64)
            .and_then(|n| n.checked_add(std::mem::size_of::<[bool; 3]>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<OriginalMaterialDirectoryBinding>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<[Option<OriginalMaterialDirectoryBinding>; 3]>() as u64))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<bool>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::fs::Metadata>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<rustix::fs::Stat>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<std::fs::Metadata, std::io::Error>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>() as u64))
            .and_then(|n| n.checked_add(creation_loop.max(validation_loop)))
            .and_then(|n| n.checked_add(identities))
            .and_then(|n| n.checked_add(original_results))
            .and_then(|n| n.checked_add((std::mem::size_of::<std::path::PathBuf>() as u64).checked_mul(2)?))
            // One join("materials/metadata"): original P-byte backing plus a
            // requested max(2P,P+19) replacement is at most 3*(P+32).
            .and_then(|n| n.checked_add((parent_path.as_os_str().len() as u64).checked_add(32)?.checked_mul(3)?))
            .ok_or(Fault::BoundsOverflow)?;
        if self.local_new_fd_admissions.checked_add(3).ok_or(Fault::BoundsOverflow)?
            > bounds.max_open_files
        {
            return Err(Fault::CapacityExceeded);
        }
        op.reserve_original_resources(3, fixed)?;
        self.material_layout_started = true;
        let root_before = audit_parent_identity(parent, parent_path, op)?;
        self.material_layout_parent = Some((root_before.0, root_before.1, root_before.2, root_before.3));
        for (index, name) in ["materials", "artifact-spool", "metadata"].into_iter().enumerate() {
            op.require_effect()?;
            let created = {
                let original = if index == 0 { parent }
                    else { self.material_directories[0].as_ref().ok_or(Fault::MaterialMissing)? };
                rustix::fs::mkdirat(original, name, Mode::from_raw_mode(0o700))
            };
            // Actual success/errno is resident before the fallible original E postcheck.
            self.material_directory_results[index] = Some(created);
            op.require_effect()?;
            self.material_directory_results[index].ok_or(Fault::MaterialMissing)?
                .map_err(|_| Fault::PathUnsafe)?;
            reserve_local_new_material_fd(&mut self.local_new_fd_admissions, bounds.max_open_files)?;
            self.material_directory_open_entered[index] = true;
            op.require_effect()?;
            let opened = {
                let original = if index == 0 { parent }
                    else { self.material_directories[0].as_ref().ok_or(Fault::MaterialMissing)? };
                rustix::fs::openat(original, name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty())
            };
            match opened {
                Ok(file) => self.material_directories[index] = Some(File::from(file)),
                Err(_) => { op.require_effect()?; return Err(Fault::IoFailure); }
            }
            op.require_effect()?;
            let original = if index == 0 { parent }
                else { self.material_directories[0].as_ref().ok_or(Fault::MaterialMissing)? };
            let directory = self.material_directories[index].as_ref().ok_or(Fault::MaterialMissing)?;
            let identity = original_material_directory_identity(directory, original, name, op)?;
            self.material_directory_bindings[index] = Some((identity.0, identity.1, identity.2, identity.3));
            // A successful exclusive mkdir creates a genuine new empty directory.
            // This structural check does not stand in for the artifact worker's later enumeration.
            if identity.4 != 2 { return Err(Fault::SourceChanged); }
            op.require_effect()?;
            let synced = directory.sync_all();
            op.require_effect()?;
            synced.map_err(|_| Fault::IoFailure)?;
            op.require_effect()?;
            let synced = original.sync_all();
            op.require_effect()?;
            synced.map_err(|_| Fault::IoFailure)?;
        }
        let root_after = audit_parent_identity(parent, parent_path, op)?;
        // Own mkdir legitimately changes parent nlink/mtime; its original identity may not change.
        if (root_before.0, root_before.1, root_before.2, root_before.3)
            != (root_after.0, root_after.1, root_after.2, root_after.3)
        {
            return Err(Fault::SourceChanged);
        }
        let materials = self.material_directories[0].as_ref().ok_or(Fault::MaterialMissing)?;
        let final_root = original_material_directory_identity(materials, parent, "materials", op)?;
        if final_root.4 != 4 { return Err(Fault::SourceChanged); }
        for (slot, name) in [(1usize, "artifact-spool"), (2usize, "metadata")] {
            let child = self.material_directories[slot].as_ref().ok_or(Fault::MaterialMissing)?;
            if original_material_directory_identity(child, materials, name, op)?.4 != 2 {
                return Err(Fault::SourceChanged);
            }
        }
        op.require_effect()?;
        self.material_layout_ready = true;
        Ok(())
    }
    fn verify_original_material_spool(
        &self, parent: &File, parent_path: &std::path::Path, op: &CaptureOperation,
    ) -> Result<(), Fault> {
        if !self.material_layout_started || !self.material_layout_ready
            || self.material_directory_results.iter().any(|r| !matches!(r, Some(Ok(()))))
            || self.material_directory_open_entered.iter().any(|entered| !entered) {
            return Err(Fault::MaterialMissing);
        }
        // New validation's own fixed slots; no new FD, directory, budget or recreated spool.
        let known = (std::mem::size_of::<[(usize, &str); 3]>() as u64)
            .checked_add(std::mem::size_of::<std::array::IntoIter<(usize, &str), 3>>() as u64)
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<(usize, &str)>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<(usize, &str)>() as u64))
            .and_then(|n| n.checked_add((std::mem::size_of::<(u64, u64, u32, u32, u64)>() as u64).checked_mul(6)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<(u64, u64, u32, u32, u64), Fault>>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::fs::Metadata>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<std::fs::Metadata, std::io::Error>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<rustix::fs::Stat>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        op.reserve_original_resources(0, known)?;
        let actual = audit_parent_identity(parent, parent_path, op)?;
        if self.material_layout_parent != Some((actual.0, actual.1, actual.2, actual.3)) {
            return Err(Fault::SourceChanged);
        }
        for (slot, name) in [(0usize, "materials"), (1usize, "artifact-spool"), (2usize, "metadata")] {
            let original = if slot == 0 { parent }
                else { self.material_directories[0].as_ref().ok_or(Fault::MaterialMissing)? };
            let directory = self.material_directories[slot].as_ref().ok_or(Fault::MaterialMissing)?;
            let actual = original_material_directory_identity(directory, original, name, op)?;
            if self.material_directory_bindings[slot]
                != Some((actual.0, actual.1, actual.2, actual.3)) {
                return Err(Fault::SourceChanged);
            }
        }
        op.require_effect()
    }

    pub(crate) fn begin_original_audit_material(&mut self) -> Result<(), Fault> {
        if self.phase != ReadPhase::SourcesClosed || self.audit.started
            || self.checkpoint.is_none() || !self.files.is_empty() {
            return Err(Fault::IntentMismatch);
        }
        // Consumed before any new producer effect; a failed attempt is never retried.
        self.audit.started = true;
        Ok(())
    }
    fn append_original_preference_material(&mut self, op: &CaptureOperation) -> Result<(), Fault> {
        if self.phase != ReadPhase::SourcesClosed || !self.material_layout_ready {
            return Err(Fault::IntentMismatch);
        }
        let host = self.host.as_ref().ok_or(Fault::MaterialMissing)?;
        let source_entry = host.entries.iter().find(|entry| entry.name == "ui-preferences-v1");
        let (plain_len, plain_sha256) = match self.preference_fact.ok_or(Fault::MaterialMissing)? {
            OriginalPreferenceMaterialFact::AbsentOriginalParentEnoent => {
                let snapshot = match self.preference_result.as_ref().ok_or(Fault::MaterialMissing)? {
                    Ok(snapshot) => snapshot,
                    Err(fault) => return Err(*fault),
                };
                if source_entry.is_some() || snapshot.byte_length().is_some() || snapshot.sha256().is_some() {
                    return Err(Fault::SourceChanged);
                }
                return Ok(());
            }
            OriginalPreferenceMaterialFact::PresentOriginalSnapshot { byte_length, sha256 } => {
                let source_entry = source_entry.ok_or(Fault::SourceChanged)?;
                if source_entry.kind != "preference-projection" || source_entry.bytes != byte_length {
                    return Err(Fault::SourceChanged);
                }
                (byte_length, sha256)
            }
        };
        let snapshot = match self.preference_result.as_ref().ok_or(Fault::MaterialMissing)? {
            Ok(snapshot) => snapshot,
            Err(fault) => return Err(*fault),
        };
        if (snapshot.byte_length(), snapshot.sha256()) != (Some(plain_len), Some(plain_sha256))
            || self.files.iter().any(|file| file.material_id == "ui-preferences-v1") {
            return Err(Fault::IntentMismatch);
        }
        let bounds = &op.profile().carrier;
        let count = self.files.len().checked_add(1).ok_or(Fault::BoundsOverflow)?;
        let old_capacity = self.files.capacity();
        let requested_capacity = old_capacity.max(count);
        let backing = (requested_capacity as u64)
            .checked_mul(std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)
            .ok_or(Fault::BoundsOverflow)?;
        let new_backing = if requested_capacity > old_capacity { backing } else { 0 };
        let id = "ui-preferences-v1";
        let path = "metadata/ui-preferences-v1.json";
        let fixed = (std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)
            .checked_add((std::mem::size_of::<String>() as u64).checked_mul(2).ok_or(Fault::BoundsOverflow)?)
            .and_then(|n| n.checked_add(std::mem::size_of::<crate::preferences::PreferenceCaptureSnapshot>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<crate::preferences::PreferenceCaptureSnapshot, Fault>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<File>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<(u64, [u8; 32])>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, CaptureOwnedMaterialFile>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<&CaptureOwnedMaterialFile>>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        let paths = (id.len() as u64).checked_add(path.len() as u64).ok_or(Fault::BoundsOverflow)?;
        let known = fixed.checked_add(paths).and_then(|n| n.checked_add(backing)).ok_or(Fault::BoundsOverflow)?;
        let plain_total = self.files.iter().try_fold(plain_len, |n, f|
            n.checked_add(f.plain_len).ok_or(Fault::BoundsOverflow))?;
        if count as u64 > bounds.max_material_files || plain_len == 0
            || plain_len > bounds.max_single_plain_bytes
            || plain_total > bounds.max_material_plain_bytes || plain_total > bounds.max_spool_bytes
            || plain_total > bounds.max_snapshot_bytes || id.len() as u64 > bounds.max_path_bytes
            || path.len() as u64 > bounds.max_path_bytes || known > bounds.max_metadata_bytes
            || known > bounds.max_total_allocation_bytes {
            return Err(Fault::CapacityExceeded);
        }
        // The original snapshot output is already charged: this pure move creates no FD.
        op.reserve_original_resources(0, fixed.checked_add(paths)
            .and_then(|n| n.checked_add(new_backing)).ok_or(Fault::BoundsOverflow)?)?;
        self.files.try_reserve_exact(1).map_err(|_| Fault::CapacityExceeded)?;
        let material_id = id.to_owned();
        let relative_path = path.to_owned();
        if self.files.capacity() != requested_capacity || material_id.capacity() != id.len()
            || relative_path.capacity() != path.len() {
            return Err(Fault::CapacityExceeded);
        }
        op.require_effect()?;
        // All fallible work preceded taking this exact original output FD.
        let snapshot = self.preference_result.take()
            .expect("checked original preference result remains resident")
            .expect("checked successful original preference snapshot remains resident");
        let file = snapshot.into_owned_file()
            .expect("private present snapshot always owns its original output");
        self.files.push(CaptureOwnedMaterialFile {
            kind: WholePgMaterialKind::ProfileInventory, material_id, relative_path,
            file, plain_len, plain_sha256,
        });
        Ok(())
    }

    pub(crate) fn retain_original_auxiliary_materials(
        &mut self,
        provenance: &mut Option<(WholePgProvenanceClaim, Vec<u8>)>,
        drivers: &mut Option<OriginalDriverMaterial>,
    ) -> Result<(), Fault> {
        if self.phase != ReadPhase::SourcesClosed || self.original_provenance.is_some()
            || self.tool_inventory.is_some() || self.original_drivers.is_some() {
            return Err(Fault::IntentMismatch);
        }
        let (claim, bytes) = provenance.as_ref().ok_or(Fault::MaterialMissing)?;
        if claim.tool_inventory_material_id != OriginalMetadataProducer::ToolInventory.material_id()
            || bytes.is_empty() || drivers.is_none() {
            return Err(Fault::MaterialMissing);
        }
        // All preconditions precede the exact takes. No allocation, IO or fallible gap follows.
        let (claim, bytes) = provenance.take().expect("checked original provenance remains resident");
        self.original_provenance = Some(claim);
        self.tool_inventory = Some(bytes);
        self.original_drivers = drivers.take();
        Ok(())
    }
    pub(crate) fn freeze_original_audit_material(
        &mut self, originals: &mut Option<Vec<CaptureOwnedMaterialFile>>,
        parent: &File, parent_path: &std::path::Path, op: &CaptureOperation,
    ) -> Result<(), Fault> {
        if self.phase != ReadPhase::SourcesClosed || !self.audit.started
            || !self.files.is_empty() || originals.is_none()
            || self.audit.measured_result.is_some() || self.audit.writable.is_some()
            || self.audit.readback.is_some()
            || self.schema_projection.started || self.migration_projection.started
            || self.receipt_projection.started || self.installation_projection.started
            || self.host_inventory_projection.started || self.compatibility_projection.started
            || self.key_metadata_projection.started || self.driver_facts_projection.started
            || self.tool_inventory_projection.started || self.profile_inventory_projection.started
            || self.workspace_inventory_projection.started {
            return Err(Fault::IntentMismatch);
        }
        self.verify_original_material_spool(parent, parent_path, op)?;
        let metadata_path = parent_path.join("materials/metadata");
        // No allocation, await or fallible gap after taking the resident original Vec.
        match originals.take() {
            Some(files) => self.files = files,
            None => return Err(Fault::MaterialMissing),
        }
        self.freeze_original_metadata_leaf(
            OriginalMetadataProducer::AuditCheckpoint, &metadata_path, op,
        )?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::Schema, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::Migrations, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::ReceiptFrontier, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::Installation, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::HostInventory, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::Compatibility, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::KeyMetadata, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::DriverFacts, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::ToolInventory, &metadata_path, op)?;
        self.append_original_preference_material(op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::ProfileInventory, &metadata_path, op)?;
        self.freeze_original_metadata_leaf(OriginalMetadataProducer::WorkspaceInventory, &metadata_path, op)
    }
    fn freeze_original_metadata_leaf(
        &mut self, producer: OriginalMetadataProducer,
        parent_path: &std::path::Path, op: &CaptureOperation,
    ) -> Result<(), Fault> {
        if self.phase != ReadPhase::SourcesClosed || !self.material_layout_ready {
            return Err(Fault::IntentMismatch);
        }
        let Self {
            audit, schema_projection, migration_projection, receipt_projection,
            installation_projection, host_inventory_projection, compatibility_projection,
            key_metadata_projection, driver_facts_projection, tool_inventory_projection,
            profile_inventory_projection, workspace_inventory_projection,
            installation, screen, preference_fact, expected: source_expected, key_id, key_version, local_canary,
            original_drivers, original_provenance, tool_inventory, host,
            checkpoint, normal, files, material_directories, local_new_fd_admissions, ..
        } = self;
        let attempt = match producer {
            OriginalMetadataProducer::AuditCheckpoint => audit,
            OriginalMetadataProducer::Schema => schema_projection,
            OriginalMetadataProducer::Migrations => migration_projection,
            OriginalMetadataProducer::ReceiptFrontier => receipt_projection,
            OriginalMetadataProducer::Installation => installation_projection,
            OriginalMetadataProducer::HostInventory => host_inventory_projection,
            OriginalMetadataProducer::Compatibility => compatibility_projection,
            OriginalMetadataProducer::KeyMetadata => key_metadata_projection,
            OriginalMetadataProducer::DriverFacts => driver_facts_projection,
            OriginalMetadataProducer::ToolInventory => tool_inventory_projection,
            OriginalMetadataProducer::ProfileInventory => profile_inventory_projection,
            OriginalMetadataProducer::WorkspaceInventory => workspace_inventory_projection,
        };
        if (producer == OriginalMetadataProducer::AuditCheckpoint && !attempt.started)
            || (producer != OriginalMetadataProducer::AuditCheckpoint && attempt.started)
            || attempt.measured_result.is_some() || attempt.written_result.is_some()
            || attempt.writable.is_some() || attempt.readback.is_some()
            || attempt.expected.is_some() || attempt.material_id.is_some()
            || attempt.relative_path.is_some() {
            return Err(Fault::IntentMismatch);
        }
        // Each fixed attempt is consumed before any allocation/IO and is never retried/refunded.
        attempt.started = true;
        let parent = material_directories[2].as_ref().ok_or(Fault::MaterialMissing)?;
        op.require_effect()?;
        let bounds = &op.profile().carrier;
        let count = files.len().checked_add(1).ok_or(Fault::BoundsOverflow)?;
        let old_capacity = files.capacity();
        let requested_capacity = old_capacity.max(count);
        let new_backing = if requested_capacity > old_capacity {
            (requested_capacity as u64)
                .checked_mul(std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)
                .ok_or(Fault::BoundsOverflow)?
        } else { 0 };
        // Only the original checkpoint encoder allocates these two IDs and three hash Strings.
        // DB headers instead use one fixed digest/hex pair and borrowed fixed names.
        let encoder_metadata = if producer == OriginalMetadataProducer::AuditCheckpoint {
            op.profile().sql.max_field_bytes.checked_mul(2)
                .and_then(|n| n.checked_add(64 * 3))
                .and_then(|n| n.checked_add(std::mem::size_of::<String>() as u64 * 5))
                .ok_or(Fault::BoundsOverflow)?
        } else if matches!(producer, OriginalMetadataProducer::Schema
            | OriginalMetadataProducer::Migrations | OriginalMetadataProducer::ReceiptFrontier) {
            (std::mem::size_of::<[u8; 32]>() as u64)
                .checked_add(std::mem::size_of::<[u8; 64]>() as u64)
                .and_then(|n| n.checked_add(std::mem::size_of::<(&str, u8, &str, &[&str], &str)>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<std::iter::Enumerate<
                    std::iter::Copied<std::slice::Iter<'_, u8>>>>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<Option<(usize, u8)>>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<(usize, u8)>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<Result<&str, std::str::Utf8Error>>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<serde_json::Serializer<&mut AuditMaterialWriter<'_>>>() as u64))
                .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), serde_json::Error>>() as u64))
                .ok_or(Fault::BoundsOverflow)?
        } else {

            let serializer = (std::mem::size_of::<serde_json::Serializer<&mut AuditMaterialWriter<'_>>>() as u64)
                .checked_add(std::mem::size_of::<Result<(), serde_json::Error>>() as u64)
                .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), Fault>>() as u64))
                .ok_or(Fault::BoundsOverflow)?;
            match producer {
                OriginalMetadataProducer::Installation => {
                    let expected = source_expected.as_ref().ok_or(Fault::MaterialMissing)?;
                    let mut retained = (std::mem::size_of::<Option<CaptureDbExpectation>>() as u64)
                        .checked_add(std::mem::size_of::<Option<String>>() as u64)
                        .ok_or(Fault::BoundsOverflow)?;
                    for capacity in [
                        expected.deployment_id.capacity(), expected.tenant_id.capacity(),
                        expected.dataset_id.capacity(), expected.instance_id.capacity(),
                        expected.system_identifier.capacity(), expected.store_id.capacity(),
                        expected.root_device.capacity(), expected.root_inode.capacity(),
                        expected.root_uid.capacity(), key_id.as_ref().map_or(0, String::capacity),
                    ] {
                        retained = retained.checked_add(u64::try_from(capacity).map_err(|_| Fault::BoundsOverflow)?)
                            .ok_or(Fault::BoundsOverflow)?;
                    }
                    retained.checked_add(serializer)
                        .and_then(|n| n.checked_add(std::mem::size_of::<OriginalInstallationMaterial<'_>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<[usize; 10]>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<std::array::IntoIter<usize, 10>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<Option<usize>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<usize>() as u64))
                        .and_then(|n| n.checked_add(original_installation_verifier_metadata().ok()?))
                        .ok_or(Fault::BoundsOverflow)?
                }
                OriginalMetadataProducer::HostInventory => {
                    let host = host.as_ref().ok_or(Fault::MaterialMissing)?;
                    let mut retained = (std::mem::size_of::<Option<HostInventory>>() as u64)
                        .checked_add(u64::try_from(host.entries.capacity()).map_err(|_| Fault::BoundsOverflow)?
                            .checked_mul(std::mem::size_of::<HostEntry>() as u64).ok_or(Fault::BoundsOverflow)?)
                        .and_then(|n| n.checked_add(u64::try_from(host.instance.capacity()).ok()?))
                        .ok_or(Fault::BoundsOverflow)?;
                    for entry in &host.entries {
                        retained = retained.checked_add(u64::try_from(entry.name.capacity()).map_err(|_| Fault::BoundsOverflow)?)
                            .ok_or(Fault::BoundsOverflow)?;
                    }
                    retained.checked_add(serializer)
                        .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, HostEntry>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<Option<&HostEntry>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<&HostEntry>() as u64))
                        .and_then(|n| n.checked_add(original_installation_verifier_metadata().ok()?))
                        .ok_or(Fault::BoundsOverflow)?
                }
                OriginalMetadataProducer::Compatibility => {
                    // This getter includes its Option body and all actual retained backing.
                    // Do not add the outer Reviewed request body a second time here.
                    op.reviewed().original_compatibility_metadata_bytes()?
                        .checked_add(serializer).ok_or(Fault::BoundsOverflow)?
                }
                OriginalMetadataProducer::ProfileInventory | OriginalMetadataProducer::WorkspaceInventory => {
                    if preference_fact.is_none() || host.is_none() || normal.is_none()
                        || screen.assembly.is_none() {
                        return Err(Fault::MaterialMissing);
                    }
                    serializer.checked_add(std::mem::size_of::<OriginalRootInventoryHeader<'_>>() as u64)
                        .and_then(|n| n.checked_add(std::mem::size_of::<Arc<dyn openbot_application::ApplicationService>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<Arc<dyn openbot_application::ScreenSessionAdministration>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<Option<Arc<dyn openbot_application::ApplicationService>>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<Option<Arc<dyn openbot_application::ScreenSessionAdministration>>>() as u64))
                        .and_then(|n| n.checked_add((std::mem::size_of::<FileIdentity>() as u64).checked_mul(4)?))
                        .and_then(|n| n.checked_add(std::mem::size_of::<Result<FileIdentity, Fault>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, HostEntry>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<Option<&HostEntry>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<[&str; 1]>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<(&str, &str, Option<OriginalPreferenceMaterialFact>)>() as u64))
                        .and_then(|n| n.checked_add((std::mem::size_of::<Result<(), MaterialEncodeFailure>>() as u64).checked_mul(2)?))
                        .and_then(|n| n.checked_add(original_installation_verifier_metadata().ok()?))
                        .ok_or(Fault::BoundsOverflow)?
                }
                OriginalMetadataProducer::KeyMetadata => {
                    if key_version.is_none() || local_canary.is_none() { return Err(Fault::SecretInvalid); }
                    serializer.checked_add(std::mem::size_of::<OriginalKeyMaterial<'_>>() as u64)
                        .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), Fault>>() as u64))
                        .ok_or(Fault::BoundsOverflow)?
                }
                OriginalMetadataProducer::DriverFacts => {
                    if original_drivers.is_none() { return Err(Fault::MaterialMissing); }
                    // The owned Vec/ID backing was prepaid before the pure DATA projection.
                    serializer.checked_add(std::mem::size_of::<&OriginalDriverMaterial>() as u64)
                        .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, OriginalDriverMaterialJoin>>() as u64))
                        .and_then(|n| n.checked_add(std::mem::size_of::<Option<&OriginalDriverMaterialJoin>>() as u64))
                        .ok_or(Fault::BoundsOverflow)?
                }
                OriginalMetadataProducer::ToolInventory => {
                    if tool_inventory.as_ref().is_none_or(Vec::is_empty)
                        || original_provenance.as_ref().is_none_or(|claim|
                            claim.tool_inventory_material_id != producer.material_id()) {
                        return Err(Fault::MaterialMissing);
                    }
                    // Same authenticated bytes are borrowed directly, never encoded into another Vec.
                    (std::mem::size_of::<&[u8]>() as u64)
                        .checked_add(std::mem::size_of::<Result<(), std::io::Error>>() as u64)
                        .ok_or(Fault::BoundsOverflow)?
                }
                _ => return Err(Fault::IntentMismatch),
            }
        };
        // Concrete simultaneous original attempt/writer/identity/result slots. These fees cover
        // known requested Rust layouts, never allocator or serializer opaque internals.
        let fixed = (std::mem::size_of::<AuditMaterialAttempt>() as u64)
            .checked_add((std::mem::size_of::<AuditMaterialWriter<'_>>() as u64)
                .checked_mul(2).ok_or(Fault::BoundsOverflow)?)
            .and_then(|n| n.checked_add((std::mem::size_of::<AuditFileIdentity>() as u64).checked_mul(4)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<FileIdentity>() as u64))
            .and_then(|n| n.checked_add((std::mem::size_of::<(u64, [u8; 32])>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<Sha256>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::fs::Metadata>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<std::fs::Metadata, std::io::Error>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<rustix::fs::Stat>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fd::OwnedFd, rustix::io::Errno>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<rustix::fd::OwnedFd>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<File>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<usize, std::io::Error>>() as u64))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<(), std::io::Error>>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<(), Fault>>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(encoder_metadata))
            .ok_or(Fault::BoundsOverflow)?;
        let path_bytes = (producer.material_id().len() as u64)
            .checked_add(producer.relative_path().len() as u64).ok_or(Fault::BoundsOverflow)?;
        let requested_metadata = fixed.checked_add(path_bytes)
            .and_then(|n| n.checked_add((requested_capacity as u64)
                .checked_mul(std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)?))
            .ok_or(Fault::BoundsOverflow)?;
        if count as u64 > bounds.max_material_files
            || producer.relative_path().len() as u64 > bounds.max_path_bytes
            || producer.material_id().len() as u64 > bounds.max_path_bytes
            || producer.leaf().len() as u64 > bounds.max_path_bytes
            || requested_metadata > bounds.max_metadata_bytes || requested_metadata > bounds.max_total_allocation_bytes
            || local_new_fd_admissions.checked_add(2).ok_or(Fault::BoundsOverflow)? > bounds.max_open_files {
            return Err(Fault::CapacityExceeded);
        }
        // The two original open-producing calls are prepaid once, before allocations or IO.
        // A full replacement backing is charged on actual growth, retaining the old fee for
        // old+new coexistence; an already reserved backing is not charged again.
        let new_metadata = fixed.checked_add(path_bytes)
            .and_then(|n| n.checked_add(new_backing)).ok_or(Fault::BoundsOverflow)?;
        op.reserve_original_resources(2, new_metadata)?;
        files.try_reserve_exact(1).map_err(|_| Fault::CapacityExceeded)?;
        attempt.material_id = Some(producer.material_id().to_owned());
        attempt.relative_path = Some(producer.relative_path().to_owned());
        if files.capacity() != requested_capacity
            || attempt.material_id.as_ref().ok_or(Fault::MaterialMissing)?.capacity() != producer.material_id().len()
            || attempt.relative_path.as_ref().ok_or(Fault::MaterialMissing)?.capacity() != producer.relative_path().len() {
            return Err(Fault::CapacityExceeded);
        }
        let actual_metadata = fixed
            .checked_add((files.capacity() as u64)
                .checked_mul(std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)
                .ok_or(Fault::BoundsOverflow)?)
            .and_then(|n| n.checked_add(attempt.material_id.as_ref()?.capacity() as u64))
            .and_then(|n| n.checked_add(attempt.relative_path.as_ref()?.capacity() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        if actual_metadata > bounds.max_metadata_bytes || actual_metadata > bounds.max_total_allocation_bytes {
            return Err(Fault::CapacityExceeded);
        }
        let limit = bounds.max_single_plain_bytes.min(bounds.max_material_plain_bytes)
            .min(bounds.max_spool_bytes).min(bounds.max_snapshot_bytes);
        let mut measured = AuditMaterialWriter { operation: op, file: None, maximum: limit,
            length: 0, sha: Sha256::new(), fault: None };
        attempt.measured_result = Some(match producer {
            OriginalMetadataProducer::AuditCheckpoint =>
                checkpoint.as_ref().ok_or(Fault::MaterialMissing)?.write_material(&mut measured)
                    .map_err(MaterialEncodeFailure::Sql),
            OriginalMetadataProducer::Schema | OriginalMetadataProducer::Migrations
                | OriginalMetadataProducer::ReceiptFrontier =>
                producer.write_db_projection(normal.as_ref().ok_or(Fault::MaterialMissing)?, &mut measured)
                    .map_err(MaterialEncodeFailure::Sql),
            OriginalMetadataProducer::Installation | OriginalMetadataProducer::HostInventory =>
                producer.write_ordinary_metadata(&mut *installation,
                    source_expected.as_ref().ok_or(Fault::MaterialMissing)?, key_id.as_deref(),
                    host.as_ref(), &mut measured).map_err(MaterialEncodeFailure::Carrier),
            OriginalMetadataProducer::Compatibility =>
                op.reviewed().write_original_compatibility(&mut measured)
                    .map_err(MaterialEncodeFailure::Carrier),
            OriginalMetadataProducer::KeyMetadata =>
                write_original_key_material(
                    source_expected.as_ref().ok_or(Fault::MaterialMissing)?,
                    key_id.as_deref().ok_or(Fault::SecretInvalid)?,
                    key_version.ok_or(Fault::SecretInvalid)?,
                    local_canary.as_ref().ok_or(Fault::SecretInvalid)?, &mut measured,
                ).map_err(MaterialEncodeFailure::Carrier),
            OriginalMetadataProducer::DriverFacts =>
                serde_json::to_writer(&mut measured,
                    original_drivers.as_ref().ok_or(Fault::MaterialMissing)?)
                    .map_err(|_| MaterialEncodeFailure::Carrier(Fault::IoFailure)),
            OriginalMetadataProducer::ToolInventory =>
                std::io::Write::write_all(&mut measured,
                    tool_inventory.as_deref().ok_or(Fault::MaterialMissing)?)
                    .map_err(|_| MaterialEncodeFailure::Carrier(Fault::IoFailure)),
            OriginalMetadataProducer::ProfileInventory | OriginalMetadataProducer::WorkspaceInventory =>
                write_original_root_inventory(producer, &*screen, &mut *installation,
                    source_expected.as_ref().ok_or(Fault::MaterialMissing)?,
                    host.as_ref().ok_or(Fault::MaterialMissing)?,
                    normal.as_ref().ok_or(Fault::MaterialMissing)?,
                    preference_fact.ok_or(Fault::MaterialMissing)?, &mut measured),
        });
        attempt.measured_fault = measured.fault;
        let post = op.require_effect();
        if let Some(fault) = attempt.measured_fault { return Err(fault); }
        post?;
        attempt.measured_result.ok_or(Fault::MaterialMissing)?.map_err(MaterialEncodeFailure::fault)?;
        let expected = (measured.length, <[u8; 32]>::from(measured.sha.finalize()));
        attempt.expected = Some(expected);
        if expected.0 == 0 { return Err(Fault::MaterialMissing); }
        let known_plain = files.iter().try_fold(expected.0, |n, f|
            n.checked_add(f.plain_len).ok_or(Fault::BoundsOverflow))?;
        let buffer_len = bounds.max_chunk_plain_bytes.min(expected.0);
        let local_metadata = actual_metadata.checked_add(buffer_len).ok_or(Fault::BoundsOverflow)?;
        if buffer_len == 0 || known_plain > bounds.max_material_plain_bytes
            || known_plain > bounds.max_spool_bytes || known_plain > bounds.max_snapshot_bytes
            || local_metadata > bounds.max_metadata_bytes || local_metadata > bounds.max_total_allocation_bytes {
            return Err(Fault::CapacityExceeded);
        }
        op.reserve_original_resources(0, buffer_len)?;
        let mut buffer = Zeroizing::new(Vec::new());
        buffer.try_reserve_exact(usize::try_from(buffer_len).map_err(|_| Fault::BoundsOverflow)?)
            .map_err(|_| Fault::CapacityExceeded)?;
        buffer.resize(usize::try_from(buffer_len).map_err(|_| Fault::BoundsOverflow)?, 0);
        if buffer.capacity() as u64 != buffer_len { return Err(Fault::CapacityExceeded); }
        let actual_metadata = actual_metadata.checked_add(buffer.capacity() as u64).ok_or(Fault::BoundsOverflow)?;
        if actual_metadata > bounds.max_metadata_bytes || actual_metadata > bounds.max_total_allocation_bytes {
            return Err(Fault::CapacityExceeded);
        }
        let parent_before = audit_parent_identity(parent, parent_path, op)?;
        op.require_effect()?;
        reserve_local_new_material_fd(local_new_fd_admissions, bounds.max_open_files)?;
        let created = rustix::fs::openat(parent, producer.leaf(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600));
        match created {
            Ok(file) => attempt.writable = Some(File::from(file)),
            Err(_) => { op.require_effect()?; return Err(Fault::IoFailure); }
        }
        op.require_effect()?;
        let writable = attempt.writable.as_ref().ok_or(Fault::MaterialMissing)?;
        let fresh = audit_held_identity(writable, op)?;
        audit_named_identity(parent, fresh, producer, op)?;
        if fresh.identity.bytes != 0 { return Err(Fault::SourceChanged); }
        let mut written = AuditMaterialWriter { operation: op, file: Some(writable), maximum: expected.0,
            length: 0, sha: Sha256::new(), fault: None };
        attempt.written_result = Some(match producer {
            OriginalMetadataProducer::AuditCheckpoint =>
                checkpoint.as_ref().ok_or(Fault::MaterialMissing)?.write_material(&mut written)
                    .map_err(MaterialEncodeFailure::Sql),
            OriginalMetadataProducer::Schema | OriginalMetadataProducer::Migrations
                | OriginalMetadataProducer::ReceiptFrontier =>
                producer.write_db_projection(normal.as_ref().ok_or(Fault::MaterialMissing)?, &mut written)
                    .map_err(MaterialEncodeFailure::Sql),
            OriginalMetadataProducer::Installation | OriginalMetadataProducer::HostInventory =>
                producer.write_ordinary_metadata(&mut *installation,
                    source_expected.as_ref().ok_or(Fault::MaterialMissing)?, key_id.as_deref(),
                    host.as_ref(), &mut written).map_err(MaterialEncodeFailure::Carrier),
            OriginalMetadataProducer::Compatibility =>
                op.reviewed().write_original_compatibility(&mut written)
                    .map_err(MaterialEncodeFailure::Carrier),
            OriginalMetadataProducer::KeyMetadata =>
                write_original_key_material(
                    source_expected.as_ref().ok_or(Fault::MaterialMissing)?,
                    key_id.as_deref().ok_or(Fault::SecretInvalid)?,
                    key_version.ok_or(Fault::SecretInvalid)?,
                    local_canary.as_ref().ok_or(Fault::SecretInvalid)?, &mut written,
                ).map_err(MaterialEncodeFailure::Carrier),
            OriginalMetadataProducer::DriverFacts =>
                serde_json::to_writer(&mut written,
                    original_drivers.as_ref().ok_or(Fault::MaterialMissing)?)
                    .map_err(|_| MaterialEncodeFailure::Carrier(Fault::IoFailure)),
            OriginalMetadataProducer::ToolInventory =>
                std::io::Write::write_all(&mut written,
                    tool_inventory.as_deref().ok_or(Fault::MaterialMissing)?)
                    .map_err(|_| MaterialEncodeFailure::Carrier(Fault::IoFailure)),
            OriginalMetadataProducer::ProfileInventory | OriginalMetadataProducer::WorkspaceInventory =>
                write_original_root_inventory(producer, &*screen, &mut *installation,
                    source_expected.as_ref().ok_or(Fault::MaterialMissing)?,
                    host.as_ref().ok_or(Fault::MaterialMissing)?,
                    normal.as_ref().ok_or(Fault::MaterialMissing)?,
                    preference_fact.ok_or(Fault::MaterialMissing)?, &mut written),
        });
        attempt.written_fault = written.fault;
        let post = op.require_effect();
        if let Some(fault) = attempt.written_fault { return Err(fault); }
        post?;
        attempt.written_result.ok_or(Fault::MaterialMissing)?.map_err(MaterialEncodeFailure::fault)?;
        if (written.length, <[u8; 32]>::from(written.sha.finalize())) != expected {
            return Err(Fault::SourceChanged);
        }
        op.require_effect()?;
        let synced = writable.sync_all();
        op.require_effect()?;
        synced.map_err(|_| Fault::IoFailure)?;
        let before = audit_held_identity(writable, op)?;
        if before.identity.bytes != expected.0 { return Err(Fault::SourceChanged); }
        audit_named_identity(parent, before, producer, op)?;
        op.require_effect()?;
        let synced = parent.sync_all();
        op.require_effect()?;
        synced.map_err(|_| Fault::IoFailure)?;
        op.require_effect()?;
        reserve_local_new_material_fd(local_new_fd_admissions, bounds.max_open_files)?;
        let reopened = rustix::fs::openat(parent, producer.leaf(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty());
        match reopened {
            Ok(file) => attempt.readback = Some(File::from(file)),
            Err(_) => { op.require_effect()?; return Err(Fault::IoFailure); }
        }
        op.require_effect()?;
        let readback = attempt.readback.as_ref().ok_or(Fault::MaterialMissing)?;
        if audit_held_identity(readback, op)? != before { return Err(Fault::SourceChanged); }
        let mut length = 0_u64;
        let mut sha = Sha256::new();
        loop {
            op.require_effect()?;
            let observed = readback.read_at(buffer.as_mut_slice(), length);
            op.require_effect()?;
            let n = observed.map_err(|_| Fault::IoFailure)?;
            if n == 0 { break; }
            length = length.checked_add(n as u64).ok_or(Fault::BoundsOverflow)?;
            if length > expected.0 { return Err(Fault::ExtraTail); }
            sha.update(&buffer[..n]);
        }
        if length != expected.0 { return Err(Fault::ShortRead); }
        if <[u8; 32]>::from(sha.finalize()) != expected.1 { return Err(Fault::ReadbackFailed); }
        if audit_held_identity(readback, op)? != before
            || audit_held_identity(writable, op)? != before { return Err(Fault::SourceChanged); }
        audit_named_identity(parent, before, producer, op)?;
        if audit_parent_identity(parent, parent_path, op)? != parent_before { return Err(Fault::SourceChanged); }
        op.require_effect()?;
        let material_id = attempt.material_id.take().ok_or(Fault::MaterialMissing)?;
        let relative_path = attempt.relative_path.take().ok_or(Fault::MaterialMissing)?;
        let file = match attempt.readback.take() {
            Some(file) => file,
            None => return Err(Fault::MaterialMissing),
        };
        files.push(CaptureOwnedMaterialFile { kind: producer.kind(),
            material_id, relative_path, file, plain_len: expected.0, plain_sha256: expected.1 });
        if producer == OriginalMetadataProducer::ToolInventory {
            // The actual file's measured/write/fsync/readback identity now records these same bytes.
            // Retire only the ordinary encoded Vec; its unique provenance claim stays resident.
            drop(tool_inventory.take());
        }
        Ok(())
    }
}

/// Only after native, SQL, driver and maintenance-postmaster original results close is this
/// opaque collection taken out of SourceOwner. The outer kernel lease is never moved here.

#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalMetadataRetirement {
    Unentered,
    Entered,
    Returned,
}
// Ordinary prepared DATA only. The existing Closed type is constructed by the
// original finish caller only after the true metadata worker wait has returned.
struct OriginalMetadataPrepared {
    source: Option<WholePgSourceClaim>,
    coverage: Vec<WholePgCoverageClaim>,
    tool_inventory_identity: Option<(u64, [u8; 32])>,
}

pub(crate) struct CaptureMaterialsClosed {
    pub(crate) files: Vec<CaptureOwnedMaterialFile>,
    pub(crate) coverage: Vec<WholePgCoverageClaim>,
    pub(crate) source: WholePgSourceClaim,
    pub(crate) backup_range: (String, String, u32, u32),
    pub(crate) provenance: WholePgProvenanceClaim,
    pub(crate) tool_inventory_identity: (u64, [u8; 32]),
    retained: NormalCaptureMaterials,
}
impl CaptureMaterialsClosed {
    /// Ordinary prior readback DATA plus fresh identities from the same held owner chain.
    /// This does not rehash payload or mint a source/Closed capability.
    pub(crate) fn original_audit_record_observations(
        &self, operation_directory: &File, op: &CaptureOperation,
    ) -> Result<((u64, u64), (u64, u64), u64, [u8; 32]), Fault> {
        type DirectoryIdentity = (u64, u64, u32, u32, u64);
        let known = (std::mem::size_of::<std::fs::Metadata>() as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add((std::mem::size_of::<rustix::fs::Stat>() as u64).checked_mul(4)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<DirectoryIdentity>() as u64).checked_mul(6)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<AuditFileIdentity>() as u64).checked_mul(3)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<DirectoryIdentity, Fault>>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<AuditFileIdentity, Fault>>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<std::fs::Metadata, std::io::Error>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, CaptureOwnedMaterialFile>>() as u64))
            .and_then(|n| n.checked_add((std::mem::size_of::<Option<&CaptureOwnedMaterialFile>>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<
                ((u64, u64), (u64, u64), u64, [u8; 32]), Fault>>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        op.reserve_original_resources(0, known)?;
        let retained = &self.retained;
        let attempt = &retained.audit;
        if retained.phase != ReadPhase::SourcesClosed || !retained.material_layout_ready
            || !attempt.started || attempt.measured_fault.is_some() || attempt.written_fault.is_some()
            || attempt.measured_result.as_ref().is_none_or(|r| r.is_err())
            || attempt.written_result.as_ref().is_none_or(|r| r.is_err())
            || attempt.readback.is_some()
            || self.files.len() as u64 > op.profile().carrier.max_material_files
        {
            return Err(Fault::MaterialMissing);
        }
        let expected = attempt.expected.ok_or(Fault::MaterialMissing)?;
        if expected.0 == 0 { return Err(Fault::MaterialMissing); }
        let mut audit: Option<&CaptureOwnedMaterialFile> = None;
        for file in &self.files {
            if file.kind == WholePgMaterialKind::AuditCheckpoint
                || file.material_id == "audit-checkpoint"
                || file.relative_path == "metadata/audit-checkpoint.jsonl"
            {
                if file.kind != WholePgMaterialKind::AuditCheckpoint
                    || file.material_id != "audit-checkpoint"
                    || file.relative_path != "metadata/audit-checkpoint.jsonl"
                    || audit.is_some()
                {
                    return Err(Fault::SourceChanged);
                }
                audit = Some(file);
            }
        }
        let audit = audit.ok_or(Fault::MaterialMissing)?;
        if (audit.plain_len, audit.plain_sha256) != expected {
            return Err(Fault::SourceChanged);
        }
        let materials = retained.material_directories[0].as_ref().ok_or(Fault::MaterialMissing)?;
        let metadata = retained.material_directories[2].as_ref().ok_or(Fault::MaterialMissing)?;
        let materials_before = original_material_directory_identity(
            materials, operation_directory, "materials", op,
        )?;
        let metadata_before = original_material_directory_identity(
            metadata, materials, "metadata", op,
        )?;
        let held = audit_held_identity(&audit.file, op)?;
        if held.identity.bytes != expected.0
            || audit_held_identity(attempt.writable.as_ref().ok_or(Fault::MaterialMissing)?, op)?
                != held
        {
            return Err(Fault::SourceChanged);
        }
        audit_named_identity(metadata, held, OriginalMetadataProducer::AuditCheckpoint, op)?;
        if audit_held_identity(&audit.file, op)? != held
            || original_material_directory_identity(metadata, materials, "metadata", op)?
                != metadata_before
            || original_material_directory_identity(materials, operation_directory, "materials", op)?
                != materials_before
        {
            return Err(Fault::SourceChanged);
        }
        op.require_effect()?;
        Ok(((metadata_before.0, metadata_before.1),
            (held.identity.device, held.identity.inode), expected.0, expected.1))
    }

    pub(crate) fn into_parts(self) -> ClosedMaterialParts {
        ClosedMaterialParts {
            files: self.files,
            coverage: self.coverage,
            source: self.source,
            backup_range: self.backup_range,
            provenance: Some(self.provenance),
            tool_inventory_identity: self.tool_inventory_identity,
            retained: self.retained,
        }
    }
}
pub(crate) struct ClosedMaterialParts {
    pub(crate) files: Vec<CaptureOwnedMaterialFile>,
    pub(crate) coverage: Vec<WholePgCoverageClaim>,
    pub(crate) source: WholePgSourceClaim,
    pub(crate) backup_range: (String, String, u32, u32),
    pub(crate) provenance: Option<WholePgProvenanceClaim>,
    pub(crate) tool_inventory_identity: (u64, [u8; 32]),
    pub(crate) retained: NormalCaptureMaterials,
}


type OriginalSnapshotJoin = Result<ArtifactSnapshotResult, tokio::task::JoinError>;
type OriginalSnapshotParts = (ArtifactCaptureHold, OwnedCaptureSpool, Vec<ArtifactSnapshotFile>);

// This writer sees only the existing nonsecret projection. JSON escapes field newlines;
// the original encoder's actual LF separators are the sole record count.
struct OriginalArtifactLineCount<'a> {
    op: &'a CaptureOperation,
    records: u64,
    first_fault: Option<Fault>,
}
impl std::io::Write for OriginalArtifactLineCount<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.first_fault.is_some() {
            return Err(std::io::ErrorKind::Other.into());
        }
        if let Err(fault) = self.op.require_effect() {
            self.first_fault = Some(fault);
            return Err(std::io::ErrorKind::Other.into());
        }
        let result = (|| {
            let mut records = self.records;
            for byte in bytes {
                if *byte == b'\n' {
                    records = records.checked_add(1).ok_or(Fault::BoundsOverflow)?;
                }
            }
            self.records = records;
            Ok::<_, Fault>(bytes.len())
        })();
        // Complete this write's original E postcheck even when arithmetic refused;
        // the current clock fault precedes classification of the saved result.
        self.op.require_effect().and(result).map_err(|fault| {
            self.first_fault = Some(fault);
            std::io::ErrorKind::Other.into()
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.op.require_effect().map_err(|fault| {
            if self.first_fault.is_none() { self.first_fault = Some(fault); }
            std::io::ErrorKind::Other.into()
        })
    }
}
fn original_snapshot_sum(values: &[u64]) -> Result<u64, Fault> {
    values.iter().try_fold(0u64, |total, value| {
        total.checked_add(*value).ok_or(Fault::BoundsOverflow)
    })
}
fn original_snapshot_mul(left: u64, right: u64) -> Result<u64, Fault> {
    left.checked_mul(right).ok_or(Fault::BoundsOverflow)
}
// A field's size plus its maximum preceding alignment padding. Summing these
// bounds does not assume Rust field order, stack reuse or optimizer elimination.
fn original_snapshot_slot<T>() -> Result<u64, Fault> {
    std::mem::size_of::<T>()
        .checked_add(std::mem::align_of::<T>() - 1)
        .and_then(|n| u64::try_from(n).ok()).ok_or(Fault::BoundsOverflow)
}
fn original_snapshot_node<K, V>() -> Result<u64, Fault> {
    // Pinned std BTree leaf is repr(C): parent pointer, parent_idx:u16, len:u16,
    // 11 keys/values. An internal node additionally holds 12 child edges.
    let mut layout = std::alloc::Layout::new::<Option<std::ptr::NonNull<()>>>();
    for field in [
        std::alloc::Layout::new::<std::mem::MaybeUninit<u16>>(),
        std::alloc::Layout::new::<u16>(),
        std::alloc::Layout::new::<[std::mem::MaybeUninit<K>; 11]>(),
        std::alloc::Layout::new::<[std::mem::MaybeUninit<V>; 11]>(),
        std::alloc::Layout::new::<[std::ptr::NonNull<()>; 12]>(),
    ] {
        layout = layout.extend(field).map_err(|_| Fault::BoundsOverflow)?.0;
    }
    u64::try_from(layout.pad_to_align().size()).map_err(|_| Fault::BoundsOverflow)
}
fn original_snapshot_bridge_bytes() -> Result<u64, Fault> {
    type Child<'a> = (&'a str, &'a File, [u64; 2]);
    let verify = original_snapshot_sum(&[
        std::mem::size_of::<[Child<'_>; 2]>() as u64,
        std::mem::size_of::<std::array::IntoIter<Child<'_>, 2>>() as u64,
        std::mem::size_of::<Option<Child<'_>>>() as u64,
        std::mem::size_of::<Child<'_>>() as u64,
    ])?;
    let factory = original_snapshot_sum(&[
        std::mem::size_of::<[&std::fs::Metadata; 3]>() as u64,
        std::mem::size_of::<std::array::IntoIter<&std::fs::Metadata, 3>>() as u64,
        std::mem::size_of::<Option<&std::fs::Metadata>>() as u64,
        std::mem::size_of::<&std::fs::Metadata>() as u64,
    ])?;
    original_snapshot_sum(&[
        // Original private view: a sized-directory reference, the original clock
        // trait-object reference and three identities containing two u64 fields each.
        // Charge each field's preceding padding, then three identity tails, the
        // identity-array preceding padding and the final view tail. No field order
        // or exact cross-crate Rust layout is assumed on the pinned toolchain.
        original_snapshot_sum(&[
            original_snapshot_slot::<&()>()?,
            original_snapshot_slot::<&dyn CaptureClockCheck>()?,
            original_snapshot_mul(6, original_snapshot_slot::<u64>()?)?,
            original_snapshot_mul(5, u64::try_from(
                std::mem::align_of::<&()>()
                    .max(std::mem::align_of::<&dyn CaptureClockCheck>())
                    .max(std::mem::align_of::<u64>()) - 1,
            ).map_err(|_| Fault::BoundsOverflow)?)?,
        ])?,
        std::mem::size_of::<[[bool; 2]; 2]>() as u64, verify.max(factory),
        std::mem::size_of::<[(u64, u64); 3]>() as u64,
        std::mem::size_of::<[std::fs::Metadata; 3]>() as u64,
        std::mem::size_of::<Result<std::fs::Metadata, Fault>>() as u64,
        std::mem::size_of::<rustix::fs::Stat>() as u64,
        std::mem::size_of::<Result<rustix::fs::Stat, Fault>>() as u64,
    ])
}
fn original_snapshot_verifier_bytes(n: u64) -> Result<u64, Fault> {
    let n2 = n.checked_add(2).ok_or(Fault::BoundsOverflow)?;
    let n3 = n.checked_add(3).ok_or(Fault::BoundsOverflow)?;
    let physical = n.checked_mul(2).and_then(|n| n.checked_add(2))
        .ok_or(Fault::BoundsOverflow)?;
    let nodes = original_snapshot_sum(&[
        original_snapshot_mul(physical, original_snapshot_node::<(&str, &str), &ArtifactSnapshotFile>()?)?,
        original_snapshot_mul(original_snapshot_mul(2, n2)?, original_snapshot_node::<&str, &()>()?)?,
        original_snapshot_mul(n2, original_snapshot_node::<(&str, &str), u64>()?)?,
        original_snapshot_mul(n2, original_snapshot_node::<&str, u64>()?)?,
        original_snapshot_mul(n3, original_snapshot_node::<&str, &()>()?)?,
        original_snapshot_mul(n2, original_snapshot_node::<&str, ()>()?)?,
        original_snapshot_mul(n3, original_snapshot_node::<&str, ()>()?)?,
    ])?;
    // All eight actual maps/sets coexist. Private Row references are thin pointers;
    // &() is a size-only pointer bound, not a duplicate Row or a decoded projection.
    let headers = original_snapshot_sum(&[
        original_snapshot_mul(6, original_snapshot_slot::<std::collections::BTreeMap<&str, &()>>()?)?,
        original_snapshot_mul(2, original_snapshot_slot::<std::collections::BTreeSet<&str>>()?)?,
        original_snapshot_mul(3, original_snapshot_slot::<
            std::iter::Filter<std::slice::Iter<'_, ()>, fn(&&()) -> bool>>()?)?,
        original_snapshot_slot::<std::collections::btree_map::Keys<'_, (&str, &str), &ArtifactSnapshotFile>>()?,
        original_snapshot_slot::<std::collections::btree_map::Iter<'_, &str, &()>>()?,
        // The three literal field-comparison loops (10,4,9 pairs), their moved
        // arrays, iterators, next results and current pair bindings are distinct slots.
        original_snapshot_slot::<[(usize, usize); 10]>()?,
        original_snapshot_slot::<std::array::IntoIter<(usize, usize), 10>>()?,
        original_snapshot_slot::<[(usize, usize); 4]>()?,
        original_snapshot_slot::<std::array::IntoIter<(usize, usize), 4>>()?,
        original_snapshot_slot::<[(usize, usize); 9]>()?,
        original_snapshot_slot::<std::array::IntoIter<(usize, usize), 9>>()?,
        original_snapshot_mul(3, original_snapshot_slot::<Option<(usize, usize)>>()?)?,
        original_snapshot_mul(3, original_snapshot_slot::<(usize, usize)>()?)?,
        // Source verifier has fewer than forty named string/reference bindings,
        // including split/get/field results; account them without stack reuse.
        original_snapshot_mul(40, original_snapshot_slot::<Option<&str>>()?)?,
        original_snapshot_mul(12, original_snapshot_slot::<Option<&ArtifactSnapshotFile>>()?)?,
        original_snapshot_mul(16, original_snapshot_slot::<u64>()?)?,
        original_snapshot_mul(8, original_snapshot_slot::<bool>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<Result<(), CaptureSqlFailure>>()?)?,
        original_snapshot_slot::<String>()?, 64,
        original_snapshot_slot::<[u8; 16]>()?,
    ])?;
    original_snapshot_sum(&[nodes, headers])
}
fn original_snapshot_audit_tail() -> Result<u64, Fault> {
    // Exact C40 original_audit_record_observations known fixed charge.
    type DirectoryIdentity = (u64, u64, u32, u32, u64);
    original_snapshot_sum(&[
        original_snapshot_mul(8, std::mem::size_of::<std::fs::Metadata>() as u64)?,
        original_snapshot_mul(4, std::mem::size_of::<rustix::fs::Stat>() as u64)?,
        original_snapshot_mul(6, std::mem::size_of::<DirectoryIdentity>() as u64)?,
        original_snapshot_mul(3, std::mem::size_of::<AuditFileIdentity>() as u64)?,
        original_snapshot_mul(2, std::mem::size_of::<Result<DirectoryIdentity, Fault>>() as u64)?,
        original_snapshot_mul(2, std::mem::size_of::<Result<AuditFileIdentity, Fault>>() as u64)?,
        std::mem::size_of::<Result<std::fs::Metadata, std::io::Error>>() as u64,
        std::mem::size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>() as u64,
        std::mem::size_of::<std::slice::Iter<'_, CaptureOwnedMaterialFile>>() as u64,
        original_snapshot_mul(2, std::mem::size_of::<Option<&CaptureOwnedMaterialFile>>() as u64)?,
        std::mem::size_of::<Result<((u64, u64), (u64, u64), u64, [u8; 32]), Fault>>() as u64,
    ])
}
fn original_snapshot_future_tail(
    state: &NormalCaptureMaterials, f: u64, bounds: &WholePgCarrierBounds,
    range: &(String, String, u32, u32), op: &CaptureOperation,
) -> Result<(u64, u64, u64), Fault> {
    use openbot_domain::backup::whole_pg_carrier::{
        FrozenWholePgManifest, WholePgManifestClaim, WholePgMaterialClaim,
        WholePgSealCodec, WholePgOpenCodec,
    };
    use openbot_infra::backup::whole_pg_capture_stream::{
        WholePgOwnedSourceInput, WholePgOwnedStreamParts,
    };
    let g = (state.files.len() as u64).checked_add(f).ok_or(Fault::BoundsOverflow)?;
    let k = g.checked_add(2).ok_or(Fault::BoundsOverflow)?;
    let coverage = (WholePgMaterialKind::ALL.len() as u64).checked_add(2)
        .ok_or(Fault::BoundsOverflow)?;
    let coverage_capacity = coverage.max(4).checked_next_power_of_two()
        .ok_or(Fault::BoundsOverflow)?;
    let mut pair_bytes = original_snapshot_mul(f, 53 + 69)?;
    let mut directory_entries = original_snapshot_mul(f, 3)?.checked_add(2)
        .ok_or(Fault::BoundsOverflow)?;
    for file in &state.files {
        pair_bytes = original_snapshot_sum(&[
            pair_bytes, file.material_id.capacity() as u64, file.relative_path.capacity() as u64,
        ])?;
        directory_entries = directory_entries.checked_add(
            file.relative_path.bytes().filter(|b| *b == b'/').count() as u64,
        ).ok_or(Fault::BoundsOverflow)?;
    }
    pair_bytes = original_snapshot_sum(&[pair_bytes,
        ("master-secret".len() + "secrets/master".len()
            + "scram-secret".len() + "secrets/scram".len()) as u64,
    ])?;
    let expected = state.expected.as_ref().ok_or(Fault::MaterialMissing)?;
    let mut source_strings = 0u64;
    for value in [&expected.instance_id, &expected.dataset_id, &expected.deployment_id,
        &expected.tenant_id, &expected.system_identifier,
        state.key_id.as_ref().ok_or(Fault::SecretInvalid)?,
    ] {
        source_strings = source_strings.checked_add(value.capacity() as u64)
            .ok_or(Fault::BoundsOverflow)?;
    }
    // Two real source-claim copies plus literal/barrier IDs, UUIDs, request,
    // original backup-range clones and coverage evidence IDs. No plaintext body.
    let top_strings = original_snapshot_sum(&[
        original_snapshot_mul(2, source_strings)?,
        original_snapshot_mul(2, original_snapshot_sum(&[
            range.0.capacity() as u64, range.1.capacity() as u64,
        ])?)?,
        original_snapshot_mul(6, 36)?, op.reviewed().request_id.capacity() as u64,
        original_snapshot_mul(coverage, 128)?, 512,
    ])?;
    let layout = original_snapshot_sum(&[
        original_snapshot_slot::<[u32; 3]>()?, original_snapshot_slot::<Vec<u64>>()?,
        original_snapshot_mul(k, std::mem::size_of::<u64>() as u64)?,
        original_snapshot_mul(4, std::mem::size_of::<std::sync::atomic::AtomicUsize>() as u64)?,
    ])?;
    let prepared = original_snapshot_sum(&[
        original_snapshot_mul(k, std::mem::size_of::<WholePgOwnedSourceInput>() as u64)?,
        original_snapshot_mul(k, std::mem::size_of::<WholePgMaterialClaim>() as u64)?,
        // Original finish coverage and later collected/pushed coverage each have
        // a distinct backing; allow their old/new growth without sharing credit.
        original_snapshot_mul(original_snapshot_mul(4, coverage_capacity)?,
            std::mem::size_of::<WholePgCoverageClaim>() as u64)?,
        pair_bytes, top_strings, layout,
        std::mem::size_of::<WholePgSourceClaim>() as u64,
        std::mem::size_of::<WholePgManifestClaim>() as u64,
        std::mem::size_of::<FrozenWholePgManifest>() as u64,
        std::mem::size_of::<WholePgOwnedStreamParts>() as u64,
        // Manifest IDs/paths, stream seen IDs and directory-prefix validation.
        original_snapshot_mul(original_snapshot_mul(3, k.checked_add(2).ok_or(Fault::BoundsOverflow)?)?,
            original_snapshot_node::<&str, ()>()?)?,
        original_snapshot_mul(directory_entries.min(bounds.max_directories).checked_add(2)
            .ok_or(Fault::BoundsOverflow)?, original_snapshot_node::<&str, ()>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<std::collections::BTreeSet<&str>>()?)?,
    ])?;
    // Stream's original private identity has ctime/ctime_ns and no links: it
    // needs one more i64 than this module's FileIdentity. This size-only tuple
    // covers its nine actual fields without a private type/getter. Its 12 new
    // files are in addition to the two original directory clones.
    let stream = original_snapshot_sum(&[
        original_snapshot_mul(k, std::mem::size_of::<Option<(FileIdentity, i64)>>() as u64)?,
        original_snapshot_mul(12, std::mem::size_of::<File>() as u64)?,
        bounds.max_manifest_bytes.max(bounds.max_chunk_plain_bytes).max(84),
        32, original_snapshot_mul(2, 104)?, 64,
        // Actual fixed ASCII names: UUID32, key, partial and final.
        32 + 52 + 57 + 53,
        std::mem::size_of::<WholePgSealCodec>() as u64,
        std::mem::size_of::<WholePgOpenCodec>() as u64,
        std::mem::size_of::<openbot_infra::backup::whole_pg_capture_stream::OwnedCaptureStreamInputs>() as u64,
        std::mem::size_of::<openbot_infra::backup::whole_pg_capture_stream::OwnedCaptureStreamResult>() as u64,
        original_snapshot_mul(8, original_snapshot_slot::<std::fs::Metadata>()?)?,
        original_snapshot_mul(8, original_snapshot_slot::<Result<std::fs::Metadata, std::io::Error>>()?)?,
        original_snapshot_mul(6, original_snapshot_slot::<(FileIdentity, i64)>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<rustix::fs::Stat>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<Result<rustix::fs::Stat, rustix::io::Errno>>()?)?,
        original_snapshot_mul(8, original_snapshot_slot::<Vec<u8>>()?)?,
        original_snapshot_mul(8, original_snapshot_slot::<String>()?)?,
        original_snapshot_mul(32, original_snapshot_slot::<u64>()?)?,
        original_snapshot_mul(16, original_snapshot_slot::<bool>()?)?,
        original_snapshot_slot::<Result<(), Fault>>()?,
        original_snapshot_slot::<JoinHandle<openbot_infra::backup::whole_pg_capture_stream::OwnedCaptureStreamResult>>()?,
    ])?;
    // Six remaining success stages and at most the existing ClosingPending record.
    // Each original stage: app/control/op-dir clones, operations open, create and
    // readback = at most six NEW FDs. Retired descriptors do not refund admissions.
    let control_stages = 7u64;
    let record = op.profile().native.max_control_bytes.min(bounds.max_metadata_bytes);
    let control = super::control::original_remaining_stage_known_tail(record)?;
    let fd = 14u64.checked_add(original_snapshot_mul(control_stages, 6)?)
        .ok_or(Fault::BoundsOverflow)?;
    let known = original_snapshot_sum(&[prepared, stream, control, original_snapshot_audit_tail()?])?;
    // Storage is a separate conservative future tail: maximum admitted carrier,
    // key medium, and original remaining stage records. Actual per-device
    // allocation/allocator/Dir/Tokio bounds are still not established by this.
    let allocation = original_snapshot_sum(&[
        bounds.max_wire_bytes, bounds.max_key_medium_allocation_bytes,
        original_snapshot_mul(control_stages, record)?,
    ])?;
    Ok((fd, known, allocation))
}
fn original_snapshot_probe_bytes() -> Result<u64, Fault> {
    original_snapshot_sum(&[
        original_snapshot_slot::<bool>()?,
        original_snapshot_slot::<Option<OriginalSnapshotJoin>>()?,
        original_snapshot_slot::<Option<OriginalSnapshotParts>>()?,
        original_snapshot_slot::<OriginalArtifactLineCount<'_>>()?,
        original_snapshot_slot::<Result<(), CaptureSqlFailure>>()?,
        original_snapshot_slot::<WholePgCarrierBounds>()?,
        original_snapshot_mul(4, original_snapshot_slot::<std::fs::Metadata>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<Result<std::fs::Metadata, std::io::Error>>()?)?,
        original_snapshot_mul(2, original_snapshot_slot::<std::slice::Iter<'_, CaptureOwnedMaterialFile>>()?)?,
        original_snapshot_mul(2, original_snapshot_slot::<std::slice::Iter<'_, Option<File>>>()?)?,
        original_snapshot_mul(64, original_snapshot_slot::<u64>()?)?,
        original_snapshot_slot::<[u64; 32]>()?,
    ])
}
async fn freeze_original_artifact_snapshot(
    state: &mut NormalCaptureMaterials, op: &Arc<CaptureOperation>,
    range: &(String, String, u32, u32),
) -> Result<(), Fault> {
    op.require_effect()?;
    if state.phase != ReadPhase::SourcesClosed || !state.material_layout_ready
        || state.artifact_hold.is_none() || state.material_directories[1].is_none()
        || state.snapshot_started || state.snapshot_task.is_some() || state.snapshot_joined.is_some()
        || state.snapshot.is_some() || state.snapshot_failure.is_some() || state.snapshot_parts.is_some()
    {
        return Err(Fault::IntentMismatch);
    }
    // Pay the new fixed owner/counter/probe slots before constructing the counter
    // or making any metadata observation. Cumulative charges survive refusal.
    op.reserve_original_resources(0, original_snapshot_probe_bytes()?)?;
    let mut count = OriginalArtifactLineCount { op: op.as_ref(), records: 0, first_fault: None };
    let projected = state.normal.as_ref().ok_or(Fault::MaterialMissing)?
        .write_projection(&["artifact_save_operations"], &mut count);
    if let Some(fault) = count.first_fault { return Err(fault); }
    op.require_effect()?;
    projected.map_err(sql_fault)?;
    let n = count.records;
    let f = n.checked_mul(2).and_then(|n| n.checked_add(1)).ok_or(Fault::BoundsOverflow)?;
    let o = f.checked_add(3).ok_or(Fault::BoundsOverflow)?;
    let new_fds = f.checked_mul(2).and_then(|n| n.checked_add(7)).ok_or(Fault::BoundsOverflow)?;
    let local_fds = new_fds.checked_add(5).ok_or(Fault::BoundsOverflow)?;
    let bounds = op.profile().carrier_bounds()?;
    let g = (state.files.len() as u64).checked_add(f).ok_or(Fault::BoundsOverflow)?;
    let k = g.checked_add(2).ok_or(Fault::BoundsOverflow)?;
    if k > bounds.max_material_files || bounds.max_directories < 3
        || bounds.max_path_bytes < 69 || bounds.max_path_depth < 4 || local_fds > bounds.max_open_files
    {
        return Err(Fault::CapacityExceeded);
    }
    let (tail_fd, tail_known, tail_allocation) =
        original_snapshot_future_tail(state, f, &bounds, range, op.as_ref())?;
    let mut current_plain = 0u64;
    let mut current_allocation = 0u64;
    for file in &state.files {
        current_plain = current_plain.checked_add(file.plain_len).ok_or(Fault::BoundsOverflow)?;
        op.require_effect()?;
        let actual = file.file.metadata();
        op.require_effect()?;
        let actual = actual.map_err(|_| Fault::IoFailure)?;
        current_allocation = current_allocation.checked_add(
            actual.blocks().checked_mul(512).ok_or(Fault::BoundsOverflow)?,
        ).ok_or(Fault::BoundsOverflow)?;
    }
    for directory in &state.material_directories {
        let directory = directory.as_ref().ok_or(Fault::MaterialMissing)?;
        op.require_effect()?;
        let actual = directory.metadata();
        op.require_effect()?;
        let actual = actual.map_err(|_| Fault::IoFailure)?;
        current_allocation = current_allocation.checked_add(
            actual.blocks().checked_mul(512).ok_or(Fault::BoundsOverflow)?,
        ).ok_or(Fault::BoundsOverflow)?;
    }
    let plain = bounds.max_material_plain_bytes.checked_sub(
        current_plain.checked_add(96).ok_or(Fault::BoundsOverflow)?,
    ).ok_or(Fault::CapacityExceeded)?
        // This independent ceiling is for artifact snapshot bytes, not the
        // already resident PostgreSQL/ordinary metadata plaintext.
        .min(bounds.max_snapshot_bytes)
        .min(bounds.max_spool_bytes.checked_sub(current_plain).ok_or(Fault::CapacityExceeded)?);
    let allocation = bounds.max_total_allocation_bytes.checked_sub(
        current_allocation.checked_add(tail_allocation).ok_or(Fault::BoundsOverflow)?,
    ).ok_or(Fault::CapacityExceeded)?;
    if plain == 0 || allocation == 0 { return Err(Fault::CapacityExceeded); }
    let chunk = bounds.max_chunk_plain_bytes.min(bounds.max_single_plain_bytes).min(plain);
    let opened_slot = original_snapshot_sum(&[
        original_snapshot_slot::<Arc<File>>()?, original_snapshot_slot::<bool>()?,
    ])?;
    let arc_file = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .extend(std::alloc::Layout::new::<File>()).map_err(|_| Fault::BoundsOverflow)?
        .0.pad_to_align().size() as u64;
    let opened_bytes = original_snapshot_mul(o, opened_slot)?;
    let readers_bytes = original_snapshot_mul(4, std::mem::size_of::<rustix::fs::Dir>() as u64)?;
    let output_bytes = original_snapshot_mul(f, std::mem::size_of::<ArtifactSnapshotFile>() as u64)?;
    let paths = f.checked_mul(300).and_then(|n| n.checked_add(500)).ok_or(Fault::BoundsOverflow)?;
    // This is the worker's finite local monotonic known-storage slice. Its
    // original actual-capacity checks remain in force, not a second profile.
    let worker = original_snapshot_sum(&[
        original_snapshot_bridge_bytes()?, opened_bytes, readers_bytes, output_bytes,
        4097, chunk, paths,
    ])?;
    let worker_fixed = original_snapshot_sum(&[
        // Public full owners bound the actual private retained/counter bodies.
        original_snapshot_mul(2, original_snapshot_slot::<ArtifactSnapshot>()?)?,
        original_snapshot_slot::<ArtifactCaptureHold>()?,
        original_snapshot_slot::<OwnedCaptureSpool>()?,
        original_snapshot_slot::<ArtifactSnapshotResult>()?,
        original_snapshot_mul(2, original_snapshot_slot::<Vec<ArtifactSnapshotFile>>()?)?,
        // Depth is exactly root plus its two closed child names; at most two
        // recursive frames coexist. Charge their distinct iteration/result slots.
        original_snapshot_mul(2, original_snapshot_sum(&[
            original_snapshot_slot::<std::fs::Metadata>()?,
            original_snapshot_slot::<[u64; 8]>()?,
            original_snapshot_slot::<rustix::fs::Stat>()?,
            original_snapshot_slot::<Result<rustix::fs::Stat, rustix::io::Errno>>()?,
            original_snapshot_slot::<rustix::fs::DirEntry>()?,
            original_snapshot_slot::<Option<Result<rustix::fs::DirEntry, rustix::io::Errno>>>()?,
            original_snapshot_slot::<String>()?, 44,
            original_snapshot_slot::<[bool; 2]>()?,
            original_snapshot_mul(8, original_snapshot_slot::<u64>()?)?,
            original_snapshot_mul(3, original_snapshot_slot::<Arc<File>>()?)?,
            original_snapshot_slot::<Sha256>()?,
        ])?)?,
        original_snapshot_mul(8, original_snapshot_slot::<std::fs::Metadata>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<Result<std::fs::Metadata, std::io::Error>>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<rustix::fs::Stat>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<Result<rustix::fs::Stat, rustix::io::Errno>>()?)?,
        original_snapshot_mul(2, original_snapshot_slot::<std::slice::Iter<'_, ArtifactSnapshotFile>>()?)?,
        original_snapshot_slot::<std::slice::Iter<'_, File>>()?,
        original_snapshot_slot::<Result<(), Fault>>()?,
    ])?;
    let worker_transient = original_snapshot_sum(&[
        // One growth at a time: each previously reported Vec backing is within
        // this same worker's original monotonic metadata cap, also on refusal.
        // The new side remains under its original capacity counter; no new grant.
        worker, worker_fixed,
    ])?;
    let target_capacity = usize::try_from(g).map_err(|_| Fault::BoundsOverflow)?
        .max(state.files.capacity());
    let new_backing = if state.files.capacity() < target_capacity {
        original_snapshot_mul(target_capacity as u64, std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)?
    } else { 0 };
    let move_transient = original_snapshot_sum(&[
        original_snapshot_mul(state.files.capacity() as u64,
            std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)?,
        original_snapshot_mul(2, original_snapshot_slot::<String>()?)?,
        original_snapshot_slot::<CaptureOwnedMaterialFile>()?,
        original_snapshot_slot::<ArtifactSnapshotFile>()?,
        original_snapshot_slot::<Option<ArtifactSnapshotFile>>()?,
        original_snapshot_mul(2, original_snapshot_slot::<Result<(), std::collections::TryReserveError>>()?)?,
        original_snapshot_slot::<std::slice::Iter<'_, ArtifactSnapshotFile>>()?,
        original_snapshot_mul(8, original_snapshot_slot::<u64>()?)?,
    ])?;
    let known = original_snapshot_sum(&[
        // Every newly allocated Arc<File> wraps a separately admitted new FD;
        // failed/unsorted layouts can exceed successful-shape O before refusal.
        worker, original_snapshot_mul(new_fds, arc_file)?, new_backing,
        original_snapshot_mul(f, 53 + 69)?,
        worker_transient.max(original_snapshot_verifier_bytes(n)?).max(move_transient),
    ])?;
    let next_local = state.local_new_fd_admissions.checked_add(new_fds).ok_or(Fault::BoundsOverflow)?;
    let (remaining_fd, remaining_known) = super::remaining_capture_resources(&op.resources)?;
    if next_local > bounds.max_open_files
        || original_snapshot_sum(&[new_fds, tail_fd])? > remaining_fd
        || original_snapshot_sum(&[known, tail_known])? > remaining_known
    {
        return Err(Fault::CapacityExceeded);
    }
    // Only this snapshot delta is committed. Future tail is headroom; its own
    // later original producer charges must not be prepaid here and charged twice.
    op.reserve_original_resources(new_fds, known)?;
    state.local_new_fd_admissions = next_local;
    let (remaining_fd, remaining_known) = super::remaining_capture_resources(&op.resources)?;
    if remaining_fd < tail_fd || remaining_known < tail_known {
        return Err(Fault::CapacityExceeded);
    }
    let mut worker_bounds = bounds;
    worker_bounds.max_material_files = f;
    worker_bounds.max_directories = 3;
    worker_bounds.max_path_bytes = 44;
    worker_bounds.max_path_depth = 2;
    worker_bounds.max_open_files = local_fds;
    worker_bounds.max_metadata_bytes = worker;
    worker_bounds.max_single_plain_bytes = bounds.max_single_plain_bytes.min(plain);
    worker_bounds.max_material_plain_bytes = plain;
    worker_bounds.max_snapshot_bytes = plain;
    worker_bounds.max_spool_bytes = plain;
    worker_bounds.max_total_allocation_bytes = allocation;
    let worker_bounds = worker_bounds.check()?;
    state.snapshot_started = true;
    let hold = state.artifact_hold.take().expect("checked original artifact hold remains resident");
    let root = state.material_directories[1].take().expect("checked original spool remains resident");
    let spool = OwnedCaptureSpool::from_owned_directory(root);
    let clock: Arc<dyn CaptureClockCheck> = Arc::clone(op) as Arc<dyn CaptureClockCheck>;
    state.snapshot_task = Some(openbot_infra::artifact_store::capture::start_capture_snapshot(
        hold, spool, worker_bounds, clock,
    ));
    // The original worker owns the only moved hold/spool, and its original handle
    // is resident before every fallible check and the first borrowed await.
    op.require_effect()?;
    let remaining = op.effect_remaining_ns()?;
    let waited = tokio::time::timeout(std::time::Duration::from_nanos(remaining),
        state.snapshot_task.as_mut().expect("original snapshot handle remains resident")).await;
    let actual = match waited {
        Err(_) => {
            op.require_effect()?;
            return Err(Fault::ClosingPending);
        }
        Ok(actual) => actual,
    };
    state.snapshot_joined = Some(actual);
    state.snapshot_task.take();
    // Transfer the actual nested result only into the existing same-owner slots.
    // No fallible call lies between taking it and installing its full owner.
    match state.snapshot_joined.take().expect("actual original JoinResult is resident") {
        Err(error) => {
            state.snapshot_joined = Some(Err(error));
            op.require_effect()?;
            return Err(Fault::ClosingPending);
        }
        Ok(Err(failure)) => {
            let fault = failure.fault;
            state.snapshot_failure = Some(failure);
            op.require_effect()?;
            return Err(fault);
        }
        Ok(Ok(snapshot)) => state.snapshot = Some(snapshot),
    }
    op.require_effect()?;
    let verified = state.normal.as_ref().ok_or(Fault::MaterialMissing)?
        .verify_artifact_snapshot(state.snapshot.as_ref().expect("original successful snapshot retained"));
    let postcheck = op.require_effect();
    postcheck?;
    verified.map_err(sql_fault)?;
    let snapshot = state.snapshot.take().expect("verified original snapshot remains resident");
    state.snapshot_parts = Some(snapshot.into_parts());
    // The full hold/spool/old Vec (including its backing) remains resident during
    // all allocation and every later refusal. No second source read or FD open.
    state.files.try_reserve_exact(target_capacity.saturating_sub(state.files.len()))
        .map_err(|_| Fault::CapacityExceeded)?;
    if state.files.capacity() > target_capacity { return Err(Fault::CapacityExceeded); }
    while let Some(file) = state.snapshot_parts.as_ref().and_then(|parts| parts.2.last()) {
        op.require_effect()?;
        let length = file.relative_path.len();
        if length == 0 || length > 44 || file.byte_length > worker_bounds.max_single_plain_bytes {
            return Err(Fault::SourceChanged);
        }
        let mut material_id = String::new();
        let mut relative_path = String::new();
        let id_len = "artifact:".len().checked_add(length).ok_or(Fault::BoundsOverflow)?;
        let path_len = "materials/artifact-spool/".len().checked_add(length).ok_or(Fault::BoundsOverflow)?;
        material_id.try_reserve_exact(id_len).map_err(|_| Fault::CapacityExceeded)?;
        relative_path.try_reserve_exact(path_len).map_err(|_| Fault::CapacityExceeded)?;
        if material_id.capacity() != id_len || relative_path.capacity() != path_len {
            return Err(Fault::CapacityExceeded);
        }
        material_id.push_str("artifact:");
        material_id.push_str(&file.relative_path);
        relative_path.push_str("materials/artifact-spool/");
        relative_path.push_str(&file.relative_path);
        let plain_len = file.byte_length;
        let plain_sha256 = file.sha256;
        op.require_effect()?;
        // Everything fallible is finished while the original next file is still
        // resident. These pure moves cannot orphan a partially transferred FD.
        let file = state.snapshot_parts.as_mut().expect("verified original parts retained")
            .2.pop().expect("checked original next snapshot file remains resident");
        let file = file.into_owned_file();
        state.files.push(CaptureOwnedMaterialFile {
            kind: WholePgMaterialKind::Artifact, material_id, relative_path,
            plain_len, plain_sha256, file,
        });
    }
    op.require_effect()?;
    Ok(())
}


impl NormalCaptureMaterials {
    // Internal worker body, not a release/task getter. The owner remains in the
    // Source's original resident Work while the closure borrows it.
    pub(crate) fn run_original_metadata_worker(
        &mut self,
        originals: &mut Option<Vec<CaptureOwnedMaterialFile>>,
        parent: &File,
        parent_path: &std::path::Path,
        range: &(String, String, u32, u32),
        op: &Arc<CaptureOperation>,
        runtime: &tokio::runtime::Handle,
        panic: &mut Option<Box<dyn std::any::Any + Send + 'static>>,
    ) -> (Result<(), Fault>, Result<(u64, u64), Fault>) {
        let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // This full future contains the nested original snapshot future.
            // Charge its actual inline frame once; no second inline grant.
            let future = self.prepare_original_metadata_worker(
                originals, parent, parent_path, range, op,
            );
            op.reserve_original_resources(0, std::mem::size_of_val(&future) as u64)?;
            runtime.block_on(future)
        }));
        let body = match returned {
            Ok(actual) => actual,
            Err(payload) => {
                *panic = Some(payload);
                Err(Fault::ClosingPending)
            }
        };
        // These DATA branches are observations of this one private original
        // state. There is no caller-provided count or global zero default.
        let snapshot = if !self.snapshot_started {
            if self.snapshot_task.is_none() && self.snapshot_joined.is_none()
                && self.snapshot.is_none() && self.snapshot_failure.is_none()
                && self.snapshot_parts.is_none()
            {
                // The sole start marker was never consumed in this body.
                Ok((0, 0))
            } else { Err(Fault::IntentMismatch) }
        } else if let Some(joined) = &self.snapshot_joined {
            match joined {
                Ok(_) => Ok((1, 1)), // full actual JoinResult is still resident
                Err(_) => Err(Fault::ClosingPending), // original unknown/panic
            }
        } else if self.snapshot_task.is_some() {
            Ok((1, 0)) // original handle issued; no successful join result yet
        } else if self.snapshot.is_some() || self.snapshot_failure.is_some()
            || self.snapshot_parts.is_some()
        {
            // Only the real joined result can move into these original slots.
            Ok((1, 1))
        } else { Err(Fault::ClosingPending) };
        (body, snapshot)
    }

    async fn prepare_original_metadata_worker(
        &mut self,
        originals: &mut Option<Vec<CaptureOwnedMaterialFile>>,
        parent: &File,
        parent_path: &std::path::Path,
        range: &(String, String, u32, u32),
        op: &Arc<CaptureOperation>,
    ) -> Result<(), Fault> {
        op.require_effect()?;
        if self.original_metadata_prepared.is_some()
            || self.original_metadata_retirement != OriginalMetadataRetirement::Unentered
        {
            return Err(Fault::IntentMismatch);
        }
        self.freeze_original_audit_material(originals, parent, parent_path, op.as_ref())?;
        freeze_original_artifact_snapshot(self, op, range).await?;
        prepay_original_metadata_last_use(self, op)?;
        let state = self;
    for expected in &state.config {
        if FileIdentity::of(state.opened_file(expected.file)?, op)? != expected.identity {
            return Err(Fault::SourceChanged);
        }
        let found = state
            .files
            .iter()
            .find(|file| {
                file.kind == WholePgMaterialKind::PostgresConfig
                    && file.relative_path == expected.relative
            })
            .ok_or(Fault::MaterialMissing)?;
        if found.plain_len != expected.identity.bytes || found.plain_sha256 != expected.sha256 {
            return Err(Fault::SourceChanged);
        }
    }
    state.installation.verify_original(op.as_ref())?;
    // Metadata/snapshot FD production is joined before this check; missing producer output
    // remains a refusal, never an empty coverage assertion.
    let expected = state.expected()?;
    let source_claim = WholePgSourceClaim {
        instance_id: expected.instance_id.clone(),
        dataset_id: expected.dataset_id.clone(),
        deployment_id: expected.deployment_id.clone(),
        tenant_id: expected.tenant_id.clone(),
        system_identifier: expected.system_identifier.clone(),
        database_oid: expected.database_oid,
        key_id: state.key_id.as_ref().ok_or(Fault::SecretInvalid)?.clone(),
        key_version: u32::try_from(state.key_version.ok_or(Fault::SecretInvalid)?)
            .map_err(|_| Fault::SecretInvalid)?,
        canary_material_id: "key-metadata".to_owned(),
        schema_material_id: "schema".to_owned(),
        migration_material_id: "migrations".to_owned(),
        compatibility_material_id: "compatibility".to_owned(),
    };

    for (copied, original) in [
        (&source_claim.instance_id, &expected.instance_id),
        (&source_claim.dataset_id, &expected.dataset_id),
        (&source_claim.deployment_id, &expected.deployment_id),
        (&source_claim.tenant_id, &expected.tenant_id),
        (&source_claim.system_identifier, &expected.system_identifier),
        (&source_claim.key_id, state.key_id.as_ref().ok_or(Fault::SecretInvalid)?),
    ] {
        if copied.capacity() > original.capacity() { return Err(Fault::CapacityExceeded); }
    }
    for (copied, literal) in [
        (&source_claim.canary_material_id, "key-metadata"),
        (&source_claim.schema_material_id, "schema"),
        (&source_claim.migration_material_id, "migrations"),
        (&source_claim.compatibility_material_id, "compatibility"),
    ] {
        if copied.capacity() > literal.len() { return Err(Fault::CapacityExceeded); }
    }
    state.original_metadata_prepared.as_mut().ok_or(Fault::MaterialMissing)?
        .source = Some(source_claim);
    for kind in WholePgMaterialKind::ALL
        .into_iter()
        .filter(|kind| !kind.is_secret())
    {
        let inventory = match kind {
            WholePgMaterialKind::ProfileInventory =>
                Some(("profile-inventory", &state.profile_inventory_projection)),
            WholePgMaterialKind::WorkspaceInventory =>
                Some(("workspace-inventory", &state.workspace_inventory_projection)),
            _ => None,
        };
        let evidence = state.files.iter()
            .find(|file| file.kind == kind && inventory.is_none_or(|(id, _)| file.material_id == id))
            .ok_or(Fault::MaterialMissing)?;
        let presence = if let Some((_, attempt)) = inventory {
            let construction = state.screen.assembly.as_ref().ok_or(Fault::SourceChanged)?.construction;
            if !matches!(construction, OriginalDesktopConstruction::PostgresBuiltInToolsFreshScreen)
                || state.normal.is_none() || state.host.is_none() || state.preference_fact.is_none()
                || !attempt.started || !matches!(attempt.measured_result, Some(Ok(())))
                || !matches!(attempt.written_result, Some(Ok(())))
                || attempt.measured_fault.is_some() || attempt.written_fault.is_some()
                || attempt.expected != Some((evidence.plain_len, evidence.plain_sha256))
                || evidence.plain_len == 0 {
                return Err(Fault::MaterialMissing);
            }
            // The completed nonempty inventory encoded this real construction+host+SQL proof.
            // This is only its physical root set, even when app-local preferences are present.
            WholePgPresence::ControlledEmpty
        } else {
            WholePgPresence::Present
        };
        let claim = WholePgCoverageClaim {
            kind, presence, evidence_material_id: evidence.material_id.clone(),
        };
        if claim.evidence_material_id.capacity() > evidence.material_id.capacity() {
            return Err(Fault::CapacityExceeded);
        }
        state.original_metadata_prepared.as_mut().ok_or(Fault::MaterialMissing)?
            .coverage.push(claim);
    }
    op.require_effect()?;
    if state.normal.is_none() || state.original_provenance.is_none()
        || state.tool_inventory.is_some() {
        return Err(Fault::MaterialMissing);
    }

        let tool_inventory_identity = state.tool_inventory_projection.expected.ok_or(Fault::MaterialMissing)?;
        state.original_metadata_prepared.as_mut().ok_or(Fault::MaterialMissing)?
            .tool_inventory_identity = Some(tool_inventory_identity);
        if !matches!(state.original_before_observation.as_ref(), Some(Ok(_)))
            || !matches!(state.original_after_observation.as_ref(), Some(Ok(_)))
            || state.local_canary.is_none()
            || !state.snapshot_started || state.snapshot_task.is_some()
            || state.snapshot_joined.is_some() || state.snapshot.is_some()
            || state.snapshot_failure.is_some() || state.snapshot_parts.is_none()
        {
            return Err(Fault::ClosingPending);
        }
        op.require_effect()?;
        state.original_metadata_retirement = OriginalMetadataRetirement::Entered;
        // No fallible gap lies between these selected takes and actual built-in
        // destruction on this same blocking worker. Existing sensitive Facts
        // destructors execute here. The current raw canary Row still lacks the
        // separately held five-String explicit wipe; its plain Drop earns no
        // zeroization/Closed acceptance. A destructor panic is caught outside
        // this borrow, with Entered preserved; consumed allocations are not
        // falsely claimed recovered or restored.
        let normal = state.normal.take().expect("checked original normal facts retained");
        let before = state.original_before_observation.take().expect("checked original before result retained");
        let after = state.original_after_observation.take().expect("checked original after result retained");
        let canary = state.local_canary.take().expect("checked original local canary retained");
        drop((normal, before, after, canary));
        state.original_metadata_retirement = OriginalMetadataRetirement::Returned;
        op.require_effect()?;
        Ok(())
    }
}

fn prepay_original_metadata_last_use(
    state: &mut NormalCaptureMaterials, op: &CaptureOperation,
) -> Result<(), Fault> {
    if state.original_metadata_prepared.is_some()
        || state.original_metadata_retirement != OriginalMetadataRetirement::Unentered
    {
        return Err(Fault::IntentMismatch);
    }
    let count = WholePgMaterialKind::ALL.into_iter().filter(|kind| !kind.is_secret()).count();
    let expected = state.expected.as_ref().ok_or(Fault::MaterialMissing)?;
    let mut strings = 0u64;
    for value in [&expected.instance_id, &expected.dataset_id, &expected.deployment_id,
        &expected.tenant_id, &expected.system_identifier,
        state.key_id.as_ref().ok_or(Fault::SecretInvalid)?,
    ] {
        strings = strings.checked_add(value.capacity() as u64).ok_or(Fault::BoundsOverflow)?;
    }
    strings = original_snapshot_sum(&[strings,
        ("key-metadata".len() + "schema".len() + "migrations".len() + "compatibility".len()) as u64,
    ])?;
    // Each coverage kind selects at most one distinct-kind file. Sum all real
    // IDs as a conservative requested backing bound; no second projection/IO.
    for file in &state.files {
        strings = strings.checked_add(file.material_id.capacity() as u64)
            .ok_or(Fault::BoundsOverflow)?;
    }
    let vector = original_snapshot_mul(count as u64, std::mem::size_of::<WholePgCoverageClaim>() as u64)?;
    let fixed = original_snapshot_sum(&[
        original_snapshot_slot::<WholePgSourceClaim>()?,
        original_snapshot_slot::<WholePgCoverageClaim>()?,
        original_snapshot_slot::<[(&String, &String); 6]>()?,
        original_snapshot_slot::<std::array::IntoIter<(&String, &String), 6>>()?,
        original_snapshot_slot::<Option<(&String, &String)>>()?,
        original_snapshot_slot::<(&String, &String)>()?,
        original_snapshot_slot::<[(&String, &str); 4]>()?,
        original_snapshot_slot::<std::array::IntoIter<(&String, &str), 4>>()?,
        original_snapshot_slot::<Option<(&String, &str)>>()?,
        original_snapshot_slot::<(&String, &str)>()?,
        original_snapshot_slot::<OriginalMetadataPrepared>()?,
        original_snapshot_slot::<std::slice::Iter<'_, CaptureOwnedMaterialFile>>()?,
        original_snapshot_slot::<std::array::IntoIter<WholePgMaterialKind, { WholePgMaterialKind::ALL.len() }>>()?,
        original_snapshot_slot::<Option<WholePgMaterialKind>>()?,
        original_snapshot_slot::<WholePgMaterialKind>()?,
        original_snapshot_mul(4, original_snapshot_slot::<FileIdentity>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<std::fs::Metadata>()?)?,
        original_snapshot_mul(4, original_snapshot_slot::<Result<std::fs::Metadata, std::io::Error>>()?)?,
        // The selected normal/before/after/canary return bodies and tuple are
        // actual moved stack slots in addition to the resident original state.
        original_snapshot_slot::<CapturedDbFacts>()?,
        original_snapshot_mul(2, original_snapshot_slot::<Result<CapturedDbFacts, CaptureSqlFailure>>()?)?,
        original_snapshot_slot::<openbot_infra::db::desktop_vault_canary::DesktopVaultCanaryRow>()?,
        original_snapshot_slot::<(
            CapturedDbFacts, Result<CapturedDbFacts, CaptureSqlFailure>,
            Result<CapturedDbFacts, CaptureSqlFailure>,
            openbot_infra::db::desktop_vault_canary::DesktopVaultCanaryRow,
        )>()?,
        original_snapshot_slot::<Result<(), Fault>>()?,
        original_snapshot_mul(8, original_snapshot_slot::<u64>()?)?,
    ])?;
    op.reserve_original_resources(0, original_snapshot_sum(&[strings, vector, fixed])?)?;
    state.original_metadata_prepared = Some(OriginalMetadataPrepared {
        source: None, coverage: Vec::new(), tool_inventory_identity: None,
    });
    let coverage = &mut state.original_metadata_prepared.as_mut()
        .expect("prepared ordinary DATA slot installed").coverage;
    coverage.try_reserve_exact(count).map_err(|_| Fault::CapacityExceeded)?;
    if coverage.capacity() != count { return Err(Fault::CapacityExceeded); }
    Ok(())
}

pub(crate) async fn finish_capture_materials(
    source: &mut CaptureSourceOwner,
    op: &Arc<CaptureOperation>,
) -> Result<CaptureMaterialsClosed, MaterialFault> {
    op.require_effect()?;
    {
        let (client, state) = source.capture_sql_and_materials()?;
        if state.phase != ReadPhase::NormalCollected
            || state.original_before_observation.is_some()
            || state.original_after_observation.is_some()
        {
            return Err(Fault::IntentMismatch);
        }
        state.phase = ReadPhase::BeforeReading;
        // Both original Result slots stay resident. The unwrapped return and borrowed
        // classification temporaries are used one observation at a time; no payload is copied.
        let known = (std::mem::size_of::<Option<Result<CapturedDbFacts, CaptureSqlFailure>>>() as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<CapturedDbFacts, CaptureSqlFailure>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<&Result<CapturedDbFacts, CaptureSqlFailure>>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<&CapturedDbFacts>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), Fault>>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        op.reserve_original_resources(0, known)?;
        state.original_before_observation = Some(
            openbot_infra::db::capture_materials::collect_database_materials_before(
                client,
                state.expected.as_ref().ok_or(Fault::MaterialMissing)?,
                state.budget.as_mut().ok_or(Fault::MaterialMissing)?,
                op.as_ref(),
            )
            .await,
        );
        // Keep the full actual SQL result before the original E postcheck or mapping.
        op.require_effect()?;
        let before = match state.original_before_observation.as_ref().ok_or(Fault::MaterialMissing)? {
            Ok(facts) => facts,
            Err(fault) => return Err(sql_fault(*fault)),
        };
        if !state
            .normal
            .as_ref()
            .ok_or(Fault::MaterialMissing)?
            .matches_after(before)
        {
            return Err(Fault::SourceChanged);
        }
        state.phase = ReadPhase::BeforeVerified;
    }
    source.materials_mut()?.phase = ReadPhase::BackupStarted;
    source.run_backup_before_postcheck(op).await?;
    source.materials_mut()?.phase = ReadPhase::BackupClosed;
    {
        let (client, state) = source.capture_sql_and_materials()?;
        if state.phase != ReadPhase::BackupClosed
            || state.original_after_observation.is_some()
            || !matches!(state.original_before_observation.as_ref(), Some(Ok(_)))
        {
            return Err(Fault::IntentMismatch);
        }
        state.phase = ReadPhase::AfterReading;
        state.original_after_observation = Some(
            openbot_infra::db::capture_materials::collect_database_materials_before(
                client,
                state.expected.as_ref().ok_or(Fault::MaterialMissing)?,
                state.budget.as_mut().ok_or(Fault::MaterialMissing)?,
                op.as_ref(),
            )
            .await,
        );
        op.require_effect()?;
        let after = match state.original_after_observation.as_ref().ok_or(Fault::MaterialMissing)? {
            Ok(facts) => facts,
            Err(fault) => return Err(sql_fault(*fault)),
        };
        if !state
            .normal
            .as_ref()
            .ok_or(Fault::MaterialMissing)?
            .matches_after(after)
        {
            return Err(Fault::SourceChanged);
        }
        state.phase = ReadPhase::AfterVerified;
    }
    source.materials_mut()?.phase = ReadPhase::SourcesClosing;
    source.stop_after_material_read(op).await?;
    source.materials_mut()?.phase = ReadPhase::SourcesClosed;
    let range = source.closed_backup_range()?;
    let metadata = source.freeze_original_audit_material(op, range);
    op.reserve_original_resources(0, std::mem::size_of_val(&metadata) as u64)?;
    let range = metadata.await?;
    {
        let state = source.materials_mut()?;
        if state.original_metadata_retirement != OriginalMetadataRetirement::Returned
            || state.normal.is_some() || state.original_before_observation.is_some()
            || state.original_after_observation.is_some() || state.local_canary.is_some()
            || state.original_provenance.is_none() || state.tool_inventory.is_some()
        {
            return Err(Fault::ClosingPending);
        }
        let prepared = state.original_metadata_prepared.as_ref().ok_or(Fault::MaterialMissing)?;
        if prepared.source.is_none() || prepared.tool_inventory_identity.is_none()
            || prepared.coverage.len() != WholePgMaterialKind::ALL.into_iter()
                .filter(|kind| !kind.is_secret()).count()
        {
            return Err(Fault::MaterialMissing);
        }
    }
    op.require_effect()?;
    let mut retained = source.take_materials()?;
    // All checks and the actual worker join have completed. These moves alone
    // derive the existing Closed return; prepared DATA had no such authority.
    let prepared = retained.original_metadata_prepared.take()
        .expect("checked completed ordinary metadata DATA retained");
    let files = std::mem::take(&mut retained.files);
    let provenance = retained.original_provenance.take()
        .expect("checked original provenance remains resident");
    Ok(CaptureMaterialsClosed {
        files,
        coverage: prepared.coverage,
        source: prepared.source.expect("checked original source DATA retained"),
        backup_range: range,
        provenance,
        tool_inventory_identity: prepared.tool_inventory_identity
            .expect("checked original tool DATA retained"),
        retained,
    })
}

fn sql_fault(error: CaptureSqlFailure) -> Fault {
    match error {
        CaptureSqlFailure::Clock => Fault::DeadlineExpired,
        CaptureSqlFailure::Bounds => Fault::CapacityExceeded,
        CaptureSqlFailure::CommitUnknown | CaptureSqlFailure::RollbackUnknown => {
            Fault::ClosingPending
        }
        CaptureSqlFailure::Database => Fault::IoFailure,
        _ => Fault::SourceChanged,
    }
}
// Consume one known local admission before the actual FD-producing call. Neither
// IO error nor a later clock/identity refusal returns it to this same source state.
fn reserve_local_new_material_fd(admissions: &mut u64, maximum: u64) -> Result<(), Fault> {
    let next = admissions.checked_add(1).ok_or(Fault::BoundsOverflow)?;
    if next > maximum {
        return Err(Fault::CapacityExceeded);
    }
    *admissions = next;
    Ok(())
}
fn open_child(
    state: &mut NormalCaptureMaterials,
    parent: MaterialParent,
    name: &str,
    directory: bool,
    op: &CaptureOperation,
) -> Result<usize, Fault> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." || name.contains('\0') {
        return Err(Fault::PathUnsafe);
    }
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    // Reserve before obtaining any new FD. This is resident custody, not a replacement
    // for the separately held whole-operation/global FD and metadata budget gate.
    state
        .opened
        .try_reserve(1)
        .map_err(|_| Fault::CapacityExceeded)?;
    op.require_effect()?;
    reserve_local_new_material_fd(
        &mut state.local_new_fd_admissions,
        op.profile().carrier.max_open_files,
    )?;
    let opened = rustix::fs::openat(state.parent_file(parent)?, name, flags, Mode::empty());
    let index = state.opened.len();
    match opened {
        Ok(file) => state.opened.push(File::from(file)),
        Err(_) => {
            op.require_effect()?;
            return Err(Fault::IoFailure);
        }
    }
    op.require_effect()?;
    let identity = FileIdentity::of(state.opened_file(index)?, op)?;
    let p = FileIdentity::of(state.parent_file(parent)?, op)?;
    if identity.uid != p.uid
        || identity.mode & 0o077 != 0
        || directory && identity.mode & 0o170000 != 0o040000
        || !directory && (identity.mode & 0o170000 != 0o100000 || identity.links != 1)
    {
        return Err(Fault::PathUnsafe);
    }
    Ok(index)
}
fn hash_original(
    file: &File,
    identity: FileIdentity,
    form: OriginalConfigForm,
    original_port: u16,
    op: &CaptureOperation,
) -> Result<[u8; 32], Fault> {
    let size = op
        .profile()
        .carrier
        .max_chunk_plain_bytes
        .min(identity.bytes.max(1));
    let mut buffer = Zeroizing::new(vec![
        0_u8;
        usize::try_from(size)
            .map_err(|_| Fault::BoundsOverflow)?
    ]);
    let mut lexer = OriginalConfigLexer::new(form, original_port)?;
    let mut sha = Sha256::new();
    let mut offset = 0_u64;
    loop {
        op.require_effect()?;
        let start = lexer.preserved_prefix_len();
        if start >= buffer.len() {
            return Err(Fault::CapacityExceeded);
        }
        let observed = file.read_at(&mut buffer[start..], offset);
        op.require_effect()?;
        let n = observed.map_err(|_| Fault::IoFailure)?;
        if n == 0 {
            break;
        }
        offset = offset.checked_add(n as u64).ok_or(Fault::BoundsOverflow)?;
        if offset > identity.bytes {
            return Err(Fault::SourceChanged);
        }
        // Hash the actual read before the lexer may overwrite an already consumed
        // prefix. Unread bytes are never used as token storage.
        sha.update(&buffer[start..start + n]);
        for index in start..start + n {
            let byte = buffer[index];
            lexer.feed(byte, &mut buffer, index + 1)?;
        }
    }
    lexer.finish()?;
    if offset != identity.bytes || FileIdentity::of(file, op)? != identity {
        return Err(Fault::SourceChanged);
    }
    op.require_effect()?;
    Ok(sha.finalize().into())
}

#[cfg(test)]
mod local_new_fd_admission_tests {
    use super::{Fault, reserve_local_new_material_fd};

    #[test]
    fn a_consumed_local_slot_is_not_refunded_before_the_next_admission() {
        let mut admissions = 0;
        assert_eq!(reserve_local_new_material_fd(&mut admissions, 2), Ok(()));
        assert_eq!(reserve_local_new_material_fd(&mut admissions, 2), Ok(()));
        assert_eq!(
            reserve_local_new_material_fd(&mut admissions, 2),
            Err(Fault::CapacityExceeded)
        );
        assert_eq!(admissions, 2);
    }

    #[test]
    fn zero_limit_and_counter_overflow_refuse_before_a_new_slot() {
        let mut admissions = 0;
        assert_eq!(
            reserve_local_new_material_fd(&mut admissions, 0),
            Err(Fault::CapacityExceeded)
        );
        assert_eq!(admissions, 0);
        admissions = u64::MAX;
        assert_eq!(
            reserve_local_new_material_fd(&mut admissions, u64::MAX),
            Err(Fault::BoundsOverflow)
        );
        assert_eq!(admissions, u64::MAX);
    }
}

// Necessary normal-only classification, not a PostgreSQL semantic safety witness.
// State is fixed-size; only the first decoded timezone uses the already-consumed
// prefix of the original Zeroizing read buffer. No full-file or line copy exists.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalConfigForm {
    Main,
    Auto,
    Hba,
    Ident,
}
#[derive(Clone, Copy)]
enum ConfigLexPhase {
    LineStart,
    Name,
    AfterName,
    BeforeValue,
    UnquotedValue,
    QuotedValue,
    QuoteSeen,
    QuotedEscape,
    AfterValue,
    Comment,
}
const CONFIG_KEYS: &[&[u8]] = &[
    b"max_connections",
    b"shared_buffers",
    b"lc_messages",
    b"lc_monetary",
    b"lc_numeric",
    b"lc_time",
    b"datestyle",
    b"default_text_search_config",
    b"dynamic_shared_memory_type",
    b"min_wal_size",
    b"max_wal_size",
    b"timezone",
    b"log_timezone",
    b"listen_addresses",
    b"port",
    b"ssl",
    b"password_encryption",
    b"logging_collector",
    b"unix_socket_directories",
];
const MAIN_CONFIG_REQUIRED: u32 = (1 << 11) - 1;
const CONFIG_TIMEZONES: u32 = (1 << 11) | (1 << 12);
const AUTO_CONFIG_REQUIRED: u32 = (1 << 0) | (1 << 8) | (((1 << 6) - 1) << 13);
const TIMEZONE_DENIED: &[&[u8]] = &[b"nan", b"inf", b"infinity", b"interval"];

struct OriginalConfigLexer {
    form: OriginalConfigForm,
    original_port: u16,
    phase: ConfigLexPhase,
    name_candidates: u32,
    name_len: usize,
    key: usize,
    seen: u32,
    quoted: bool,
    value_len: usize,
    number: u64,
    shared_unit: u8,
    shared_multiplier: u64,
    literal_candidates: u8,
    record_timezone: bool,
    timezone_prefix_len: usize,
    timezone_component_start: bool,
    timezone_previous: u8,
    timezone_denied: u8,
    hba_rule: usize,
    hba_field: usize,
    hba_token_len: usize,
    hba_in_token: bool,
}
impl OriginalConfigLexer {
    fn new(form: OriginalConfigForm, original_port: u16) -> Result<Self, Fault> {
        if original_port == 0 {
            return Err(Fault::SourceChanged);
        }
        Ok(Self {
            form,
            original_port,
            phase: ConfigLexPhase::LineStart,
            name_candidates: 0,
            name_len: 0,
            key: 0,
            seen: 0,
            quoted: false,
            value_len: 0,
            number: 0,
            shared_unit: 0,
            shared_multiplier: 0,
            literal_candidates: 0,
            record_timezone: false,
            timezone_prefix_len: 0,
            timezone_component_start: true,
            timezone_previous: 0,
            timezone_denied: 0,
            hba_rule: 0,
            hba_field: 0,
            hba_token_len: 0,
            hba_in_token: false,
        })
    }
    fn preserved_prefix_len(&self) -> usize {
        self.timezone_prefix_len
    }
    fn feed(&mut self, byte: u8, buffer: &mut [u8], consumed: usize) -> Result<(), Fault> {
        if (byte < 0x20 && byte != b'\t' && byte != b'\n') || byte == 0x7f {
            return Err(Fault::PathUnsafe);
        }
        match self.form {
            OriginalConfigForm::Ident => {
                if matches!(self.phase, ConfigLexPhase::Comment) {
                    if byte == b'\n' {
                        self.phase = ConfigLexPhase::LineStart;
                    }
                } else if byte == b'#' {
                    self.phase = ConfigLexPhase::Comment;
                } else if !matches!(byte, b' ' | b'\t' | b'\n') {
                    return Err(Fault::PathUnsafe);
                }
                Ok(())
            }
            OriginalConfigForm::Hba => self.feed_hba(byte),
            OriginalConfigForm::Main | OriginalConfigForm::Auto => {
                self.feed_setting(byte, buffer, consumed)
            }
        }
    }
    fn feed_setting(&mut self, byte: u8, buffer: &mut [u8], consumed: usize) -> Result<(), Fault> {
        match self.phase {
            ConfigLexPhase::LineStart => match byte {
                b' ' | b'\t' | b'\n' => {}
                b'#' => self.phase = ConfigLexPhase::Comment,
                _ => {
                    self.name_candidates = (1 << CONFIG_KEYS.len()) - 1;
                    self.name_len = 0;
                    self.phase = ConfigLexPhase::Name;
                    self.feed_name(byte)?;
                }
            },
            ConfigLexPhase::Name => match byte {
                b'=' => {
                    self.finish_name()?;
                    self.phase = ConfigLexPhase::BeforeValue;
                }
                b' ' | b'\t' => {
                    self.finish_name()?;
                    self.phase = ConfigLexPhase::AfterName;
                }
                _ => self.feed_name(byte)?,
            },
            ConfigLexPhase::AfterName => match byte {
                b' ' | b'\t' => {}
                b'=' => self.phase = ConfigLexPhase::BeforeValue,
                _ => return Err(Fault::PathUnsafe),
            },
            ConfigLexPhase::BeforeValue => match byte {
                b' ' | b'\t' => {}
                b'\'' => {
                    self.begin_value(true);
                    self.phase = ConfigLexPhase::QuotedValue;
                }
                b'\n' | b'#' => return Err(Fault::PathUnsafe),
                _ => {
                    self.begin_value(false);
                    self.phase = ConfigLexPhase::UnquotedValue;
                    self.feed_value(byte, buffer, consumed)?;
                }
            },
            ConfigLexPhase::UnquotedValue => match byte {
                b' ' | b'\t' => {
                    self.finish_value()?;
                    self.phase = ConfigLexPhase::AfterValue;
                }
                b'\n' => {
                    self.finish_value()?;
                    self.phase = ConfigLexPhase::LineStart;
                }
                b'#' => {
                    self.finish_value()?;
                    self.phase = ConfigLexPhase::Comment;
                }
                b'\'' | b'\\' => return Err(Fault::PathUnsafe),
                _ => self.feed_value(byte, buffer, consumed)?,
            },
            ConfigLexPhase::QuotedValue => match byte {
                b'\'' => self.phase = ConfigLexPhase::QuoteSeen,
                b'\\' => self.phase = ConfigLexPhase::QuotedEscape,
                b'\n' => return Err(Fault::PathUnsafe),
                _ => self.feed_value(byte, buffer, consumed)?,
            },
            ConfigLexPhase::QuotedEscape => {
                if !matches!(byte, b'\'' | b'\\') {
                    return Err(Fault::PathUnsafe);
                }
                self.feed_value(byte, buffer, consumed)?;
                self.phase = ConfigLexPhase::QuotedValue;
            }
            ConfigLexPhase::QuoteSeen => match byte {
                b'\'' => {
                    self.feed_value(byte, buffer, consumed)?;
                    self.phase = ConfigLexPhase::QuotedValue;
                }
                b' ' | b'\t' => {
                    self.finish_value()?;
                    self.phase = ConfigLexPhase::AfterValue;
                }
                b'\n' => {
                    self.finish_value()?;
                    self.phase = ConfigLexPhase::LineStart;
                }
                b'#' => {
                    self.finish_value()?;
                    self.phase = ConfigLexPhase::Comment;
                }
                _ => return Err(Fault::PathUnsafe),
            },
            ConfigLexPhase::AfterValue => match byte {
                b' ' | b'\t' => {}
                b'\n' => self.phase = ConfigLexPhase::LineStart,
                b'#' => self.phase = ConfigLexPhase::Comment,
                _ => return Err(Fault::PathUnsafe),
            },
            ConfigLexPhase::Comment => {
                if byte == b'\n' {
                    self.phase = ConfigLexPhase::LineStart;
                }
            }
        }
        Ok(())
    }
    fn feed_name(&mut self, byte: u8) -> Result<(), Fault> {
        for (index, name) in CONFIG_KEYS.iter().enumerate() {
            if name.get(self.name_len).copied() != Some(byte.to_ascii_lowercase()) {
                self.name_candidates &= !(1 << index);
            }
        }
        if self.name_candidates == 0 {
            return Err(Fault::PathUnsafe);
        }
        self.name_len = self.name_len.checked_add(1).ok_or(Fault::BoundsOverflow)?;
        Ok(())
    }
    fn finish_name(&mut self) -> Result<(), Fault> {
        let key = CONFIG_KEYS
            .iter()
            .enumerate()
            .find(|(index, name)| {
                self.name_candidates & (1 << index) != 0 && name.len() == self.name_len
            })
            .map(|(index, _)| index)
            .ok_or(Fault::PathUnsafe)?;
        let allowed = match self.form {
            OriginalConfigForm::Main => MAIN_CONFIG_REQUIRED | CONFIG_TIMEZONES,
            OriginalConfigForm::Auto => AUTO_CONFIG_REQUIRED,
            _ => return Err(Fault::PathUnsafe),
        };
        if allowed & (1 << key) == 0 || self.seen & (1 << key) != 0 {
            return Err(Fault::PathUnsafe);
        }
        self.key = key;
        Ok(())
    }
    fn begin_value(&mut self, quoted: bool) {
        self.quoted = quoted;
        self.value_len = 0;
        self.number = 0;
        self.shared_unit = 0;
        self.shared_multiplier = 0;
        self.literal_candidates = u8::MAX;
        self.record_timezone = self.seen & CONFIG_TIMEZONES == 0;
        self.timezone_component_start = true;
        self.timezone_previous = 0;
        self.timezone_denied = 0x0f;
    }
    fn literals(&self) -> &'static [&'static [u8]] {
        match self.key {
            2..=5 => &[b"C"],
            6 => &[b"iso, mdy", b"iso, dmy", b"iso, ymd"],
            7 => &[b"pg_catalog.english"],
            8 if self.form == OriginalConfigForm::Main => &[b"posix", b"sysv"],
            8 => &[b"posix"],
            9 => &[b"80MB"],
            10 => &[b"1GB"],
            13 => &[b"127.0.0.1"],
            15 | 17 => &[b"off"],
            16 => &[b"scram-sha-256"],
            18 => &[b""],
            _ => &[],
        }
    }
    fn feed_value(&mut self, byte: u8, buffer: &mut [u8], consumed: usize) -> Result<(), Fault> {
        if !byte.is_ascii() {
            return Err(Fault::PathUnsafe);
        }
        match self.key {
            0 | 14 => {
                if !byte.is_ascii_digit() || self.value_len >= 20 {
                    return Err(Fault::PathUnsafe);
                }
                if (self.key == 14 || self.key == 0 && self.form == OriginalConfigForm::Auto)
                    && self.value_len == 0
                    && byte == b'0'
                {
                    return Err(Fault::PathUnsafe);
                }
                self.number = self
                    .number
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                    .ok_or(Fault::BoundsOverflow)?;
            }
            1 => match self.shared_unit {
                0 if byte.is_ascii_digit() => {
                    if self.value_len >= 20 {
                        return Err(Fault::PathUnsafe);
                    }
                    self.number = self
                        .number
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                        .ok_or(Fault::BoundsOverflow)?;
                }
                0 if self.value_len != 0 && matches!(byte, b'k' | b'M') => {
                    self.shared_multiplier = if byte == b'k' { 1024 } else { 1048576 };
                    self.shared_unit = 1;
                }
                1 if byte == b'B' => self.shared_unit = 2,
                _ => return Err(Fault::PathUnsafe),
            },
            11 | 12 => self.feed_timezone(byte, buffer, consumed)?,
            _ => {
                let folded = if self.key == 6 {
                    byte.to_ascii_lowercase()
                } else {
                    byte
                };
                for (index, literal) in self.literals().iter().enumerate() {
                    if literal.get(self.value_len).copied() != Some(folded) {
                        self.literal_candidates &= !(1 << index);
                    }
                }
                if !self
                    .literals()
                    .iter()
                    .enumerate()
                    .any(|(index, _)| self.literal_candidates & (1 << index) != 0)
                {
                    return Err(Fault::PathUnsafe);
                }
            }
        }
        self.value_len = self.value_len.checked_add(1).ok_or(Fault::BoundsOverflow)?;
        Ok(())
    }
    fn feed_timezone(&mut self, byte: u8, buffer: &mut [u8], consumed: usize) -> Result<(), Fault> {
        if self.value_len >= 255
            || self.value_len == 0 && !(byte.is_ascii_alphabetic() || byte == b'<')
            || !(byte.is_ascii_alphanumeric() || b"_+-/:.,<>".contains(&byte))
            || self.timezone_component_start && matches!(byte, b'/' | b'.')
            || byte == b'.' && self.timezone_previous == b'.'
        {
            return Err(Fault::PathUnsafe);
        }
        self.timezone_component_start = byte == b'/';
        self.timezone_previous = byte;
        for (index, denied) in TIMEZONE_DENIED.iter().enumerate() {
            if self.value_len < denied.len() {
                if denied[self.value_len] != byte.to_ascii_lowercase() {
                    self.timezone_denied &= !(1 << index);
                }
            } else if index != 3 {
                self.timezone_denied &= !(1 << index);
            }
        }
        if self.record_timezone {
            // Keep at least one byte available for every following read, including EOF.
            // The caller copied this consumed byte to a scalar before reaching here.
            if self.value_len >= buffer.len().saturating_sub(1) || self.value_len >= consumed {
                return Err(Fault::CapacityExceeded);
            }
            buffer[self.value_len] = byte;
            self.timezone_prefix_len =
                self.value_len.checked_add(1).ok_or(Fault::BoundsOverflow)?;
        } else if self.value_len >= self.timezone_prefix_len
            || buffer.get(self.value_len).copied() != Some(byte)
        {
            return Err(Fault::PathUnsafe);
        }
        Ok(())
    }
    fn finish_value(&mut self) -> Result<(), Fault> {
        let valid = match self.key {
            0 => {
                self.value_len != 0
                    && match self.form {
                        OriginalConfigForm::Main => (1..=100).contains(&self.number),
                        OriginalConfigForm::Auto => self.number == 32,
                        _ => false,
                    }
            }
            14 => self.value_len != 0 && self.number == u64::from(self.original_port),
            1 => {
                self.shared_unit == 2
                    && self.number != 0
                    && self
                        .number
                        .checked_mul(self.shared_multiplier)
                        .is_some_and(|bytes| bytes <= 134217728)
            }
            11 | 12 => {
                self.value_len != 0
                    && !self.timezone_component_start
                    && self.value_len == self.timezone_prefix_len
                    && !TIMEZONE_DENIED.iter().enumerate().any(|(index, denied)| {
                        self.timezone_denied & (1 << index) != 0
                            && (index == 3 || self.value_len == denied.len())
                    })
            }
            _ => self.literals().iter().enumerate().any(|(index, literal)| {
                self.literal_candidates & (1 << index) != 0
                    && self.value_len == literal.len()
                    && (self.value_len != 0 || self.quoted)
            }),
        };
        if !valid {
            return Err(Fault::PathUnsafe);
        }
        self.seen |= 1 << self.key;
        Ok(())
    }
    fn hba_tokens(&self) -> &'static [&'static [u8]] {
        match self.hba_rule {
            0 => &[b"local", b"all", b"all", b"reject"],
            1 => &[b"host", b"all", b"all", b"127.0.0.1/32", b"scram-sha-256"],
            2 => &[b"host", b"all", b"all", b"::1/128", b"scram-sha-256"],
            _ => &[],
        }
    }
    fn feed_hba(&mut self, byte: u8) -> Result<(), Fault> {
        if matches!(self.phase, ConfigLexPhase::Comment) {
            if byte == b'\n' {
                self.finish_hba_line()?;
                self.phase = ConfigLexPhase::LineStart;
            }
            return Ok(());
        }
        match byte {
            b' ' | b'\t' => self.finish_hba_token()?,
            b'\n' => self.finish_hba_line()?,
            b'#' => {
                self.finish_hba_token()?;
                self.phase = ConfigLexPhase::Comment;
            }
            _ => {
                let token = self
                    .hba_tokens()
                    .get(self.hba_field)
                    .copied()
                    .ok_or(Fault::PathUnsafe)?;
                if token.get(self.hba_token_len).copied() != Some(byte) {
                    return Err(Fault::PathUnsafe);
                }
                self.hba_token_len = self
                    .hba_token_len
                    .checked_add(1)
                    .ok_or(Fault::BoundsOverflow)?;
                self.hba_in_token = true;
            }
        }
        Ok(())
    }
    fn finish_hba_token(&mut self) -> Result<(), Fault> {
        if self.hba_in_token {
            let token = self
                .hba_tokens()
                .get(self.hba_field)
                .copied()
                .ok_or(Fault::PathUnsafe)?;
            if self.hba_token_len != token.len() {
                return Err(Fault::PathUnsafe);
            }
            self.hba_field = self.hba_field.checked_add(1).ok_or(Fault::BoundsOverflow)?;
            self.hba_token_len = 0;
            self.hba_in_token = false;
        }
        Ok(())
    }
    fn finish_hba_line(&mut self) -> Result<(), Fault> {
        self.finish_hba_token()?;
        if self.hba_field != 0 {
            if self.hba_field != self.hba_tokens().len() {
                return Err(Fault::PathUnsafe);
            }
            self.hba_rule = self.hba_rule.checked_add(1).ok_or(Fault::BoundsOverflow)?;
            self.hba_field = 0;
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Fault> {
        match self.form {
            OriginalConfigForm::Ident => return Ok(()),
            OriginalConfigForm::Hba => {
                self.finish_hba_line()?;
                return if self.hba_rule == 3 {
                    Ok(())
                } else {
                    Err(Fault::PathUnsafe)
                };
            }
            _ => {}
        }
        match self.phase {
            ConfigLexPhase::UnquotedValue | ConfigLexPhase::QuoteSeen => self.finish_value()?,
            ConfigLexPhase::LineStart | ConfigLexPhase::AfterValue | ConfigLexPhase::Comment => {}
            _ => return Err(Fault::PathUnsafe),
        }
        let valid = match self.form {
            OriginalConfigForm::Main => {
                self.seen == MAIN_CONFIG_REQUIRED
                    || self.seen == MAIN_CONFIG_REQUIRED | CONFIG_TIMEZONES
            }
            OriginalConfigForm::Auto => self.seen == AUTO_CONFIG_REQUIRED,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(Fault::PathUnsafe)
        }
    }
}

#[cfg(test)]
mod original_config_lexer_tests {
    use super::{Fault, OriginalConfigForm, OriginalConfigLexer};

    // Pure synthetic bytes only. Exercise the same consumed-prefix discipline without
    // constructing a Source, opening a cluster or running a PostgreSQL process.
    fn feed_prefix(
        form: OriginalConfigForm,
        input: &[u8],
        chunk: usize,
    ) -> Result<OriginalConfigLexer, Fault> {
        let mut lexer = OriginalConfigLexer::new(form, 54321)?;
        let mut buffer = vec![0_u8; chunk];
        let mut offset = 0;
        while offset < input.len() {
            let start = lexer.preserved_prefix_len();
            let room = buffer
                .len()
                .checked_sub(start)
                .filter(|room| *room != 0)
                .ok_or(Fault::CapacityExceeded)?;
            let n = room.min(input.len() - offset);
            buffer[start..start + n].copy_from_slice(&input[offset..offset + n]);
            for index in start..start + n {
                let byte = buffer[index];
                lexer.feed(byte, &mut buffer, index + 1)?;
            }
            offset += n;
        }
        Ok(lexer)
    }
    const MAIN: &[u8] = b"max_connections=32\nshared_buffers=16MB\nlc_messages='C'\nlc_monetary='C'\nlc_numeric='C'\nlc_time='C'\ndatestyle='ISO, MDY'\ndefault_text_search_config='pg_catalog.english'\ndynamic_shared_memory_type=posix\nmin_wal_size=80MB\nmax_wal_size=1GB\nlog_timezone='Etc/UTC'\ntimezone='Etc/UTC'";
    #[test]
    fn timezone_pair_survives_every_one_byte_tail_and_reversed_key_order() {
        assert_eq!(
            feed_prefix(OriginalConfigForm::Main, MAIN, 8).and_then(|mut lexer| lexer.finish()),
            Ok(())
        );
        assert_eq!(
            feed_prefix(OriginalConfigForm::Main, MAIN, 7).err(),
            Some(Fault::CapacityExceeded)
        );
    }
    #[test]
    fn unsafe_timezones_unknown_keys_duplicates_and_trailing_garbage_refuse() {
        for input in [
            b"timezone='nan'\n".as_slice(),
            b"timezone='1'\n",
            b"timezone='INTERVAL1'\n",
            b"timezone='Etc/../UTC'\n",
            b"include='x'\n",
            b"max_connections=32\nMAX_CONNECTIONS=32\n",
            b"shared_buffers=16\n",
            b"max_connections='32';\n",
        ] {
            assert!(feed_prefix(OriginalConfigForm::Main, input, 32).is_err());
        }
        assert!(feed_prefix(OriginalConfigForm::Ident, b"map user role\n", 4).is_err());
    }
    #[test]
    fn exact_auto_port_empty_socket_and_ordered_hba_have_closed_finishes() {
        let auto = b"listen_addresses='127.0.0.1'\nport=54321\nssl=off\npassword_encryption='scram-sha-256'\nmax_connections=32\nlogging_collector=off\nunix_socket_directories=''\ndynamic_shared_memory_type=posix";
        assert_eq!(
            feed_prefix(OriginalConfigForm::Auto, auto, 3).and_then(|mut lexer| lexer.finish()),
            Ok(())
        );
        let hba = b"local all all reject\nhost all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256";
        assert_eq!(
            feed_prefix(OriginalConfigForm::Hba, hba, 1).and_then(|mut lexer| lexer.finish()),
            Ok(())
        );
        assert!(
            feed_prefix(
                OriginalConfigForm::Hba,
                b"local all all reject option=x\n",
                8
            )
            .is_err()
        );
        assert!(feed_prefix(OriginalConfigForm::Auto, b"port=054321\n", 3).is_err());
        for input in [
            b"max_connections=032\n".as_slice(),
            b"max_connections='032'\n",
        ] {
            assert!(feed_prefix(OriginalConfigForm::Auto, input, 3).is_err());
        }
    }
}
