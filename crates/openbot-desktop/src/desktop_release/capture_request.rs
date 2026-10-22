//! Closed, reviewed capture configuration. Parsing never opens a destination or reads a secret.
use super::{DesktopReleaseError, decode_digest};
use crate::postgres_maintenance::bundle::{self, VerifiedMaintenanceBundle};
use crate::postgres_maintenance::limits::{self, ProfileFields};
use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as CompatibilityFault;
use serde::{Deserialize, Deserializer, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Default)]
pub(super) enum CaptureField {
    #[default]
    Missing,
    Null,
    Request(RawCaptureRequest),
}
impl<'de> Deserialize<'de> for CaptureField {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Option::<RawCaptureRequest>::deserialize(d)? {
            Some(raw) => Self::Request(raw),
            None => Self::Null,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawCaptureRequest {
    request_id: String,
    trigger: String,
    profile: CaptureProfile,
    maintenance_outer_sha256: String,
    maintenance_root: String,
    output_root: TrustedDestination,
    independent_key_medium: TrustedDestination,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedDestination {
    pub(crate) absolute_path: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) uid: u32,
}
impl TrustedDestination {
    fn validate(&self) -> Result<(), DesktopReleaseError> {
        let text = self
            .absolute_path
            .to_str()
            .ok_or(DesktopReleaseError::Manifest)?;
        if !self.absolute_path.is_absolute()
            || self.device == 0
            || self.inode == 0
            || text.is_empty()
            || text.len() > 4096
            || text.contains('\0')
            || text.contains("//")
            || text.split('/').any(|part| part == "." || part == "..")
            || text.len() > 1 && text.ends_with('/')
            || self
                .absolute_path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err(DesktopReleaseError::Manifest);
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureProfile {
    pub(crate) native: ProfileFields,
    pub(crate) carrier: CarrierProfile,
    pub(crate) secrets: SecretProfile,
    pub(crate) drivers: DriverProfile,
    pub(crate) sql: SqlProfile,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CarrierProfile {
    pub(crate) max_material_files: u64,
    pub(crate) max_directories: u64,
    pub(crate) max_path_bytes: u64,
    pub(crate) max_path_depth: u64,
    pub(crate) max_single_plain_bytes: u64,
    pub(crate) max_material_plain_bytes: u64,
    pub(crate) max_manifest_bytes: u64,
    pub(crate) max_header_bytes: u64,
    pub(crate) max_data_chunks: u64,
    pub(crate) max_chunk_plain_bytes: u64,
    pub(crate) max_wire_bytes: u64,
    pub(crate) max_metadata_bytes: u64,
    pub(crate) max_open_files: u64,
    pub(crate) max_snapshot_bytes: u64,
    pub(crate) max_spool_bytes: u64,
    pub(crate) max_retained_prior_bytes: u64,
    pub(crate) max_journal_bytes: u64,
    pub(crate) max_total_allocation_bytes: u64,
    pub(crate) capacity_reserve_bytes: u64,
    pub(crate) free_floor_bytes: u64,
    pub(crate) max_key_medium_allocation_bytes: u64,
    pub(crate) key_medium_reserve_bytes: u64,
    pub(crate) key_medium_free_floor_bytes: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DriverProfile {
    pub(crate) max_live_original_tasks: u64,
    pub(crate) max_unjoined_original_tasks: u64,
    pub(crate) max_pending_connects: u64,
    pub(crate) max_live_proxies: u64,
    pub(crate) max_owner_metadata_bytes: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SqlProfile {
    pub(crate) max_rows: u64,
    pub(crate) max_row_bytes: u64,
    pub(crate) max_field_bytes: u64,
    pub(crate) max_pages: u64,
    pub(crate) page_rows: u64,
    pub(crate) max_catalog_objects: u64,
    pub(crate) max_query_tasks: u64,
    pub(crate) phase_ns: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SecretClassBound {
    pub(crate) max_count: u64,
    pub(crate) max_one_bytes: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SecretClassBounds {
    pub(crate) master_source: SecretClassBound,
    pub(crate) credential_wrapping: SecretClassBound,
    pub(crate) remote_assertion_signing: SecretClassBound,
    pub(crate) application_derived: SecretClassBound,
    pub(crate) scram_source: SecretClassBound,
    pub(crate) pg_config_passwords: SecretClassBound,
    pub(crate) native_secret_frames: SecretClassBound,
    pub(crate) recovery_key: SecretClassBound,
    pub(crate) stream_key: SecretClassBound,
    pub(crate) key_medium_readback: SecretClassBound,
    pub(crate) decode_crypto_temporary: SecretClassBound,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SecretProfile {
    pub(crate) max_source_secret_count: u64,
    pub(crate) max_one_source_secret_bytes: u64,
    pub(crate) max_total_source_secret_bytes: u64,
    pub(crate) max_secret_structure_bytes: u64,
    pub(crate) max_secret_memory_bytes: u64,
    pub(crate) classes: SecretClassBounds,
}
fn positive(values: &[u64]) -> Result<(), DesktopReleaseError> {
    if values
        .iter()
        .any(|n| *n == 0 || usize::try_from(*n).is_err())
    {
        return Err(DesktopReleaseError::Manifest);
    }
    Ok(())
}
impl CaptureProfile {
    pub(crate) fn carrier_bounds(
        &self,
    ) -> Result<
        openbot_domain::backup::whole_pg_carrier::WholePgCarrierBounds,
        openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault,
    > {
        let c = &self.carrier;
        openbot_domain::backup::whole_pg_carrier::WholePgCarrierBounds {
            max_material_files: c.max_material_files,
            max_directories: c.max_directories,
            max_path_bytes: c.max_path_bytes,
            max_path_depth: c.max_path_depth,
            max_single_plain_bytes: c.max_single_plain_bytes,
            max_material_plain_bytes: c.max_material_plain_bytes,
            max_manifest_bytes: c.max_manifest_bytes,
            max_header_bytes: c.max_header_bytes,
            max_data_chunks: c.max_data_chunks,
            max_chunk_plain_bytes: c.max_chunk_plain_bytes,
            max_wire_bytes: c.max_wire_bytes,
            max_metadata_bytes: c.max_metadata_bytes,
            max_open_files: c.max_open_files,
            max_snapshot_bytes: c.max_snapshot_bytes,
            max_spool_bytes: c.max_spool_bytes,
            max_retained_prior_bytes: c.max_retained_prior_bytes,
            max_journal_bytes: c.max_journal_bytes,
            max_total_allocation_bytes: c.max_total_allocation_bytes,
            capacity_reserve_bytes: c.capacity_reserve_bytes,
            free_floor_bytes: c.free_floor_bytes,
            max_key_medium_allocation_bytes: c.max_key_medium_allocation_bytes,
            key_medium_reserve_bytes: c.key_medium_reserve_bytes,
            key_medium_free_floor_bytes: c.key_medium_free_floor_bytes,
        }
        .check()
    }
    pub(crate) fn secret_bounds(
        &self,
    ) -> Result<
        openbot_domain::backup::whole_pg_carrier::WholePgSecretBounds,
        openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault,
    > {
        use openbot_domain::backup::whole_pg_carrier::{
            WholePgSecretBounds, WholePgSecretClassBounds, WholePgSecretClasses,
        };
        let s = &self.secrets;
        let class = |value: &SecretClassBound| WholePgSecretClassBounds {
            max_count: value.max_count,
            max_one_bytes: value.max_one_bytes,
        };
        WholePgSecretBounds {
            max_source_secret_count: s.max_source_secret_count,
            max_one_source_secret_bytes: s.max_one_source_secret_bytes,
            max_total_source_secret_bytes: s.max_total_source_secret_bytes,
            max_secret_structure_bytes: s.max_secret_structure_bytes,
            max_secret_memory_bytes: s.max_secret_memory_bytes,
            classes: WholePgSecretClasses {
                master_source: class(&s.classes.master_source),
                credential_wrapping: class(&s.classes.credential_wrapping),
                remote_assertion_signing: class(&s.classes.remote_assertion_signing),
                application_derived: class(&s.classes.application_derived),
                scram_source: class(&s.classes.scram_source),
                pg_config_passwords: class(&s.classes.pg_config_passwords),
                native_secret_frames: class(&s.classes.native_secret_frames),
                recovery_key: class(&s.classes.recovery_key),
                stream_key: class(&s.classes.stream_key),
                key_medium_readback: class(&s.classes.key_medium_readback),
                decode_crypto_temporary: class(&s.classes.decode_crypto_temporary),
            },
        }
        .check()
    }
    pub(crate) fn validate(&self) -> Result<(), DesktopReleaseError> {
        limits::validate_fields(&self.native).map_err(|_| DesktopReleaseError::Manifest)?;
        let c = &self.carrier;
        positive(&[
            c.max_material_files,
            c.max_directories,
            c.max_path_bytes,
            c.max_path_depth,
            c.max_single_plain_bytes,
            c.max_material_plain_bytes,
            c.max_manifest_bytes,
            c.max_header_bytes,
            c.max_data_chunks,
            c.max_chunk_plain_bytes,
            c.max_wire_bytes,
            c.max_metadata_bytes,
            c.max_open_files,
            c.max_snapshot_bytes,
            c.max_spool_bytes,
            c.max_retained_prior_bytes,
            c.max_journal_bytes,
            c.max_total_allocation_bytes,
            c.capacity_reserve_bytes,
            c.free_floor_bytes,
            c.max_key_medium_allocation_bytes,
            c.key_medium_reserve_bytes,
            c.key_medium_free_floor_bytes,
        ])?;
        let d = &self.drivers;
        positive(&[
            d.max_live_original_tasks,
            d.max_unjoined_original_tasks,
            d.max_pending_connects,
            d.max_live_proxies,
            d.max_owner_metadata_bytes,
        ])?;
        let q = &self.sql;
        positive(&[
            q.max_rows,
            q.max_row_bytes,
            q.max_field_bytes,
            q.max_pages,
            q.page_rows,
            q.max_catalog_objects,
            q.max_query_tasks,
            q.phase_ns,
        ])?;
        if c.max_manifest_bytes > 4 * 1024 * 1024
            || c.max_chunk_plain_bytes > 4 * 1024 * 1024
            || c.max_header_bytes < 80
            || c.max_data_chunks > u64::from(u32::MAX) - 1
            || c.max_single_plain_bytes > c.max_material_plain_bytes
            || c.max_snapshot_bytes > c.max_total_allocation_bytes
            || c.max_spool_bytes > c.max_total_allocation_bytes
            || c.max_wire_bytes > c.max_total_allocation_bytes
            || c.max_metadata_bytes > c.max_total_allocation_bytes
            || c.max_key_medium_allocation_bytes < 104
            || q.max_field_bytes > q.max_row_bytes
            || q.max_row_bytes > c.max_chunk_plain_bytes
            || q.page_rows > q.max_rows
            || q.phase_ns > self.native.effect_ns
        {
            return Err(DesktopReleaseError::Manifest);
        }
        q.page_rows
            .checked_add(1)
            .ok_or(DesktopReleaseError::Manifest)?;
        self.native
            .effect_ns
            .checked_add(self.native.convergence_ns)
            .ok_or(DesktopReleaseError::Manifest)?;
        c.max_data_chunks
            .checked_add(2)
            .and_then(|n| n.checked_mul(37))
            .and_then(|n| n.checked_add(164))
            .and_then(|n| n.checked_add(c.max_manifest_bytes))
            .and_then(|n| n.checked_add(c.max_material_plain_bytes))
            .ok_or(DesktopReleaseError::Manifest)?;
        self.validate_master_retention()
    }
    // Returns (cold same-book admission, complete non-Config secret-structure increment).
    // Original pool metadata is prepaid once as one bounded slice, not once per pool.
    #[cfg(all(feature = "postgres-maintenance", target_os = "macos"))]
    pub(crate) fn checked_original_decode_structure_bytes(
        &self,
    ) -> Result<(u64, u64), DesktopReleaseError> {
        use openbot_infra::db::capture_materials::CaptureDecodeBudget;
        let arc = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .align_to(2).map_err(|_| DesktopReleaseError::Manifest)?
            .extend(std::alloc::Layout::new::<CaptureDecodeBudget>())
            .map_err(|_| DesktopReleaseError::Manifest)?.0.pad_to_align();
        let arc = u64::try_from(arc.size()).map_err(|_| DesktopReleaseError::Manifest)?;
        // bytes1.12.1 Shared is Vec<u8>, usize, AtomicUsize. Bound every possible
        // Rust field-order padding and final alignment, without claiming repr(C).
        let fields = [
            (core::mem::size_of::<Vec<u8>>(), core::mem::align_of::<Vec<u8>>()),
            (core::mem::size_of::<usize>(), core::mem::align_of::<usize>()),
            (core::mem::size_of::<std::sync::atomic::AtomicUsize>(),
                core::mem::align_of::<std::sync::atomic::AtomicUsize>()),
        ];
        let mut shared = 0usize;
        let mut align = 1usize;
        for (size, a) in fields {
            shared = shared.checked_add(size).and_then(|n| n.checked_add(a - 1))
                .ok_or(DesktopReleaseError::Manifest)?;
            align = align.max(a);
        }
        shared = shared.checked_add(align - 1).ok_or(DesktopReleaseError::Manifest)?;
        let heads = u64::try_from(shared).map_err(|_| DesktopReleaseError::Manifest)?
            .checked_mul(self.secrets.classes.decode_crypto_temporary.max_count)
            .ok_or(DesktopReleaseError::Manifest)?;
        let cold = arc.checked_add(heads)
            .and_then(|n| n.checked_add(self.drivers.max_owner_metadata_bytes))
            .ok_or(DesktopReleaseError::Manifest)?;
        let attempts = self.secrets.classes.pg_config_passwords.max_count;
        let source = openbot_infra::db::pool::CapturePgIo::checked_metadata_bytes(attempts)
            .map_err(|_| DesktopReleaseError::Manifest)?
            .checked_add(crate::postgres_maintenance::capture::
                checked_original_source_connect_metadata_bytes(attempts)
                .map_err(|_| DesktopReleaseError::Manifest)?)
            .ok_or(DesktopReleaseError::Manifest)?;
        // A already pays original Config headers. The concrete future fees contain
        // those same headers, so remove only this proven overlap from the increment.
        let originals = self.drivers.max_live_original_tasks
            .min(self.drivers.max_unjoined_original_tasks);
        let overlap = originals.checked_add(attempts)
            .and_then(|n| n.checked_mul(core::mem::size_of::<tokio_postgres::Config>() as u64))
            .ok_or(DesktopReleaseError::Manifest)?;
        let increment = cold.checked_add(source).and_then(|n| n.checked_sub(overlap))
            .ok_or(DesktopReleaseError::Manifest)?;
        Ok((cold, increment))
    }

    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    pub(crate) fn validate_self_owned_fixture_retention(&self, fixture_metadata: u64) -> Result<(), DesktopReleaseError> {
        self.validate_master_retention()?;
        let k = &self.secrets.classes;
        if k.master_source.max_count < 4 || k.master_source.max_one_bytes < 64
            || k.scram_source.max_count < 4 || k.scram_source.max_one_bytes < 64 {
            return Err(DesktopReleaseError::Manifest);
        }
        let n = self.drivers.max_live_original_tasks.checked_add(3)
            .ok_or(DesktopReleaseError::Manifest)?
            .max(self.drivers.max_live_original_tasks.min(self.drivers.max_pending_connects).min(17)
                .checked_add(7).ok_or(DesktopReleaseError::Manifest)?);
        let config = u64::try_from(core::mem::size_of::<tokio_postgres::Config>())
            .map_err(|_| DesktopReleaseError::Manifest)?;
        let arc = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .align_to(2).map_err(|_| DesktopReleaseError::Manifest)?
            .extend(std::alloc::Layout::new::<tokio_postgres::Config>())
            .map_err(|_| DesktopReleaseError::Manifest)?.0.pad_to_align();
        let required = n.checked_sub(1).and_then(|n| n.checked_mul(config))
            .and_then(|n| n.checked_add(u64::try_from(arc.size()).ok()?))
            .and_then(|n| n.checked_add(u64::try_from(core::mem::size_of::<SecretClassBounds>()).ok()?))
            .and_then(|n| n.checked_add(self.checked_original_decode_structure_bytes().ok()?.1))
            .and_then(|n| n.checked_add(fixture_metadata)).ok_or(DesktopReleaseError::Manifest)?;
        if required > self.secrets.max_secret_structure_bytes { return Err(DesktopReleaseError::Manifest); }
        Ok(())
    }
    pub(crate) fn validate_master_retention(&self) -> Result<(), DesktopReleaseError> {
        let s = &self.secrets;
        positive(&[
            s.max_source_secret_count,
            s.max_one_source_secret_bytes,
            s.max_total_source_secret_bytes,
            s.max_secret_structure_bytes,
            s.max_secret_memory_bytes,
        ])?;
        let k = &s.classes;
        let classes = [
            &k.master_source,
            &k.credential_wrapping,
            &k.remote_assertion_signing,
            &k.application_derived,
            &k.scram_source,
            &k.pg_config_passwords,
            &k.native_secret_frames,
            &k.recovery_key,
            &k.stream_key,
            &k.key_medium_readback,
            &k.decode_crypto_temporary,
        ];
        let mut peak = self.carrier.max_chunk_plain_bytes;
        for class in classes {
            positive(&[class.max_one_bytes])?;
            let bytes = class
                .max_count
                .checked_mul(class.max_one_bytes)
                .ok_or(DesktopReleaseError::Manifest)?;
            peak = peak
                .checked_add(bytes)
                .ok_or(DesktopReleaseError::Manifest)?;
        }
        peak = peak
            .checked_add(s.max_secret_structure_bytes)
            .ok_or(DesktopReleaseError::Manifest)?;
        let require = |class: &SecretClassBound, count: u64, bytes: u64| {
            if class.max_count < count || class.max_one_bytes < bytes {
                Err(DesktopReleaseError::Manifest)
            } else {
                Ok(())
            }
        };
        require(&k.master_source, 1, 32)?;
        require(&k.credential_wrapping, 1, 32)?;
        require(&k.remote_assertion_signing, 1, 32)?;
        // Eighteen real Assembly audit copies, its original input, MCP input/copy,
        // and the five original bootstrap adapters/capture audit owner are live at peak.
        require(&k.application_derived, 26, 32)?;
        require(&k.scram_source, 1, 64)?;
        // Preserve the original driver floor. The original Desktop stocks are admin1/app16.
        // ThreadDirectory clones and listeners share one immutable Config; only its
        // constructor temporarily overlaps the old input and the new shared Config.
        // Startup has at most seven fixed/relay copies; stable four plus relay/source
        // temporaries is at most six. These are original-owner phase bounds, not D+7.
        let passwords = self
            .drivers
            .max_live_original_tasks
            .checked_add(3)
            .ok_or(DesktopReleaseError::Manifest)?;
        let connecting_passwords = self
            .drivers
            .max_live_original_tasks
            .min(self.drivers.max_pending_connects)
            .min(17);
        let startup_passwords = connecting_passwords
            .checked_add(7)
            .ok_or(DesktopReleaseError::Manifest)?;
        let required_passwords = passwords.max(startup_passwords);
        require(&k.pg_config_passwords, required_passwords, 64)?;
        require(
            &k.native_secret_frames,
            self.native.max_native_secret_copies,
            64,
        )?;
        require(&k.recovery_key, 1, 32)?;
        require(&k.stream_key, 1, 32)?;
        require(&k.key_medium_readback, 1, 32)?;
        require(&k.decode_crypto_temporary, 1, 64)?;
        // One shared Config is inside ArcInner; the other actual Config headers are
        // counted once each. Password backing remains in pg_config_passwords above.
        let config_bytes = u64::try_from(core::mem::size_of::<tokio_postgres::Config>())
            .map_err(|_| DesktopReleaseError::Manifest)?;
        // Locked Rust 1.98 ArcInner is repr(C, align(2)): two AtomicUsize then T.
        let arc_layout = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .align_to(2)
            .map_err(|_| DesktopReleaseError::Manifest)?
            .extend(std::alloc::Layout::new::<tokio_postgres::Config>())
            .map_err(|_| DesktopReleaseError::Manifest)?
            .0
            .pad_to_align();
        let arc_bytes = u64::try_from(arc_layout.size())
            .map_err(|_| DesktopReleaseError::Manifest)?;
        let config_structures = required_passwords
            .checked_sub(1)
            .ok_or(DesktopReleaseError::Manifest)?
            .checked_mul(config_bytes)
            .ok_or(DesktopReleaseError::Manifest)?
            .checked_add(arc_bytes)
            .ok_or(DesktopReleaseError::Manifest)?;
        #[cfg(all(feature = "postgres-maintenance", target_os = "macos"))]
        let (_, decode_structure) = self.checked_original_decode_structure_bytes()?;
        #[cfg(not(all(feature = "postgres-maintenance", target_os = "macos")))]
        let decode_structure: u64 = return Err(DesktopReleaseError::Manifest);
        let required_secret_structure = u64::try_from(core::mem::size_of::<SecretClassBounds>())
            .map_err(|_| DesktopReleaseError::Manifest)?
            .checked_add(config_structures)
            .and_then(|n| n.checked_add(decode_structure))
            .ok_or(DesktopReleaseError::Manifest)?;
        if s.max_source_secret_count < 2
            || s.max_one_source_secret_bytes < 64
            || s.max_total_source_secret_bytes < 96
            || peak > s.max_secret_memory_bytes
            || s.max_secret_structure_bytes < required_secret_structure
        {
            return Err(DesktopReleaseError::Manifest);
        }
        Ok(())
    }
}

// Nonsecret DATA from the successful original release preflight only. It is not installed
// tenant identity, an active application/Engine observation, a signer accessor or a grant.
#[derive(Serialize)]
struct OriginalReleaseCompatibility {
    release_schema_version: u32,
    core_version: String,
    release_epoch: u64,
    platform: String,
    arch: String,
    ui: super::ResourceTree,
    tenant: super::ResourceTree,
    postgres: OriginalPostgresCompatibility,
    accepted_release_application_budgets: super::AgentBudgets,
}

#[derive(Serialize)]
struct OriginalPostgresCompatibility {
    root: String,
    manifest_sha256: String,
    key_store_service: String,
}

fn compatibility_tree_backing(tree: &super::ResourceTree) -> Result<u64, CompatibilityFault> {
    if tree.files.is_empty() || tree.files.len() > super::TREE_MAX_ENTRIES {
        return Err(CompatibilityFault::ManifestInvalid);
    }
    let backing = tree
        .files
        .capacity()
        .checked_mul(core::mem::size_of::<super::ResourceFile>())
        .and_then(|n| n.checked_add(tree.root.capacity()))
        .ok_or(CompatibilityFault::BoundsOverflow)?;
    let mut backing = u64::try_from(backing).map_err(|_| CompatibilityFault::BoundsOverflow)?;
    let mut resource_bytes = 0u64;
    for file in &tree.files {
        if !super::valid_relative_path(&file.path) || super::decode_digest(&file.sha256).is_none() {
            return Err(CompatibilityFault::ManifestInvalid);
        }
        resource_bytes = resource_bytes
            .checked_add(file.bytes)
            .ok_or(CompatibilityFault::BoundsOverflow)?;
        if resource_bytes > super::TREE_MAX_BYTES {
            return Err(CompatibilityFault::CapacityExceeded);
        }
        let strings = file
            .path
            .capacity()
            .checked_add(file.sha256.capacity())
            .ok_or(CompatibilityFault::BoundsOverflow)?;
        backing = backing
            .checked_add(u64::try_from(strings).map_err(|_| CompatibilityFault::BoundsOverflow)?)
            .ok_or(CompatibilityFault::BoundsOverflow)?;
    }
    // ResourceTree/Vec/String headers are already in the original Option body or Vec backing.
    Ok(backing)
}

impl OriginalReleaseCompatibility {
    fn metadata_bytes(&self) -> Result<u64, CompatibilityFault> {
        let mut bytes = u64::try_from(core::mem::size_of::<Option<Self>>())
            .map_err(|_| CompatibilityFault::BoundsOverflow)?;
        for capacity in [
            self.core_version.capacity(),
            self.platform.capacity(),
            self.arch.capacity(),
            self.postgres.root.capacity(),
            self.postgres.manifest_sha256.capacity(),
            self.postgres.key_store_service.capacity(),
        ] {
            bytes = bytes
                .checked_add(
                    u64::try_from(capacity).map_err(|_| CompatibilityFault::BoundsOverflow)?,
                )
                .ok_or(CompatibilityFault::BoundsOverflow)?;
        }
        let ui = compatibility_tree_backing(&self.ui)?;
        let tenant = compatibility_tree_backing(&self.tenant)?;
        bytes = bytes
            .checked_add(ui)
            .and_then(|n| n.checked_add(tenant))
            .ok_or(CompatibilityFault::BoundsOverflow)?;
        Ok(bytes)
    }
}

pub(crate) struct ReviewedNormalCaptureRequest {
    pub(crate) release_root: std::fs::File,
    pub(crate) release_path: PathBuf,
    pub(crate) request_id: String,
    pub(crate) release_digest: [u8; 32],
    pub(crate) maintenance_digest: [u8; 32],
    pub(crate) maintenance: VerifiedMaintenanceBundle,
    pub(crate) profile: CaptureProfile,
    pub(crate) output: TrustedDestination,
    pub(crate) key_medium: TrustedDestination,
    // None exists only inside original open before its final successful release binding.
    release_compatibility: Option<OriginalReleaseCompatibility>,
}
impl ReviewedNormalCaptureRequest {
    // Only the original parent open may bind, after application/UI/tenant/PG all succeeded.
    // Tuple groups move the original remaining fields; the PG signer was already consumed.
    pub(super) fn bind_original_release_compatibility(
        &mut self,
        identity: (u32, String, u64, String, String),
        inventories: (super::ResourceTree, super::ResourceTree),
        postgres: (String, String, String),
        application_budgets: super::AgentBudgets,
    ) -> Result<(), DesktopReleaseError> {
        if self.release_compatibility.is_some() {
            return Err(DesktopReleaseError::Manifest);
        }
        let (release_schema_version, core_version, release_epoch, platform, arch) = identity;
        let (ui, tenant) = inventories;
        let (root, manifest_sha256, key_store_service) = postgres;
        if ui.root != "ui"
            || tenant.root != "tenant"
            || root != "postgres"
            || super::decode_digest(&manifest_sha256).is_none()
        {
            return Err(DesktopReleaseError::Manifest);
        }
        let compatibility = OriginalReleaseCompatibility {
            release_schema_version,
            core_version,
            release_epoch,
            platform,
            arch,
            ui,
            tenant,
            postgres: OriginalPostgresCompatibility {
                root,
                manifest_sha256,
                key_store_service,
            },
            accepted_release_application_budgets: application_budgets,
        };
        let metadata = compatibility
            .metadata_bytes()
            .map_err(|_| DesktopReleaseError::Manifest)?;
        if metadata > self.profile.carrier.max_metadata_bytes {
            return Err(DesktopReleaseError::Manifest);
        }
        self.release_compatibility = Some(compatibility);
        Ok(())
    }

    /// Original resident compatibility contribution, including its Option body and actual
    /// requested Vec/String capacities. Neither serialized length nor opaque allocator peak.
    pub(crate) fn original_compatibility_metadata_bytes(&self) -> Result<u64, CompatibilityFault> {
        self.release_compatibility
            .as_ref()
            .ok_or(CompatibilityFault::MaterialMissing)?
            .metadata_bytes()
    }

    /// Borrow sealed nonsecret DATA into the caller's existing bounded writer. No file/clock/
    /// source acquisition, runtime lookup or whole encoded allocation is introduced here.
    pub(crate) fn write_original_compatibility(
        &self,
        output: &mut impl std::io::Write,
    ) -> Result<(), CompatibilityFault> {
        let compatibility = self
            .release_compatibility
            .as_ref()
            .ok_or(CompatibilityFault::MaterialMissing)?;
        serde_json::to_writer(output, compatibility).map_err(|_| CompatibilityFault::IoFailure)
    }
}

impl RawCaptureRequest {
    pub(super) fn validate(&self) -> Result<(), DesktopReleaseError> {
        if decode_digest(&self.request_id).is_none()
            || self.trigger != "once_on_normal_ready_exit"
            || decode_digest(&self.maintenance_outer_sha256).is_none()
        {
            return Err(DesktopReleaseError::Manifest);
        }
        self.profile.validate()?;
        self.output_root.validate()?;
        self.independent_key_medium.validate()?;
        let path = Path::new(&self.maintenance_root);
        if path.as_os_str().is_empty()
            || self.maintenance_root.len() > 4096
            || self.maintenance_root.contains('\0')
            || self.maintenance_root.contains('\\')
            || self.maintenance_root.contains("//")
            || self
                .maintenance_root
                .split('/')
                .any(|part| part == "." || part == "..")
            || self.maintenance_root.ends_with('/')
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            || path.components().next().is_some_and(
                |c| matches!(c, Component::Normal(n) if n=="ui" || n=="tenant" || n=="postgres"),
            )
        {
            return Err(DesktopReleaseError::Manifest);
        }
        if self.output_root.absolute_path == self.independent_key_medium.absolute_path
            || self
                .output_root
                .absolute_path
                .starts_with(&self.independent_key_medium.absolute_path)
            || self
                .independent_key_medium
                .absolute_path
                .starts_with(&self.output_root.absolute_path)
        {
            return Err(DesktopReleaseError::Manifest);
        }
        Ok(())
    }
    pub(super) fn verify(
        self,
        root: &Path,
        release_digest: [u8; 32],
    ) -> Result<ReviewedNormalCaptureRequest, DesktopReleaseError> {
        self.validate()?;
        let digest =
            decode_digest(&self.maintenance_outer_sha256).ok_or(DesktopReleaseError::Manifest)?;
        let directory = root.join(&self.maintenance_root);
        let outer = super::read_file(
            &directory.join("wrokbot-pg-maintenance-release.json"),
            1024 * 1024,
        )?;
        use sha2::Digest as _;
        if <[u8; 32]>::from(sha2::Sha256::digest(&outer)) != digest {
            return Err(DesktopReleaseError::Digest);
        }
        let maintenance = bundle::reviewed_bundle_binding()
            .and_then(|expected| bundle::verify_bundle(&directory, expected))
            .map_err(|_| DesktopReleaseError::Postgres)?;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let release_root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC)
                    .bits() as i32,
            )
            .open(root)
            .map_err(|_| DesktopReleaseError::Manifest)?;
        let held = release_root
            .metadata()
            .map_err(|_| DesktopReleaseError::Manifest)?;
        let named = std::fs::symlink_metadata(root).map_err(|_| DesktopReleaseError::Manifest)?;
        if !held.is_dir()
            || !named.is_dir()
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
        {
            return Err(DesktopReleaseError::Manifest);
        }
        Ok(ReviewedNormalCaptureRequest {
            release_root,
            release_path: root.to_owned(),
            request_id: self.request_id,
            release_digest,
            maintenance_digest: digest,
            maintenance,
            profile: self.profile,
            output: self.output_root,
            key_medium: self.independent_key_medium,
            release_compatibility: None,
        })
    }
}
