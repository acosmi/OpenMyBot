//! Explicit finite owner profile and checked file/WAL/remaining-capacity accounting.
use serde::{Deserialize, Serialize};

use super::MaintenanceError;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileFields {
    pub(crate) effect_ns: u64,
    pub(crate) convergence_ns: u64,
    pub(crate) max_source_secret_bytes: u64,
    pub(crate) max_secret_memory_bytes: u64,
    pub(crate) max_native_secret_copies: u64,
    pub(crate) max_control_bytes: u64,
    pub(crate) max_status_bytes: u64,
    pub(crate) max_status_records: u64,
    pub(crate) max_stderr_bytes: u64,
    pub(crate) max_material_files: u64,
    pub(crate) max_directories: u64,
    pub(crate) max_path_bytes: u64,
    pub(crate) max_depth: u64,
    pub(crate) max_single_file_bytes: u64,
    pub(crate) max_material_plain_bytes: u64,
    pub(crate) max_wal_bytes: u64,
    pub(crate) max_wal_segments: u64,
    pub(crate) max_wal_span_bytes: u64,
    pub(crate) max_wal_timelines: u64,
    pub(crate) max_backup_manifest_bytes: u64,
    pub(crate) max_total_copy_blocks: u64,
    pub(crate) copy_block_bytes: u64,
    pub(crate) max_spool_bytes: u64,
    pub(crate) max_restore_check_bytes: u64,
    pub(crate) max_open_files: u64,
    pub(crate) max_journal_bytes: u64,
    pub(crate) capacity_reserve_bytes: u64,
    pub(crate) free_floor_bytes: u64,
}

/// Parsed only through the closed decoder; no deserializer or free constructor on this type.
pub(crate) struct MaintenanceProfile {
    fields: ProfileFields,
}

pub(crate) fn parse_profile(bytes: &[u8]) -> Result<MaintenanceProfile, MaintenanceError> {
    if bytes.is_empty() {
        return Err(MaintenanceError::ProfileMissing);
    }
    let fields: ProfileFields =
        serde_json::from_slice(bytes).map_err(|_| MaintenanceError::ProfileInvalid)?;
    validate_fields(&fields)?;
    Ok(MaintenanceProfile { fields })
}
impl MaintenanceProfile {
    pub(crate) fn fields(&self) -> &ProfileFields {
        &self.fields
    }
    pub(crate) fn encoded(&self) -> Result<Vec<u8>, MaintenanceError> {
        serde_json::to_vec(&self.fields).map_err(|_| MaintenanceError::ProfileInvalid)
    }
}
pub(crate) fn validate_fields(p: &ProfileFields) -> Result<(), MaintenanceError> {
    let values = [
        p.effect_ns,
        p.convergence_ns,
        p.max_source_secret_bytes,
        p.max_secret_memory_bytes,
        p.max_native_secret_copies,
        p.max_control_bytes,
        p.max_status_bytes,
        p.max_status_records,
        p.max_stderr_bytes,
        p.max_material_files,
        p.max_directories,
        p.max_path_bytes,
        p.max_depth,
        p.max_single_file_bytes,
        p.max_material_plain_bytes,
        p.max_wal_bytes,
        p.max_wal_segments,
        p.max_wal_span_bytes,
        p.max_wal_timelines,
        p.max_backup_manifest_bytes,
        p.max_total_copy_blocks,
        p.copy_block_bytes,
        p.max_spool_bytes,
        p.max_restore_check_bytes,
        p.max_open_files,
        p.max_journal_bytes,
        p.capacity_reserve_bytes,
        p.free_floor_bytes,
    ];
    if values.contains(&0)
        || p.max_source_secret_bytes > 4096
        || p.copy_block_bytes > 4 * 1024 * 1024
        || p.max_wal_timelines != 1
        || !(8..=u64::from(u32::MAX)).contains(&p.max_status_records)
        || p.max_path_bytes > 4096
        || p.max_depth > 1024
        || p.max_open_files < 8
    {
        return Err(MaintenanceError::ProfileInvalid);
    }
    let control = 128_u64
        .checked_add(p.max_source_secret_bytes)
        .ok_or(MaintenanceError::ProfileInvalid)?;
    let status = 168_u64
        .checked_mul(p.max_status_records)
        .ok_or(MaintenanceError::ProfileInvalid)?;
    let secret = p
        .max_source_secret_bytes
        .checked_add(1)
        .ok_or(MaintenanceError::ProfileInvalid)?;
    if p.max_control_bytes < control
        || p.max_status_bytes < status
        || p.max_secret_memory_bytes < secret
        || p.effect_ns.checked_add(p.convergence_ns).is_none()
    {
        return Err(MaintenanceError::ProfileInvalid);
    }
    Ok(())
}
impl ProfileFields {
    pub(crate) fn native_fields(&self) -> [(&'static str, u64); 26] {
        [
            ("max-source-secret-bytes", self.max_source_secret_bytes),
            ("max-secret-memory-bytes", self.max_secret_memory_bytes),
            ("max-native-secret-copies", self.max_native_secret_copies),
            ("max-control-bytes", self.max_control_bytes),
            ("max-status-bytes", self.max_status_bytes),
            ("max-status-records", self.max_status_records),
            ("max-stderr-bytes", self.max_stderr_bytes),
            ("max-material-files", self.max_material_files),
            ("max-directories", self.max_directories),
            ("max-path-bytes", self.max_path_bytes),
            ("max-depth", self.max_depth),
            ("max-single-file-bytes", self.max_single_file_bytes),
            ("max-material-plain-bytes", self.max_material_plain_bytes),
            ("max-wal-bytes", self.max_wal_bytes),
            ("max-wal-segments", self.max_wal_segments),
            ("max-wal-span-bytes", self.max_wal_span_bytes),
            ("max-wal-timelines", self.max_wal_timelines),
            ("max-backup-manifest-bytes", self.max_backup_manifest_bytes),
            ("max-total-copy-blocks", self.max_total_copy_blocks),
            ("copy-block-bytes", self.copy_block_bytes),
            ("max-spool-bytes", self.max_spool_bytes),
            ("max-restore-check-bytes", self.max_restore_check_bytes),
            ("max-open-files", self.max_open_files),
            ("max-journal-bytes", self.max_journal_bytes),
            ("capacity-reserve-bytes", self.capacity_reserve_bytes),
            ("free-floor-bytes", self.free_floor_bytes),
        ]
    }
}

#[derive(Default, Debug, Serialize)]
pub(crate) struct MaterialCounters {
    pub(crate) files: u64,
    pub(crate) directories: u64,
    pub(crate) bytes: u64,
    pub(crate) blocks: u64,
    pub(crate) wal_bytes: u64,
    pub(crate) wal_segments: u64,
    pub(crate) allocated_bytes: u64,
}
impl MaterialCounters {
    pub(crate) fn directory(&mut self, p: &ProfileFields) -> Result<(), MaintenanceError> {
        let n = self
            .directories
            .checked_add(1)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if n > p.max_directories {
            return Err(MaintenanceError::CapacityExceeded);
        }
        self.directories = n;
        Ok(())
    }
    pub(crate) fn file(
        &mut self,
        p: &ProfileFields,
        len: u64,
        allocated: u64,
        wal: bool,
    ) -> Result<(), MaintenanceError> {
        if len > p.max_single_file_bytes {
            return Err(MaintenanceError::CapacityExceeded);
        }
        let blocks = len
            .checked_div(p.copy_block_bytes)
            .and_then(|n| n.checked_add(u64::from(!len.is_multiple_of(p.copy_block_bytes))))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let files = self
            .files
            .checked_add(1)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let total = self
            .bytes
            .checked_add(len)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let block_total = self
            .blocks
            .checked_add(blocks)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let alloc = self
            .allocated_bytes
            .checked_add(allocated)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let wal_bytes = self
            .wal_bytes
            .checked_add(if wal { len } else { 0 })
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let wal_segments = self
            .wal_segments
            .checked_add(u64::from(wal))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if files > p.max_material_files
            || total > p.max_material_plain_bytes
            || block_total > p.max_total_copy_blocks
            || wal_bytes > p.max_wal_bytes
            || wal_segments > p.max_wal_segments
            || total > p.max_spool_bytes
        {
            return Err(MaintenanceError::CapacityExceeded);
        }
        self.files = files;
        self.bytes = total;
        self.blocks = block_total;
        self.allocated_bytes = alloc;
        self.wal_bytes = wal_bytes;
        self.wal_segments = wal_segments;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CapacityObservation {
    pub(crate) free_bytes: u64,
    pub(crate) retained_allocated_bytes: u64,
    pub(crate) remaining_source_bytes: u64,
    pub(crate) remaining_spool_bytes: u64,
    pub(crate) remaining_restore_bytes: u64,
    pub(crate) remaining_journal_bytes: u64,
    pub(crate) reserve_bytes: u64,
    pub(crate) free_floor_bytes: u64,
}
impl CapacityObservation {
    pub(crate) fn validate(&self) -> Result<(), MaintenanceError> {
        let additional = self
            .remaining_source_bytes
            .checked_add(self.remaining_spool_bytes)
            .and_then(|n| n.checked_add(self.remaining_restore_bytes))
            .and_then(|n| n.checked_add(self.remaining_journal_bytes))
            .and_then(|n| n.checked_add(self.reserve_bytes))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if self.free_bytes < additional
            || self
                .free_bytes
                .checked_sub(self.free_floor_bytes)
                .is_none_or(|n| n < additional)
        {
            return Err(MaintenanceError::CapacityExceeded);
        }
        // Already allocated source/bundle/spool/restore bytes are observations, not subtracted twice.
        Ok(())
    }
}
pub(crate) fn validate_wal_range(
    p: &ProfileFields,
    timeline: u32,
    segment: u32,
    start: u64,
    stop: u64,
) -> Result<u64, MaintenanceError> {
    let size = u64::from(segment);
    if timeline == 0
        || p.max_wal_timelines != 1
        || !size.is_power_of_two()
        || !(1024 * 1024..=1024 * 1024 * 1024).contains(&size)
        || size > p.max_single_file_bytes
        || stop <= start
    {
        return Err(MaintenanceError::WalRangeInvalid);
    }
    let span = stop
        .checked_sub(start)
        .ok_or(MaintenanceError::WalRangeInvalid)?;
    let first = start / size;
    let last = stop
        .checked_sub(1)
        .ok_or(MaintenanceError::WalRangeInvalid)?
        / size;
    let count = last
        .checked_sub(first)
        .and_then(|n| n.checked_add(1))
        .ok_or(MaintenanceError::WalRangeInvalid)?;
    if span > p.max_wal_span_bytes || count > p.max_wal_segments {
        return Err(MaintenanceError::WalRangeInvalid);
    }
    Ok(count)
}
