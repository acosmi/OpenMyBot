//! Fixed WRKPGM01 framing. A parsed status is never an operating-system wait receipt.
use serde::Serialize;
use zeroize::Zeroizing;

use super::MaintenanceError;

pub(super) const HEADER: usize = 40;
pub(super) const STATUS: usize = 128;
pub(super) const STATUS_KIND: u16 = 0x8001;
pub(super) const WORKER_CREATED: u64 = 1;
pub(super) const WORKER_WAITED: u64 = 2;
pub(super) const CONNECTIONS_CLOSED: u64 = 4;
pub(super) const OWNED_BUFFERS_WIPED: u64 = 8;
pub(super) const TERMINAL: u64 = 16;

fn header(op: &[u8; 16], kind: u16, seq: u32, len: u32) -> [u8; HEADER] {
    let mut b = [0; HEADER];
    b[..8].copy_from_slice(b"WRKPGM01");
    b[8..10].copy_from_slice(&1_u16.to_be_bytes());
    b[10..12].copy_from_slice(&kind.to_be_bytes());
    b[12..14].copy_from_slice(&40_u16.to_be_bytes());
    b[16..32].copy_from_slice(op);
    b[32..36].copy_from_slice(&seq.to_be_bytes());
    b[36..40].copy_from_slice(&len.to_be_bytes());
    b
}
pub(super) fn secret_frame(
    op: &[u8; 16],
    secret: &[u8],
    max: u64,
) -> Result<Zeroizing<Vec<u8>>, MaintenanceError> {
    if secret.is_empty()
        || secret.len() as u64 > max
        || max > 4096
        || secret.contains(&0)
        || std::str::from_utf8(secret).is_err()
    {
        return Err(MaintenanceError::SecretInvalid);
    }
    let n = u32::try_from(secret.len()).map_err(|_| MaintenanceError::SecretInvalid)?;
    let mut b = Zeroizing::new(Vec::with_capacity(HEADER + secret.len()));
    b.extend_from_slice(&header(op, 1, 0, n));
    b.extend_from_slice(secret);
    Ok(b)
}
pub(super) fn start_frame(op: &[u8; 16]) -> [u8; HEADER] {
    header(op, 2, 1, 0)
}
pub(super) fn cancel_frame(
    op: &[u8; 16],
    tighter: u64,
    original: u64,
) -> Result<[u8; 48], MaintenanceError> {
    if tighter > original {
        return Err(MaintenanceError::ProtocolInvalid);
    }
    let mut b = [0; 48];
    b[..40].copy_from_slice(&header(op, 3, 2, 8));
    b[40..].copy_from_slice(&tighter.to_be_bytes());
    Ok(b)
}
pub(super) fn status_header(
    b: &[u8; HEADER],
    op: &[u8; 16],
    seq: u32,
) -> Result<(), MaintenanceError> {
    if &b[..8] != b"WRKPGM01"
        || u16::from_be_bytes([b[8], b[9]]) != 1
        || u16::from_be_bytes([b[10], b[11]]) != STATUS_KIND
        || u16::from_be_bytes([b[12], b[13]]) != 40
        || b[14..16] != [0, 0]
        || b[16..32] != *op
        || u32::from_be_bytes(
            b[32..36]
                .try_into()
                .map_err(|_| MaintenanceError::ProtocolInvalid)?,
        ) != seq
        || u32::from_be_bytes(
            b[36..40]
                .try_into()
                .map_err(|_| MaintenanceError::ProtocolInvalid)?,
        ) != 128
    {
        return Err(MaintenanceError::ProtocolInvalid);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct StatusRecord {
    pub(super) event: u16,
    pub(super) error: u16,
    pub(super) leader_pid: u32,
    pub(super) wal_pid: u32,
    pub(super) wait_status: i32,
    pub(super) system_id: u64,
    pub(super) timeline: u32,
    pub(super) wal_segment_bytes: u32,
    pub(super) start_lsn: u64,
    pub(super) stop_lsn: u64,
    pub(super) material_bytes: u64,
    pub(super) material_files: u64,
    pub(super) wal_bytes: u64,
    pub(super) wal_segments: u64,
    pub(super) observed_ns: u64,
    pub(super) worker_wait_ns: u64,
    pub(super) flags: u64,
}
impl StatusRecord {
    pub(super) fn parse(b: &[u8; STATUS]) -> Result<Self, MaintenanceError> {
        let u16at = |i| u16::from_be_bytes([b[i], b[i + 1]]);
        let u32at = |i| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let u64at = |i| {
            u64::from_be_bytes([
                b[i],
                b[i + 1],
                b[i + 2],
                b[i + 3],
                b[i + 4],
                b[i + 5],
                b[i + 6],
                b[i + 7],
            ])
        };
        let z = Self {
            event: u16at(0),
            error: u16at(2),
            leader_pid: u32at(4),
            wal_pid: u32at(8),
            wait_status: i32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            system_id: u64at(16),
            timeline: u32at(24),
            wal_segment_bytes: u32at(28),
            start_lsn: u64at(32),
            stop_lsn: u64at(40),
            material_bytes: u64at(48),
            material_files: u64at(56),
            wal_bytes: u64at(64),
            wal_segments: u64at(72),
            observed_ns: u64at(80),
            worker_wait_ns: u64at(88),
            flags: u64at(96),
        };
        if !(1..=8).contains(&z.event)
            || z.error > 12
            || z.flags & !31 != 0
            || z.leader_pid == 0
            || b[104..].iter().any(|n| *n != 0)
        {
            return Err(MaintenanceError::ProtocolInvalid);
        }
        Ok(z)
    }
}

pub(super) struct StatusTrail {
    op: [u8; 16],
    pid: u32,
    t0: u64,
    max_records: u64,
    max_bytes: u64,
    records: Vec<StatusRecord>,
    worker: Option<u32>,
    waited: bool,
    closing: bool,
    terminal: bool,
}
impl StatusTrail {
    pub(super) fn new(op: [u8; 16], pid: u32, t0: u64, max_records: u64, max_bytes: u64) -> Self {
        Self {
            op,
            pid,
            t0,
            max_records,
            max_bytes,
            records: Vec::new(),
            worker: None,
            waited: false,
            closing: false,
            terminal: false,
        }
    }
    pub(super) fn push(
        &mut self,
        h: &[u8; HEADER],
        p: &[u8; STATUS],
        now: u64,
    ) -> Result<StatusRecord, MaintenanceError> {
        if self.terminal {
            return Err(MaintenanceError::ProtocolInvalid);
        }
        let seq =
            u32::try_from(self.records.len()).map_err(|_| MaintenanceError::CapacityExceeded)?;
        status_header(h, &self.op, seq)?;
        let count = (self.records.len() as u64)
            .checked_add(1)
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if count > self.max_records || count.checked_mul(168).is_none_or(|n| n > self.max_bytes) {
            return Err(MaintenanceError::CapacityExceeded);
        }
        let r = StatusRecord::parse(p)?;
        if r.leader_pid != self.pid
            || r.observed_ns < self.t0
            || r.observed_ns > now
            || self.records.last().is_some_and(|old| {
                r.observed_ns < old.observed_ns
                    || r.flags & old.flags != old.flags
                    || old.error != 0 && r.error == 0
                    || old.error == 12 && r.error != 12
            })
            || self.records.is_empty() && r.event != 1
            || !self.records.is_empty() && r.event == 1
        {
            return Err(MaintenanceError::ProtocolInvalid);
        }
        let has = |e| self.records.iter().any(|z| z.event == e);
        match r.event {
            1 => {}
            2 if has(1) && !has(2) && !self.closing => {}
            3 if has(2) && self.worker.is_none() && !self.closing => {
                if r.wal_pid == 0 || r.flags & WORKER_CREATED == 0 {
                    return Err(MaintenanceError::ProtocolInvalid);
                }
                self.worker = Some(r.wal_pid);
            }
            4 if self.worker.is_some() && !has(4) && !self.closing => {}
            5 if !has(5) && !self.closing => {}
            6 if self.worker == Some(r.wal_pid) && !self.waited => {
                if r.flags & WORKER_WAITED == 0
                    || r.worker_wait_ns < self.t0
                    || r.worker_wait_ns > r.observed_ns
                {
                    return Err(MaintenanceError::ProtocolInvalid);
                }
                self.waited = true;
            }
            7 if !self.closing => {
                self.closing = true;
            }
            8 if self.closing => {
                self.terminal = true;
            }
            _ => return Err(MaintenanceError::ProtocolInvalid),
        }
        if self.worker.is_none() && (r.flags & WORKER_CREATED != 0 || r.wal_pid != 0)
            || self.worker.is_some()
                && (r.flags & WORKER_CREATED == 0 || self.worker != Some(r.wal_pid))
            || self.waited && r.flags & WORKER_WAITED == 0
            || r.flags & WORKER_WAITED != 0 && !self.waited
            || r.flags & TERMINAL != 0 && r.event != 8
            || r.event == 8 && r.flags & TERMINAL == 0
        {
            return Err(MaintenanceError::ProtocolInvalid);
        }
        self.records.push(r);
        Ok(r)
    }
    pub(super) fn terminal(&self) -> Option<StatusRecord> {
        self.records.last().copied().filter(|z| z.event == 8)
    }
    pub(super) fn records(&self) -> &[StatusRecord] {
        &self.records
    }
    pub(super) fn worker_created(&self) -> bool {
        self.worker.is_some()
    }
    pub(super) fn worker_wait_observed(&self) -> bool {
        self.waited
    }
    pub(super) fn worker_closed(&self) -> bool {
        self.worker.is_none()
            || self.waited
                && self
                    .records
                    .iter()
                    .any(|r| r.event == 6 && r.wait_status == 0)
    }
    pub(super) fn owners_closed(&self) -> bool {
        self.terminal()
            .is_some_and(|r| r.flags & (CONNECTIONS_CLOSED | OWNED_BUFFERS_WIPED | TERMINAL) == 28)
            && (self.worker.is_none() || self.waited)
    }
    pub(super) fn closed_success(&self) -> bool {
        self.terminal()
            .is_some_and(|r| r.error == 0 && r.flags == 31 && r.wait_status == 0)
            && self.worker.is_some()
            && self.worker_closed()
            && self.records.iter().any(|r| r.event == 4)
            && !self.records.iter().any(|r| r.event == 5 || r.error != 0)
            && self.owners_closed()
    }
    pub(super) fn closed_failure(&self) -> bool {
        // C expiry remains error12 permanently. A later genuine wait/close can release resident
        // owners while retaining a closed-late failure; it can never mint native success.
        self.terminal().is_some_and(|r| (1..=12).contains(&r.error)) && self.owners_closed()
    }
}
