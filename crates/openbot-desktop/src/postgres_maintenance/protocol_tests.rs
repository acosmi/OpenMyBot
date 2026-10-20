use openbot_domain::vault::SecretBytes;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use super::protocol::{self, StatusRecord, StatusTrail};
use super::{MaintenanceError, runner};

fn frame(
    op: [u8; 16],
    seq: u32,
    event: u16,
    worker: u32,
    flags: u64,
    wait: i32,
) -> ([u8; 40], [u8; 128]) {
    let mut h = [0; 40];
    h[..8].copy_from_slice(b"WRKPGM01");
    h[8..10].copy_from_slice(&1_u16.to_be_bytes());
    h[10..12].copy_from_slice(&protocol::STATUS_KIND.to_be_bytes());
    h[12..14].copy_from_slice(&40_u16.to_be_bytes());
    h[16..32].copy_from_slice(&op);
    h[32..36].copy_from_slice(&seq.to_be_bytes());
    h[36..].copy_from_slice(&128_u32.to_be_bytes());
    let mut p = [0; 128];
    p[..2].copy_from_slice(&event.to_be_bytes());
    p[4..8].copy_from_slice(&321_u32.to_be_bytes());
    p[8..12].copy_from_slice(&worker.to_be_bytes());
    p[12..16].copy_from_slice(&wait.to_be_bytes());
    p[80..88].copy_from_slice(&(100 + u64::from(seq)).to_be_bytes());
    if flags & protocol::WORKER_WAITED != 0 {
        p[88..96].copy_from_slice(&(100 + u64::from(seq)).to_be_bytes());
    }
    p[96..104].copy_from_slice(&flags.to_be_bytes());
    (h, p)
}
fn trail() -> StatusTrail {
    StatusTrail::new([7; 16], 321, 100, 8, 1344)
}
fn started_worker(t: &mut StatusTrail) {
    for (seq, event, worker, flags) in [(0, 1, 0, 0), (1, 2, 0, 0), (2, 3, 654, 1)] {
        let (h, p) = frame([7; 16], seq, event, worker, flags, 0);
        t.push(&h, &p, 1000).expect("numeric protocol fixture");
    }
}

#[test]
fn secret_start_cancel_and_eof_are_closed_and_bounded() {
    let op = [9; 16];
    let secret = protocol::secret_frame(&op, b"fixture-secret", 64).expect("private payload");
    assert_eq!(secret.len(), 54);
    assert_eq!(&secret[40..], b"fixture-secret");
    assert_eq!(&secret[..8], b"WRKPGM01");
    assert_eq!(&secret[16..32], &op);
    assert_eq!(&secret[32..36], &0_u32.to_be_bytes());
    let start = protocol::start_frame(&op);
    assert_eq!(start.len(), 40);
    assert_eq!(&start[32..36], &1_u32.to_be_bytes());
    let cancel = protocol::cancel_frame(&op, 150, 200).expect("tighten");
    assert_eq!(&cancel[32..36], &2_u32.to_be_bytes());
    assert_eq!(&cancel[40..], &150_u64.to_be_bytes());
    assert_eq!(
        protocol::cancel_frame(&op, 201, 200),
        Err(MaintenanceError::ProtocolInvalid)
    );
    for invalid in [b"".as_slice(), b"a\0b", b"\xff"] {
        assert!(matches!(
            protocol::secret_frame(&op, invalid, 64),
            Err(MaintenanceError::SecretInvalid)
        ));
    }
    assert!(matches!(
        protocol::secret_frame(&op, b"long", 3),
        Err(MaintenanceError::SecretInvalid)
    ));
    assert!(matches!(
        protocol::secret_frame(&op, b"x", 4097),
        Err(MaintenanceError::SecretInvalid)
    ));
}

#[test]
fn stdout_status_dag_and_sequence_reject_short_extra_or_cross_operation() {
    let mut t = trail();
    started_worker(&mut t);
    for (seq, event, flags) in [(3, 4, 1), (4, 6, 3), (5, 7, 15), (6, 8, 31)] {
        let (h, p) = frame([7; 16], seq, event, 654, flags, 0);
        t.push(&h, &p, 1000).expect("success DAG");
    }
    assert!(t.closed_success());
    assert!(t.owners_closed());
    assert!(t.worker_wait_observed());
    let (h, p) = frame([7; 16], 7, 8, 654, 31, 0);
    assert!(t.push(&h, &p, 1000).is_err());
    for kind in 0..5 {
        let mut t = trail();
        let (mut h, mut p) = frame([7; 16], 0, 1, 0, 0, 0);
        match kind {
            0 => h[39] = 127,
            1 => h[16] ^= 1,
            2 => h[35] = 1,
            3 => p[127] = 1,
            _ => p[0] = 1,
        }
        assert!(t.push(&h, &p, 1000).is_err());
    }
    let mut t = trail();
    started_worker(&mut t);
    let (h, p) = frame([7; 16], 3, 8, 654, 31, 0);
    assert!(t.push(&h, &p, 1000).is_err());
    let mut late = trail();
    started_worker(&mut late);
    for (seq, event, flags) in [(3, 6, 3), (4, 7, 15), (5, 8, 31)] {
        let (h, mut p) = frame([7; 16], seq, event, 654, flags, 0);
        p[2..4].copy_from_slice(&12_u16.to_be_bytes());
        late.push(&h, &p, 1000).expect("late true closure");
    }
    assert!(late.closed_failure());
    assert!(late.owners_closed());
    assert!(!late.closed_success());
}

#[tokio::test]
async fn eof_or_epipe_cancels_without_fabricating_worker_wait() {
    let now = super::clock::monotonic_ns().expect("clock");
    let (writer, peer) = tokio::io::duplex(256);
    drop(peer);
    let (_control, commands) = tokio::sync::mpsc::channel(2);
    let (start, started) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(runner::control_writer(
        writer,
        commands,
        started,
        Arc::new(SecretBytes::new(b"fixture-private-secret".to_vec())),
        [7; 16],
        64,
        (now + 1_000_000_000, now + 2_000_000_000),
    ));
    start.send(()).expect("original writer installed");
    let error = handle
        .await
        .expect("same original writer join")
        .expect_err("closed peer");
    assert_eq!(error, MaintenanceError::Cancelled);
    let mut t = trail();
    started_worker(&mut t);
    assert!(t.worker_created());
    assert!(!t.worker_wait_observed());
    assert!(!t.owners_closed());
    // A real closed writer is not an OS WAL-worker wait or a terminal success.
    let (mut source, peer) = tokio::io::duplex(8);
    drop(peer);
    assert!(source.write_all(b"closed").await.is_err());
}

#[test]
fn all_protocol_diagnostics_redact_secret_and_server_text() {
    let secret = "fixture-do-not-print";
    let server = "server-supplied-sensitive-text";
    let mut bytes = [0; 128];
    bytes[..secret.len()].copy_from_slice(secret.as_bytes());
    let error = StatusRecord::parse(&bytes).expect_err("unframed external input");
    for error in [
        error,
        MaintenanceError::ConnectionFailed,
        MaintenanceError::SecretInvalid,
        MaintenanceError::WalWorkerWaitUnknown,
        MaintenanceError::ClosingPending,
    ] {
        let text = format!(
            "{error:?}/{error}/{}",
            serde_json::to_string(&error).expect("closed error")
        );
        assert!(!text.contains(secret));
        assert!(!text.contains(server));
        assert!(text.len() < 160);
    }
}
