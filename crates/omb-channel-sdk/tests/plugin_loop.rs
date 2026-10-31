use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use omb_channel_sdk::frame::{FrameError, decode};
use omb_channel_sdk::protocol::{
    EventFrame, EventKind, FailureClass, FromPlugin, GapReason, Limits, SendErrorCode, SkipCounter,
    SuspendReason, ToPlugin, VerifyFailure,
};
use omb_channel_sdk::testkit::Host;
use omb_channel_sdk::{FRAME_MAX, PROTOCOL};
use tokio::time::{Instant, timeout};

const FAKE: &str = env!("CARGO_BIN_EXE_fake-channel-plugin");
const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(300);

async fn spawn(args: &[&str]) -> Host {
    Host::spawn(Path::new(FAKE), args, &[]).await.unwrap()
}

/// Spawns the fake, completes the handshake and sends `start`.
async fn started(args: &[&str], credential: &str) -> Host {
    let mut host = spawn(args).await;
    host.hello("fake").await.unwrap();
    host.send(&ToPlugin::Start {
        source_key: "fake-source".to_owned(),
        credential: credential.to_owned(),
        last_event_key: None,
        last_accepted_at: None,
    })
    .await
    .unwrap();
    host
}

async fn next(host: &mut Host) -> FromPlugin {
    host.recv(WAIT).await.unwrap().expect("a frame")
}

/// Closes stdin and returns the exit code.
async fn exit_code(host: Host) -> Option<i32> {
    let Host {
        mut child, stdin, ..
    } = host;
    drop(stdin);
    timeout(WAIT, child.wait()).await.unwrap().unwrap().code()
}

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("omb-channel-sdk-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn event(key: &str) -> EventFrame {
    EventFrame {
        event_key: key.to_owned(),
        event_type: "fake.message".to_owned(),
        occurred_at: Some("2026-10-31T08:00:00.123Z".to_owned()),
        private: true,
        sender_key: Some("fake:7".to_owned()),
        chat_key: Some("fake:9".to_owned()),
        kind: EventKind::Text,
        text: format!("text {key}"),
        data: BTreeMap::from([("messageId".to_owned(), key.to_owned())]),
    }
}

fn events_file(name: &str, keys: &[&str]) -> PathBuf {
    let path = scratch(name);
    std::fs::write(&path, event_lines(keys)).unwrap();
    path
}

fn event_lines(keys: &[&str]) -> String {
    keys.iter()
        .map(|key| serde_json::to_string(&event(key)).unwrap() + "\n")
        .collect()
}

fn send(delivery_id: &str) -> ToPlugin {
    ToPlugin::Send {
        delivery_id: delivery_id.to_owned(),
        chat_key: "fake:9".to_owned(),
        body: format!("body {delivery_id}"),
        idempotency_key: format!("key-{delivery_id}"),
    }
}

#[tokio::test]
async fn hello_handshake_returns_name_and_version() {
    let mut host = spawn(&[]).await;
    let (name, version) = host.hello("fake").await.unwrap();
    assert_eq!(name, "fake-channel-plugin");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert_eq!(exit_code(host).await, Some(0));

    let mut host = spawn(&["--channel-kind", "telegram"]).await;
    host.hello("telegram").await.unwrap();
    assert_eq!(exit_code(host).await, Some(0));
}

#[tokio::test]
async fn wrong_first_frame_exits_non_zero() {
    let limits = Limits {
        send_timeout_ms: 35_000,
        ack_timeout_ms: 3_000,
    };
    for first in [
        ToPlugin::Hello {
            protocol: "openmybot-channel/2".to_owned(),
            channel_kind: "fake".to_owned(),
            limits: limits.clone(),
        },
        ToPlugin::Hello {
            protocol: PROTOCOL.to_owned(),
            channel_kind: "telegram".to_owned(),
            limits: limits.clone(),
        },
        ToPlugin::Stop {},
    ] {
        let mut host = spawn(&[]).await;
        host.send(&first).await.unwrap();
        assert!(host.recv(WAIT).await.unwrap().is_none());
        let code = exit_code(host).await;
        assert!(
            matches!(code, Some(code) if code != 0),
            "{first:?} -> {code:?}"
        );
    }
}

#[tokio::test]
async fn verify_returns_the_source_key_or_each_failure_code() {
    let mut host = spawn(&["--source-key", "42"]).await;
    host.hello("fake").await.unwrap();
    host.send(&ToPlugin::Verify {
        credential: "secret".to_owned(),
        source_key: None,
    })
    .await
    .unwrap();
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Verified {
            source_key: "42".to_owned()
        }
    );
    assert_eq!(exit_code(host).await, Some(0));

    for (wire, code) in [
        ("credential_rejected", VerifyFailure::CredentialRejected),
        ("webhook_conflict", VerifyFailure::WebhookConflict),
        ("unreachable", VerifyFailure::Unreachable),
        ("malformed", VerifyFailure::Malformed),
    ] {
        let mut host = spawn(&["--scenario", &format!("verify_fail:{wire}")]).await;
        host.hello("fake").await.unwrap();
        host.send(&ToPlugin::Verify {
            credential: "secret".to_owned(),
            source_key: Some("42".to_owned()),
        })
        .await
        .unwrap();
        assert_eq!(next(&mut host).await, FromPlugin::VerifyFailed { code });
        assert_eq!(exit_code(host).await, Some(0));
    }
}

#[tokio::test]
async fn events_wait_for_accepted_one_by_one_and_follow_appends() {
    let path = events_file("events", &["1", "2", "3"]);
    let mut host = started(&["--events", path.to_str().unwrap()], "secret").await;
    for key in ["1", "2", "3"] {
        assert_eq!(next(&mut host).await, FromPlugin::Event(event(key)));
        // The next event waits for this one's receipt.
        assert!(host.recv(QUIET).await.unwrap().is_none());
        host.send(&ToPlugin::Accepted {
            event_key: key.to_owned(),
        })
        .await
        .unwrap();
    }
    assert!(host.recv(QUIET).await.unwrap().is_none());
    // A line appended after start is picked up by the tail.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut file, event_lines(&["4"]).as_bytes()).unwrap();
    assert_eq!(next(&mut host).await, FromPlugin::Event(event("4")));
    host.send(&ToPlugin::Accepted {
        event_key: "4".to_owned(),
    })
    .await
    .unwrap();
    // Unknown and late receipts are ignored.
    host.send(&ToPlugin::Accepted {
        event_key: "unknown".to_owned(),
    })
    .await
    .unwrap();
    host.send(&ToPlugin::Stop {}).await.unwrap();
    assert_eq!(exit_code(host).await, Some(0));
}

#[tokio::test]
async fn no_ack_wait_resends_every_event() {
    let path = events_file("no-ack", &["1", "2", "3"]);
    let mut host = started(
        &[
            "--events",
            path.to_str().unwrap(),
            "--scenario",
            "no_ack_wait",
        ],
        "secret",
    )
    .await;
    let mut seen = BTreeMap::<String, u32>::new();
    for _ in 0..6 {
        let FromPlugin::Event(frame) = next(&mut host).await else {
            panic!("not an event");
        };
        *seen.entry(frame.event_key).or_default() += 1;
    }
    assert_eq!(
        seen,
        BTreeMap::from([
            ("1".to_owned(), 2),
            ("2".to_owned(), 2),
            ("3".to_owned(), 2)
        ])
    );
    assert_eq!(exit_code(host).await, Some(0));
}

#[tokio::test]
async fn send_maps_to_sent_and_send_failed() {
    let log = scratch("sent-log");
    let mut host = spawn(&["--sent-log", log.to_str().unwrap()]).await;
    host.hello("fake").await.unwrap();
    for (delivery_id, message_id) in [("d1", "fake-1"), ("d2", "fake-2")] {
        host.send(&send(delivery_id)).await.unwrap();
        assert_eq!(
            next(&mut host).await,
            FromPlugin::Sent {
                delivery_id: delivery_id.to_owned(),
                platform_message_id: Some(message_id.to_owned()),
            }
        );
    }
    assert_eq!(exit_code(host).await, Some(0));
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        lines,
        [
            serde_json::json!({"delivery_id": "d1", "chat_key": "fake:9", "body": "body d1", "idempotency_key": "key-d1"}),
            serde_json::json!({"delivery_id": "d2", "chat_key": "fake:9", "body": "body d2", "idempotency_key": "key-d2"}),
        ]
    );

    for (scenario, class, code, retry_after_ms) in [
        (
            "send_fail:retryable:rate_limited:1500",
            FailureClass::Retryable,
            SendErrorCode::RateLimited,
            Some(1500),
        ),
        (
            "send_fail:final:client_error",
            FailureClass::Final,
            SendErrorCode::ClientError,
            None,
        ),
        (
            "send_fail:unknown:receiver_inactive",
            FailureClass::Unknown,
            SendErrorCode::ReceiverInactive,
            None,
        ),
    ] {
        let mut host = spawn(&["--scenario", scenario]).await;
        host.hello("fake").await.unwrap();
        host.send(&send("d3")).await.unwrap();
        assert_eq!(
            next(&mut host).await,
            FromPlugin::SendFailed {
                delivery_id: "d3".to_owned(),
                class,
                code,
                retry_after_ms,
            }
        );
        assert_eq!(exit_code(host).await, Some(0));
    }
}

#[tokio::test]
async fn send_fail_once_then_sent() {
    let mut host = spawn(&["--scenario", "send_fail_once:retryable:server_error:250"]).await;
    host.hello("fake").await.unwrap();
    host.send(&send("d1")).await.unwrap();
    assert_eq!(
        next(&mut host).await,
        FromPlugin::SendFailed {
            delivery_id: "d1".to_owned(),
            class: FailureClass::Retryable,
            code: SendErrorCode::ServerError,
            retry_after_ms: Some(250),
        }
    );
    host.send(&send("d1")).await.unwrap();
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Sent {
            delivery_id: "d1".to_owned(),
            platform_message_id: Some("fake-2".to_owned()),
        }
    );
    assert_eq!(exit_code(host).await, Some(0));
}

#[tokio::test]
async fn recv_log_records_frames_in_arrival_order() {
    let log = scratch("recv-log");
    let events = events_file("recv-log-events", &["1"]);
    let mut host = started(
        &[
            "--recv-log",
            log.to_str().unwrap(),
            "--events",
            events.to_str().unwrap(),
        ],
        "secret",
    )
    .await;
    assert_eq!(next(&mut host).await, FromPlugin::Event(event("1")));
    let accepted = ToPlugin::Accepted {
        event_key: "1".to_owned(),
    };
    host.send(&accepted).await.unwrap();
    host.send(&ToPlugin::Stop {}).await.unwrap();
    assert_eq!(exit_code(host).await, Some(0));
    let frames: Vec<ToPlugin> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| decode(line.as_bytes()).unwrap())
        .collect();
    assert!(matches!(
        frames.as_slice(),
        [ToPlugin::Hello { .. }, ToPlugin::Start { .. }, received, ToPlugin::Stop {}]
            if *received == accepted
    ));
}

#[tokio::test]
async fn crash_after_hello_exits_with_3() {
    let mut host = spawn(&["--scenario", "crash_after_hello"]).await;
    host.hello("fake").await.unwrap();
    let status = timeout(WAIT, host.child.wait()).await.unwrap().unwrap();
    assert_eq!(status.code(), Some(3));
}

#[tokio::test]
async fn slow_hello_times_out() {
    let mut host = spawn(&["--scenario", "slow_hello"]).await;
    let error = host.hello("fake").await.unwrap_err();
    assert!(matches!(error, FrameError::Io(ref io) if io.kind() == std::io::ErrorKind::TimedOut));
    // TERM ends the plugin by signal.
    assert_eq!(host.kill().await, None);
}

#[tokio::test]
async fn oversize_frame_and_unknown_field_are_frame_errors() {
    let mut host = started(&["--scenario", "oversize_frame"], "secret").await;
    let error = host.recv(WAIT).await.unwrap_err();
    assert!(matches!(error, FrameError::TooLarge(length) if length == FRAME_MAX + 1));
    assert_eq!(exit_code(host).await, Some(0));

    let mut host = started(&["--scenario", "unknown_field"], "secret").await;
    assert!(matches!(host.recv(WAIT).await, Err(FrameError::Json)));
    assert_eq!(exit_code(host).await, Some(0));
}

#[tokio::test]
async fn status_scenarios_emit_their_frames() {
    let mut host = started(&["--scenario", "gap_then_closed"], "secret").await;
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Gap {
            reason: GapReason::StreamBroken
        }
    );
    let opened = Instant::now();
    assert_eq!(next(&mut host).await, FromPlugin::GapClosed {});
    assert!(opened.elapsed() >= Duration::from_millis(900));
    assert_eq!(exit_code(host).await, Some(0));

    for (wire, reason) in [
        ("credential_rejected", SuspendReason::CredentialRejected),
        ("webhook_conflict", SuspendReason::WebhookConflict),
    ] {
        let mut host = started(&["--scenario", &format!("suspend:{wire}")], "secret").await;
        assert_eq!(next(&mut host).await, FromPlugin::Suspend { reason });
        assert_eq!(exit_code(host).await, Some(0));
    }

    let mut host = started(&["--scenario", "skip_both"], "secret").await;
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Skipped {
            counter: SkipCounter::PlatformPayloadUnparseable
        }
    );
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Skipped {
            counter: SkipCounter::UnsupportedUpdate
        }
    );
    assert_eq!(exit_code(host).await, Some(0));
}

#[tokio::test]
async fn stop_then_closed_stdin_exits_zero() {
    let mut host = started(&[], "secret").await;
    host.send(&ToPlugin::Stop {}).await.unwrap();
    assert_eq!(exit_code(host).await, Some(0));
}

#[tokio::test]
async fn stderr_secret_reaches_the_stderr_tail() {
    let sentinel = "123456:SENTINEL-omb013";
    let host = started(&["--scenario", "stderr_secret"], sentinel).await;
    let tail = host.stderr_tail.clone();
    let deadline = Instant::now() + WAIT;
    while !String::from_utf8_lossy(&tail.lock().unwrap()).contains(sentinel) {
        assert!(Instant::now() < deadline, "sentinel never reached stderr");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(exit_code(host).await, Some(0));
}
