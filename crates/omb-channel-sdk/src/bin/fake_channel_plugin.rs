//! Fake channel plugin for tests. The real daemon can only pass manifest `args`, so behaviour is
//! chosen on the command line:
//!   --channel-kind <kind>   default `fake`
//!   --source-key <key>      returned by a successful verify, default `fake-source`
//!   --events <path>         newline-terminated JSON lines of events; after `start` the existing lines
//!                           are emitted in order, then the file is polled every 100 ms for appended
//!                           lines; each event awaits its `accepted`; a missing file counts as empty
//!   --sent-log <path>       one JSON line per `send`
//!   --recv-log <path>       every received frame as one JSON line, in arrival order
//!   --scenario <name>       normal | verify_fail:<code> | send_fail:<class>:<code>[:<retry_after_ms>] |
//!                           send_fail_once:<class>:<code>[:<retry_after_ms>] | send_hang |
//!                           crash_after_hello | slow_hello | oversize_frame | unknown_field | no_ack_wait |
//!                           gap_then_closed | suspend:<reason> | skip_both | stderr_secret
//! A scenario only adds behaviour; hello_ok, verify, start with events, send and stop always work.
//!
//! With `--recv-log` the process relays its stdin to a copy of itself (same arguments without
//! `--recv-log`) and logs each frame before forwarding it; it exits with the copy's exit code.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus, Stdio};
use std::time::Duration;

use omb_channel_sdk::frame::{decode, read_frame, write_frame};
use omb_channel_sdk::plugin::{
    ChannelPlugin, HelloInfo, Outbox, SendArgs, SendOutcome, StartArgs, run_channel_plugin,
};
use omb_channel_sdk::protocol::{
    EventFrame, FailureClass, GapReason, SendErrorCode, SkipCounter, SuspendReason, VerifyFailure,
};
use omb_channel_sdk::{FRAME_MAX, HELLO_TIMEOUT};
use serde::de::DeserializeOwned;
use tokio::task::JoinHandle;

enum Scenario {
    Normal,
    VerifyFail(VerifyFailure),
    SendFail(FailureClass, SendErrorCode, Option<u64>),
    SendFailOnce(FailureClass, SendErrorCode, Option<u64>),
    SendHang,
    CrashAfterHello,
    SlowHello,
    OversizeFrame,
    UnknownField,
    NoAckWait,
    GapThenClosed,
    Suspend(SuspendReason),
    SkipBoth,
    StderrSecret,
}

struct Fake {
    channel_kind: String,
    source_key: String,
    events: Option<PathBuf>,
    sent_log: Option<PathBuf>,
    scenario: Scenario,
    sent: u64,
    tail: Option<JoinHandle<()>>,
}

/// Parses a snake_case wire code into its protocol enum.
fn code<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .unwrap_or_else(|_| panic!("unknown code {name}"))
}

fn scenario(name: &str) -> Scenario {
    match name.split(':').collect::<Vec<_>>().as_slice() {
        ["normal"] => Scenario::Normal,
        ["verify_fail", failure] => Scenario::VerifyFail(code(failure)),
        ["send_fail", class, failure] => Scenario::SendFail(code(class), code(failure), None),
        ["send_fail", class, failure, retry_after_ms] => Scenario::SendFail(
            code(class),
            code(failure),
            Some(retry_after_ms.parse().expect("retry_after_ms")),
        ),
        ["send_fail_once", class, failure] => {
            Scenario::SendFailOnce(code(class), code(failure), None)
        }
        ["send_fail_once", class, failure, retry_after_ms] => Scenario::SendFailOnce(
            code(class),
            code(failure),
            Some(retry_after_ms.parse().expect("retry_after_ms")),
        ),
        ["send_hang"] => Scenario::SendHang,
        ["crash_after_hello"] => Scenario::CrashAfterHello,
        ["slow_hello"] => Scenario::SlowHello,
        ["oversize_frame"] => Scenario::OversizeFrame,
        ["unknown_field"] => Scenario::UnknownField,
        ["no_ack_wait"] => Scenario::NoAckWait,
        ["gap_then_closed"] => Scenario::GapThenClosed,
        ["suspend", reason] => Scenario::Suspend(code(reason)),
        ["skip_both"] => Scenario::SkipBoth,
        ["stderr_secret"] => Scenario::StderrSecret,
        _ => panic!("unknown scenario {name}"),
    }
}

/// The complete lines of `path` after byte `from`, and the new offset; a missing file has none.
fn events_after(path: &Path, from: usize) -> (Vec<EventFrame>, usize) {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let end = text.rfind('\n').map_or(0, |last| last + 1).max(from);
    let events = text[from..end]
        .lines()
        .map(|line| decode(line.as_bytes()).expect("event line"))
        .collect();
    (events, end)
}

impl ChannelPlugin for Fake {
    fn hello_ok(&self) -> HelloInfo {
        match self.scenario {
            // Leave the SDK time to write hello_ok first.
            Scenario::CrashAfterHello => {
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_millis(300));
                    std::process::exit(3);
                });
            }
            Scenario::SlowHello => std::thread::sleep(HELLO_TIMEOUT + Duration::from_secs(2)),
            _ => {}
        }
        HelloInfo {
            plugin_name: "fake-channel-plugin".to_owned(),
            plugin_version: env!("CARGO_PKG_VERSION").to_owned(),
            channel_kind: self.channel_kind.clone(),
        }
    }

    async fn verify(
        &mut self,
        _credential: String,
        _source_key: Option<String>,
    ) -> Result<String, VerifyFailure> {
        match &self.scenario {
            Scenario::VerifyFail(failure) => Err(failure.clone()),
            _ => Ok(self.source_key.clone()),
        }
    }

    async fn start(&mut self, start: StartArgs, outbox: Outbox) {
        match &self.scenario {
            Scenario::OversizeFrame => {
                let mut stdout = std::io::stdout();
                stdout
                    .write_all(&((FRAME_MAX + 1) as u32).to_be_bytes())
                    .expect("stdout");
                stdout.flush().expect("stdout");
            }
            Scenario::UnknownField => {
                let payload = br#"{"type":"gap","reason":"stream_broken","extra":1}"#;
                let mut stdout = std::io::stdout();
                stdout
                    .write_all(&(payload.len() as u32).to_be_bytes())
                    .expect("stdout");
                stdout.write_all(payload).expect("stdout");
                stdout.flush().expect("stdout");
            }
            Scenario::NoAckWait => {
                // Every existing event goes out twice without waiting for its receipt.
                let events = self
                    .events
                    .as_deref()
                    .map_or(Vec::new(), |path| events_after(path, 0).0);
                for event in events.iter().chain(&events).cloned() {
                    let outbox = outbox.clone();
                    tokio::spawn(async move {
                        let _ = outbox.emit(event).await;
                    });
                }
                return;
            }
            Scenario::GapThenClosed => {
                let outbox = outbox.clone();
                tokio::spawn(async move {
                    outbox.gap(GapReason::StreamBroken).await;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    outbox.gap_closed().await;
                });
            }
            Scenario::Suspend(reason) => outbox.suspend(reason.clone()).await,
            Scenario::SkipBoth => {
                outbox
                    .skipped(SkipCounter::PlatformPayloadUnparseable)
                    .await;
                outbox.skipped(SkipCounter::UnsupportedUpdate).await;
            }
            Scenario::StderrSecret => eprintln!("{}", start.credential),
            _ => {}
        }
        if let Some(path) = self.events.clone() {
            self.tail = Some(tokio::spawn(async move {
                let mut from = 0;
                loop {
                    let (events, end) = events_after(&path, from);
                    from = end;
                    for event in events {
                        let _ = outbox.emit(event).await;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }));
        }
    }

    async fn stop(&mut self) {
        if let Some(tail) = self.tail.take() {
            tail.abort();
        }
    }

    async fn send(&mut self, send: SendArgs) -> SendOutcome {
        self.sent += 1;
        if let Some(path) = &self.sent_log {
            let line = serde_json::json!({
                "delivery_id": send.delivery_id,
                "chat_key": send.chat_key,
                "body": send.body,
                "idempotency_key": send.idempotency_key,
            });
            let mut log = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("sent log");
            writeln!(log, "{line}").expect("sent log");
        }
        match &self.scenario {
            Scenario::SendHang => std::future::pending().await,
            Scenario::SendFail(class, failure, retry_after_ms) => SendOutcome::Failed {
                class: class.clone(),
                code: failure.clone(),
                retry_after_ms: *retry_after_ms,
            },
            Scenario::SendFailOnce(class, failure, retry_after_ms) if self.sent == 1 => {
                SendOutcome::Failed {
                    class: class.clone(),
                    code: failure.clone(),
                    retry_after_ms: *retry_after_ms,
                }
            }
            _ => SendOutcome::Sent {
                platform_message_id: Some(format!("fake-{}", self.sent)),
            },
        }
    }
}

/// Relays stdin frames to a copy of this plugin, logging each one first, and exits as soon as the
/// copy does: returning would wait for the runtime's blocked stdin read.
async fn relay(recv_log: PathBuf, args: Vec<String>) -> ExitCode {
    let mut plugin = tokio::process::Command::new(std::env::current_exe().expect("current exe"))
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .expect("plugin copy");
    let mut input = plugin.stdin.take().expect("piped stdin");
    let mut stdin = tokio::io::stdin();
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(recv_log)
        .expect("recv log");
    fn exit(status: std::io::Result<ExitStatus>) -> ! {
        let status = status.expect("plugin copy");
        std::process::exit(
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        )
    }
    loop {
        tokio::select! {
            status = plugin.wait() => exit(status),
            frame = read_frame(&mut stdin) => {
                let Ok(Some(payload)) = frame else { break };
                log.write_all(&payload).expect("recv log");
                log.write_all(b"\n").expect("recv log");
                if write_frame(&mut input, &payload).await.is_err() {
                    break;
                }
            }
        }
    }
    drop(input);
    exit(plugin.wait().await)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut fake = Fake {
        channel_kind: "fake".to_owned(),
        source_key: "fake-source".to_owned(),
        events: None,
        sent_log: None,
        scenario: Scenario::Normal,
        sent: 0,
        tail: None,
    };
    let mut recv_log = None;
    let mut forwarded = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--channel-kind" => fake.channel_kind = value.clone(),
            "--source-key" => fake.source_key = value.clone(),
            "--events" => fake.events = Some(value.clone().into()),
            "--sent-log" => fake.sent_log = Some(value.clone().into()),
            "--scenario" => fake.scenario = scenario(&value),
            "--recv-log" => {
                recv_log = Some(PathBuf::from(value));
                continue;
            }
            _ => panic!("unknown option {flag}"),
        }
        forwarded.extend([flag, value]);
    }
    if let Some(recv_log) = recv_log {
        return relay(recv_log, forwarded).await;
    }
    match run_channel_plugin(fake).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
