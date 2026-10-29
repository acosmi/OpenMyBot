//! Binary-level behaviour of `openmybot`: piped stdin secrets, exit codes, output shapes and the
//! request frames an in-process stand-in daemon receives over the control socket.
use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};

const SENTINEL: &str = "123456:SENTINEL-cli-token";

/// Runs the binary with `args`, feeding `stdin` through a pipe.
async fn run(args: Vec<String>, stdin: &'static [u8]) -> Output {
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_openmybot"))
            .args(&args)
            .env_remove("OPENMYBOT_DATA_DIR")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A child that exits before reading closes the pipe; the write result does not matter.
        let _ = child.stdin.take().unwrap().write_all(stdin);
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}
fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}
fn missing_dir() -> PathBuf {
    std::env::temp_dir().join(format!("omb-cli-missing-{}", std::process::id()))
}
/// A data directory with private permissions, a control token and a bound control socket.
fn data_dir() -> (PathBuf, UnixListener) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "omb-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("run"))
        .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("run/control.token"))
        .unwrap()
        .write_all("a".repeat(64).as_bytes())
        .unwrap();
    let path = root.join("run/control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (root, listener)
}
async fn read_frame(stream: &mut UnixStream) -> Value {
    let length = stream.read_u32().await.unwrap();
    let mut body = vec![0; length as usize];
    stream.read_exact(&mut body).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}
async fn write_frame(stream: &mut UnixStream, value: &Value) {
    let body = serde_json::to_vec(value).unwrap();
    stream.write_u32(body.len() as u32).await.unwrap();
    stream.write_all(&body).await.unwrap();
}
/// Serves one connection: answers `hello` and the request with `response`, returning the
/// hello and request frames it read.
fn stand_in(listener: UnixListener, response: Value) -> JoinHandle<(Value, Value)> {
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hello = read_frame(&mut stream).await;
        write_frame(
            &mut stream,
            &json!({"type": "hello_ok", "daemon_version": "0.0.0", "engine_pin": "0".repeat(40)}),
        )
        .await;
        let request = read_frame(&mut stream).await;
        write_frame(&mut stream, &response).await;
        (hello, request)
    })
}
async fn answered(args: &[&str], stdin: &'static [u8], response: Value) -> (Output, Value) {
    let (root, listener) = data_dir();
    let server = stand_in(listener, response);
    let mut values = strings(args);
    values.extend(["--data-dir".into(), root.to_str().unwrap().into()]);
    assert!(values.iter().all(|value| !value.contains("SENTINEL")));
    let output = run(values, stdin).await;
    let (_, request) = server.await.unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    (output, request)
}
/// Every control form with the stdin each needs.
fn control_forms() -> Vec<(Vec<&'static str>, &'static [u8])> {
    vec![
        (vec!["status"], b""),
        (vec!["status", "--run", "r1"], b""),
        (vec!["pair", "telegram", "--workspace", "/ws"], b""),
        (vec!["bindings", "list"], b""),
        (vec!["bindings", "revoke", "b1"], b""),
        (vec!["bindings", "reconfirm", "b1"], b""),
        (
            vec!["bindings", "reset-thread", "b1", "--ack-unknown", "r1"],
            b"",
        ),
        (
            vec!["bindings", "receiver", "telegram"],
            b"123456:SENTINEL-cli-token\n",
        ),
        (
            vec!["bindings", "receiver", "feishu", "--app-id", "cli_a"],
            b"app-secret\n",
        ),
        (
            vec!["bindings", "host", "crabcode", "--workspace", "/ws"],
            b"",
        ),
        (vec!["approve", "hp1"], b""),
        (vec!["deny", "hp1"], b""),
        (vec!["cancel", "r1"], b""),
    ]
}

#[tokio::test]
async fn every_control_command_exits_3_when_daemon_not_running() {
    let missing = missing_dir();
    for (args, stdin) in control_forms() {
        let mut values = strings(&args);
        values.extend([
            "--json".into(),
            "--data-dir".into(),
            missing.to_str().unwrap().into(),
        ]);
        let output = run(values, stdin).await;
        assert_eq!(output.status.code(), Some(3), "{args:?}");
        assert_eq!(
            stdout_json(&output),
            json!({"code": "daemon_not_running", "ok": false}),
            "{args:?}"
        );
    }
}

#[tokio::test]
async fn usage_errors_exit_2_with_invalid_arguments_in_json() {
    for args in [
        vec!["--json", "unknown"],
        vec!["--json", "approve"],
        vec!["--json", "status", "--run", "a", "--run", "b"],
        vec!["--json", "mcp"],
        vec!["--json", "bindings", "reset-thread", "b1"],
    ] {
        let output = run(strings(&args), b"").await;
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(
            stdout_json(&output),
            json!({"code": "invalid_arguments", "ok": false}),
            "{args:?}"
        );
    }
}

#[tokio::test]
async fn empty_or_over_512_byte_stdin_secret_exits_2_before_connecting() {
    let long: &'static [u8] = format!("{}\n", "x".repeat(513)).into_bytes().leak();
    for stdin in [&b""[..], b"\n", long] {
        let (root, listener) = data_dir();
        let output = run(
            strings(&[
                "--json",
                "bindings",
                "receiver",
                "telegram",
                "--data-dir",
                root.to_str().unwrap(),
            ]),
            stdin,
        )
        .await;
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            stdout_json(&output),
            json!({"code": "invalid_arguments", "ok": false})
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[tokio::test]
async fn json_failure_output_has_only_ok_and_code() {
    let usage = run(strings(&["--json", "mcp"]), b"").await;
    let missing = missing_dir();
    let not_running = run(
        strings(&[
            "--json",
            "cancel",
            "r1",
            "--data-dir",
            missing.to_str().unwrap(),
        ]),
        b"",
    )
    .await;
    let (rejected, _) = answered(
        &["--json", "cancel", "r1"],
        b"",
        json!({"type": "response", "ok": false, "code": "run_not_found"}),
    )
    .await;
    let (internal, _) = answered(
        &["--json", "cancel", "r1"],
        b"",
        json!({"type": "response", "ok": false, "code": "internal_error"}),
    )
    .await;
    for (output, code) in [(usage, 2), (not_running, 3), (rejected, 4), (internal, 5)] {
        assert_eq!(output.status.code(), Some(code));
        let value = stdout_json(&output);
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 2);
        assert_eq!(object["ok"], false);
        assert!(object["code"].is_string());
    }
}

#[tokio::test]
async fn success_prints_ok_true_with_data_in_json_mode_and_bare_data_otherwise() {
    let data = json!({"run_id": "r1", "state": "requested"});
    let response = json!({"type": "response", "ok": true, "data": data});
    let (output, _) = answered(&["--json", "cancel", "r1"], b"", response.clone()).await;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout_json(&output), json!({"ok": true, "data": data}));
    let (output, _) = answered(&["cancel", "r1"], b"", response).await;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout_json(&output), data);
    assert!(output.stderr.is_empty());
}

#[tokio::test]
async fn remote_rejection_codes_exit_4_and_unknown_code_exits_5() {
    for code in [
        "permission_not_pending",
        "run_not_found",
        "channel_unreachable",
    ] {
        let (output, _) = answered(
            &["--json", "approve", "hp1"],
            b"",
            json!({"type": "response", "ok": false, "code": code}),
        )
        .await;
        assert_eq!(output.status.code(), Some(4), "{code}");
        assert_eq!(stdout_json(&output), json!({"ok": false, "code": code}));
    }
    let (output, _) = answered(
        &["--json", "approve", "hp1"],
        b"",
        json!({"type": "response", "ok": false, "code": "no_such_code"}),
    )
    .await;
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        stdout_json(&output),
        json!({"ok": false, "code": "internal_error"})
    );
}

#[tokio::test]
async fn request_frame_carries_op_and_args_and_the_secret_only_in_args_and_never_in_output() {
    let ok = json!({"type": "response", "ok": true, "data": {"binding_id": "b", "source_key": "123456"}});
    let (output, request) = answered(
        &["--json", "bindings", "receiver", "telegram"],
        b"123456:SENTINEL-cli-token\r\n",
        ok.clone(),
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        request,
        json!({"type": "request", "op": "bindings_receiver", "args": {"channel": "telegram", "token": SENTINEL}})
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains("SENTINEL"));
    }
    let (_, request) = answered(
        &["bindings", "receiver", "feishu", "--app-id", "cli_a"],
        b"feishu-SENTINEL\n",
        ok.clone(),
    )
    .await;
    assert_eq!(
        request,
        json!({"type": "request", "op": "bindings_receiver", "args": {"channel": "feishu", "app_id": "cli_a", "app_secret": "feishu-SENTINEL"}})
    );
    for (args, op, expected) in [
        (
            vec!["status", "--run", "r1"],
            "status_run",
            json!({"run_id": "r1"}),
        ),
        (
            vec![
                "pair",
                "feishu",
                "--workspace",
                "/ws",
                "--run-deadline",
                "60",
            ],
            "pair_start",
            json!({"channel": "feishu", "workspace": "/ws", "run_deadline": 60}),
        ),
        (vec!["bindings", "list"], "bindings_list", json!({})),
        (
            vec!["bindings", "reset-thread", "b1", "--ack-unknown", "r1"],
            "bindings_reset_thread",
            json!({"binding_id": "b1", "ack_unknown": "r1"}),
        ),
        (vec!["deny", "hp1"], "deny", json!({"permission_id": "hp1"})),
    ] {
        let (_, request) = answered(&args, b"", ok.clone()).await;
        assert_eq!(
            request,
            json!({"type": "request", "op": op, "args": expected}),
            "{args:?}"
        );
    }
    // The secret is never accepted as an argument.
    let output = run(
        strings(&["--json", "bindings", "receiver", "telegram", SENTINEL]),
        b"",
    )
    .await;
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SENTINEL"));
    // The child inherits this environment, which carries no secret; its arguments are checked
    // in `answered`.
    assert!(std::env::vars_os().all(|(_, value)| !value.to_string_lossy().contains("SENTINEL")));
}
