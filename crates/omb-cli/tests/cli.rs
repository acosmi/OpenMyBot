//! Binary-level behaviour of `openmybot`: piped stdin secrets, exit codes, output shapes and the
//! request frames an in-process stand-in daemon receives over the control socket.
use serde_json::{Value, json};
use std::{
    io::{BufRead, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
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
/// A `plugins_list` answer whose plugin serves `telegram` with a plain `bot_id` and a secret
/// `token`, and `feishu` with a plain `app_id` and a secret `app_secret`.
fn listed() -> Value {
    let field = |name: &str, secret: bool| json!({"name": name, "secret": secret});
    json!({"type": "response", "ok": true, "data": {"plugins": [{
        "name": "chat", "version": "1.0.0", "process": "stopped", "last_exit_code": null,
        "channels": [
            {"channel_kind": "feishu", "status_note": "n", "credential_fields": [field("app_id", false), field("app_secret", true)]},
            {"channel_kind": "telegram", "status_note": "n", "credential_fields": [field("token", true)]},
        ],
    }]}})
}
/// Serves the receiver command's two connections: `plugins_list` answered with [`listed`], then
/// the request answered with `response`; returns the second request frame.
async fn receiver(args: &[&str], stdin: &'static [u8], response: Value) -> (Output, Value) {
    let (root, listener) = data_dir();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in [listed(), response] {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_frame(&mut stream).await;
            write_frame(
                &mut stream,
                &json!({"type": "hello_ok", "daemon_version": "0.0.0", "engine_pin": "0".repeat(40)}),
            )
            .await;
            requests.push(read_frame(&mut stream).await);
            write_frame(&mut stream, &response).await;
        }
        assert_eq!(
            requests[0],
            json!({"type": "request", "op": "plugins_list", "args": {}})
        );
        requests.pop().unwrap()
    });
    let mut values = strings(args);
    values.extend(["--data-dir".into(), root.to_str().unwrap().into()]);
    assert!(values.iter().all(|value| !value.contains("SENTINEL")));
    let output = run(values, stdin).await;
    let request = server.await.unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    (output, request)
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
            vec!["bindings", "receiver", "feishu"],
            b"cli_a\napp-secret\n",
        ),
        (vec!["plugins", "list"], b""),
        (vec!["plugins", "add", "/pkg"], b""),
        (vec!["plugins", "remove", "chat"], b""),
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
        vec!["--json", "plugins", "add", "--built-in", "telegram"],
        vec![
            "--json", "bindings", "receiver", "feishu", "--app-id", "cli_a",
        ],
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
async fn empty_or_over_512_byte_field_line_exits_2_without_a_second_connection() {
    let long: &'static [u8] = format!("{}\n", "x".repeat(513)).into_bytes().leak();
    for stdin in [&b""[..], b"\n", long, b"cli_a\n"] {
        let (root, listener) = data_dir();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_frame(&mut stream).await;
            write_frame(
                &mut stream,
                &json!({"type": "hello_ok", "daemon_version": "0.0.0", "engine_pin": "0".repeat(40)}),
            )
            .await;
            read_frame(&mut stream).await;
            write_frame(&mut stream, &listed()).await;
            // The request is never sent.
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err()
        });
        let output = run(
            strings(&[
                "--json",
                "bindings",
                "receiver",
                "feishu",
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
        assert!(server.await.unwrap());
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[tokio::test]
async fn receiver_of_a_channel_no_plugin_serves_exits_4_with_plugin_not_installed() {
    let (root, listener) = data_dir();
    let server = stand_in(listener, listed());
    let output = run(
        strings(&[
            "--json",
            "bindings",
            "receiver",
            "slack",
            "--data-dir",
            root.to_str().unwrap(),
        ]),
        b"secret\n",
    )
    .await;
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        stdout_json(&output),
        json!({"code": "plugin_not_installed", "ok": false})
    );
    server.await.unwrap();
    std::fs::remove_dir_all(&root).unwrap();
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
    let (output, request) = receiver(
        &["--json", "bindings", "receiver", "telegram"],
        b"123456:SENTINEL-cli-token\r\n",
        ok.clone(),
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        request,
        json!({"type": "request", "op": "bindings_receiver", "args": {"channel": "telegram", "fields": {"token": SENTINEL}}})
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains("SENTINEL"));
    }
    // One line per declared field, in declaration order.
    let (_, request) = receiver(
        &["bindings", "receiver", "feishu"],
        b"cli_a\nfeishu-SENTINEL\n",
        ok.clone(),
    )
    .await;
    assert_eq!(
        request,
        json!({"type": "request", "op": "bindings_receiver", "args": {"channel": "feishu", "fields": {"app_id": "cli_a", "app_secret": "feishu-SENTINEL"}}})
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
        (vec!["plugins", "list"], "plugins_list", json!({})),
        (
            vec!["plugins", "add", "/pkg"],
            "plugins_add",
            json!({"dir": "/pkg"}),
        ),
        (
            vec!["plugins", "remove", "chat"],
            "plugins_remove",
            json!({"name": "chat"}),
        ),
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

#[tokio::test]
async fn mcp_answers_discover_and_tools_list_without_a_daemon_connection() {
    let (root, listener) = data_dir();
    let (counter, accepted) = counting(listener);
    let mut child = spawn_mcp(Some(&root), &[], &[]);
    child.send(&rpc(1, "server/discover", json!({})));
    let discovered = child.recv(WITHIN).await;
    let result = &discovered["result"];
    assert_eq!(
        result["supportedVersions"],
        json!(["2026-07-28", "2025-11-25"])
    );
    assert_eq!(
        result["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    assert_eq!(result["ttlMs"], 0);
    assert_eq!(result["cacheScope"], "private");
    assert_eq!(result["resultType"], "complete");
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"],
        json!({"name": "openmybot", "version": env!("CARGO_PKG_VERSION")})
    );
    child.send(&rpc(2, "tools/list", json!({})));
    let listed = child.recv(WITHIN).await;
    five_tools(&listed);
    assert!(listed["result"].get("nextCursor").is_none());
    assert_eq!(listed["result"]["resultType"], "complete");
    assert_eq!(accepted.load(Ordering::Relaxed), 0);
    let (status, _, _) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    counter.abort();
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn mcp_tool_calls_without_a_daemon_answer_wrok_not_running() {
    let (no_token, listener) = data_dir();
    drop(listener);
    std::fs::remove_file(no_token.join("run/control.token")).unwrap();
    let (no_socket, listener) = data_dir();
    drop(listener);
    std::fs::remove_file(no_socket.join("run/control.sock")).unwrap();
    let (stale_socket, listener) = data_dir();
    drop(listener);
    for dir in [&no_token, &missing_dir(), &no_socket, &stale_socket] {
        let mut child = spawn_mcp(Some(dir), &[], &[]);
        for (id, (tool, arguments)) in (1..).zip(five_calls()) {
            child.send(&call(id, tool, Some(arguments)));
            tool_error(&child.recv(WITHIN).await, "wrok_not_running");
        }
        let (status, _, _) = child.finish(WITHIN).await;
        assert_eq!(status.code(), Some(0), "{dir:?}");
    }
    for dir in [no_token, no_socket, stale_socket] {
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn mcp_nested_env_refuses_every_call_without_a_connection() {
    let (root, listener) = data_dir();
    let (counter, accepted) = counting(listener);
    let mut child = spawn_mcp(Some(&root), &[("OPENMYBOT_HOST_DRIVER_CHILD", "1")], &[]);
    let unknown = ("wrok_unknown", json!({}));
    for (id, (tool, arguments)) in (1..).zip(five_calls().into_iter().chain([unknown])) {
        child.send(&call(id, tool, Some(arguments)));
        tool_error(&child.recv(WITHIN).await, "nested_delegation_refused");
    }
    child.send(&rpc(10, "server/discover", json!({})));
    assert_eq!(
        child.recv(WITHIN).await["result"]["supportedVersions"],
        json!(["2026-07-28", "2025-11-25"])
    );
    child.send(&rpc(11, "tools/list", json!({})));
    five_tools(&child.recv(WITHIN).await);
    assert_eq!(accepted.load(Ordering::Relaxed), 0);
    let (status, _, _) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    counter.abort();
    std::fs::remove_dir_all(&root).unwrap();
    for value in ["0", "true", "", "11", " 1"] {
        let mut child = spawn_mcp(
            Some(&missing_dir()),
            &[("OPENMYBOT_HOST_DRIVER_CHILD", value)],
            &[],
        );
        child.send(&call(1, "wrok_thread_list", Some(json!({}))));
        tool_error(&child.recv(WITHIN).await, "wrok_not_running");
        let (status, _, _) = child.finish(WITHIN).await;
        assert_eq!(status.code(), Some(0), "{value:?}");
    }
}

#[tokio::test]
async fn mcp_sends_hello_mcp_with_the_op_and_arguments_verbatim() {
    let data = [
        json!({"run_id": "r1", "thread_id": "T1", "state": "accepted"}),
        json!({"run_id": "r1", "state": "running", "permission_ids": []}),
        json!({"run_id": "r1", "state": "requested"}),
        json!({"run_id": "r1", "terminal_kind": "succeeded", "summary": "done", "artifacts": []}),
        json!({"runs": []}),
    ];
    let (root, listener) = data_dir();
    let server = serve(listener, data.iter().cloned().map(success).collect());
    let mut child = spawn_mcp(Some(&root), &[], &[]);
    let token = "a".repeat(64);
    let mut answers = Vec::new();
    for ((id, (tool, arguments)), data) in (1..).zip(five_calls()).zip(&data) {
        child.send(&call(id, tool, Some(arguments)));
        let answer = child.recv(WITHIN).await;
        tool_data(&answer, data);
        answers.push(answer.to_string());
    }
    let records = server.await.unwrap();
    let hello = json!({"type": "hello", "token": token, "client": "mcp", "client_version": env!("CARGO_PKG_VERSION")});
    let ops = [
        "mcp_run_begin",
        "mcp_run_status",
        "mcp_run_cancel",
        "mcp_run_result",
        "mcp_thread_list",
    ];
    assert_eq!(records.len(), 5);
    for ((recorded, op), (_, arguments)) in records.iter().zip(ops).zip(five_calls()) {
        assert_eq!(recorded.0, hello);
        assert_eq!(
            recorded.1,
            json!({"type": "request", "op": op, "args": arguments})
        );
    }
    let (root_again, listener) = data_dir();
    let server = serve(
        listener,
        vec![success(json!({"runs": []})), failure("invalid_request")],
    );
    let mut again = spawn_mcp(Some(&root_again), &[], &[]);
    again.send(&call(1, "wrok_thread_list", None));
    tool_data(&again.recv(WITHIN).await, &json!({"runs": []}));
    let odd = json!({"run_id": 7, "x": [1]});
    again.send(&call(2, "wrok_run_status", Some(odd.clone())));
    tool_error(&again.recv(WITHIN).await, "invalid_request");
    let records = server.await.unwrap();
    assert_eq!(
        records[0].1,
        json!({"type": "request", "op": "mcp_thread_list", "args": {}})
    );
    assert_eq!(
        records[1].1,
        json!({"type": "request", "op": "mcp_run_status", "args": odd})
    );
    let (status, rest, errors) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    for text in answers.iter().chain(&rest).chain([&errors]) {
        assert!(!text.contains(&token));
    }
    let (status, _, _) = again.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&root_again).unwrap();
}

#[tokio::test]
async fn mcp_passes_daemon_codes_through_and_maps_unknown_codes_to_internal_error() {
    let codes = [
        "host_not_bound",
        "host_binding_suspended",
        "operation_conflict",
        "run_not_terminal",
        "dispatch_queue_full",
        "run_not_found",
        "invalid_request",
        "request_timeout",
        "internal_error",
        "op_not_allowed",
        "no_such_code",
    ];
    let (root, listener) = data_dir();
    let server = serve(listener, codes.iter().map(|code| failure(code)).collect());
    let mut child = spawn_mcp(Some(&root), &[], &[]);
    for (id, code) in (1..).zip(codes) {
        child.send(&call(id, "wrok_run_status", Some(json!({"run_id": "r1"}))));
        let expected = if code == "no_such_code" {
            "internal_error"
        } else {
            code
        };
        tool_error(&child.recv(WITHIN).await, expected);
    }
    assert_eq!(server.await.unwrap().len(), codes.len());
    let (status, _, _) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn mcp_call_timeout_bounds_the_whole_call_and_the_server_keeps_serving() {
    let (root, listener) = data_dir();
    let slow = Answer::After {
        hello_delay: Duration::from_secs(6),
        response_delay: Duration::from_secs(6),
        value: json!({"type": "response", "ok": true, "data": {"runs": []}}),
    };
    let server = serve(listener, vec![slow, success(json!({"runs": []}))]);
    let mut child = spawn_mcp(Some(&root), &[], &[]);
    // The clock starts once the server answers, so process start-up stays outside the bound.
    child.send(&rpc(1, "tools/list", json!({})));
    five_tools(&child.recv(WITHIN).await);
    child.send(&call(2, "wrok_thread_list", Some(json!({}))));
    let sent = tokio::time::Instant::now();
    let answer = child.recv(WITHIN).await;
    let took = sent.elapsed();
    tool_error(&answer, "request_timeout");
    assert!(
        took >= Duration::from_millis(9500) && took < Duration::from_millis(11500),
        "{took:?}"
    );
    child.send(&call(3, "wrok_thread_list", Some(json!({}))));
    tool_data(&child.recv(WITHIN).await, &json!({"runs": []}));
    server.await.unwrap();
    let (status, _, _) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn mcp_non_object_arguments_and_unknown_tools_are_json_rpc_errors_and_the_server_survives() {
    let (root, listener) = data_dir();
    let (counter, accepted) = counting(listener);
    let mut child = spawn_mcp(Some(&root), &[], &[]);
    child.send(&rpc(1, "tools/list", json!({})));
    five_tools(&child.recv(WITHIN).await);
    for (id, arguments) in (10..).zip([json!([]), json!("x"), json!(5)]) {
        child.send(&call(id, "wrok_thread_list", Some(arguments.clone())));
        let answer = child.recv(WITHIN).await;
        // rmcp 3.1.4 reads a `tools/call` whose params do not parse as a custom request, which
        // its default handler answers with method-not-found; `call_tool` is never reached.
        assert_eq!(answer["error"]["code"], -32601, "{arguments} {answer}");
        assert_eq!(answer["id"], id, "{answer}");
        child.send(&rpc(id + 100, "tools/list", json!({})));
        five_tools(&child.recv(WITHIN).await);
    }
    child.send(&call(20, "wrok_unknown", Some(json!({}))));
    let answer = child.recv(WITHIN).await;
    assert_eq!(answer["error"]["code"], -32602);
    assert_eq!(answer["id"], 20);
    child.send(&rpc(21, "tools/list", json!({})));
    five_tools(&child.recv(WITHIN).await);
    assert_eq!(accepted.load(Ordering::Relaxed), 0);
    let (status, _, _) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    counter.abort();
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn mcp_process_semantics_exit_codes_stdout_stderr_and_data_dir() {
    let mut child = spawn_mcp(Some(&missing_dir()), &[], &[]);
    child.send(&rpc(1, "server/discover", json!({})));
    let first = child.recv(WITHIN).await;
    let (status, rest, errors) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    assert_eq!(first["jsonrpc"], "2.0");
    for line in &rest {
        assert_eq!(
            serde_json::from_str::<Value>(line).unwrap()["jsonrpc"],
            "2.0"
        );
    }
    assert!(errors.is_empty(), "{errors}");
    let (flagged, listener) = data_dir();
    let flagged_server = serve(listener, vec![success(json!({"runs": ["flag"]}))]);
    let (shadowed, listener) = data_dir();
    let (counter, shadowed_accepts) = counting(listener);
    let mut child = spawn_mcp(
        Some(&flagged),
        &[("OPENMYBOT_DATA_DIR", shadowed.to_str().unwrap())],
        &[],
    );
    child.send(&call(1, "wrok_thread_list", Some(json!({}))));
    tool_data(&child.recv(WITHIN).await, &json!({"runs": ["flag"]}));
    flagged_server.await.unwrap();
    assert_eq!(shadowed_accepts.load(Ordering::Relaxed), 0);
    child.finish(WITHIN).await;
    counter.abort();
    let (environment, listener) = data_dir();
    let environment_server = serve(listener, vec![success(json!({"runs": ["env"]}))]);
    let mut child = spawn_mcp(
        None,
        &[("OPENMYBOT_DATA_DIR", environment.to_str().unwrap())],
        &[],
    );
    child.send(&call(1, "wrok_thread_list", Some(json!({}))));
    tool_data(&child.recv(WITHIN).await, &json!({"runs": ["env"]}));
    environment_server.await.unwrap();
    child.finish(WITHIN).await;
    for dir in [flagged, shadowed, environment] {
        std::fs::remove_dir_all(dir).unwrap();
    }
    for child in [
        spawn_mcp(None, &[], &["--data-dir", "relative"]),
        spawn_mcp(None, &[("OPENMYBOT_DATA_DIR", "relative")], &[]),
    ] {
        let (status, rest, errors) = child.finish(WITHIN).await;
        assert_eq!(status.code(), Some(2));
        assert!(rest.is_empty(), "{rest:?}");
        assert_eq!(errors, "invalid_arguments\n");
    }
    for args in [
        vec!["mcp", "extra"],
        vec!["mcp", "serve"],
        vec!["mcp", "--workspace", "/w"],
    ] {
        let output = run(strings(&args), b"").await;
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    for args in [vec!["mcp", "--json"], vec!["--json", "mcp"]] {
        let output = run(strings(&args), b"").await;
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "{\"code\":\"invalid_arguments\",\"ok\":false}\n",
            "{args:?}"
        );
    }
}

#[tokio::test]
async fn mcp_first_message_without_meta_ends_with_exit_5_after_stdin_closes() {
    let mut child = spawn_mcp(Some(&missing_dir()), &[], &[]);
    child.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
    let answer = child.recv(WITHIN).await;
    assert!(answer.get("error").is_some(), "{answer}");
    let (status, rest, errors) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(5));
    assert_eq!(errors, "internal_error\n");
    assert!(rest.is_empty(), "{rest:?}");
}

#[tokio::test]
async fn mcp_reads_the_token_and_connects_anew_for_every_call() {
    let (root, listener) = data_dir();
    let first = serve(listener, vec![success(json!({"runs": ["a"]}))]);
    let mut child = spawn_mcp(Some(&root), &[], &[]);
    child.send(&call(1, "wrok_thread_list", Some(json!({}))));
    tool_data(&child.recv(WITHIN).await, &json!({"runs": ["a"]}));
    first.await.unwrap();
    std::fs::remove_file(root.join("run/control.sock")).unwrap();
    std::fs::remove_file(root.join("run/control.token")).unwrap();
    child.send(&call(2, "wrok_thread_list", Some(json!({}))));
    tool_error(&child.recv(WITHIN).await, "wrok_not_running");
    // Another 64-digit hexadecimal token than the one `data_dir` writes.
    let rotated = "b".repeat(64);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("run/control.token"))
        .unwrap()
        .write_all(rotated.as_bytes())
        .unwrap();
    let path = root.join("run/control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let second = serve(listener, vec![success(json!({"runs": ["b"]}))]);
    child.send(&call(3, "wrok_thread_list", Some(json!({}))));
    tool_data(&child.recv(WITHIN).await, &json!({"runs": ["b"]}));
    let records = second.await.unwrap();
    assert_eq!(records[0].0["token"], rotated);
    let (status, _, _) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn mcp_daemon_closing_after_hello_is_an_internal_error() {
    let (root, listener) = data_dir();
    let server = serve(
        listener,
        vec![Answer::CloseAfterHello, success(json!({"runs": []}))],
    );
    let mut child = spawn_mcp(Some(&root), &[], &[]);
    child.send(&call(1, "wrok_thread_list", Some(json!({}))));
    tool_error(&child.recv(WITHIN).await, "internal_error");
    child.send(&call(2, "wrok_thread_list", Some(json!({}))));
    tool_data(&child.recv(WITHIN).await, &json!({"runs": []}));
    server.await.unwrap();
    let (status, _, _) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn mcp_serves_the_2025_11_25_initialize_flow_through_the_daemon_bridge() {
    let data = json!({"run_id": "r1", "state": "running", "permission_ids": []});
    let (root, listener) = data_dir();
    let server = serve(listener, vec![success(data.clone())]);
    let mut child = spawn_mcp(Some(&root), &[], &[]);
    child.send(&legacy_rpc(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
    ));
    assert_eq!(
        child.recv(WITHIN).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    child.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    child.send(&legacy_rpc(2, "tools/list", json!({})));
    let listed = child.recv(WITHIN).await;
    five_tools(&listed);
    assert!(listed["result"].get("resultType").is_none(), "{listed}");
    child.send(&legacy_rpc(
        3,
        "tools/call",
        json!({"name": "wrok_run_status", "arguments": {"run_id": "r1"}}),
    ));
    let called = child.recv(WITHIN).await;
    tool_data(&called, &data);
    assert!(called["result"].get("resultType").is_none(), "{called}");
    let records = server.await.unwrap();
    assert_eq!(records[0].0["client"], "mcp");
    assert_eq!(
        records[0].1,
        json!({"type": "request", "op": "mcp_run_status", "args": {"run_id": "r1"}})
    );
    let (status, _, errors) = child.finish(WITHIN).await;
    assert_eq!(status.code(), Some(0));
    assert!(errors.is_empty(), "{errors}");
    std::fs::remove_dir_all(&root).unwrap();
}

const WITHIN: Duration = Duration::from_secs(15);
/// A running `openmybot mcp` with its three pipes; stdout arrives line by line.
struct McpChild {
    child: Child,
    stdin: ChildStdin,
    lines: tokio::sync::mpsc::UnboundedReceiver<String>,
    errors: std::thread::JoinHandle<String>,
}
fn spawn_mcp(data_dir: Option<&Path>, env: &[(&str, &str)], extra: &[&str]) -> McpChild {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openmybot"));
    command.arg("mcp");
    if let Some(dir) = data_dir {
        command.arg("--data-dir").arg(dir);
    }
    let mut child = command
        .args(extra)
        .env_remove("OPENMYBOT_DATA_DIR")
        .env_remove("OPENMYBOT_HOST_DRIVER_CHILD")
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, lines) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = sender.send(line);
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).unwrap();
        text
    });
    McpChild {
        stdin: child.stdin.take().unwrap(),
        child,
        lines,
        errors,
    }
}
impl McpChild {
    fn send(&mut self, message: &Value) {
        writeln!(self.stdin, "{message}").unwrap();
        self.stdin.flush().unwrap();
    }
    async fn recv(&mut self, within: Duration) -> Value {
        let line = tokio::time::timeout(within, self.lines.recv())
            .await
            .expect("no answer in time")
            .expect("stdout closed");
        serde_json::from_str(&line).unwrap()
    }
    /// Closes stdin and waits for the exit; returns the status, the unread stdout lines and the
    /// whole stderr.
    async fn finish(self, within: Duration) -> (ExitStatus, Vec<String>, String) {
        let Self {
            mut child,
            stdin,
            mut lines,
            errors,
        } = self;
        drop(stdin);
        let status = tokio::task::spawn_blocking(move || {
            let limit = std::time::Instant::now() + within;
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    return status;
                }
                if std::time::Instant::now() >= limit {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("openmybot mcp did not exit in time");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })
        .await
        .unwrap();
        let mut rest = Vec::new();
        while let Some(line) = lines.recv().await {
            rest.push(line);
        }
        (status, rest, errors.join().unwrap())
    }
}
fn rpc(id: u64, method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}
fn call(id: u64, tool: &str, arguments: Option<Value>) -> Value {
    let mut params = json!({"name": tool});
    if let Some(arguments) = arguments {
        params["arguments"] = arguments;
    }
    rpc(id, "tools/call", params)
}
/// A request of a session negotiated through `initialize`, without `_meta`.
fn legacy_rpc(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}
/// The five tools with arguments of the shape each takes.
fn five_calls() -> [(&'static str, Value); 5] {
    [
        (
            "wrok_run_begin",
            json!({"operation_id": "op-1", "message": "hi"}),
        ),
        ("wrok_run_status", json!({"run_id": "r1"})),
        ("wrok_run_cancel", json!({"run_id": "r1"})),
        ("wrok_run_result", json!({"run_id": "r1"})),
        ("wrok_thread_list", json!({})),
    ]
}
fn five_tools(listed: &Value) {
    let tools = listed["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "wrok_run_begin",
            "wrok_run_status",
            "wrok_run_cancel",
            "wrok_run_result",
            "wrok_thread_list",
        ]
    );
    for tool in tools {
        assert!(tool["description"].is_string());
        assert!(tool["inputSchema"].is_object());
        assert!(tool["outputSchema"].is_object());
    }
}
fn tool_error(answer: &Value, text: &str) {
    assert_eq!(answer["result"]["isError"], true, "{answer}");
    assert_eq!(
        answer["result"]["content"],
        json!([{"type": "text", "text": text}]),
        "{answer}"
    );
    assert!(
        answer["result"].get("structuredContent").is_none(),
        "{answer}"
    );
}
fn tool_data(answer: &Value, data: &Value) {
    assert_ne!(answer["result"]["isError"], true, "{answer}");
    assert_eq!(&answer["result"]["structuredContent"], data, "{answer}");
    let content = answer["result"]["content"].as_array().unwrap();
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");
    let text: Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, data);
}
/// How the stand-in daemon answers one connection.
enum Answer {
    Respond(Value),
    After {
        hello_delay: Duration,
        response_delay: Duration,
        value: Value,
    },
    CloseAfterHello,
}
fn success(data: Value) -> Answer {
    Answer::Respond(json!({"type": "response", "ok": true, "data": data}))
}
fn failure(code: &str) -> Answer {
    Answer::Respond(json!({"type": "response", "ok": false, "code": code}))
}
/// Accepts one connection per answer and serves each in its own task; returns each connection's
/// hello and request frames in accept order, `null` for a request never read.
fn serve(listener: UnixListener, answers: Vec<Answer>) -> JoinHandle<Vec<(Value, Value)>> {
    tokio::spawn(async move {
        let mut connections = Vec::new();
        for answer in answers {
            let (mut stream, _) = listener.accept().await.unwrap();
            connections.push(tokio::spawn(async move {
                let hello = read_frame(&mut stream).await;
                let (hello_delay, response_delay, value) = match answer {
                    Answer::CloseAfterHello => return (hello, Value::Null),
                    Answer::Respond(value) => (Duration::ZERO, Duration::ZERO, value),
                    Answer::After {
                        hello_delay,
                        response_delay,
                        value,
                    } => (hello_delay, response_delay, value),
                };
                tokio::time::sleep(hello_delay).await;
                let hello_ok = json!({"type": "hello_ok", "daemon_version": "0.0.0", "engine_pin": "0".repeat(40)});
                reply(&mut stream, &hello_ok).await;
                let request = read_frame(&mut stream).await;
                tokio::time::sleep(response_delay).await;
                reply(&mut stream, &value).await;
                (hello, request)
            }));
        }
        let mut records = Vec::new();
        for connection in connections {
            records.push(connection.await.unwrap());
        }
        records
    })
}
/// Like `write_frame`, ignoring a client that already left.
async fn reply(stream: &mut UnixStream, value: &Value) {
    let body = serde_json::to_vec(value).unwrap();
    let _ = stream.write_u32(body.len() as u32).await;
    let _ = stream.write_all(&body).await;
}
/// Counts the connections made to `listener`, reading and writing nothing.
fn counting(listener: UnixListener) -> (JoinHandle<()>, Arc<AtomicUsize>) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            count.fetch_add(1, Ordering::Relaxed);
        }
    });
    (task, accepted)
}
