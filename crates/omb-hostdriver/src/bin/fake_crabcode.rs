//! In-repository stand-in for `crabcode` (testkit only). Behaviour is chosen by environment
//! variables the tests place in the version window's `extra_env`:
//! `FAKE_CRABCODE_SCENARIO` (behaviour), `FAKE_CRABCODE_VERSION` (version line),
//! `FAKE_CRABCODE_REPORT` (JSON-lines observations: argv, environment, cwd, stdin, signals,
//! descendants), `FAKE_CRABCODE_SESSION`, `FAKE_CRABCODE_TEXT`, `FAKE_CRABCODE_TOOL`,
//! `FAKE_CRABCODE_INPUT`, `FAKE_CRABCODE_INPUT2`, `FAKE_CRABCODE_BYTES`, `FAKE_CRABCODE_DELAY_MS`,
//! `FAKE_CRABCODE_HOLD_MS`.
use serde_json::{Value, json};
use std::{
    io::{BufRead, Write},
    time::Duration,
};
use tokio::sync::mpsc;

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}
fn report(entry: Value) {
    if let Some(path) = var("FAKE_CRABCODE_REPORT") {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let mut line = entry.to_string();
        line.push('\n');
        file.write_all(line.as_bytes()).unwrap();
    }
}
async fn emit(value: &Value) {
    emit_raw(&format!("{value}\n")).await;
}
/// Stdout bytes written so far, newlines included.
static EMITTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
async fn emit_raw(text: &str) {
    EMITTED.fetch_add(text.len(), std::sync::atomic::Ordering::SeqCst);
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes()).unwrap();
    out.flush().unwrap();
}
fn delay() -> Duration {
    Duration::from_millis(
        var("FAKE_CRABCODE_DELAY_MS")
            .and_then(|ms| ms.parse().ok())
            .unwrap_or(0),
    )
}
fn bytes() -> usize {
    var("FAKE_CRABCODE_BYTES")
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}
fn input(name: &str) -> Value {
    var(name)
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| json!({}))
}

struct Child {
    /// Stdin lines, recorded as they are read by a blocking thread; the channel closes at end of
    /// input.
    lines: mpsc::UnboundedReceiver<Value>,
    session: String,
}
impl Child {
    /// The next stdin line, recorded and parsed; the initialize request is answered here.
    async fn next(&mut self) -> Option<Value> {
        loop {
            let value = self.lines.recv().await?;
            if value["type"] == "control_request" && value["request"]["subtype"] == "initialize" {
                emit(&json!({"type": "control_response", "response": {"subtype": "success", "request_id": value["request_id"], "response": {}}})).await;
                continue;
            }
            return Some(value);
        }
    }
    /// Reads until the first user message.
    async fn user(&mut self) -> bool {
        while let Some(value) = self.next().await {
            if value["type"] == "user" {
                return true;
            }
        }
        false
    }
    async fn until_interrupt(&mut self) -> bool {
        while let Some(value) = self.next().await {
            if value["request"]["subtype"] == "interrupt" {
                return true;
            }
        }
        false
    }
    async fn until_eof(&mut self) {
        while self.next().await.is_some() {}
    }
    async fn init(&self) {
        emit(&json!({"type": "system", "subtype": "init", "session_id": self.session, "tools": ["Read", "Write"]})).await;
    }
    async fn text(&self, text: &str) {
        emit(&json!({"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": text}]}, "session_id": self.session})).await;
    }
    async fn success(&self, text: &str) {
        emit(&json!({"type": "result", "subtype": "success", "is_error": false, "result": text, "session_id": self.session, "usage": {"input_tokens": 11, "output_tokens": 7}})).await;
    }
    async fn failure(&self) {
        emit(&json!({"type": "result", "subtype": "error_during_execution", "is_error": true, "session_id": self.session})).await;
    }
    /// Sends `can_use_tool` requests and applies each answer: an allowed `file_path` with
    /// `content` is written relative to the working directory.
    async fn permissions(&mut self, requests: &[(&str, Value)]) -> Vec<Value> {
        let tool = var("FAKE_CRABCODE_TOOL").unwrap_or_else(|| "Write".into());
        for (id, input) in requests {
            emit(&json!({"type": "control_request", "request_id": id, "request": {"subtype": "can_use_tool", "tool_name": tool, "input": input, "tool_use_id": format!("tu-{id}")}})).await;
        }
        let mut answers = Vec::new();
        while answers.len() < requests.len() {
            let Some(value) = self.next().await else {
                break;
            };
            if value["type"] != "control_response" {
                continue;
            }
            let response = &value["response"]["response"];
            if response["behavior"] == "allow"
                && let (Some(path), Some(content)) = (
                    response["updatedInput"]["file_path"].as_str(),
                    response["updatedInput"]["content"].as_str(),
                )
            {
                std::fs::write(path, content).unwrap();
            }
            answers.push(value);
        }
        answers
    }
}

fn spawn_descendant(role: &str) {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .env("FAKE_CRABCODE_ROLE", role)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    report(json!({"event": "descendant", "role": role, "pid": child.id()}));
    std::mem::forget(child);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Some(role) = var("FAKE_CRABCODE_ROLE") {
        if role == "setsid" {
            rustix::process::setsid().unwrap();
            report(
                json!({"event": "detached", "pid": rustix::process::getpid().as_raw_nonzero().get()}),
            );
        }
        std::future::pending::<()>().await;
    }
    let argv: Vec<String> = std::env::args().collect();
    let pid = rustix::process::getpid();
    report(json!({
        "event": "start",
        "argv": argv,
        "env": std::env::vars().collect::<std::collections::BTreeMap<_, _>>(),
        "cwd": std::env::current_dir().unwrap(),
        "pid": pid.as_raw_nonzero().get(),
        "pgid": rustix::process::getpgid(None).unwrap().as_raw_nonzero().get(),
    }));
    if argv.get(1).map(String::as_str) == Some("--version") {
        let version = var("FAKE_CRABCODE_VERSION").unwrap_or_else(|| "1.1.16".into());
        println!("crabcode {version}");
        return;
    }
    let resume = argv
        .iter()
        .position(|arg| arg == "--resume")
        .and_then(|index| argv.get(index + 1).cloned());
    let mut child = Child {
        lines: {
            let (sender, receiver) = mpsc::unbounded_channel();
            std::thread::spawn(move || {
                for line in std::io::stdin().lock().lines() {
                    let Ok(line) = line else { break };
                    let value: Value = serde_json::from_str(&line).unwrap_or(Value::String(line));
                    report(json!({"event": "stdin", "frame": value}));
                    if sender.send(value).is_err() {
                        break;
                    }
                }
                report(json!({"event": "stdin_eof"}));
            });
            receiver
        },
        session: resume
            .or_else(|| var("FAKE_CRABCODE_SESSION"))
            .unwrap_or_else(|| "fake-session-1".into()),
    };
    let text = var("FAKE_CRABCODE_TEXT").unwrap_or_else(|| "hello from fake".into());
    let scenario = var("FAKE_CRABCODE_SCENARIO").unwrap_or_else(|| "happy".into());
    if !child.user().await {
        return;
    }
    match scenario.as_str() {
        "happy" => {
            child.init().await;
            child.text(&text).await;
            child.success(&text).await;
            child.until_eof().await;
        }
        "requests" => {
            child.init().await;
            for (id, subtype) in [
                ("h1", "hook_callback"),
                ("e1", "elicitation"),
                ("m1", "mcp_message"),
                ("s1", "set_model"),
            ] {
                emit(&json!({"type": "control_request", "request_id": id, "request": {"subtype": subtype}})).await;
            }
            let mut answered = 0;
            while answered < 4 {
                match child.next().await {
                    Some(value) if value["type"] == "control_response" => answered += 1,
                    Some(_) => (),
                    None => return,
                }
            }
            child.text(&text).await;
            child.success(&text).await;
            child.until_eof().await;
        }
        "no_init" => child.until_eof().await,
        "non_json" => {
            child.init().await;
            emit_raw("this is not json\n").await;
            child.until_eof().await;
        }
        "exit_early" => {
            child.init().await;
            child.text(&text).await;
            std::process::exit(3);
        }
        "exit_before_init" => std::process::exit(4),
        "result_error" => {
            child.init().await;
            child.failure().await;
            child.until_eof().await;
        }
        "silence" => {
            child.init().await;
            child.until_eof().await;
        }
        "permission" => {
            child.init().await;
            tokio::time::sleep(delay()).await;
            let answers = child
                .permissions(&[("req-1", input("FAKE_CRABCODE_INPUT"))])
                .await;
            let allowed = answers
                .iter()
                .all(|a| a["response"]["response"]["behavior"] == "allow");
            tokio::time::sleep(Duration::from_millis(
                var("FAKE_CRABCODE_HOLD_MS")
                    .and_then(|ms| ms.parse().ok())
                    .unwrap_or(0),
            ))
            .await;
            let reply = if allowed { "allowed" } else { "denied" };
            child.text(reply).await;
            child.success(reply).await;
            child.until_eof().await;
        }
        "two_permissions" => {
            child.init().await;
            child
                .permissions(&[
                    ("req-1", input("FAKE_CRABCODE_INPUT")),
                    ("req-2", input("FAKE_CRABCODE_INPUT2")),
                ])
                .await;
            child.text(&text).await;
            child.success(&text).await;
            child.until_eof().await;
        }
        "flood" => {
            child.init().await;
            child.text(&"x".repeat(bytes())).await;
            child.success(&text).await;
            child.until_eof().await;
        }
        "exact" => {
            // Stdout totals exactly FAKE_CRABCODE_BYTES, newlines included.
            let init = format!(
                "{}\n",
                json!({"type": "system", "subtype": "init", "session_id": child.session})
            );
            let result = format!(
                "{}\n",
                json!({"type": "result", "subtype": "success", "is_error": false, "result": "x"})
            );
            let empty = format!(
                "{}\n",
                json!({"type": "assistant", "message": {"content": [{"type": "text", "text": ""}]}})
            );
            let written = EMITTED.load(std::sync::atomic::Ordering::SeqCst);
            let padding = bytes() - written - init.len() - result.len() - empty.len();
            let assistant = format!(
                "{}\n",
                json!({"type": "assistant", "message": {"content": [{"type": "text", "text": "y".repeat(padding)}]}})
            );
            emit_raw(&format!("{init}{assistant}{result}")).await;
            child.until_eof().await;
        }
        "stderr" => {
            child.init().await;
            let mut err = std::io::stderr().lock();
            let pattern: String = (0..bytes())
                .map(|n| char::from(b'a' + (n % 26) as u8))
                .collect();
            err.write_all(pattern.as_bytes()).unwrap();
            err.flush().unwrap();
            drop(err);
            tokio::time::sleep(Duration::from_millis(300)).await;
            child.text(&text).await;
            child.success(&text).await;
            child.until_eof().await;
        }
        "long_line" => {
            child.init().await;
            let frame = json!({"type": "system", "subtype": "status", "pad": ""}).to_string();
            let padded = frame.replace(
                "\"pad\":\"\"",
                &format!("\"pad\":\"{}\"", "p".repeat(bytes() - frame.len())),
            );
            emit_raw(&format!("{padded}\n")).await;
            child.until_eof().await;
        }
        "cooperative" => {
            child.init().await;
            if child.until_interrupt().await {
                child.failure().await;
                std::process::exit(0);
            }
        }
        "slow_result" => {
            child.init().await;
            tokio::select! {
                interrupted = child.until_interrupt() => if interrupted {
                    child.failure().await;
                    std::process::exit(0);
                },
                () = tokio::time::sleep(delay()) => {
                    child.text(&text).await;
                    child.success(&text).await;
                    child.until_eof().await;
                }
            }
        }
        "ignore_interrupt" => {
            child.init().await;
            child.until_eof().await;
        }
        "ignore_eof" => {
            child.init().await;
            child.until_eof().await;
            std::future::pending::<()>().await;
        }
        "ignore_term" => {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
            tokio::spawn(async move {
                while terminate.recv().await.is_some() {
                    report(json!({"event": "signal", "signal": 15}));
                }
            });
            child.init().await;
            child.until_eof().await;
            std::future::pending::<()>().await;
        }
        "grandchild" | "setsid" => {
            spawn_descendant(if scenario == "setsid" {
                "setsid"
            } else {
                "sleeper"
            });
            child.init().await;
            if child.until_interrupt().await {
                child.failure().await;
                std::process::exit(0);
            }
        }
        other => panic!("unknown fake scenario {other}"),
    }
}
