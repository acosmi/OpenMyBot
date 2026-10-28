//! Layer-2 recheck against the real CrabCode binary of this machine. Ignored: the controller runs
//! it once the isolation mode is chosen. Inputs (all required unless noted):
//! `OMB_REAL_CRABCODE_BIN`, `OMB_REAL_RECHECK_SANDBOX` (a fresh directory under `$HOME`),
//! `OMB_REAL_RECHECK_ISOLATION` (`home` | `config_dir` | `bare`), `OMB_REAL_RECHECK_WINDOW`
//! (`inject`, the default, or `embedded`), `OMB_REAL_RECHECK_REPORT` (inside the sandbox) and
//! `OMB_TEST_PG_BIN_DIR`. `config_dir` points `CRABCODE_CONFIG_DIR` at
//! `<sandbox>/crabcode-config`; `bare` adds `--bare` and passes `ACOSMI_API_KEY` from this
//! process's environment. `OMB_REAL_RECHECK_EXTRA_ARGS` (optional, whitespace-separated) adds
//! per-version arguments to the window entry. The report holds no absolute path and no credential; it is rewritten
//! after every step, so a failed gate still leaves it behind.
use omb_hostdriver::{
    CC_STOP_GRACE, HostDriver, HostDriverConfig, Limits, VersionWindow, WorkspaceRoots,
};
use omb_store::{
    Decision, migrate,
    testkit::{Fixture, deadline, decide, insert_event_for_run, insert_sender_in, set_terminal},
};
use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderExtensionKey, ProviderMessage, ProviderMessageRole,
    ProviderRequest, ProviderRoute, StopOutcome,
};
use serde_json::{Map, Value, json};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}
fn version_of(line: &str) -> Option<String> {
    line.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find(|token| {
            let parts: Vec<&str> = token.split('.').collect();
            parts.len() >= 3 && parts[..3].iter().all(|p| !p.is_empty())
        })
        .map(|token| token.split('.').take(3).collect::<Vec<_>>().join("."))
}
/// Replaces the sandbox and home prefixes so the report carries no absolute path.
fn relative(text: &str, sandbox: &Path, home: &Path) -> String {
    text.replace(sandbox.to_str().unwrap(), "<sandbox>")
        .replace(home.to_str().unwrap(), "<home>")
}
fn request(binding: Uuid, prompt: &str) -> ProviderRequest {
    let user = |content: String| ProviderMessage {
        role: ProviderMessageRole::User,
        content,
        tool_call_id: None,
        tool_name: None,
        tool_calls: Vec::new(),
    };
    ProviderRequest {
        route: ProviderRoute::Extension(ProviderExtensionKey::new("crabcode").unwrap()),
        messages: vec![user(format!("[omb-binding {binding}]\n{prompt}"))],
        tools: Vec::new(),
        max_output_tokens: None,
        rate_card: None,
        cost_cap: None,
    }
}

/// The report, rewritten on every change.
struct Report {
    path: PathBuf,
    sandbox: PathBuf,
    home: PathBuf,
    fields: Map<String, Value>,
}
impl Report {
    fn set(&mut self, key: &str, value: Value) {
        self.fields.insert(key.to_owned(), value);
        let text = relative(
            &serde_json::to_string_pretty(&self.fields).unwrap(),
            &self.sandbox,
            &self.home,
        );
        assert!(
            !text.contains(self.home.to_str().unwrap())
                && !text.contains(self.sandbox.to_str().unwrap()),
            "the report holds no absolute path"
        );
        std::fs::write(&self.path, text).unwrap();
    }
}

/// The owner-scope settings file written for the G4 turn only, removed when dropped (also while
/// unwinding). Nothing else in the configuration directory is listed, read or copied.
struct UserSettings(PathBuf);
impl UserSettings {
    fn write(dir: &Path, contents: &str) -> Self {
        assert!(dir.is_dir(), "<sandbox>/crabcode-config does not exist");
        let path = dir.join("settings.json");
        // An existing file is never touched: the guard exists only once this call created it.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("settings.json must not already exist in the configuration directory");
        let guard = Self(path);
        std::io::Write::write_all(&mut file, contents.as_bytes()).unwrap();
        guard
    }
}
impl Drop for UserSettings {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// What one run produced.
#[derive(Default)]
struct Turn {
    init: bool,
    terminal: Option<String>,
    decisions: Vec<(String, String)>,
    stop: Option<String>,
    stop_elapsed: Option<Duration>,
}

/// G5 asks for the stop this long after `ResponseStarted`: assistant text and the result arrive
/// back to back in stream-json, so a stop on the first text would usually land after the result.
const STOP_DELAY: Duration = Duration::from_secs(2);

/// Kills the probe's process group when dropped, also while unwinding.
struct GroupKill(rustix::process::Pid);
impl Drop for GroupKill {
    fn drop(&mut self) {
        let _ = rustix::process::kill_process_group(self.0, rustix::process::Signal::KILL);
    }
}

struct Recheck {
    _fixture: Fixture,
    client: tokio_postgres::Client,
    driver: HostDriver,
}
impl Recheck {
    async fn row(&self, run: &str) -> Value {
        self.client
            .query_one("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='session' AND run_id=$1", &[&run])
            .await
            .unwrap()
            .get(0)
    }
    async fn permissions(&self, run: &str) -> Vec<Value> {
        self.client
            .query("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='permission' AND run_id=$1 ORDER BY requested_at", &[&run])
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect()
    }
    /// Drives one run to its terminal, answering each waiting request through the testkit
    /// decision interface with `policy(tool, input summary)`; `stop_after_start` asks for a stop
    /// `STOP_DELAY` after `ResponseStarted`. The run's channel event is marked terminal afterwards, so the
    /// binding's next run resolves to the next event.
    async fn turn(
        &self,
        binding: Uuid,
        run: &str,
        thread: &str,
        prompt: &str,
        policy: impl Fn(&str, &str) -> Decision,
        stop_after_start: bool,
    ) -> Turn {
        let event = insert_event_for_run(&self.client, binding, run, thread, "dispatched").await;
        let turn = self
            .drive(binding, run, prompt, policy, stop_after_start)
            .await;
        let kind = match (&turn.stop, turn.terminal.as_deref()) {
            (Some(_), _) => "cancelled",
            (None, Some("Completed")) => "succeeded",
            _ => "failed",
        };
        set_terminal(&self.client, event, kind).await;
        turn
    }
    async fn drive(
        &self,
        binding: Uuid,
        run: &str,
        prompt: &str,
        policy: impl Fn(&str, &str) -> Decision,
        stop_after_start: bool,
    ) -> Turn {
        let mut turn = Turn::default();
        let mut session = match self.driver.adapter().start(request(binding, prompt)).await {
            Ok(session) => session,
            Err(error) => {
                turn.terminal = Some(format!("start_error:{error}"));
                return turn;
            }
        };
        let limit = tokio::time::Instant::now() + Duration::from_secs(900);
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                event = session.next_event() => match event {
                    Ok(Some(event)) => {
                        let name = format!("{event:?}");
                        let started = matches!(event, ProviderEvent::ResponseStarted { .. });
                        turn.init |= started;
                        let done = matches!(event, ProviderEvent::Completed | ProviderEvent::Failed(_));
                        if done {
                            turn.terminal = Some(name);
                            return turn;
                        }
                        if stop_after_start && started {
                            tokio::time::sleep(STOP_DELAY).await;
                            let asked = std::time::Instant::now();
                            let outcome = session.request_stop().await.unwrap();
                            turn.stop_elapsed = Some(asked.elapsed());
                            turn.stop = Some(match outcome {
                                StopOutcome::Confirmed { .. } => "confirmed".into(),
                                StopOutcome::Unknown => "unknown".into(),
                                StopOutcome::Unsupported => "unsupported".into(),
                            });
                            return turn;
                        }
                    }
                    other => {
                        turn.terminal = Some(format!("{other:?}"));
                        return turn;
                    }
                },
                _ = tick.tick() => {
                    if tokio::time::Instant::now() >= limit {
                        turn.terminal = Some("turn_deadline".into());
                        return turn;
                    }
                    for row in self.permissions(run).await {
                        if row["decision"].is_null() {
                            let tool = row["tool_name"].as_str().unwrap_or_default().to_owned();
                            let decision = policy(&tool, row["input_summary"].as_str().unwrap_or_default());
                            decide(&self.client, row["permission_id"].as_str().unwrap(), decision).await;
                            turn.decisions.push((tool, format!("{decision:?}")));
                        }
                    }
                }
            }
        }
    }
}

/// The minimal environment of the driver's children.
struct ChildEnvironment<'a> {
    binary: &'a Path,
    home: &'a Path,
    tmp: &'a Path,
    extra_env: &'a BTreeMap<String, String>,
}
impl ChildEnvironment<'_> {
    fn command(&self, args: &[String], cwd: &Path) -> tokio::process::Command {
        let mut path = OsString::from("/usr/bin:/bin:/usr/sbin:/sbin:");
        path.push(self.binary.parent().unwrap());
        let mut command = tokio::process::Command::new(self.binary);
        command
            .args(args)
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.home)
            .env("LANG", "en_US.UTF-8")
            .env("TERM", "dumb")
            .env("TMPDIR", self.tmp)
            .env("OPENMYBOT_HOST_DRIVER_CHILD", "1")
            .envs(self.extra_env)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        command
    }
}

/// G5's stdin-close observation: one turn with the driver's argv shape, then stdin closes after
/// the result frame; returns whether the child exited without a signal within `CC_STOP_GRACE`,
/// and what was seen.
async fn stdin_close_probe(
    child_env: &ChildEnvironment<'_>,
    extra_args: &[String],
    cwd: &Path,
) -> (bool, Value) {
    let mut args: Vec<String> = [
        "--print",
        "--",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--permission-mode",
        "default",
        "--permission-prompt-tool",
        "stdio",
    ]
    .iter()
    .map(|arg| arg.to_string())
    .collect();
    args.extend(extra_args.iter().cloned());
    let mut child = child_env.command(&args, cwd).spawn().unwrap();
    let pgid = rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap();
    let _kill = GroupKill(pgid);
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    for frame in [
        json!({"type":"control_request","request_id":"probe-initialize","request":{"subtype":"initialize"}}),
        json!({"type":"user","message":{"role":"user","content":"Reply with the single word READY."}}),
    ] {
        stdin
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("probe stdin write; the guard kills the group while unwinding");
    }
    let result = tokio::time::timeout(Duration::from_secs(300), async {
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(frame) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if frame["type"] == "result" {
                return true;
            }
            if frame["type"] == "control_request" {
                let deny = json!({"type":"control_response","response":{"subtype":"success","request_id":frame["request_id"],"response":{"behavior":"deny","message":"owner_denied"}}});
                let _ = stdin.write_all(format!("{deny}\n").as_bytes()).await;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    drop(stdin);
    let closed = std::time::Instant::now();
    let status = tokio::time::timeout(CC_STOP_GRACE, child.wait()).await;
    let elapsed = closed.elapsed();
    let group_empty =
        rustix::process::test_kill_process_group(pgid) == Err(rustix::io::Errno::SRCH);
    let observation = match &status {
        Ok(Ok(status)) => {
            json!({"result_seen": result, "exit_code": status.code(), "exit_signal": status.signal(), "exit_after_ms": elapsed.as_millis() as u64, "process_group_empty": group_empty})
        }
        _ => {
            json!({"result_seen": result, "exited_within_stop_grace": false, "process_group_empty": group_empty})
        }
    };
    // Tool or MCP subprocesses of the probe never outlive it.
    let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
    if status.is_err() {
        let _ = child.wait().await;
    }
    let exited_cleanly = result && matches!(&status, Ok(Ok(status)) if status.signal().is_none());
    (exited_cleanly, observation)
}

#[tokio::test]
#[ignore = "real CrabCode on this machine; run by the controller after the isolation mode is chosen"]
async fn real_crabcode_recheck() {
    let binary = PathBuf::from(required("OMB_REAL_CRABCODE_BIN"));
    let sandbox = std::fs::canonicalize(required("OMB_REAL_RECHECK_SANDBOX")).unwrap();
    let isolation = required("OMB_REAL_RECHECK_ISOLATION");
    let window_mode = std::env::var("OMB_REAL_RECHECK_WINDOW").unwrap_or_else(|_| "inject".into());
    let report_path = PathBuf::from(required("OMB_REAL_RECHECK_REPORT"));
    assert!(
        report_path.starts_with(&sandbox),
        "the report stays in the sandbox"
    );
    let home = std::fs::canonicalize(required("HOME")).unwrap();
    assert!(
        sandbox.starts_with(&home) && sandbox != home && !sandbox.starts_with(home.join("Library"))
    );
    let mut report = Report {
        path: report_path,
        sandbox: sandbox.clone(),
        home: home.clone(),
        fields: Map::new(),
    };
    report.set("isolation", json!(isolation));
    report.set("window", json!(window_mode));
    let config_dir = sandbox.join("crabcode-config");
    let (mut extra_args, extra_env): (Vec<String>, BTreeMap<String, String>) =
        match isolation.as_str() {
            "home" => (Vec::new(), BTreeMap::new()),
            "config_dir" => (
                Vec::new(),
                BTreeMap::from([(
                    "CRABCODE_CONFIG_DIR".to_owned(),
                    config_dir.to_str().unwrap().to_owned(),
                )]),
            ),
            "bare" => (
                vec!["--bare".to_owned()],
                BTreeMap::from([("ACOSMI_API_KEY".to_owned(), required("ACOSMI_API_KEY"))]),
            ),
            other => panic!("OMB_REAL_RECHECK_ISOLATION {other} is not home, config_dir or bare"),
        };
    // Per-version arguments the window entry carries (e.g. `--verbose` for 1.1.16).
    extra_args.extend(
        std::env::var("OMB_REAL_RECHECK_EXTRA_ARGS")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned),
    );
    let report_env: BTreeMap<&String, String> = extra_env
        .iter()
        .map(|(key, value)| {
            let shown = if key == "ACOSMI_API_KEY" {
                "<redacted>".to_owned()
            } else {
                relative(value, &sandbox, &home)
            };
            (key, shown)
        })
        .collect();
    report.set("extra_env", json!(report_env));

    let mut suffix = [0; 4];
    getrandom::fill(&mut suffix).unwrap();
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = sandbox.join(format!("tmp-{suffix}"));
    std::fs::create_dir_all(&tmp).unwrap();
    let child_env = ChildEnvironment {
        binary: &binary,
        home: &home,
        tmp: &tmp,
        extra_env: &extra_env,
    };

    // G1 for the record: the version line of a probe in the sandbox. The driver's own probe at
    // every start is the authoritative check.
    let probe = child_env
        .command(&["--version".to_owned()], &sandbox)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    let version_line = String::from_utf8_lossy(&probe.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let version = version_of(&version_line);
    let binary_sha256: String = sha2::Sha256::digest(std::fs::read(&binary).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let build_id = std::fs::read_to_string(binary.parent().unwrap().join("build-id"))
        .map(|text| text.trim().to_owned())
        .ok();
    let engine_commit = String::from_utf8(
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    report.set("version_line", json!(version_line));
    report.set("version", json!(version));
    report.set("binary_sha256", json!(binary_sha256));
    report.set("build_id", json!(build_id));
    report.set("engine_commit", json!(engine_commit));
    let manifest = match window_mode.as_str() {
        "inject" => json!({"accepted": [{
            "version": version.clone().unwrap_or_default(),
            "extra_args": extra_args,
            "extra_env": extra_env,
            "gates": {"G1": "pass", "G2": "pass", "G3": "pass", "G4": "pass", "G5": "pass", "G6": "pass"},
            "verified_at": "1970-01-01T00:00:00Z",
            "engine_commit": engine_commit,
            "record": format!("compat/crabcode/{}.md", version.clone().unwrap_or_default()),
        }]}),
        "embedded" => {
            // The compiled-in manifest with this run's arguments and the isolation environment
            // laid over the entry of the probed version: the entry's arguments followed by any not
            // already present, its environment with the isolation keys inserted or overwritten.
            // Version, gates and record stay as committed.
            let mut manifest: Value = serde_json::from_str(include_str!(
                "../../../openmybot/compat/crabcode/accepted.json"
            ))
            .unwrap();
            let probed = version.clone().unwrap_or_default();
            let entry = manifest["accepted"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|entry| entry["version"] == probed.as_str())
                .unwrap_or_else(|| panic!("the embedded window has no entry for {probed}"));
            let args = entry["extra_args"].as_array_mut().unwrap();
            for arg in &extra_args {
                if !args.iter().any(|known| known == arg.as_str()) {
                    args.push(json!(arg));
                }
            }
            let env = entry["extra_env"].as_object_mut().unwrap();
            for (key, value) in &extra_env {
                env.insert(key.clone(), json!(value));
            }
            report.set(
                "embedded_overlay",
                json!({"extra_args": extra_args, "extra_env_keys": extra_env.keys().collect::<Vec<_>>()}),
            );
            manifest
        }
        other => panic!("OMB_REAL_RECHECK_WINDOW {other} is not inject or embedded"),
    };
    let probed = version.clone().unwrap_or_default();
    let effective_args: Vec<String> = manifest["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["version"] == probed.as_str())
        .map(|entry| serde_json::from_value(entry["extra_args"].clone()).unwrap())
        .unwrap_or_default();
    report.set("extra_args", json!(effective_args));
    let window = VersionWindow::parse(&manifest.to_string()).unwrap();

    let workspace = sandbox.join(format!("ws-{suffix}"));
    let permissive = sandbox.join(format!("ws-g4-{suffix}"));
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(permissive.join(".crabcode")).unwrap();
    std::fs::write(
        workspace.join("notes.txt"),
        "The sandbox note says: rivers.\n",
    )
    .unwrap();
    let permissions =
        json!({"permissions": {"defaultMode": "acceptEdits", "allow": ["Read", "Write", "Edit", "Bash"]}})
            .to_string();
    // G4, workspace scope: the workspace itself allows every tool.
    std::fs::write(permissive.join(".crabcode/settings.json"), &permissions).unwrap();

    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    let (store, _store_driver) = fixture.open().await;
    let (client, _client_driver) = fixture.open().await;
    let driver = HostDriver::new(
        HostDriverConfig {
            binary: Some(binary.clone()),
            home: home.clone(),
            tmp_dir: tmp.clone(),
            roots: WorkspaceRoots::parse(&home, &[workspace.clone(), permissive.clone()]).unwrap(),
            window,
            limits: Limits::default(),
        },
        Arc::new(store),
    );
    let recheck = Recheck {
        _fixture: fixture,
        client,
        driver,
    };
    let main = insert_sender_in(
        &recheck.client,
        "telegram",
        "1001",
        "telegram:1",
        "T-main",
        workspace.to_str().unwrap(),
    )
    .await;
    let g4 = insert_sender_in(
        &recheck.client,
        "feishu",
        "app",
        "feishu:1",
        "T-g4",
        permissive.to_str().unwrap(),
    )
    .await;
    let pass = |ok: bool| if ok { "pass" } else { "fail" };
    report.set(
        "G1",
        json!({"result": pass(version.is_some()), "observation": version_line}),
    );

    // Step 1–3: start, the read-only tool, and the write request denied.
    let deny_all = |_: &str, _: &str| Decision::Deny;
    let first = recheck
        .turn(main, "real-1", "T-main", "Use the Read tool to read notes.txt in the current directory. Then use the Write tool to create denied.txt containing the word no. Finally reply with the word DONE.", deny_all, false)
        .await;
    let first_row = recheck.row("real-1").await;
    let first_permissions = recheck.permissions("real-1").await;
    let readonly_rows = first_permissions
        .iter()
        .filter(|p| p["decided_via"] == "readonly_rule")
        .count();
    let read_requested = first_permissions.iter().any(|p| p["tool_name"] == "Read");
    let denied_absent = !workspace.join("denied.txt").exists();
    let write_asked_first = first_permissions
        .iter()
        .any(|p| p["tool_name"] == "Write" && p["decision"] == "deny");
    let g2 = first.init && first_row["native_session_id"].is_string();
    report.set(
        "G2",
        json!({"result": pass(g2), "observation": {"system_init": first.init, "terminal": first.terminal, "exit_code": first_row["exit_code"], "exit_signal": first_row["exit_signal"], "stderr_tail": first_row["stderr_tail"]}}),
    );

    // Step 4–5: the write request allowed, and the run's terminal result.
    let allow_writes = |tool: &str, _: &str| {
        if tool == "Write" {
            Decision::Allow
        } else {
            Decision::Deny
        }
    };
    let second = recheck
        .turn(main, "real-2", "T-allow", "Use the Write tool to create allowed.txt containing the word yes. Then reply with the word DONE.", allow_writes, false)
        .await;
    let second_row = recheck.row("real-2").await;
    let allowed_present = workspace.join("allowed.txt").exists();
    let write_asked_second = recheck
        .permissions("real-2")
        .await
        .iter()
        .any(|p| p["tool_name"] == "Write");
    let g3 = write_asked_first && denied_absent && write_asked_second && allowed_present;
    report.set(
        "G3",
        json!({"result": pass(g3), "observation": {"write_requested_then_denied": write_asked_first, "no_file_after_deny": denied_absent, "write_requested_then_allowed": write_asked_second, "file_after_allow": allowed_present}}),
    );

    // G4: workspace and user configuration both allow every tool; the host must still ask. The
    // user-scope file is written only into the sandbox configuration directory.
    let (fourth, g4_ok, g4_observation) = if isolation == "config_dir" {
        let user_settings = UserSettings::write(&config_dir, &permissions);
        let fourth = recheck
            .turn(g4, "real-g4", "T-g4", "Use the Write tool to create g4.txt containing the word four. Then reply with the word DONE.", deny_all, false)
            .await;
        drop(user_settings);
        let g4_asked = recheck
            .permissions("real-g4")
            .await
            .iter()
            .any(|p| p["tool_name"] == "Write");
        let g4_absent = !permissive.join("g4.txt").exists();
        (
            fourth,
            g4_asked && g4_absent,
            json!({"write_requested": g4_asked, "no_file_after_deny": g4_absent, "workspace_settings_permissive": true, "user_settings_permissive": true}),
        )
    } else {
        (
            Turn::default(),
            false,
            json!({"not_run": format!("isolation {isolation} has no sandbox user configuration to make permissive")}),
        )
    };
    report.set(
        "G4",
        json!({"result": pass(g4_ok), "observation": g4_observation}),
    );

    // Step 6 / G5: a second turn stopped mid-way, and a separate stdin-close probe.
    let stopped = recheck
        .turn(main, "real-stop", "T-stop", "Count from 1 to 300, writing each number on its own line with a short sentence about it.", deny_all, true)
        .await;
    let stop_row = recheck.row("real-stop").await;
    let group_empty = stop_row["pgid"].as_i64().is_some_and(|pgid| {
        rustix::process::test_kill_process_group(
            rustix::process::Pid::from_raw(pgid as i32).unwrap(),
        ) == Err(rustix::io::Errno::SRCH)
    });
    let stop_in_grace = stopped
        .stop_elapsed
        .is_some_and(|elapsed| elapsed < CC_STOP_GRACE);
    let (stdin_close_exit, stdin_close) =
        stdin_close_probe(&child_env, &effective_args, &workspace).await;
    let g5 = stopped.stop.as_deref() == Some("confirmed")
        && group_empty
        && stop_row["end_reason"] == "stop_requested"
        && stop_in_grace
        && stdin_close_exit;
    report.set(
        "G5",
        json!({"result": pass(g5), "observation": {
            "stop_trigger": "ResponseStarted",
            "stop_delay_ms": STOP_DELAY.as_millis() as u64,
            "request_stop": stopped.stop,
            "request_stop_ms": stopped.stop_elapsed.map(|e| e.as_millis() as u64),
            "within_stop_grace": stop_in_grace,
            "end_reason": stop_row["end_reason"],
            "process_group_empty": group_empty,
            "exit_code": stop_row["exit_code"],
            "exit_signal": stop_row["exit_signal"],
            "stdin_close": stdin_close,
        }}),
    );

    // G6: the next run in the first thread resumes the session of G2.
    let sixth = recheck
        .turn(
            main,
            "real-resume",
            "T-main",
            "Which word did the sandbox note contain? Reply with that single word.",
            deny_all,
            false,
        )
        .await;
    let resume_row = recheck.row("real-resume").await;
    let g6 = resume_row["resumed_from"].is_string()
        && resume_row["resumed_from"] == first_row["native_session_id"]
        && resume_row["end_reason"] == "result_success";
    report.set(
        "G6",
        json!({"result": pass(g6), "observation": {"resumed_from_matches_g2": resume_row["resumed_from"] == first_row["native_session_id"], "end_reason": resume_row["end_reason"]}}),
    );

    let turns = [&first, &second, &fourth, &stopped, &sixth];
    let mut all_permissions = Vec::new();
    for run in ["real-1", "real-2", "real-g4", "real-stop", "real-resume"] {
        all_permissions.extend(recheck.permissions(run).await);
    }
    report.set(
        "steps",
        json!([
            {"step": "start", "init": first.init, "terminal": first.terminal, "exit_code": first_row["exit_code"], "exit_signal": first_row["exit_signal"], "stderr_tail": first_row["stderr_tail"]},
            {"step": "readonly_auto_allow", "read_via_can_use_tool": read_requested, "readonly_rule_rows": readonly_rows, "note": if read_requested { "observed through can_use_tool" } else { "CLI allowed internally, not through can_use_tool" }},
            {"step": "approval_required_tool_blocked", "write_requested": write_asked_first, "denied": denied_absent},
            {"step": "allow", "write_requested": write_asked_second, "file_written": allowed_present},
            {"step": "terminal", "terminal": second.terminal, "end_reason": second_row["end_reason"]},
            {"step": "second_turn_stopped", "request_stop": stopped.stop, "process_group_empty": group_empty},
        ]),
    );
    report.set(
        "counts",
        json!({
            "system_init": turns.iter().filter(|t| t.init).count(),
            "can_use_tool": all_permissions.len(),
            "readonly_allowed": all_permissions.iter().filter(|p| p["decided_via"] == "readonly_rule").count(),
            "allowed": all_permissions.iter().filter(|p| p["decision"] == "allow" && p["decided_via"] == "cli").count(),
            "denied": all_permissions.iter().filter(|p| p["decision"] == "deny").count(),
            "terminal_provider_events": turns.iter().filter(|t| t.terminal.as_deref().is_some_and(|e| e == "Completed" || e.starts_with("Failed"))).count(),
        }),
    );
    report.set(
        "decisions",
        json!(
            turns
                .iter()
                .map(|t| t
                    .decisions
                    .iter()
                    .map(|(tool, d)| json!([tool, d]))
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>()
        ),
    );
    report.set(
        "deviations",
        json!(["argv places --print before -- and the protocol flags after it"]),
    );
    report.set(
        "uncovered",
        json!(if isolation == "config_dir" {
            Vec::<&str>::new()
        } else {
            vec!["G4 needs the config_dir isolation"]
        }),
    );
    println!(
        "real recheck report written; gates G1..G6 = {} {} {} {} {} {}",
        pass(version.is_some()),
        pass(g2),
        pass(g3),
        pass(g4_ok),
        pass(g5),
        pass(g6)
    );
    recheck.driver.shutdown().await;
    let Recheck {
        _fixture: fixture,
        client,
        ..
    } = recheck;
    drop(client);
    session.close().await;
    fixture.stop().await;
}
