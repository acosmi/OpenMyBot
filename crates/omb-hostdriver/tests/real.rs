//! Layer-2 recheck against the real CrabCode binary of this machine. Ignored: the controller runs
//! it once the isolation mode is chosen. Inputs (all required unless noted):
//! `OMB_REAL_CRABCODE_BIN`, `OMB_REAL_RECHECK_SANDBOX` (a fresh directory under `$HOME`),
//! `OMB_REAL_RECHECK_ISOLATION` (`home` | `config_dir` | `bare`), `OMB_REAL_RECHECK_WINDOW`
//! (`inject`, the default, or `embedded`), `OMB_REAL_RECHECK_REPORT` (inside the sandbox) and
//! `OMB_TEST_PG_BIN_DIR`. `config_dir` points `CRABCODE_CONFIG_DIR` at
//! `<sandbox>/crabcode-config`; `bare` adds `--bare` and passes `ACOSMI_API_KEY` from this
//! process's environment. The report holds no absolute path and no credential.
use omb_hostdriver::{HostDriver, HostDriverConfig, Limits, VersionWindow, WorkspaceRoots};
use omb_store::{
    Decision, migrate,
    testkit::{Fixture, deadline, decide, insert_event_for_run, insert_sender_in},
};
use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderExtensionKey, ProviderMessage, ProviderMessageRole,
    ProviderRequest, ProviderRoute, StopOutcome,
};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
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

/// What one run produced.
#[derive(Default)]
struct Turn {
    init: bool,
    terminal: Option<String>,
    decisions: Vec<(String, String)>,
    stop: Option<String>,
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
    /// decision interface with `policy(tool, input summary)`; `stop_after` asks for a stop once
    /// the first text arrives.
    async fn turn(
        &self,
        binding: Uuid,
        run: &str,
        thread: &str,
        prompt: &str,
        policy: impl Fn(&str, &str) -> Decision,
        stop_after_text: bool,
    ) -> Turn {
        insert_event_for_run(&self.client, binding, run, thread, "dispatched").await;
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
                        turn.init |= matches!(event, ProviderEvent::ResponseStarted { .. });
                        let text = matches!(event, ProviderEvent::TextDelta { .. });
                        let done = matches!(event, ProviderEvent::Completed | ProviderEvent::Failed(_));
                        if done {
                            turn.terminal = Some(name);
                            return turn;
                        }
                        if stop_after_text && text {
                            let outcome = session.request_stop().await.unwrap();
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
                    assert!(tokio::time::Instant::now() < limit, "turn deadline");
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
    let (extra_args, extra_env): (Vec<String>, BTreeMap<String, String>) = match isolation.as_str()
    {
        "home" => (Vec::new(), BTreeMap::new()),
        "config_dir" => (
            Vec::new(),
            BTreeMap::from([(
                "CRABCODE_CONFIG_DIR".to_owned(),
                sandbox.join("crabcode-config").to_str().unwrap().to_owned(),
            )]),
        ),
        "bare" => (
            vec!["--bare".to_owned()],
            BTreeMap::from([("ACOSMI_API_KEY".to_owned(), required("ACOSMI_API_KEY"))]),
        ),
        other => panic!("OMB_REAL_RECHECK_ISOLATION {other} is not home, config_dir or bare"),
    };
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

    // G1: the version line under the run's minimal environment.
    let mut path = std::ffi::OsString::from("/usr/bin:/bin:/usr/sbin:/sbin:");
    path.push(binary.parent().unwrap());
    let probe = std::process::Command::new(&binary)
        .arg("--version")
        .env_clear()
        .env("PATH", path)
        .env("HOME", &home)
        .env("LANG", "en_US.UTF-8")
        .env("TERM", "dumb")
        .envs(&extra_env)
        .current_dir(&sandbox)
        .output()
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
    let window = match window_mode.as_str() {
        "inject" => VersionWindow::parse(
            &json!({"accepted": [{
                "version": version.clone().unwrap_or_default(),
                "extra_args": extra_args,
                "extra_env": extra_env,
                "gates": {"G1": "pass", "G2": "pass", "G3": "pass", "G4": "pass", "G5": "pass", "G6": "pass"},
                "verified_at": "1970-01-01T00:00:00Z",
                "engine_commit": engine_commit,
                "record": format!("compat/crabcode/{}.md", version.clone().unwrap_or_default()),
            }]})
            .to_string(),
        )
        .unwrap(),
        "embedded" => VersionWindow::embedded(),
        other => panic!("OMB_REAL_RECHECK_WINDOW {other} is not inject or embedded"),
    };

    let mut suffix = [0; 4];
    getrandom::fill(&mut suffix).unwrap();
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let workspace = sandbox.join(format!("ws-{suffix}"));
    let permissive = sandbox.join(format!("ws-g4-{suffix}"));
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(permissive.join(".crabcode")).unwrap();
    std::fs::write(
        workspace.join("notes.txt"),
        "The sandbox note says: rivers.\n",
    )
    .unwrap();
    // G4: the workspace itself allows every tool; the gate holds only if the host still asks.
    std::fs::write(
        permissive.join(".crabcode/settings.json"),
        json!({"permissions": {"defaultMode": "acceptEdits", "allow": ["Read", "Write", "Edit", "Bash"]}}).to_string(),
    )
    .unwrap();
    let tmp = sandbox.join(format!("tmp-{suffix}"));
    std::fs::create_dir_all(&tmp).unwrap();

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

    // G4: a workspace that allows every tool still routes the write through the host.
    let fourth = recheck
        .turn(g4, "real-g4", "T-g4", "Use the Write tool to create g4.txt containing the word four. Then reply with the word DONE.", deny_all, false)
        .await;
    let g4_asked = recheck
        .permissions("real-g4")
        .await
        .iter()
        .any(|p| p["tool_name"] == "Write");
    let g4_absent = !permissive.join("g4.txt").exists();

    // Step 6 / G5: a second turn stopped mid-way.
    let stopped = recheck
        .turn(main, "real-stop", "T-stop", "Count from 1 to 300, writing each number on its own line with a short sentence about it.", deny_all, true)
        .await;
    let stop_row = recheck.row("real-stop").await;
    let group_empty = stop_row["pgid"].as_i64().is_some_and(|pgid| {
        rustix::process::test_kill_process_group(
            rustix::process::Pid::from_raw(pgid as i32).unwrap(),
        ) == Err(rustix::io::Errno::SRCH)
    });

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

    let pass = |ok: bool| if ok { "pass" } else { "fail" };
    let g2 = first.init && first_row["native_session_id"].is_string();
    let g3 = write_asked_first && denied_absent && write_asked_second && allowed_present;
    let g4_ok = g4_asked && g4_absent;
    let g5 = stopped.stop.as_deref() == Some("confirmed") && group_empty;
    let g6 = resume_row["resumed_from"].is_string()
        && resume_row["resumed_from"] == first_row["native_session_id"]
        && resume_row["end_reason"] == "result_success";
    let turns = [&first, &second, &fourth, &stopped, &sixth];
    let mut all_permissions = Vec::new();
    for run in ["real-1", "real-2", "real-g4", "real-stop", "real-resume"] {
        all_permissions.extend(recheck.permissions(run).await);
    }
    let rows = [&first_row, &second_row, &recheck.row("real-g4").await, &stop_row, &resume_row]
        .iter()
        .map(|row| json!({"end_reason": row["end_reason"], "exit_code": row["exit_code"], "exit_signal": row["exit_signal"], "stop_outcome": row["stop_outcome"], "resumed_from_g2": row["resumed_from"] == first_row["native_session_id"] && row["resumed_from"].is_string()}))
        .collect::<Vec<_>>();
    let report = json!({
        "version_line": version_line,
        "version": version,
        "binary_sha256": binary_sha256,
        "build_id": build_id,
        "isolation": isolation,
        "window": window_mode,
        "extra_args": extra_args,
        "extra_env": report_env,
        "engine_commit": engine_commit,
        "gates": {
            "G1": {"result": pass(version.is_some()), "observation": version_line},
            "G2": {"result": pass(g2), "observation": {"system_init": first.init}},
            "G3": {"result": pass(g3), "observation": {"write_requested_then_denied": write_asked_first, "no_file_after_deny": denied_absent, "write_requested_then_allowed": write_asked_second, "file_after_allow": allowed_present}},
            "G4": {"result": pass(g4_ok), "observation": {"write_requested": g4_asked, "no_file_after_deny": g4_absent, "workspace_settings_permissive": true, "user_settings_permissive": "not written by the harness"}},
            "G5": {"result": pass(g5), "observation": {"request_stop": stopped.stop, "process_group_empty": group_empty, "exit_code": stop_row["exit_code"], "exit_signal": stop_row["exit_signal"]}},
            "G6": {"result": pass(g6), "observation": {"resumed_from_matches_g2": resume_row["resumed_from"] == first_row["native_session_id"], "end_reason": resume_row["end_reason"]}},
        },
        "steps": [
            {"step": "start", "init": first.init, "terminal": first.terminal},
            {"step": "readonly_auto_allow", "read_via_can_use_tool": read_requested, "readonly_rule_rows": readonly_rows, "note": if read_requested { "observed through can_use_tool" } else { "CLI allowed internally, not through can_use_tool" }},
            {"step": "approval_required_tool_blocked", "write_requested": write_asked_first, "denied": denied_absent},
            {"step": "allow", "write_requested": write_asked_second, "file_written": allowed_present},
            {"step": "terminal", "terminal": second.terminal, "end_reason": second_row["end_reason"]},
            {"step": "second_turn_stopped", "request_stop": stopped.stop, "process_group_empty": group_empty},
        ],
        "counts": {
            "system_init": turns.iter().filter(|t| t.init).count(),
            "can_use_tool": all_permissions.len(),
            "readonly_allowed": all_permissions.iter().filter(|p| p["decided_via"] == "readonly_rule").count(),
            "allowed": all_permissions.iter().filter(|p| p["decision"] == "allow" && p["decided_via"] == "cli").count(),
            "denied": all_permissions.iter().filter(|p| p["decision"] == "deny").count(),
            "result": turns.iter().filter(|t| t.terminal.as_deref().is_some_and(|e| e == "Completed" || e.starts_with("Failed"))).count(),
        },
        "rows": rows,
        "decisions": turns.iter().map(|t| t.decisions.iter().map(|(tool, d)| json!([tool, d])).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "deviations": ["argv places --print before -- and the protocol flags after it"],
        "uncovered": ["user-level permissive settings for G4 are not written by the harness"],
    });
    let text = relative(
        &serde_json::to_string_pretty(&report).unwrap(),
        &sandbox,
        &home,
    );
    assert!(!text.contains(home.to_str().unwrap()));
    std::fs::write(&report_path, text).unwrap();
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
