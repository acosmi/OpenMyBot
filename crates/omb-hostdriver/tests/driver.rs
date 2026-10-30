//! Driver start, version window, spawn and the event mapping against the in-repository fake.
/// Own PostgreSQL 17.11, a temporary home with one workspace root, and the in-repository fake.
#[allow(
    dead_code,
    unused_imports,
    reason = "shared harness copy; each target uses a subset"
)]
mod harness {
    pub use omb_hostdriver::{HostDriver, HostDriverConfig, Limits, VersionWindow, WorkspaceRoots};
    pub use omb_store::{
        Decided, Decision, migrate,
        testkit::{
            Fixture, Session, deadline, decide, insert_event_for_run, insert_host_binding,
            insert_sender_in, set_terminal,
        },
    };
    pub use openbot_application::{
        ProviderAdapter, ProviderEvent, ProviderExtensionKey, ProviderFailure, ProviderMessage,
        ProviderMessageRole, ProviderOutputKind, ProviderPortError, ProviderRequest, ProviderRoute,
        ProviderSession, ProviderUsage, StopOutcome,
    };
    pub use serde_json::{Value, json};
    pub use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };
    pub use uuid::Uuid;

    pub const FAKE: &str = env!("CARGO_BIN_EXE_fake-crabcode");

    pub struct Env {
        pub fixture: Fixture,
        pub session: Session,
        pub store: Arc<tokio_postgres::Client>,
        pub store_driver: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
        pub home: PathBuf,
        pub workspace: PathBuf,
        pub report: PathBuf,
    }
    impl Env {
        pub async fn new() -> Self {
            let mut fixture = Fixture::new().await;
            let mut session = fixture.connect().await;
            migrate(&mut session.client, deadline()).await.unwrap();
            let (client, store_driver) = fixture.open().await;
            let mut bytes = [0; 8];
            getrandom::fill(&mut bytes).unwrap();
            let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let home = std::env::temp_dir().join(format!("omb-hd-{suffix}"));
            std::fs::create_dir_all(home.join("ws")).unwrap();
            let home = std::fs::canonicalize(home).unwrap();
            Self {
                fixture,
                session,
                store: Arc::new(client),
                store_driver,
                workspace: home.join("ws"),
                report: home.join("report.jsonl"),
                home,
            }
        }
        pub fn client(&self) -> &tokio_postgres::Client {
            &self.session.client
        }
        pub async fn stop(self) {
            self.store_driver.abort();
            let _ = self.store_driver.await;
            self.session.close().await;
            self.fixture.stop().await;
            std::fs::remove_dir_all(&self.home).unwrap();
        }
        /// One accepted entry `1.1.16`; the fake prints `version` and plays `scenario`.
        pub fn window_with(
            &self,
            version: &str,
            scenario: &str,
            extra_args: &[&str],
            extra: &[(&str, &str)],
        ) -> VersionWindow {
            let mut env = BTreeMap::from([
                ("FAKE_CRABCODE_SCENARIO".to_owned(), scenario.to_owned()),
                ("FAKE_CRABCODE_VERSION".to_owned(), version.to_owned()),
                (
                    "FAKE_CRABCODE_REPORT".to_owned(),
                    self.report.to_str().unwrap().to_owned(),
                ),
            ]);
            env.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
            VersionWindow::parse(
                &json!({"accepted": [{
                    "version": "1.1.16",
                    "extra_args": extra_args,
                    "extra_env": env,
                    "gates": {"G1": "pass", "G2": "pass", "G3": "pass", "G4": "pass", "G5": "pass", "G6": "pass"},
                    "verified_at": "2026-10-28T00:00:00Z",
                    "engine_commit": "0123456789abcdef0123456789abcdef01234567",
                    "record": "compat/crabcode/1.1.16.md"
                }]})
                .to_string(),
            )
            .unwrap()
        }
        pub fn window(&self, scenario: &str, extra: &[(&str, &str)]) -> VersionWindow {
            self.window_with("1.1.16", scenario, &[], extra)
        }
        pub fn config(&self, window: VersionWindow, limits: Limits) -> HostDriverConfig {
            HostDriverConfig {
                binary: Some(PathBuf::from(FAKE)),
                home: self.home.clone(),
                tmp_dir: self.home.clone(),
                roots: WorkspaceRoots::parse(&self.home, std::slice::from_ref(&self.workspace))
                    .unwrap(),
                window,
                limits,
            }
        }
        pub fn driver(&self, window: VersionWindow, limits: Limits) -> HostDriver {
            HostDriver::new(self.config(window, limits), Arc::clone(&self.store))
        }
        pub async fn host(&self) -> Uuid {
            insert_host_binding(self.client(), self.workspace.to_str().unwrap()).await
        }
        pub async fn sender(&self, channel: &str, thread: &str) -> Uuid {
            insert_sender_in(
                self.client(),
                channel,
                "1001",
                &format!("{channel}:42"),
                thread,
                self.workspace.to_str().unwrap(),
            )
            .await
        }
        pub async fn event(&self, binding: Uuid, run: &str, thread: &str) -> Uuid {
            insert_event_for_run(self.client(), binding, run, thread, "dispatched").await
        }
        pub async fn row(&self, run: &str) -> Value {
            self.client()
                .query_one("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='session' AND run_id=$1", &[&run])
                .await
                .unwrap()
                .get(0)
        }
        pub async fn permissions(&self, run: &str) -> Vec<Value> {
            self.client()
                .query("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='permission' AND run_id=$1 ORDER BY requested_at,native_request_id", &[&run])
                .await
                .unwrap()
                .iter()
                .map(|row| row.get(0))
                .collect()
        }
        /// Waits until `count` permission rows of the run exist.
        pub async fn requested(&self, run: &str, count: usize) -> Vec<Value> {
            eventually(async || {
                let rows = self.permissions(run).await;
                (rows.len() >= count).then_some(rows)
            })
            .await
        }
        pub fn observed(&self) -> Vec<Value> {
            observed(&self.report)
        }
    }
    pub fn observed(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    /// The fake's observations of one kind.
    pub fn of(observations: &[Value], event: &str) -> Vec<Value> {
        observations
            .iter()
            .filter(|o| o["event"] == event)
            .cloned()
            .collect()
    }
    /// Frames the fake read from stdin.
    pub fn stdin(observations: &[Value]) -> Vec<Value> {
        of(observations, "stdin")
            .into_iter()
            .map(|o| o["frame"].clone())
            .collect()
    }
    pub async fn eventually<T>(mut probe: impl AsyncFnMut() -> Option<T>) -> T {
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(value) = probe().await {
                return value;
            }
            assert!(tokio::time::Instant::now() < limit, "condition deadline");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    pub fn request(binding: Uuid) -> ProviderRequest {
        let user = |content: String| ProviderMessage {
            role: ProviderMessageRole::User,
            content,
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        };
        ProviderRequest {
            route: ProviderRoute::Extension(ProviderExtensionKey::new("crabcode").unwrap()),
            messages: vec![
                user(format!("[omb-binding {binding}]\ntemplate")),
                user("material".into()),
            ],
            tools: Vec::new(),
            max_output_tokens: None,
            rate_card: None,
            cost_cap: None,
        }
    }
    pub async fn start(
        driver: &HostDriver,
        binding: Uuid,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        driver.adapter().start(request(binding)).await
    }
    pub fn is_terminal(event: &ProviderEvent) -> bool {
        matches!(event, ProviderEvent::Completed | ProviderEvent::Failed(_))
    }
    /// Events up to and including the terminal one.
    pub async fn terminal(session: &mut Box<dyn ProviderSession>) -> Vec<ProviderEvent> {
        let mut events = Vec::new();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(60), session.next_event())
                .await
                .expect("terminal deadline")
                .unwrap()
                .expect("stream ended before a terminal");
            let done = is_terminal(&event);
            events.push(event);
            if done {
                return events;
            }
        }
    }
    pub async fn started(session: &mut Box<dyn ProviderSession>) {
        let event = tokio::time::timeout(Duration::from_secs(30), session.next_event())
            .await
            .expect("init deadline")
            .unwrap()
            .unwrap();
        assert!(
            matches!(event, ProviderEvent::ResponseStarted { .. }),
            "{event:?}"
        );
    }
    /// Short budgets for the stop ladder and the permission poll.
    pub fn quick() -> Limits {
        Limits {
            stop_grace: Duration::from_secs(2),
            term_grace: Duration::from_secs(1),
            kill_grace: Duration::from_secs(1),
            permission_poll: Duration::from_millis(50),
            ..Limits::default()
        }
    }
    pub fn pid_of(row: &Value) -> rustix::process::Pid {
        rustix::process::Pid::from_raw(row["pgid"].as_i64().unwrap() as i32).unwrap()
    }
    pub fn group_gone(pgid: rustix::process::Pid) -> bool {
        rustix::process::test_kill_process_group(pgid) == Err(rustix::io::Errno::SRCH)
    }
    pub fn process_gone(pid: i64) -> bool {
        rustix::process::test_kill_process(rustix::process::Pid::from_raw(pid as i32).unwrap())
            == Err(rustix::io::Errno::SRCH)
    }
}
use harness::*;

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn version_outside_window_is_unavailable_and_child_receives_no_input() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window_with("1.1.15", "happy", &[], &[]), quick());
    assert_eq!(
        start(&driver, binding).await.err(),
        Some(ProviderPortError::Unavailable)
    );
    let observed = env.observed();
    let starts = of(&observed, "start");
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0]["argv"], json!([FAKE, "--version"]));
    assert!(stdin(&observed).is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn version_rejected_writes_session_row_with_end_reason() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window_with("2.0.0", "happy", &[], &[]), quick());
    assert!(start(&driver, binding).await.is_err());
    let row = env.row("r1").await;
    assert_eq!(row["end_reason"], "version_rejected");
    assert!(row["ended_at"].is_string());
    for column in [
        "host_version",
        "child_pid",
        "pgid",
        "init_at",
        "args_sha256",
    ] {
        assert!(row[column].is_null(), "{column}");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn retry_after_rejection_updates_the_same_session_row() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let rejecting = env.driver(env.window_with("1.1.15", "happy", &[], &[]), quick());
    for _ in 0..3 {
        assert_eq!(
            start(&rejecting, binding).await.err(),
            Some(ProviderPortError::Unavailable)
        );
    }
    let rejected = env.row("r1").await;
    assert_eq!(rejected["end_reason"], "version_rejected");
    let accepting = env.driver(env.window("happy", &[]), quick());
    let mut session = start(&accepting, binding).await.unwrap();
    let running = env.row("r1").await;
    assert_eq!(running["record_id"], rejected["record_id"]);
    assert!(running["end_reason"].is_null() && running["ended_at"].is_null());
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    let row = env.row("r1").await;
    assert_eq!(row["record_id"], rejected["record_id"]);
    assert_eq!(row["end_reason"], "result_success");
    let count: i64 = env
        .client()
        .query_one(
            "SELECT count(*) FROM openmybot.host_driver_sessions WHERE run_id='r1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn version_probe_uses_run_environment_cwd_and_extra_env() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("happy", &[("PROBE_MARK", "same")]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    terminal(&mut session).await;
    let starts = of(&env.observed(), "start");
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[0]["argv"], json!([FAKE, "--version"]));
    assert_eq!(starts[0]["env"], starts[1]["env"]);
    assert_eq!(starts[0]["env"]["PROBE_MARK"], "same");
    assert_eq!(starts[0]["cwd"], starts[1]["cwd"]);
    assert_eq!(starts[0]["cwd"], env.workspace.to_str().unwrap());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn child_receives_argv_with_double_dash_then_flags() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(
        env.window_with("1.1.16", "happy", &["--verbose"], &[]),
        quick(),
    );
    let mut session = start(&driver, binding).await.unwrap();
    terminal(&mut session).await;
    let starts = of(&env.observed(), "start");
    assert_eq!(
        starts[1]["argv"],
        json!([
            FAKE,
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
            "--verbose"
        ])
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn missing_binary_or_forbidden_extra_args_are_spawn_failed_without_child() {
    let env = Env::new().await;
    let binding = env.host().await;
    let first = env.event(binding, "r1", "TH").await;
    let missing = HostDriver::new(
        HostDriverConfig {
            binary: None,
            ..env.config(env.window("happy", &[]), quick())
        },
        Arc::clone(&env.store),
    );
    assert_eq!(
        start(&missing, binding).await.err(),
        Some(ProviderPortError::Unavailable)
    );
    let row = env.row("r1").await;
    assert_eq!(row["end_reason"], "spawn_failed");
    assert!(row["child_pid"].is_null() && row["host_version"].is_null());
    assert!(env.observed().is_empty());
    set_terminal(env.client(), first, "failed").await;
    env.event(binding, "r2", "TH").await;
    let forbidden = env.driver(
        env.window_with("1.1.16", "happy", &["--allowedTools", "Write"], &[]),
        quick(),
    );
    assert_eq!(
        start(&forbidden, binding).await.err(),
        Some(ProviderPortError::Unavailable)
    );
    let row = env.row("r2").await;
    assert_eq!(row["end_reason"], "spawn_failed");
    assert!(row["child_pid"].is_null() && row["pgid"].is_null());
    // Only the version probe ran; no run child was created.
    let starts = of(&env.observed(), "start");
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0]["argv"], json!([FAKE, "--version"]));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn workspace_outside_roots_at_spawn_is_refused() {
    let env = Env::new().await;
    let inside = env.workspace.join("real");
    let outside = env.home.join("outside");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let link = env.workspace.join("link");
    std::os::unix::fs::symlink(&inside, &link).unwrap();
    let binding = insert_host_binding(env.client(), link.to_str().unwrap()).await;
    let first = env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("happy", &[]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    terminal(&mut session).await;
    assert_eq!(
        of(&env.observed(), "start")[1]["cwd"],
        inside.to_str().unwrap()
    );
    set_terminal(env.client(), first, "succeeded").await;
    // The symlink now points outside every root; the start re-checks its real path.
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    env.event(binding, "r2", "TH").await;
    assert_eq!(
        start(&driver, binding).await.err(),
        Some(ProviderPortError::Unavailable)
    );
    assert_eq!(env.row("r2").await["end_reason"], "spawn_failed");
    assert_eq!(of(&env.observed(), "start").len(), 2);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn fourth_start_is_unavailable_while_three_children_live() {
    let env = Env::new().await;
    let host = env.host().await;
    let telegram = env.sender("telegram", "T1").await;
    let feishu = env.sender("feishu", "T2").await;
    let first = env.event(host, "r1", "TH").await;
    env.event(host, "r4", "TH").await;
    env.event(telegram, "r2", "T1").await;
    env.event(feishu, "r3", "T2").await;
    let driver = env.driver(env.window("cooperative", &[]), quick());
    let mut live = Vec::new();
    for binding in [host, telegram, feishu] {
        let mut session = start(&driver, binding).await.unwrap();
        started(&mut session).await;
        live.push(session);
    }
    // The host binding's next run is r4 once r1 carries a terminal.
    set_terminal(env.client(), first, "succeeded").await;
    assert_eq!(
        start(&driver, host).await.err(),
        Some(ProviderPortError::Unavailable)
    );
    let refused = env.row("r4").await;
    assert_eq!(refused["end_reason"], "spawn_failed");
    assert!(refused["child_pid"].is_null());
    let mut stopped = live.remove(1);
    assert!(matches!(
        stopped.request_stop().await.unwrap(),
        StopOutcome::Confirmed { .. }
    ));
    let mut session = start(&driver, host).await.unwrap();
    started(&mut session).await;
    assert!(env.row("r4").await["end_reason"].is_null());
    live.push(session);
    for mut session in live {
        session.request_stop().await.unwrap();
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn happy_turn_maps_to_closed_event_sequence_and_result_success_row() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("happy", &[]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    assert_eq!(
        terminal(&mut session).await,
        vec![
            ProviderEvent::ResponseStarted {
                response_id: "fake-session-1".into()
            },
            ProviderEvent::OutputItemAdded {
                index: 0,
                kind: ProviderOutputKind::Message
            },
            ProviderEvent::TextDelta {
                index: 0,
                delta: "hello from fake".into()
            },
            ProviderEvent::Usage(ProviderUsage {
                input_tokens: 11,
                output_tokens: 7,
                total_tokens: 18
            }),
            ProviderEvent::Completed,
        ]
    );
    assert_eq!(session.next_event().await, Ok(None));
    let row = env.row("r1").await;
    assert_eq!(row["end_reason"], "result_success");
    assert_eq!(row["host_kind"], "crabcode");
    assert_eq!(row["host_version"], "1.1.16");
    assert_eq!(row["native_session_id"], "fake-session-1");
    assert_eq!(row["result_summary"], "hello from fake");
    assert_eq!(row["resumable"], true);
    assert_eq!(row["workspace_dir"], env.workspace.to_str().unwrap());
    assert_eq!(row["child_pid"], row["pgid"]);
    assert!(
        row["args_sha256"].is_string() && row["init_at"].is_string() && row["ended_at"].is_string()
    );
    assert!(row["last_event_seq"].as_i64().unwrap() >= 4);
    assert!(row["output_bytes"].as_i64().unwrap() > 0);
    assert!(row["exit_code"] == 0 || row["exit_signal"] == 15, "{row}");
    assert!(row["stop_outcome"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn child_runs_in_own_process_group_with_workspace_cwd_and_closed_environment() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("happy", &[]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    terminal(&mut session).await;
    let run = of(&env.observed(), "start")[1].clone();
    assert_eq!(run["pid"], run["pgid"]);
    let own = rustix::process::getpgid(None)
        .unwrap()
        .as_raw_nonzero()
        .get();
    assert_ne!(run["pgid"], own);
    assert_eq!(env.row("r1").await["pgid"], run["pgid"]);
    assert_eq!(run["cwd"], env.workspace.to_str().unwrap());
    let fake_dir = Path::new(FAKE).parent().unwrap().to_str().unwrap();
    assert_eq!(
        run["env"],
        json!({
            "PATH": format!("/usr/bin:/bin:/usr/sbin:/sbin:{fake_dir}"),
            "HOME": env.home.to_str().unwrap(),
            "LANG": "en_US.UTF-8",
            "TERM": "dumb",
            "TMPDIR": env.home.to_str().unwrap(),
            "OPENMYBOT_HOST_DRIVER_CHILD": "1",
            "FAKE_CRABCODE_SCENARIO": "happy",
            "FAKE_CRABCODE_VERSION": "1.1.16",
            "FAKE_CRABCODE_REPORT": env.report.to_str().unwrap(),
        })
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn initialize_and_user_frames_have_closed_shapes() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("happy", &[]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    terminal(&mut session).await;
    let frames = stdin(&env.observed());
    assert_eq!(
        frames[0],
        json!({"type":"control_request","request_id":"omb-initialize","request":{"subtype":"initialize"}})
    );
    assert_eq!(
        frames[1],
        json!({"type":"user","message":{"role":"user","content":"template\n\nmaterial"}})
    );
    assert_eq!(frames.len(), 2);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn hook_elicitation_and_mcp_requests_are_refused_with_codes() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("requests", &[]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    let answers: BTreeMap<String, Value> = stdin(&env.observed())
        .into_iter()
        .filter(|frame| frame["type"] == "control_response")
        .map(|frame| {
            (
                frame["response"]["request_id"].as_str().unwrap().to_owned(),
                frame["response"].clone(),
            )
        })
        .collect();
    for (id, code) in [
        ("h1", "hook_callback_refused"),
        ("e1", "elicitation_refused"),
        ("m1", "sdk_mcp_refused"),
        ("s1", "subtype_unsupported"),
    ] {
        assert_eq!(
            answers[id],
            json!({"subtype":"error","request_id":id,"error":code})
        );
    }
    assert!(env.permissions("r1").await.is_empty());
    env.stop().await;
}

/// Runs one scenario to its terminal and returns the events and the session row.
async fn failing(
    scenario: &str,
    limits: Limits,
    extra: &[(&str, &str)],
) -> (Env, Vec<ProviderEvent>, Value) {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window(scenario, extra), limits);
    let mut session = start(&driver, binding).await.unwrap();
    let events = terminal(&mut session).await;
    let row = env.row("r1").await;
    assert!(group_gone(pid_of(&row)), "child reaped before the terminal");
    (env, events, row)
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn init_timeout_stops_then_fails_invalid_response() {
    let limits = Limits {
        init_timeout: Duration::from_millis(500),
        stop_grace: Duration::from_millis(200),
        ..quick()
    };
    let (env, events, row) = failing("no_init", limits, &[]).await;
    assert_eq!(
        events,
        vec![ProviderEvent::Failed(ProviderFailure::InvalidResponse)]
    );
    assert_eq!(row["end_reason"], "init_timeout");
    assert!(row["init_at"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn non_json_output_stops_then_fails_invalid_response() {
    let limits = Limits {
        stop_grace: Duration::from_millis(200),
        ..quick()
    };
    let (env, events, row) = failing("non_json", limits, &[]).await;
    assert_eq!(
        events,
        vec![
            ProviderEvent::ResponseStarted {
                response_id: "fake-session-1".into()
            },
            ProviderEvent::Failed(ProviderFailure::InvalidResponse)
        ]
    );
    assert_eq!(row["end_reason"], "protocol_error");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn exit_before_result_fails_transport_with_child_exited() {
    let (env, events, row) = failing("exit_early", quick(), &[]).await;
    assert_eq!(
        events.last(),
        Some(&ProviderEvent::Failed(ProviderFailure::Transport))
    );
    assert!(!events.contains(&ProviderEvent::Completed));
    assert_eq!(row["end_reason"], "child_exited");
    assert_eq!(row["exit_code"], 3);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn result_error_fails_generation_failed() {
    let (env, events, row) = failing("result_error", quick(), &[]).await;
    assert_eq!(
        events,
        vec![
            ProviderEvent::ResponseStarted {
                response_id: "fake-session-1".into()
            },
            ProviderEvent::Failed(ProviderFailure::GenerationFailed)
        ]
    );
    assert_eq!(row["end_reason"], "result_error");
    assert!(row["resumable"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn silence_without_permission_stops_then_fails_stream_stalled() {
    let limits = Limits {
        stall: Duration::from_millis(500),
        stop_grace: Duration::from_millis(200),
        ..quick()
    };
    let started = std::time::Instant::now();
    let (env, events, row) = failing("silence", limits, &[]).await;
    assert!(started.elapsed() >= Duration::from_millis(500));
    assert_eq!(
        events.last(),
        Some(&ProviderEvent::Failed(ProviderFailure::StreamStalled))
    );
    assert_eq!(row["end_reason"], "stalled");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn permission_wait_does_not_count_toward_stall() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let limits = Limits {
        stall: Duration::from_millis(300),
        ..quick()
    };
    let driver = env.driver(
        env.window(
            "permission",
            &[(
                "FAKE_CRABCODE_INPUT",
                r#"{"file_path":"w.txt","content":"w"}"#,
            )],
        ),
        limits,
    );
    let mut session = start(&driver, binding).await.unwrap();
    let rows = env.requested("r1", 1).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let id = rows[0]["permission_id"].as_str().unwrap();
    assert_eq!(
        decide(env.client(), id, Decision::Allow).await,
        Decided::Decided
    );
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    assert_eq!(env.row("r1").await["end_reason"], "result_success");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn store_write_failure_stops_the_session_and_fails_transport() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(
        env.window("permission", &[("FAKE_CRABCODE_DELAY_MS", "1000")]),
        quick(),
    );
    let mut session = start(&driver, binding).await.unwrap();
    started(&mut session).await;
    let pgid = pid_of(&env.row("r1").await);
    // The driver's own store connection ends; the next session write fails.
    env.store_driver.abort();
    let events = terminal(&mut session).await;
    assert_eq!(
        events,
        vec![ProviderEvent::Failed(ProviderFailure::Transport)]
    );
    assert!(group_gone(pgid));
    assert_eq!(session.next_event().await, Ok(None));
    let row = env.row("r1").await;
    assert!(row["end_reason"].is_null() && row["ended_at"].is_null());
    assert!(env.permissions("r1").await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn session_progress_records_seq_and_output_bytes_without_counter_columns() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("permission", &[]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    started(&mut session).await;
    let at_init = env.row("r1").await;
    // The initialize acknowledgement and `system/init` are the parsed objects so far.
    assert_eq!(at_init["last_event_seq"], 2);
    let rows = env.requested("r1", 1).await;
    let at_request = env.row("r1").await;
    assert_eq!(at_request["last_event_seq"], 3);
    assert!(at_request["output_bytes"].as_i64() > at_init["output_bytes"].as_i64());
    decide(
        env.client(),
        rows[0]["permission_id"].as_str().unwrap(),
        Decision::Deny,
    )
    .await;
    terminal(&mut session).await;
    let ended = env.row("r1").await;
    assert_eq!(ended["last_event_seq"], 5);
    assert!(ended["output_bytes"].as_i64() > at_request["output_bytes"].as_i64());
    let columns: Vec<String> = env
        .client()
        .query("SELECT column_name::text FROM information_schema.columns WHERE table_schema='openmybot' AND table_name='host_driver_sessions'", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(
        columns.iter().all(|c| !c.contains("tool_use")
            && !c.contains("tool_result")
            && !c.contains("ignored"))
    );
    env.stop().await;
}
