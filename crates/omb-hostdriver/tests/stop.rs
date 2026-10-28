//! The stop ladder, shutdown and cancellation safety against the in-repository fake.
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

/// One live run of `scenario` past its `system/init`.
async fn live(env: &Env, scenario: &str, limits: Limits) -> (HostDriver, Box<dyn ProviderSession>) {
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window(scenario, &[]), limits);
    let mut session = start(&driver, binding).await.unwrap();
    started(&mut session).await;
    (driver, session)
}
async fn stopped(env: &Env, session: &mut Box<dyn ProviderSession>) -> (StopOutcome, Value) {
    let outcome = session.request_stop().await.unwrap();
    (outcome, env.row("r1").await)
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cooperative_interrupt_is_confirmed_and_group_is_empty() {
    let env = Env::new().await;
    let (_driver, mut session) = live(&env, "cooperative", quick()).await;
    let (outcome, row) = stopped(&env, &mut session).await;
    assert!(matches!(outcome, StopOutcome::Confirmed { .. }));
    assert_eq!(row["end_reason"], "stop_requested");
    assert_eq!(row["stop_outcome"], "confirmed");
    assert!(row["stop_confirmed_at"].is_string());
    assert!(group_gone(pid_of(&row)));
    assert!(
        stdin(&env.observed())
            .iter()
            .any(|f| f["request"]["subtype"] == "interrupt")
    );
    assert_eq!(session.next_event().await, Ok(None));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn ignored_interrupt_still_ends_confirmed_after_stdin_close() {
    let env = Env::new().await;
    let limits = Limits {
        stop_grace: Duration::from_millis(300),
        ..quick()
    };
    let (_driver, mut session) = live(&env, "ignore_interrupt", limits).await;
    let (outcome, row) = stopped(&env, &mut session).await;
    assert!(matches!(outcome, StopOutcome::Confirmed { .. }));
    assert_eq!(row["stop_outcome"], "confirmed");
    assert!(group_gone(pid_of(&row)));
    assert!(of(&env.observed(), "stdin_eof").len() == 1 || row["exit_signal"] == 15);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn ignored_stdin_close_is_followed_by_sigterm_exit() {
    let env = Env::new().await;
    let limits = Limits {
        stop_grace: Duration::from_millis(300),
        ..quick()
    };
    let (_driver, mut session) = live(&env, "ignore_eof", limits).await;
    let (outcome, row) = stopped(&env, &mut session).await;
    assert!(matches!(outcome, StopOutcome::Confirmed { .. }));
    assert_eq!(row["exit_signal"], 15);
    assert!(row["exit_code"].is_null());
    assert!(group_gone(pid_of(&row)));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn ignored_sigterm_is_followed_by_sigkill() {
    let env = Env::new().await;
    let limits = Limits {
        stop_grace: Duration::from_millis(300),
        term_grace: Duration::from_millis(500),
        ..quick()
    };
    let (_driver, mut session) = live(&env, "ignore_term", limits).await;
    let (outcome, row) = stopped(&env, &mut session).await;
    assert!(matches!(outcome, StopOutcome::Confirmed { .. }));
    assert_eq!(row["exit_signal"], 9);
    assert!(!of(&env.observed(), "signal").is_empty());
    assert!(group_gone(pid_of(&row)));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn grandchild_in_same_group_is_killed_and_group_is_empty() {
    let env = Env::new().await;
    let (_driver, mut session) = live(&env, "grandchild", quick()).await;
    let descendant = of(&env.observed(), "descendant")[0]["pid"]
        .as_i64()
        .unwrap();
    assert!(!process_gone(descendant));
    let (outcome, row) = stopped(&env, &mut session).await;
    assert!(matches!(outcome, StopOutcome::Confirmed { .. }));
    assert!(group_gone(pid_of(&row)));
    assert!(process_gone(descendant));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn setsid_descendant_is_outside_confirmation() {
    let env = Env::new().await;
    let (_driver, mut session) = live(&env, "setsid", quick()).await;
    let descendant = eventually(async || {
        of(&env.observed(), "detached")
            .first()
            .map(|d| d["pid"].as_i64().unwrap())
    })
    .await;
    let (outcome, row) = stopped(&env, &mut session).await;
    // The detached descendant left the child's process group, so it does not block confirmation.
    assert!(matches!(outcome, StopOutcome::Confirmed { .. }));
    assert!(group_gone(pid_of(&row)));
    assert!(!process_gone(descendant));
    let pid = rustix::process::Pid::from_raw(descendant as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::KILL).unwrap();
    eventually(async || process_gone(descendant).then_some(())).await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stop_denies_pending_permissions_with_run_stopped_first() {
    let env = Env::new().await;
    let (_driver, mut session) = live(&env, "permission", quick()).await;
    let rows = env.requested("r1", 1).await;
    let (outcome, _) = stopped(&env, &mut session).await;
    assert!(matches!(outcome, StopOutcome::Confirmed { .. }));
    let row = &env.permissions("r1").await[0];
    assert_eq!(row["permission_id"], rows[0]["permission_id"]);
    assert_eq!(
        (row["decision"].as_str(), row["decided_via"].as_str()),
        (Some("deny"), Some("run_stopped"))
    );
    let frames = stdin(&env.observed());
    let denied = frames
        .iter()
        .position(|f| {
            f["response"]["response"] == json!({"behavior": "deny", "message": "run_stopped"})
        })
        .unwrap();
    let interrupt = frames
        .iter()
        .position(|f| f["request"]["subtype"] == "interrupt")
        .unwrap();
    assert!(denied < interrupt);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unconfirmable_stop_with_zero_grace_returns_unknown() {
    let env = Env::new().await;
    let limits = Limits {
        stop_grace: Duration::from_millis(200),
        term_grace: Duration::from_millis(200),
        kill_grace: Duration::ZERO,
        ..quick()
    };
    let (_driver, mut session) = live(&env, "ignore_term", limits).await;
    let (outcome, row) = stopped(&env, &mut session).await;
    assert_eq!(outcome, StopOutcome::Unknown);
    assert_eq!(row["end_reason"], "stop_requested");
    assert_eq!(row["stop_outcome"], "unknown");
    assert!(row["stop_confirmed_at"].is_null());
    let pgid = pid_of(&row);
    let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
    eventually(async || group_gone(pgid).then_some(())).await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stop_after_normal_completion_is_confirmed_immediately() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("happy", &[]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    assert_eq!(
        terminal(&mut session).await.last(),
        Some(&ProviderEvent::Completed)
    );
    let asked = std::time::Instant::now();
    assert!(matches!(
        session.request_stop().await.unwrap(),
        StopOutcome::Confirmed { .. }
    ));
    assert!(asked.elapsed() < Duration::from_millis(500));
    let row = env.row("r1").await;
    assert_eq!(row["end_reason"], "result_success");
    assert!(row["stop_outcome"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn dropping_the_session_reaps_the_child_in_the_background() {
    let env = Env::new().await;
    let limits = Limits {
        stop_grace: Duration::from_millis(200),
        ..quick()
    };
    let (_driver, session) = live(&env, "silence", limits).await;
    let pgid = pid_of(&env.row("r1").await);
    drop(session);
    let row = eventually(async || {
        let row = env.row("r1").await;
        row["end_reason"].is_string().then_some(row)
    })
    .await;
    assert_eq!(row["end_reason"], "stop_requested");
    assert!(row["stop_outcome"].is_null());
    assert!(group_gone(pgid));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn normal_completion_reaps_child_through_the_stop_ladder() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(env.window("happy", &[]), quick());
    let mut session = start(&driver, binding).await.unwrap();
    let events = terminal(&mut session).await;
    // Steps 3–6 ran before `Completed` was sent: the child and its group are gone already.
    assert_eq!(events.last(), Some(&ProviderEvent::Completed));
    let row = env.row("r1").await;
    assert!(group_gone(pid_of(&row)));
    assert!(row["exit_code"].is_number() || row["exit_signal"].is_number());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn shutdown_runs_ladder_steps_3_to_6_for_all_live_sessions() {
    let env = Env::new().await;
    let limits = Limits {
        stop_grace: Duration::from_millis(300),
        ..quick()
    };
    let driver = env.driver(env.window("ignore_eof", &[]), limits);
    let mut sessions = Vec::new();
    for (index, binding) in [
        env.host().await,
        env.sender("telegram", "T1").await,
        env.sender("feishu", "T2").await,
    ]
    .into_iter()
    .enumerate()
    {
        env.event(binding, &format!("r{index}"), "T").await;
        let mut session = start(&driver, binding).await.unwrap();
        started(&mut session).await;
        sessions.push(session);
    }
    let mut groups = Vec::new();
    for index in 0..3 {
        groups.push(pid_of(&env.row(&format!("r{index}")).await));
    }
    driver.shutdown().await;
    for (index, pgid) in groups.into_iter().enumerate() {
        assert!(group_gone(pgid), "r{index}");
        let row = env.row(&format!("r{index}")).await;
        assert_eq!(row["end_reason"], "stop_requested", "r{index}");
        assert_eq!(row["stop_outcome"], "confirmed", "r{index}");
    }
    drop(sessions);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn shutdown_with_no_live_session_returns_immediately() {
    let env = Env::new().await;
    let driver = env.driver(env.window("happy", &[]), quick());
    let begun = std::time::Instant::now();
    driver.shutdown().await;
    assert!(begun.elapsed() < Duration::from_millis(100));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn next_event_future_cancellation_loses_no_event() {
    let env = Env::new().await;
    let binding = env.host().await;
    env.event(binding, "r1", "TH").await;
    let driver = env.driver(
        env.window("happy", &[("FAKE_CRABCODE_DELAY_MS", "0")]),
        quick(),
    );
    let mut session = start(&driver, binding).await.unwrap();
    let mut events = Vec::new();
    loop {
        // Each read races a short timer; a cancelled read must not consume an event.
        tokio::select! {
            biased;
            () = tokio::time::sleep(Duration::from_micros(50)) => continue,
            event = session.next_event() => {
                let event = event.unwrap().unwrap();
                let done = is_terminal(&event);
                events.push(event);
                if done { break; }
            }
        }
    }
    assert_eq!(
        events,
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
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stop_and_result_racing_yield_one_terminal() {
    let env = Env::new().await;
    let binding = env.host().await;
    let mut previous = None;
    let mut seen = BTreeMap::<&str, usize>::new();
    for round in 0..10 {
        if let Some(event) = previous {
            set_terminal(env.client(), event, "succeeded").await;
        }
        let run = format!("r{round}");
        previous = Some(env.event(binding, &run, "TH").await);
        let driver = env.driver(
            env.window("slow_result", &[("FAKE_CRABCODE_DELAY_MS", "100")]),
            quick(),
        );
        let mut session = start(&driver, binding).await.unwrap();
        started(&mut session).await;
        tokio::time::sleep(Duration::from_millis(80 + 4 * round)).await;
        let outcome = session.request_stop().await.unwrap();
        assert!(
            matches!(outcome, StopOutcome::Confirmed { .. }),
            "round {round}"
        );
        let mut terminals = Vec::new();
        while let Some(event) = session.next_event().await.unwrap() {
            if is_terminal(&event) {
                terminals.push(event);
            }
        }
        let row = env.row(&run).await;
        match terminals.as_slice() {
            [] => assert_eq!(row["end_reason"], "stop_requested", "round {round}"),
            [ProviderEvent::Completed] => {
                assert_eq!(row["end_reason"], "result_success", "round {round}")
            }
            other => panic!("round {round}: {other:?}"),
        }
        *seen
            .entry(row["end_reason"].as_str().map_or("none", |r| {
                if r == "result_success" {
                    "result"
                } else {
                    "stop"
                }
            }))
            .or_default() += 1;
    }
    println!("race outcomes: {seen:?}");
    env.stop().await;
}
