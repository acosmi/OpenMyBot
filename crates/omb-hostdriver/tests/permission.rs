//! The `can_use_tool` relay against the in-repository fake.
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

/// Starts one run of `scenario` with the tool and inputs given to the fake.
async fn run_with(
    env: &Env,
    binding: Uuid,
    run: &str,
    scenario: &str,
    extra: &[(&str, &str)],
    limits: Limits,
) -> (HostDriver, Box<dyn ProviderSession>) {
    env.event(binding, run, "T1").await;
    let driver = env.driver(env.window(scenario, extra), limits);
    let session = start(&driver, binding).await.unwrap();
    (driver, session)
}
/// The control responses the fake read, keyed by request id.
fn responses(env: &Env) -> BTreeMap<String, Value> {
    stdin(&env.observed())
        .into_iter()
        .filter(|frame| frame["type"] == "control_response")
        .map(|frame| {
            (
                frame["response"]["request_id"].as_str().unwrap().to_owned(),
                frame["response"]["response"].clone(),
            )
        })
        .collect()
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn readonly_tool_inside_workspace_is_allowed_by_rule() {
    let env = Env::new().await;
    std::fs::write(env.workspace.join("a.txt"), "a").unwrap();
    let binding = env.host().await;
    let input = json!({"file_path": env.workspace.join("a.txt")}).to_string();
    let (_driver, mut session) = run_with(
        &env,
        binding,
        "r1",
        "permission",
        &[
            ("FAKE_CRABCODE_TOOL", "Read"),
            ("FAKE_CRABCODE_INPUT", &input),
        ],
        quick(),
    )
    .await;
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    let rows = env.permissions("r1").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["tool_name"], "Read");
    assert_eq!(rows[0]["decision"], "allow");
    assert_eq!(rows[0]["decided_via"], "readonly_rule");
    assert!(rows[0]["answered_at"].is_string() && rows[0]["decided_by_token"].is_null());
    assert_eq!(
        responses(&env)["req-1"],
        json!({"behavior": "allow", "updatedInput": serde_json::from_str::<Value>(&input).unwrap()})
    );
    assert!(env.row("r1").await["artifact_paths"] == json!([]));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn readonly_tool_outside_workspace_waits_for_human() {
    let env = Env::new().await;
    std::fs::write(env.home.join("secret.txt"), "s").unwrap();
    let binding = env.host().await;
    let input = json!({"file_path": env.home.join("secret.txt")}).to_string();
    let (_driver, mut session) = run_with(
        &env,
        binding,
        "r1",
        "permission",
        &[
            ("FAKE_CRABCODE_TOOL", "Read"),
            ("FAKE_CRABCODE_INPUT", &input),
        ],
        quick(),
    )
    .await;
    let rows = env.requested("r1", 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let row = &env.permissions("r1").await[0];
    assert!(row["decision"].is_null() && row["answered_at"].is_null());
    assert!(!responses(&env).contains_key("req-1"));
    decide(
        env.client(),
        rows[0]["permission_id"].as_str().unwrap(),
        Decision::Deny,
    )
    .await;
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    assert_eq!(
        responses(&env)["req-1"],
        json!({"behavior": "deny", "message": "owner_denied"})
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn write_tool_waits_then_cli_allow_sends_allow_with_original_input() {
    let env = Env::new().await;
    let binding = env.host().await;
    let input = r#"{"file_path":"out.txt","content":"data","extra":[1,2.5,{"k":null}]}"#;
    let (_driver, mut session) = run_with(
        &env,
        binding,
        "r1",
        "permission",
        &[("FAKE_CRABCODE_INPUT", input)],
        quick(),
    )
    .await;
    let rows = env.requested("r1", 1).await;
    assert_eq!(rows[0]["tool_name"], "Write");
    assert!(rows[0]["decision"].is_null());
    assert!(!env.workspace.join("out.txt").exists());
    let id = rows[0]["permission_id"].as_str().unwrap();
    assert_eq!(
        decide(env.client(), id, Decision::Allow).await,
        Decided::Decided
    );
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    assert_eq!(
        responses(&env)["req-1"],
        json!({"behavior": "allow", "updatedInput": serde_json::from_str::<Value>(input).unwrap()})
    );
    assert_eq!(
        std::fs::read_to_string(env.workspace.join("out.txt")).unwrap(),
        "data"
    );
    let row = &env.permissions("r1").await[0];
    assert_eq!(row["decided_via"], "cli");
    let ordered: bool = env
        .client()
        .query_one("SELECT answered_at>decided_at FROM openmybot.host_driver_sessions WHERE permission_id=$1", &[&id])
        .await
        .unwrap()
        .get(0);
    assert!(ordered);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cli_decision_wakes_the_wait_within_two_poll_intervals() {
    let env = Env::new().await;
    let binding = env.host().await;
    let limits = Limits {
        permission_poll: Duration::from_millis(50),
        ..quick()
    };
    let (_driver, mut session) = run_with(&env, binding, "r1", "permission", &[], limits).await;
    let rows = env.requested("r1", 1).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    let id = rows[0]["permission_id"].as_str().unwrap();
    decide(env.client(), id, Decision::Allow).await;
    let decided = std::time::Instant::now();
    eventually(async || responses(&env).contains_key("req-1").then_some(())).await;
    let elapsed = decided.elapsed();
    assert!(elapsed <= Duration::from_millis(100), "{elapsed:?}");
    terminal(&mut session).await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cli_deny_sends_owner_denied_and_no_file_is_written() {
    let env = Env::new().await;
    let binding = env.host().await;
    let (_driver, mut session) = run_with(
        &env,
        binding,
        "r1",
        "permission",
        &[(
            "FAKE_CRABCODE_INPUT",
            r#"{"file_path":"no.txt","content":"x"}"#,
        )],
        quick(),
    )
    .await;
    let rows = env.requested("r1", 1).await;
    decide(
        env.client(),
        rows[0]["permission_id"].as_str().unwrap(),
        Decision::Deny,
    )
    .await;
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    assert_eq!(
        responses(&env)["req-1"],
        json!({"behavior": "deny", "message": "owner_denied"})
    );
    assert!(!env.workspace.join("no.txt").exists());
    let row = &env.permissions("r1").await[0];
    assert_eq!(
        (row["decision"].as_str(), row["decided_via"].as_str()),
        (Some("deny"), Some("cli"))
    );
    assert!(row["answered_at"].is_string());
    assert_eq!(env.row("r1").await["artifact_paths"], json!([]));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn undecided_permission_times_out_with_permission_timeout() {
    let env = Env::new().await;
    let binding = env.host().await;
    let limits = Limits {
        permission_ttl: Duration::from_millis(400),
        ..quick()
    };
    let (_driver, mut session) = run_with(&env, binding, "r1", "permission", &[], limits).await;
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    let row = &env.permissions("r1").await[0];
    assert_eq!(
        (row["decision"].as_str(), row["decided_via"].as_str()),
        (Some("deny"), Some("timeout"))
    );
    assert!(row["decided_by_token"].is_null() && row["answered_at"].is_string());
    assert_eq!(
        responses(&env)["req-1"],
        json!({"behavior": "deny", "message": "permission_timeout"})
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn two_concurrent_requests_are_independent() {
    let mut env = Env::new().await;
    let binding = env.host().await;
    let other = env.fixture.connect().await;
    let mut previous = None;
    for round in 0..10 {
        if let Some(event) = previous {
            set_terminal(env.client(), event, "succeeded").await;
        }
        let run = format!("r{round}");
        previous = Some(env.event(binding, &run, "TH").await);
        let a = format!(r#"{{"file_path":"a{round}.txt","content":"a"}}"#);
        let b = format!(r#"{{"file_path":"b{round}.txt","content":"b"}}"#);
        let driver = env.driver(
            env.window(
                "two_permissions",
                &[("FAKE_CRABCODE_INPUT", &a), ("FAKE_CRABCODE_INPUT2", &b)],
            ),
            quick(),
        );
        let mut session = start(&driver, binding).await.unwrap();
        let rows = env.requested(&run, 2).await;
        let by_native: BTreeMap<String, String> = rows
            .iter()
            .map(|row| {
                (
                    row["native_request_id"].as_str().unwrap().to_owned(),
                    row["permission_id"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        let (first, second) = tokio::join!(
            decide(env.client(), &by_native["req-1"], Decision::Allow),
            decide(&other.client, &by_native["req-2"], Decision::Deny),
        );
        assert_eq!(
            (first, second),
            (Decided::Decided, Decided::Decided),
            "round {round}"
        );
        assert!(
            matches!(
                terminal(&mut session).await.last(),
                Some(ProviderEvent::Completed)
            ),
            "round {round}"
        );
        let answers = responses(&env);
        assert_eq!(answers["req-1"]["behavior"], "allow", "round {round}");
        assert_eq!(
            answers["req-2"],
            json!({"behavior": "deny", "message": "owner_denied"}),
            "round {round}"
        );
        assert!(
            env.workspace.join(format!("a{round}.txt")).exists(),
            "round {round}"
        );
        assert!(
            !env.workspace.join(format!("b{round}.txt")).exists(),
            "round {round}"
        );
        assert_eq!(
            env.row(&run).await["artifact_paths"],
            json!([format!("a{round}.txt")]),
            "round {round}"
        );
        std::fs::remove_file(&env.report).unwrap();
    }
    other.close().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn sender_run_permission_row_carries_notice_delivery_row() {
    let env = Env::new().await;
    let binding = env.sender("telegram", "T1").await;
    let (_driver, mut session) = run_with(&env, binding, "r1", "permission", &[], quick()).await;
    let rows = env.requested("r1", 1).await;
    let id = rows[0]["permission_id"].as_str().unwrap().to_owned();
    let delivery: Value = env
        .client()
        .query_one(
            "SELECT row_to_json(d) FROM openmybot.deliveries d WHERE idempotency_key=$1",
            &[&format!("perm:{id}")],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(delivery["kind"], "permission_notice");
    assert_eq!(delivery["chat_key"], "telegram:42");
    assert_eq!(delivery["channel_kind"], "telegram");
    assert_eq!(delivery["binding_id"], binding.to_string());
    assert_eq!(
        delivery["body"],
        format!(
            "CrabCode 请求使用工具 Write。在本机执行 openmybot approve {id} 放行，或 openmybot deny {id} 拒绝。"
        )
    );
    decide(env.client(), &id, Decision::Deny).await;
    terminal(&mut session).await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn host_run_permission_has_no_notice_delivery() {
    let env = Env::new().await;
    let binding = env.host().await;
    let (_driver, mut session) = run_with(&env, binding, "r1", "permission", &[], quick()).await;
    let rows = env.requested("r1", 1).await;
    let deliveries: i64 = env
        .client()
        .query_one("SELECT count(*) FROM openmybot.deliveries", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(deliveries, 0);
    decide(
        env.client(),
        rows[0]["permission_id"].as_str().unwrap(),
        Decision::Deny,
    )
    .await;
    terminal(&mut session).await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn artifacts_from_cli_allowed_file_paths_are_recorded() {
    let env = Env::new().await;
    std::fs::create_dir_all(env.workspace.join("docs")).unwrap();
    let binding = env.host().await;
    let (_driver, mut session) = run_with(
        &env,
        binding,
        "r1",
        "two_permissions",
        &[
            (
                "FAKE_CRABCODE_INPUT",
                r#"{"file_path":"docs/report.md","content":"r"}"#,
            ),
            (
                "FAKE_CRABCODE_INPUT2",
                r#"{"file_path":"denied.md","content":"d"}"#,
            ),
        ],
        quick(),
    )
    .await;
    let rows = env.requested("r1", 2).await;
    for row in &rows {
        let decision = if row["native_request_id"] == "req-1" {
            Decision::Allow
        } else {
            Decision::Deny
        };
        decide(
            env.client(),
            row["permission_id"].as_str().unwrap(),
            decision,
        )
        .await;
    }
    assert!(matches!(
        terminal(&mut session).await.last(),
        Some(ProviderEvent::Completed)
    ));
    assert_eq!(
        env.row("r1").await["artifact_paths"],
        json!(["docs/report.md"])
    );
    env.stop().await;
}
