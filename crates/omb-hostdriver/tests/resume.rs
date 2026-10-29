//! Session resumption across runs of one thread against the in-repository fake.
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

/// Runs one turn of the binding's earliest open run with `scenario` and marks its event done.
async fn turn(env: &Env, binding: Uuid, run: &str, scenario: &str) -> Vec<ProviderEvent> {
    let event = env.event(binding, run, "T1").await;
    let driver = env.driver(
        env.window(scenario, &[("FAKE_CRABCODE_SESSION", "s-one")]),
        quick(),
    );
    let mut session = start(&driver, binding).await.unwrap();
    let events = terminal(&mut session).await;
    set_terminal(env.client(), event, "succeeded").await;
    events
}
fn last_argv(env: &Env) -> Vec<String> {
    let starts = of(&env.observed(), "start");
    serde_json::from_value(starts.last().unwrap()["argv"].clone()).unwrap()
}
fn resumes(argv: &[String]) -> Option<&str> {
    argv.iter()
        .position(|arg| arg == "--resume")
        .map(|index| argv[index + 1].as_str())
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn second_run_in_same_thread_resumes_native_session() {
    let env = Env::new().await;
    let binding = env.sender("telegram", "T1").await;
    turn(&env, binding, "r1", "happy").await;
    assert_eq!(resumes(&last_argv(&env)), None);
    turn(&env, binding, "r2", "happy").await;
    let argv = last_argv(&env);
    assert_eq!(resumes(&argv), Some("s-one"));
    assert_eq!(
        &argv[3..11],
        [
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--permission-mode",
            "default",
            "--permission-prompt-tool",
            "stdio"
        ]
    );
    assert_eq!(env.row("r2").await["resumed_from"], "s-one");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resume_exit_before_init_is_resume_failed_and_clears_resumable() {
    let env = Env::new().await;
    let binding = env.sender("telegram", "T1").await;
    turn(&env, binding, "r1", "happy").await;
    assert_eq!(env.row("r1").await["resumable"], true);
    let events = turn(&env, binding, "r2", "exit_before_init").await;
    assert_eq!(
        events,
        vec![ProviderEvent::Failed(ProviderFailure::GenerationFailed)]
    );
    let row = env.row("r2").await;
    assert_eq!(row["end_reason"], "resume_failed");
    assert_eq!(row["resumed_from"], "s-one");
    assert_eq!(env.row("r1").await["resumable"], false);
    turn(&env, binding, "r3", "happy").await;
    assert_eq!(resumes(&last_argv(&env)), None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resume_result_error_is_resume_failed() {
    let env = Env::new().await;
    let binding = env.sender("telegram", "T1").await;
    turn(&env, binding, "r1", "happy").await;
    let events = turn(&env, binding, "r2", "result_error").await;
    assert_eq!(
        events.last(),
        Some(&ProviderEvent::Failed(ProviderFailure::GenerationFailed))
    );
    assert_eq!(env.row("r2").await["end_reason"], "resume_failed");
    assert_eq!(env.row("r1").await["resumable"], false);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resumed_run_success_sets_resumable_on_the_new_row() {
    let env = Env::new().await;
    let binding = env.sender("telegram", "T1").await;
    turn(&env, binding, "r1", "happy").await;
    let events = turn(&env, binding, "r2", "happy").await;
    assert_eq!(events.last(), Some(&ProviderEvent::Completed));
    let row = env.row("r2").await;
    assert_eq!(row["end_reason"], "result_success");
    assert_eq!(row["resumable"], true);
    assert_eq!(row["resumed_from"], "s-one");
    assert_eq!(row["native_session_id"], "s-one");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn host_binding_run_never_resumes() {
    let env = Env::new().await;
    let binding = env.host().await;
    turn(&env, binding, "r1", "happy").await;
    assert_eq!(env.row("r1").await["resumable"], true);
    turn(&env, binding, "r2", "happy").await;
    assert_eq!(resumes(&last_argv(&env)), None);
    assert!(env.row("r2").await["resumed_from"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn run_ended_by_result_error_is_not_resumed_from() {
    let env = Env::new().await;
    let binding = env.sender("telegram", "T1").await;
    turn(&env, binding, "r1", "result_error").await;
    turn(&env, binding, "r2", "happy").await;
    assert_eq!(resumes(&last_argv(&env)), None);
    assert!(env.row("r2").await["resumed_from"].is_null());
    env.stop().await;
}
