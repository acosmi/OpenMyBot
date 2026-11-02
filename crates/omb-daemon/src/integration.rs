//! In-process closed-loop acceptance: the daemon's assembly (channel plugin supervisors, control
//! operations, the `/cancel` canceller and the Agent runtime) against the fake channel plugin, the
//! in-repository fake host and an own PostgreSQL 17.11 cluster. Events from a channel are lines the
//! fake plugin emits; events written to the store directly are written before the channel tasks
//! start.
use crate::{
    CANCEL_QUEUE, DaemonError, OMB_REPLY_CANCEL_REQUESTED_V1, StatusOptions, StatusSnapshot,
    TERMINAL_QUEUE, Timings,
    agent::{AgentRuntime, tests as agent},
    channels::{Channels, Outbound, utc_millis},
    config,
    control::{self, ControlState, ENGINE_PIN},
    delegation::fixture::Fixture,
    ops::{BindingRunCanceller, CancelQueue, Op, Ops, ReceiverCommand, ThreadMinter},
    plugins::{
        Plugins,
        tests::{Logs, fake_channel, package},
    },
};
use omb_hostdriver::{HostDriverConfig, Limits, WorkspaceRoots};
use omb_store::{ChannelKind, testkit};
use openbot_application::RunTerminalNotice;
use openbot_contracts::ids::{ActorId, RunId, thread::ThreadIdentity};
use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::{UnixListener, UnixStream},
    process::{Child, ChildStdin, ChildStdout},
    sync::{Mutex, Notify, mpsc, oneshot},
    task::JoinHandle,
    time::Instant,
};
use tokio_postgres::Client;
use uuid::Uuid;

/// The credential every receiver is bound with: the plugins declare one secret field `token`.
const TOKEN: &str = "1001:omb008-closed-loop-token";
/// The source key the fake's verify answers for that credential.
const SOURCE: &str = "1001";
/// The paired sender, whose private chat has the same id.
const OWNER: i64 = 42;
/// Upper bound of every wait on the assembly.
const LIMIT: Duration = Duration::from_secs(90);

/// Channel timings of the assembly: short heartbeat, backoff, dispatch retry and delivery poll,
/// a 300 ms delivery retry plan; every other value is the production one.
fn timings() -> Timings {
    Timings {
        heartbeat: Duration::from_millis(100),
        backoff_min: Duration::from_millis(10),
        backoff_max: Duration::from_millis(100),
        dispatch_retry: Duration::from_millis(100),
        delivery_poll: Duration::from_millis(50),
        delivery_retry: [Duration::from_millis(300); 5],
        ..Timings::default()
    }
}
/// A text event of channel `kind` created now, as the fake plugin emits it.
fn message(kind: &str, key: &str, sender: &str, chat: &str, private: bool, text: &str) -> Value {
    json!({
        "event_key": key,
        "event_type": format!("{kind}.message"),
        "occurred_at": utc_millis(time::OffsetDateTime::now_utc()),
        "private": private,
        "sender_key": format!("{kind}:{sender}"),
        "chat_key": format!("{kind}:{chat}"),
        "kind": "text",
        "text": text,
        "data": {"text": text},
    })
}
/// A Telegram text of `from` in chat `chat`, private when the chat is the sender's own.
fn update(id: u64, from: i64, chat: i64, text: &str) -> Value {
    message(
        "telegram",
        &id.to_string(),
        &from.to_string(),
        &chat.to_string(),
        chat == from,
        text,
    )
}
/// A private Feishu text of the paired sender `ou_rig` in its chat `oc_rig`.
fn feishu_text(event_id: &str, text: &str) -> Value {
    message("feishu", event_id, "ou_rig", "oc_rig", true, text)
}
/// The text of one logged send.
fn body(sent: &Value) -> &str {
    sent["body"].as_str().unwrap()
}
/// How often the daemon confirmed event `key` of the channel `logs` belongs to.
fn acks(logs: &Logs, key: &str) -> usize {
    logs.received_of("accepted")
        .iter()
        .filter(|frame| frame["event_key"] == key)
        .count()
}
/// Installs the fake as plugin `fake-<kind>` serving `kind` with `scenario`, replacing an earlier
/// installation of it; its verify answers `SOURCE`.
fn install(plugins: &Plugins, kind: &str, logs: &Logs, scenario: &str) {
    let mut channel = fake_channel(
        kind,
        logs,
        scenario,
        json!([{"name": "token", "secret": true}]),
    );
    channel["args"]
        .as_array_mut()
        .unwrap()
        .extend([json!("--source-key"), json!(SOURCE)]);
    let package = package(&format!("fake-{kind}"), json!({kind: channel}));
    plugins.install(&package, &HashSet::new()).unwrap();
    std::fs::remove_dir_all(package).unwrap();
}
/// Polls `probe` every 20 ms until it yields a value, for at most `limit`.
async fn until<T>(limit: Duration, mut probe: impl AsyncFnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(found) = probe().await {
            return found;
        }
        assert!(Instant::now() < deadline, "wait exceeded {limit:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
/// A fresh control token row, as a daemon start writes it.
async fn control_token(fixture: &mut Fixture) -> Uuid {
    let token_id = Uuid::now_v7();
    let mut digest = [0; 32];
    digest[..16].copy_from_slice(token_id.as_bytes());
    fixture
        .pg
        .start_control_token(omb_store::ControlTokenStart {
            token_id,
            token_sha256: digest,
            daemon_pid: 1,
            engine_pin: ENGINE_PIN,
            omb_version: "0.0.0",
        })
        .await
        .unwrap();
    token_id
}

// Host scenarios; the fixture takes plain function pointers.
fn asking(root: &Path) -> HostDriverConfig {
    agent::host(
        root,
        "permission",
        agent::quick(),
        &[(
            "FAKE_CRABCODE_INPUT",
            r#"{"file_path":"approved.txt","content":"data"}"#,
        )],
    )
}
fn expiring(root: &Path) -> HostDriverConfig {
    agent::host(
        root,
        "permission",
        Limits {
            permission_ttl: Duration::from_secs(1),
            ..agent::quick()
        },
        &[(
            "FAKE_CRABCODE_INPUT",
            r#"{"file_path":"approved.txt","content":"data"}"#,
        )],
    )
}
fn outside_window(root: &Path) -> HostDriverConfig {
    agent::host(
        root,
        "happy",
        agent::quick(),
        &[("FAKE_CRABCODE_VERSION", "9.9.9")],
    )
}
/// One stdout line of 262145 bytes, one over the default line limit.
fn line_over(root: &Path) -> HostDriverConfig {
    agent::host(
        root,
        "long_line",
        agent::quick(),
        &[("FAKE_CRABCODE_BYTES", "262145")],
    )
}
/// Stderr of 1048577 bytes, one over the default output limit.
fn stderr_over(root: &Path) -> HostDriverConfig {
    agent::host(
        root,
        "stderr",
        agent::quick(),
        &[("FAKE_CRABCODE_BYTES", "1048577")],
    )
}

/// The daemon's assembly in this process: the fixture's engine and host driver, a control token
/// row, the Agent runtime, the fake plugin installed for `telegram` and `feishu` under the
/// fixture's data directory, `Ops` on those plugins, and, once started, the channel tasks with the
/// `/cancel` canceller. The test serves the receiver commands the daemon's main loop serves.
struct Rig {
    fixture: Fixture,
    /// What the `telegram` and `feishu` plugins emit, sent and received.
    telegram: Logs,
    feishu: Logs,
    plugins: Plugins,
    token: Uuid,
    /// Setup and inspection connection outside the assembly.
    client: Client,
    ops: Option<Ops>,
    commands: mpsc::Receiver<ReceiverCommand>,
    channels: Option<Channels>,
    canceller: Option<CancelQueue>,
    runtime: AgentRuntime,
    control_link: JoinHandle<Result<(), tokio_postgres::Error>>,
    canceller_link: JoinHandle<Result<(), tokio_postgres::Error>>,
}
impl Rig {
    /// Everything up to the channel tasks, in the daemon's order.
    async fn prepare(host: fn(&Path) -> HostDriverConfig) -> Rig {
        let mut fixture = Fixture::start_with_host(host).await;
        let token = control_token(&mut fixture).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let control = fixture
            .pg
            .open_resident_connection("openmybot-control")
            .await
            .unwrap();
        let client = fixture.client().await;
        let telegram = Logs::new();
        let feishu = Logs::new();
        let plugins = Plugins::load(&fixture.root, Vec::new(), fixture.root.clone()).unwrap();
        install(&plugins, "telegram", &telegram, "normal");
        install(&plugins, "feishu", &feishu, "normal");
        let (receiver, commands) = mpsc::channel(8);
        let home = fixture.root.join("home");
        let canceller = fixture
            .pg
            .open_resident_connection("openmybot-canceller")
            .await
            .unwrap();
        let engine = fixture.engine();
        let ops = Ops {
            control: Mutex::new(control.client),
            application: engine.assembly.application.clone(),
            resolver: engine.resolver.clone(),
            vault: engine.vault.clone(),
            owner: ActorId::new(SINGLE_USER_ACTOR_ID),
            roots: WorkspaceRoots::parse(&home, &[home.join("ws")]).unwrap(),
            plugins: plugins.clone(),
            receiver,
            // Replaced by the channels' wake-up at every start of the channel tasks.
            wake: Arc::new(Notify::new()),
            minter: ThreadMinter::new(engine.assembly.application.clone(), engine.resolver.clone()),
            canceller: BindingRunCanceller::new(
                engine.assembly.application.clone(),
                engine.resolver.clone(),
                Arc::new(canceller.client),
                Arc::default(),
            ),
            // Replaced by the channels' counters at every start of the channel tasks.
            counters: Arc::default(),
        };
        Rig {
            fixture,
            telegram,
            feishu,
            plugins,
            token,
            client,
            ops: Some(ops),
            commands,
            channels: None,
            canceller: None,
            runtime,
            control_link: control.driver,
            canceller_link: canceller.driver,
        }
    }
    /// Starts the channel tasks on the installed plugins with `terminals` as the engine's notices,
    /// the canceller on its own connection, and points `Ops` at the channels' wake-up and counters.
    async fn start_channels(
        &mut self,
        timings: Timings,
        terminals: mpsc::Receiver<RunTerminalNotice>,
    ) {
        let connection = self
            .fixture
            .pg
            .open_resident_connection("openmybot-canceller")
            .await
            .unwrap();
        let (cancel, requests) = mpsc::channel(CANCEL_QUEUE);
        let engine = self.fixture.engine.as_ref().unwrap();
        let gate = Arc::default();
        let channels = Channels::start(
            &mut self.fixture.pg,
            engine,
            self.token,
            timings,
            self.plugins.clone(),
            cancel,
            Outbound {
                terminals,
                crabcode: Some(agent::fake()),
            },
            Arc::clone(&gate),
        )
        .await
        .unwrap();
        let canceller = BindingRunCanceller::new(
            engine.assembly.application.clone(),
            engine.resolver.clone(),
            Arc::new(connection.client),
            gate,
        );
        self.canceller = Some(CancelQueue::start(
            canceller.clone(),
            connection.driver,
            requests,
        ));
        let ops = self.ops.as_mut().unwrap();
        ops.canceller = canceller;
        ops.wake = channels.wake();
        ops.counters = channels.status_source().counters;
        self.channels = Some(channels);
    }
    async fn start(host: fn(&Path) -> HostDriverConfig, timings: Timings) -> Rig {
        let mut rig = Rig::prepare(host).await;
        let terminals = rig.fixture.take_terminals();
        rig.start_channels(timings, terminals).await;
        rig
    }
    /// Runs one control operation, serving the receiver commands it sends meanwhile.
    async fn call(&mut self, op: &str, args: Value) -> Result<Value, DaemonError> {
        let run = self.ops.as_ref().unwrap().run(
            Op::parse(op).unwrap(),
            args,
            Instant::now() + Duration::from_secs(10),
            self.token,
        );
        tokio::pin!(run);
        loop {
            tokio::select! {
                result = &mut run => return result,
                Some(command) = self.commands.recv() => {
                    let channels = self.channels.as_mut().unwrap();
                    match command {
                        ReceiverCommand::Start(row, done) => {
                            channels.start_receiver(&mut self.fixture.pg, row, done).await;
                        }
                        ReceiverCommand::Stop(binding_id, done) => {
                            channels.stop_receiver(binding_id, done).await;
                        }
                        ReceiverCommand::Retire(kinds, done) => {
                            channels.retire(kinds, done).await;
                        }
                        ReceiverCommand::Verify { kind, credential, source_key, reply } => {
                            channels.verify(kind, credential, source_key, reply).await;
                        }
                    }
                }
            }
        }
    }
    /// Binds the `kind` receiver through `bindings_receiver`; the plugin verifies the credential.
    async fn bind(&mut self, kind: &str) {
        self.call(
            "bindings_receiver",
            json!({"channel": kind, "fields": {"token": TOKEN}}),
        )
        .await
        .unwrap();
    }
    /// A pending sender of `channel` on the workspace: its binding id and one-time code.
    async fn pair_start(&mut self, channel: &str) -> (Uuid, String) {
        let workspace = self.fixture.root.join("home/ws");
        let started = self
            .call(
                "pair_start",
                json!({"channel": channel, "workspace": workspace}),
            )
            .await
            .unwrap();
        (
            Uuid::parse_str(started["binding_id"].as_str().unwrap()).unwrap(),
            started["code"].as_str().unwrap().to_owned(),
        )
    }
    /// Pairs the owner's Telegram chat with update `1`; returns the active sender and the used
    /// code.
    async fn pair(&mut self) -> (Uuid, String) {
        let (binding, code) = self.pair_start("telegram").await;
        self.telegram
            .push(&update(1, OWNER, OWNER, &format!("/pair {code}")));
        let reply = until(LIMIT, async || self.sent().into_iter().next()).await;
        assert!(body(&reply).starts_with("绑定成功"), "{reply}");
        assert_eq!(reply["chat_key"], "telegram:42");
        assert_eq!(self.binding(binding).await["status"], "active");
        (binding, code)
    }
    /// Installs the Telegram plugin again with `scenario` and starts the active receiver again,
    /// which replaces the running process with one of the new installation. The new process
    /// emits the earlier events again; they are duplicates and change nothing.
    async fn rescenario(&mut self, scenario: &str) {
        // No send is in flight when the process is replaced.
        until(LIMIT, async || {
            (self
                .count("SELECT count(*) FROM openmybot.deliveries WHERE status IN ('pending','sending')")
                .await
                == 0)
                .then_some(())
        })
        .await;
        install(&self.plugins, "telegram", &self.telegram, scenario);
        let row = self
            .fixture
            .pg
            .list_active_receivers(ChannelKind::from_static("telegram"))
            .await
            .unwrap()
            .pop()
            .unwrap();
        let (done, started) = oneshot::channel();
        self.channels
            .as_mut()
            .unwrap()
            .start_receiver(&mut self.fixture.pg, row, done)
            .await;
        started.await.unwrap().unwrap();
    }
    /// Every send of the Telegram plugin, in order.
    fn sent(&self) -> Vec<Value> {
        self.telegram.sent()
    }
    async fn count(&self, sql: &str) -> i64 {
        self.client.query_one(sql, &[]).await.unwrap().get(0)
    }
    async fn binding(&self, id: Uuid) -> Value {
        testkit::read_row(&self.client, "channel_bindings", "binding_id", id).await
    }
    /// The Telegram event row of update `update`, once recorded.
    async fn event(&self, update: u64) -> Value {
        let key = update.to_string();
        until(LIMIT, async || {
            let rows = self.client.query("SELECT row_to_json(e) FROM openmybot.channel_events e WHERE channel_kind='telegram' AND event_key=$1", &[&key]).await.unwrap();
            rows.first().map(|row| row.get(0))
        })
        .await
    }
    /// The run id the accepted message of update `update` carries.
    async fn run_of(&self, update: u64) -> String {
        self.event(update).await["run_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    /// The terminal kind recorded on the run's event.
    async fn terminal_of(&self, run: &str) -> String {
        until(LIMIT, async || {
            self.client
                .query_one(
                    "SELECT terminal_kind FROM openmybot.channel_events WHERE run_id=$1",
                    &[&run],
                )
                .await
                .unwrap()
                .get::<_, Option<String>>(0)
        })
        .await
    }
    /// The run's session row once its stop outcome is recorded.
    async fn stopped(&self, run: &str) -> Value {
        let run = RunId::new(run);
        until(LIMIT, async || {
            let row = agent::session(&self.client, &run).await;
            (!row["stop_outcome"].is_null()).then_some(row)
        })
        .await
    }
    /// The run's only result message: one `run_result` row, sent, and one message to the owner's
    /// chat naming the run, still the only one three delivery polls later.
    async fn result_of(&self, run: &str) -> String {
        let marker = format!(" · run {}", &run[..8]);
        let mine = || {
            self.sent()
                .into_iter()
                .filter(|sent| {
                    body(sent).starts_with("[OpenMyBot] ") && body(sent).contains(&marker)
                })
                .collect::<Vec<_>>()
        };
        let first = until(LIMIT, async || mine().into_iter().next()).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(mine().len(), 1, "{:?}", self.sent());
        assert_eq!(first["chat_key"], "telegram:42");
        assert_eq!(first["idempotency_key"], format!("result:{run}"));
        let rows = self
            .client
            .query(
                "SELECT status FROM openmybot.deliveries WHERE kind='run_result' AND idempotency_key=$1",
                &[&format!("result:{run}")],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<_, String>(0), "sent");
        body(&first).to_owned()
    }
    /// The permission id the run's host asked for, once its row exists.
    async fn permission_of(&self, run: &str) -> String {
        until(LIMIT, async || {
            let rows = self.client.query("SELECT permission_id FROM openmybot.host_driver_sessions WHERE record_kind='permission' AND run_id=$1", &[&run]).await.unwrap();
            rows.first().map(|row| row.get(0))
        })
        .await
    }
    /// Waits until the daemon confirmed Telegram event `key` `times` times. The fake emits in file
    /// order and awaits each confirmation, so every earlier event was committed too.
    async fn consumed(&self, key: &str, times: usize) {
        until(LIMIT, async || {
            (acks(&self.telegram, key) >= times).then_some(())
        })
        .await;
    }
    /// The daemon's stop order: channel tasks, canceller, Agent runtime, control operations and
    /// their connection, then the host driver, the engine and the cluster.
    async fn stop(self) {
        if let Some(channels) = self.channels {
            channels.stop().await;
        }
        if let Some(canceller) = self.canceller {
            canceller.stop().await;
        }
        self.runtime.stop().await;
        drop(self.ops);
        self.canceller_link.abort();
        let _ = self.canceller_link.await;
        self.control_link.abort();
        let _ = self.control_link.await;
        drop(self.client);
        self.fixture.stop().await;
    }
}

// ---- Cases ---------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn injected_pending_host_events_dispatch_in_order_on_a_fingerprint_minted_thread() {
    let mut rig = Rig::prepare(agent::happy).await;
    let engine = rig.fixture.engine();
    let mut entropy = [0; 16];
    getrandom::fill(&mut entropy).unwrap();
    let thread = ThreadIdentity::new(&engine.deployment).mint_from_entropy(entropy);
    let generation = engine
        .resolver
        .local_context()
        .unwrap()
        .auth_generation()
        .get();
    let workspace = rig.fixture.root.join("home/ws");
    let binding = omb_store::activate_host(
        &mut rig.client,
        omb_store::HostBinding {
            workspace_dir: workspace.to_str().unwrap(),
            granted_generation: generation,
            run_deadline: None,
        },
        Instant::now() + Duration::from_secs(30),
    )
    .await
    .unwrap();
    // Two pending messages of the host binding in one statement, before the channel tasks start.
    let (first, second) = (Uuid::now_v7(), Uuid::now_v7());
    let runs = [format!("run-{first}"), format!("run-{second}")];
    rig.client.execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,text,text_sha256,run_id,thread_id,dispatch_status) VALUES ($1,'event','host','crabcode',$3,statement_timestamp(),$7,'accepted_message','do the work',sha256('do the work'::bytea),$5,$8,'pending'),($2,'event','host','crabcode',$4,statement_timestamp(),$7,'accepted_message','do the work',sha256('do the work'::bytea),$6,$8,'pending')", &[&first, &second, &format!("op:{first}"), &format!("op:{second}"), &runs[0], &runs[1], &binding, &thread.as_str()]).await.unwrap();
    let terminals = rig.fixture.take_terminals();
    rig.start_channels(timings(), terminals).await;
    for run in &runs {
        assert_eq!(rig.terminal_of(run).await, "succeeded");
        let session = agent::session(&rig.client, &RunId::new(run)).await;
        assert_eq!(session["end_reason"], "result_success");
    }
    let rows = rig.client.query("SELECT dispatch_status,dispatch_attempts,thread_id FROM openmybot.channel_events WHERE binding_id=$1 ORDER BY accepted_at,record_id", &[&binding]).await.unwrap();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.get::<_, String>(0), "dispatched");
        assert_eq!(row.get::<_, i32>(1), 1);
        assert_eq!(row.get::<_, String>(2), thread.as_str());
    }
    // The second event was claimed only after the first one's terminal was recorded.
    let ordered: bool = rig.client.query_one("SELECT (SELECT dispatched_at FROM openmybot.channel_events WHERE record_id=$2)>=(SELECT terminal_at FROM openmybot.channel_events WHERE record_id=$1)", &[&first, &second]).await.unwrap().get(0);
    assert!(ordered);
    assert_eq!(
        rig.count("SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn happy_line_pushed_update_runs_and_sends_one_result() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    rig.telegram
        .push(&update(2, OWNER, OWNER, "please do the work"));
    let run = rig.run_of(2).await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    assert_eq!(
        rig.result_of(&run).await,
        format!("[OpenMyBot] 已完成 · run {}\nhello from fake", &run[..8])
    );
    let sent = rig.sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    // Receiving and sending share the one plugin process, started once with the bound credential
    // and the source key its verify answered.
    let starts = rig.telegram.received_of("start");
    assert_eq!(starts.len(), 1, "{starts:?}");
    assert_eq!(
        [&starts[0]["credential"], &starts[0]["source_key"]],
        [TOKEN, SOURCE]
    );
    assert_eq!(rig.telegram.received_of("hello").len(), 1);
    assert!(sent.iter().all(|sent| sent["chat_key"] == "telegram:42"));
    let event = rig.event(2).await;
    assert_eq!(event["dispatch_status"], "dispatched");
    assert_eq!(event["terminal_kind"], "succeeded");
    assert_eq!(event["source_key"], SOURCE);
    let status = rig
        .call("status_run", json!({"run_id": run}))
        .await
        .unwrap();
    assert_eq!(status["terminal_kind"], "succeeded");
    assert_eq!(status["session"]["end_reason"], "result_success");
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn permission_line_notice_cli_approve_then_one_result() {
    let mut rig = Rig::start(asking, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    rig.telegram
        .push(&update(2, OWNER, OWNER, "write the file"));
    let run = rig.run_of(2).await;
    let id = rig.permission_of(&run).await;
    let notice = until(LIMIT, async || rig.sent().into_iter().nth(1)).await;
    assert!(body(&notice).contains(&id), "{notice}");
    assert!(body(&notice).contains("openmybot approve"), "{notice}");
    assert_eq!(
        rig.call("approve", json!({"permission_id": id}))
            .await
            .unwrap(),
        json!({"permission_id": id, "decision": "allow"})
    );
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    assert_eq!(
        std::fs::read_to_string(rig.fixture.root.join("home/ws/approved.txt")).unwrap(),
        "data"
    );
    let row = testkit::permission_row_json(&rig.client, &id).await;
    assert_eq!(row["decision"], "allow");
    assert_eq!(row["decided_via"], "cli");
    assert_eq!(row["decided_by_token"], rig.token.to_string());
    let result = rig.result_of(&run).await;
    assert!(
        result.starts_with(&format!("[OpenMyBot] 已完成 · run {}", &run[..8])),
        "{result}"
    );
    let texts: Vec<String> = rig
        .sent()
        .iter()
        .map(|sent| body(sent).to_owned())
        .collect();
    assert_eq!(texts.len(), 3, "{texts:?}");
    assert!(texts[0].starts_with("绑定成功"));
    assert_eq!(texts[1], body(&notice));
    assert_eq!(texts[2], result);
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_line_channel_cancel_ends_cancelled_with_one_result() {
    let mut rig = Rig::start(agent::cooperative, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    // A host binding's run beside the sender's: the channel `/cancel` must leave it running.
    let (other, other_client) = agent::begin(&mut rig.fixture).await;
    agent::initialized(&rig.client, &other.run).await;
    rig.telegram.push(&update(2, OWNER, OWNER, "a long task"));
    let run = rig.run_of(2).await;
    agent::initialized(&rig.client, &RunId::new(&run)).await;
    rig.telegram.push(&update(3, OWNER, OWNER, "/cancel"));
    until(LIMIT, async || {
        rig.sent()
            .into_iter()
            .find(|sent| body(sent) == OMB_REPLY_CANCEL_REQUESTED_V1)
    })
    .await;
    assert_eq!(rig.terminal_of(&run).await, "cancelled");
    let row = rig.stopped(&run).await;
    assert_eq!(row["end_reason"], "stop_requested");
    assert_eq!(row["stop_outcome"], "confirmed");
    assert!(agent::group_gone(&row));
    let result = rig.result_of(&run).await;
    assert!(
        result.starts_with(&format!("[OpenMyBot] 已取消 · run {}", &run[..8])),
        "{result}"
    );
    assert_eq!(rig.sent().len(), 3);
    let untouched = agent::session(&rig.client, &other.run).await;
    assert!(untouched["end_reason"].is_null(), "{untouched}");
    assert_eq!(
        rig.call("cancel", json!({"run_id": other.run.as_str()}))
            .await
            .unwrap()["state"],
        "requested"
    );
    assert_eq!(rig.terminal_of(other.run.as_str()).await, "cancelled");
    drop(other_client);
    rig.stop().await;
}

/// The run's `run_result` row once its status is `status`.
async fn result_row(rig: &Rig, run: &str, status: &str) -> Value {
    let key = format!("result:{run}");
    until(LIMIT, async || {
        let row: Value = rig
            .client
            .query_one(
                "SELECT row_to_json(d) FROM openmybot.deliveries d WHERE idempotency_key=$1",
                &[&key],
            )
            .await
            .unwrap()
            .get(0);
        (row["status"] == status).then_some(row)
    })
    .await
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn deterministic_send_failure_retries_on_schedule_and_keeps_the_run_terminal() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    // The first send of the restarted plugin, the run's result, fails with a retryable server
    // error.
    rig.rescenario("send_fail_once:retryable:server_error")
        .await;
    rig.telegram
        .push(&update(2, OWNER, OWNER, "please do the work"));
    let run = rig.run_of(2).await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    let row = result_row(&rig, &run, "sent").await;
    assert_eq!(row["attempts"], 2);
    assert_eq!(row["last_error_code"], "server_error");
    // The retry waited for the first interval of the plan.
    let waited: bool = rig
        .client
        .query_one(
            "SELECT finished_at-first_attempt_at>=interval '300 milliseconds' FROM openmybot.deliveries WHERE idempotency_key=$1",
            &[&format!("result:{run}")],
        )
        .await
        .unwrap()
        .get(0);
    assert!(waited);
    // Three more retry intervals bring no further send.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let sent = rig.sent();
    assert_eq!(
        sent.len(),
        3,
        "pairing reply, refused result, sent result: {sent:?}"
    );
    assert_eq!(sent[1]["delivery_id"], sent[2]["delivery_id"]);
    assert_eq!(body(&sent[1]), body(&sent[2]));
    assert!(body(&sent[2]).starts_with(&format!("[OpenMyBot] 已完成 · run {}", &run[..8])));
    assert_eq!(rig.event(2).await["terminal_kind"], "succeeded");
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unknown_send_result_is_not_retried_and_keeps_the_run_terminal() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    rig.rescenario("send_fail:unknown:server_error").await;
    rig.telegram
        .push(&update(2, OWNER, OWNER, "please do the work"));
    let run = rig.run_of(2).await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    let row = result_row(&rig, &run, "unknown").await;
    assert_eq!(row["last_error_code"], "result_unknown");
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        rig.sent().len(),
        2,
        "pairing reply and the one result attempt"
    );
    assert_eq!(result_row(&rig, &run, "unknown").await["attempts"], 1);
    assert_eq!(rig.event(2).await["terminal_kind"], "succeeded");
    rig.stop().await;
}

async fn event_conflicts(rig: &Rig) -> u64 {
    let channels = rig
        .channels
        .as_ref()
        .unwrap()
        .status_source()
        .read()
        .await
        .unwrap();
    channels[0].counters.event_conflict
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn redelivered_update_adds_no_event_no_run_and_one_result() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    let message = update(2, OWNER, OWNER, "please do the work");
    let changed = update(2, OWNER, OWNER, "please do other work");
    for event in [&message, &message, &message, &changed] {
        rig.telegram.push(event);
    }
    rig.consumed("2", 4).await;
    let run = rig.run_of(2).await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    rig.result_of(&run).await;
    assert_eq!(rig.count("SELECT count(*) FROM openmybot.channel_events WHERE channel_kind='telegram' AND event_key='2'").await, 1);
    assert_eq!(rig.event(2).await["text"], "please do the work");
    assert_eq!(rig.count("SELECT count(DISTINCT run_id) FROM openmybot.channel_events WHERE disposition='accepted_message'").await, 1);
    assert_eq!(
        rig.count(
            "SELECT count(*) FROM openmybot.host_driver_sessions WHERE record_kind='session'"
        )
        .await,
        1
    );
    assert_eq!(event_conflicts(&rig).await, 1);
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn race_duplicate_delivery_dispatcher_and_engine_run_once_per_round() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    // RACE_REPEAT_MIN rounds; each round's redeliveries overlap the claim, `begin` and the start.
    for round in 1..=10_i64 {
        let id = round as u64 + 1;
        let message = update(id, OWNER, OWNER, &format!("round {round}"));
        for _ in 0..4 {
            rig.telegram.push(&message);
        }
        let run = rig.run_of(id).await;
        assert_eq!(rig.terminal_of(&run).await, "succeeded");
        rig.result_of(&run).await;
        rig.consumed(&id.to_string(), 4).await;
        assert_eq!(
            rig.count(&format!("SELECT count(*) FROM openmybot.channel_events WHERE channel_kind='telegram' AND event_key='{id}'")).await,
            1,
            "round {round}"
        );
        assert_eq!(rig.count("SELECT count(DISTINCT run_id) FROM openmybot.channel_events WHERE disposition='accepted_message'").await, round);
        assert_eq!(
            rig.count(
                "SELECT count(*) FROM openmybot.host_driver_sessions WHERE record_kind='session'"
            )
            .await,
            round
        );
        assert_eq!(rig.count("SELECT count(*) FROM openmybot.deliveries WHERE kind='run_result' AND status='sent'").await, round);
        let results = rig
            .sent()
            .iter()
            .filter(|sent| body(sent).starts_with("[OpenMyBot] "))
            .count();
        assert_eq!(results as i64, round);
        assert_eq!(event_conflicts(&rig).await, 0, "round {round}");
    }
    // The binding's ten runs reached their terminals one after another, in update order.
    let rows = rig.client.query("SELECT event_key,dispatched_at<=terminal_at,terminal_at<=lead(dispatched_at) OVER (ORDER BY dispatched_at) FROM openmybot.channel_events WHERE disposition='accepted_message' ORDER BY dispatched_at", &[]).await.unwrap();
    let keys: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
    assert_eq!(keys, (2..=11).map(|id| id.to_string()).collect::<Vec<_>>());
    for row in &rows {
        assert!(row.get::<_, bool>(1));
        assert_ne!(row.get::<_, Option<bool>>(2), Some(false));
    }
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn feishu_redelivery_racing_dispatch_adds_no_run() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("feishu").await;
    // Pairs the Feishu chat `oc_rig` of `ou_rig`.
    let (binding, code) = rig.pair_start("feishu").await;
    rig.feishu
        .push(&feishu_text("ev_rig_pair", &format!("/pair {code}")));
    let reply = until(LIMIT, async || rig.feishu.sent().into_iter().next()).await;
    assert!(body(&reply).starts_with("绑定成功"), "{reply}");
    assert_eq!(reply["chat_key"], "feishu:oc_rig");
    let row = rig.binding(binding).await;
    assert_eq!(
        [&row["status"], &row["chat_key"]],
        ["active", "feishu:oc_rig"]
    );
    let results = |rig: &Rig| {
        rig.feishu
            .sent()
            .iter()
            .filter(|sent| body(sent).starts_with("[OpenMyBot] 已完成"))
            .count() as i64
    };
    // RACE_REPEAT_MIN rounds; each round's redeliveries overlap the claim, `begin` and the start.
    for round in 1..=10_i64 {
        let event = format!("ev_rig_{round}");
        let message = feishu_text(&event, &format!("work {round}"));
        for _ in 0..3 {
            rig.feishu.push(&message);
        }
        let run: String = until(LIMIT, async || {
            let rows = rig.client.query("SELECT run_id FROM openmybot.channel_events WHERE channel_kind='feishu' AND event_key=$1 AND run_id IS NOT NULL", &[&event]).await.unwrap();
            rows.first().map(|row| row.get(0))
        })
        .await;
        assert_eq!(rig.terminal_of(&run).await, "succeeded");
        until(LIMIT, async || (results(&rig) >= round).then_some(())).await;
        until(LIMIT, async || {
            (acks(&rig.feishu, &event) >= 3).then_some(())
        })
        .await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(acks(&rig.feishu, &event), 3, "round {round}");
        assert_eq!(results(&rig), round, "round {round}");
        assert_eq!(
            rig.count(&format!("SELECT count(*) FROM openmybot.channel_events WHERE channel_kind='feishu' AND event_key='{event}'")).await,
            1,
            "round {round}"
        );
        assert_eq!(
            rig.count(&format!(
                "SELECT count(*) FROM openmybot.channel_events WHERE run_id='{run}'"
            ))
            .await,
            1
        );
        assert_eq!(
            rig.count(
                "SELECT count(*) FROM openmybot.host_driver_sessions WHERE record_kind='session'"
            )
            .await,
            round
        );
        assert_eq!(event_conflicts(&rig).await, 0, "round {round}");
    }
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unbound_and_group_traffic_gets_no_reply_no_row_and_no_run() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    rig.telegram
        .push(&update(2, 99, 99, "hello from a stranger"));
    rig.telegram
        .push(&update(3, OWNER, -100, "hello from the group"));
    rig.consumed("3", 1).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    // Only the pairing reply the paired uid needed was ever sent.
    let sent = rig.sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(body(&sent[0]).starts_with("绑定成功"));
    // The owner's pairing reply is the one delivery row.
    assert_eq!(
        rig.count("SELECT count(*) FROM openmybot.deliveries").await,
        1
    );
    assert_eq!(
        rig.count(
            "SELECT count(*) FROM openmybot.channel_events WHERE disposition='accepted_message'"
        )
        .await,
        0
    );
    assert_eq!(
        rig.count("SELECT count(*) FROM openmybot.host_driver_sessions")
            .await,
        0
    );
    let stranger = rig.event(2).await;
    assert_eq!(stranger["disposition"], "dropped_unbound");
    assert!(stranger["text"].is_null());
    let group = rig.event(3).await;
    assert_eq!(group["disposition"], "dropped_not_private");
    assert!(group["text"].is_null());
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pairing_code_is_single_use_end_to_end() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    let (binding, code) = rig.pair().await;
    rig.telegram
        .push(&update(2, 43, 43, &format!("/pair {code}")));
    rig.consumed("2", 1).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let sent = rig.sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["chat_key"], "telegram:42");
    // The first pairing's reply is the one delivery row.
    assert_eq!(
        rig.count("SELECT count(*) FROM openmybot.deliveries").await,
        1
    );
    assert_eq!(rig.event(2).await["disposition"], "pairing_failed");
    let listed = rig.call("bindings_list", json!({})).await.unwrap();
    let senders: Vec<&Value> = listed["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|binding| binding["binding_kind"] == "sender")
        .collect();
    assert_eq!(senders.len(), 1);
    assert_eq!(senders[0]["binding_id"], binding.to_string());
    assert_eq!(senders[0]["sender_key"], "telegram:42");
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn five_wrong_pair_codes_lock_and_the_right_code_is_refused_without_replies() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    let (binding, code) = rig.pair_start("telegram").await;
    // The first symbol replaced by another Crockford base32 symbol.
    let wrong = format!(
        "{}{}",
        if code.starts_with('0') { '1' } else { '0' },
        &code[1..]
    );
    for id in 1..=5 {
        rig.telegram
            .push(&update(id, OWNER, OWNER, &format!("/pair {wrong}")));
    }
    rig.telegram
        .push(&update(6, OWNER, OWNER, &format!("/pair {code}")));
    rig.consumed("6", 1).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(rig.sent().is_empty(), "{:?}", rig.sent());
    assert_eq!(rig.binding(binding).await["status"], "pending");
    for id in 1..=5 {
        assert_eq!(rig.event(id).await["disposition"], "pairing_failed");
    }
    assert_eq!(rig.event(6).await["disposition"], "pairing_locked");
    assert_eq!(
        rig.count(
            "SELECT count(*) FROM openmybot.channel_events WHERE disposition='accepted_message'"
        )
        .await,
        0
    );
    assert_eq!(
        rig.count("SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn channel_text_yes_tongyi_and_approve_leave_the_permission_row_undecided() {
    let mut rig = Rig::start(asking, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    rig.telegram
        .push(&update(2, OWNER, OWNER, "write the file"));
    let run = rig.run_of(2).await;
    let id = rig.permission_of(&run).await;
    until(LIMIT, async || rig.sent().into_iter().nth(1)).await;
    for (update_id, text) in [
        (3, "yes".to_owned()),
        (4, "同意".to_owned()),
        (5, format!("approve {id}")),
    ] {
        rig.telegram.push(&update(update_id, OWNER, OWNER, &text));
    }
    for update_id in 3..=5 {
        assert_eq!(rig.event(update_id).await["dispatch_status"], "pending");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(testkit::permission_row_json(&rig.client, &id).await["decision"].is_null());
    assert_eq!(
        rig.call("deny", json!({"permission_id": id}))
            .await
            .unwrap()["decision"],
        "deny"
    );
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    let row = testkit::permission_row_json(&rig.client, &id).await;
    assert_eq!(row["decision"], "deny");
    assert_eq!(row["decided_via"], "cli");
    assert!(!rig.fixture.root.join("home/ws/approved.txt").exists());
    let result = rig.result_of(&run).await;
    assert!(result.ends_with("\ndenied"), "{result}");
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unconfirmable_stop_ends_reconciliation_required_pauses_later_events_until_reset_thread() {
    let mut rig = Rig::start(agent::unconfirmable, timings()).await;
    rig.bind("telegram").await;
    let (binding, _) = rig.pair().await;
    rig.telegram.push(&update(2, OWNER, OWNER, "first message"));
    let run = rig.run_of(2).await;
    agent::initialized(&rig.client, &RunId::new(&run)).await;
    rig.telegram
        .push(&update(3, OWNER, OWNER, "second message"));
    let later = rig.run_of(3).await;
    rig.telegram.push(&update(4, OWNER, OWNER, "/cancel"));
    until(LIMIT, async || {
        rig.sent()
            .into_iter()
            .find(|sent| body(sent) == OMB_REPLY_CANCEL_REQUESTED_V1)
    })
    .await;
    assert_eq!(rig.terminal_of(&run).await, "reconciliation_required");
    let row = rig.stopped(&run).await;
    assert_eq!(row["end_reason"], "stop_requested");
    assert_eq!(row["stop_outcome"], "unknown");
    let result = rig.result_of(&run).await;
    assert!(
        result.starts_with(&format!(
            "[OpenMyBot] 结果未知，在本机执行 openmybot status --run {run} 核对 · run {}",
            &run[..8]
        )),
        "{result}"
    );
    // The later message stays pending on the paused thread.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rig.event(3).await["dispatch_status"], "pending");
    let before = rig.binding(binding).await;
    for (ack, refused) in [
        ("", DaemonError::InvalidRequest),
        ("run-other", DaemonError::BindingStateInvalid),
    ] {
        assert_eq!(
            rig.call(
                "bindings_reset_thread",
                json!({"binding_id": binding.to_string(), "ack_unknown": ack})
            )
            .await,
            Err(refused)
        );
    }
    let reset = rig
        .call(
            "bindings_reset_thread",
            json!({"binding_id": binding.to_string(), "ack_unknown": run}),
        )
        .await
        .unwrap();
    assert_eq!(
        reset["thread_generation"],
        before["thread_generation"].as_i64().unwrap() + 1
    );
    let fresh = rig.binding(binding).await["thread_id"].clone();
    assert_ne!(fresh, before["thread_id"]);
    // The reset wakes the dispatcher; no further inbound message is needed.
    let moved = until(LIMIT, async || {
        let row = rig.event(3).await;
        (row["dispatch_status"] == "dispatched").then_some(row)
    })
    .await;
    assert_eq!(moved["thread_id"], fresh);
    agent::initialized(&rig.client, &RunId::new(&later)).await;
    for row in rig.client.query("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='session' AND pgid IS NOT NULL", &[]).await.unwrap() {
        let row: Value = row.get(0);
        let pgid = rustix::process::Pid::from_raw(row["pgid"].as_i64().unwrap() as i32).unwrap();
        let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
    }
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn telegram_offset_catch_up_after_channels_restart_adds_no_duplicates_and_records_daemon_down_gap()
 {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    for id in [2, 3] {
        rig.telegram.push(&update(id, OWNER, OWNER, "/status"));
    }
    until(LIMIT, async || (rig.sent().len() == 3).then_some(())).await;
    rig.consumed("3", 1).await;
    rig.channels.take().unwrap().stop().await;
    rig.canceller.take().unwrap().stop().await;
    let old = rig.token;
    let receiver: Uuid = rig
        .client
        .query_one(
            "SELECT binding_id FROM openmybot.channel_bindings WHERE binding_kind='receiver'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    // While the channel tasks are down: two new updates. The restarted plugin emits the accepted
    // ones again as well, as redeliveries.
    for id in [4, 5] {
        rig.telegram.push(&update(id, OWNER, OWNER, "/status"));
    }
    // The restart writes a control token row as a daemon start does.
    rig.token = control_token(&mut rig.fixture).await;
    rig.start_channels(timings(), mpsc::channel(TERMINAL_QUEUE).1)
        .await;
    until(LIMIT, async || (rig.sent().len() == 5).then_some(())).await;
    rig.consumed("5", 1).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    // The restarted plugin is told the last accepted update to catch up from, and every
    // redelivered update is confirmed again without a new row or reply.
    let starts = rig.telegram.received_of("start");
    assert_eq!(starts.len(), 2, "{starts:?}");
    assert_eq!(starts[1]["last_event_key"], "3");
    for key in ["1", "2", "3"] {
        assert_eq!(acks(&rig.telegram, key), 2, "update {key}");
    }
    for id in 2..=5 {
        let event = rig.event(id).await;
        assert_eq!(event["disposition"], "control_command");
        let replies = rig.count(&format!("SELECT count(*) FROM openmybot.deliveries WHERE kind='control_reply' AND idempotency_key='control_reply:{}'", event["record_id"].as_str().unwrap())).await;
        assert_eq!(replies, 1, "update {id}");
    }
    assert_eq!(
        rig.count("SELECT count(*) FROM openmybot.channel_events WHERE channel_kind='telegram' AND record_kind='event'")
            .await,
        5
    );
    let sent = rig.sent();
    assert_eq!(sent.len(), 5, "{sent:?}");
    assert!(
        sent[1..]
            .iter()
            .all(|sent| body(sent).starts_with("绑定：telegram 已激活"))
    );
    let gaps = rig.client.query("SELECT binding_id,gap_started_at=(SELECT last_heartbeat_at FROM openmybot.control_tokens WHERE token_id=$1),gap_ended_at IS NOT NULL FROM openmybot.channel_events WHERE gap_reason='daemon_down'", &[&old]).await.unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].get::<_, Uuid>(0), receiver);
    assert!(gaps[0].get::<_, bool>(1));
    assert!(gaps[0].get::<_, bool>(2));
    let channels = rig
        .channels
        .as_ref()
        .unwrap()
        .status_source()
        .read()
        .await
        .unwrap();
    assert_eq!(channels[0].note, "telegram fake note");
    assert_eq!(channels[0].counters.event_conflict, 0);
    assert!(
        channels[0]
            .gaps
            .iter()
            .any(|gap| gap.reason == "daemon_down" && gap.ended_at.is_some())
    );
    rig.stop().await;
}

/// Every session row of the run.
async fn sessions(rig: &Rig, run: &str) -> Vec<Value> {
    rig.client
        .query(
            "SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='session' AND run_id=$1",
            &[&run],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn version_outside_window_refuses_start_and_the_child_receives_no_input() {
    let mut rig = Rig::start(outside_window, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    rig.telegram
        .push(&update(2, OWNER, OWNER, "please do the work"));
    let run = rig.run_of(2).await;
    // The engine retries an unavailable provider start before the run fails.
    let terminal = until(Duration::from_secs(240), async || {
        rig.client
            .query_one(
                "SELECT terminal_kind FROM openmybot.channel_events WHERE run_id=$1",
                &[&run],
            )
            .await
            .unwrap()
            .get::<_, Option<String>>(0)
    })
    .await;
    assert_eq!(terminal, "failed");
    let rows = sessions(&rig, &run).await;
    assert!(!rows.is_empty());
    for row in &rows {
        assert_eq!(row["end_reason"], "version_rejected", "{row}");
    }
    assert!(rig.result_of(&run).await.starts_with("[OpenMyBot] 失败"));
    let report = std::fs::read_to_string(rig.fixture.root.join("home/report.jsonl")).unwrap();
    let observed: Vec<Value> = report
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let starts: Vec<&Value> = observed
        .iter()
        .filter(|entry| entry["event"] == "start")
        .collect();
    assert!(!starts.is_empty());
    let fake = agent::fake();
    for start in starts {
        assert_eq!(start["argv"], json!([fake, "--version"]));
    }
    assert!(!observed.iter().any(|entry| entry["event"] == "stdin"));
    rig.stop().await;
}

/// A failed run of a host that broke a default output limit: `reason` on its session and one
/// failure result message.
async fn failed_on_limit(host: fn(&Path) -> HostDriverConfig, reason: &str) {
    let mut rig = Rig::start(host, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    rig.telegram
        .push(&update(2, OWNER, OWNER, "please do the work"));
    let run = rig.run_of(2).await;
    assert_eq!(rig.terminal_of(&run).await, "failed");
    let rows = sessions(&rig, &run).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["end_reason"], reason);
    assert!(rig.result_of(&run).await.starts_with("[OpenMyBot] 失败"));
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn line_one_byte_over_cc_line_max_fails_invalid_response() {
    failed_on_limit(line_over, "line_limit").await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stderr_over_cc_output_max_fails_invalid_response() {
    failed_on_limit(stderr_over, "output_limit").await;
}

/// One control frame; a write the rejecting side already closed is ignored.
async fn frame(stream: &mut UnixStream, value: &Value) {
    let bytes = value.to_string().into_bytes();
    let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
    let _ = stream.write_all(&bytes).await;
}
async fn read_frame(stream: &mut UnixStream) -> Value {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn t10_rejected_connections_run_no_operation_on_the_assembled_control_state() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    let workspace = rig.fixture.root.join("home/ws");
    let binding = testkit::insert_host_binding(&rig.client, workspace.to_str().unwrap()).await;
    testkit::insert_permission_row(&rig.client, binding, "run-t10", "hp-t10", 600.0).await;
    let token = config::hex_random(config::TOKEN_BYTES).unwrap();
    let state = ControlState::new(
        token.clone(),
        rig.token,
        StatusSnapshot {
            deployment_id: rig.fixture.deployment_id.clone(),
            daemon_pid: std::process::id(),
            pg_pid: rig.fixture.pg.pid(),
            pg_server_version_num: rig.fixture.pg.version,
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            engine_pin: ENGINE_PIN.into(),
            authentication_failures: 0,
            channels: Vec::new(),
            plugins: Vec::new(),
        },
        Some(rig.channels.as_ref().unwrap().status_source()),
        rig.ops.take(),
    );
    let hello = |token: &str| json!({"type": "hello", "token": token, "client": "cli", "client_version": "0.0.0"});
    let approve = json!({"type": "request", "op": "approve", "args": {"permission_id": "hp-t10"}});
    let wrong = config::hex_random(config::TOKEN_BYTES).unwrap();
    // A wrong token through `handle`, then the right token under a different peer uid.
    for (sent_token, peer_uid) in [
        (&wrong, None),
        (&token, Some(config::uid().wrapping_add(1))),
    ] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            match peer_uid {
                None => control::handle(server, shared).await,
                Some(uid) => control::handle_with_uid(&mut server, shared, uid).await,
            }
        });
        frame(&mut client, &hello(sent_token)).await;
        frame(&mut client, &approve).await;
        let mut answer = Vec::new();
        let read = client.read_to_end(&mut answer).await;
        assert!(read.is_ok() || read.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
        assert!(answer.is_empty());
        task.await.unwrap();
    }
    assert!(testkit::permission_row_json(&rig.client, "hp-t10").await["decision"].is_null());
    let (mut client, server) = UnixStream::pair().unwrap();
    let task = tokio::spawn(control::handle(server, Arc::clone(&state)));
    frame(&mut client, &hello(&token)).await;
    assert_eq!(read_frame(&mut client).await["type"], "hello_ok");
    frame(
        &mut client,
        &json!({"type": "request", "op": "status", "args": {}}),
    )
    .await;
    let response = read_frame(&mut client).await;
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"]["authentication_failures"], 2);
    task.await.unwrap();
    // Without a token file nothing connects to the listening socket.
    let root = config::test_dir();
    config::make_dir(&root.join("run")).unwrap();
    let listener = UnixListener::bind(root.join("run/control.sock")).unwrap();
    assert_eq!(
        crate::status(StatusOptions {
            data_dir: root.clone()
        })
        .await
        .unwrap_err(),
        DaemonError::DaemonNotRunning
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    drop(listener);
    std::fs::remove_dir_all(root).unwrap();
    drop(state);
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn undecided_permission_expires_to_deny_and_late_approve_is_not_pending() {
    let mut rig = Rig::start(expiring, timings()).await;
    rig.bind("telegram").await;
    rig.pair().await;
    rig.telegram
        .push(&update(2, OWNER, OWNER, "write the file"));
    let run = rig.run_of(2).await;
    let id = rig.permission_of(&run).await;
    let row = until(LIMIT, async || {
        let row = testkit::permission_row_json(&rig.client, &id).await;
        (!row["decision"].is_null()).then_some(row)
    })
    .await;
    assert_eq!(row["decision"], "deny");
    assert_eq!(row["decided_via"], "timeout");
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    assert!(rig.result_of(&run).await.ends_with("\ndenied"));
    assert_eq!(
        rig.call("approve", json!({"permission_id": id})).await,
        Err(DaemonError::PermissionNotPending)
    );
    assert!(!rig.fixture.root.join("home/ws/approved.txt").exists());
    rig.stop().await;
}

// ---- End to end with the first-party plugins -------------------------------------------------

/// The fake Telegram and Feishu platforms of `fake-channel-platform` in their own process, driven
/// by one JSON line per command.
struct Platform {
    _child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    telegram: String,
    feishu: String,
}
impl Platform {
    async fn start() -> Platform {
        let binary = std::env::var_os("OMB_TEST_CHANNEL_PLATFORM")
            .expect("OMB_TEST_CHANNEL_PLATFORM: absolute path of the fake channel platform");
        let mut child = tokio::process::Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let bases: Value =
            serde_json::from_str(&stdout.next_line().await.unwrap().unwrap()).unwrap();
        Platform {
            _child: child,
            stdin,
            stdout,
            telegram: bases["telegram_api_base"].as_str().unwrap().to_owned(),
            feishu: bases["feishu_api_base"].as_str().unwrap().to_owned(),
        }
    }
    async fn call(&mut self, command: Value) -> Value {
        self.stdin
            .write_all(format!("{command}\n").as_bytes())
            .await
            .unwrap();
        serde_json::from_str(&self.stdout.next_line().await.unwrap().unwrap()).unwrap()
    }
    async fn push_update(&mut self, update: Value) {
        let pushed = self
            .call(json!({"op": "telegram_push_update", "update": update}))
            .await;
        assert_eq!(pushed, json!({"ok": true}));
    }
    /// Pushes the event once the long connection is up.
    async fn push_event(&mut self, event: &Value) {
        until(LIMIT, async || {
            let pushed = self
                .call(json!({"op": "feishu_push_event", "event": event}))
                .await;
            (pushed == json!({"ok": true})).then_some(())
        })
        .await;
    }
    async fn list(&mut self, op: &str, key: &str) -> Vec<Value> {
        self.call(json!({ "op": op }))
            .await
            .get(key)
            .and_then(Value::as_array)
            .unwrap()
            .clone()
    }
    async fn telegram_sent(&mut self) -> Vec<Value> {
        self.list("telegram_sent", "sent").await
    }
    async fn feishu_sent(&mut self) -> Vec<Value> {
        self.list("feishu_sent", "sent").await
    }
    async fn offsets(&mut self) -> Vec<Value> {
        self.list("telegram_offsets", "offsets").await
    }
    async fn acks(&mut self) -> u64 {
        self.call(json!({"op": "feishu_acks"})).await["acks"]
            .as_u64()
            .unwrap()
    }
}

/// Replaces the fake for `kind` with the first-party plugin binary in `OMB_TEST_CHANNEL_<KIND>`,
/// installed from its production manifest plus `--api-base` of the fake platform.
fn install_first_party(plugins: &Plugins, kind: &str, base: &str) {
    plugins.remove(&format!("fake-{kind}")).unwrap();
    let variable = format!("OMB_TEST_CHANNEL_{}", kind.to_uppercase());
    let binary = PathBuf::from(
        std::env::var_os(&variable)
            .unwrap_or_else(|| panic!("{variable}: absolute path of the {kind} plugin")),
    );
    assert!(binary.is_absolute());
    let package = config::test_dir();
    let name = format!("openmybot-channel-{kind}");
    std::fs::create_dir(package.join("bin")).unwrap();
    std::fs::copy(binary, package.join("bin").join(&name)).unwrap();
    let mut manifest: Value = serde_json::from_str(match kind {
        "telegram" => include_str!("../../../openmybot/plugins/telegram/plugin.json"),
        _ => include_str!("../../../openmybot/plugins/feishu/plugin.json"),
    })
    .unwrap();
    manifest["extensions"]["org.openmybot"]["channels"][kind]["args"] = json!(["--api-base", base]);
    std::fs::write(package.join("plugin.json"), manifest.to_string()).unwrap();
    assert_eq!(
        plugins.install(&package, &HashSet::new()).unwrap().name,
        name
    );
    std::fs::remove_dir_all(package).unwrap();
}
/// The assembly with the first-party plugin of `kind` against a fresh fake platform.
async fn first_party(kind: &str) -> (Rig, Platform) {
    let mut rig = Rig::prepare(agent::happy).await;
    let platform = Platform::start().await;
    let base = match kind {
        "telegram" => &platform.telegram,
        _ => &platform.feishu,
    };
    install_first_party(&rig.plugins, kind, base);
    let terminals = rig.fixture.take_terminals();
    rig.start_channels(timings(), terminals).await;
    (rig, platform)
}
/// A Bot API update of `from` in chat `chat` sent now, private when the chat is the sender's own.
fn bot_update(id: u64, from: i64, chat: i64, text: &str) -> Value {
    json!({"update_id": id, "message": {
        "message_id": id,
        "date": time::OffsetDateTime::now_utc().unix_timestamp(),
        "from": {"id": from, "is_bot": false},
        "chat": {"id": chat, "type": if chat == from { "private" } else { "group" }},
        "text": text,
    }})
}
/// A Feishu message event of the paired user `ou_rig` sent now in `chat`.
fn feishu_event(event_id: &str, chat: &str, chat_type: &str, text: &str) -> Value {
    json!({
        "schema": "2.0",
        "header": {
            "event_id": event_id,
            "event_type": "im.message.receive_v1",
            "create_time": (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).to_string(),
            "app_id": "cli_rig",
        },
        "event": {
            "sender": {"sender_id": {"open_id": "ou_rig"}, "sender_type": "user"},
            "message": {
                "message_id": format!("om_{event_id}"),
                "chat_id": chat,
                "chat_type": chat_type,
                "message_type": "text",
                "content": json!({"text": text}).to_string(),
            },
        },
    })
}
/// Binds the Telegram receiver through the plugin's verify against the fake Bot API and pairs the
/// owner's private chat with update 1.
async fn pair_telegram(rig: &mut Rig, platform: &mut Platform) {
    rig.bind("telegram").await;
    let (binding, code) = rig.pair_start("telegram").await;
    platform
        .push_update(bot_update(1, OWNER, OWNER, &format!("/pair {code}")))
        .await;
    let reply = until(LIMIT, async || {
        platform.telegram_sent().await.into_iter().next()
    })
    .await;
    assert!(
        reply["text"].as_str().unwrap().starts_with("绑定成功"),
        "{reply}"
    );
    assert_eq!(reply["chat_id"], OWNER);
    assert_eq!(rig.binding(binding).await["status"], "active");
}
/// Binds the Feishu receiver with app id `cli_rig` and pairs `ou_rig`'s private chat `oc_rig`.
async fn pair_feishu(rig: &mut Rig, platform: &mut Platform) {
    let bound = rig
        .call(
            "bindings_receiver",
            json!({"channel": "feishu", "fields": {"app_id": "cli_rig", "app_secret": "rig-secret"}}),
        )
        .await
        .unwrap();
    let receiver = Uuid::parse_str(bound["binding_id"].as_str().unwrap()).unwrap();
    assert_eq!(rig.binding(receiver).await["source_key"], "cli_rig");
    let (binding, code) = rig.pair_start("feishu").await;
    platform
        .push_event(&feishu_event(
            "ev_pair",
            "oc_rig",
            "p2p",
            &format!("/pair {code}"),
        ))
        .await;
    let reply = until(LIMIT, async || {
        platform.feishu_sent().await.into_iter().next()
    })
    .await;
    assert!(
        reply["text"].as_str().unwrap().starts_with("绑定成功"),
        "{reply}"
    );
    assert_eq!(reply["receive_id"], "oc_rig");
    let row = rig.binding(binding).await;
    assert_eq!(
        [&row["status"], &row["chat_key"]],
        ["active", "feishu:oc_rig"]
    );
}
/// The run id of the event `key` of `kind`, once recorded.
async fn run_of(rig: &Rig, kind: &str, key: &str) -> String {
    until(LIMIT, async || {
        let rows = rig.client.query("SELECT run_id FROM openmybot.channel_events WHERE channel_kind=$1 AND event_key=$2 AND run_id IS NOT NULL", &[&kind, &key]).await.unwrap();
        rows.first().map(|row| row.get(0))
    })
    .await
}
/// The expected result text of a happy run.
fn result_text(run: &str) -> String {
    format!("[OpenMyBot] 已完成 · run {}\nhello from fake", &run[..8])
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn e2e_telegram_pushed_update_runs_and_sends_one_result() {
    let (mut rig, mut platform) = first_party("telegram").await;
    pair_telegram(&mut rig, &mut platform).await;
    platform
        .push_update(bot_update(2, OWNER, OWNER, "please do the work"))
        .await;
    let run = run_of(&rig, "telegram", "2").await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    let result = until(LIMIT, async || {
        platform.telegram_sent().await.into_iter().nth(1)
    })
    .await;
    assert_eq!(result, json!({"chat_id": OWNER, "text": result_text(&run)}));
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(platform.telegram_sent().await.len(), 2);
    let event = rig.event(2).await;
    assert_eq!(event["source_key"], SOURCE);
    assert_eq!(event["dispatch_status"], "dispatched");
    assert_eq!(
        rig.count(
            "SELECT count(*) FROM openmybot.deliveries WHERE kind='run_result' AND status='sent'"
        )
        .await,
        1
    );
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn e2e_telegram_redelivered_update_adds_no_event_and_no_run() {
    let (mut rig, mut platform) = first_party("telegram").await;
    pair_telegram(&mut rig, &mut platform).await;
    // While the plugin process is ended the platform holds three copies of update 2 and a changed
    // one; the receiver's next process fetches them in one batch from the stored cursor.
    let (done, retired) = oneshot::channel();
    rig.channels
        .as_mut()
        .unwrap()
        .retire(vec!["telegram".to_owned()], done)
        .await;
    retired.await.unwrap();
    let message = bot_update(2, OWNER, OWNER, "please do the work");
    let mut changed = message.clone();
    changed["message"]["text"] = json!("please do other work");
    for update in [&message, &message, &message, &changed] {
        platform.push_update(update.clone()).await;
    }
    let row = rig
        .fixture
        .pg
        .list_active_receivers(ChannelKind::from_static("telegram"))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let (done, started) = oneshot::channel();
    rig.channels
        .as_mut()
        .unwrap()
        .start_receiver(&mut rig.fixture.pg, row, done)
        .await;
    started.await.unwrap().unwrap();
    let run = run_of(&rig, "telegram", "2").await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    until(LIMIT, async || {
        (event_conflicts(&rig).await == 1).then_some(())
    })
    .await;
    let result = until(LIMIT, async || {
        platform.telegram_sent().await.into_iter().nth(1)
    })
    .await;
    assert_eq!(result["text"], result_text(&run));
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(platform.telegram_sent().await.len(), 2);
    assert_eq!(rig.count("SELECT count(*) FROM openmybot.channel_events WHERE channel_kind='telegram' AND event_key='2'").await, 1);
    assert_eq!(rig.event(2).await["text"], "please do the work");
    assert_eq!(rig.count("SELECT count(DISTINCT run_id) FROM openmybot.channel_events WHERE disposition='accepted_message'").await, 1);
    assert_eq!(
        rig.count(
            "SELECT count(*) FROM openmybot.host_driver_sessions WHERE record_kind='session'"
        )
        .await,
        1
    );
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn e2e_telegram_offset_catch_up_after_restart_adds_no_duplicates() {
    let (mut rig, mut platform) = first_party("telegram").await;
    pair_telegram(&mut rig, &mut platform).await;
    for id in [2, 3] {
        platform
            .push_update(bot_update(id, OWNER, OWNER, "/status"))
            .await;
    }
    until(LIMIT, async || {
        (platform.telegram_sent().await.len() == 3).then_some(())
    })
    .await;
    // Update 3 was confirmed once the plugin polls past it.
    until(LIMIT, async || {
        platform.offsets().await.contains(&json!(4)).then_some(())
    })
    .await;
    rig.channels.take().unwrap().stop().await;
    rig.canceller.take().unwrap().stop().await;
    // A request of the ended plugin may still be on its way to the platform.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = platform.offsets().await.len();
    for id in [4, 5] {
        platform
            .push_update(bot_update(id, OWNER, OWNER, "/status"))
            .await;
    }
    rig.token = control_token(&mut rig.fixture).await;
    rig.start_channels(timings(), mpsc::channel(TERMINAL_QUEUE).1)
        .await;
    until(LIMIT, async || {
        (platform.telegram_sent().await.len() == 5).then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    // The restarted plugin's first poll continues one past the last accepted update.
    assert_eq!(platform.offsets().await[before], json!(4));
    for id in 2..=5 {
        let event = rig.event(id).await;
        assert_eq!(event["disposition"], "control_command");
        let replies = rig.count(&format!("SELECT count(*) FROM openmybot.deliveries WHERE kind='control_reply' AND idempotency_key='control_reply:{}'", event["record_id"].as_str().unwrap())).await;
        assert_eq!(replies, 1, "update {id}");
    }
    assert_eq!(
        rig.count("SELECT count(*) FROM openmybot.channel_events WHERE channel_kind='telegram' AND record_kind='event'")
            .await,
        5
    );
    let sent = platform.telegram_sent().await;
    assert_eq!(sent.len(), 5, "{sent:?}");
    assert!(sent[1..].iter().all(|sent| {
        sent["text"]
            .as_str()
            .unwrap()
            .starts_with("绑定：telegram 已激活")
    }));
    assert_eq!(event_conflicts(&rig).await, 0);
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn e2e_feishu_event_runs_and_platform_receives_one_ack_and_one_send() {
    let (mut rig, mut platform) = first_party("feishu").await;
    pair_feishu(&mut rig, &mut platform).await;
    // Group traffic of the paired user is confirmed and dropped without a reply.
    platform
        .push_event(&feishu_event(
            "ev_group",
            "oc_group",
            "group",
            "hello group",
        ))
        .await;
    platform
        .push_event(&feishu_event(
            "ev_work",
            "oc_rig",
            "p2p",
            "please do the work",
        ))
        .await;
    let run = run_of(&rig, "feishu", "ev_work").await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    let result = until(LIMIT, async || {
        platform.feishu_sent().await.into_iter().nth(1)
    })
    .await;
    let uuid: String = Sha256::digest(format!("result:{run}").as_bytes())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        result,
        json!({"receive_id": "oc_rig", "text": result_text(&run), "uuid": uuid})
    );
    until(LIMIT, async || (platform.acks().await == 3).then_some(())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    // The pairing message, the group message and the work message: one acknowledgement each, and
    // the pairing reply and the result as the only sends.
    assert_eq!(platform.acks().await, 3);
    assert_eq!(platform.feishu_sent().await.len(), 2);
    let group: Value = rig.client.query_one("SELECT row_to_json(e) FROM openmybot.channel_events e WHERE channel_kind='feishu' AND event_key='ev_group'", &[]).await.unwrap().get(0);
    assert_eq!(group["disposition"], "dropped_not_private");
    assert!(group["text"].is_null());
    assert_eq!(
        rig.count(
            "SELECT count(*) FROM openmybot.host_driver_sessions WHERE record_kind='session'"
        )
        .await,
        1
    );
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn e2e_feishu_redelivered_event_adds_no_run() {
    let (mut rig, mut platform) = first_party("feishu").await;
    pair_feishu(&mut rig, &mut platform).await;
    let message = feishu_event("ev_work", "oc_rig", "p2p", "please do the work");
    for _ in 0..3 {
        platform.push_event(&message).await;
    }
    let run = run_of(&rig, "feishu", "ev_work").await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    until(LIMIT, async || {
        platform.feishu_sent().await.into_iter().nth(1)
    })
    .await;
    // The pairing message once and the work message once per delivery.
    until(LIMIT, async || (platform.acks().await == 4).then_some(())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(platform.acks().await, 4);
    assert_eq!(platform.feishu_sent().await.len(), 2);
    assert_eq!(rig.count("SELECT count(*) FROM openmybot.channel_events WHERE channel_kind='feishu' AND event_key='ev_work'").await, 1);
    assert_eq!(
        rig.count(&format!(
            "SELECT count(*) FROM openmybot.channel_events WHERE run_id='{run}'"
        ))
        .await,
        1
    );
    assert_eq!(
        rig.count(
            "SELECT count(*) FROM openmybot.host_driver_sessions WHERE record_kind='session'"
        )
        .await,
        1
    );
    assert_eq!(event_conflicts(&rig).await, 0);
    rig.stop().await;
}
