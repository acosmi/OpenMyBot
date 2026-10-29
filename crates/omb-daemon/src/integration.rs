//! In-process closed-loop acceptance: the daemon's assembly (channel tasks, control operations,
//! the `/cancel` canceller and the Agent runtime) against the fake Bot API, the in-repository fake
//! host and an own PostgreSQL 17.11 cluster. Events from the channel arrive as fake updates;
//! events written to the store directly are written before the channel tasks start.
use crate::{
    DaemonError, StatusOptions, StatusSnapshot,
    agent::{AgentRuntime, tests as agent},
    channels::{Channels, Outbound},
    config,
    control::{self, ControlState, ENGINE_PIN},
    delegation::fixture::Fixture,
    ops::{BindingRunCanceller, Op, Ops, ReceiverCommand},
};
use omb_channels::{
    CANCEL_QUEUE, OMB_REPLY_CANCEL_REQUESTED_V1, TERMINAL_QUEUE, Timings,
    testkit::{FakeTelegram, Reply, Sent},
};
use omb_hostdriver::{HostDriverConfig, Limits, WorkspaceRoots};
use omb_store::testkit;
use openbot_application::RunTerminalNotice;
use openbot_contracts::ids::{ActorId, RunId, thread::ThreadIdentity};
use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Notify, mpsc},
    task::JoinHandle,
    time::Instant,
};
use tokio_postgres::Client;
use uuid::Uuid;

/// The Bot API token the receiver is bound with; its prefix is the bot id `getMe` answers.
const TOKEN: &str = "1001:omb008-closed-loop-token";
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
/// A Telegram text message from `from` in chat `chat`, private when the chat is the sender's own.
fn update(id: u64, from: i64, chat: i64, text: &str) -> Value {
    let kind = if chat == from { "private" } else { "group" };
    json!({"update_id": id, "message": {"message_id": id, "date": chrono::Utc::now().timestamp(), "from": {"id": from, "is_bot": false}, "chat": {"id": chat, "type": kind}, "text": text}})
}
/// One scripted `getUpdates` answer.
fn batch(updates: &[Value]) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok": true, "result": updates})).unwrap()
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
/// row, the Agent runtime, `Ops` on the fake Bot API, and, once started, the channel tasks with
/// the `/cancel` canceller. The test serves the receiver commands the daemon's main loop serves.
struct Rig {
    fixture: Fixture,
    fake: FakeTelegram,
    token: Uuid,
    /// Setup and inspection connection outside the assembly.
    client: Client,
    ops: Option<Ops>,
    commands: mpsc::Receiver<ReceiverCommand>,
    channels: Option<Channels>,
    canceller: Option<BindingRunCanceller>,
    runtime: AgentRuntime,
    control_link: JoinHandle<Result<(), tokio_postgres::Error>>,
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
        let fake = FakeTelegram::start().await;
        let (receiver, commands) = mpsc::channel(8);
        let home = fixture.root.join("home");
        let engine = fixture.engine();
        let ops = Ops {
            control: Mutex::new(control.client),
            application: engine.assembly.application.clone(),
            resolver: engine.resolver.clone(),
            vault: engine.vault.clone(),
            owner: ActorId::new(SINGLE_USER_ACTOR_ID),
            roots: WorkspaceRoots::parse(&home, &[home.join("ws")]).unwrap(),
            endpoint: fake.endpoint(),
            receiver,
            // Replaced by the channels' wake-up at every start of the channel tasks.
            wake: Arc::new(Notify::new()),
        };
        Rig {
            fixture,
            fake,
            token,
            client,
            ops: Some(ops),
            commands,
            channels: None,
            canceller: None,
            runtime,
            control_link: control.driver,
        }
    }
    /// Starts the channel tasks on the fake endpoint with `terminals` as the engine's notices,
    /// the canceller on its own connection, and points `Ops` at the channels' wake-up.
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
        let channels = Channels::start(
            &mut self.fixture.pg,
            engine,
            self.token,
            timings,
            self.fake.endpoint(),
            cancel,
            Outbound {
                terminals,
                crabcode: Some(agent::fake()),
            },
        )
        .await
        .unwrap();
        self.canceller = Some(BindingRunCanceller::start(
            engine.assembly.application.clone(),
            engine.resolver.clone(),
            connection,
            requests,
        ));
        self.ops.as_mut().unwrap().wake = channels.wake();
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
                Some(command) = self.commands.recv() => match command {
                    ReceiverCommand::Start(row, done) => {
                        let started = self.channels.as_mut().unwrap().start_receiver(&mut self.fixture.pg, row).await;
                        let _ = done.send(started);
                    }
                    ReceiverCommand::Stop(binding_id, done) => {
                        self.channels.as_mut().unwrap().stop_receiver(binding_id).await;
                        let _ = done.send(());
                    }
                },
            }
        }
    }
    /// Binds the Telegram receiver through `bindings_receiver` after a scripted credential check.
    async fn bind_receiver(&mut self) {
        self.fake.script(
            "getMe",
            200,
            json!({"ok": true, "result": {"id": 1001, "is_bot": true, "first_name": "Bot", "username": "bot"}}).to_string(),
        );
        self.fake.script(
            "getWebhookInfo",
            200,
            br#"{"ok":true,"result":{"url":"","pending_update_count":0}}"#.to_vec(),
        );
        self.call(
            "bindings_receiver",
            json!({"channel": "telegram", "token": TOKEN}),
        )
        .await
        .unwrap();
    }
    /// A pending sender on the workspace: its binding id and one-time code.
    async fn pair_start(&mut self) -> (Uuid, String) {
        let workspace = self.fixture.root.join("home/ws");
        let started = self
            .call(
                "pair_start",
                json!({"channel": "telegram", "workspace": workspace}),
            )
            .await
            .unwrap();
        (
            Uuid::parse_str(started["binding_id"].as_str().unwrap()).unwrap(),
            started["code"].as_str().unwrap().to_owned(),
        )
    }
    /// Pairs the owner's chat with update `1`; returns the active sender and the used code.
    async fn pair(&mut self) -> (Uuid, String) {
        let (binding, code) = self.pair_start().await;
        self.fake
            .push_update(update(1, OWNER, OWNER, &format!("/pair {code}")));
        let reply = until(LIMIT, async || self.sent().into_iter().next()).await;
        assert!(reply.text.starts_with("绑定成功"), "{reply:?}");
        assert_eq!(reply.chat_id, OWNER);
        assert_eq!(self.binding(binding).await["status"], "active");
        (binding, code)
    }
    fn sent(&self) -> Vec<Sent> {
        self.fake.sent_messages()
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
                .filter(|sent| sent.text.starts_with("[OpenMyBot] ") && sent.text.contains(&marker))
                .collect::<Vec<_>>()
        };
        let first = until(LIMIT, async || mine().into_iter().next()).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(mine().len(), 1, "{:?}", self.sent());
        assert_eq!(first.chat_id, OWNER);
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
        first.text
    }
    /// The permission id the run's host asked for, once its row exists.
    async fn permission_of(&self, run: &str) -> String {
        until(LIMIT, async || {
            let rows = self.client.query("SELECT permission_id FROM openmybot.host_driver_sessions WHERE record_kind='permission' AND run_id=$1", &[&run]).await.unwrap();
            rows.first().map(|row| row.get(0))
        })
        .await
    }
    /// Waits until the receiver asked for updates from `offset` on, so every earlier one is consumed.
    async fn consumed(&self, offset: u64) {
        let offset = offset.to_string();
        until(LIMIT, async || {
            self.fake
                .calls("getUpdates")
                .iter()
                .any(|request| request.param("offset") == Some(offset.as_str()))
                .then_some(())
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
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake
        .push_update(update(2, OWNER, OWNER, "please do the work"));
    let run = rig.run_of(2).await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    assert_eq!(
        rig.result_of(&run).await,
        format!("[OpenMyBot] 已完成 · run {}\nhello from fake", &run[..8])
    );
    let sent = rig.sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    // Polling and sending share the one fake endpoint and the bound token.
    for request in rig.fake.requests() {
        assert!(
            request.path.starts_with(&format!("/bot{TOKEN}/")),
            "{}",
            request.path
        );
    }
    assert!(sent.iter().all(|sent| !sent.has_parse_mode));
    let event = rig.event(2).await;
    assert_eq!(event["dispatch_status"], "dispatched");
    assert_eq!(event["terminal_kind"], "succeeded");
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
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake
        .push_update(update(2, OWNER, OWNER, "write the file"));
    let run = rig.run_of(2).await;
    let id = rig.permission_of(&run).await;
    let notice = until(LIMIT, async || rig.sent().into_iter().nth(1)).await;
    assert!(notice.text.contains(&id), "{notice:?}");
    assert!(notice.text.contains("openmybot approve"), "{notice:?}");
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
    let texts: Vec<String> = rig.sent().into_iter().map(|sent| sent.text).collect();
    assert_eq!(texts.len(), 3, "{texts:?}");
    assert!(texts[0].starts_with("绑定成功"));
    assert_eq!(texts[1], notice.text);
    assert_eq!(texts[2], result);
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_line_channel_cancel_ends_cancelled_with_one_result() {
    let mut rig = Rig::start(agent::cooperative, timings()).await;
    rig.bind_receiver().await;
    rig.pair().await;
    // A host binding's run beside the sender's: the channel `/cancel` must leave it running.
    let (other, other_client) = agent::begin(&mut rig.fixture).await;
    agent::initialized(&rig.client, &other.run).await;
    rig.fake.push_update(update(2, OWNER, OWNER, "a long task"));
    let run = rig.run_of(2).await;
    agent::initialized(&rig.client, &RunId::new(&run)).await;
    rig.fake.push_update(update(3, OWNER, OWNER, "/cancel"));
    until(LIMIT, async || {
        rig.sent()
            .into_iter()
            .find(|sent| sent.text == OMB_REPLY_CANCEL_REQUESTED_V1)
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
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake
        .script("sendMessage", 500, b"{\"ok\":false}".to_vec());
    rig.fake
        .push_update(update(2, OWNER, OWNER, "please do the work"));
    let run = rig.run_of(2).await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    let row = result_row(&rig, &run, "sent").await;
    assert_eq!(row["attempts"], 2);
    assert_eq!(row["last_error_code"], "server_error");
    // Three more retry intervals bring no further send.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let sends = rig.fake.calls("sendMessage");
    assert_eq!(sends.len(), 3, "pairing reply, refused result, sent result");
    assert!(sends[2].at - sends[1].at >= Duration::from_millis(300));
    let sent = rig.sent();
    assert_eq!(sent[1].text, sent[2].text);
    assert!(
        sent[2]
            .text
            .starts_with(&format!("[OpenMyBot] 已完成 · run {}", &run[..8]))
    );
    assert_eq!(rig.event(2).await["terminal_kind"], "succeeded");
    rig.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unknown_send_result_is_not_retried_and_keeps_the_run_terminal() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake.script_reply("sendMessage", Reply::Disconnect);
    rig.fake
        .push_update(update(2, OWNER, OWNER, "please do the work"));
    let run = rig.run_of(2).await;
    assert_eq!(rig.terminal_of(&run).await, "succeeded");
    let row = result_row(&rig, &run, "unknown").await;
    assert_eq!(row["last_error_code"], "result_unknown");
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        rig.fake.calls("sendMessage").len(),
        2,
        "pairing reply and the one result attempt"
    );
    assert_eq!(result_row(&rig, &run, "unknown").await["attempts"], 1);
    assert_eq!(rig.event(2).await["terminal_kind"], "succeeded");
    rig.stop().await;
}

/// Waits until three more `getUpdates` answers than `before` were consumed and processed: the
/// receiver asks again only after finishing the previous batch.
async fn polled_past(rig: &Rig, before: usize, answers: usize) {
    until(LIMIT, async || {
        (rig.fake.calls("getUpdates").len() > before + answers).then_some(())
    })
    .await;
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
    rig.bind_receiver().await;
    rig.pair().await;
    let message = update(2, OWNER, OWNER, "please do the work");
    let changed = update(2, OWNER, OWNER, "please do other work");
    let before = rig.fake.calls("getUpdates").len();
    for updates in [
        vec![message.clone(), message.clone()],
        vec![message.clone()],
        vec![changed],
    ] {
        rig.fake.script("getUpdates", 200, batch(&updates));
    }
    polled_past(&rig, before, 3).await;
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
    rig.bind_receiver().await;
    rig.pair().await;
    // RACE_REPEAT_MIN rounds; each round's redeliveries overlap the claim, `begin` and the start.
    for round in 1..=10_i64 {
        let id = round as u64 + 1;
        let message = update(id, OWNER, OWNER, &format!("round {round}"));
        let before = rig.fake.calls("getUpdates").len();
        for updates in [
            vec![message.clone(), message.clone()],
            vec![message.clone()],
            vec![message.clone()],
        ] {
            rig.fake.script("getUpdates", 200, batch(&updates));
        }
        let run = rig.run_of(id).await;
        assert_eq!(rig.terminal_of(&run).await, "succeeded");
        rig.result_of(&run).await;
        polled_past(&rig, before, 3).await;
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
            .into_iter()
            .filter(|sent| sent.text.starts_with("[OpenMyBot] "))
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
async fn unbound_and_group_traffic_gets_no_reply_no_row_and_no_run() {
    let mut rig = Rig::start(agent::happy, timings()).await;
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake
        .push_update(update(2, 99, 99, "hello from a stranger"));
    rig.fake
        .push_update(update(3, OWNER, -100, "hello from the group"));
    rig.consumed(4).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    // Only the pairing reply the paired uid needed was ever sent.
    let sent = rig.sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].text.starts_with("绑定成功"));
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
    rig.bind_receiver().await;
    let (binding, code) = rig.pair().await;
    rig.fake
        .push_update(update(2, 43, 43, &format!("/pair {code}")));
    rig.consumed(3).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let sent = rig.sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].chat_id, OWNER);
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
    rig.bind_receiver().await;
    let (binding, code) = rig.pair_start().await;
    // The first symbol replaced by another Crockford base32 symbol.
    let wrong = format!(
        "{}{}",
        if code.starts_with('0') { '1' } else { '0' },
        &code[1..]
    );
    for id in 1..=5 {
        rig.fake
            .push_update(update(id, OWNER, OWNER, &format!("/pair {wrong}")));
    }
    rig.fake
        .push_update(update(6, OWNER, OWNER, &format!("/pair {code}")));
    rig.consumed(7).await;
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
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake
        .push_update(update(2, OWNER, OWNER, "write the file"));
    let run = rig.run_of(2).await;
    let id = rig.permission_of(&run).await;
    until(LIMIT, async || rig.sent().into_iter().nth(1)).await;
    for (update_id, text) in [
        (3, "yes".to_owned()),
        (4, "同意".to_owned()),
        (5, format!("approve {id}")),
    ] {
        rig.fake.push_update(update(update_id, OWNER, OWNER, &text));
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
    rig.bind_receiver().await;
    let (binding, _) = rig.pair().await;
    rig.fake
        .push_update(update(2, OWNER, OWNER, "first message"));
    let run = rig.run_of(2).await;
    agent::initialized(&rig.client, &RunId::new(&run)).await;
    rig.fake
        .push_update(update(3, OWNER, OWNER, "second message"));
    let later = rig.run_of(3).await;
    rig.fake.push_update(update(4, OWNER, OWNER, "/cancel"));
    until(LIMIT, async || {
        rig.sent()
            .into_iter()
            .find(|sent| sent.text == OMB_REPLY_CANCEL_REQUESTED_V1)
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
    rig.bind_receiver().await;
    rig.pair().await;
    // Built once: a redelivery carries the same date and so the same fingerprint.
    let status: Vec<Value> = (0..=5)
        .map(|id| update(id, OWNER, OWNER, "/status"))
        .collect();
    rig.fake.push_update(status[2].clone());
    rig.fake.push_update(status[3].clone());
    until(LIMIT, async || (rig.sent().len() == 3).then_some(())).await;
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
    // While the channel tasks are down: two new updates and a redelivery of an accepted one.
    rig.fake.push_update(status[4].clone());
    rig.fake.push_update(status[5].clone());
    rig.fake.script("getUpdates", 200, batch(&status[3..4]));
    // The restart writes a control token row as a daemon start does.
    rig.token = control_token(&mut rig.fixture).await;
    let before = rig.fake.calls("getUpdates").len();
    rig.start_channels(timings(), mpsc::channel(TERMINAL_QUEUE).1)
        .await;
    until(LIMIT, async || (rig.sent().len() == 5).then_some(())).await;
    rig.consumed(6).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        rig.fake.calls("getUpdates")[before].param("offset"),
        Some("4")
    );
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
            .all(|sent| sent.text.starts_with("绑定：telegram 已激活"))
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
    assert_eq!(channels[0].note, "telegram 长轮询");
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
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake
        .push_update(update(2, OWNER, OWNER, "please do the work"));
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
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake
        .push_update(update(2, OWNER, OWNER, "please do the work"));
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
    rig.bind_receiver().await;
    rig.pair().await;
    rig.fake
        .push_update(update(2, OWNER, OWNER, "write the file"));
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
