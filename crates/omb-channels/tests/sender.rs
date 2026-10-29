//! The outbound sender end to end: an own PostgreSQL 17.11 cluster, the loopback fake Bot API and
//! a real credential vault.
use omb_channels::{
    ChannelError, Connection, SenderContext, Task, TelegramEndpoint, Timings, start_sender,
    testkit::{FakeTelegram, Reply, Sent},
};
use omb_store::{
    EndReason, SessionEnd, deny_undecided_permissions, end_session, migrate,
    testkit::{
        Fixture, Session, deadline, insert_delivery, insert_ended_session, insert_event_for_run,
        insert_host_binding, insert_orphan_session, insert_permission_row, insert_receiver_with,
        insert_sender, read_row, set_terminal, shift_column,
    },
};
use openbot_application::{RunTerminalKind, RunTerminalNotice};
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::vault::CredentialRecordVault;
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Notify, mpsc};
use tokio_postgres::Client;
use uuid::Uuid;

const TOKEN: &str = "123456:SENTINEL-omb007-token";
const SOURCE: &str = "123456";

fn vault() -> CredentialRecordVault {
    CredentialRecordVault::single_key(
        TenantId::new("omb-test"),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![9; 32]).unwrap(),
    )
}
fn owner() -> ActorId {
    ActorId::new("owner")
}
fn seal(id: Uuid, token: &str) -> String {
    vault()
        .seal(
            &id,
            SecretKind::Connector,
            SecretPrincipal::Actor(owner()),
            SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
            &SecretBytes::new(token.as_bytes().to_vec()),
        )
        .unwrap()
}
const PLAN: [Duration; 5] = [
    Duration::from_millis(60),
    Duration::from_millis(80),
    Duration::from_millis(100),
    Duration::from_millis(120),
    Duration::from_millis(140),
];
fn quick() -> Timings {
    Timings {
        delivery_poll: Duration::from_millis(20),
        delivery_retry: PLAN,
        http_send_timeout: Duration::from_secs(5),
        ..Timings::default()
    }
}
fn timeout_after(send: Duration) -> Timings {
    Timings {
        http_send_timeout: send,
        ..quick()
    }
}
fn notice(run: &str, terminal: RunTerminalKind) -> RunTerminalNotice {
    RunTerminalNotice {
        deployment: DeploymentId::new("deployment"),
        tenant: TenantId::new("tenant"),
        thread_id: ThreadId::new("T1"),
        run_id: RunId::new(run),
        terminal,
    }
}

struct Env {
    fixture: Fixture,
    session: Session,
    fake: FakeTelegram,
    receiver: Uuid,
    sender: Uuid,
    wake: Arc<Notify>,
}
impl Env {
    /// An active Telegram receiver sealing `TOKEN` and a sender on chat `telegram:42`.
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        let receiver = Uuid::now_v7();
        insert_receiver_with(
            &session.client,
            receiver,
            "telegram",
            SOURCE,
            &seal(receiver, TOKEN),
        )
        .await;
        let sender = insert_sender(&session.client, "telegram", SOURCE, "telegram:42", "T1").await;
        Self {
            fixture,
            session,
            fake: FakeTelegram::start().await,
            receiver,
            sender,
            wake: Arc::new(Notify::new()),
        }
    }
    fn client(&self) -> &Client {
        &self.session.client
    }
    async fn start(&mut self, timings: Timings) -> (Task, mpsc::Sender<RunTerminalNotice>) {
        let endpoint = self.fake.endpoint();
        self.start_at(endpoint, timings).await
    }
    async fn start_at(
        &mut self,
        endpoint: TelegramEndpoint,
        timings: Timings,
    ) -> (Task, mpsc::Sender<RunTerminalNotice>) {
        let (client, driver) = self.fixture.open().await;
        let (queue, terminals) = mpsc::channel(16);
        let task = start_sender(
            Connection { client, driver },
            SenderContext {
                vault: vault(),
                owner: owner(),
                endpoint,
                timings,
                wake: Arc::clone(&self.wake),
            },
            terminals,
        );
        (task, queue)
    }
    async fn delivery(&self, kind: &str, key: &str, body: Option<&str>) -> Uuid {
        insert_delivery(self.client(), self.sender, kind, key, body, "pending", None).await
    }
    async fn reply(&self, key: &str, body: &str) -> Uuid {
        self.delivery("control_reply", key, Some(body)).await
    }
    async fn row(&self, id: Uuid) -> Value {
        read_row(self.client(), "deliveries", "delivery_id", id).await
    }
    /// Polls the row until `check` holds.
    async fn until(&self, id: Uuid, check: impl Fn(&Value) -> bool) -> Value {
        let limit = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let row = self.row(id).await;
            if check(&row) {
                return row;
            }
            assert!(tokio::time::Instant::now() < limit, "{row}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    async fn status(&self, id: Uuid, status: &str) -> Value {
        self.until(id, |row| row["status"] == status).await
    }
    fn sends(&self) -> usize {
        self.fake.calls("sendMessage").len()
    }
    async fn event(&self, run: &str) -> Uuid {
        insert_event_for_run(self.client(), self.sender, run, "T1", "dispatched").await
    }
    async fn event_row(&self, id: Uuid) -> Value {
        read_row(self.client(), "channel_events", "record_id", id).await
    }
    async fn count(&self, sql: &str) -> i64 {
        self.client().query_one(sql, &[]).await.unwrap().get(0)
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
fn path() -> String {
    format!("/bot{TOKEN}/sendMessage")
}
fn sent(text: &str) -> Sent {
    Sent {
        path: path(),
        chat_id: 42,
        text: text.into(),
        has_parse_mode: false,
    }
}
async fn set_status(client: &Client, binding: Uuid, status: &str) {
    assert_eq!(client.execute("UPDATE openmybot.channel_bindings SET status=$2,ended_at=CASE WHEN $2 IN ('revoked','expired') THEN statement_timestamp() END WHERE binding_id=$1", &[&binding, &status]).await.unwrap(), 1);
}
async fn exhausted(env: &Env, id: Uuid) -> Value {
    let row = env.status(id, "failed").await;
    assert_eq!(row["last_error_code"], "retries_exhausted");
    assert_eq!(row["attempts"], 6);
    assert!(row["finished_at"].is_string());
    row
}
const FAIL_UPDATE: &str = "CREATE FUNCTION openmybot.fail_row() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test failure'; END$$; CREATE TRIGGER fail_update BEFORE UPDATE ON openmybot.deliveries FOR EACH ROW EXECUTE FUNCTION openmybot.fail_row()";
fn result_text(state: &str, run: &str) -> String {
    format!("[OpenMyBot] {state} · run {}", &run[..8])
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn sends_pending_text_as_json_post_to_the_token_path_and_marks_sent() {
    let mut env = Env::new().await;
    let id = env.reply("control_reply:1", "状态：已激活").await;
    let (task, _queue) = env.start(quick()).await;
    let row = env.status(id, "sent").await;
    task.stop().await;
    assert_eq!(env.fake.sent_messages(), [sent("状态：已激活")]);
    let request = &env.fake.calls("sendMessage")[0];
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert!(body["chat_id"].is_i64());
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(row["attempts"], 1);
    assert!(row["first_attempt_at"].is_string());
    assert!(row["finished_at"].is_string());
    assert_eq!(row["platform_message_id"], "1");
    // Every row of every product table, envelope columns aside.
    let mut dump = String::new();
    for table in env
        .client()
        .query(
            "SELECT tablename::text FROM pg_tables WHERE schemaname='openmybot'",
            &[],
        )
        .await
        .unwrap()
    {
        let table: String = table.get(0);
        let rows: String = env
            .client()
            .query_one(
                &format!("SELECT coalesce(string_agg((to_jsonb(t)-'credential_envelope')::text, ','), '') FROM openmybot.{table} t"),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        dump.push_str(&rows);
    }
    assert!(dump.contains("telegram:42"));
    assert!(!dump.contains("SENTINEL"));
    assert!(!format!("{row:?}").contains("SENTINEL"));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn sends_rows_in_created_at_order() {
    let mut env = Env::new().await;
    let mut ids = Vec::new();
    for (text, age) in [("first", -30.0), ("third", -10.0), ("second", -20.0)] {
        let id = env.reply(&format!("control_reply:{text}"), text).await;
        shift_column(
            env.client(),
            "deliveries",
            "delivery_id",
            id,
            "created_at",
            age,
        )
        .await;
        ids.push(id);
    }
    let (task, _queue) = env.start(quick()).await;
    for id in &ids {
        env.status(*id, "sent").await;
    }
    task.stop().await;
    assert_eq!(
        env.fake.sent_messages(),
        [sent("first"), sent("second"), sent("third")]
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn feishu_rows_are_never_claimed() {
    let mut env = Env::new().await;
    let feishu = insert_sender(env.client(), "feishu", "cli_a", "feishu:7", "T2").await;
    let id = insert_delivery(
        env.client(),
        feishu,
        "control_reply",
        "control_reply:f",
        Some("x"),
        "pending",
        None,
    )
    .await;
    let (task, _queue) = env.start(quick()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    task.stop().await;
    let row = env.row(id).await;
    assert_eq!(row["status"], "pending");
    assert_eq!(row["attempts"], 0);
    assert_eq!(env.fake.requests().len(), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn sender_not_active_fails_binding_inactive_for_all_six_kinds_without_request() {
    let mut env = Env::new().await;
    set_status(env.client(), env.sender, "suspended").await;
    let mut ids = Vec::new();
    for (kind, key, body) in [
        ("run_result", "result:run-1", None),
        ("permission_notice", "perm:p-1", Some("notice")),
        ("control_reply", "control_reply:1", Some("reply")),
        ("pairing_reply", "pair:1", Some("paired")),
        ("reject_reply", "reject_reply:1", Some("rejected")),
        ("expiry_notice", "expiry_notice:1", Some("expired")),
    ] {
        ids.push(env.delivery(kind, key, body).await);
    }
    let (task, _queue) = env.start(quick()).await;
    for id in &ids {
        let row = env.status(*id, "failed").await;
        assert_eq!(row["last_error_code"], "binding_inactive");
        assert!(row["finished_at"].is_string());
        assert!(row["next_attempt_at"].is_null());
    }
    task.stop().await;
    assert_eq!(env.sends(), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoked_suspended_and_expired_sender_each_fail_binding_inactive() {
    let mut env = Env::new().await;
    set_status(env.client(), env.sender, "revoked").await;
    let expired = insert_sender(env.client(), "telegram", SOURCE, "telegram:43", "T3").await;
    set_status(env.client(), expired, "expired").await;
    let suspended = insert_sender(env.client(), "telegram", SOURCE, "telegram:44", "T4").await;
    set_status(env.client(), suspended, "suspended").await;
    let mut ids = Vec::new();
    for (index, binding) in [env.sender, expired, suspended].into_iter().enumerate() {
        ids.push(
            insert_delivery(
                env.client(),
                binding,
                "control_reply",
                &format!("control_reply:{index}"),
                Some("reply"),
                "pending",
                None,
            )
            .await,
        );
    }
    let (task, _queue) = env.start(quick()).await;
    for id in &ids {
        env.status(*id, "failed").await;
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    task.stop().await;
    for id in &ids {
        let row = env.row(*id).await;
        assert_eq!(row["last_error_code"], "binding_inactive");
        assert_eq!(row["attempts"], 1);
    }
    assert_eq!(env.sends(), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn missing_or_unopenable_receiver_fails_receiver_inactive_and_takes_a_retry_slot() {
    let mut env = Env::new().await;
    // Without an active receiver.
    set_status(env.client(), env.receiver, "revoked").await;
    let (task, _queue) = env.start(quick()).await;
    let mut cases = Vec::new();
    let none = env.reply("control_reply:none", "x").await;
    cases.push(none);
    let first = env
        .until(none, |row| {
            row["attempts"] == 1 && row["status"] == "pending"
        })
        .await;
    assert_eq!(first["last_error_code"], "receiver_inactive");
    assert!(first["next_attempt_at"].is_string());
    exhausted(&env, none).await;
    // An envelope that does not open.
    let garbage = Uuid::now_v7();
    insert_receiver_with(env.client(), garbage, "telegram", SOURCE, "not-an-envelope").await;
    let unopenable = env.reply("control_reply:garbage", "x").await;
    let first = env
        .until(unopenable, |row| {
            row["attempts"] == 1 && row["status"] == "pending"
        })
        .await;
    assert_eq!(first["last_error_code"], "receiver_inactive");
    assert!(first["next_attempt_at"].is_string());
    exhausted(&env, unopenable).await;
    // A token of another bot than the receiver's source.
    env.client()
        .execute(
            "UPDATE openmybot.channel_bindings SET credential_envelope=$2 WHERE binding_id=$1",
            &[&garbage, &seal(garbage, "999:other-bot-token")],
        )
        .await
        .unwrap();
    let foreign = env.reply("control_reply:foreign", "x").await;
    let first = env
        .until(foreign, |row| {
            row["attempts"] == 1 && row["status"] == "pending"
        })
        .await;
    assert_eq!(first["last_error_code"], "receiver_inactive");
    exhausted(&env, foreign).await;
    task.stop().await;
    assert_eq!(env.sends(), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn receiver_replaced_between_attempts_is_used_on_the_next_attempt() {
    let mut env = Env::new().await;
    set_status(env.client(), env.receiver, "revoked").await;
    let id = env.reply("control_reply:1", "hello").await;
    let (task, _queue) = env.start(quick()).await;
    let first = env
        .until(id, |row| row["attempts"] == 1 && row["status"] == "pending")
        .await;
    assert_eq!(first["last_error_code"], "receiver_inactive");
    let replacement = Uuid::now_v7();
    let token = "123456:SENTINEL-replacement-token";
    insert_receiver_with(
        env.client(),
        replacement,
        "telegram",
        SOURCE,
        &seal(replacement, token),
    )
    .await;
    let row = env.status(id, "sent").await;
    task.stop().await;
    assert!(row["attempts"].as_i64().unwrap() >= 2);
    let paths: Vec<_> = env
        .fake
        .sent_messages()
        .into_iter()
        .map(|sent| sent.path)
        .collect();
    assert_eq!(paths, [format!("/bot{token}/sendMessage")]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn chat_key_without_telegram_prefix_fails_client_error_without_request() {
    let mut env = Env::new().await;
    set_status(env.client(), env.sender, "revoked").await;
    let odd = insert_sender(env.client(), "telegram", SOURCE, "user-42", "T5").await;
    let id = insert_delivery(
        env.client(),
        odd,
        "control_reply",
        "control_reply:1",
        Some("x"),
        "pending",
        None,
    )
    .await;
    let (task, _queue) = env.start(quick()).await;
    let row = env.status(id, "failed").await;
    task.stop().await;
    assert_eq!(row["last_error_code"], "client_error");
    assert_eq!(env.sends(), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn server_error_follows_the_shortened_schedule_then_fails_retries_exhausted() {
    let mut env = Env::new().await;
    for _ in 0..6 {
        env.fake
            .script("sendMessage", 500, b"{\"ok\":false}".to_vec());
    }
    let id = env.reply("control_reply:1", "x").await;
    let (task, _queue) = env.start(quick()).await;
    exhausted(&env, id).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    task.stop().await;
    let requests = env.fake.calls("sendMessage");
    assert_eq!(requests.len(), 6);
    for (index, pair) in requests.windows(2).enumerate() {
        assert!(
            pair[1].at - pair[0].at >= PLAN[index],
            "retry {index}: {:?}",
            pair[1].at - pair[0].at
        );
    }
    env.stop().await;
}

/// Seconds from the database clock to the row's next attempt.
async fn ahead(client: &Client, id: Uuid) -> f64 {
    client
        .query_one("SELECT extract(epoch FROM next_attempt_at-statement_timestamp())::float8 FROM openmybot.deliveries WHERE delivery_id=$1", &[&id])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn rate_limited_next_attempt_is_the_larger_of_retry_after_and_plan() {
    let mut env = Env::new().await;
    env.fake.script(
        "sendMessage",
        429,
        br#"{"ok":false,"error_code":429,"parameters":{"retry_after":2}}"#.to_vec(),
    );
    let id = env.reply("control_reply:1", "x").await;
    let (task, _queue) = env.start(quick()).await;
    let row = env
        .until(id, |row| row["last_error_code"] == "rate_limited")
        .await;
    task.stop().await;
    assert_eq!(row["status"], "pending");
    let waited = ahead(env.client(), id).await;
    assert!(waited >= 1.5, "{waited}");
    env.fake.script(
        "sendMessage",
        429,
        br#"{"ok":false,"error_code":429,"parameters":{"retry_after":0}}"#.to_vec(),
    );
    let second = env.reply("control_reply:2", "y").await;
    shift_column(
        env.client(),
        "deliveries",
        "delivery_id",
        second,
        "created_at",
        -60.0,
    )
    .await;
    let (task, _queue) = env
        .start(Timings {
            delivery_retry: [Duration::from_secs(3); 5],
            ..quick()
        })
        .await;
    env.until(second, |row| row["last_error_code"] == "rate_limited")
        .await;
    task.stop().await;
    let waited = ahead(env.client(), second).await;
    assert!(waited >= 2.5, "{waited}");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn rate_limited_and_server_errors_each_consume_one_retry_slot() {
    let mut env = Env::new().await;
    for status in [429, 500, 429, 500, 500, 500] {
        env.fake
            .script("sendMessage", status, b"{\"ok\":false}".to_vec());
    }
    let id = env.reply("control_reply:1", "x").await;
    let (task, _queue) = env.start(quick()).await;
    exhausted(&env, id).await;
    task.stop().await;
    assert_eq!(env.sends(), 6);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unreachable_endpoint_retries_then_fails_retries_exhausted() {
    let mut env = Env::new().await;
    let id = env.reply("control_reply:1", "x").await;
    let (task, _queue) = env
        .start_at(
            FakeTelegram::endpoint_at(FakeTelegram::unused_port()),
            quick(),
        )
        .await;
    let first = env
        .until(id, |row| row["attempts"] == 1 && row["status"] == "pending")
        .await;
    assert_eq!(first["last_error_code"], "unreachable");
    exhausted(&env, id).await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn client_errors_fail_without_retry_and_do_not_suspend_the_receiver() {
    let mut env = Env::new().await;
    let before = read_row(env.client(), "channel_bindings", "binding_id", env.receiver).await;
    let mut ids = Vec::new();
    for (index, status) in [400, 401, 403, 404].into_iter().enumerate() {
        env.fake
            .script("sendMessage", status, b"{\"ok\":false}".to_vec());
        let id = env.reply(&format!("control_reply:{status}"), "x").await;
        shift_column(
            env.client(),
            "deliveries",
            "delivery_id",
            id,
            "created_at",
            index as f64 - 10.0,
        )
        .await;
        ids.push(id);
    }
    let (task, _queue) = env.start(quick()).await;
    for id in &ids {
        let row = env.status(*id, "failed").await;
        assert_eq!(row["last_error_code"], "client_error");
        assert_eq!(row["attempts"], 1);
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    task.stop().await;
    assert_eq!(env.sends(), 4);
    assert_eq!(
        read_row(env.client(), "channel_bindings", "binding_id", env.receiver).await,
        before
    );
    env.stop().await;
}

async fn unknown_once(reply: Reply, timings: Timings) {
    let mut env = Env::new().await;
    env.fake.script_reply("sendMessage", reply);
    let id = env.reply("control_reply:1", "x").await;
    let (task, _queue) = env.start(timings).await;
    let row = env.status(id, "unknown").await;
    assert_eq!(row["last_error_code"], "result_unknown");
    assert!(row["finished_at"].is_string());
    assert!(row["next_attempt_at"].is_null());
    tokio::time::sleep(Duration::from_millis(800)).await;
    task.stop().await;
    assert_eq!(env.sends(), 1);
    assert_eq!(env.row(id).await["attempts"], 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn timeout_after_the_request_is_unknown_and_never_resent() {
    unknown_once(Reply::Hang, timeout_after(Duration::from_millis(300))).await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn disconnect_after_the_request_is_read_is_unknown_and_never_resent() {
    unknown_once(Reply::Disconnect, quick()).await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn ok_false_and_unparseable_200_are_unknown_and_never_resent() {
    let mut env = Env::new().await;
    let mut ids = Vec::new();
    for (index, body) in [br#"{"ok":false}"#.as_slice(), b"<html>not json</html>"]
        .into_iter()
        .enumerate()
    {
        env.fake.script("sendMessage", 200, body.to_vec());
        let id = env.reply(&format!("control_reply:{index}"), "x").await;
        shift_column(
            env.client(),
            "deliveries",
            "delivery_id",
            id,
            "created_at",
            index as f64 - 10.0,
        )
        .await;
        ids.push(id);
    }
    let (task, _queue) = env.start(quick()).await;
    for id in &ids {
        let row = env.status(*id, "unknown").await;
        assert_eq!(row["last_error_code"], "result_unknown");
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    task.stop().await;
    assert_eq!(env.sends(), 2);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn failed_and_unknown_deliveries_leave_the_run_event_terminal_unchanged() {
    let mut env = Env::new().await;
    let failing = env.event("run-failing-0000").await;
    set_terminal(env.client(), failing, "succeeded").await;
    let unknown = env.event("run-unknown-0000").await;
    set_terminal(env.client(), unknown, "succeeded").await;
    let before = [env.event_row(failing).await, env.event_row(unknown).await];
    for _ in 0..6 {
        env.fake
            .script("sendMessage", 500, b"{\"ok\":false}".to_vec());
    }
    let first = env
        .delivery("run_result", "result:run-failing-0000", None)
        .await;
    let (task, _queue) = env.start(timeout_after(Duration::from_millis(300))).await;
    exhausted(&env, first).await;
    env.fake.script_reply("sendMessage", Reply::Hang);
    let second = env
        .delivery("run_result", "result:run-unknown-0000", None)
        .await;
    env.status(second, "unknown").await;
    task.stop().await;
    assert_eq!(
        [env.event_row(failing).await, env.event_row(unknown).await],
        before
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn terminal_notice_writes_terminal_and_one_run_result_message() {
    let mut env = Env::new().await;
    let run = "0192f1a2-0000-7000-8000-000000000100";
    let event = env.event(run).await;
    let (task, queue) = env.start(quick()).await;
    queue
        .send(notice(run, RunTerminalKind::Succeeded))
        .await
        .unwrap();
    let id: Uuid = loop {
        let found = env
            .client()
            .query(
                "SELECT delivery_id FROM openmybot.deliveries WHERE kind='run_result'",
                &[],
            )
            .await
            .unwrap();
        if let Some(row) = found.first() {
            break row.get(0);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    env.status(id, "sent").await;
    task.stop().await;
    let stored = env.event_row(event).await;
    assert_eq!(stored["terminal_kind"], "succeeded");
    assert!(stored["terminal_at"].is_string());
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.deliveries WHERE kind='run_result'")
            .await,
        1
    );
    assert_eq!(
        env.fake.sent_messages(),
        [sent(&result_text("已完成", run))]
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn duplicate_or_unknown_run_notices_send_at_most_one_message() {
    let mut env = Env::new().await;
    let run = "0192f1a2-0000-7000-8000-000000000101";
    env.event(run).await;
    let before: i64 = env
        .count("SELECT count(*) FROM openmybot.channel_events")
        .await;
    let (task, queue) = env.start(quick()).await;
    for _ in 0..3 {
        queue
            .send(notice(run, RunTerminalKind::Succeeded))
            .await
            .unwrap();
    }
    queue
        .send(notice("run-not-ours", RunTerminalKind::Failed))
        .await
        .unwrap();
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.fake.sent_messages().is_empty() {
        assert!(tokio::time::Instant::now() < limit, "no message");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    task.stop().await;
    assert_eq!(env.sends(), 1);
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.deliveries").await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.channel_events")
            .await,
        before
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn notice_for_host_run_writes_terminal_and_sends_nothing() {
    let mut env = Env::new().await;
    let host = insert_host_binding(env.client(), "/w/host").await;
    let event = insert_event_for_run(env.client(), host, "run-host", "TH", "dispatched").await;
    let (task, queue) = env.start(quick()).await;
    queue
        .send(notice("run-host", RunTerminalKind::Cancelled))
        .await
        .unwrap();
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.event_row(event).await["terminal_kind"].is_null() {
        assert!(tokio::time::Instant::now() < limit, "terminal");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    task.stop().await;
    assert_eq!(env.event_row(event).await["terminal_kind"], "cancelled");
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    assert_eq!(env.sends(), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn first_terminal_write_wakes_the_dispatcher_and_a_repeat_does_not() {
    let mut env = Env::new().await;
    let run = "0192f1a2-0000-7000-8000-000000000103";
    env.event(run).await;
    let (task, queue) = env.start(quick()).await;
    queue
        .send(notice(run, RunTerminalKind::Succeeded))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(100), env.wake.notified())
        .await
        .unwrap();
    queue
        .send(notice(run, RunTerminalKind::Succeeded))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), env.wake.notified())
            .await
            .is_err()
    );
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn run_result_text_uses_session_summary_and_artifact_paths_read_at_send_time() {
    let mut env = Env::new().await;
    let run = "0192f1a2-0000-7000-8000-000000000104";
    let event = env.event(run).await;
    set_terminal(env.client(), event, "succeeded").await;
    let id = env
        .delivery("run_result", &format!("result:{run}"), None)
        .await;
    insert_ended_session(
        env.client(),
        env.sender,
        run,
        "result_success",
        Some("report written to /srv/data/report.txt"),
        &["report.txt", "notes/summary.md"],
    )
    .await;
    let (task, _queue) = env.start(quick()).await;
    env.status(id, "sent").await;
    task.stop().await;
    assert_eq!(
        env.fake.sent_messages(),
        [sent(&format!(
            "{}\nreport written to /srv/data/report.txt\n成果：report.txt\nnotes/summary.md",
            result_text("已完成", run)
        ))]
    );
    assert!(env.row(id).await["body"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn failed_and_cancelled_texts_carry_no_stderr_tail() {
    let mut env = Env::new().await;
    let mut ids = Vec::new();
    for (index, (terminal, reason)) in [
        ("failed", EndReason::ResultError),
        ("cancelled", EndReason::StopRequested),
    ]
    .into_iter()
    .enumerate()
    {
        let run = format!("0192f1a2-0000-7000-8000-00000000010{index}");
        let event = env.event(&run).await;
        set_terminal(env.client(), event, terminal).await;
        let session = insert_orphan_session(env.client(), env.sender, &run, None).await;
        end_session(
            env.client(),
            session,
            SessionEnd {
                reason,
                exit_code: None,
                exit_signal: None,
                stop: None,
                result_summary: None,
                artifact_paths: &[],
                stderr_tail: "STDERR-SENTINEL tail",
            },
            deadline(),
        )
        .await
        .unwrap();
        ids.push(
            env.delivery("run_result", &format!("result:{run}"), None)
                .await,
        );
    }
    let (task, _queue) = env.start(quick()).await;
    for id in &ids {
        env.status(*id, "sent").await;
    }
    task.stop().await;
    let texts: Vec<_> = env
        .fake
        .sent_messages()
        .into_iter()
        .map(|sent| sent.text)
        .collect();
    assert_eq!(texts.len(), 2);
    for text in texts {
        assert!(!text.contains("STDERR-SENTINEL"), "{text}");
        assert!(text.starts_with("[OpenMyBot] 失败") || text.starts_with("[OpenMyBot] 已取消"));
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn expired_permission_notice_is_still_sent_verbatim() {
    let mut env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-old", -5.0).await;
    assert_eq!(
        deny_undecided_permissions(env.client(), deadline())
            .await
            .unwrap(),
        1
    );
    let body = "run run-1 需要审批 Write，许可 p-old，openmybot approve p-old";
    let id = env
        .delivery("permission_notice", "perm:p-old", Some(body))
        .await;
    let (task, _queue) = env.start(quick()).await;
    env.status(id, "sent").await;
    task.stop().await;
    assert_eq!(env.fake.sent_messages(), [sent(body)]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stop_lets_the_in_flight_send_finish_and_ends_the_task() {
    let mut env = Env::new().await;
    env.fake.script_reply(
        "sendMessage",
        Reply::Delayed {
            delay: Duration::from_millis(500),
            status: 200,
            body: br#"{"ok":true,"result":{"message_id":77}}"#.to_vec(),
        },
    );
    let id = env.reply("control_reply:1", "x").await;
    let (task, _queue) = env.start(quick()).await;
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.sends() == 0 {
        assert!(tokio::time::Instant::now() < limit, "no request");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    task.stop().await;
    let row = env.row(id).await;
    assert_eq!(row["status"], "sent");
    assert_eq!(row["platform_message_id"], "77");
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.deliveries WHERE status='sending'")
            .await,
        0
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stop_between_sends_leaves_the_remaining_rows_pending() {
    let mut env = Env::new().await;
    env.fake.script_reply(
        "sendMessage",
        Reply::Delayed {
            delay: Duration::from_millis(300),
            status: 200,
            body: br#"{"ok":true,"result":{"message_id":5}}"#.to_vec(),
        },
    );
    let first = env.reply("control_reply:1", "first").await;
    shift_column(
        env.client(),
        "deliveries",
        "delivery_id",
        first,
        "created_at",
        -10.0,
    )
    .await;
    let second = env.reply("control_reply:2", "second").await;
    let (task, _queue) = env.start(quick()).await;
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.sends() == 0 {
        assert!(tokio::time::Instant::now() < limit, "no request");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    task.stop().await;
    assert_eq!(env.row(first).await["status"], "sent");
    let rest = env.row(second).await;
    assert_eq!(rest["status"], "pending");
    assert_eq!(rest["attempts"], 0);
    assert_eq!(env.sends(), 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn store_failure_ends_the_task_with_store_failed() {
    let mut env = Env::new().await;
    env.client().batch_execute(FAIL_UPDATE).await.unwrap();
    env.reply("control_reply:1", "x").await;
    let (mut task, _queue) = env.start(quick()).await;
    let ended = tokio::time::timeout(Duration::from_secs(10), task.finished())
        .await
        .unwrap();
    assert_eq!(ended, Err(ChannelError::StoreFailed));
    task.stop().await;
    assert_eq!(env.sends(), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn idle_sender_picks_up_a_new_row_within_one_poll_interval() {
    let mut env = Env::new().await;
    let (task, _queue) = env.start(quick()).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let inserted = tokio::time::Instant::now();
    let id = env.reply("control_reply:1", "later").await;
    env.status(id, "sent").await;
    let took = inserted.elapsed();
    task.stop().await;
    assert!(took <= Duration::from_millis(20) * 10, "{took:?}");
    assert_eq!(env.fake.sent_messages(), [sent("later")]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn two_senders_send_each_pending_row_once_per_round() {
    let mut env = Env::new().await;
    for round in 0..10 {
        let mut ids = Vec::new();
        for index in 0..6 {
            ids.push(
                env.reply(
                    &format!("control_reply:{round}:{index}"),
                    &format!("round {round} row {index}"),
                )
                .await,
            );
        }
        let (first, _a) = env.start(quick()).await;
        let (second, _b) = env.start(quick()).await;
        for id in &ids {
            let row = env.status(*id, "sent").await;
            assert_eq!(row["attempts"], 1, "round {round}");
        }
        first.stop().await;
        second.stop().await;
        let mut texts: Vec<_> = env
            .fake
            .sent_messages()
            .into_iter()
            .map(|sent| sent.text)
            .filter(|text| text.starts_with(&format!("round {round} ")))
            .collect();
        assert_eq!(texts.len(), 6, "round {round}");
        texts.sort();
        texts.dedup();
        assert_eq!(texts.len(), 6, "round {round}");
    }
    env.stop().await;
}
