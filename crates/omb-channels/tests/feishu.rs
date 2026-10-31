//! Feishu receiver and sender end to end: an own PostgreSQL 17.11 cluster, the loopback fake open
//! platform and a real credential vault.
use omb_channels::{
    CANCEL_QUEUE, CancelRequests, Connection, Counters, Endpoints, FEISHU, FS_FRAME_MAX,
    OMB_REPLY_CANCEL_REQUESTED_V1, ReceiverContext, SenderContext, Task, Timings,
    fake_feishu::{FakeFeishu, FeishuSent, Handshake},
    start_receiver, start_sender,
    testkit::{FakeTelegram, Reply},
};
use omb_store::{
    ReceiverRow, Suspension, channel_status, list_active_receivers, migrate, receiver_row,
    reconfirm_binding, suspend_receiver,
    testkit::{
        Fixture, Session, deadline, insert_delivery, insert_ended_session, insert_event_for_run,
        insert_receiver_with, insert_sender, read_row, set_terminal, suspend_binding,
    },
};
use openbot_contracts::ids::{ActorId, TenantId};
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::{
    net::safe_http::{SafeHttpBudget, SafeHttpRequest},
    vault::CredentialRecordVault,
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{
    sync::{Notify, mpsc},
    time::Instant,
};
use tokio_postgres::Client;
use url::Url;
use uuid::Uuid;

const APP_ID: &str = "cli_test";
const SECRET: &str = "SENTINEL-feishu-app-secret";
const SECRET_2: &str = "SENTINEL-feishu-app-secret-2";
const TOKEN_PATH: &str = "/open-apis/auth/v3/tenant_access_token/internal";
const ENDPOINT_PATH: &str = "/callback/ws/endpoint";
const MESSAGES_PATH: &str = "/open-apis/im/v1/messages";
/// Client sessions of the cluster other than the asking one.
const OTHER_SESSIONS: &str = "SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()";
const PLAN: [Duration; 5] = [
    Duration::from_millis(60),
    Duration::from_millis(80),
    Duration::from_millis(100),
    Duration::from_millis(120),
    Duration::from_millis(140),
];

fn vault() -> CredentialRecordVault {
    CredentialRecordVault::single_key(
        TenantId::new("omb-test"),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![11; 32]).unwrap(),
    )
}
fn owner() -> ActorId {
    ActorId::new("owner")
}
fn seal_as(id: Uuid, service: &str, secret: &str) -> String {
    vault()
        .seal(
            &id,
            SecretKind::Connector,
            SecretPrincipal::Actor(owner()),
            SecretPrincipal::Service(ServiceId::new(service)),
            &SecretBytes::new(secret.as_bytes().to_vec()),
        )
        .unwrap()
}
fn seal(id: Uuid, secret: &str) -> String {
    seal_as(id, "openmybot.feishu", secret)
}
fn quick() -> Timings {
    Timings {
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(200),
        http_send_timeout: Duration::from_secs(2),
        fs_ping_interval: Duration::from_millis(500),
        fs_read_grace: Duration::from_millis(300),
        delivery_poll: Duration::from_millis(20),
        delivery_retry: PLAN,
        ..Timings::default()
    }
}
fn respond(status: u16, body: &str) -> Reply {
    Reply::Respond {
        status,
        body: body.as_bytes().to_vec(),
    }
}
fn now_ms() -> i128 {
    OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000
}
/// A 2.0 `im.message.receive_v1` envelope created now.
fn message(
    event_id: &str,
    open_id: &str,
    chat_type: &str,
    message_type: &str,
    content: &str,
) -> Value {
    json!({
        "schema": "2.0",
        "header": {"event_id": event_id, "event_type": "im.message.receive_v1", "create_time": now_ms().to_string(), "app_id": APP_ID},
        "event": {
            "sender": {"sender_id": {"open_id": open_id}, "sender_type": "user"},
            "message": {"message_id": format!("om_{event_id}"), "chat_id": "oc_chat", "chat_type": chat_type, "message_type": message_type, "content": content}
        }
    })
}
fn content(text: &str) -> String {
    json!({ "text": text }).to_string()
}
/// A private text of the bound sender.
fn text(event_id: &str, body: &str) -> Value {
    message(event_id, "ou_user", "p2p", "text", &content(body))
}
fn unsupported(event_id: &str) -> Value {
    let mut value = text(event_id, "read");
    value["header"]["event_type"] = json!("im.message.message_read_v1");
    value
}

struct Env {
    fixture: Fixture,
    session: Session,
    fake: FakeFeishu,
    receiver: Uuid,
    envelope: String,
    sender: Uuid,
    counters: Arc<Counters>,
    wake: Arc<Notify>,
    cancel: CancelRequests,
    cancels: mpsc::Receiver<Uuid>,
}
impl Env {
    /// An active Feishu receiver sealing `SECRET` and a sender `feishu:ou_user` on chat
    /// `feishu:oc_chat`.
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        let receiver = Uuid::now_v7();
        let envelope = seal(receiver, SECRET);
        insert_receiver_with(&session.client, receiver, "feishu", APP_ID, &envelope).await;
        let sender = insert_sender(
            &session.client,
            "feishu",
            APP_ID,
            "feishu:ou_user",
            "thread-F",
        )
        .await;
        session
            .client
            .execute(
                "UPDATE openmybot.channel_bindings SET chat_key='feishu:oc_chat' WHERE binding_id=$1",
                &[&sender],
            )
            .await
            .unwrap();
        let (cancel, cancels) = mpsc::channel(CANCEL_QUEUE);
        Self {
            fixture,
            session,
            fake: FakeFeishu::start().await,
            receiver,
            envelope,
            sender,
            counters: Arc::new(Counters::default()),
            wake: Arc::new(Notify::new()),
            cancel,
            cancels,
        }
    }
    fn client(&self) -> &Client {
        &self.session.client
    }
    fn endpoints(&self) -> Endpoints {
        Endpoints {
            telegram: FakeTelegram::endpoint_at(FakeTelegram::unused_port()),
            feishu: self.fake.endpoint(),
        }
    }
    async fn start(&mut self, timings: Timings) -> Task {
        let (client, driver) = self.fixture.open().await;
        start_receiver(
            Connection { client, driver },
            ReceiverRow {
                binding_id: self.receiver,
                channel: FEISHU,
                source_key: APP_ID.into(),
                credential_envelope: self.envelope.clone(),
            },
            ReceiverContext {
                vault: vault(),
                owner: owner(),
                endpoints: self.endpoints(),
                timings,
                counters: Arc::clone(&self.counters),
                wake: Arc::clone(&self.wake),
                cancel: self.cancel.clone(),
            },
        )
    }
    async fn start_sender(&mut self, timings: Timings) -> Task {
        let (client, driver) = self.fixture.open().await;
        let (_queue, terminals) = mpsc::channel(16);
        start_sender(
            Connection { client, driver },
            SenderContext {
                vault: vault(),
                owner: owner(),
                endpoints: self.endpoints(),
                timings,
                wake: Arc::clone(&self.wake),
            },
            terminals,
        )
    }
    async fn connected(&self, handshakes: usize) {
        until(&format!("{handshakes} handshakes"), || {
            self.fake.handshakes().len() >= handshakes
        })
        .await;
    }
    fn acks_of(&self, event_id: &str) -> usize {
        self.fake
            .acks()
            .iter()
            .filter(|ack| ack.message_id == event_id)
            .count()
    }
    /// Waits for `count` acknowledgements of the event; every one of them is valid.
    async fn acked(&self, event_id: &str, count: usize) {
        until(&format!("{count} acks of {event_id}"), || {
            self.acks_of(event_id) >= count
        })
        .await;
        assert!(
            self.fake
                .acks()
                .iter()
                .filter(|ack| ack.message_id == event_id)
                .all(|ack| ack.valid)
        );
    }
    /// Holds the acceptance transaction's advisory lock of the event from another session.
    async fn hold(&mut self, event_id: &str) -> Session {
        let lock = self.fixture.connect().await;
        lock.client
            .execute(
                "SELECT pg_advisory_lock(hashtextextended($1,0))",
                &[&format!("feishu\n{APP_ID}\n{event_id}")],
            )
            .await
            .unwrap();
        lock
    }
    async fn reply(&self, key: &str, body: &str) -> Uuid {
        insert_delivery(
            self.client(),
            self.sender,
            "control_reply",
            key,
            Some(body),
            "pending",
            None,
        )
        .await
    }
    /// Polls the delivery row until `check` holds.
    async fn until(&self, id: Uuid, check: impl Fn(&Value) -> bool) -> Value {
        let limit = Instant::now() + Duration::from_secs(20);
        loop {
            let row = read_row(self.client(), "deliveries", "delivery_id", id).await;
            if check(&row) {
                return row;
            }
            assert!(Instant::now() < limit, "{row}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    async fn status(&self, id: Uuid, status: &str) -> Value {
        self.until(id, |row| row["status"] == status).await
    }
    fn token_bodies(&self) -> Vec<Value> {
        self.fake
            .calls(TOKEN_PATH)
            .iter()
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect()
    }
    fn authorizations(&self) -> Vec<Option<String>> {
        self.fake
            .sent_messages()
            .into_iter()
            .map(|sent| sent.authorization)
            .collect()
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
async fn release(lock: Session, event_id: &str) {
    lock.client
        .execute(
            "SELECT pg_advisory_unlock(hashtextextended($1,0))",
            &[&format!("feishu\n{APP_ID}\n{event_id}")],
        )
        .await
        .unwrap();
    lock.close().await;
}
async fn until(what: &str, condition: impl Fn() -> bool) {
    let limit = Instant::now() + Duration::from_secs(20);
    while !condition() {
        assert!(Instant::now() < limit, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn count(client: &Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).await.unwrap().get(0)
}
async fn rows_reach(client: &Client, sql: &str, expected: i64) {
    let limit = Instant::now() + Duration::from_secs(20);
    loop {
        let found = count(client, sql).await;
        if found == expected {
            return;
        }
        assert!(Instant::now() < limit, "{sql}: {found} != {expected}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn rows_of(client: &Client, event_id: &str) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='event' AND event_key=$1",
            &[&event_id],
        )
        .await
        .unwrap()
        .get(0)
}
async fn events(client: &Client) -> i64 {
    count(
        client,
        "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='event'",
    )
    .await
}
async fn disposition(client: &Client, event_id: &str) -> String {
    client
        .query_one(
            "SELECT disposition FROM openmybot.channel_events WHERE event_key=$1",
            &[&event_id],
        )
        .await
        .unwrap()
        .get(0)
}
fn gaps_sql(reason: &str, ended: Option<bool>) -> String {
    let ended = match ended {
        Some(true) => " AND gap_ended_at IS NOT NULL",
        Some(false) => " AND gap_ended_at IS NULL",
        None => "",
    };
    format!(
        "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='gap' AND gap_reason='{reason}'{ended}"
    )
}
async fn gaps(client: &Client, reason: &str, ended: Option<bool>) -> i64 {
    count(client, &gaps_sql(reason, ended)).await
}
async fn receiver_state(client: &Client, id: Uuid) -> (String, Option<String>) {
    let row = client
        .query_one(
            "SELECT status,status_reason FROM openmybot.channel_bindings WHERE binding_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}
async fn finished(task: &mut Task) -> Result<(), omb_channels::ChannelError> {
    tokio::time::timeout(Duration::from_secs(20), task.finished())
        .await
        .unwrap()
}
async fn fail_key(client: &Client, key: &str) {
    client.batch_execute(&format!("CREATE FUNCTION openmybot.test_fail_event() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_key='{key}' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END$$; CREATE TRIGGER test_fail_event BEFORE INSERT ON openmybot.channel_events FOR EACH ROW EXECUTE FUNCTION openmybot.test_fail_event();")).await.unwrap();
}
async fn heal(client: &Client) {
    client.batch_execute("DROP TRIGGER test_fail_event ON openmybot.channel_events; DROP FUNCTION openmybot.test_fail_event();").await.unwrap();
}
/// Every delivery and event row as JSON text.
async fn dump(client: &Client) -> String {
    client
        .query_one(
            "SELECT concat_ws(' ',(SELECT json_agg(d)::text FROM openmybot.deliveries d),(SELECT json_agg(e)::text FROM openmybot.channel_events e))",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}
async fn suspend_row(client: &Client, binding: Uuid) {
    assert_eq!(
        client
            .execute(
                "UPDATE openmybot.channel_bindings SET status='suspended',status_reason='credential_rejected',suspended_at=statement_timestamp() WHERE binding_id=$1",
                &[&binding],
            )
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn connects_with_the_endpoint_url_and_pings_with_the_url_service_id() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let connected = Instant::now();
    until("three pings", || env.fake.pings().len() >= 3).await;
    let pings = env.fake.pings();
    assert!(pings[0].at <= connected + Duration::from_millis(300));
    assert!(pings[0].valid);
    assert_eq!(pings[0].service, 7);
    assert!(pings[2].at <= connected + Duration::from_millis(1600));
    for pair in pings[..3].windows(2) {
        assert!(pair[1].at - pair[0].at >= Duration::from_millis(400));
        assert!(pair[1].valid && pair[1].service == 7);
    }
    task.stop().await;
    let endpoint = env.fake.calls(ENDPOINT_PATH);
    assert_eq!(endpoint.len(), 1);
    assert_eq!(endpoint[0].method, "POST");
    assert_eq!(
        serde_json::from_slice::<Value>(&endpoint[0].body).unwrap(),
        json!({"AppID": APP_ID, "AppSecret": SECRET})
    );
    assert_eq!(
        env.fake.handshakes(),
        ["/ws?device_id=fake-device&service_id=7"]
    );
    assert!(env.fake.calls(TOKEN_PATH).is_empty());
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='gap'"
        )
        .await,
        0
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn text_event_is_acked_only_after_its_commit() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let lock = env.hold("ev_commit").await;
    assert!(env.fake.push_event(&text("ev_commit", "hello")));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(env.acks_of("ev_commit"), 0);
    assert_eq!(rows_of(env.client(), "ev_commit").await, 0);
    let released = Instant::now();
    release(lock, "ev_commit").await;
    env.acked("ev_commit", 1).await;
    let ack = env.fake.acks().pop().unwrap();
    assert!(ack.valid && ack.at >= released);
    assert_eq!(
        disposition(env.client(), "ev_commit").await,
        "accepted_message"
    );
    tokio::time::timeout(Duration::from_secs(5), env.wake.notified())
        .await
        .unwrap();
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn commit_after_the_budget_withholds_the_ack_and_the_redelivery_is_acked_as_duplicate() {
    let mut env = Env::new().await;
    let task = env
        .start(Timings {
            fs_ack_budget: Duration::from_millis(300),
            ..quick()
        })
        .await;
    env.connected(1).await;
    let late = text("ev_late", "late");
    let lock = env.hold("ev_late").await;
    assert!(env.fake.push_event(&late));
    tokio::time::sleep(Duration::from_millis(600)).await;
    release(lock, "ev_late").await;
    rows_reach(
        env.client(),
        "SELECT count(*) FROM openmybot.channel_events WHERE event_key='ev_late'",
        1,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(env.acks_of("ev_late"), 0);
    assert_eq!(env.fake.handshakes().len(), 1);
    assert_eq!(gaps(env.client(), "stream_broken", None).await, 0);
    assert!(env.fake.push_event(&late));
    env.acked("ev_late", 1).await;
    assert_eq!(rows_of(env.client(), "ev_late").await, 1);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn uncommitted_acceptance_sends_no_ack_keeps_the_connection_and_heals_on_redelivery() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    fail_key(env.client(), "ev_fail").await;
    let failing = text("ev_fail", "boom");
    assert!(env.fake.push_event(&failing));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(env.acks_of("ev_fail"), 0);
    assert_eq!(rows_of(env.client(), "ev_fail").await, 0);
    assert_eq!(env.fake.handshakes().len(), 1);
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='gap'"
        )
        .await,
        0
    );
    assert!(env.fake.push_event(&text("ev_ok", "fine")));
    env.acked("ev_ok", 1).await;
    assert_eq!(disposition(env.client(), "ev_ok").await, "accepted_message");
    heal(env.client()).await;
    assert!(env.fake.push_event(&failing));
    env.acked("ev_fail", 1).await;
    assert_eq!(rows_of(env.client(), "ev_fail").await, 1);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn redelivery_with_the_same_content_adds_no_row_and_is_acked_each_time() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let duplicate = text("ev_dup", "same");
    assert!(env.fake.push_event(&duplicate));
    assert!(env.fake.push_event(&duplicate));
    env.acked("ev_dup", 2).await;
    task.stop().await;
    let row = env
        .client()
        .query_one(
            "SELECT disposition,dispatch_status FROM openmybot.channel_events WHERE event_key='ev_dup'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (row.get::<_, String>(0), row.get::<_, String>(1)),
        ("accepted_message".to_owned(), "pending".to_owned())
    );
    assert_eq!(rows_of(env.client(), "ev_dup").await, 1);
    assert_eq!(env.counters.event_conflict.load(Ordering::Relaxed), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn same_event_id_with_changed_content_counts_a_conflict_and_is_acked() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    assert!(env.fake.push_event(&text("ev_c", "a")));
    env.acked("ev_c", 1).await;
    assert!(env.fake.push_event(&text("ev_c", "b")));
    env.acked("ev_c", 2).await;
    task.stop().await;
    assert_eq!(rows_of(env.client(), "ev_c").await, 1);
    let stored: String = env
        .client()
        .query_one(
            "SELECT text FROM openmybot.channel_events WHERE event_key='ev_c'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, "a");
    assert_eq!(env.counters.event_conflict.load(Ordering::Relaxed), 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn rejected_and_dropped_dispositions_are_acked() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let mut malformed = text("ev_malformed", "x");
    malformed["header"]
        .as_object_mut()
        .unwrap()
        .remove("create_time");
    let mut old = text("ev_old", "x");
    old["header"]["create_time"] = json!((now_ms() - 25 * 3600 * 1000).to_string());
    for (value, expected) in [
        (
            message(
                "ev_image",
                "ou_user",
                "p2p",
                "image",
                r#"{"image_key":"img_1"}"#,
            ),
            "rejected_unsupported",
        ),
        (malformed, "rejected_malformed"),
        (old, "rejected_outside_window"),
        (
            message("ev_group", "ou_user", "group", "text", &content("x")),
            "dropped_not_private",
        ),
        (
            message("ev_unbound", "ou_stranger", "p2p", "text", &content("x")),
            "dropped_unbound",
        ),
    ] {
        let event_id = value["header"]["event_id"].as_str().unwrap().to_owned();
        assert!(env.fake.push_event(&value));
        env.acked(&event_id, 1).await;
        assert_eq!(disposition(env.client(), &event_id).await, expected);
    }
    suspend_binding(env.client(), env.sender).await;
    assert!(env.fake.push_event(&text("ev_inactive", "x")));
    env.acked("ev_inactive", 1).await;
    assert_eq!(
        disposition(env.client(), "ev_inactive").await,
        "dropped_inactive"
    );
    task.stop().await;
    for event_id in [
        "ev_image",
        "ev_malformed",
        "ev_old",
        "ev_group",
        "ev_unbound",
        "ev_inactive",
    ] {
        assert_eq!(env.acks_of(event_id), 1, "{event_id}");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unparseable_and_non_receive_events_are_counted_without_rows_and_acked() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let mut old_schema = text("ev_schema", "x");
    old_schema["schema"] = json!("1.0");
    let mut without_id = text("ev_without_id", "x");
    without_id["header"]
        .as_object_mut()
        .unwrap()
        .remove("event_id");
    for payload in [
        old_schema,
        without_id,
        json!("not an object"),
        unsupported("ev_read"),
    ] {
        assert!(env.fake.push_event(&payload));
    }
    until("four acks", || env.fake.acks().len() == 4).await;
    task.stop().await;
    assert!(env.fake.acks().iter().all(|ack| ack.valid));
    assert_eq!(
        env.counters
            .platform_payload_unparseable
            .load(Ordering::Relaxed),
        3
    );
    assert_eq!(env.counters.unsupported_update.load(Ordering::Relaxed), 1);
    assert_eq!(events(env.client()).await, 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn card_and_unknown_type_frames_are_ignored_without_ack() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    for kind in ["card", "other"] {
        let frame = env.fake.data_frame(kind, &text(&format!("ev_{kind}"), "x"));
        assert!(env.fake.push_frame(frame));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(env.fake.acks().is_empty());
    assert_eq!(events(env.client()).await, 0);
    assert_eq!(
        env.counters
            .platform_payload_unparseable
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(env.counters.unsupported_update.load(Ordering::Relaxed), 0);
    assert!(env.fake.push_event(&text("ev_after", "x")));
    env.acked("ev_after", 1).await;
    assert_eq!(env.fake.acks().len(), 1);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn receiver_not_active_withholds_the_ack_and_ends_the_receiver() {
    let mut env = Env::new().await;
    let mut task = env.start(quick()).await;
    env.connected(1).await;
    suspend_row(env.client(), env.receiver).await;
    assert!(env.fake.push_event(&text("ev_x", "x")));
    let ended = tokio::time::timeout(Duration::from_secs(5), task.finished())
        .await
        .unwrap();
    assert_eq!(ended, Ok(()));
    task.stop().await;
    assert_eq!(env.acks_of("ev_x"), 0);
    assert_eq!(events(env.client()).await, 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn fragmented_event_is_reassembled_and_acked_once_echoing_the_completing_fragment() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let body = "段".repeat(1000);
    let frames = env.fake.fragment_frames(&text("ev_frag", &body), 3);
    for seq in [2, 0, 1] {
        assert!(env.fake.push_frame(frames[seq].clone()));
    }
    env.acked("ev_frag", 1).await;
    let stored: String = env
        .client()
        .query_one(
            "SELECT text FROM openmybot.channel_events WHERE event_key='ev_frag'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, body);
    tokio::time::sleep(Duration::from_millis(300)).await;
    task.stop().await;
    let acks = env.fake.acks();
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].seq.as_deref(), Some("1"));
    assert!(acks[0].valid);
    assert_eq!(rows_of(env.client(), "ev_frag").await, 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn fragments_left_incomplete_past_the_ttl_are_dropped_without_ack() {
    let mut env = Env::new().await;
    let task = env
        .start(Timings {
            fs_fragment_ttl: Duration::from_millis(200),
            ..quick()
        })
        .await;
    env.connected(1).await;
    let frames = env
        .fake
        .fragment_frames(&text("ev_ttl", &"y".repeat(300)), 3);
    assert!(env.fake.push_frame(frames[0].clone()));
    assert!(env.fake.push_frame(frames[1].clone()));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(env.fake.push_frame(frames[2].clone()));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(rows_of(env.client(), "ev_ttl").await, 0);
    assert!(env.fake.acks().is_empty());
    for frame in &frames {
        assert!(env.fake.push_frame(frame.clone()));
    }
    env.acked("ev_ttl", 1).await;
    assert_eq!(rows_of(env.client(), "ev_ttl").await, 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    task.stop().await;
    assert_eq!(env.fake.acks().len(), 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn frame_or_reassembled_event_over_frame_max_breaks_the_stream() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    assert!(
        env.fake
            .push_event(&text("ev_big", &"z".repeat(FS_FRAME_MAX + 1)))
    );
    env.connected(2).await;
    rows_reach(env.client(), &gaps_sql("stream_broken", Some(true)), 1).await;
    for frame in env
        .fake
        .fragment_frames(&text("ev_huge", &"h".repeat(FS_FRAME_MAX * 3 / 2)), 3)
    {
        env.fake.push_frame(frame);
    }
    env.connected(3).await;
    rows_reach(env.client(), &gaps_sql("stream_broken", Some(true)), 2).await;
    task.stop().await;
    assert_eq!(gaps(env.client(), "stream_broken", None).await, 2);
    assert_eq!(events(env.client()).await, 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn undecodable_binary_frames_are_counted_and_text_messages_are_ignored() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let mut r5 = vec![0x08];
    r5.extend([0xff; 10]);
    r5.push(0x01);
    for frame in [vec![0x0a, 0x00], r5] {
        assert!(env.fake.push_frame(frame));
    }
    until("two unparseable frames", || {
        env.counters
            .platform_payload_unparseable
            .load(Ordering::Relaxed)
            == 2
    })
    .await;
    assert!(env.fake.acks().is_empty());
    assert!(env.fake.push_text("hello"));
    assert!(env.fake.push_event(&text("ev_after", "x")));
    env.acked("ev_after", 1).await;
    task.stop().await;
    assert_eq!(
        env.counters
            .platform_payload_unparseable
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(env.fake.handshakes().len(), 1);
    assert_eq!(env.fake.acks().len(), 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_command_hands_the_binding_to_the_canceller_and_is_acked() {
    let mut env = Env::new().await;
    insert_event_for_run(env.client(), env.sender, "run-c", "thread-F", "dispatched").await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    assert!(env.fake.push_event(&text("ev_cancel", "/cancel")));
    let cancelled = tokio::time::timeout(Duration::from_secs(5), env.cancels.recv())
        .await
        .unwrap();
    assert_eq!(cancelled, Some(env.sender));
    env.acked("ev_cancel", 1).await;
    task.stop().await;
    let rows = env
        .client()
        .query("SELECT kind,chat_key,body FROM openmybot.deliveries", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].get::<_, String>(0),
            rows[0].get::<_, String>(1),
            rows[0].get::<_, String>(2),
        ),
        (
            "control_reply".to_owned(),
            "feishu:oc_chat".to_owned(),
            OMB_REPLY_CANCEL_REQUESTED_V1.to_owned(),
        )
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn endpoint_server_errors_open_one_connect_failed_gap_until_the_next_101() {
    let mut env = Env::new().await;
    for reply in [
        respond(503, "{}"),
        respond(200, r#"{"code":1}"#),
        respond(200, r#"{"code":1000040343}"#),
        respond(200, r#"{"code":0,"data":{"URL":""}}"#),
        respond(200, r#"{"code":0}"#),
        Reply::Disconnect,
        Reply::Hang,
    ] {
        env.fake.script(ENDPOINT_PATH, reply);
    }
    let task = env.start(quick()).await;
    env.connected(1).await;
    rows_reach(env.client(), &gaps_sql("connect_failed", Some(true)), 1).await;
    task.stop().await;
    assert_eq!(env.fake.handshakes().len(), 1);
    assert_eq!(gaps(env.client(), "connect_failed", None).await, 1);
    assert!(env.fake.calls(ENDPOINT_PATH).len() >= 8);
    assert_eq!(
        receiver_state(env.client(), env.receiver).await,
        ("active".to_owned(), None)
    );
    assert!(env.fake.calls(TOKEN_PATH).is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn endpoint_client_error_code_suspends_credential_rejected_and_ends() {
    let mut env = Env::new().await;
    env.fake
        .script(ENDPOINT_PATH, respond(200, r#"{"code":10014,"msg":"x"}"#));
    let mut task = env.start(quick()).await;
    assert_eq!(finished(&mut task).await, Ok(()));
    task.stop().await;
    assert_eq!(
        receiver_state(env.client(), env.receiver).await,
        (
            "suspended".to_owned(),
            Some("credential_rejected".to_owned())
        )
    );
    assert_eq!(
        gaps(env.client(), "receiver_suspended", Some(false)).await,
        1
    );
    assert!(env.fake.handshakes().is_empty());
    assert_eq!(env.fake.calls(ENDPOINT_PATH).len(), 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn handshake_403_suspends_credential_rejected_and_ends() {
    let mut env = Env::new().await;
    env.fake.script_handshake(Handshake::Reject {
        status: 403,
        handshake_status: Some("403".to_owned()),
        autherrcode: None,
    });
    let mut task = env.start(quick()).await;
    assert_eq!(finished(&mut task).await, Ok(()));
    task.stop().await;
    assert_eq!(
        receiver_state(env.client(), env.receiver).await,
        (
            "suspended".to_owned(),
            Some("credential_rejected".to_owned())
        )
    );
    assert_eq!(
        gaps(env.client(), "receiver_suspended", Some(false)).await,
        1
    );
    assert!(env.fake.handshakes().is_empty());
    assert_eq!(env.fake.calls(ENDPOINT_PATH).len(), 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn handshake_514_and_other_rejections_are_connect_failed() {
    let mut env = Env::new().await;
    for (handshake_status, autherrcode) in [
        (Some("514"), Some("1000040350")),
        (Some("514"), Some("1")),
        (None, None),
    ] {
        env.fake.script_handshake(Handshake::Reject {
            status: 500,
            handshake_status: handshake_status.map(str::to_owned),
            autherrcode: autherrcode.map(str::to_owned),
        });
    }
    let task = env.start(quick()).await;
    env.connected(1).await;
    rows_reach(env.client(), &gaps_sql("connect_failed", Some(true)), 1).await;
    task.stop().await;
    assert_eq!(gaps(env.client(), "connect_failed", None).await, 1);
    assert_eq!(
        receiver_state(env.client(), env.receiver).await,
        ("active".to_owned(), None)
    );
    assert!(env.fake.calls(ENDPOINT_PATH).len() >= 4);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unreachable_port_and_hanging_upgrade_are_connect_failed() {
    let mut env = Env::new().await;
    env.fake.set_ws_url(Some(format!(
        "ws://127.0.0.1:{}/ws?device_id=fake-device&service_id=7",
        FakeTelegram::unused_port()
    )));
    let task = env.start(quick()).await;
    rows_reach(env.client(), &gaps_sql("connect_failed", Some(false)), 1).await;
    env.fake.set_ws_url(None);
    env.connected(1).await;
    rows_reach(env.client(), &gaps_sql("connect_failed", Some(true)), 1).await;
    task.stop().await;
    env.fake.script_handshake(Handshake::Hang);
    let requests = env.fake.calls(ENDPOINT_PATH).len();
    let restarted = Instant::now();
    let task = env
        .start(Timings {
            http_send_timeout: Duration::from_millis(500),
            ..quick()
        })
        .await;
    rows_reach(env.client(), &gaps_sql("connect_failed", None), 2).await;
    assert!(restarted.elapsed() < Duration::from_secs(2));
    until("a second endpoint request", || {
        env.fake.calls(ENDPOINT_PATH).len() >= requests + 2
    })
    .await;
    assert!(restarted.elapsed() < Duration::from_secs(3));
    env.connected(2).await;
    rows_reach(env.client(), &gaps_sql("connect_failed", Some(true)), 2).await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn server_close_and_read_timeout_are_stream_broken() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    env.fake.disconnect();
    env.connected(2).await;
    rows_reach(env.client(), &gaps_sql("stream_broken", Some(true)), 1).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let silent = Instant::now();
    let silent_wall = OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1e9;
    env.fake.set_silent(true);
    // The last ping before the silence was answered; the read deadline runs from that pong.
    let anchor = env
        .fake
        .pings()
        .into_iter()
        .rfind(|ping| ping.at <= silent)
        .unwrap();
    let last_pong = silent_wall - (silent - anchor.at).as_secs_f64();
    rows_reach(env.client(), &gaps_sql("stream_broken", None), 2).await;
    assert!(silent.elapsed() < Duration::from_secs(3));
    let started: f64 = env
        .client()
        .query_one(
            "SELECT extract(epoch FROM gap_started_at)::float8 FROM openmybot.channel_events WHERE gap_reason='stream_broken' ORDER BY gap_started_at DESC LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(started >= last_pong + 1.0, "{started} < {last_pong} + 1.0");
    // The read timeout reconnected at least once more.
    env.fake.set_silent(false);
    env.connected(3).await;
    rows_reach(
        env.client(),
        "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='gap' AND gap_ended_at IS NULL",
        0,
    )
    .await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn ping_interval_follows_client_config_and_reconnect_fields_are_ignored() {
    let mut env = Env::new().await;
    env.fake.set_client_config(Some(json!({"PingInterval": 1, "ReconnectInterval": 3600, "ReconnectNonce": 3600, "ReconnectCount": 0})));
    let task = env.start(quick()).await;
    env.connected(1).await;
    until("four pings", || env.fake.pings().len() >= 4).await;
    for pair in env.fake.pings()[..4].windows(2) {
        let interval = pair[1].at - pair[0].at;
        assert!(
            (Duration::from_millis(900)..=Duration::from_millis(1500)).contains(&interval),
            "{interval:?}"
        );
    }
    env.fake.set_pong_config(Some(json!({"PingInterval": 2})));
    let changed = Instant::now();
    let answered =
        |pings: &[omb_channels::fake_feishu::Ping]| pings.iter().position(|ping| ping.at > changed);
    until("a ping answered with the new config", || {
        answered(&env.fake.pings()).is_some()
    })
    .await;
    let first = answered(&env.fake.pings()).unwrap();
    until("the ping after it", || env.fake.pings().len() > first + 1).await;
    let pings = env.fake.pings();
    assert!(pings[first + 1].at - pings[first].at >= Duration::from_millis(1800));
    env.fake.disconnect();
    let disconnected = Instant::now();
    env.connected(2).await;
    assert!(disconnected.elapsed() < Duration::from_secs(1));
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn read_deadline_extends_with_every_message() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    env.fake.set_silent(true);
    let started = Instant::now();
    let mut sent = 0;
    while started.elapsed() < Duration::from_secs(3) {
        assert!(
            env.fake
                .push_event(&unsupported(&format!("ev_keep_{sent}")))
        );
        sent += 1;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(gaps(env.client(), "stream_broken", None).await, 0);
    assert_eq!(env.fake.handshakes().len(), 1);
    let stopped = Instant::now();
    rows_reach(env.client(), &gaps_sql("stream_broken", None), 1).await;
    assert!(stopped.elapsed() < Duration::from_millis(2500));
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn secret_and_connection_url_never_reach_rows_or_debug() {
    let mut env = Env::new().await;
    let endpoint = env.fake.endpoint();
    let mut url = endpoint.api_base.clone();
    url.set_path(ENDPOINT_PATH);
    let budget = SafeHttpBudget::new(64 * 1024, Duration::from_secs(5)).unwrap();
    let response = endpoint
        .dialer
        .execute(
            SafeHttpRequest::post_json_with_scheme(
                url,
                endpoint.scheme,
                b"{}".to_vec(),
                None,
                budget,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let mut ws = Url::parse(body["data"]["URL"].as_str().unwrap()).unwrap();
    ws.set_query(Some(
        "device_id=SENTINEL-device&service_id=7&ticket=SENTINEL-ticket",
    ));
    env.fake.set_ws_url(Some(ws.to_string()));
    let mut task = env.start(quick()).await;
    env.connected(1).await;
    env.fake
        .script(ENDPOINT_PATH, respond(200, r#"{"code":10014}"#));
    env.fake.disconnect();
    let ended = finished(&mut task).await;
    task.stop().await;
    assert_eq!(gaps(env.client(), "stream_broken", None).await, 1);
    assert_eq!(
        receiver_state(env.client(), env.receiver).await.0,
        "suspended"
    );
    let events: String = env
        .client()
        .query_one(
            "SELECT coalesce(string_agg(row_to_json(e)::text, ','), '') FROM openmybot.channel_events e",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let bindings: String = env
        .client()
        .query_one(
            "SELECT coalesce(string_agg((to_jsonb(b)-'credential_envelope')::text, ','), '') FROM openmybot.channel_bindings b",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let rendered = format!(
        "{events} {bindings} {:?} {:?} {ended:?}",
        list_active_receivers(env.client(), FEISHU).await,
        receiver_row(env.client(), env.receiver, deadline()).await,
    );
    assert!(rendered.contains("stream_broken"));
    assert_eq!(rendered.matches("SENTINEL").count(), 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn events_during_a_disconnect_are_lost_and_redelivery_adds_no_row() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let before = text("ev_before", "before");
    assert!(env.fake.push_event(&before));
    env.acked("ev_before", 1).await;
    for _ in 0..3 {
        env.fake.script_handshake(Handshake::Reject {
            status: 500,
            handshake_status: None,
            autherrcode: None,
        });
    }
    env.fake.disconnect();
    assert!(!env.fake.push_event(&text("ev_during", "during")));
    assert_eq!(env.fake.dropped(), 1);
    env.connected(2).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(rows_of(env.client(), "ev_during").await, 0);
    assert!(env.fake.push_event(&before));
    env.acked("ev_before", 2).await;
    assert_eq!(rows_of(env.client(), "ev_before").await, 1);
    rows_reach(env.client(), &gaps_sql("stream_broken", Some(true)), 1).await;
    task.stop().await;
    let status = channel_status(env.client()).await.unwrap();
    let receiver = status
        .iter()
        .find(|receiver| receiver.binding_id == env.receiver)
        .unwrap();
    assert_eq!(receiver.channel, FEISHU);
    assert_eq!(receiver.gaps.len(), 1);
    assert_eq!(receiver.gaps[0].reason, "stream_broken");
    assert!(receiver.gaps[0].ended_at.is_some());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unbound_and_group_messages_are_dropped_silently_and_acked() {
    let mut env = Env::new().await;
    let receiver = env.start(quick()).await;
    let sender = env.start_sender(quick()).await;
    env.connected(1).await;
    for (value, expected) in [
        (
            message("ev_hello", "ou_stranger", "p2p", "text", &content("hello")),
            "dropped_unbound",
        ),
        (
            message(
                "ev_pair",
                "ou_stranger",
                "p2p",
                "text",
                &content("/pair WRONG1"),
            ),
            "pairing_failed",
        ),
        (
            message("ev_help", "ou_stranger", "p2p", "text", &content("/help")),
            "dropped_unbound",
        ),
        (
            message(
                "ev_stranger_group",
                "ou_stranger",
                "group",
                "text",
                &content("hi"),
            ),
            "dropped_not_private",
        ),
    ] {
        let event_id = value["header"]["event_id"].as_str().unwrap().to_owned();
        assert!(env.fake.push_event(&value));
        env.acked(&event_id, 1).await;
        assert_eq!(disposition(env.client(), &event_id).await, expected);
    }
    let row = env
        .client()
        .query_one(
            "SELECT text IS NULL AND fingerprint IS NULL AND sender_key IS NULL AND chat_key IS NULL FROM openmybot.channel_events WHERE event_key='ev_hello'",
            &[],
        )
        .await
        .unwrap();
    assert!(row.get::<_, bool>(0));
    tokio::time::sleep(Duration::from_millis(300)).await;
    receiver.stop().await;
    sender.stop().await;
    assert_eq!(
        count(env.client(), "SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    assert!(env.fake.sent_messages().is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unopenable_envelope_suspends_credential_rejected_without_network() {
    let mut env = Env::new().await;
    env.envelope = seal_as(env.receiver, "openmybot.telegram", SECRET);
    let mut task = env.start(quick()).await;
    assert_eq!(finished(&mut task).await, Ok(()));
    task.stop().await;
    assert_eq!(
        receiver_state(env.client(), env.receiver).await,
        (
            "suspended".to_owned(),
            Some("credential_rejected".to_owned())
        )
    );
    assert!(env.fake.requests().is_empty());
    assert!(env.fake.handshakes().is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn disconnect_racing_the_ack_never_duplicates_the_event() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    for round in 1..=10 {
        let event_id = format!("ev_race_{round}");
        let value = text(&event_id, &format!("race {round}"));
        env.fake.push_event(&value);
        env.fake.disconnect();
        env.connected(round + 1).await;
        let reconnected = Instant::now();
        assert!(env.fake.push_event(&value));
        until(&format!("an ack of {event_id} after the reconnect"), || {
            env.fake
                .acks()
                .iter()
                .any(|ack| ack.message_id == event_id && ack.valid && ack.at >= reconnected)
        })
        .await;
        assert_eq!(rows_of(env.client(), &event_id).await, 1, "round {round}");
        assert_eq!(events(env.client()).await, round as i64, "round {round}");
        assert_eq!(env.counters.event_conflict.load(Ordering::Relaxed), 0);
    }
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stop_during_a_stalled_ack_write_ends_the_receiver_without_the_write_timeout() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    // Each unparseable event is acknowledged with its megabyte pad; with the platform reading
    // nothing, one acknowledgement write blocks once the socket buffers are full.
    env.fake.set_stalled(true);
    for _ in 0..24 {
        assert!(
            env.fake
                .push_frame(env.fake.padded_event_frame(&json!({}), 1_000_000))
        );
    }
    let handled = || {
        env.counters
            .platform_payload_unparseable
            .load(Ordering::Relaxed)
    };
    until("the first padded event", || handled() > 0).await;
    let mut seen = 0;
    while handled() != seen {
        seen = handled();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(seen < 24, "{seen}");
    let stopped = Instant::now();
    task.stop().await;
    assert!(
        stopped.elapsed() < Duration::from_secs(1),
        "{:?}",
        stopped.elapsed()
    );
    assert_eq!(gaps(env.client(), "stream_broken", None).await, 0);
    rows_reach(env.client(), OTHER_SESSIONS, 0).await;
    env.fake.disconnect();
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stop_during_a_stalled_acceptance_ends_the_receiver_and_the_redelivery_is_accepted_once() {
    let mut env = Env::new().await;
    let task = env.start(quick()).await;
    env.connected(1).await;
    let stalled = text("ev_stall", "hello");
    let lock = env.hold("ev_stall").await;
    assert!(env.fake.push_event(&stalled));
    rows_reach(
        env.client(),
        "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted",
        1,
    )
    .await;
    let stopped = Instant::now();
    let stopping = tokio::spawn(task.stop());
    until("the receiver to close its connection", || {
        !env.fake.connected()
    })
    .await;
    assert!(
        stopped.elapsed() < Duration::from_millis(500),
        "{:?}",
        stopped.elapsed()
    );
    // The receiver's database session answers the stalled statement, rolls back and ends.
    release(lock, "ev_stall").await;
    tokio::time::timeout(Duration::from_secs(20), stopping)
        .await
        .unwrap()
        .unwrap();
    rows_reach(env.client(), OTHER_SESSIONS, 0).await;
    assert_eq!(rows_of(env.client(), "ev_stall").await, 0);
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory'"
        )
        .await,
        0
    );
    assert_eq!(env.acks_of("ev_stall"), 0);
    let task = env.start(quick()).await;
    env.connected(2).await;
    assert!(env.fake.push_event(&stalled));
    env.acked("ev_stall", 1).await;
    assert!(env.fake.push_event(&stalled));
    env.acked("ev_stall", 2).await;
    assert_eq!(rows_of(env.client(), "ev_stall").await, 1);
    assert_eq!(
        disposition(env.client(), "ev_stall").await,
        "accepted_message"
    );
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn feishu_reply_is_sent_with_bearer_token_chat_id_and_uuid() {
    let mut env = Env::new().await;
    let task = env.start_sender(quick()).await;
    let id = env.reply("control_reply:f1", "你好").await;
    let row = env.status(id, "sent").await;
    task.stop().await;
    assert_eq!(row["attempts"], 1);
    assert_eq!(row["platform_message_id"], "om_1");
    assert_eq!(
        env.token_bodies(),
        [json!({"app_id": APP_ID, "app_secret": SECRET})]
    );
    assert_eq!(
        env.fake.sent_messages(),
        [FeishuSent {
            query: vec![("receive_id_type".to_owned(), "chat_id".to_owned())],
            authorization: Some("Bearer t-fake-1".to_owned()),
            receive_id: "oc_chat".to_owned(),
            msg_type: "text".to_owned(),
            content: "{\"text\":\"你好\"}".to_owned(),
            uuid: "95f12bd8e78f5b6e7d886b7f16c05d03".to_owned(),
            keys: 4,
        }]
    );
    let dump = dump(env.client()).await;
    assert!(dump.contains("feishu:oc_chat"));
    assert!(!dump.contains("SENTINEL"));
    assert!(!dump.contains("t-fake-1"));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn tenant_token_with_less_than_the_margin_left_is_fetched_again() {
    let mut env = Env::new().await;
    for token in ["t-short-1", "t-short-2"] {
        env.fake.script(
            TOKEN_PATH,
            respond(
                200,
                &json!({"code": 0, "tenant_access_token": token, "expire": 1800}).to_string(),
            ),
        );
    }
    let first = env.reply("control_reply:short-1", "one").await;
    let second = env.reply("control_reply:short-2", "two").await;
    let task = env.start_sender(quick()).await;
    env.status(first, "sent").await;
    env.status(second, "sent").await;
    task.stop().await;
    assert_eq!(env.fake.calls(TOKEN_PATH).len(), 2);
    assert_eq!(
        env.authorizations(),
        [
            Some("Bearer t-short-1".to_owned()),
            Some("Bearer t-short-2".to_owned())
        ]
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn token_failures_retry_by_class_and_rejection_fails() {
    let mut env = Env::new().await;
    for (index, (reply, code)) in [
        (Reply::Disconnect, "unreachable"),
        (respond(429, "{}"), "rate_limited"),
        (respond(503, "{}"), "server_error"),
        (respond(400, r#"{"code":99991400}"#), "rate_limited"),
    ]
    .into_iter()
    .enumerate()
    {
        // A new sender has no cached token, so each row asks for one.
        env.fake.script(TOKEN_PATH, reply);
        let messages = env.fake.calls(MESSAGES_PATH).len();
        let id = env.reply(&format!("control_reply:t{index}"), "x").await;
        let task = env.start_sender(quick()).await;
        let first = env
            .until(id, |row| row["attempts"] == 1 && row["status"] == "pending")
            .await;
        assert_eq!(first["last_error_code"], code);
        assert!(first["next_attempt_at"].is_string());
        assert_eq!(env.fake.calls(MESSAGES_PATH).len(), messages);
        let row = env.status(id, "sent").await;
        assert_eq!(row["attempts"], 2);
        task.stop().await;
    }
    env.fake
        .script(TOKEN_PATH, respond(200, r#"{"code":10014}"#));
    let messages = env.fake.calls(MESSAGES_PATH).len();
    let id = env.reply("control_reply:rejected", "x").await;
    let task = env.start_sender(quick()).await;
    let row = env.status(id, "failed").await;
    task.stop().await;
    assert_eq!(row["last_error_code"], "client_error");
    assert!(row["finished_at"].is_string());
    assert_eq!(env.fake.calls(MESSAGES_PATH).len(), messages);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn message_outcomes_follow_the_closed_classification() {
    let mut env = Env::new().await;
    let task = env.start_sender(quick()).await;
    for (index, (reply, code)) in [
        (respond(400, r#"{"code":230020}"#), "rate_limited"),
        (respond(400, r#"{"code":99991400}"#), "rate_limited"),
        (respond(429, "{}"), "rate_limited"),
        (respond(500, "{}"), "server_error"),
    ]
    .into_iter()
    .enumerate()
    {
        env.fake.script(MESSAGES_PATH, reply);
        let id = env.reply(&format!("control_reply:retry{index}"), "x").await;
        let first = env
            .until(id, |row| row["attempts"] == 1 && row["status"] == "pending")
            .await;
        assert_eq!(first["last_error_code"], code);
        assert_eq!(env.status(id, "sent").await["attempts"], 2);
    }
    for (index, (status, body)) in [(200, r#"{"code":230001}"#), (400, r#"{"code":230002}"#)]
        .into_iter()
        .enumerate()
    {
        env.fake.script(MESSAGES_PATH, respond(status, body));
        let id = env
            .reply(&format!("control_reply:client{index}"), "x")
            .await;
        let row = env.status(id, "failed").await;
        assert_eq!(row["last_error_code"], "client_error");
        assert_eq!(row["attempts"], 1);
    }
    for (index, reply) in [Reply::Disconnect, respond(200, "not json")]
        .into_iter()
        .enumerate()
    {
        env.fake.script(MESSAGES_PATH, reply);
        let requests = env.fake.calls(MESSAGES_PATH).len();
        let id = env
            .reply(&format!("control_reply:unknown{index}"), "x")
            .await;
        let row = env.status(id, "unknown").await;
        assert_eq!(row["last_error_code"], "result_unknown");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(env.fake.calls(MESSAGES_PATH).len(), requests + 1);
    }
    task.stop().await;
    env.fake.script(
        MESSAGES_PATH,
        Reply::Delayed {
            delay: Duration::from_secs(1),
            status: 200,
            body: br#"{"code":0,"data":{"message_id":"om_late"}}"#.to_vec(),
        },
    );
    let id = env.reply("control_reply:delayed", "x").await;
    let task = env
        .start_sender(Timings {
            http_send_timeout: Duration::from_millis(300),
            ..quick()
        })
        .await;
    let row = env.status(id, "unknown").await;
    task.stop().await;
    assert_eq!(row["last_error_code"], "result_unknown");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn definite_failures_retry_on_the_plan_until_exhausted() {
    let mut env = Env::new().await;
    for _ in 0..6 {
        env.fake.script(MESSAGES_PATH, respond(500, "{}"));
    }
    let id = env.reply("control_reply:exhaust", "x").await;
    let task = env.start_sender(quick()).await;
    let row = env.status(id, "failed").await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    task.stop().await;
    assert_eq!(row["last_error_code"], "retries_exhausted");
    assert_eq!(row["attempts"], 6);
    let requests = env.fake.calls(MESSAGES_PATH);
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

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn run_result_for_a_feishu_binding_is_composed_and_sent() {
    let mut env = Env::new().await;
    let event =
        insert_event_for_run(env.client(), env.sender, "run-9", "thread-F", "dispatched").await;
    set_terminal(env.client(), event, "succeeded").await;
    insert_ended_session(
        env.client(),
        env.sender,
        "run-9",
        "result_success",
        Some("done"),
        &["a.txt"],
    )
    .await;
    let id = insert_delivery(
        env.client(),
        env.sender,
        "run_result",
        "result:run-9",
        None,
        "pending",
        None,
    )
    .await;
    let task = env.start_sender(quick()).await;
    env.status(id, "sent").await;
    task.stop().await;
    let sent = &env.fake.sent_messages()[0];
    let text: Value = serde_json::from_str(&sent.content).unwrap();
    assert_eq!(
        text["text"],
        "[OpenMyBot] 已完成 · run run-9\ndone\n成果：a.txt"
    );
    assert_eq!(sent.uuid, "10587490d704f9cc303b3c5e1ad34e44");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn missing_or_unopenable_feishu_receiver_takes_receiver_inactive() {
    let mut env = Env::new().await;
    suspend_row(env.client(), env.receiver).await;
    let id = env.reply("control_reply:inactive", "x").await;
    let task = env
        .start_sender(Timings {
            delivery_retry: [Duration::from_millis(500); 5],
            ..quick()
        })
        .await;
    let inactive = |attempts: i64| {
        move |row: &Value| {
            row["attempts"] == attempts
                && row["status"] == "pending"
                && row["last_error_code"] == "receiver_inactive"
        }
    };
    env.until(id, inactive(1)).await;
    env.client()
        .execute(
            "UPDATE openmybot.channel_bindings SET status='active',status_reason=NULL,suspended_at=NULL,credential_envelope=$2 WHERE binding_id=$1",
            &[&env.receiver, &seal_as(env.receiver, "openmybot.telegram", SECRET)],
        )
        .await
        .unwrap();
    env.until(id, inactive(2)).await;
    insert_receiver_with(
        env.client(),
        Uuid::now_v7(),
        "telegram",
        "1001",
        "telegram-envelope",
    )
    .await;
    env.until(id, inactive(3)).await;
    assert!(env.fake.requests().is_empty());
    env.client()
        .execute(
            "UPDATE openmybot.channel_bindings SET credential_envelope=$2 WHERE binding_id=$1",
            &[&env.receiver, &seal(env.receiver, SECRET)],
        )
        .await
        .unwrap();
    let row = env.status(id, "sent").await;
    task.stop().await;
    assert_eq!(row["attempts"], 4);
    assert_eq!(env.fake.sent_messages().len(), 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn malformed_feishu_chat_key_fails_client_error_without_request() {
    let mut env = Env::new().await;
    env.client()
        .execute(
            "UPDATE openmybot.channel_bindings SET chat_key='feishu:' WHERE binding_id=$1",
            &[&env.sender],
        )
        .await
        .unwrap();
    let id = env.reply("control_reply:malformed", "x").await;
    let task = env.start_sender(quick()).await;
    let row = env.status(id, "failed").await;
    task.stop().await;
    assert_eq!(row["last_error_code"], "client_error");
    assert_eq!(row["attempts"], 1);
    assert!(env.fake.requests().is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reconfirmed_receiver_revision_refetches_the_token_with_the_new_secret() {
    let mut env = Env::new().await;
    let task = env.start_sender(quick()).await;
    let first = env.reply("control_reply:r1", "one").await;
    env.status(first, "sent").await;
    assert_eq!(
        env.token_bodies(),
        [json!({"app_id": APP_ID, "app_secret": SECRET})]
    );
    assert_eq!(env.authorizations(), [Some("Bearer t-fake-1".to_owned())]);
    suspend_receiver(
        &mut env.session.client,
        env.receiver,
        Suspension::CredentialRejected,
        deadline(),
    )
    .await
    .unwrap();
    env.client()
        .execute(
            "UPDATE openmybot.channel_bindings SET credential_envelope=$2 WHERE binding_id=$1",
            &[&env.receiver, &seal(env.receiver, SECRET_2)],
        )
        .await
        .unwrap();
    assert_eq!(
        reconfirm_binding(&mut env.session.client, env.receiver, 0, deadline())
            .await
            .unwrap(),
        2
    );
    let second = env.reply("control_reply:r2", "two").await;
    env.status(second, "sent").await;
    assert_eq!(
        env.token_bodies(),
        [
            json!({"app_id": APP_ID, "app_secret": SECRET}),
            json!({"app_id": APP_ID, "app_secret": SECRET_2})
        ]
    );
    let third = env.reply("control_reply:r3", "three").await;
    env.status(third, "sent").await;
    task.stop().await;
    assert_eq!(env.fake.calls(TOKEN_PATH).len(), 2);
    assert_eq!(
        env.authorizations(),
        [
            Some("Bearer t-fake-1".to_owned()),
            Some("Bearer t-fake-2".to_owned()),
            Some("Bearer t-fake-2".to_owned())
        ]
    );
    assert!(!dump(env.client()).await.contains("SENTINEL"));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn consecutive_sends_within_one_revision_fetch_the_token_once() {
    let mut env = Env::new().await;
    let task = env.start_sender(quick()).await;
    let first = env.reply("control_reply:s1", "one").await;
    env.status(first, "sent").await;
    let second = env.reply("control_reply:s2", "two").await;
    env.status(second, "sent").await;
    task.stop().await;
    assert_eq!(env.fake.calls(TOKEN_PATH).len(), 1);
    assert_eq!(
        env.authorizations(),
        [
            Some("Bearer t-fake-1".to_owned()),
            Some("Bearer t-fake-1".to_owned())
        ]
    );
    assert_eq!(
        read_row(env.client(), "channel_bindings", "binding_id", env.receiver).await["revision"],
        1
    );
    env.stop().await;
}
