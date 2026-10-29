//! Telegram receiver end to end: an own PostgreSQL 17.11 cluster and the loopback fake Bot API.
use omb_channels::{
    CANCEL_QUEUE, CancelRequests, Connection, Counters, CredentialProblem,
    OMB_REPLY_CANCEL_NONE_V1, OMB_REPLY_CANCEL_REQUESTED_V1, OMB_REPLY_HELP_V1, ReceiverContext,
    TG_RESPONSE_MAX, Task, Timings, start_receiver, testkit::FakeTelegram, verify_credentials,
};
use omb_store::{
    PollGapReason, ReceiverRow, migrate, open_poll_gap,
    testkit::{
        Fixture, Session, deadline, insert_event_for_run, insert_permission_row,
        insert_receiver_with, insert_sender, permission_row_json, shift_event,
    },
};
use openbot_contracts::ids::{ActorId, TenantId};
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::vault::CredentialRecordVault;
use serde_json::{Value, json};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc};
use tokio_postgres::Client;
use uuid::Uuid;

const TOKEN: &str = "1001:test-token-sentinel";

fn vault() -> CredentialRecordVault {
    CredentialRecordVault::single_key(
        TenantId::new("omb-test"),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![7; 32]).unwrap(),
    )
}
fn owner() -> ActorId {
    ActorId::new("owner")
}
fn seal_as(id: Uuid, kind: SecretKind, service: &str, token: &str) -> String {
    vault()
        .seal(
            &id,
            kind,
            SecretPrincipal::Actor(owner()),
            SecretPrincipal::Service(ServiceId::new(service)),
            &SecretBytes::new(token.as_bytes().to_vec()),
        )
        .unwrap()
}
fn seal(id: Uuid, token: &str) -> String {
    seal_as(id, SecretKind::Connector, "openmybot.telegram", token)
}
fn quick() -> Timings {
    Timings {
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(200),
        ..Timings::default()
    }
}
fn message(id: u64, from: i64, text: Option<&str>) -> Value {
    let mut message = json!({"message_id": id, "date": OffsetDateTime::now_utc().unix_timestamp(), "from": {"id": from, "is_bot": false}, "chat": {"id": from, "type": "private"}});
    if let Some(text) = text {
        message["text"] = json!(text);
    }
    json!({"update_id": id, "message": message})
}
fn text(id: u64, body: &str) -> Value {
    message(id, 42, Some(body))
}
fn batch(updates: &[Value]) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok": true, "result": updates})).unwrap()
}

struct Env {
    fixture: Fixture,
    session: Session,
    fake: FakeTelegram,
    receiver: Uuid,
    envelope: String,
    counters: Arc<Counters>,
    wake: Arc<Notify>,
    sender: Uuid,
    cancel: CancelRequests,
    cancels: mpsc::Receiver<Uuid>,
}
impl Env {
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        let receiver = Uuid::now_v7();
        let envelope = seal(receiver, TOKEN);
        insert_receiver_with(&session.client, receiver, "telegram", "1001", &envelope).await;
        let sender = insert_sender(
            &session.client,
            "telegram",
            "1001",
            "telegram:42",
            "thread-A",
        )
        .await;
        let (cancel, cancels) = mpsc::channel(CANCEL_QUEUE);
        Self {
            fixture,
            session,
            fake: FakeTelegram::start().await,
            receiver,
            envelope,
            counters: Arc::new(Counters::default()),
            wake: Arc::new(Notify::new()),
            sender,
            cancel,
            cancels,
        }
    }
    async fn start(&mut self) -> Task {
        let endpoint = self.fake.endpoint();
        self.start_at(endpoint).await
    }
    async fn start_at(&mut self, endpoint: omb_channels::TelegramEndpoint) -> Task {
        let (client, driver) = self.fixture.open().await;
        start_receiver(
            Connection { client, driver },
            ReceiverRow {
                binding_id: self.receiver,
                source_key: "1001".into(),
                credential_envelope: self.envelope.clone(),
            },
            ReceiverContext {
                vault: vault(),
                owner: owner(),
                endpoint,
                timings: quick(),
                counters: Arc::clone(&self.counters),
                wake: Arc::clone(&self.wake),
                cancel: self.cancel.clone(),
            },
        )
    }
    fn client(&self) -> &Client {
        &self.session.client
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
async fn count(client: &Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).await.unwrap().get(0)
}
async fn rows_reach(client: &Client, sql: &str, expected: i64) {
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let found = count(client, sql).await;
        if found == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < limit,
            "{sql}: {found} != {expected}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn events(client: &Client, expected: i64) {
    rows_reach(
        client,
        "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='event'",
        expected,
    )
    .await;
}
async fn keys(client: &Client) -> Vec<String> {
    client
        .query("SELECT event_key FROM openmybot.channel_events WHERE record_kind='event' ORDER BY accepted_at,record_id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}
async fn disposition(client: &Client, key: &str) -> String {
    client
        .query_one(
            "SELECT disposition FROM openmybot.channel_events WHERE event_key=$1",
            &[&key],
        )
        .await
        .unwrap()
        .get(0)
}
/// Waits until the fake has seen a `getUpdates` request satisfying `check`, after `skip` earlier ones.
async fn polled(fake: &FakeTelegram, check: impl Fn(&omb_channels::testkit::Request) -> bool) {
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while !fake.calls("getUpdates").iter().any(&check) {
        assert!(
            tokio::time::Instant::now() < limit,
            "no matching getUpdates"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn finished(task: &mut Task) -> Result<(), omb_channels::ChannelError> {
    tokio::time::timeout(Duration::from_secs(20), task.finished())
        .await
        .unwrap()
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
async fn gaps(client: &Client) -> Vec<(String, bool)> {
    client
        .query("SELECT gap_reason,gap_ended_at IS NOT NULL FROM openmybot.channel_events WHERE record_kind='gap' ORDER BY accepted_at,record_id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}
async fn gap_closed(client: &Client, reason: &str) {
    rows_reach(client, &format!("SELECT count(*) FROM openmybot.channel_events WHERE gap_reason='{reason}' AND gap_ended_at IS NOT NULL"), 1).await;
}
async fn gap_open(client: &Client, reason: &str) {
    rows_reach(client, &format!("SELECT count(*) FROM openmybot.channel_events WHERE gap_reason='{reason}' AND gap_ended_at IS NULL"), 1).await;
}
async fn fail_key(client: &Client, key: &str) {
    client.batch_execute(&format!("CREATE FUNCTION openmybot.test_fail_event() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_key='{key}' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END$$; CREATE TRIGGER test_fail_event BEFORE INSERT ON openmybot.channel_events FOR EACH ROW EXECUTE FUNCTION openmybot.test_fail_event();")).await.unwrap();
}
async fn heal(client: &Client) {
    client.batch_execute("DROP TRIGGER test_fail_event ON openmybot.channel_events; DROP FUNCTION openmybot.test_fail_event();").await.unwrap();
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn batch_is_accepted_in_ascending_update_id_order() {
    let mut env = Env::new().await;
    for id in [1, 2, 3] {
        env.fake.push_update(text(id, &format!("m{id}")));
    }
    let task = env.start().await;
    events(env.client(), 3).await;
    assert_eq!(keys(env.client()).await, ["1", "2", "3"]);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn out_of_order_batch_is_sorted_before_acceptance() {
    let mut env = Env::new().await;
    env.fake.script(
        "getUpdates",
        200,
        batch(&[text(13, "c"), text(11, "a"), text(12, "b")]),
    );
    let task = env.start().await;
    events(env.client(), 3).await;
    assert_eq!(keys(env.client()).await, ["11", "12", "13"]);
    polled(&env.fake, |r| r.param("offset") == Some("14")).await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn repeated_update_ids_across_batches_add_no_rows() {
    let mut env = Env::new().await;
    env.fake
        .script("getUpdates", 200, batch(&[text(1, "a"), text(2, "b")]));
    env.fake.script(
        "getUpdates",
        200,
        batch(&[text(2, "b"), text(3, "c"), text(3, "c")]),
    );
    env.fake.script("getUpdates", 200, batch(&[text(1, "a")]));
    let task = env.start().await;
    events(env.client(), 3).await;
    polled(&env.fake, |r| r.param("offset") == Some("4")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(keys(env.client()).await, ["1", "2", "3"]);
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.channel_events WHERE run_id IS NOT NULL"
        )
        .await,
        3
    );
    assert_eq!(env.counters.event_conflict.load(Ordering::Relaxed), 0);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn offset_advances_only_after_commit() {
    let mut env = Env::new().await;
    env.fake.push_update(text(1, "a"));
    let task = env.start().await;
    events(env.client(), 1).await;
    polled(&env.fake, |r| r.param("offset") == Some("2")).await;
    fail_key(env.client(), "2").await;
    env.fake.push_update(text(2, "b"));
    let seen = env.fake.calls("getUpdates").len();
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.fake.calls("getUpdates").len() < seen + 3 {
        assert!(tokio::time::Instant::now() < limit);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        env.fake.calls("getUpdates")[seen..]
            .iter()
            .all(|r| r.param("offset") == Some("2"))
    );
    assert_eq!(keys(env.client()).await, ["1"]);
    heal(env.client()).await;
    events(env.client(), 2).await;
    polled(&env.fake, |r| r.param("offset") == Some("3")).await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn batch_stops_at_first_failed_commit_and_refetches_it() {
    let mut env = Env::new().await;
    fail_key(env.client(), "11").await;
    for id in [10, 11, 12] {
        env.fake.push_update(text(id, "m"));
    }
    let task = env.start().await;
    events(env.client(), 1).await;
    polled(&env.fake, |r| r.param("offset") == Some("11")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(keys(env.client()).await, ["10"]);
    heal(env.client()).await;
    events(env.client(), 3).await;
    assert_eq!(keys(env.client()).await, ["10", "11", "12"]);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn restart_resumes_from_last_event_row_without_duplicates() {
    let mut env = Env::new().await;
    env.fake.push_update(text(1, "a"));
    env.fake.push_update(text(2, "b"));
    let task = env.start().await;
    events(env.client(), 2).await;
    task.stop().await;
    let before = env.fake.calls("getUpdates").len();
    env.fake
        .script("getUpdates", 200, batch(&[text(2, "b"), text(3, "c")]));
    let task = env.start().await;
    events(env.client(), 3).await;
    assert_eq!(
        env.fake.calls("getUpdates")[before].param("offset"),
        Some("3")
    );
    assert_eq!(keys(env.client()).await, ["1", "2", "3"]);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn stale_last_event_omits_offset() {
    let mut env = Env::new().await;
    env.fake.push_update(text(1, "a"));
    let task = env.start().await;
    events(env.client(), 1).await;
    task.stop().await;
    let record: Uuid = env
        .client()
        .query_one(
            "SELECT record_id FROM openmybot.channel_events WHERE event_key='1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    shift_event(env.client(), record, "accepted_at", -(7.0 * 86400.0)).await;
    let before = env.fake.calls("getUpdates").len();
    let task = env.start().await;
    polled(&env.fake, |_| true).await;
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.fake.calls("getUpdates").len() <= before {
        assert!(tokio::time::Instant::now() < limit);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(env.fake.calls("getUpdates")[before].param("offset"), None);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn getupdates_wire_parameters_match_profile() {
    let mut env = Env::new().await;
    let task = env.start().await;
    polled(&env.fake, |_| true).await;
    let first = env.fake.calls("getUpdates")[0].clone();
    assert_eq!(first.path, format!("/bot{TOKEN}/getUpdates"));
    let pairs: Vec<(&str, &str)> = first
        .query
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("timeout", "50"),
            ("limit", "100"),
            ("allowed_updates", "[\"message\"]")
        ]
    );
    env.fake.push_update(text(5, "x"));
    polled(&env.fake, |r| r.param("offset") == Some("6")).await;
    let next = env
        .fake
        .calls("getUpdates")
        .into_iter()
        .find(|r| r.param("offset").is_some())
        .unwrap();
    let names: Vec<&str> = next.query.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["offset", "timeout", "limit", "allowed_updates"]);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn timestamp_outside_window_is_rejected_and_consumed() {
    let mut env = Env::new().await;
    let mut late = text(7, "late");
    late["message"]["date"] = json!(OffsetDateTime::now_utc().unix_timestamp() - 2 * 86400);
    env.fake.push_update(late);
    let task = env.start().await;
    events(env.client(), 1).await;
    assert_eq!(
        disposition(env.client(), "7").await,
        "rejected_outside_window"
    );
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.deliveries WHERE kind='reject_reply'"
        )
        .await,
        1
    );
    polled(&env.fake, |r| r.param("offset") == Some("8")).await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unbound_traffic_stores_nothing_and_sends_nothing() {
    let mut env = Env::new().await;
    env.fake.push_update(message(1, 77, Some("hello there")));
    env.fake.push_update(message(2, 77, Some("/help")));
    env.fake.push_update(message(3, 77, None));
    let task = env.start().await;
    events(env.client(), 3).await;
    polled(&env.fake, |r| r.param("offset") == Some("4")).await;
    assert_eq!(count(env.client(), "SELECT count(*) FROM openmybot.channel_events WHERE disposition='dropped_unbound' AND text IS NULL AND sender_key IS NULL AND fingerprint IS NULL").await, 3);
    assert_eq!(
        count(env.client(), "SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    assert!(env.fake.requests().iter().all(|r| r.method == "getUpdates"));
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn non_private_chat_is_dropped_and_consumed() {
    let mut env = Env::new().await;
    let mut group = text(4, "hi all");
    group["message"]["chat"] = json!({"id": -100, "type": "group"});
    env.fake.push_update(group);
    let task = env.start().await;
    events(env.client(), 1).await;
    assert_eq!(disposition(env.client(), "4").await, "dropped_not_private");
    polled(&env.fake, |r| r.param("offset") == Some("5")).await;
    assert_eq!(
        count(env.client(), "SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn control_and_reject_replies_are_rows_only_with_no_send_method_on_wire() {
    let mut env = Env::new().await;
    env.fake.push_update(text(1, "/help"));
    env.fake.push_update(text(2, "/status"));
    env.fake.push_update(message(3, 42, None));
    env.fake.push_update(text(4, &"x".repeat(5000)));
    let task = env.start().await;
    events(env.client(), 4).await;
    let kinds: Vec<String> = env
        .client()
        .query(
            "SELECT kind FROM openmybot.deliveries ORDER BY created_at",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        kinds,
        [
            "control_reply",
            "control_reply",
            "reject_reply",
            "reject_reply"
        ]
    );
    polled(&env.fake, |r| r.param("offset") == Some("5")).await;
    let methods: std::collections::BTreeSet<String> =
        env.fake.requests().into_iter().map(|r| r.method).collect();
    assert_eq!(methods.into_iter().collect::<Vec<_>>(), ["getUpdates"]);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unparseable_update_increments_counter_and_writes_no_row() {
    let mut env = Env::new().await;
    let mut broken = text(9, "x");
    broken.as_object_mut().unwrap().remove("update_id");
    env.fake.script(
        "getUpdates",
        200,
        batch(&[
            broken,
            json!({"update_id": "10", "message": {}}),
            text(5, "ok"),
        ]),
    );
    let task = env.start().await;
    events(env.client(), 1).await;
    assert_eq!(keys(env.client()).await, ["5"]);
    assert_eq!(
        env.counters
            .platform_payload_unparseable
            .load(Ordering::Relaxed),
        2
    );
    polled(&env.fake, |r| r.param("offset") == Some("6")).await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn update_without_message_counts_unsupported_update_and_consumes_offset() {
    let mut env = Env::new().await;
    env.fake
        .push_update(json!({"update_id": 7, "edited_message": {"text": "x"}}));
    let task = env.start().await;
    polled(&env.fake, |r| r.param("offset") == Some("8")).await;
    assert_eq!(env.counters.unsupported_update.load(Ordering::Relaxed), 1);
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.channel_events"
        )
        .await,
        0
    );
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn changed_fingerprint_redelivery_increments_event_conflict_counter() {
    let mut env = Env::new().await;
    env.fake
        .script("getUpdates", 200, batch(&[text(5, "original")]));
    env.fake
        .script("getUpdates", 200, batch(&[text(5, "edited")]));
    let task = env.start().await;
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.counters.event_conflict.load(Ordering::Relaxed) == 0 {
        assert!(tokio::time::Instant::now() < limit);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(env.counters.event_conflict.load(Ordering::Relaxed), 1);
    let stored: String = env
        .client()
        .query_one(
            "SELECT text FROM openmybot.channel_events WHERE event_key='5'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, "original");
    polled(&env.fake, |r| r.param("offset") == Some("6")).await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn nul_text_is_rejected_malformed_and_batch_proceeds() {
    let mut env = Env::new().await;
    env.fake.push_update(text(5, "a\u{0}b"));
    env.fake.push_update(text(6, "fine"));
    let task = env.start().await;
    events(env.client(), 2).await;
    let row = env.client().query_one("SELECT disposition,fingerprint IS NOT NULL,sender_key,text IS NULL FROM openmybot.channel_events WHERE event_key='5'", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "rejected_malformed");
    assert!(row.get::<_, bool>(1) && row.get::<_, bool>(3));
    assert_eq!(row.get::<_, String>(2), "telegram:42");
    assert_eq!(disposition(env.client(), "6").await, "accepted_message");
    task.stop().await;
    env.stop().await;
}

async fn suspended_by(status: u16, reason: &str) {
    let mut env = Env::new().await;
    env.fake
        .script("getUpdates", status, br#"{"ok":false}"#.to_vec());
    let mut task = env.start().await;
    assert_eq!(finished(&mut task).await, Ok(()));
    assert_eq!(
        receiver_state(env.client(), env.receiver).await,
        ("suspended".into(), Some(reason.into()))
    );
    assert_eq!(
        gaps(env.client()).await,
        [("receiver_suspended".to_owned(), false)]
    );
    assert_eq!(env.fake.calls("getUpdates").len(), 1);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unauthorized_response_suspends_receiver_with_gap() {
    suspended_by(401, "credential_rejected").await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn not_found_response_suspends_receiver_with_credential_rejected() {
    suspended_by(404, "credential_rejected").await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn conflict_response_suspends_receiver_with_webhook_conflict() {
    suspended_by(409, "webhook_conflict").await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn rate_limit_waits_retry_after_seconds() {
    let mut env = Env::new().await;
    env.fake.script(
        "getUpdates",
        429,
        br#"{"ok":false,"error_code":429,"parameters":{"retry_after":1}}"#.to_vec(),
    );
    let task = env.start().await;
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.fake.calls("getUpdates").len() < 2 {
        assert!(tokio::time::Instant::now() < limit);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let calls = env.fake.calls("getUpdates");
    assert!(
        calls[1].at - calls[0].at >= Duration::from_secs(1),
        "{:?}",
        calls[1].at - calls[0].at
    );
    gap_closed(env.client(), "stream_broken").await;
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn server_error_backs_off_and_records_stream_broken_gap_until_next_success() {
    let mut env = Env::new().await;
    for _ in 0..3 {
        env.fake.script("getUpdates", 502, b"bad gateway".to_vec());
    }
    let task = env.start().await;
    gap_open(env.client(), "stream_broken").await;
    gap_closed(env.client(), "stream_broken").await;
    assert_eq!(
        gaps(env.client()).await,
        [("stream_broken".to_owned(), true)]
    );
    let calls = env.fake.calls("getUpdates");
    assert!(calls.len() >= 4);
    assert!(calls[3].at - calls[2].at <= Duration::from_millis(200) + Duration::from_millis(500));
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn connection_refused_records_connect_failed_gap_until_next_success() {
    let mut env = Env::new().await;
    let port = FakeTelegram::unused_port();
    let task = env.start_at(FakeTelegram::endpoint_at(port)).await;
    gap_open(env.client(), "connect_failed").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(gaps(env.client()).await.len(), 1);
    let fake = FakeTelegram::start_at(port).await;
    fake.push_update(text(1, "after outage"));
    gap_closed(env.client(), "connect_failed").await;
    events(env.client(), 1).await;
    assert_eq!(
        gaps(env.client()).await,
        [("connect_failed".to_owned(), true)]
    );
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn oversize_response_is_rejected_as_stream_broken_and_refetched() {
    let mut env = Env::new().await;
    let mut oversized = batch(&[text(1, "x")]);
    oversized.resize(TG_RESPONSE_MAX + 1, b' ');
    env.fake.script("getUpdates", 200, oversized);
    let task = env.start().await;
    gap_open(env.client(), "stream_broken").await;
    env.fake.push_update(text(1, "x"));
    events(env.client(), 1).await;
    gap_closed(env.client(), "stream_broken").await;
    assert!(env.fake.calls("getUpdates")[1].param("offset").is_none());
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn empty_batch_closes_open_gap() {
    let mut env = Env::new().await;
    open_poll_gap(
        &mut env.session.client,
        env.receiver,
        PollGapReason::StreamBroken,
        deadline(),
    )
    .await
    .unwrap();
    let task = env.start().await;
    gap_closed(env.client(), "stream_broken").await;
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='event'"
        )
        .await,
        0
    );
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn receiver_stops_when_binding_leaves_active() {
    let mut env = Env::new().await;
    let mut task = env.start().await;
    polled(&env.fake, |_| true).await;
    env.client().execute("UPDATE openmybot.channel_bindings SET status='revoked',status_reason='owner_revoked',ended_at=statement_timestamp() WHERE binding_id=$1", &[&env.receiver]).await.unwrap();
    env.fake.push_update(text(1, "too late"));
    assert_eq!(finished(&mut task).await, Ok(()));
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.channel_events"
        )
        .await,
        0
    );
    let seen = env.fake.calls("getUpdates").len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(env.fake.calls("getUpdates").len(), seen);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accepted_message_wakes_dispatcher_notify() {
    let mut env = Env::new().await;
    let wake = Arc::clone(&env.wake);
    let notified = wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    env.fake.push_update(text(1, "/help"));
    let task = env.start().await;
    events(env.client(), 1).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), notified.as_mut())
            .await
            .is_err()
    );
    env.fake.push_update(text(2, "real work"));
    tokio::time::timeout(Duration::from_secs(20), notified)
        .await
        .unwrap();
    assert_eq!(disposition(env.client(), "2").await, "accepted_message");
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn credential_is_opened_from_vault_envelope_with_connector_context() {
    let mut env = Env::new().await;
    assert!(env.envelope.starts_with("v2:") || !env.envelope.contains("test-token-sentinel"));
    let task = env.start().await;
    polled(&env.fake, |r| r.path == format!("/bot{TOKEN}/getUpdates")).await;
    assert_eq!(receiver_state(env.client(), env.receiver).await.0, "active");
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn plaintext_or_foreign_envelope_suspends_receiver_without_polling() {
    let mut env = Env::new().await;
    let other = Uuid::now_v7();
    let foreign_vault = CredentialRecordVault::single_key(
        TenantId::new("omb-test"),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![9; 32]).unwrap(),
    )
    .seal(
        &env.receiver,
        SecretKind::Connector,
        SecretPrincipal::Actor(owner()),
        SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
        &SecretBytes::new(TOKEN.as_bytes().to_vec()),
    )
    .unwrap();
    for envelope in [
        TOKEN.to_owned(),
        seal(other, TOKEN),
        seal_as(
            env.receiver,
            SecretKind::Connector,
            "openmybot.feishu",
            TOKEN,
        ),
        seal_as(env.receiver, SecretKind::Model, "openmybot.telegram", TOKEN),
        foreign_vault,
    ] {
        env.client().execute("UPDATE openmybot.channel_bindings SET status='active',status_reason=NULL,suspended_at=NULL,credential_envelope=$2 WHERE binding_id=$1", &[&env.receiver, &envelope]).await.unwrap();
        env.envelope = envelope;
        let mut task = env.start().await;
        assert_eq!(finished(&mut task).await, Ok(()));
        assert_eq!(
            receiver_state(env.client(), env.receiver).await,
            ("suspended".into(), Some("credential_rejected".into()))
        );
        task.stop().await;
    }
    assert!(env.fake.requests().is_empty());
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.channel_events WHERE gap_reason='receiver_suspended'"
        )
        .await,
        5
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn envelope_bot_id_must_equal_source_key() {
    let mut env = Env::new().await;
    for token in ["2002:test-token-sentinel", "test-token-sentinel", "10011:x"] {
        let envelope = seal(env.receiver, token);
        env.client().execute("UPDATE openmybot.channel_bindings SET status='active',status_reason=NULL,suspended_at=NULL,credential_envelope=$2 WHERE binding_id=$1", &[&env.receiver, &envelope]).await.unwrap();
        env.envelope = envelope;
        let mut task = env.start().await;
        assert_eq!(finished(&mut task).await, Ok(()));
        assert_eq!(
            receiver_state(env.client(), env.receiver)
                .await
                .1
                .as_deref(),
            Some("credential_rejected")
        );
        task.stop().await;
    }
    assert!(env.fake.requests().is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn token_sentinel_absent_from_rows_errors_and_debug() {
    let mut env = Env::new().await;
    env.fake.push_update(text(1, "work"));
    env.fake.push_update(text(2, "/status"));
    let task = env.start().await;
    events(env.client(), 2).await;
    task.stop().await;
    env.fake.script("getUpdates", 401, b"{}".to_vec());
    let mut task = env.start().await;
    let ended = finished(&mut task).await;
    task.stop().await;
    let dump: String = env.client().query_one("SELECT concat_ws(' ',(SELECT json_agg(b)::text FROM openmybot.channel_bindings b),(SELECT json_agg(e)::text FROM openmybot.channel_events e),(SELECT json_agg(d)::text FROM openmybot.deliveries d),(SELECT json_agg(t)::text FROM openmybot.control_tokens t))", &[]).await.unwrap().get(0);
    assert!(dump.contains("credential_rejected"));
    let rendered = format!(
        "{dump} {ended:?} {:?} {:?} {}",
        env.counters,
        ReceiverRow {
            binding_id: env.receiver,
            source_key: "1001".into(),
            credential_envelope: TOKEN.into()
        },
        omb_channels::ChannelError::StoreFailed
    );
    assert!(!rendered.contains("test-token-sentinel"));
    env.stop().await;
}

fn bot(id: i64) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"ok": true, "result": {"id": id, "is_bot": true, "username": "omb_bot"}}),
    )
    .unwrap()
}
fn webhook(url: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok": true, "result": {"url": url, "pending_update_count": 0}}))
        .unwrap()
}
fn secret() -> SecretBytes {
    SecretBytes::new(TOKEN.as_bytes().to_vec())
}

#[tokio::test]
async fn verify_credentials_rejects_bot_id_mismatch() {
    let fake = FakeTelegram::start().await;
    fake.script("getMe", 200, bot(2002));
    assert_eq!(
        verify_credentials(&fake.endpoint(), &secret(), "1001").await,
        Err(CredentialProblem::CredentialRejected)
    );
    fake.script("getMe", 401, b"{}".to_vec());
    assert_eq!(
        verify_credentials(&fake.endpoint(), &secret(), "1001").await,
        Err(CredentialProblem::CredentialRejected)
    );
    fake.script("getMe", 500, b"{}".to_vec());
    assert_eq!(
        verify_credentials(&fake.endpoint(), &secret(), "1001").await,
        Err(CredentialProblem::Unreachable)
    );
    fake.script("getMe", 200, bot(1001));
    fake.script("getWebhookInfo", 200, webhook(""));
    assert_eq!(
        verify_credentials(&fake.endpoint(), &secret(), "1001").await,
        Ok(())
    );
    assert_eq!(fake.calls("getMe")[0].path, format!("/bot{TOKEN}/getMe"));
    let closed = FakeTelegram::endpoint_at(FakeTelegram::unused_port());
    assert_eq!(
        verify_credentials(&closed, &secret(), "1001").await,
        Err(CredentialProblem::Unreachable)
    );
}

#[tokio::test]
async fn verify_credentials_rejects_non_empty_webhook() {
    let fake = FakeTelegram::start().await;
    fake.script("getMe", 200, bot(1001));
    fake.script(
        "getWebhookInfo",
        200,
        webhook("https://example.invalid/hook"),
    );
    assert_eq!(
        verify_credentials(&fake.endpoint(), &secret(), "1001").await,
        Err(CredentialProblem::WebhookConflict)
    );
}

#[tokio::test]
async fn verify_credentials_never_calls_set_or_delete_webhook() {
    let fake = FakeTelegram::start().await;
    for url in ["", "https://example.invalid/hook", ""] {
        fake.script("getMe", 200, bot(1001));
        fake.script("getWebhookInfo", 200, webhook(url));
        let _ = verify_credentials(&fake.endpoint(), &secret(), "1001").await;
    }
    fake.script("getMe", 200, bot(9));
    let _ = verify_credentials(&fake.endpoint(), &secret(), "1001").await;
    let methods: Vec<String> = fake.requests().into_iter().map(|r| r.method).collect();
    assert_eq!(
        methods,
        [
            "getMe",
            "getWebhookInfo",
            "getMe",
            "getWebhookInfo",
            "getMe",
            "getWebhookInfo",
            "getMe"
        ]
    );
    assert!(
        methods
            .iter()
            .all(|m| m != "setWebhook" && m != "deleteWebhook")
    );
}

async fn reply_bodies(client: &Client) -> Vec<String> {
    client
        .query(
            "SELECT body FROM openmybot.deliveries ORDER BY created_at,delivery_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}
async fn cancel_request(env: &mut Env) -> Uuid {
    tokio::time::timeout(Duration::from_secs(20), env.cancels.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_command_sends_the_binding_id_after_commit() {
    let mut env = Env::new().await;
    let run = insert_event_for_run(env.client(), env.sender, "r1", "thread-A", "dispatched").await;
    // The receiver resumes from the latest event key of its bot, so the run's event needs an update id.
    env.client()
        .execute(
            "UPDATE openmybot.channel_events SET event_key='0' WHERE record_id=$1",
            &[&run],
        )
        .await
        .unwrap();
    env.fake.push_update(text(1, "/cancel"));
    let task = env.start().await;
    assert_eq!(cancel_request(&mut env).await, env.sender);
    // Both rows are visible to another connection when the id arrives.
    assert_eq!(
        count(
            env.client(),
            "SELECT count(*) FROM openmybot.channel_events WHERE event_key='1' AND command='cancel'"
        )
        .await,
        1
    );
    assert_eq!(
        reply_bodies(env.client()).await,
        [OMB_REPLY_CANCEL_REQUESTED_V1]
    );
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_command_without_open_run_sends_binding_id_and_stores_none_reply() {
    let mut env = Env::new().await;
    env.fake.push_update(text(1, "/cancel"));
    let task = env.start().await;
    assert_eq!(cancel_request(&mut env).await, env.sender);
    assert_eq!(reply_bodies(env.client()).await, [OMB_REPLY_CANCEL_NONE_V1]);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn redelivered_cancel_command_sends_nothing_again() {
    let mut env = Env::new().await;
    env.fake
        .script("getUpdates", 200, batch(&[text(1, "/cancel")]));
    env.fake
        .script("getUpdates", 200, batch(&[text(1, "/cancel")]));
    let task = env.start().await;
    assert_eq!(cancel_request(&mut env).await, env.sender);
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    while env.fake.calls("getUpdates").len() < 3 {
        assert!(tokio::time::Instant::now() < limit, "redelivery not polled");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(env.cancels.try_recv().is_err());
    assert_eq!(reply_bodies(env.client()).await.len(), 1);
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_from_unbound_sender_sends_nothing() {
    let mut env = Env::new().await;
    env.fake.push_update(message(1, 99, Some("/cancel")));
    let task = env.start().await;
    events(env.client(), 1).await;
    assert_eq!(disposition(env.client(), "1").await, "dropped_unbound");
    polled(&env.fake, |r| r.param("offset") == Some("2")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(env.cancels.try_recv().is_err());
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn help_command_reply_row_lists_status_cancel_and_help() {
    let mut env = Env::new().await;
    env.fake.push_update(text(1, "/help"));
    let task = env.start().await;
    events(env.client(), 1).await;
    let bodies = reply_bodies(env.client()).await;
    assert_eq!(bodies, [OMB_REPLY_HELP_V1]);
    for command in ["/status", "/cancel", "/help"] {
        assert!(bodies[0].contains(command), "{command}");
    }
    task.stop().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn channel_text_yes_tongyi_and_approve_leave_the_permission_row_unchanged() {
    let mut env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "r1", "hp-channel", 600.0).await;
    let before = permission_row_json(env.client(), "hp-channel").await;
    for (id, body) in [
        (1, "yes"),
        (2, "同意"),
        (3, "approve hp-channel"),
        (4, "deny hp-channel"),
    ] {
        env.fake.push_update(text(id, body));
    }
    let task = env.start().await;
    events(env.client(), 4).await;
    polled(&env.fake, |r| r.param("offset") == Some("5")).await;
    let after = permission_row_json(env.client(), "hp-channel").await;
    assert_eq!(after, before);
    assert!(after["decision"].is_null());
    task.stop().await;
    env.stop().await;
}
