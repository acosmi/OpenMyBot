//! Acceptance transaction against an own PostgreSQL 17.11 cluster.
use omb_store::{
    AcceptOutcome, Channel, Command, Content, Disposition, IdentityKey, NormalizedEvent, PairStart,
    PollGapReason, ReplyTexts, StateLabels, StoreError, accept_event, latest_update_id,
    list_active_receivers, migrate, open_poll_gap, pair_start,
    testkit::{Fixture, Session, deadline, insert_receiver, insert_sender, shift_event},
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use time::OffsetDateTime;
use tokio_postgres::Client;
use uuid::Uuid;

const SENDER: &str = "telegram:42";
const STATES: StateLabels<'static> = StateLabels {
    none: "S-none",
    queued: "S-queued",
    running: "S-running",
    conflict: "S-conflict",
    expired: "S-expired",
    cancelled: "S-cancelled",
    succeeded: "S-succeeded",
    failed: "S-failed",
    reconciliation: "S-reconciliation",
};
const REPLIES: ReplyTexts<'static> = ReplyTexts {
    help: "R-help",
    already_bound: "R-already-bound",
    unknown_command: "R-unknown",
    cancel_unavailable: "R-cancel",
    status: "{channel}|{dir}|{state}|{pending}|{gap}",
    states: STATES,
    outside_window: "R-window",
    too_long: "R-long",
    unsupported: "R-unsupported",
    queue_full: "R-full",
};

struct Env {
    fixture: Fixture,
    session: Session,
    receiver: Uuid,
}
impl Env {
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        let receiver = insert_receiver(&session.client, "telegram", "1001").await;
        Self {
            fixture,
            session,
            receiver,
        }
    }
    async fn sender(&self) -> Uuid {
        insert_sender(&self.session.client, "telegram", "1001", SENDER, "thread-A").await
    }
    async fn accept(&mut self, event: &NormalizedEvent) -> AcceptOutcome {
        accept_event(
            &mut self.session.client,
            self.receiver,
            event,
            &REPLIES,
            deadline(),
        )
        .await
        .unwrap()
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
fn digest(parts: &[&str]) -> [u8; 32] {
    Sha256::digest(parts.join("\u{1}").as_bytes()).into()
}
fn event(key: &str, sender: &str, content: Content) -> NormalizedEvent {
    let seed = format!("{content:?}");
    NormalizedEvent {
        channel: Channel::Telegram,
        source_key: "1001".into(),
        event_key: key.into(),
        event_type: "telegram.message".into(),
        occurred_at: Some(OffsetDateTime::now_utc()),
        private: true,
        sender: IdentityKey::parse(sender),
        chat: IdentityKey::parse(sender),
        fingerprint: Some(digest(&[key, &seed])),
        content,
    }
}
fn text(key: &str, body: &str) -> NormalizedEvent {
    event(
        key,
        SENDER,
        Content::Text {
            text: body.into(),
            command: None,
            pair_code: None,
        },
    )
}
fn command(key: &str, body: &str, command: Command) -> NormalizedEvent {
    event(
        key,
        SENDER,
        Content::Text {
            text: body.into(),
            command: Some(command),
            pair_code: None,
        },
    )
}
async fn scalar<T: for<'a> tokio_postgres::types::FromSql<'a>>(client: &Client, sql: &str) -> T {
    client.query_one(sql, &[]).await.unwrap().get(0)
}
async fn snapshot(client: &Client) -> Vec<Option<String>> {
    let row = client.query_one("SELECT (SELECT json_agg(b ORDER BY binding_id)::text FROM openmybot.channel_bindings b),(SELECT json_agg(e ORDER BY record_id)::text FROM openmybot.channel_events e),(SELECT json_agg(d ORDER BY delivery_id)::text FROM openmybot.deliveries d)", &[]).await.unwrap();
    (0..3).map(|i| row.get(i)).collect()
}
async fn row(client: &Client, key: &str) -> serde_json::Value {
    client
        .query_one(
            "SELECT row_to_json(e) FROM openmybot.channel_events e WHERE event_key=$1",
            &[&key],
        )
        .await
        .unwrap()
        .get(0)
}
async fn record_id(client: &Client, key: &str) -> Uuid {
    client
        .query_one(
            "SELECT record_id FROM openmybot.channel_events WHERE event_key=$1",
            &[&key],
        )
        .await
        .unwrap()
        .get(0)
}
async fn replies(client: &Client) -> Vec<(String, String, String)> {
    client
        .query(
            "SELECT kind,idempotency_key,body FROM openmybot.deliveries ORDER BY created_at,delivery_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}
async fn status_body(env: &mut Env, key: &str) -> String {
    assert_eq!(
        env.accept(&command(key, "/status", Command::Status)).await,
        AcceptOutcome::Recorded(Disposition::ControlCommand)
    );
    let id = record_id(&env.session.client, key).await;
    env.session
        .client
        .query_one(
            "SELECT body FROM openmybot.deliveries WHERE idempotency_key=$1",
            &[&format!("control_reply:{id}")],
        )
        .await
        .unwrap()
        .get(0)
}
/// RFC 4122 version 5 computed here from its definition, independent of the store's code.
fn uuid_v5(namespace: Uuid, name: &str) -> Uuid {
    let mut hasher = <sha1::Sha1 as sha1::Digest>::new();
    sha1::Digest::update(&mut hasher, namespace.as_bytes());
    sha1::Digest::update(&mut hasher, name.as_bytes());
    let hash = sha1::Digest::finalize(hasher);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accepts_private_text_as_pending_message_with_run_thread_and_hash() {
    let mut env = Env::new().await;
    let binding = env.sender().await;
    let incoming = text("10", "please refactor");
    assert_eq!(
        env.accept(&incoming).await,
        AcceptOutcome::Recorded(Disposition::AcceptedMessage)
    );
    let stored = row(&env.session.client, "10").await;
    let id: Uuid = stored["record_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(stored["record_kind"], "event");
    assert_eq!(stored["disposition"], "accepted_message");
    assert_eq!(stored["text"], "please refactor");
    assert_eq!(stored["binding_id"], binding.to_string());
    assert_eq!(stored["sender_key"], SENDER);
    assert_eq!(stored["chat_key"], SENDER);
    assert_eq!(stored["thread_id"], "thread-A");
    assert_eq!(stored["dispatch_status"], "pending");
    assert_eq!(stored["dispatch_attempts"], 0);
    assert!(stored["next_dispatch_at"].is_null() && stored["command"].is_null());
    assert_eq!(stored["event_type"], "telegram.message");
    assert!(!stored["occurred_at"].is_null());
    let ns = uuid_v5(Uuid::NAMESPACE_URL, "urn:openmybot:v1");
    assert_eq!(
        stored["run_id"],
        uuid_v5(ns, &format!("run:{binding}:{id}")).to_string()
    );
    let hashes = env
        .session
        .client
        .query_one(
            "SELECT text_sha256,fingerprint FROM openmybot.channel_events WHERE record_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(
        hashes.get::<_, Vec<u8>>(0),
        Sha256::digest("please refactor").to_vec()
    );
    assert_eq!(
        hashes.get::<_, Vec<u8>>(1),
        incoming.fingerprint.unwrap().to_vec()
    );
    assert!(replies(&env.session.client).await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn same_fingerprint_redelivery_adds_no_row_and_no_run() {
    let mut env = Env::new().await;
    env.sender().await;
    let incoming = text("10", "hello");
    env.accept(&incoming).await;
    let before = snapshot(&env.session.client).await;
    for _ in 0..3 {
        assert_eq!(env.accept(&incoming).await, AcceptOutcome::Duplicate);
    }
    assert_eq!(snapshot(&env.session.client).await, before);
    assert_eq!(
        scalar::<i64>(
            &env.session.client,
            "SELECT count(*) FROM openmybot.channel_events WHERE run_id IS NOT NULL"
        )
        .await,
        1
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn different_fingerprint_is_conflict_and_changes_nothing() {
    let mut env = Env::new().await;
    env.sender().await;
    env.accept(&text("10", "hello")).await;
    let before = snapshot(&env.session.client).await;
    assert_eq!(
        env.accept(&text("10", "edited")).await,
        AcceptOutcome::Conflict
    );
    let mut malformed = text("10", "hello");
    malformed.content = Content::Malformed;
    malformed.fingerprint = None;
    assert_eq!(env.accept(&malformed).await, AcceptOutcome::Conflict);
    assert_eq!(snapshot(&env.session.client).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn null_fingerprint_row_counts_as_duplicate() {
    let mut env = Env::new().await;
    env.sender().await;
    let mut malformed = text("10", "x");
    malformed.content = Content::Malformed;
    malformed.fingerprint = None;
    assert_eq!(
        env.accept(&malformed).await,
        AcceptOutcome::Recorded(Disposition::RejectedMalformed)
    );
    let before = snapshot(&env.session.client).await;
    assert_eq!(
        env.accept(&text("10", "anything")).await,
        AcceptOutcome::Duplicate
    );
    assert_eq!(env.accept(&malformed).await, AcceptOutcome::Duplicate);
    assert_eq!(snapshot(&env.session.client).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn rejected_rows_occupy_the_dedupe_key() {
    let mut env = Env::new().await;
    env.sender().await;
    let mut late = text("10", "late");
    late.occurred_at = Some(OffsetDateTime::now_utc() - time::Duration::days(2));
    let other = event("11", SENDER, Content::Other);
    let dropped = event("12", "telegram:7", Content::Other);
    for (incoming, disposition) in [
        (&late, Disposition::RejectedOutsideWindow),
        (&other, Disposition::RejectedUnsupported),
        (&dropped, Disposition::DroppedUnbound),
    ] {
        assert_eq!(
            env.accept(incoming).await,
            AcceptOutcome::Recorded(disposition)
        );
    }
    let before = snapshot(&env.session.client).await;
    for incoming in [&late, &other, &dropped] {
        assert_eq!(env.accept(incoming).await, AcceptOutcome::Duplicate);
    }
    assert_eq!(snapshot(&env.session.client).await, before);
    assert_eq!(replies(&env.session.client).await.len(), 2);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn malformed_event_writes_rejected_malformed_row_without_reply() {
    let mut env = Env::new().await;
    env.sender().await;
    let mut malformed = text("10", "x");
    malformed.content = Content::Malformed;
    malformed.fingerprint = None;
    assert_eq!(
        env.accept(&malformed).await,
        AcceptOutcome::Recorded(Disposition::RejectedMalformed)
    );
    let stored = row(&env.session.client, "10").await;
    assert_eq!(stored["disposition"], "rejected_malformed");
    assert!(stored["fingerprint"].is_null() && stored["text"].is_null());
    assert!(stored["binding_id"].is_null() && stored["run_id"].is_null());
    assert!(replies(&env.session.client).await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn malformed_row_occupies_key_and_keeps_obtainable_identity() {
    let mut env = Env::new().await;
    let mut malformed = text("10", "x");
    malformed.content = Content::Malformed;
    malformed.fingerprint = None;
    malformed.chat = IdentityKey::parse("telegram:43");
    env.accept(&malformed).await;
    let mut partial = text("11", "x");
    partial.content = Content::Malformed;
    partial.fingerprint = None;
    partial.sender = None;
    env.accept(&partial).await;
    let stored = row(&env.session.client, "10").await;
    assert_eq!(stored["sender_key"], SENDER);
    assert_eq!(stored["chat_key"], "telegram:43");
    let stored = row(&env.session.client, "11").await;
    assert!(stored["sender_key"].is_null());
    assert_eq!(stored["chat_key"], SENDER);
    let before = snapshot(&env.session.client).await;
    assert_eq!(env.accept(&malformed).await, AcceptOutcome::Duplicate);
    assert_eq!(env.accept(&partial).await, AcceptOutcome::Duplicate);
    assert_eq!(snapshot(&env.session.client).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unbound_non_pair_text_is_dropped_without_identity_text_or_fingerprint() {
    let mut env = Env::new().await;
    assert_eq!(
        env.accept(&text("10", "hello")).await,
        AcceptOutcome::Recorded(Disposition::DroppedUnbound)
    );
    let stored = row(&env.session.client, "10").await;
    assert_eq!(stored["disposition"], "dropped_unbound");
    for column in [
        "fingerprint",
        "text",
        "sender_key",
        "chat_key",
        "binding_id",
        "run_id",
    ] {
        assert!(stored[column].is_null(), "{column}");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn non_private_chat_is_dropped_without_identity_text_or_fingerprint() {
    let mut env = Env::new().await;
    env.sender().await;
    let mut group = text("10", "hello");
    group.private = false;
    group.chat = IdentityKey::parse("telegram:-100");
    assert_eq!(
        env.accept(&group).await,
        AcceptOutcome::Recorded(Disposition::DroppedNotPrivate)
    );
    let stored = row(&env.session.client, "10").await;
    for column in [
        "fingerprint",
        "text",
        "sender_key",
        "chat_key",
        "binding_id",
        "run_id",
    ] {
        assert!(stored[column].is_null(), "{column}");
    }
    assert!(replies(&env.session.client).await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unbound_traffic_creates_no_delivery_and_no_run() {
    let mut env = Env::new().await;
    let stranger = "telegram:7";
    let inputs = [
        event(
            "1",
            stranger,
            Content::Text {
                text: "hello".into(),
                command: None,
                pair_code: None,
            },
        ),
        event(
            "2",
            stranger,
            Content::Text {
                text: "/help".into(),
                command: Some(Command::Help),
                pair_code: None,
            },
        ),
        event(
            "3",
            stranger,
            Content::Text {
                text: "/status".into(),
                command: Some(Command::Status),
                pair_code: None,
            },
        ),
        event(
            "4",
            stranger,
            Content::Text {
                text: "/pair".into(),
                command: Some(Command::Pair),
                pair_code: None,
            },
        ),
        event("5", stranger, Content::Other),
        event(
            "6",
            stranger,
            Content::Text {
                text: "x".repeat(5000),
                command: None,
                pair_code: None,
            },
        ),
    ];
    for incoming in &inputs {
        assert_eq!(
            env.accept(incoming).await,
            AcceptOutcome::Recorded(Disposition::DroppedUnbound)
        );
    }
    assert!(replies(&env.session.client).await.is_empty());
    assert_eq!(
        scalar::<i64>(&env.session.client, "SELECT count(*) FROM openmybot.channel_events WHERE run_id IS NOT NULL OR text IS NOT NULL OR sender_key IS NOT NULL").await,
        0
    );
    env.stop().await;
}

async fn pending_pair(client: &mut Client) -> omb_store::PairStarted {
    pair_start(
        client,
        PairStart {
            channel: Channel::Telegram,
            workspace_dir: "/workspaces/project",
            thread_id: "thread-P",
            granted_generation: 1,
            run_deadline: None,
        },
        deadline(),
    )
    .await
    .unwrap()
}
fn pair(key: &str, code: &str) -> NormalizedEvent {
    let body = format!("/pair {code}");
    event(
        key,
        SENDER,
        Content::Text {
            text: body,
            command: Some(Command::Pair),
            pair_code: Some(code.into()),
        },
    )
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_text_from_unbound_sender_runs_pairing_in_same_transaction() {
    let mut env = Env::new().await;
    let started = pending_pair(&mut env.session.client).await;
    let code = started.code.display();
    let before = snapshot(&env.session.client).await;
    let injected = pair(&"9".repeat(129), &code);
    assert_eq!(
        accept_event(
            &mut env.session.client,
            env.receiver,
            &injected,
            &REPLIES,
            deadline()
        )
        .await
        .unwrap_err(),
        StoreError::BindingFailed
    );
    assert_eq!(snapshot(&env.session.client).await, before);
    assert_eq!(
        env.accept(&pair("10", &code)).await,
        AcceptOutcome::Recorded(Disposition::PairingSucceeded)
    );
    let binding = env
        .session
        .client
        .query_one(
            "SELECT status,sender_key FROM openmybot.channel_bindings WHERE binding_id=$1",
            &[&started.binding_id],
        )
        .await
        .unwrap();
    assert_eq!(binding.get::<_, String>(0), "active");
    assert_eq!(binding.get::<_, String>(1), SENDER);
    let stored = row(&env.session.client, "10").await;
    assert_eq!(stored["disposition"], "pairing_succeeded");
    assert_eq!(stored["command"], "pair");
    assert!(stored["text"].is_null());
    let replies = replies(&env.session.client).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].0, "pairing_reply");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_text_redelivery_with_same_fingerprint_is_duplicate() {
    let mut env = Env::new().await;
    let started = pending_pair(&mut env.session.client).await;
    let wrong = pair("10", "WRONG000");
    assert_eq!(
        env.accept(&wrong).await,
        AcceptOutcome::Recorded(Disposition::PairingFailed)
    );
    let before = snapshot(&env.session.client).await;
    assert_eq!(env.accept(&wrong).await, AcceptOutcome::Duplicate);
    assert_eq!(snapshot(&env.session.client).await, before);
    let mut right = pair("10", &started.code.display());
    right.fingerprint = wrong.fingerprint;
    assert_eq!(env.accept(&right).await, AcceptOutcome::Duplicate);
    assert_eq!(snapshot(&env.session.client).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_text_with_changed_fingerprint_is_conflict() {
    let mut env = Env::new().await;
    let started = pending_pair(&mut env.session.client).await;
    env.accept(&pair("10", "WRONG000")).await;
    let before = snapshot(&env.session.client).await;
    assert_eq!(
        env.accept(&pair("10", &started.code.display())).await,
        AcceptOutcome::Conflict
    );
    assert_eq!(snapshot(&env.session.client).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_text_event_row_carries_occurred_at_and_event_type() {
    let mut env = Env::new().await;
    pending_pair(&mut env.session.client).await;
    let incoming = pair("10", "WRONG000");
    env.accept(&incoming).await;
    let stored = env.session.client.query_one("SELECT occurred_at,event_type,disposition FROM openmybot.channel_events WHERE event_key='10'", &[]).await.unwrap();
    let occurred: OffsetDateTime = stored.get(0);
    let expected = incoming.occurred_at.unwrap();
    assert!((occurred - expected).abs() < time::Duration::milliseconds(1));
    assert_eq!(stored.get::<_, String>(1), "telegram.message");
    assert_eq!(stored.get::<_, String>(2), "pairing_failed");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn suspended_sender_is_dropped_inactive() {
    let mut env = Env::new().await;
    let binding = env.sender().await;
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&binding]).await.unwrap();
    let incoming = text("10", "hello");
    assert_eq!(
        env.accept(&incoming).await,
        AcceptOutcome::Recorded(Disposition::DroppedInactive)
    );
    let stored = row(&env.session.client, "10").await;
    assert_eq!(stored["binding_id"], binding.to_string());
    assert_eq!(stored["sender_key"], SENDER);
    assert_eq!(stored["chat_key"], SENDER);
    assert!(!stored["fingerprint"].is_null());
    assert!(stored["text"].is_null() && stored["run_id"].is_null());
    assert!(replies(&env.session.client).await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn window_rejects_older_than_24h_and_later_than_5min_with_reply() {
    let mut env = Env::new().await;
    env.sender().await;
    let now = OffsetDateTime::now_utc();
    for (key, at) in [
        (
            "10",
            now - time::Duration::hours(24) - time::Duration::seconds(2),
        ),
        (
            "11",
            now + time::Duration::minutes(5) + time::Duration::seconds(2),
        ),
        ("12", now - time::Duration::days(30)),
    ] {
        let mut incoming = text(key, "hello");
        incoming.occurred_at = Some(at);
        assert_eq!(
            env.accept(&incoming).await,
            AcceptOutcome::Recorded(Disposition::RejectedOutsideWindow)
        );
    }
    let mut missing = text("13", "hello");
    missing.occurred_at = None;
    assert_eq!(
        env.accept(&missing).await,
        AcceptOutcome::Recorded(Disposition::RejectedOutsideWindow)
    );
    let replies = replies(&env.session.client).await;
    assert_eq!(replies.len(), 4);
    assert!(
        replies
            .iter()
            .all(|(kind, _, body)| kind == "reject_reply" && body == "R-window")
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn window_boundaries_accept_exactly_24h_and_5min() {
    let mut env = Env::new().await;
    env.sender().await;
    // The window is evaluated against the transaction's statement time, a few milliseconds after
    // `now`; one second inside each end stays inside the closed interval.
    let now = OffsetDateTime::now_utc();
    for (key, at) in [
        (
            "10",
            now - time::Duration::hours(24) + time::Duration::seconds(1),
        ),
        (
            "11",
            now + time::Duration::minutes(5) - time::Duration::seconds(1),
        ),
        ("12", now),
    ] {
        let mut incoming = text(key, "hello");
        incoming.occurred_at = Some(at);
        assert_eq!(
            env.accept(&incoming).await,
            AcceptOutcome::Recorded(Disposition::AcceptedMessage),
            "{key}"
        );
    }
    let inclusive: bool = scalar(&env.session.client, "SELECT (statement_timestamp()-make_interval(secs=>86400)) BETWEEN statement_timestamp()-make_interval(secs=>86400) AND statement_timestamp()+make_interval(secs=>300) AND (statement_timestamp()+make_interval(secs=>300)) BETWEEN statement_timestamp()-make_interval(secs=>86400) AND statement_timestamp()+make_interval(secs=>300)").await;
    assert!(inclusive);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn non_text_from_bound_sender_is_rejected_unsupported_with_reply() {
    let mut env = Env::new().await;
    let binding = env.sender().await;
    assert_eq!(
        env.accept(&event("10", SENDER, Content::Other)).await,
        AcceptOutcome::Recorded(Disposition::RejectedUnsupported)
    );
    let stored = row(&env.session.client, "10").await;
    assert_eq!(stored["binding_id"], binding.to_string());
    assert!(stored["text"].is_null() && stored["run_id"].is_null());
    let replies = replies(&env.session.client).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(
        (replies[0].0.as_str(), replies[0].2.as_str()),
        ("reject_reply", "R-unsupported")
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn text_limit_accepts_4096_bytes_and_rejects_4097_by_bytes_not_chars() {
    let mut env = Env::new().await;
    env.sender().await;
    for (key, body, disposition) in [
        ("10", "a".repeat(4096), Disposition::AcceptedMessage),
        ("11", "é".repeat(2048), Disposition::AcceptedMessage),
        ("12", "a".repeat(4097), Disposition::RejectedTooLong),
        (
            "13",
            format!("{}a", "é".repeat(2048)),
            Disposition::RejectedTooLong,
        ),
        ("14", "中".repeat(1366), Disposition::RejectedTooLong),
    ] {
        assert_eq!(
            env.accept(&text(key, &body)).await,
            AcceptOutcome::Recorded(disposition),
            "{key}"
        );
    }
    let bodies: Vec<String> = replies(&env.session.client)
        .await
        .into_iter()
        .map(|r| r.2)
        .collect();
    assert_eq!(bodies, ["R-long", "R-long", "R-long"]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn control_commands_record_command_and_one_reply_each_without_run() {
    let mut env = Env::new().await;
    env.sender().await;
    for (key, body, cmd, column) in [
        ("10", "/help", Command::Help, "help"),
        ("11", "/start payload", Command::Start, "start"),
        ("12", "/status", Command::Status, "status"),
        ("13", "/whatever", Command::Unknown, "unknown"),
    ] {
        assert_eq!(
            env.accept(&command(key, body, cmd)).await,
            AcceptOutcome::Recorded(Disposition::ControlCommand)
        );
        let stored = row(&env.session.client, key).await;
        assert_eq!(stored["command"], column);
        assert!(
            stored["text"].is_null()
                && stored["run_id"].is_null()
                && stored["dispatch_status"].is_null()
        );
    }
    let replies = replies(&env.session.client).await;
    assert_eq!(replies.len(), 4);
    assert!(replies.iter().all(|r| r.0 == "control_reply"));
    assert_eq!(replies[0].2, "R-help");
    assert_eq!(replies[1].2, "R-help");
    assert!(replies[2].2.starts_with("telegram|project|"));
    assert_eq!(replies[3].2, "R-unknown");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_records_cancel_command_and_replies_unavailable_text() {
    let mut env = Env::new().await;
    env.sender().await;
    env.accept(&text("9", "work")).await;
    env.accept(&command("10", "/cancel", Command::Cancel)).await;
    assert_eq!(row(&env.session.client, "10").await["command"], "cancel");
    let replies = replies(&env.session.client).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(
        (replies[0].0.as_str(), replies[0].2.as_str()),
        ("control_reply", "R-cancel")
    );
    assert_eq!(
        row(&env.session.client, "9").await["dispatch_status"],
        "pending"
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn bound_sender_pair_command_replies_already_bound() {
    let mut env = Env::new().await;
    let binding = env.sender().await;
    let before: String = scalar(
        &env.session.client,
        "SELECT row_to_json(b)::text FROM openmybot.channel_bindings b WHERE binding_kind='sender'",
    )
    .await;
    assert_eq!(
        env.accept(&pair("10", "ABCD2345")).await,
        AcceptOutcome::Recorded(Disposition::ControlCommand)
    );
    let stored = row(&env.session.client, "10").await;
    assert_eq!(stored["command"], "pair");
    assert_eq!(stored["binding_id"], binding.to_string());
    assert_eq!(replies(&env.session.client).await[0].2, "R-already-bound");
    let after: String = scalar(
        &env.session.client,
        "SELECT row_to_json(b)::text FROM openmybot.channel_bindings b WHERE binding_kind='sender'",
    )
    .await;
    assert_eq!(after, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unknown_slash_text_replies_fixed_unknown_command_text() {
    let mut env = Env::new().await;
    env.sender().await;
    for (key, body) in [("10", "/foo"), ("11", "/approve perm-1"), ("12", "/")] {
        env.accept(&command(key, body, Command::Unknown)).await;
    }
    let replies = replies(&env.session.client).await;
    assert_eq!(replies.len(), 3);
    assert!(replies.iter().all(|r| r.2 == "R-unknown"));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn status_reply_renders_channel_workspace_tail_state_pending_and_gap() {
    let mut env = Env::new().await;
    env.sender().await;
    assert_eq!(
        status_body(&mut env, "10").await,
        "telegram|project|S-none|0|S-none"
    );
    env.accept(&text("11", "one")).await;
    env.accept(&text("12", "two")).await;
    open_poll_gap(
        &mut env.session.client,
        env.receiver,
        PollGapReason::StreamBroken,
        deadline(),
    )
    .await
    .unwrap();
    let gap = env.session.client.query_one("SELECT to_char(gap_started_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US') FROM openmybot.channel_events WHERE record_kind='gap'", &[]).await.unwrap().get::<_, String>(0);
    let body = status_body(&mut env, "13").await;
    let (head, gap_text) = body.rsplit_once('|').unwrap();
    assert_eq!(head, "telegram|project|S-queued|2");
    let gap_text = gap_text.strip_prefix("stream_broken ").unwrap();
    let (started, ended) = gap_text.split_once('–').unwrap();
    assert_eq!(ended, "S-running");
    assert!(started.ends_with('Z'), "{started}");
    let parsed =
        OffsetDateTime::parse(started, &time::format_description::well_known::Rfc3339).unwrap();
    assert_eq!(parsed.offset(), time::UtcOffset::UTC);
    assert!(
        started.starts_with(gap.trim_end_matches('0').trim_end_matches('.')),
        "{started} {gap}"
    );
    env.session.client.execute("UPDATE openmybot.channel_events SET gap_ended_at=gap_started_at+interval '3 seconds' WHERE record_kind='gap'", &[]).await.unwrap();
    let body = status_body(&mut env, "14").await;
    let gap_text = body.rsplit_once('|').unwrap().1;
    let (_, ended) = gap_text.split_once('–').unwrap();
    assert!(ended.ends_with('Z') && ended != "S-running", "{ended}");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn status_state_maps_all_nine_dispatch_and_terminal_combinations() {
    let mut env = Env::new().await;
    env.sender().await;
    assert_eq!(
        status_body(&mut env, "s0").await.split('|').nth(2).unwrap(),
        "S-none"
    );
    env.accept(&text("m", "work")).await;
    let id = record_id(&env.session.client, "m").await;
    for (index, (status, terminal, label)) in [
        ("pending", None, "S-queued"),
        ("dispatched", None, "S-running"),
        ("conflict", None, "S-conflict"),
        ("expired", None, "S-expired"),
        ("cancelled", None, "S-cancelled"),
        ("dispatched", Some("succeeded"), "S-succeeded"),
        ("dispatched", Some("failed"), "S-failed"),
        ("dispatched", Some("cancelled"), "S-cancelled"),
        (
            "dispatched",
            Some("reconciliation_required"),
            "S-reconciliation",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        env.session.client.execute("UPDATE openmybot.channel_events SET dispatch_status=$2,terminal_kind=$3,terminal_at=CASE WHEN $3::text IS NULL THEN NULL ELSE statement_timestamp() END WHERE record_id=$1", &[&id, &status, &terminal]).await.unwrap();
        let body = status_body(&mut env, &format!("s{}", index + 1)).await;
        assert_eq!(
            body.split('|').nth(2).unwrap(),
            label,
            "{status} {terminal:?}"
        );
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn status_state_is_none_without_accepted_message() {
    let mut env = Env::new().await;
    env.sender().await;
    env.accept(&command("10", "/help", Command::Help)).await;
    env.accept(&event("11", SENDER, Content::Other)).await;
    assert_eq!(
        status_body(&mut env, "12").await,
        "telegram|project|S-none|0|S-none"
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pending_queue_rejects_twenty_first_and_ignores_dispatched_rows() {
    let mut env = Env::new().await;
    env.sender().await;
    for index in 0..20 {
        assert_eq!(
            env.accept(&text(&format!("{index}"), "work")).await,
            AcceptOutcome::Recorded(Disposition::AcceptedMessage)
        );
    }
    assert_eq!(
        env.accept(&text("20", "work")).await,
        AcceptOutcome::Recorded(Disposition::RejectedQueueFull)
    );
    assert_eq!(replies(&env.session.client).await[0].2, "R-full");
    let first = record_id(&env.session.client, "0").await;
    env.session.client.execute("UPDATE openmybot.channel_events SET dispatch_status='dispatched',dispatched_at=statement_timestamp() WHERE record_id=$1", &[&first]).await.unwrap();
    assert_eq!(
        env.accept(&text("21", "work")).await,
        AcceptOutcome::Recorded(Disposition::AcceptedMessage)
    );
    assert_eq!(
        env.accept(&text("22", "work")).await,
        AcceptOutcome::Recorded(Disposition::RejectedQueueFull)
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reject_reply_text_is_fixed_and_never_echoes_input() {
    let mut env = Env::new().await;
    env.sender().await;
    let marker = "ECHO-MARKER";
    let mut late = text("1", marker);
    late.occurred_at = Some(OffsetDateTime::now_utc() - time::Duration::days(3));
    env.accept(&late).await;
    env.accept(&text("2", &format!("{marker}{}", "x".repeat(5000))))
        .await;
    env.accept(&event("3", SENDER, Content::Other)).await;
    for index in 0..20 {
        env.accept(&text(&format!("q{index}"), "work")).await;
    }
    env.accept(&text("4", marker)).await;
    let bodies: Vec<String> = replies(&env.session.client)
        .await
        .into_iter()
        .map(|r| r.2)
        .collect();
    assert_eq!(bodies, ["R-window", "R-long", "R-unsupported", "R-full"]);
    assert_eq!(
        scalar::<i64>(
            &env.session.client,
            "SELECT count(*) FROM openmybot.channel_events WHERE text LIKE '%ECHO-MARKER%'"
        )
        .await,
        0
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reply_idempotency_keys_are_kind_colon_record_id() {
    let mut env = Env::new().await;
    let binding = env.sender().await;
    env.accept(&command("10", "/help", Command::Help)).await;
    env.accept(&event("11", SENDER, Content::Other)).await;
    let help = record_id(&env.session.client, "10").await;
    let other = record_id(&env.session.client, "11").await;
    let rows = env.session.client.query("SELECT kind,idempotency_key,binding_id,channel_kind,chat_key,status FROM openmybot.deliveries ORDER BY created_at", &[]).await.unwrap();
    assert_eq!(rows[0].get::<_, String>(1), format!("control_reply:{help}"));
    assert_eq!(rows[1].get::<_, String>(1), format!("reject_reply:{other}"));
    for row in &rows {
        assert_eq!(row.get::<_, Uuid>(2), binding);
        assert_eq!(row.get::<_, String>(3), "telegram");
        assert_eq!(row.get::<_, String>(4), SENDER);
        assert_eq!(row.get::<_, String>(5), "pending");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn inactive_receiver_aborts_with_receiver_not_active_and_writes_nothing() {
    let mut env = Env::new().await;
    env.sender().await;
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='credential_rejected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&env.receiver]).await.unwrap();
    let before = snapshot(&env.session.client).await;
    for receiver in [env.receiver, Uuid::now_v7()] {
        assert_eq!(
            accept_event(
                &mut env.session.client,
                receiver,
                &text("10", "hi"),
                &REPLIES,
                deadline()
            )
            .await
            .unwrap_err(),
            StoreError::ReceiverNotActive
        );
    }
    assert_eq!(snapshot(&env.session.client).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn failure_in_any_step_rolls_back_event_and_delivery_rows() {
    let mut env = Env::new().await;
    env.sender().await;
    let before = snapshot(&env.session.client).await;
    let long_key = "9".repeat(129);
    for incoming in [
        command(&long_key, "/help", Command::Help),
        event(&long_key, SENDER, Content::Other),
        text(&long_key, "work"),
    ] {
        assert_eq!(
            accept_event(
                &mut env.session.client,
                env.receiver,
                &incoming,
                &REPLIES,
                deadline()
            )
            .await
            .unwrap_err(),
            StoreError::EventFailed
        );
        assert_eq!(snapshot(&env.session.client).await, before);
    }
    assert_eq!(
        env.accept(&command("10", "/help", Command::Help)).await,
        AcceptOutcome::Recorded(Disposition::ControlCommand)
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn statement_timeout_budget_is_set_local_two_seconds() {
    let mut env = Env::new().await;
    env.sender().await;
    let mut holder = env.fixture.connect().await;
    let lock = holder.client.transaction().await.unwrap();
    lock.execute(
        "SELECT 1 FROM openmybot.channel_bindings WHERE binding_id=$1 FOR UPDATE",
        &[&env.receiver],
    )
    .await
    .unwrap();
    let started = std::time::Instant::now();
    let error = accept_event(
        &mut env.session.client,
        env.receiver,
        &text("10", "hi"),
        &REPLIES,
        tokio::time::Instant::now() + Duration::from_secs(30),
    )
    .await
    .unwrap_err();
    let waited = started.elapsed();
    assert_eq!(error, StoreError::EventFailed);
    assert!(
        waited >= Duration::from_millis(1900) && waited < Duration::from_secs(10),
        "{waited:?}"
    );
    lock.rollback().await.unwrap();
    assert_eq!(
        scalar::<String>(
            &env.session.client,
            "SELECT current_setting('statement_timeout')"
        )
        .await,
        "0"
    );
    assert_eq!(
        env.accept(&text("10", "hi")).await,
        AcceptOutcome::Recorded(Disposition::AcceptedMessage)
    );
    holder.close().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn concurrent_redelivery_accepts_once() {
    let mut env = Env::new().await;
    env.sender().await;
    let mut sessions = Vec::new();
    for _ in 0..4 {
        sessions.push(env.fixture.connect().await);
    }
    for round in 0..10 {
        let incoming = text(&format!("r{round}"), "work");
        let receiver = env.receiver;
        let [a, b, c, d] = &mut sessions[..] else {
            unreachable!()
        };
        let outcomes = tokio::join!(
            accept_event(&mut a.client, receiver, &incoming, &REPLIES, deadline()),
            accept_event(&mut b.client, receiver, &incoming, &REPLIES, deadline()),
            accept_event(&mut c.client, receiver, &incoming, &REPLIES, deadline()),
            accept_event(&mut d.client, receiver, &incoming, &REPLIES, deadline()),
        );
        let outcomes = [outcomes.0, outcomes.1, outcomes.2, outcomes.3].map(Result::unwrap);
        let accepted = outcomes
            .iter()
            .filter(|o| **o == AcceptOutcome::Recorded(Disposition::AcceptedMessage))
            .count();
        let duplicates = outcomes
            .iter()
            .filter(|o| **o == AcceptOutcome::Duplicate)
            .count();
        assert_eq!((accepted, duplicates), (1, 3), "round {round}");
        assert_eq!(
            scalar::<i64>(
                &env.session.client,
                &format!(
                    "SELECT count(*) FROM openmybot.channel_events WHERE event_key='r{round}'"
                )
            )
            .await,
            1
        );
    }
    for session in sessions {
        session.close().await;
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn latest_update_id_ignores_gap_rows_and_orders_by_accepted_at() {
    let mut env = Env::new().await;
    assert_eq!(
        latest_update_id(&env.session.client, Channel::Telegram, "1001")
            .await
            .unwrap(),
        None
    );
    env.accept(&text("50", "x")).await;
    env.accept(&text("30", "x")).await;
    let fifty = record_id(&env.session.client, "50").await;
    let thirty = record_id(&env.session.client, "30").await;
    shift_event(&env.session.client, fifty, "accepted_at", -60.0).await;
    shift_event(&env.session.client, thirty, "accepted_at", -30.0).await;
    open_poll_gap(
        &mut env.session.client,
        env.receiver,
        PollGapReason::ConnectFailed,
        deadline(),
    )
    .await
    .unwrap();
    let (id, at) = latest_update_id(&env.session.client, Channel::Telegram, "1001")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(id, 30);
    let stored: OffsetDateTime = env
        .session
        .client
        .query_one(
            "SELECT accepted_at FROM openmybot.channel_events WHERE record_id=$1",
            &[&thirty],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(at, stored);
    assert_eq!(
        latest_update_id(&env.session.client, Channel::Telegram, "2002")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        latest_update_id(&env.session.client, Channel::Feishu, "1001")
            .await
            .unwrap(),
        None
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn list_active_receivers_returns_only_active_rows_of_the_channel() {
    let env = Env::new().await;
    let feishu = insert_receiver(&env.session.client, "feishu", "cli_app").await;
    let listed = list_active_receivers(&env.session.client, Channel::Telegram)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].binding_id, env.receiver);
    assert_eq!(listed[0].source_key, "1001");
    assert_eq!(listed[0].credential_envelope, "test-envelope");
    assert!(!format!("{:?}", listed[0]).contains("test-envelope"));
    let listed = list_active_receivers(&env.session.client, Channel::Feishu)
        .await
        .unwrap();
    assert_eq!(
        listed.iter().map(|r| r.binding_id).collect::<Vec<_>>(),
        [feishu]
    );
    for (status, reason) in [
        ("suspended", "credential_rejected"),
        ("revoked", "owner_revoked"),
    ] {
        env.session.client.execute("UPDATE openmybot.channel_bindings SET status=$2,status_reason=$3,suspended_at=statement_timestamp(),ended_at=CASE WHEN $2='revoked' THEN statement_timestamp() END WHERE binding_id=$1", &[&env.receiver, &status, &reason]).await.unwrap();
        assert!(
            list_active_receivers(&env.session.client, Channel::Telegram)
                .await
                .unwrap()
                .is_empty(),
            "{status}"
        );
    }
    env.stop().await;
}
