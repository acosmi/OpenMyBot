//! Host run acceptance and per-binding cancel against an own PostgreSQL 17.11 cluster.
use omb_store::{
    Claim, DISPATCH_QUEUE_MAX, DispatchOutcome, EventCancel, HostAccept, HostMessage, HostRun,
    OperationId, accept_host_begin, cancel_event, claim_dispatch, expire_pending, migrate,
    reconfirm_binding, record_dispatch, revoke_binding,
    testkit::{
        Fixture, Session, deadline, insert_event_for_run, insert_host_binding, insert_sender,
        set_terminal, shift_event, suspend_binding,
    },
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_postgres::Client;
use uuid::Uuid;

/// UUIDv5(NAMESPACE_URL, `urn:openmybot:v1`), the run identity namespace.
const OMB_NS: &str = "b09a90b8-a527-5aa1-be6d-0645747da37f";

struct Env {
    fixture: Fixture,
    session: Session,
}
impl Env {
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        Self { fixture, session }
    }
    fn client(&self) -> &Client {
        &self.session.client
    }
    async fn host(&self) -> Uuid {
        insert_host_binding(self.client(), "/w/host").await
    }
    /// One acceptance on thread `T-host`.
    async fn begin(&mut self, id: &str, message: &str) -> HostAccept {
        self.begin_on(id, message, "T-host").await
    }
    async fn begin_on(&mut self, id: &str, message: &str, thread: &str) -> HostAccept {
        begin(&mut self.session.client, id, message, thread).await
    }
    /// The event row of operation `id` as JSON.
    async fn event(&self, id: &str) -> Value {
        self.client()
            .query_one(
                "SELECT row_to_json(e) FROM openmybot.channel_events e WHERE event_key=$1",
                &[&format!("op:{id}")],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn record(&self, id: &str) -> Uuid {
        Uuid::parse_str(self.event(id).await["record_id"].as_str().unwrap()).unwrap()
    }
    async fn row(&self, record: Uuid) -> Value {
        omb_store::testkit::read_row(self.client(), "channel_events", "record_id", record).await
    }
    async fn count(&self, sql: &str) -> i64 {
        self.client().query_one(sql, &[]).await.unwrap().get(0)
    }
    async fn keyed(&self, id: &str) -> i64 {
        self.client()
            .query_one(
                "SELECT count(*) FROM openmybot.channel_events WHERE event_key=$1",
                &[&format!("op:{id}")],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
/// The `bytea` text form `row_to_json` writes.
fn bytea(bytes: &[u8]) -> Value {
    Value::String(format!("\\x{}", hex(bytes)))
}
fn canonical(binding: Uuid, id: &str, message: &str) -> String {
    format!(
        r#"{{"data":{{"bindingId":{},"message":{},"operationId":{}}},"eventType":"host.run_begin"}}"#,
        serde_json::to_string(&binding.to_string()).unwrap(),
        serde_json::to_string(message).unwrap(),
        serde_json::to_string(id).unwrap(),
    )
}
fn run_v5(binding: Uuid, record: Uuid) -> String {
    use sha1::Digest as _;
    let namespace = Uuid::parse_str(OMB_NS).unwrap();
    let digest = sha1::Sha1::new()
        .chain_update(namespace.as_bytes())
        .chain_update(format!("run:{binding}:{record}").as_bytes())
        .finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_sha1_bytes(bytes)
        .into_uuid()
        .to_string()
}
/// One acceptance on `client` with its own thread id.
async fn begin(client: &mut Client, id: &str, message: &str, thread: &str) -> HostAccept {
    accept_host_begin(
        client,
        &OperationId::parse(id).unwrap(),
        &HostMessage::parse(message).unwrap(),
        thread,
        deadline(),
    )
    .await
    .unwrap()
}
fn accepted(outcome: HostAccept) -> HostRun {
    match outcome {
        HostAccept::Accepted(run) => run,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accepted_begin_writes_the_event_row_with_the_derived_run_id() {
    let mut env = Env::new().await;
    let host = env.host().await;
    let run = accepted(env.begin("op-1", "hello").await);
    let row = env.event("op-1").await;
    let record = Uuid::parse_str(row["record_id"].as_str().unwrap()).unwrap();
    for (column, expected) in [
        ("record_kind", "event"),
        ("channel_kind", "host"),
        ("source_key", "crabcode"),
        ("event_type", "host.run_begin"),
        ("sender_key", "host:crabcode"),
        ("disposition", "accepted_message"),
        ("text", "hello"),
        ("thread_id", "T-host"),
        ("dispatch_status", "pending"),
    ] {
        assert_eq!(row[column], expected, "{column}");
    }
    for column in [
        "occurred_at",
        "chat_key",
        "command",
        "next_dispatch_at",
        "terminal_kind",
    ] {
        assert!(row[column].is_null(), "{column}");
    }
    assert_eq!(row["binding_id"], host.to_string());
    assert_eq!(row["dispatch_attempts"], 0);
    assert_eq!(row["text_sha256"], bytea(&Sha256::digest(b"hello")));
    assert_eq!(
        row["fingerprint"],
        bytea(&Sha256::digest(canonical(host, "op-1", "hello").as_bytes()))
    );
    assert_eq!(row["run_id"], run_v5(host, record));
    assert_eq!(
        run,
        HostRun {
            run_id: run_v5(host, record),
            thread_id: "T-host".into()
        }
    );
    let longest = "a".repeat(125);
    accepted(env.begin(&longest, "long key").await);
    let key = env.event(&longest).await["event_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(key.len(), 128);
    accepted(env.begin("empty", "").await);
    let empty = env.event("empty").await;
    assert_eq!(empty["text"], "");
    assert_eq!(empty["text_sha256"], bytea(&Sha256::digest(b"")));
    let full = format!("{}a", "€".repeat(1365));
    assert_eq!(full.len(), 4096);
    accepted(env.begin("full", &full).await);
    assert_eq!(env.event("full").await["text"], full.as_str());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn same_operation_and_message_replays_the_stored_run() {
    let mut env = Env::new().await;
    env.host().await;
    let first = accepted(env.begin("op-1", "hello").await);
    let before = env.event("op-1").await;
    assert_eq!(
        env.begin_on("op-1", "hello", "T-other").await,
        HostAccept::Replayed(first.clone())
    );
    assert_eq!(env.keyed("op-1").await, 1);
    assert_eq!(env.event("op-1").await, before);
    env.client()
        .execute(
            "UPDATE openmybot.channel_events SET fingerprint=NULL WHERE event_key='op:op-1'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        env.begin("op-1", "another message").await,
        HostAccept::Replayed(first)
    );
    assert_eq!(env.keyed("op-1").await, 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn same_operation_with_another_message_is_a_conflict_and_writes_nothing() {
    let mut env = Env::new().await;
    env.host().await;
    let first = accepted(env.begin("op-1", "first").await);
    assert_eq!(env.begin("op-1", "second").await, HostAccept::Conflict);
    assert_eq!(
        env.begin("op-1", "first").await,
        HostAccept::Replayed(first)
    );
    assert_eq!(env.keyed("op-1").await, 1);
    assert_eq!(env.event("op-1").await["text"], "first");
    accepted(env.begin("Op-1", "first").await);
    assert_eq!(env.keyed("Op-1").await, 1);
    assert_eq!(env.keyed("op-1").await, 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn no_live_host_binding_is_not_bound() {
    let mut env = Env::new().await;
    let events = "SELECT count(*) FROM openmybot.channel_events";
    assert_eq!(env.begin("op-1", "hello").await, HostAccept::NotBound);
    assert_eq!(env.count(events).await, 0);
    let host = env.host().await;
    revoke_binding(&mut env.session.client, host, deadline())
        .await
        .unwrap();
    assert_eq!(env.begin("op-1", "hello").await, HostAccept::NotBound);
    assert_eq!(env.count(events).await, 0);
    insert_sender(env.client(), "telegram", "1001", "telegram:42", "T1").await;
    assert_eq!(env.begin("op-1", "hello").await, HostAccept::NotBound);
    assert_eq!(env.count(events).await, 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn suspended_host_binding_is_refused_until_reconfirmed() {
    let mut env = Env::new().await;
    let host = env.host().await;
    suspend_binding(env.client(), host).await;
    assert_eq!(env.begin("op-1", "hello").await, HostAccept::Suspended);
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.channel_events")
            .await,
        0
    );
    reconfirm_binding(&mut env.session.client, host, 1, deadline())
        .await
        .unwrap();
    accepted(env.begin("op-1", "hello").await);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn queue_full_refuses_the_next_pending_but_still_replays() {
    let mut env = Env::new().await;
    let host = env.host().await;
    let mut runs = Vec::new();
    for index in 0..DISPATCH_QUEUE_MAX {
        runs.push(accepted(env.begin(&format!("op-{index}"), "work").await));
    }
    assert_eq!(env.begin("op-over", "work").await, HostAccept::QueueFull);
    let events = "SELECT count(*) FROM openmybot.channel_events";
    assert_eq!(env.count(events).await, DISPATCH_QUEUE_MAX);
    assert_eq!(
        env.begin("op-3", "work").await,
        HostAccept::Replayed(runs[3].clone())
    );
    assert_eq!(env.begin("op-3", "other").await, HostAccept::Conflict);
    assert_eq!(
        cancel_event(env.client(), host, &runs[0].run_id)
            .await
            .unwrap(),
        EventCancel::Cancelled
    );
    accepted(env.begin("op-over", "work").await);
    assert_eq!(env.count(events).await, DISPATCH_QUEUE_MAX + 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accepted_begins_are_claimed_oldest_first_one_open_run_at_a_time() {
    let mut env = Env::new().await;
    let host = env.host().await;
    let first = accepted(env.begin("op-1", "first").await);
    let second = accepted(env.begin("op-2", "second").await);
    let Claim::Item(item) = claim_dispatch(env.client()).await.unwrap() else {
        panic!("first claim");
    };
    let record = env.record("op-1").await;
    assert_eq!(item.record_id, record);
    assert_eq!(item.binding_id, host);
    assert_eq!(item.thread_id, first.thread_id);
    assert_eq!(item.run_id, first.run_id);
    assert_eq!(item.text, "first");
    assert_eq!(item.attempts, 0);
    record_dispatch(
        &mut env.session.client,
        record,
        DispatchOutcome::Dispatched,
        deadline(),
    )
    .await
    .unwrap();
    assert!(matches!(
        claim_dispatch(env.client()).await.unwrap(),
        Claim::Idle { .. }
    ));
    set_terminal(env.client(), record, "succeeded").await;
    let Claim::Item(item) = claim_dispatch(env.client()).await.unwrap() else {
        panic!("second claim");
    };
    assert_eq!(item.record_id, env.record("op-2").await);
    assert_eq!(item.run_id, second.run_id);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn concurrent_begins_with_one_operation_id_write_one_row() {
    let mut env = Env::new().await;
    env.host().await;
    let mut sessions = Vec::new();
    for _ in 0..4 {
        sessions.push(env.fixture.connect().await);
    }
    for round in 0..10 {
        let [a, b, c, d] = &mut sessions[..] else {
            unreachable!()
        };
        let same = format!("same-{round}");
        let outcomes = tokio::join!(
            begin(&mut a.client, &same, "work", "T-a"),
            begin(&mut b.client, &same, "work", "T-b"),
            begin(&mut c.client, &same, "work", "T-c"),
            begin(&mut d.client, &same, "work", "T-d"),
        );
        let outcomes = [outcomes.0, outcomes.1, outcomes.2, outcomes.3];
        let runs: Vec<HostRun> = outcomes
            .iter()
            .map(|outcome| match outcome {
                HostAccept::Accepted(run) | HostAccept::Replayed(run) => run.clone(),
                other => panic!("round {round}: {other:?}"),
            })
            .collect();
        let winners = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, HostAccept::Accepted(_)))
            .count();
        assert_eq!(winners, 1, "round {round}");
        assert!(runs.iter().all(|run| *run == runs[0]), "round {round}");
        assert_eq!(env.keyed(&same).await, 1, "round {round}");
        let split = format!("split-{round}");
        let outcomes = tokio::join!(
            begin(&mut a.client, &split, "message A", "T-a"),
            begin(&mut b.client, &split, "message A", "T-b"),
            begin(&mut c.client, &split, "message B", "T-c"),
            begin(&mut d.client, &split, "message B", "T-d"),
        );
        let stored = env.event(&split).await["text"].as_str().unwrap().to_owned();
        let (won, lost) = if stored == "message A" {
            ([outcomes.0, outcomes.1], [outcomes.2, outcomes.3])
        } else {
            ([outcomes.2, outcomes.3], [outcomes.0, outcomes.1])
        };
        let accepted = won
            .iter()
            .filter(|outcome| matches!(outcome, HostAccept::Accepted(_)))
            .count();
        let replayed = won
            .iter()
            .filter(|outcome| matches!(outcome, HostAccept::Replayed(_)))
            .count();
        assert_eq!((accepted, replayed), (1, 1), "round {round}");
        assert_eq!(
            lost,
            [HostAccept::Conflict, HostAccept::Conflict],
            "round {round}"
        );
        assert_eq!(env.keyed(&split).await, 1, "round {round}");
    }
    for session in sessions {
        session.close().await;
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn expiry_marks_host_events_without_a_notice_and_still_notifies_telegram() {
    let mut env = Env::new().await;
    let host = env.host().await;
    let sender = insert_sender(env.client(), "telegram", "1001", "telegram:42", "T1").await;
    accepted(env.begin("aged", "work").await);
    let hosted = env.record("aged").await;
    let telegram =
        insert_event_for_run(env.client(), sender, "run-telegram", "T1", "pending").await;
    shift_event(env.client(), hosted, "accepted_at", -7200.0).await;
    shift_event(env.client(), telegram, "accepted_at", -7200.0).await;
    let expired = expire_pending(
        &mut env.session.client,
        Duration::from_secs(3600),
        "NOTICE",
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(expired.count, 2);
    assert_eq!(expired.next_due, None);
    assert_eq!(env.row(hosted).await["dispatch_status"], "expired");
    let deliveries: Vec<Value> = env
        .client()
        .query("SELECT row_to_json(d) FROM openmybot.deliveries d", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0]["binding_id"], sender.to_string());
    assert_eq!(deliveries[0]["kind"], "expiry_notice");
    assert_eq!(deliveries[0]["channel_kind"], "telegram");
    assert_eq!(
        deliveries[0]["idempotency_key"],
        format!("expiry_notice:{telegram}")
    );
    assert!(
        deliveries
            .iter()
            .all(|delivery| delivery["binding_id"] != host.to_string())
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_acts_only_on_a_pending_run_of_the_binding() {
    let mut env = Env::new().await;
    let host = env.host().await;
    let pending = accepted(env.begin("op-p", "work").await);
    let p = env.record("op-p").await;
    assert_eq!(
        cancel_event(env.client(), host, &pending.run_id)
            .await
            .unwrap(),
        EventCancel::Cancelled
    );
    assert_eq!(env.row(p).await["dispatch_status"], "cancelled");
    assert_eq!(
        cancel_event(env.client(), host, &pending.run_id)
            .await
            .unwrap(),
        EventCancel::Ended
    );
    assert!(matches!(
        claim_dispatch(env.client()).await.unwrap(),
        Claim::Idle { .. }
    ));
    let client = env.client();
    let d = insert_event_for_run(client, host, "run-d", "T-D", "dispatched").await;
    let t = insert_event_for_run(client, host, "run-t", "T-T", "dispatched").await;
    set_terminal(client, t, "succeeded").await;
    let x = insert_event_for_run(client, host, "run-x", "T-X", "expired").await;
    let c = insert_event_for_run(client, host, "run-c", "T-C", "cancelled").await;
    let v = insert_event_for_run(client, host, "run-v", "T-V", "conflict").await;
    let pt = insert_event_for_run(client, host, "run-pt", "T-PT", "pending").await;
    set_terminal(client, pt, "failed").await;
    let sender = insert_sender(client, "telegram", "1001", "telegram:42", "T-S").await;
    let s = insert_event_for_run(client, sender, "run-s", "T-S", "dispatched").await;
    let before_d = env.row(d).await;
    assert_eq!(
        cancel_event(env.client(), host, "run-d").await.unwrap(),
        EventCancel::Open {
            thread_id: "T-D".into()
        }
    );
    assert_eq!(env.row(d).await, before_d);
    for (record, run) in [
        (t, "run-t"),
        (x, "run-x"),
        (c, "run-c"),
        (v, "run-v"),
        (pt, "run-pt"),
    ] {
        let before = env.row(record).await;
        assert_eq!(
            cancel_event(env.client(), host, run).await.unwrap(),
            EventCancel::Ended,
            "{run}"
        );
        assert_eq!(env.row(record).await, before, "{run}");
    }
    assert_eq!(env.row(pt).await["dispatch_status"], "pending");
    let before_s = env.row(s).await;
    for run in ["run-s", "run-missing"] {
        assert_eq!(
            cancel_event(env.client(), host, run).await.unwrap(),
            EventCancel::NotFound,
            "{run}"
        );
    }
    assert_eq!(env.row(s).await, before_s);
    assert_eq!(
        cancel_event(env.client(), sender, "run-s").await.unwrap(),
        EventCancel::Open {
            thread_id: "T-S".into()
        }
    );
    assert_eq!(env.row(s).await, before_s);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn cancel_racing_the_dispatch_receipt_leaves_one_consistent_outcome() {
    let mut env = Env::new().await;
    let host = env.host().await;
    let canceller = env.fixture.connect().await;
    let mut receipt = env.fixture.connect().await;
    for round in 0..10 {
        let id = format!("race-{round}");
        let run = accepted(env.begin(&id, "work").await);
        let record = env.record(&id).await;
        let (cancelled, dispatched) = tokio::join!(
            cancel_event(&canceller.client, host, &run.run_id),
            record_dispatch(
                &mut receipt.client,
                record,
                DispatchOutcome::Dispatched,
                deadline()
            ),
        );
        dispatched.unwrap();
        let row = env.row(record).await;
        match cancelled.unwrap() {
            EventCancel::Cancelled => {
                assert_eq!(row["dispatch_status"], "cancelled", "round {round}");
                assert_eq!(row["dispatch_attempts"], 0, "round {round}");
            }
            EventCancel::Open { thread_id } => {
                assert_eq!(thread_id, run.thread_id, "round {round}");
                assert_eq!(row["dispatch_status"], "dispatched", "round {round}");
                assert_eq!(row["dispatch_attempts"], 1, "round {round}");
            }
            other => panic!("round {round}: {other:?}"),
        }
    }
    canceller.close().await;
    receipt.close().await;
    env.stop().await;
}
