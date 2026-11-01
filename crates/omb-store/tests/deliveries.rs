//! Terminal recording, the delivery claim and the end of one attempt against an own PostgreSQL
//! 17.11 cluster.
use omb_store::{
    ChannelKind, Claimed, DeliveryContent, DispatchOutcome, ErrorCode, Finish, GrantKind,
    RunResultFacts, StoreError, TerminalKind, TerminalWrite, claim_delivery, finish_delivery,
    lock_dispatch, migrate, record_dispatch, record_terminal, run_result_facts, send_target,
    testkit::{
        Fixture, Session, deadline, insert_delivery, insert_ended_session, insert_event_for_run,
        insert_host_binding, insert_receiver_with, insert_sender, read_row, set_terminal,
        shift_column,
    },
};
use serde_json::Value;
use std::time::Duration;
use tokio_postgres::Client;
use uuid::Uuid;

struct Env {
    fixture: Fixture,
    session: Session,
    sender: Uuid,
}
impl Env {
    /// A Telegram sender on source `1001`, chat `telegram:42`, thread `T1`.
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        let sender = insert_sender(&session.client, "telegram", "1001", "telegram:42", "T1").await;
        Self {
            fixture,
            session,
            sender,
        }
    }
    fn client(&self) -> &Client {
        &self.session.client
    }
    async fn event(&self, run: &str, status: &str) -> Uuid {
        insert_event_for_run(self.client(), self.sender, run, "T1", status).await
    }
    async fn record(&mut self, run: &str, kind: TerminalKind) -> Option<TerminalWrite> {
        record_terminal(&mut self.session.client, run, kind, deadline())
            .await
            .unwrap()
    }
    async fn delivery(&self, kind: &str, key: &str, body: Option<&str>, status: &str) -> Uuid {
        insert_delivery(self.client(), self.sender, kind, key, body, status, None).await
    }
    async fn row(&self, id: Uuid) -> Value {
        read_row(self.client(), "deliveries", "delivery_id", id).await
    }
    async fn claim(&self) -> Option<Claimed> {
        claim_delivery(self.client(), deadline()).await.unwrap()
    }
    async fn count(&self, sql: &str) -> i64 {
        self.client().query_one(sql, &[]).await.unwrap().get(0)
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
/// Every row of the three tables a terminal write may touch, as one sorted text.
async fn dump(client: &Client) -> String {
    let mut all = String::new();
    for table in ["channel_bindings", "channel_events", "deliveries"] {
        let text: String = client
            .query_one(
                &format!("SELECT coalesce(string_agg(row_to_json(x)::text, ',' ORDER BY row_to_json(x)::text), '') FROM openmybot.{table} x"),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        all.push_str(&text);
    }
    all
}
async fn results(client: &Client, run: &str) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM openmybot.deliveries WHERE idempotency_key=$1",
            &[&format!("result:{run}")],
        )
        .await
        .unwrap()
        .get(0)
}
async fn set_status(client: &Client, binding: Uuid, status: &str) {
    assert_eq!(client.execute("UPDATE openmybot.channel_bindings SET status=$2,ended_at=CASE WHEN $2 IN ('revoked','expired') THEN statement_timestamp() END WHERE binding_id=$1", &[&binding, &status]).await.unwrap(), 1);
}
const FAIL_INSERT: &str = "CREATE FUNCTION openmybot.fail_row() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test failure'; END$$; CREATE TRIGGER fail_insert BEFORE INSERT ON openmybot.deliveries FOR EACH ROW EXECUTE FUNCTION openmybot.fail_row()";

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_writes_terminal_columns_and_inserts_one_pending_run_result_for_sender() {
    let mut env = Env::new().await;
    let event = env.event("run-1", "dispatched").await;
    let written = env.record("run-1", TerminalKind::Succeeded).await.unwrap();
    assert_eq!(
        written,
        TerminalWrite {
            written: true,
            binding_kind: GrantKind::Sender,
            binding_id: env.sender,
            chat_key: Some("telegram:42".into()),
            channel_kind: "telegram".into(),
        }
    );
    let stored = read_row(env.client(), "channel_events", "record_id", event).await;
    assert_eq!(stored["terminal_kind"], "succeeded");
    assert!(stored["terminal_at"].is_string());
    let rows = env
        .client()
        .query("SELECT row_to_json(d) FROM openmybot.deliveries d", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row: Value = rows[0].get(0);
    assert_eq!(row["kind"], "run_result");
    assert_eq!(row["idempotency_key"], "result:run-1");
    assert_eq!(row["status"], "pending");
    assert!(row["body"].is_null());
    assert_eq!(row["attempts"], 0);
    assert_eq!(row["binding_id"], env.sender.to_string());
    assert_eq!(row["chat_key"], "telegram:42");
    assert_eq!(row["channel_kind"], "telegram");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_stores_each_of_the_four_kinds() {
    let mut env = Env::new().await;
    for (index, (kind, text)) in [
        (TerminalKind::Succeeded, "succeeded"),
        (TerminalKind::Failed, "failed"),
        (TerminalKind::Cancelled, "cancelled"),
        (
            TerminalKind::ReconciliationRequired,
            "reconciliation_required",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let run = format!("run-{index}");
        let event = env.event(&run, "dispatched").await;
        assert!(env.record(&run, kind).await.unwrap().written);
        let stored = read_row(env.client(), "channel_events", "record_id", event).await;
        assert_eq!(stored["terminal_kind"], text);
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_does_not_require_dispatched_status_and_dispatch_keeps_the_terminal() {
    let mut env = Env::new().await;
    let event = env.event("run-1", "pending").await;
    assert!(
        env.record("run-1", TerminalKind::Failed)
            .await
            .unwrap()
            .written
    );
    let stored = read_row(env.client(), "channel_events", "record_id", event).await;
    assert_eq!(stored["dispatch_status"], "pending");
    assert_eq!(stored["terminal_kind"], "failed");
    let dispatch = lock_dispatch(&mut env.session.client, event, deadline())
        .await
        .unwrap()
        .unwrap();
    record_dispatch(dispatch, event, DispatchOutcome::Dispatched, deadline())
        .await
        .unwrap();
    let stored = read_row(env.client(), "channel_events", "record_id", event).await;
    assert_eq!(stored["dispatch_status"], "dispatched");
    assert_eq!(stored["terminal_kind"], "failed");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_for_host_binding_writes_terminal_columns_only() {
    let mut env = Env::new().await;
    let host = insert_host_binding(env.client(), "/w/host").await;
    let event = insert_event_for_run(env.client(), host, "run-h", "T9", "dispatched").await;
    let written = env.record("run-h", TerminalKind::Succeeded).await.unwrap();
    assert!(written.written);
    assert_eq!(written.binding_kind, GrantKind::Host);
    assert_eq!(written.binding_id, host);
    assert_eq!(written.chat_key, None);
    let stored = read_row(env.client(), "channel_events", "record_id", event).await;
    assert_eq!(stored["terminal_kind"], "succeeded");
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_second_call_is_noop_and_keeps_first_kind() {
    let mut env = Env::new().await;
    let event = env.event("run-1", "dispatched").await;
    assert!(
        env.record("run-1", TerminalKind::Succeeded)
            .await
            .unwrap()
            .written
    );
    let first = read_row(env.client(), "channel_events", "record_id", event).await;
    for kind in [TerminalKind::Succeeded, TerminalKind::Failed] {
        let again = env.record("run-1", kind).await.unwrap();
        assert!(!again.written);
        assert_eq!(again.binding_id, env.sender);
    }
    let stored = read_row(env.client(), "channel_events", "record_id", event).await;
    assert_eq!(stored["terminal_kind"], "succeeded");
    assert_eq!(stored["terminal_at"], first["terminal_at"]);
    assert_eq!(results(env.client(), "run-1").await, 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_for_unknown_run_returns_none_and_writes_nothing() {
    let mut env = Env::new().await;
    env.event("run-1", "dispatched").await;
    let before = dump(env.client()).await;
    assert_eq!(
        env.record("run-unknown", TerminalKind::Succeeded).await,
        None
    );
    assert_eq!(dump(env.client()).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_inserts_pending_row_for_suspended_and_revoked_sender() {
    let mut env = Env::new().await;
    env.event("run-s", "dispatched").await;
    env.event("run-r", "dispatched").await;
    set_status(env.client(), env.sender, "suspended").await;
    assert!(
        env.record("run-s", TerminalKind::Succeeded)
            .await
            .unwrap()
            .written
    );
    set_status(env.client(), env.sender, "revoked").await;
    assert!(
        env.record("run-r", TerminalKind::Failed)
            .await
            .unwrap()
            .written
    );
    for run in ["run-s", "run-r"] {
        let status: String = env
            .client()
            .query_one(
                "SELECT status FROM openmybot.deliveries WHERE idempotency_key=$1",
                &[&format!("result:{run}")],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(status, "pending");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_event_and_delivery_roll_back_together_on_insert_failure() {
    let mut env = Env::new().await;
    let event = env.event("run-1", "dispatched").await;
    env.client().batch_execute(FAIL_INSERT).await.unwrap();
    assert_eq!(
        record_terminal(
            &mut env.session.client,
            "run-1",
            TerminalKind::Succeeded,
            deadline()
        )
        .await,
        Err(StoreError::DeliveryFailed)
    );
    let stored = read_row(env.client(), "channel_events", "record_id", event).await;
    assert!(stored["terminal_kind"].is_null());
    assert!(stored["terminal_at"].is_null());
    env.client()
        .batch_execute("DROP TRIGGER fail_insert ON openmybot.deliveries")
        .await
        .unwrap();
    assert!(
        env.record("run-1", TerminalKind::Succeeded)
            .await
            .unwrap()
            .written
    );
    assert_eq!(results(env.client(), "run-1").await, 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_keeps_preexisting_idempotency_row_untouched() {
    let mut env = Env::new().await;
    env.event("run-1", "dispatched").await;
    let existing = env
        .delivery("run_result", "result:run-1", Some("earlier"), "failed")
        .await;
    let before = env.row(existing).await;
    assert!(
        env.record("run-1", TerminalKind::Succeeded)
            .await
            .unwrap()
            .written
    );
    assert_eq!(results(env.client(), "run-1").await, 1);
    assert_eq!(env.row(existing).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn record_terminal_past_deadline_fails_and_leaves_no_open_transaction() {
    let mut env = Env::new().await;
    env.event("run-1", "dispatched").await;
    let pid: i32 = env
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let holder = env.fixture.connect().await;
    holder
        .client
        .batch_execute(
            "BEGIN; SELECT 1 FROM openmybot.channel_events WHERE run_id='run-1' FOR UPDATE",
        )
        .await
        .unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        holder.client.batch_execute("COMMIT").await.unwrap();
        holder
    });
    let short = tokio::time::Instant::now() + Duration::from_millis(300);
    assert_eq!(
        record_terminal(
            &mut env.session.client,
            "run-1",
            TerminalKind::Succeeded,
            short
        )
        .await,
        Err(StoreError::DeliveryFailed)
    );
    release.await.unwrap().close().await;
    let other = env.fixture.connect().await;
    let limit = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let row = other
            .client
            .query_one(
                "SELECT state='idle' AND xact_start IS NULL FROM pg_stat_activity WHERE pid=$1",
                &[&pid],
            )
            .await
            .unwrap();
        if row.get::<_, bool>(0) {
            break;
        }
        assert!(tokio::time::Instant::now() < limit, "transaction left open");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    other.close().await;
    let stored: Option<String> = env
        .client()
        .query_one(
            "SELECT terminal_kind FROM openmybot.channel_events WHERE run_id='run-1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, None);
    assert!(
        env.record("run-1", TerminalKind::Succeeded)
            .await
            .unwrap()
            .written
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn concurrent_record_terminal_writes_once_per_round() {
    let mut env = Env::new().await;
    let mut a = env.fixture.connect().await;
    let mut b = env.fixture.connect().await;
    let mut c = env.fixture.connect().await;
    for round in 0..10 {
        let run = format!("run-{round}");
        let event = env.event(&run, "dispatched").await;
        let (x, y, z) = tokio::join!(
            record_terminal(&mut a.client, &run, TerminalKind::Succeeded, deadline()),
            record_terminal(&mut b.client, &run, TerminalKind::Failed, deadline()),
            record_terminal(&mut c.client, &run, TerminalKind::Cancelled, deadline()),
        );
        let outcomes = [
            x.unwrap().unwrap(),
            y.unwrap().unwrap(),
            z.unwrap().unwrap(),
        ];
        let winners: Vec<_> = outcomes
            .iter()
            .zip(["succeeded", "failed", "cancelled"])
            .filter(|(write, _)| write.written)
            .map(|(_, kind)| kind)
            .collect();
        assert_eq!(winners.len(), 1, "round {round}");
        let stored = read_row(env.client(), "channel_events", "record_id", event).await;
        assert_eq!(stored["terminal_kind"], *winners[0], "round {round}");
        assert_eq!(results(env.client(), &run).await, 1, "round {round}");
    }
    for session in [a, b, c] {
        session.close().await;
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_delivery_marks_sending_counts_attempt_and_keeps_first_attempt_at() {
    let env = Env::new().await;
    let id = env
        .delivery("control_reply", "control_reply:1", Some("hi"), "pending")
        .await;
    let claimed = env.claim().await.unwrap();
    assert_eq!(claimed.delivery_id, id);
    assert_eq!(claimed.attempts, 1);
    let first = env.row(id).await;
    assert_eq!(first["status"], "sending");
    assert_eq!(first["attempts"], 1);
    assert!(first["first_attempt_at"].is_string());
    finish_delivery(
        env.client(),
        id,
        Finish::Retry {
            after: Duration::ZERO,
            code: ErrorCode::ServerError,
        },
        deadline(),
    )
    .await
    .unwrap();
    let again = env.claim().await.unwrap();
    assert_eq!(again.attempts, 2);
    let second = env.row(id).await;
    assert_eq!(second["attempts"], 2);
    assert_eq!(second["first_attempt_at"], first["first_attempt_at"]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_delivery_takes_oldest_created_at_first() {
    let env = Env::new().await;
    let mut ids = Vec::new();
    for (index, age) in [-30.0, -10.0, -20.0].into_iter().enumerate() {
        let id = env
            .delivery(
                "control_reply",
                &format!("control_reply:{index}"),
                Some("x"),
                "pending",
            )
            .await;
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
    let mut order = Vec::new();
    while let Some(claimed) = env.claim().await {
        order.push(claimed.delivery_id);
    }
    assert_eq!(order, [ids[0], ids[2], ids[1]]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_delivery_honours_next_attempt_at() {
    let env = Env::new().await;
    let unscheduled = env
        .delivery("control_reply", "control_reply:a", Some("a"), "pending")
        .await;
    let due = insert_delivery(
        env.client(),
        env.sender,
        "control_reply",
        "control_reply:b",
        Some("b"),
        "pending",
        Some(-5.0),
    )
    .await;
    let later = insert_delivery(
        env.client(),
        env.sender,
        "control_reply",
        "control_reply:c",
        Some("c"),
        "pending",
        Some(3600.0),
    )
    .await;
    let mut claimed = vec![
        env.claim().await.unwrap().delivery_id,
        env.claim().await.unwrap().delivery_id,
    ];
    claimed.sort();
    let mut expected = vec![unscheduled, due];
    expected.sort();
    assert_eq!(claimed, expected);
    assert_eq!(env.claim().await, None);
    assert_eq!(env.row(later).await["status"], "pending");
    shift_column(
        env.client(),
        "deliveries",
        "delivery_id",
        later,
        "next_attempt_at",
        -1.0,
    )
    .await;
    assert_eq!(env.claim().await.unwrap().delivery_id, later);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_delivery_ignores_non_pending_rows_and_empty_table_returns_none() {
    let env = Env::new().await;
    assert_eq!(env.claim().await, None);
    let mut ids = Vec::new();
    for status in ["sending", "sent", "failed", "unknown"] {
        ids.push(
            env.delivery(
                "control_reply",
                &format!("control_reply:{status}"),
                Some("x"),
                status,
            )
            .await,
        );
    }
    let before: Vec<Value> = rows_of(&env, &ids).await;
    assert_eq!(env.claim().await, None);
    assert_eq!(rows_of(&env, &ids).await, before);
    env.stop().await;
}
async fn rows_of(env: &Env, ids: &[Uuid]) -> Vec<Value> {
    let mut rows = Vec::new();
    for id in ids {
        rows.push(env.row(*id).await);
    }
    rows
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_delivery_claims_feishu_rows_with_channel_and_idempotency_key() {
    let env = Env::new().await;
    let feishu = insert_sender(env.client(), "feishu", "2002", "feishu:7", "T2").await;
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
    assert_eq!(env.row(id).await["channel_kind"], "feishu");
    let claimed = env.claim().await.unwrap();
    assert_eq!(claimed.delivery_id, id);
    assert_eq!(claimed.binding_id, feishu);
    assert_eq!(claimed.channel, ChannelKind::from_static("feishu"));
    assert_eq!(claimed.chat_key, "feishu:7");
    assert_eq!(claimed.idempotency_key, "control_reply:f");
    assert_eq!(claimed.attempts, 1);
    assert_eq!(claimed.content, DeliveryContent::Text("x".into()));
    assert_eq!(env.row(id).await["status"], "sending");
    let telegram = env
        .delivery("control_reply", "control_reply:t", Some("y"), "pending")
        .await;
    let claimed = env.claim().await.unwrap();
    assert_eq!(claimed.delivery_id, telegram);
    assert_eq!(claimed.channel, ChannelKind::from_static("telegram"));
    assert_eq!(claimed.chat_key, "telegram:42");
    assert_eq!(claimed.idempotency_key, "control_reply:t");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_delivery_claims_slack_rows_of_a_plugin_channel() {
    let env = Env::new().await;
    let slack = insert_sender(env.client(), "slack", "T0SLACK", "slack:C1", "T3").await;
    let id = insert_delivery(
        env.client(),
        slack,
        "control_reply",
        "control_reply:s",
        Some("z"),
        "pending",
        None,
    )
    .await;
    let claimed = env.claim().await.unwrap();
    assert_eq!(claimed.delivery_id, id);
    assert_eq!(claimed.channel, ChannelKind::from_static("slack"));
    assert_eq!(claimed.chat_key, "slack:C1");
    assert_eq!(env.row(id).await["status"], "sending");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_delivery_returns_text_for_stored_kinds_and_run_id_for_run_result() {
    let env = Env::new().await;
    let mut expected = Vec::new();
    for kind in [
        "permission_notice",
        "control_reply",
        "pairing_reply",
        "reject_reply",
        "expiry_notice",
    ] {
        let body = format!("body of {kind}");
        let id = env
            .delivery(kind, &format!("{kind}:1"), Some(&body), "pending")
            .await;
        expected.push((id, DeliveryContent::Text(body)));
    }
    let id = env
        .delivery("run_result", "result:run-9", None, "pending")
        .await;
    expected.push((
        id,
        DeliveryContent::RunResult {
            run_id: "run-9".into(),
        },
    ));
    let mut seen = Vec::new();
    while let Some(claimed) = env.claim().await {
        assert_eq!(claimed.binding_id, env.sender);
        assert_eq!(claimed.chat_key, "telegram:42");
        seen.push((claimed.delivery_id, claimed.content));
    }
    seen.sort_by_key(|(id, _)| *id);
    expected.sort_by_key(|(id, _)| *id);
    assert_eq!(seen, expected);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn concurrent_claims_of_one_pending_row_claim_it_once() {
    let mut env = Env::new().await;
    let a = env.fixture.connect().await;
    let b = env.fixture.connect().await;
    for round in 0..10 {
        env.delivery(
            "control_reply",
            &format!("control_reply:{round}"),
            Some("x"),
            "pending",
        )
        .await;
        let (x, y) = tokio::join!(
            claim_delivery(&a.client, deadline()),
            claim_delivery(&b.client, deadline())
        );
        let claims: Vec<Claimed> = [x.unwrap(), y.unwrap()].into_iter().flatten().collect();
        assert_eq!(claims.len(), 1, "round {round}");
        assert_eq!(claims[0].attempts, 1, "round {round}");
        assert_eq!(
            env.count("SELECT count(*) FROM openmybot.deliveries WHERE status='pending'")
                .await,
            0,
            "round {round}"
        );
    }
    a.close().await;
    b.close().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn finish_sent_records_message_id_and_finished_at_and_clears_schedule() {
    let env = Env::new().await;
    let id = env
        .delivery("control_reply", "control_reply:1", Some("x"), "pending")
        .await;
    env.claim().await.unwrap();
    finish_delivery(
        env.client(),
        id,
        Finish::Sent {
            platform_message_id: "4711",
        },
        deadline(),
    )
    .await
    .unwrap();
    let row = env.row(id).await;
    assert_eq!(row["status"], "sent");
    assert_eq!(row["platform_message_id"], "4711");
    assert!(row["finished_at"].is_string());
    assert!(row["next_attempt_at"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn finish_retry_returns_row_to_pending_with_next_attempt_and_code() {
    let env = Env::new().await;
    let id = env
        .delivery("control_reply", "control_reply:1", Some("x"), "pending")
        .await;
    env.claim().await.unwrap();
    finish_delivery(
        env.client(),
        id,
        Finish::Retry {
            after: Duration::from_secs(60),
            code: ErrorCode::RateLimited,
        },
        deadline(),
    )
    .await
    .unwrap();
    let row = env.row(id).await;
    assert_eq!(row["status"], "pending");
    assert_eq!(row["last_error_code"], "rate_limited");
    assert!(row["finished_at"].is_null());
    assert_eq!(row["attempts"], 1);
    let ahead: f64 = env
        .client()
        .query_one(
            "SELECT extract(epoch FROM next_attempt_at-statement_timestamp())::float8 FROM openmybot.deliveries WHERE delivery_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert!((55.0..=60.0).contains(&ahead), "{ahead}");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn finish_failed_and_unknown_set_finished_at_code_and_no_schedule() {
    let env = Env::new().await;
    for (index, (finish, status, code)) in [
        (
            Finish::Failed {
                code: ErrorCode::ClientError,
            },
            "failed",
            "client_error",
        ),
        (
            Finish::Unknown {
                code: ErrorCode::ResultUnknown,
            },
            "unknown",
            "result_unknown",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let id = env
            .delivery(
                "control_reply",
                &format!("control_reply:{index}"),
                Some("x"),
                "pending",
            )
            .await;
        assert_eq!(env.claim().await.unwrap().delivery_id, id);
        finish_delivery(env.client(), id, finish, deadline())
            .await
            .unwrap();
        let row = env.row(id).await;
        assert_eq!(row["status"], status);
        assert!(row["finished_at"].is_string());
        assert_eq!(row["last_error_code"], code);
        assert!(row["next_attempt_at"].is_null());
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn finish_of_row_not_sending_is_refused_without_change() {
    let env = Env::new().await;
    for status in ["pending", "sent"] {
        let id = env
            .delivery(
                "control_reply",
                &format!("control_reply:{status}"),
                Some("x"),
                status,
            )
            .await;
        let before = env.row(id).await;
        assert_eq!(
            finish_delivery(
                env.client(),
                id,
                Finish::Sent {
                    platform_message_id: "1"
                },
                deadline()
            )
            .await,
            Err(StoreError::DeliveryFailed)
        );
        assert_eq!(
            finish_delivery(
                env.client(),
                id,
                Finish::Failed {
                    code: ErrorCode::ClientError
                },
                deadline()
            )
            .await,
            Err(StoreError::DeliveryFailed)
        );
        assert_eq!(env.row(id).await, before);
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn send_target_reports_sender_status_and_the_active_receiver_of_its_channel() {
    let env = Env::new().await;
    let receiver = Uuid::now_v7();
    insert_receiver_with(
        env.client(),
        receiver,
        "telegram",
        "1001",
        "sealed-envelope",
    )
    .await;
    for (status, active) in [
        ("active", true),
        ("suspended", false),
        ("revoked", false),
        ("expired", false),
    ] {
        set_status(env.client(), env.sender, status).await;
        let target = send_target(
            env.client(),
            env.sender,
            ChannelKind::from_static("telegram"),
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(target.sender_active, active, "{status}");
        let (row, revision) = target.receiver.unwrap();
        assert_eq!(row.binding_id, receiver);
        assert_eq!(row.channel, ChannelKind::from_static("telegram"));
        assert_eq!(row.source_key, "1001");
        assert_eq!(row.credential_envelope, "sealed-envelope");
        assert_eq!(revision, 1);
    }
    let feishu_sender = insert_sender(env.client(), "feishu", "cli_a", "feishu:7", "T2").await;
    let feishu = Uuid::now_v7();
    insert_receiver_with(env.client(), feishu, "feishu", "cli_a", "feishu-envelope").await;
    let target = send_target(
        env.client(),
        feishu_sender,
        ChannelKind::from_static("feishu"),
        deadline(),
    )
    .await
    .unwrap();
    assert!(target.sender_active);
    let (row, revision) = target.receiver.unwrap();
    assert_eq!(row.binding_id, feishu);
    assert_eq!(row.channel, ChannelKind::from_static("feishu"));
    assert_eq!(row.source_key, "cli_a");
    assert_eq!(row.credential_envelope, "feishu-envelope");
    assert_eq!(revision, 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn send_target_without_an_active_receiver_of_its_channel_has_none() {
    let env = Env::new().await;
    let none = send_target(
        env.client(),
        env.sender,
        ChannelKind::from_static("telegram"),
        deadline(),
    )
    .await
    .unwrap();
    assert!(none.sender_active);
    assert!(none.receiver.is_none());
    let feishu = Uuid::now_v7();
    insert_receiver_with(env.client(), feishu, "feishu", "cli_a", "feishu-envelope").await;
    let only_feishu = send_target(
        env.client(),
        env.sender,
        ChannelKind::from_static("telegram"),
        deadline(),
    )
    .await
    .unwrap();
    assert!(only_feishu.receiver.is_none());
    let receiver = Uuid::now_v7();
    insert_receiver_with(
        env.client(),
        receiver,
        "telegram",
        "1001",
        "sealed-envelope",
    )
    .await;
    for status in ["suspended", "revoked"] {
        set_status(env.client(), receiver, status).await;
        let target = send_target(
            env.client(),
            env.sender,
            ChannelKind::from_static("telegram"),
            deadline(),
        )
        .await
        .unwrap();
        assert!(target.receiver.is_none(), "{status}");
    }
    // A Feishu sender is served only by the Feishu receiver.
    let feishu_sender = insert_sender(env.client(), "feishu", "cli_a", "feishu:7", "T2").await;
    set_status(env.client(), feishu, "suspended").await;
    let telegram = Uuid::now_v7();
    insert_receiver_with(
        env.client(),
        telegram,
        "telegram",
        "1001",
        "sealed-envelope",
    )
    .await;
    let only_telegram = send_target(
        env.client(),
        feishu_sender,
        ChannelKind::from_static("feishu"),
        deadline(),
    )
    .await
    .unwrap();
    assert!(only_telegram.sender_active);
    assert!(only_telegram.receiver.is_none());
    for status in ["suspended", "revoked"] {
        set_status(env.client(), feishu, status).await;
        let target = send_target(
            env.client(),
            feishu_sender,
            ChannelKind::from_static("feishu"),
            deadline(),
        )
        .await
        .unwrap();
        assert!(target.receiver.is_none(), "{status}");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn run_result_facts_return_kind_summary_and_artifacts_of_the_session() {
    let env = Env::new().await;
    let with = env.event("run-1", "dispatched").await;
    set_terminal(env.client(), with, "succeeded").await;
    insert_ended_session(
        env.client(),
        env.sender,
        "run-1",
        "result_success",
        Some("all done"),
        &["src/a.rs", "b.txt"],
    )
    .await;
    assert_eq!(
        run_result_facts(env.client(), "run-1", deadline())
            .await
            .unwrap(),
        RunResultFacts {
            terminal: TerminalKind::Succeeded,
            result_summary: Some("all done".into()),
            artifact_paths: vec!["src/a.rs".into(), "b.txt".into()],
        }
    );
    let without = env.event("run-2", "dispatched").await;
    set_terminal(env.client(), without, "cancelled").await;
    assert_eq!(
        run_result_facts(env.client(), "run-2", deadline())
            .await
            .unwrap(),
        RunResultFacts {
            terminal: TerminalKind::Cancelled,
            result_summary: None,
            artifact_paths: Vec::new(),
        }
    );
    env.stop().await;
}
