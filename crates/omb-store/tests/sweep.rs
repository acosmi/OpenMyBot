//! The cleaner against an own PostgreSQL 17.11 cluster; every age is moved relative to the
//! database clock.
use omb_store::{
    Decided, Decision, clear_content, delete_expired, migrate,
    testkit::{
        Fixture, Session, deadline, decide, insert_delivery, insert_ended_session,
        insert_event_for_run, insert_orphan_session, insert_permission_row, insert_sender,
        permission_row_json, read_row, set_terminal, shift_column,
    },
};
use serde_json::Value;
use std::time::Duration;
use tokio_postgres::Client;
use uuid::Uuid;

const DAY: f64 = 86_400.0;
const CONTENT: Duration = Duration::from_secs(7 * 24 * 3600);
const TOMBSTONE: Duration = Duration::from_secs(30 * 24 * 3600);

struct Env {
    fixture: Fixture,
    session: Session,
    sender: Uuid,
}
impl Env {
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
    /// An accepted message of `run` with `status`, accepted `accepted_days` ago.
    async fn event(&self, run: &str, status: &str, accepted_days: f64) -> Uuid {
        let id = insert_event_for_run(self.client(), self.sender, run, "T1", status).await;
        self.shift(
            "channel_events",
            "record_id",
            id,
            "accepted_at",
            accepted_days,
        )
        .await;
        id
    }
    async fn shift(&self, table: &str, key: &str, id: Uuid, column: &str, days: f64) {
        shift_column(self.client(), table, key, id, column, days * DAY).await;
    }
    async fn row(&self, table: &str, key: &str, id: Uuid) -> Value {
        read_row(self.client(), table, key, id).await
    }
    async fn exists(&self, table: &str, key: &str, id: Uuid) -> bool {
        self.client()
            .query_one(
                &format!("SELECT EXISTS (SELECT 1 FROM openmybot.{table} WHERE {key}=$1)"),
                &[&id],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn count(&self, sql: &str) -> i64 {
        self.client().query_one(sql, &[]).await.unwrap().get(0)
    }
    async fn clear(&self) -> u64 {
        clear_content(self.client(), CONTENT).await.unwrap()
    }
    async fn delete(&self) -> u64 {
        delete_expired(self.client(), TOMBSTONE).await.unwrap()
    }
    /// A control command event without text or run, accepted `days` ago.
    async fn command_event(&self, key: &str, days: f64) -> Uuid {
        let id = Uuid::now_v7();
        self.client().execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,command) VALUES ($1,'event','telegram','1001',$2,statement_timestamp()+make_interval(secs=>$3),$4,'control_command','status')", &[&id, &key, &(days * DAY), &self.sender]).await.unwrap();
        id
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
fn without(mut row: Value, columns: &[&str]) -> Value {
    for column in columns {
        row.as_object_mut().unwrap().remove(*column);
    }
    row
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_content_empties_event_text_keeping_sha_and_stamps_content_cleared_at() {
    let env = Env::new().await;
    let id = env.event("run-1", "dispatched", -9.0).await;
    set_terminal(env.client(), id, "succeeded").await;
    env.shift("channel_events", "record_id", id, "terminal_at", -8.0)
        .await;
    let before = env.row("channel_events", "record_id", id).await;
    assert_eq!(env.clear().await, 1);
    let after = env.row("channel_events", "record_id", id).await;
    assert_eq!(after["text"], "");
    assert_eq!(after["text_sha256"], before["text_sha256"]);
    assert!(after["content_cleared_at"].is_string());
    assert_eq!(
        without(after, &["text", "content_cleared_at"]),
        without(before, &["text", "content_cleared_at"])
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_content_times_events_with_terminal_by_terminal_at() {
    let env = Env::new().await;
    let recent = env.event("run-1", "dispatched", -40.0).await;
    set_terminal(env.client(), recent, "failed").await;
    env.shift("channel_events", "record_id", recent, "terminal_at", -1.0)
        .await;
    let old = env.event("run-2", "dispatched", -40.0).await;
    set_terminal(env.client(), old, "failed").await;
    env.shift("channel_events", "record_id", old, "terminal_at", -8.0)
        .await;
    assert_eq!(env.clear().await, 1);
    assert_eq!(
        env.row("channel_events", "record_id", recent).await["text"],
        "test message"
    );
    assert_eq!(
        env.row("channel_events", "record_id", old).await["text"],
        ""
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_content_times_conflict_expired_cancelled_events_without_terminal_by_accepted_at() {
    let env = Env::new().await;
    let mut old = Vec::new();
    for status in ["conflict", "expired", "cancelled"] {
        old.push(env.event(&format!("run-{status}"), status, -8.0).await);
        env.event(&format!("run-{status}-young"), status, -6.0)
            .await;
    }
    assert_eq!(env.clear().await, 3);
    for id in old {
        let row = env.row("channel_events", "record_id", id).await;
        assert_eq!(row["text"], "");
        assert!(row["content_cleared_at"].is_string());
    }
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.channel_events WHERE text='test message'")
            .await,
        3
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_content_keeps_pending_dispatched_open_and_younger_rows() {
    let env = Env::new().await;
    env.event("run-p", "pending", -20.0).await;
    env.event("run-d", "dispatched", -20.0).await;
    let young = env.event("run-y", "dispatched", -20.0).await;
    set_terminal(env.client(), young, "succeeded").await;
    env.shift("channel_events", "record_id", young, "terminal_at", -6.0)
        .await;
    assert_eq!(env.clear().await, 0);
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.channel_events WHERE text='test message' AND content_cleared_at IS NULL")
            .await,
        3
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_content_does_not_touch_non_message_event_rows() {
    let env = Env::new().await;
    let id = env.command_event("status-1", -20.0).await;
    let before = env.row("channel_events", "record_id", id).await;
    assert_eq!(env.clear().await, 0);
    let after = env.row("channel_events", "record_id", id).await;
    assert!(after["content_cleared_at"].is_null());
    assert_eq!(after, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_content_nulls_delivery_body_of_finished_rows_only() {
    let env = Env::new().await;
    let mut finished = Vec::new();
    for status in ["sent", "failed", "unknown"] {
        let id = insert_delivery(
            env.client(),
            env.sender,
            "control_reply",
            &format!("control_reply:{status}"),
            Some("body"),
            status,
            None,
        )
        .await;
        env.shift("deliveries", "delivery_id", id, "finished_at", -8.0)
            .await;
        finished.push(id);
    }
    let young = insert_delivery(
        env.client(),
        env.sender,
        "control_reply",
        "control_reply:young",
        Some("body"),
        "sent",
        None,
    )
    .await;
    env.shift("deliveries", "delivery_id", young, "finished_at", -6.0)
        .await;
    let mut open = Vec::new();
    for status in ["pending", "sending"] {
        let id = insert_delivery(
            env.client(),
            env.sender,
            "control_reply",
            &format!("control_reply:{status}"),
            Some("body"),
            status,
            None,
        )
        .await;
        env.shift("deliveries", "delivery_id", id, "created_at", -20.0)
            .await;
        open.push(id);
    }
    assert_eq!(env.clear().await, 3);
    let mut stamps = Vec::new();
    for id in &finished {
        let row = env.row("deliveries", "delivery_id", *id).await;
        assert!(row["body"].is_null());
        assert!(row["content_cleared_at"].is_string());
        stamps.push(row["content_cleared_at"].clone());
    }
    for id in open.iter().chain([&young]) {
        let row = env.row("deliveries", "delivery_id", *id).await;
        assert_eq!(row["body"], "body");
        assert!(row["content_cleared_at"].is_null());
    }
    assert_eq!(env.clear().await, 0);
    for (id, stamp) in finished.iter().zip(stamps) {
        assert_eq!(
            env.row("deliveries", "delivery_id", *id).await["content_cleared_at"],
            stamp
        );
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_content_nulls_session_summary_and_stderr_tail_of_ended_sessions_only() {
    let env = Env::new().await;
    let ended = insert_ended_session(
        env.client(),
        env.sender,
        "run-1",
        "result_success",
        Some("summary"),
        &["a.txt"],
    )
    .await;
    env.client()
        .execute(
            "UPDATE openmybot.host_driver_sessions SET stderr_tail='tail' WHERE record_id=$1",
            &[&ended],
        )
        .await
        .unwrap();
    env.shift("host_driver_sessions", "record_id", ended, "ended_at", -8.0)
        .await;
    let open = insert_orphan_session(env.client(), env.sender, "run-2", None).await;
    env.shift(
        "host_driver_sessions",
        "record_id",
        open,
        "started_at",
        -20.0,
    )
    .await;
    let before = env.row("host_driver_sessions", "record_id", open).await;
    assert_eq!(env.clear().await, 1);
    let row = env.row("host_driver_sessions", "record_id", ended).await;
    assert!(row["result_summary"].is_null());
    assert!(row["stderr_tail"].is_null());
    assert!(row["content_cleared_at"].is_string());
    assert_eq!(row["artifact_paths"], serde_json::json!(["a.txt"]));
    assert_eq!(
        env.row("host_driver_sessions", "record_id", open).await,
        before
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_content_nulls_input_summary_of_decided_permissions_only() {
    let env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-decided", 600.0).await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-open", 600.0).await;
    assert_eq!(
        decide(env.client(), "p-decided", Decision::Allow).await,
        Decided::Decided
    );
    env.client().execute("UPDATE openmybot.host_driver_sessions SET decided_at=statement_timestamp()-interval '8 days',requested_at=statement_timestamp()-interval '9 days' WHERE permission_id='p-decided'", &[]).await.unwrap();
    env.client().execute("UPDATE openmybot.host_driver_sessions SET requested_at=statement_timestamp()-interval '9 days' WHERE permission_id='p-open'", &[]).await.unwrap();
    assert_eq!(env.clear().await, 1);
    let decided = permission_row_json(env.client(), "p-decided").await;
    assert!(decided["input_summary"].is_null());
    assert!(decided["content_cleared_at"].is_string());
    let open = permission_row_json(env.client(), "p-open").await;
    assert!(open["input_summary"].is_string());
    assert!(open["content_cleared_at"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_removes_old_event_rows_and_keeps_younger_ones() {
    let env = Env::new().await;
    let old = env.event("run-1", "conflict", -31.0).await;
    let young = env.event("run-2", "conflict", -29.0).await;
    let bindings = env
        .count("SELECT count(*) FROM openmybot.channel_bindings")
        .await;
    assert_eq!(env.delete().await, 1);
    assert!(!env.exists("channel_events", "record_id", old).await);
    assert!(env.exists("channel_events", "record_id", young).await);
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.channel_bindings")
            .await,
        bindings
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_keeps_dispatched_run_without_terminal_regardless_of_age() {
    let env = Env::new().await;
    let open = env.event("run-1", "dispatched", -400.0).await;
    assert_eq!(env.delete().await, 0);
    assert!(env.exists("channel_events", "record_id", open).await);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_removes_conflict_expired_cancelled_pending_and_runless_events() {
    let env = Env::new().await;
    let mut gone = Vec::new();
    for status in ["conflict", "expired", "cancelled", "pending"] {
        gone.push(env.event(&format!("run-{status}"), status, -31.0).await);
    }
    gone.push(env.command_event("status-1", -31.0).await);
    let ended = env.event("run-ended", "dispatched", -31.0).await;
    set_terminal(env.client(), ended, "succeeded").await;
    gone.push(ended);
    assert_eq!(env.delete().await, 6);
    for id in gone {
        assert!(!env.exists("channel_events", "record_id", id).await);
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_removes_gap_rows_by_gap_ended_at_and_keeps_open_gaps() {
    let env = Env::new().await;
    let mut gaps = Vec::new();
    for ended in [Some(-31.0), Some(-29.0), None] {
        let id = Uuid::now_v7();
        env.client().execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,gap_started_at,gap_ended_at,gap_reason) VALUES ($1,'gap','telegram','1001',$4,statement_timestamp()-interval '60 days',$2,'gap',statement_timestamp()-interval '60 days',statement_timestamp()+make_interval(secs=>$3),'connect_failed')", &[&id, &env.sender, &ended.map(|days: f64| days * DAY), &format!("gap:{id}")]).await.unwrap();
        gaps.push(id);
    }
    assert_eq!(env.delete().await, 1);
    assert!(!env.exists("channel_events", "record_id", gaps[0]).await);
    assert!(env.exists("channel_events", "record_id", gaps[1]).await);
    assert!(env.exists("channel_events", "record_id", gaps[2]).await);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_removes_event_identity_so_the_key_inserts_again() {
    let env = Env::new().await;
    let insert = "INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,command) VALUES (gen_random_uuid(),'event','telegram','1001','update-7',statement_timestamp()-interval '31 days',$1,'control_command','status')";
    env.client().execute(insert, &[&env.sender]).await.unwrap();
    assert!(env.client().execute(insert, &[&env.sender]).await.is_err());
    assert_eq!(env.delete().await, 1);
    assert_eq!(
        env.client().execute(insert, &[&env.sender]).await.unwrap(),
        1
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_removes_finished_deliveries_and_keeps_unfinished() {
    let env = Env::new().await;
    let mut ids = Vec::new();
    for (status, finished_days) in [
        ("sent", Some(-31.0)),
        ("failed", Some(-29.0)),
        ("pending", None),
        ("sending", None),
    ] {
        let id = insert_delivery(
            env.client(),
            env.sender,
            "control_reply",
            &format!("control_reply:{status}"),
            Some("body"),
            status,
            None,
        )
        .await;
        env.shift("deliveries", "delivery_id", id, "created_at", -60.0)
            .await;
        if let Some(days) = finished_days {
            env.shift("deliveries", "delivery_id", id, "finished_at", days)
                .await;
        }
        ids.push(id);
    }
    assert_eq!(env.delete().await, 1);
    assert!(!env.exists("deliveries", "delivery_id", ids[0]).await);
    for id in &ids[1..] {
        assert!(env.exists("deliveries", "delivery_id", *id).await);
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_removes_permission_rows_together_with_their_old_session() {
    let env = Env::new().await;
    let session = insert_ended_session(
        env.client(),
        env.sender,
        "run-1",
        "result_success",
        None,
        &[],
    )
    .await;
    env.shift(
        "host_driver_sessions",
        "record_id",
        session,
        "ended_at",
        -31.0,
    )
    .await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-1", 600.0).await;
    assert_eq!(env.delete().await, 2);
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.host_driver_sessions")
            .await,
        0
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_removes_sessionless_permission_rows_by_requested_at() {
    let env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-old", 600.0).await;
    insert_permission_row(env.client(), env.sender, "run-2", "p-young", 600.0).await;
    env.client().execute("UPDATE openmybot.host_driver_sessions SET requested_at=statement_timestamp()-interval '31 days' WHERE permission_id='p-old'", &[]).await.unwrap();
    env.client().execute("UPDATE openmybot.host_driver_sessions SET requested_at=statement_timestamp()-interval '29 days' WHERE permission_id='p-young'", &[]).await.unwrap();
    assert_eq!(env.delete().await, 1);
    assert_eq!(
        env.count(
            "SELECT count(*) FROM openmybot.host_driver_sessions WHERE permission_id='p-young'"
        )
        .await,
        1
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_keeps_unended_sessions_and_their_permissions() {
    let env = Env::new().await;
    let session = insert_orphan_session(env.client(), env.sender, "run-1", None).await;
    env.shift(
        "host_driver_sessions",
        "record_id",
        session,
        "started_at",
        -60.0,
    )
    .await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-1", 600.0).await;
    env.client().execute("UPDATE openmybot.host_driver_sessions SET requested_at=statement_timestamp()-interval '59 days' WHERE permission_id='p-1'", &[]).await.unwrap();
    assert_eq!(env.delete().await, 0);
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.host_driver_sessions")
            .await,
        2
    );
    env.stop().await;
}

async fn token(client: &Client, hours_ago: f64) -> Uuid {
    let id = Uuid::now_v7();
    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(id.as_bytes());
    client.execute("INSERT INTO openmybot.control_tokens(token_id,token_sha256,daemon_pid,engine_pin,omb_version,pg_system_identifier,pg_timeline_id,restore_detected,created_at,last_heartbeat_at,revoked_at,revoke_reason) VALUES ($1,$2,1,'0123456789abcdef0123456789abcdef01234567','0.0.0','test',1,false,statement_timestamp()-make_interval(secs=>$3),statement_timestamp(),statement_timestamp(),'daemon_stop')", &[&id, &digest.as_slice(), &(hours_ago * 3600.0)]).await.unwrap();
    id
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_removes_non_latest_unreferenced_control_tokens_only() {
    let env = Env::new().await;
    let oldest = token(env.client(), 3.0).await;
    let older = token(env.client(), 2.0).await;
    let newest = token(env.client(), 1.0).await;
    assert_eq!(env.delete().await, 2);
    assert!(!env.exists("control_tokens", "token_id", oldest).await);
    assert!(!env.exists("control_tokens", "token_id", older).await);
    assert!(env.exists("control_tokens", "token_id", newest).await);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_keeps_non_latest_token_referenced_by_a_retained_permission_row() {
    let env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-1", 600.0).await;
    assert_eq!(
        decide(env.client(), "p-1", Decision::Allow).await,
        Decided::Decided
    );
    let referenced: Uuid = env
        .client()
        .query_one(
            "SELECT decided_by_token FROM openmybot.host_driver_sessions WHERE permission_id='p-1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    env.shift("control_tokens", "token_id", referenced, "created_at", -1.0)
        .await;
    let newest = token(env.client(), 0.0).await;
    assert_eq!(env.delete().await, 0);
    assert!(env.exists("control_tokens", "token_id", referenced).await);
    env.client().execute("UPDATE openmybot.host_driver_sessions SET requested_at=statement_timestamp()-interval '31 days' WHERE permission_id='p-1'", &[]).await.unwrap();
    assert_eq!(env.delete().await, 2);
    assert!(!env.exists("control_tokens", "token_id", referenced).await);
    assert!(env.exists("control_tokens", "token_id", newest).await);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delete_expired_loops_batches_until_empty_under_two_second_statement_timeout() {
    let env = Env::new().await;
    env.client()
        .batch_execute("SET statement_timeout='2s'")
        .await
        .unwrap();
    env.client().execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,text,text_sha256,run_id,thread_id,dispatch_status) SELECT gen_random_uuid(),'event','telegram','1001','bulk:'||g,statement_timestamp()-interval '31 days',$1,'accepted_message','x',sha256('x'::bytea),'bulk-run-'||g,'T1','conflict' FROM generate_series(1,1200) g", &[&env.sender]).await.unwrap();
    assert_eq!(env.delete().await, 1200);
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.channel_events")
            .await,
        0
    );
    env.stop().await;
}
