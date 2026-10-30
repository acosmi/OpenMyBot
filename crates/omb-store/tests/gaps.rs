//! Heartbeat, interruption intervals, receiver suspension and the status view against an own
//! PostgreSQL 17.11 cluster.
use omb_store::{
    Channel, ControlTokenStart, PollGapReason, Suspension, channel_status, close_poll_gaps,
    migrate, open_poll_gap, read_heartbeat, reconfirm_binding, record_startup_gaps,
    start_control_token, stop_control_token, suspend_receiver,
    testkit::{Fixture, Session, deadline, insert_receiver, insert_sender},
    touch_heartbeat,
};
use std::time::Duration;
use time::OffsetDateTime;
use tokio_postgres::Client;
use uuid::Uuid;

const GAP: Duration = Duration::from_secs(90);

struct Env {
    fixture: Fixture,
    session: Session,
    telegram: Uuid,
}
impl Env {
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        let telegram = insert_receiver(&session.client, "telegram", "1001").await;
        Self {
            fixture,
            session,
            telegram,
        }
    }
    async fn token(&mut self) -> Uuid {
        let token_id = Uuid::now_v7();
        let mut digest = [0; 32];
        digest[..16].copy_from_slice(token_id.as_bytes());
        start_control_token(
            &mut self.session.client,
            ControlTokenStart {
                token_id,
                token_sha256: digest,
                daemon_pid: 1,
                engine_pin: "0123456789abcdef0123456789abcdef01234567",
                omb_version: "0.0.0",
            },
            deadline(),
        )
        .await
        .unwrap();
        token_id
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
async fn gaps(client: &Client) -> Vec<(Uuid, String, OffsetDateTime, Option<OffsetDateTime>)> {
    client
        .query("SELECT binding_id,gap_reason,gap_started_at,gap_ended_at FROM openmybot.channel_events WHERE record_kind='gap' ORDER BY accepted_at,record_id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect()
}
async fn heartbeat(client: &Client, token: Uuid) -> OffsetDateTime {
    read_heartbeat(client, token).await.unwrap().unwrap()
}
async fn set_heartbeat(client: &Client, token: Uuid, seconds_ago: f64) {
    client.execute("UPDATE openmybot.control_tokens SET last_heartbeat_at=statement_timestamp()-make_interval(secs=>$2) WHERE token_id=$1", &[&token, &seconds_ago]).await.unwrap();
}
async fn binding(client: &Client, id: Uuid) -> (String, Option<String>, Option<OffsetDateTime>) {
    let row = client.query_one("SELECT status,status_reason,suspended_at FROM openmybot.channel_bindings WHERE binding_id=$1", &[&id]).await.unwrap();
    (row.get(0), row.get(1), row.get(2))
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn touch_heartbeat_returns_previous_value_and_read_heartbeat_returns_stored_value() {
    let mut env = Env::new().await;
    let token = env.token().await;
    assert_eq!(
        read_heartbeat(&env.session.client, Uuid::now_v7())
            .await
            .unwrap(),
        None
    );
    let initial = heartbeat(&env.session.client, token).await;
    let tick = touch_heartbeat(&mut env.session.client, token, GAP, deadline())
        .await
        .unwrap();
    assert_eq!(tick.previous, initial);
    assert!(tick.now > initial);
    assert_eq!(tick.gaps_written, 0);
    assert_eq!(heartbeat(&env.session.client, token).await, tick.now);
    let next = touch_heartbeat(&mut env.session.client, token, GAP, deadline())
        .await
        .unwrap();
    assert_eq!(next.previous, tick.now);
    assert!(
        touch_heartbeat(&mut env.session.client, Uuid::now_v7(), GAP, deadline())
            .await
            .is_err()
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn first_start_without_previous_token_writes_no_gap() {
    let mut env = Env::new().await;
    let token = env.token().await;
    let written = record_startup_gaps(&mut env.session.client, token, deadline())
        .await
        .unwrap();
    assert_eq!((written.daemon_down, written.receiver_suspended), (0, 0));
    assert!(gaps(&env.session.client).await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn startup_gap_spans_previous_heartbeat_to_start_per_active_receiver() {
    let mut env = Env::new().await;
    let feishu = insert_receiver(&env.session.client, "feishu", "cli_app").await;
    let first = env.token().await;
    set_heartbeat(&env.session.client, first, 600.0).await;
    let last = heartbeat(&env.session.client, first).await;
    let second = env.token().await;
    let created: OffsetDateTime = env
        .session
        .client
        .query_one(
            "SELECT created_at FROM openmybot.control_tokens WHERE token_id=$1",
            &[&second],
        )
        .await
        .unwrap()
        .get(0);
    let reason: String = env
        .session
        .client
        .query_one(
            "SELECT revoke_reason FROM openmybot.control_tokens WHERE token_id=$1",
            &[&first],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(reason, "daemon_restart");
    let written = record_startup_gaps(&mut env.session.client, second, deadline())
        .await
        .unwrap();
    assert_eq!((written.daemon_down, written.receiver_suspended), (2, 0));
    let rows = gaps(&env.session.client).await;
    let mut receivers: Vec<Uuid> = rows.iter().map(|g| g.0).collect();
    receivers.sort();
    let mut expected = vec![env.telegram, feishu];
    expected.sort();
    assert_eq!(receivers, expected);
    for (_, reason, started, ended) in rows {
        assert_eq!(reason, "daemon_down");
        assert_eq!(started, last);
        let ended = ended.unwrap();
        assert!(
            ended >= created && ended <= OffsetDateTime::now_utc() + time::Duration::seconds(5)
        );
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn startup_gap_after_graceful_stop_starts_at_stop_time() {
    let mut env = Env::new().await;
    let first = env.token().await;
    set_heartbeat(&env.session.client, first, 600.0).await;
    stop_control_token(&mut env.session.client, first, deadline())
        .await
        .unwrap();
    let stopped: OffsetDateTime = env
        .session
        .client
        .query_one(
            "SELECT revoked_at FROM openmybot.control_tokens WHERE token_id=$1",
            &[&first],
        )
        .await
        .unwrap()
        .get(0);
    let second = env.token().await;
    let written = record_startup_gaps(&mut env.session.client, second, deadline())
        .await
        .unwrap();
    assert_eq!(written.daemon_down, 1);
    let rows = gaps(&env.session.client).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "daemon_down");
    assert_eq!(rows[0].2, stopped);
    assert!(rows[0].3.unwrap() >= stopped);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn startup_gap_skips_non_active_receivers() {
    let mut env = Env::new().await;
    env.token().await;
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='revoked',status_reason='owner_revoked',ended_at=statement_timestamp() WHERE binding_id=$1", &[&env.telegram]).await.unwrap();
    let feishu = insert_receiver(&env.session.client, "feishu", "cli_app").await;
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='credential_rejected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&feishu]).await.unwrap();
    let second = env.token().await;
    let written = record_startup_gaps(&mut env.session.client, second, deadline())
        .await
        .unwrap();
    assert_eq!(written.daemon_down, 0);
    assert!(
        gaps(&env.session.client)
            .await
            .iter()
            .all(|g| g.1 != "daemon_down")
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn startup_scan_writes_receiver_suspended_gap_from_suspended_at() {
    let mut env = Env::new().await;
    let first = env.token().await;
    // A different cluster identity makes the next start a restore: active bindings are suspended.
    env.session
        .client
        .execute(
            "UPDATE openmybot.control_tokens SET pg_system_identifier='0' WHERE token_id=$1",
            &[&first],
        )
        .await
        .unwrap();
    let second = env.token().await;
    let (status, reason, suspended_at) = binding(&env.session.client, env.telegram).await;
    assert_eq!(
        (status.as_str(), reason.as_deref()),
        ("suspended", Some("restore_detected"))
    );
    let written = record_startup_gaps(&mut env.session.client, second, deadline())
        .await
        .unwrap();
    assert_eq!((written.daemon_down, written.receiver_suspended), (0, 1));
    let rows = gaps(&env.session.client).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, env.telegram);
    assert_eq!(rows[0].1, "receiver_suspended");
    assert_eq!(Some(rows[0].2), suspended_at);
    assert_eq!(rows[0].3, None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn startup_scan_does_not_duplicate_open_receiver_suspended_gap() {
    let mut env = Env::new().await;
    let token = env.token().await;
    suspend_receiver(
        &mut env.session.client,
        env.telegram,
        Suspension::CredentialRejected,
        deadline(),
    )
    .await
    .unwrap();
    for _ in 0..2 {
        let written = record_startup_gaps(&mut env.session.client, token, deadline())
            .await
            .unwrap();
        assert_eq!(written.receiver_suspended, 0);
    }
    env.session.client.execute("UPDATE openmybot.channel_events SET gap_ended_at=statement_timestamp() WHERE record_kind='gap'", &[]).await.unwrap();
    let written = record_startup_gaps(&mut env.session.client, token, deadline())
        .await
        .unwrap();
    assert_eq!(written.receiver_suspended, 1);
    assert_eq!(gaps(&env.session.client).await.len(), 2);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn heartbeat_interval_over_gap_threshold_writes_daemon_suspended_per_active_receiver() {
    let mut env = Env::new().await;
    let feishu = insert_receiver(&env.session.client, "feishu", "cli_app").await;
    let token = env.token().await;
    set_heartbeat(&env.session.client, token, 120.0).await;
    let previous = heartbeat(&env.session.client, token).await;
    let tick = touch_heartbeat(&mut env.session.client, token, GAP, deadline())
        .await
        .unwrap();
    assert_eq!(tick.previous, previous);
    assert_eq!(tick.gaps_written, 2);
    let rows = gaps(&env.session.client).await;
    let mut receivers: Vec<Uuid> = rows.iter().map(|g| g.0).collect();
    receivers.sort();
    let mut expected = vec![env.telegram, feishu];
    expected.sort();
    assert_eq!(receivers, expected);
    for (_, reason, started, ended) in rows {
        assert_eq!(reason, "daemon_suspended");
        assert_eq!((started, ended), (previous, Some(tick.now)));
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn heartbeat_interval_at_or_below_threshold_writes_no_gap() {
    let mut env = Env::new().await;
    let token = env.token().await;
    set_heartbeat(&env.session.client, token, 60.0).await;
    let tick = touch_heartbeat(&mut env.session.client, token, GAP, deadline())
        .await
        .unwrap();
    assert_eq!(tick.gaps_written, 0);
    // Strictly greater: an interval exactly at the threshold is not a gap.
    set_heartbeat(&env.session.client, token, 30.0).await;
    let tick = touch_heartbeat(
        &mut env.session.client,
        token,
        Duration::from_secs(3600),
        deadline(),
    )
    .await
    .unwrap();
    let interval = tick.now - tick.previous;
    assert_eq!(tick.gaps_written, 0);
    let exact = Duration::try_from(interval).unwrap();
    let equal: bool = env
        .session
        .client
        .query_one(
            "SELECT $1::timestamptz-$2::timestamptz>make_interval(secs=>$3)",
            &[&tick.now, &tick.previous, &exact.as_secs_f64()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!equal);
    assert!(gaps(&env.session.client).await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn connect_failure_opens_gap_and_success_closes_it() {
    let mut env = Env::new().await;
    open_poll_gap(
        &mut env.session.client,
        env.telegram,
        PollGapReason::ConnectFailed,
        deadline(),
    )
    .await
    .unwrap();
    let rows = gaps(&env.session.client).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "connect_failed");
    assert_eq!(rows[0].3, None);
    assert_eq!(
        close_poll_gaps(&mut env.session.client, env.telegram, deadline())
            .await
            .unwrap(),
        1
    );
    let rows = gaps(&env.session.client).await;
    assert!(rows[0].3.unwrap() >= rows[0].2);
    assert_eq!(
        close_poll_gaps(&mut env.session.client, env.telegram, deadline())
            .await
            .unwrap(),
        0
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn repeated_failures_with_mixed_reasons_keep_one_open_gap() {
    let mut env = Env::new().await;
    for reason in [
        PollGapReason::StreamBroken,
        PollGapReason::ConnectFailed,
        PollGapReason::StreamBroken,
        PollGapReason::ConnectFailed,
    ] {
        open_poll_gap(&mut env.session.client, env.telegram, reason, deadline())
            .await
            .unwrap();
    }
    let rows = gaps(&env.session.client).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "stream_broken");
    close_poll_gaps(&mut env.session.client, env.telegram, deadline())
        .await
        .unwrap();
    open_poll_gap(
        &mut env.session.client,
        env.telegram,
        PollGapReason::ConnectFailed,
        deadline(),
    )
    .await
    .unwrap();
    let rows = gaps(&env.session.client).await;
    assert_eq!(rows.len(), 2);
    assert_eq!((rows[1].1.as_str(), rows[1].3), ("connect_failed", None));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn close_poll_gaps_leaves_other_reasons_open() {
    let mut env = Env::new().await;
    open_poll_gap(
        &mut env.session.client,
        env.telegram,
        PollGapReason::ConnectFailed,
        deadline(),
    )
    .await
    .unwrap();
    suspend_receiver(
        &mut env.session.client,
        env.telegram,
        Suspension::WebhookConflict,
        deadline(),
    )
    .await
    .unwrap();
    env.session.client.execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,gap_started_at,gap_reason) SELECT r,'gap','telegram','1001','gap:'||r,statement_timestamp(),$1,'gap',statement_timestamp(),'daemon_suspended' FROM gen_random_uuid() r", &[&env.telegram]).await.unwrap();
    assert_eq!(
        close_poll_gaps(&mut env.session.client, env.telegram, deadline())
            .await
            .unwrap(),
        1
    );
    let rows = gaps(&env.session.client).await;
    for (_, reason, _, ended) in rows {
        assert_eq!(ended.is_some(), reason == "connect_failed", "{reason}");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn suspend_receiver_sets_status_reason_and_opens_receiver_suspended_gap() {
    let mut env = Env::new().await;
    let feishu = insert_receiver(&env.session.client, "feishu", "cli_app").await;
    for (receiver, why, reason) in [
        (
            env.telegram,
            Suspension::CredentialRejected,
            "credential_rejected",
        ),
        (feishu, Suspension::WebhookConflict, "webhook_conflict"),
    ] {
        suspend_receiver(&mut env.session.client, receiver, why, deadline())
            .await
            .unwrap();
        let (status, stored, suspended_at) = binding(&env.session.client, receiver).await;
        assert_eq!(
            (status.as_str(), stored.as_deref()),
            ("suspended", Some(reason))
        );
        let rows = gaps(&env.session.client).await;
        let gap = rows.iter().find(|g| g.0 == receiver).unwrap();
        assert_eq!(gap.1, "receiver_suspended");
        assert_eq!((Some(gap.2), gap.3), (suspended_at, None));
    }
    suspend_receiver(
        &mut env.session.client,
        env.telegram,
        Suspension::WebhookConflict,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        binding(&env.session.client, env.telegram)
            .await
            .1
            .as_deref(),
        Some("credential_rejected")
    );
    assert_eq!(gaps(&env.session.client).await.len(), 2);
    let sender = insert_sender(
        &env.session.client,
        "telegram",
        "1001",
        "telegram:42",
        "thread-A",
    )
    .await;
    suspend_receiver(
        &mut env.session.client,
        sender,
        Suspension::CredentialRejected,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(binding(&env.session.client, sender).await.0, "active");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reconfirm_closes_receiver_suspended_gap() {
    let mut env = Env::new().await;
    suspend_receiver(
        &mut env.session.client,
        env.telegram,
        Suspension::CredentialRejected,
        deadline(),
    )
    .await
    .unwrap();
    open_poll_gap(
        &mut env.session.client,
        env.telegram,
        PollGapReason::StreamBroken,
        deadline(),
    )
    .await
    .unwrap();
    let revision = reconfirm_binding(&mut env.session.client, env.telegram, 3, deadline())
        .await
        .unwrap();
    assert_eq!(revision, 2);
    let reconfirmed: OffsetDateTime = env
        .session
        .client
        .query_one(
            "SELECT reconfirmed_at FROM openmybot.channel_bindings WHERE binding_id=$1",
            &[&env.telegram],
        )
        .await
        .unwrap()
        .get(0);
    let rows = gaps(&env.session.client).await;
    let suspended = rows.iter().find(|g| g.1 == "receiver_suspended").unwrap();
    assert_eq!(suspended.3, Some(reconfirmed));
    let polling = rows.iter().find(|g| g.1 == "stream_broken").unwrap();
    assert_eq!(polling.3, None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn gap_rows_satisfy_check_constraints_and_use_gap_event_key() {
    let mut env = Env::new().await;
    env.token().await;
    let second = env.token().await;
    record_startup_gaps(&mut env.session.client, second, deadline())
        .await
        .unwrap();
    set_heartbeat(&env.session.client, second, 200.0).await;
    touch_heartbeat(&mut env.session.client, second, GAP, deadline())
        .await
        .unwrap();
    open_poll_gap(
        &mut env.session.client,
        env.telegram,
        PollGapReason::ConnectFailed,
        deadline(),
    )
    .await
    .unwrap();
    suspend_receiver(
        &mut env.session.client,
        env.telegram,
        Suspension::CredentialRejected,
        deadline(),
    )
    .await
    .unwrap();
    let rows = env.session.client.query("SELECT record_id,event_key,binding_id,channel_kind,source_key,disposition,gap_reason,fingerprint IS NULL AND text IS NULL AND sender_key IS NULL AND run_id IS NULL FROM openmybot.channel_events WHERE record_kind='gap' ORDER BY accepted_at", &[]).await.unwrap();
    let reasons: Vec<String> = rows.iter().map(|r| r.get(6)).collect();
    assert_eq!(
        reasons,
        [
            "daemon_down",
            "daemon_suspended",
            "connect_failed",
            "receiver_suspended"
        ]
    );
    for row in &rows {
        let id: Uuid = row.get(0);
        assert_eq!(row.get::<_, String>(1), format!("gap:{id}"));
        assert_eq!(row.get::<_, Uuid>(2), env.telegram);
        assert_eq!(row.get::<_, String>(3), "telegram");
        assert_eq!(row.get::<_, String>(4), "1001");
        assert_eq!(row.get::<_, String>(5), "gap");
        assert!(row.get::<_, bool>(7));
    }
    let violation = env.session.client.execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,disposition) VALUES (gen_random_uuid(),'gap','telegram','1001','gap:x',statement_timestamp(),'gap')", &[]).await;
    assert!(violation.is_err());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn status_lists_gaps_within_seven_days_newest_first_and_open_gaps_always() {
    let env = Env::new().await;
    for (reason, started_days, ended_days) in [
        ("stream_broken", 9.0, Some(8.0)),
        ("connect_failed", 7.5, Some(6.5)),
        ("receiver_suspended", 10.0, None),
        ("daemon_down", 1.0, Some(0.5)),
    ] {
        env.session.client.execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,gap_started_at,gap_ended_at,gap_reason) SELECT r,'gap','telegram','1001','gap:'||r,statement_timestamp(),$1,'gap',statement_timestamp()-make_interval(secs=>$2),statement_timestamp()-make_interval(secs=>$3),$4 FROM gen_random_uuid() r", &[&env.telegram, &(started_days * 86400.0), &ended_days.map(|d: f64| d * 86400.0), &reason]).await.unwrap();
    }
    let status = channel_status(&env.session.client).await.unwrap();
    assert_eq!(status.len(), 1);
    let reasons: Vec<&str> = status[0].gaps.iter().map(|g| g.reason.as_str()).collect();
    assert_eq!(
        reasons,
        ["daemon_down", "connect_failed", "receiver_suspended"]
    );
    assert!(status[0].gaps[2].ended_at.is_none());
    assert!(
        status[0]
            .gaps
            .windows(2)
            .all(|w| w[0].started_at >= w[1].started_at)
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn status_counts_pending_dispatch_per_receiver() {
    let env = Env::new().await;
    let feishu = insert_receiver(&env.session.client, "feishu", "cli_app").await;
    let a = insert_sender(
        &env.session.client,
        "telegram",
        "1001",
        "telegram:42",
        "thread-A",
    )
    .await;
    let b = insert_sender(
        &env.session.client,
        "feishu",
        "cli_app",
        "feishu:ou_1",
        "thread-B",
    )
    .await;
    for (binding, channel, source, status, count) in [
        (a, "telegram", "1001", "pending", 3),
        (a, "telegram", "1001", "dispatched", 2),
        (b, "feishu", "cli_app", "pending", 1),
        (b, "feishu", "cli_app", "expired", 4),
    ] {
        for _ in 0..count {
            env.session.client.execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,text,text_sha256,run_id,thread_id,dispatch_status) SELECT r,'event',$2,$3,r::text,statement_timestamp(),$1,'accepted_message','x',sha256('x'),r::text,'thread',$4 FROM gen_random_uuid() r", &[&binding, &channel, &source, &status]).await.unwrap();
        }
    }
    let status = channel_status(&env.session.client).await.unwrap();
    let pending: Vec<(Channel, Uuid, u64)> = status
        .iter()
        .map(|s| (s.channel, s.binding_id, s.pending_dispatch))
        .collect();
    assert_eq!(
        pending,
        [
            (Channel::Feishu, feishu, 1),
            (Channel::Telegram, env.telegram, 3)
        ]
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn status_lists_only_active_and_suspended_receivers() {
    let mut env = Env::new().await;
    let feishu = insert_receiver(&env.session.client, "feishu", "cli_app").await;
    insert_sender(
        &env.session.client,
        "telegram",
        "1001",
        "telegram:42",
        "thread-A",
    )
    .await;
    suspend_receiver(
        &mut env.session.client,
        feishu,
        Suspension::CredentialRejected,
        deadline(),
    )
    .await
    .unwrap();
    let status = channel_status(&env.session.client).await.unwrap();
    let listed: Vec<(Uuid, String, Option<String>)> = status
        .iter()
        .map(|s| (s.binding_id, s.status.clone(), s.status_reason.clone()))
        .collect();
    assert_eq!(
        listed,
        [
            (
                feishu,
                "suspended".into(),
                Some("credential_rejected".into())
            ),
            (env.telegram, "active".into(), None)
        ]
    );
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='revoked',status_reason='owner_revoked',ended_at=statement_timestamp() WHERE binding_id=$1", &[&feishu]).await.unwrap();
    let status = channel_status(&env.session.client).await.unwrap();
    assert_eq!(
        status.iter().map(|s| s.binding_id).collect::<Vec<_>>(),
        [env.telegram]
    );
    env.stop().await;
}
