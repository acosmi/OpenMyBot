//! Dispatch claim, receipt recording and expiry against an own PostgreSQL 17.11 cluster.
use omb_store::{
    AcceptOutcome, ChannelKind, Claim, Content, DispatchOutcome, Disposition, IdentityKey,
    NormalizedEvent, ReplyTexts, StateLabels, accept_event, claim_dispatch, expire_pending,
    lock_dispatch, migrate, record_dispatch, revoke_binding,
    testkit::{
        Fixture, Session, deadline, insert_receiver, insert_sender, set_terminal, shift_event,
    },
};
use std::time::Duration;
use time::OffsetDateTime;
use tokio_postgres::Client;
use uuid::Uuid;

const STATES: StateLabels<'static> = StateLabels {
    none: "-",
    queued: "-",
    running: "-",
    conflict: "-",
    expired: "-",
    cancelled: "-",
    succeeded: "-",
    failed: "-",
    reconciliation: "-",
};
const REPLIES: ReplyTexts<'static> = ReplyTexts {
    help: "-",
    already_bound: "-",
    unknown_command: "-",
    cancel_requested: "-",
    cancel_none: "-",
    status: "-",
    states: STATES,
    outside_window: "-",
    too_long: "-",
    unsupported: "-",
    queue_full: "-",
};
const TTL: Duration = Duration::from_secs(24 * 3600);

struct Env {
    fixture: Fixture,
    session: Session,
    telegram: Uuid,
    feishu: Uuid,
    a: Uuid,
    b: Uuid,
}
impl Env {
    /// Telegram sender `a` and Feishu sender `b`, each behind an active receiver.
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        let telegram = insert_receiver(&session.client, "telegram", "1001").await;
        let feishu = insert_receiver(&session.client, "feishu", "cli_app").await;
        let a = insert_sender(
            &session.client,
            "telegram",
            "1001",
            "telegram:42",
            "thread-A",
        )
        .await;
        let b = insert_sender(
            &session.client,
            "feishu",
            "cli_app",
            "feishu:ou_1",
            "thread-B",
        )
        .await;
        Self {
            fixture,
            session,
            telegram,
            feishu,
            a,
            b,
        }
    }
    /// Accepts one message for sender `a` (`telegram`) or `b` (`feishu`) and returns its record id.
    async fn message(&mut self, telegram: bool, key: &str) -> Uuid {
        let (channel, source, sender, receiver) = if telegram {
            (
                ChannelKind::from_static("telegram"),
                "1001",
                "telegram:42",
                self.telegram,
            )
        } else {
            (
                ChannelKind::from_static("feishu"),
                "cli_app",
                "feishu:ou_1",
                self.feishu,
            )
        };
        let incoming = NormalizedEvent {
            channel,
            source_key: source.into(),
            event_key: key.into(),
            event_type: "message".into(),
            occurred_at: Some(OffsetDateTime::now_utc()),
            private: true,
            sender: IdentityKey::parse(sender),
            chat: IdentityKey::parse(sender),
            fingerprint: Some([key.len() as u8; 32]),
            content: Content::Text {
                text: format!("text {key}"),
                command: None,
                pair_code: None,
            },
        };
        assert_eq!(
            accept_event(
                &mut self.session.client,
                receiver,
                &incoming,
                &REPLIES,
                deadline()
            )
            .await
            .unwrap(),
            AcceptOutcome::Recorded(Disposition::AcceptedMessage)
        );
        self.session
            .client
            .query_one(
                "SELECT record_id FROM openmybot.channel_events WHERE event_key=$1 AND source_key=$2",
                &[&key, &source],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn claim(&self) -> Option<Uuid> {
        match claim_dispatch(&self.session.client).await.unwrap() {
            Claim::Item(item) => Some(item.record_id),
            Claim::Idle { .. } => None,
        }
    }
    /// Records `outcome` as the dispatcher does: under the event's lock, only while it is pending.
    async fn record(&mut self, id: Uuid, outcome: DispatchOutcome) {
        if let Some(dispatch) = lock_dispatch(&mut self.session.client, id, deadline())
            .await
            .unwrap()
        {
            record_dispatch(dispatch, id, outcome, deadline())
                .await
                .unwrap();
        }
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
async fn event(client: &Client, id: Uuid) -> serde_json::Value {
    omb_store::testkit::read_row(client, "channel_events", "record_id", id).await
}
async fn binding(client: &Client, id: Uuid) -> (String, Option<String>, bool) {
    let row = client.query_one("SELECT status,status_reason,suspended_at IS NOT NULL FROM openmybot.channel_bindings WHERE binding_id=$1", &[&id]).await.unwrap();
    (row.get(0), row.get(1), row.get(2))
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claims_oldest_pending_event_per_active_binding_in_accepted_order() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    let b1 = env.message(false, "b1").await;
    let a2 = env.message(true, "a2").await;
    let Claim::Item(item) = claim_dispatch(&env.session.client).await.unwrap() else {
        panic!("item expected");
    };
    assert_eq!(item.record_id, a1);
    assert_eq!(item.binding_id, env.a);
    assert_eq!(item.revision, 1);
    assert_eq!(item.thread_id, "thread-A");
    assert_eq!(item.text, "text a1");
    assert_eq!(item.attempts, 0);
    assert_eq!(item.run_id, event(&env.session.client, a1).await["run_id"]);
    env.record(a1, DispatchOutcome::Dispatched).await;
    assert_eq!(env.claim().await, Some(b1));
    env.record(b1, DispatchOutcome::Dispatched).await;
    assert_eq!(env.claim().await, None);
    set_terminal(&env.session.client, a1, "succeeded").await;
    assert_eq!(env.claim().await, Some(a2));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn at_most_one_non_terminal_run_per_binding() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    env.message(true, "a2").await;
    env.message(true, "a3").await;
    env.record(a1, DispatchOutcome::Dispatched).await;
    for _ in 0..3 {
        assert_eq!(env.claim().await, None);
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn terminal_marker_releases_next_event() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    let a2 = env.message(true, "a2").await;
    env.record(a1, DispatchOutcome::Dispatched).await;
    assert_eq!(env.claim().await, None);
    for kind in ["failed", "cancelled", "succeeded"] {
        set_terminal(&env.session.client, a1, kind).await;
        assert_eq!(env.claim().await, Some(a2), "{kind}");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn latest_reconciliation_required_pauses_binding() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    let a2 = env.message(true, "a2").await;
    let a3 = env.message(true, "a3").await;
    env.record(a1, DispatchOutcome::Dispatched).await;
    set_terminal(&env.session.client, a1, "reconciliation_required").await;
    assert_eq!(env.claim().await, None);
    // A newer dispatched run with an ordinary terminal supersedes the older reconciliation.
    env.record(a2, DispatchOutcome::Dispatched).await;
    set_terminal(&env.session.client, a2, "succeeded").await;
    assert_eq!(env.claim().await, Some(a3));
    let b1 = env.message(false, "b1").await;
    env.record(a3, DispatchOutcome::Dispatched).await;
    set_terminal(&env.session.client, a3, "reconciliation_required").await;
    env.message(true, "a4").await;
    assert_eq!(env.claim().await, Some(b1));
    env.record(b1, DispatchOutcome::Conflict).await;
    assert_eq!(env.claim().await, None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn suspended_or_revoked_binding_is_not_claimed() {
    let mut env = Env::new().await;
    env.message(true, "a1").await;
    let b1 = env.message(false, "b1").await;
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&env.a]).await.unwrap();
    assert_eq!(env.claim().await, Some(b1));
    revoke_binding(&mut env.session.client, env.b, deadline())
        .await
        .unwrap();
    assert_eq!(
        event(&env.session.client, b1).await["dispatch_status"],
        "cancelled"
    );
    env.session
        .client
        .execute(
            "UPDATE openmybot.channel_events SET dispatch_status='pending' WHERE record_id=$1",
            &[&b1],
        )
        .await
        .unwrap();
    assert_eq!(env.claim().await, None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_does_not_filter_by_channel_kind() {
    let mut env = Env::new().await;
    let b1 = env.message(false, "b1").await;
    let Claim::Item(item) = claim_dispatch(&env.session.client).await.unwrap() else {
        panic!("feishu item expected");
    };
    assert_eq!((item.record_id, item.binding_id), (b1, env.b));
    assert_eq!(item.thread_id, "thread-B");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn retry_scheduled_head_blocks_later_events_and_reports_wake_time() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    env.message(true, "a2").await;
    env.record(a1, DispatchOutcome::RetryAfter(Duration::from_secs(60)))
        .await;
    let next: OffsetDateTime = env
        .session
        .client
        .query_one(
            "SELECT next_dispatch_at FROM openmybot.channel_events WHERE record_id=$1",
            &[&a1],
        )
        .await
        .unwrap()
        .get(0);
    let Claim::Idle { wake_at } = claim_dispatch(&env.session.client).await.unwrap() else {
        panic!("idle expected");
    };
    assert_eq!(wake_at, Some(next));
    let b1 = env.message(false, "b1").await;
    env.record(b1, DispatchOutcome::RetryAfter(Duration::from_secs(30)))
        .await;
    let sooner: OffsetDateTime = env
        .session
        .client
        .query_one(
            "SELECT next_dispatch_at FROM openmybot.channel_events WHERE record_id=$1",
            &[&b1],
        )
        .await
        .unwrap()
        .get(0);
    let Claim::Idle { wake_at } = claim_dispatch(&env.session.client).await.unwrap() else {
        panic!("idle expected");
    };
    assert_eq!(wake_at, Some(sooner));
    env.session.client.execute("UPDATE openmybot.channel_events SET next_dispatch_at=statement_timestamp()-interval '1 second' WHERE record_id=$1", &[&a1]).await.unwrap();
    assert_eq!(env.claim().await, Some(a1));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn dispatched_outcome_records_status_time_and_attempts() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    env.record(a1, DispatchOutcome::RetryAfter(Duration::from_secs(0)))
        .await;
    env.record(a1, DispatchOutcome::Dispatched).await;
    let stored = event(&env.session.client, a1).await;
    assert_eq!(stored["dispatch_status"], "dispatched");
    assert_eq!(stored["dispatch_attempts"], 2);
    assert!(!stored["dispatched_at"].is_null());
    assert!(stored["terminal_kind"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn conflict_outcome_is_final_and_not_reclaimed() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    let a2 = env.message(true, "a2").await;
    env.record(a1, DispatchOutcome::Conflict).await;
    let stored = event(&env.session.client, a1).await;
    assert_eq!(stored["dispatch_status"], "conflict");
    assert_eq!(stored["dispatch_attempts"], 1);
    assert_eq!(env.claim().await, Some(a2));
    env.record(a1, DispatchOutcome::Dispatched).await;
    assert_eq!(
        event(&env.session.client, a1).await["dispatch_status"],
        "conflict"
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn retry_after_keeps_pending_increments_attempts_and_sets_next_time() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    for attempt in 1..=3 {
        env.record(a1, DispatchOutcome::RetryAfter(Duration::from_secs(5)))
            .await;
        let row = env.session.client.query_one("SELECT dispatch_status,dispatch_attempts,extract(epoch FROM next_dispatch_at-statement_timestamp())::float8 FROM openmybot.channel_events WHERE record_id=$1", &[&a1]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "pending");
        assert_eq!(row.get::<_, i32>(1), attempt);
        let remaining: f64 = row.get(2);
        assert!((3.0..=5.0).contains(&remaining), "{remaining}");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn outcome_is_ignored_when_event_is_no_longer_pending() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    assert_eq!(env.claim().await, Some(a1));
    revoke_binding(&mut env.session.client, env.a, deadline())
        .await
        .unwrap();
    let before = event(&env.session.client, a1).await;
    assert_eq!(before["dispatch_status"], "cancelled");
    for outcome in [
        DispatchOutcome::Dispatched,
        DispatchOutcome::RetryAfter(Duration::from_secs(1)),
        DispatchOutcome::Conflict,
        DispatchOutcome::GrantStale,
    ] {
        env.record(a1, outcome).await;
        assert_eq!(event(&env.session.client, a1).await, before);
    }
    assert_eq!(binding(&env.session.client, env.a).await.0, "revoked");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn grant_stale_cancels_event_and_suspends_active_binding() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    env.record(a1, DispatchOutcome::GrantStale).await;
    let stored = event(&env.session.client, a1).await;
    assert_eq!(stored["dispatch_status"], "cancelled");
    assert_eq!(stored["dispatch_attempts"], 1);
    assert_eq!(
        binding(&env.session.client, env.a).await,
        ("suspended".into(), Some("grant_stale".into()), true)
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn grant_stale_on_non_active_binding_only_cancels_event() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp()-interval '1 hour' WHERE binding_id=$1", &[&env.a]).await.unwrap();
    let before: String = env
        .session
        .client
        .query_one(
            "SELECT row_to_json(b)::text FROM openmybot.channel_bindings b WHERE binding_id=$1",
            &[&env.a],
        )
        .await
        .unwrap()
        .get(0);
    env.record(a1, DispatchOutcome::GrantStale).await;
    assert_eq!(
        event(&env.session.client, a1).await["dispatch_status"],
        "cancelled"
    );
    let after: String = env
        .session
        .client
        .query_one(
            "SELECT row_to_json(b)::text FROM openmybot.channel_bindings b WHERE binding_id=$1",
            &[&env.a],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn grant_stale_leaves_other_pending_events_pending() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    let a2 = env.message(true, "a2").await;
    let a3 = env.message(true, "a3").await;
    env.record(a1, DispatchOutcome::GrantStale).await;
    for id in [a2, a3] {
        let stored = event(&env.session.client, id).await;
        assert_eq!(stored["dispatch_status"], "pending");
        assert_eq!(stored["dispatch_attempts"], 0);
    }
    assert_eq!(env.claim().await, None);
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='active',status_reason=NULL,revision=revision+1 WHERE binding_id=$1", &[&env.a]).await.unwrap();
    let Claim::Item(item) = claim_dispatch(&env.session.client).await.unwrap() else {
        panic!("item after reconfirmation");
    };
    assert_eq!((item.record_id, item.revision), (a2, 2));
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn expiry_marks_older_than_ttl_expired_and_inserts_expiry_notice_once() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    let a2 = env.message(true, "a2").await;
    shift_event(&env.session.client, a1, "accepted_at", -(25.0 * 3600.0)).await;
    let expired = expire_pending(&mut env.session.client, TTL, "NOTICE", deadline())
        .await
        .unwrap();
    assert_eq!(expired.count, 1);
    assert_eq!(
        event(&env.session.client, a1).await["dispatch_status"],
        "expired"
    );
    assert_eq!(
        event(&env.session.client, a2).await["dispatch_status"],
        "pending"
    );
    let again = expire_pending(&mut env.session.client, TTL, "NOTICE", deadline())
        .await
        .unwrap();
    assert_eq!(again.count, 0);
    let rows = env.session.client.query("SELECT binding_id,channel_kind,chat_key,kind,idempotency_key,body,status FROM openmybot.deliveries", &[]).await.unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.get::<_, Uuid>(0), env.a);
    assert_eq!(row.get::<_, String>(1), "telegram");
    assert_eq!(row.get::<_, String>(2), "telegram:42");
    assert_eq!(row.get::<_, String>(3), "expiry_notice");
    assert_eq!(row.get::<_, String>(4), format!("expiry_notice:{a1}"));
    assert_eq!(row.get::<_, String>(5), "NOTICE");
    assert_eq!(row.get::<_, String>(6), "pending");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn expiry_notice_for_suspended_binding_is_still_inserted() {
    let mut env = Env::new().await;
    let a1 = env.message(true, "a1").await;
    let b1 = env.message(false, "b1").await;
    env.session.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='grant_stale',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&env.a]).await.unwrap();
    shift_event(&env.session.client, a1, "accepted_at", -(25.0 * 3600.0)).await;
    let expired = expire_pending(&mut env.session.client, TTL, "NOTICE", deadline())
        .await
        .unwrap();
    assert_eq!(expired.count, 1);
    let row = env.session.client.query_one("SELECT idempotency_key,binding_id,chat_key FROM openmybot.deliveries WHERE kind='expiry_notice'", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), format!("expiry_notice:{a1}"));
    assert_eq!(row.get::<_, Uuid>(1), env.a);
    assert_eq!(row.get::<_, String>(2), "telegram:42");
    assert_eq!(
        event(&env.session.client, a1).await["dispatch_status"],
        "expired"
    );
    assert_eq!(
        event(&env.session.client, b1).await["dispatch_status"],
        "pending"
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn expire_pending_reports_next_due_time() {
    let mut env = Env::new().await;
    let empty = expire_pending(&mut env.session.client, TTL, "NOTICE", deadline())
        .await
        .unwrap();
    assert_eq!((empty.count, empty.next_due), (0, None));
    let a1 = env.message(true, "a1").await;
    let b1 = env.message(false, "b1").await;
    shift_event(&env.session.client, a1, "accepted_at", -(20.0 * 3600.0)).await;
    shift_event(&env.session.client, b1, "accepted_at", -(23.0 * 3600.0)).await;
    let expired = expire_pending(&mut env.session.client, TTL, "NOTICE", deadline())
        .await
        .unwrap();
    assert_eq!(expired.count, 0);
    let accepted: OffsetDateTime = env
        .session
        .client
        .query_one(
            "SELECT accepted_at FROM openmybot.channel_events WHERE record_id=$1",
            &[&b1],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(expired.next_due, Some(accepted + time::Duration::hours(24)));
    env.stop().await;
}
