//! Store functions of the owner's control operations against an own PostgreSQL 17.11 cluster.
use omb_store::{
    AcceptOutcome, AcceptedEvent, Channel, Claim, Command, Content, Disposition, IdentityKey,
    NewReceiver, NormalizedEvent, OpenRun, PairAttempt, PairOutcome, PairStart, ReplyTexts,
    ResetDone, SessionStart, StateLabels, StoreError, Suspension, accept_event, activate_host,
    activate_receiver, claim_dispatch, list_bindings, migrate, open_run, pair_attempt, pair_start,
    receiver_row, reset_thread, revoke_binding, run_facts, suspend_receiver,
    testkit::{
        Fixture, Session, deadline, insert_event_for_run, insert_host_binding,
        insert_permission_row, insert_receiver, insert_receiver_with, insert_sender,
        permission_row_json, read_row, set_terminal, shift_event,
    },
    upsert_session,
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
const REQUESTED: &str = "已请求取消当前任务。";
const NONE: &str = "当前没有进行中的任务。";
const REPLIES: ReplyTexts<'static> = ReplyTexts {
    help: "-",
    already_bound: "-",
    unknown_command: "-",
    cancel_requested: REQUESTED,
    cancel_none: NONE,
    status: "-",
    states: STATES,
    outside_window: "-",
    too_long: "-",
    unsupported: "-",
    queue_full: "-",
};
const SENDER: &str = "telegram:42";

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
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
/// A dispatched event of the binding on `thread`, stamped with the database clock.
async fn dispatched(client: &Client, binding: Uuid, run: &str, thread: &str) -> Uuid {
    let id = insert_event_for_run(client, binding, run, thread, "dispatched").await;
    shift_event(client, id, "dispatched_at", 0.0).await;
    id
}
async fn snapshot(client: &Client) -> Vec<Option<String>> {
    let row = client.query_one("SELECT (SELECT json_agg(b ORDER BY binding_id)::text FROM openmybot.channel_bindings b),(SELECT json_agg(e ORDER BY record_id)::text FROM openmybot.channel_events e),(SELECT json_agg(d ORDER BY delivery_id)::text FROM openmybot.deliveries d),(SELECT json_agg(h ORDER BY record_id)::text FROM openmybot.host_driver_sessions h)", &[]).await.unwrap();
    (0..4).map(|i| row.get(i)).collect()
}
async fn binding(client: &Client, id: Uuid) -> serde_json::Value {
    read_row(client, "channel_bindings", "binding_id", id).await
}
async fn event(client: &Client, id: Uuid) -> serde_json::Value {
    read_row(client, "channel_events", "record_id", id).await
}
async fn suspend(client: &Client, id: Uuid) {
    assert_eq!(client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&id]).await.unwrap(), 1);
}
async fn pending_sender(client: &mut Client, channel: Channel) -> Uuid {
    pair_start(
        client,
        PairStart {
            channel,
            workspace_dir: "/workspaces/project",
            thread_id: "thread-P",
            granted_generation: 1,
            run_deadline: None,
        },
        deadline(),
    )
    .await
    .unwrap()
    .binding_id
}
fn open(thread: &str, run: &str) -> OpenRun {
    OpenRun {
        thread_id: thread.into(),
        run_id: run.into(),
    }
}
async fn receive(client: &mut Client, id: Uuid, source_key: &str) -> Vec<OpenRun> {
    activate_receiver(
        client,
        NewReceiver {
            binding_id: id,
            channel: Channel::Telegram,
            source_key,
            credential_envelope: "sealed-envelope",
        },
        deadline(),
    )
    .await
    .unwrap()
}
fn command(key: &str, body: &str, command: Command) -> NormalizedEvent {
    NormalizedEvent {
        channel: Channel::Telegram,
        source_key: "1001".into(),
        event_key: key.into(),
        event_type: "telegram.message".into(),
        occurred_at: Some(OffsetDateTime::now_utc()),
        private: true,
        sender: IdentityKey::parse(SENDER),
        chat: IdentityKey::parse(SENDER),
        fingerprint: Some([key.len() as u8; 32]),
        content: Content::Text {
            text: body.into(),
            command: Some(command),
            pair_code: None,
        },
    }
}
async fn replies(client: &Client) -> Vec<String> {
    client
        .query(
            "SELECT body FROM openmybot.deliveries WHERE kind='control_reply' ORDER BY created_at,delivery_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}
async fn claimed(client: &Client) -> Option<(Uuid, String)> {
    match claim_dispatch(client).await.unwrap() {
        Claim::Item(item) => Some((item.record_id, item.thread_id)),
        Claim::Idle { .. } => None,
    }
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn list_bindings_returns_live_rows_only_without_secret_columns() {
    let mut env = Env::new().await;
    let receiver = Uuid::now_v7();
    insert_receiver_with(
        env.client(),
        receiver,
        "telegram",
        "1001",
        "envelope-sentinel",
    )
    .await;
    let expired = pending_sender(&mut env.session.client, Channel::Telegram).await;
    let pending = pending_sender(&mut env.session.client, Channel::Telegram).await;
    let revoked = insert_host_binding(env.client(), "/workspaces/old").await;
    revoke_binding(&mut env.session.client, revoked, deadline())
        .await
        .unwrap();
    let host = insert_host_binding(env.client(), "/workspaces/host").await;
    let suspended = Uuid::now_v7();
    insert_receiver_with(
        env.client(),
        suspended,
        "feishu",
        "cli_a",
        "envelope-sentinel",
    )
    .await;
    suspend_receiver(
        &mut env.session.client,
        suspended,
        Suspension::CredentialRejected,
        deadline(),
    )
    .await
    .unwrap();
    let listed = list_bindings(env.client(), deadline()).await.unwrap();
    let ids: Vec<Uuid> = listed.iter().map(|view| view.binding_id).collect();
    assert_eq!(ids, [host, suspended, receiver, pending]);
    assert_eq!(listed[1].status, "suspended");
    assert!(!ids.contains(&expired) && !ids.contains(&revoked));
    let hash: Vec<u8> = env
        .client()
        .query_one(
            "SELECT pairing_code_hash FROM openmybot.channel_bindings WHERE binding_id=$1",
            &[&pending],
        )
        .await
        .unwrap()
        .get(0);
    for view in &listed {
        let texts = [
            Some(view.binding_kind.as_str()),
            Some(view.channel_kind.as_str()),
            Some(view.source_key.as_str()),
            view.sender_key.as_deref(),
            Some(view.status.as_str()),
            view.status_reason.as_deref(),
            view.workspace_dir.as_deref(),
            view.thread_id.as_deref(),
        ];
        for text in texts.into_iter().flatten() {
            assert!(!text.contains("envelope-sentinel"));
            assert!(!text.as_bytes().windows(hash.len()).any(|w| w == hash));
        }
    }
    let view = &listed[3];
    assert_eq!(
        (
            view.binding_kind.as_str(),
            view.status.as_str(),
            view.revision
        ),
        ("sender", "pending", 0)
    );
    assert_eq!(view.thread_id.as_deref(), Some("thread-P"));
    assert!(view.activated_at.is_none() && view.reconfirmed_at.is_none());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn list_bindings_orders_by_kind_channel_created() {
    let env = Env::new().await;
    insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    insert_receiver(env.client(), "telegram", "1001").await;
    insert_sender(env.client(), "feishu", "cli_app", "feishu:ou_1", "thread-F").await;
    insert_host_binding(env.client(), "/workspaces/host").await;
    insert_receiver(env.client(), "feishu", "cli_app").await;
    let order: Vec<(String, String)> = list_bindings(env.client(), deadline())
        .await
        .unwrap()
        .into_iter()
        .map(|view| (view.binding_kind, view.channel_kind))
        .collect();
    let expected = [
        ("host", "host"),
        ("receiver", "feishu"),
        ("receiver", "telegram"),
        ("sender", "feishu"),
        ("sender", "telegram"),
    ];
    assert_eq!(
        order,
        expected.map(|(kind, channel)| (kind.to_owned(), channel.to_owned()))
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_sender_returns_open_runs_and_cancels_pending_events() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let finished = dispatched(env.client(), sender, "r0", "thread-T").await;
    set_terminal(env.client(), finished, "succeeded").await;
    let running = dispatched(env.client(), sender, "r1", "thread-T").await;
    let queued = insert_event_for_run(env.client(), sender, "r2", "thread-T", "pending").await;
    let before = event(env.client(), finished).await;
    let runs = revoke_binding(&mut env.session.client, sender, deadline())
        .await
        .unwrap();
    assert_eq!(runs, [open("thread-T", "r1")]);
    assert_eq!(
        event(env.client(), queued).await["dispatch_status"],
        "cancelled"
    );
    assert_eq!(
        event(env.client(), running).await["dispatch_status"],
        "dispatched"
    );
    assert_eq!(event(env.client(), finished).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_denies_undecided_permissions_of_the_binding_as_run_stopped_without_token() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    dispatched(env.client(), sender, "r1", "thread-T").await;
    insert_permission_row(env.client(), sender, "r1", "hp-undecided", 600.0).await;
    revoke_binding(&mut env.session.client, sender, deadline())
        .await
        .unwrap();
    let row = permission_row_json(env.client(), "hp-undecided").await;
    assert_eq!(row["decision"], "deny");
    assert_eq!(row["decided_via"], "run_stopped");
    assert!(row["decided_at"].is_string());
    assert!(row["decided_by_token"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_keeps_decided_and_foreign_permissions_unchanged() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let host = insert_host_binding(env.client(), "/workspaces/host").await;
    insert_permission_row(env.client(), sender, "r1", "hp-decided", 600.0).await;
    assert_eq!(
        omb_store::testkit::decide(env.client(), "hp-decided", omb_store::Decision::Allow).await,
        omb_store::Decided::Decided
    );
    insert_permission_row(env.client(), host, "r2", "hp-foreign", 600.0).await;
    let decided = permission_row_json(env.client(), "hp-decided").await;
    let foreign = permission_row_json(env.client(), "hp-foreign").await;
    revoke_binding(&mut env.session.client, sender, deadline())
        .await
        .unwrap();
    assert_eq!(
        permission_row_json(env.client(), "hp-decided").await,
        decided
    );
    assert_eq!(
        permission_row_json(env.client(), "hp-foreign").await,
        foreign
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_receiver_cascades_active_sender_to_revoked_owner_revoked() {
    let mut env = Env::new().await;
    let receiver = insert_receiver(env.client(), "telegram", "1001").await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    revoke_binding(&mut env.session.client, receiver, deadline())
        .await
        .unwrap();
    let row = binding(env.client(), receiver).await;
    assert_eq!(
        (
            &row["status"],
            &row["status_reason"],
            &row["credential_envelope"]
        ),
        (
            &serde_json::json!("revoked"),
            &serde_json::json!("owner_revoked"),
            &serde_json::json!("")
        )
    );
    let row = binding(env.client(), sender).await;
    assert_eq!(row["status"], "revoked");
    assert_eq!(row["status_reason"], "owner_revoked");
    assert!(row["ended_at"].is_string());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_receiver_cascades_pending_sender_to_expired_owner_revoked() {
    let mut env = Env::new().await;
    let receiver = insert_receiver(env.client(), "telegram", "1001").await;
    let pending = pending_sender(&mut env.session.client, Channel::Telegram).await;
    revoke_binding(&mut env.session.client, receiver, deadline())
        .await
        .unwrap();
    let row = binding(env.client(), pending).await;
    assert_eq!(row["status"], "expired");
    assert_eq!(row["status_reason"], "owner_revoked");
    assert!(row["pairing_code_hash"].is_null());
    assert!(row["ended_at"].is_string());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_receiver_cascade_settles_events_permissions_and_open_runs_of_the_sender() {
    let mut env = Env::new().await;
    let receiver = insert_receiver(env.client(), "telegram", "1001").await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    dispatched(env.client(), sender, "r1", "thread-T").await;
    let queued = insert_event_for_run(env.client(), sender, "r2", "thread-T", "pending").await;
    insert_permission_row(env.client(), sender, "r1", "hp-1", 600.0).await;
    let runs = revoke_binding(&mut env.session.client, receiver, deadline())
        .await
        .unwrap();
    assert_eq!(runs, [open("thread-T", "r1")]);
    assert_eq!(
        event(env.client(), queued).await["dispatch_status"],
        "cancelled"
    );
    let permission = permission_row_json(env.client(), "hp-1").await;
    assert_eq!(
        (&permission["decision"], &permission["decided_via"]),
        (
            &serde_json::json!("deny"),
            &serde_json::json!("run_stopped")
        )
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_of_ended_or_unknown_binding_is_refused_without_changes() {
    let mut env = Env::new().await;
    insert_receiver(env.client(), "telegram", "1001").await;
    let revoked = insert_host_binding(env.client(), "/workspaces/host").await;
    revoke_binding(&mut env.session.client, revoked, deadline())
        .await
        .unwrap();
    let expired = pending_sender(&mut env.session.client, Channel::Telegram).await;
    pending_sender(&mut env.session.client, Channel::Telegram).await;
    let before = snapshot(env.client()).await;
    for id in [revoked, expired] {
        assert_eq!(
            revoke_binding(&mut env.session.client, id, deadline())
                .await
                .unwrap_err(),
            StoreError::BindingStateInvalid
        );
    }
    assert_eq!(
        revoke_binding(&mut env.session.client, Uuid::now_v7(), deadline())
            .await
            .unwrap_err(),
        StoreError::BindingNotFound
    );
    assert_eq!(snapshot(env.client()).await, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_past_deadline_fails_and_leaves_the_connection_without_open_transaction() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let pid: i32 = env
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let holder = env.fixture.connect().await;
    holder.client.batch_execute("BEGIN").await.unwrap();
    holder
        .client
        .execute(
            "SELECT 1 FROM openmybot.channel_bindings WHERE binding_id=$1 FOR UPDATE",
            &[&sender],
        )
        .await
        .unwrap();
    let short = tokio::time::Instant::now() + Duration::from_millis(500);
    assert_eq!(
        revoke_binding(&mut env.session.client, sender, short)
            .await
            .unwrap_err(),
        StoreError::BindingFailed
    );
    holder.client.batch_execute("ROLLBACK").await.unwrap();
    let observer = env.fixture.connect().await;
    let limit = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let row = observer
            .client
            .query_one(
                "SELECT state,xact_start IS NULL FROM pg_stat_activity WHERE pid=$1",
                &[&pid],
            )
            .await
            .unwrap();
        if row.get::<_, String>(0) == "idle" && row.get::<_, bool>(1) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < limit,
            "connection stays in a transaction"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(binding(env.client(), sender).await["status"], "active");
    revoke_binding(&mut env.session.client, sender, deadline())
        .await
        .unwrap();
    assert_eq!(binding(env.client(), sender).await["status"], "revoked");
    holder.close().await;
    observer.close().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_receiver_inserts_active_row_revision_1_with_envelope_and_writes_no_gap() {
    let mut env = Env::new().await;
    let id = Uuid::now_v7();
    assert!(
        receive(&mut env.session.client, id, "1001")
            .await
            .is_empty()
    );
    let row = binding(env.client(), id).await;
    assert_eq!(row["binding_kind"], "receiver");
    assert_eq!(row["channel_kind"], "telegram");
    assert_eq!(row["source_key"], "1001");
    assert_eq!(row["credential_envelope"], "sealed-envelope");
    assert_eq!(row["status"], "active");
    assert_eq!(row["revision"], 1);
    assert!(row["activated_at"].is_string() && row["created_at"].is_string());
    let gaps: i64 = env
        .client()
        .query_one(
            "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='gap'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(gaps, 0);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_receiver_replaces_active_receiver_with_receiver_replaced_and_empty_envelope() {
    let mut env = Env::new().await;
    let old = insert_receiver(env.client(), "telegram", "1001").await;
    let new = Uuid::now_v7();
    receive(&mut env.session.client, new, "2002").await;
    let row = binding(env.client(), old).await;
    assert_eq!(row["status"], "revoked");
    assert_eq!(row["status_reason"], "receiver_replaced");
    assert_eq!(row["credential_envelope"], "");
    assert!(row["ended_at"].is_string());
    let active: Vec<Uuid> = env
        .client()
        .query("SELECT binding_id FROM openmybot.channel_bindings WHERE binding_kind='receiver' AND status='active'", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(active, [new]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_receiver_replaces_suspended_receiver() {
    let mut env = Env::new().await;
    let old = insert_receiver(env.client(), "telegram", "1001").await;
    suspend(env.client(), old).await;
    let new = Uuid::now_v7();
    receive(&mut env.session.client, new, "1001").await;
    let row = binding(env.client(), old).await;
    assert_eq!(
        (&row["status"], &row["status_reason"]),
        (
            &serde_json::json!("revoked"),
            &serde_json::json!("receiver_replaced")
        )
    );
    assert_eq!(binding(env.client(), new).await["status"], "active");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_receiver_cascades_pending_to_expired_and_active_suspended_to_revoked() {
    let mut env = Env::new().await;
    insert_receiver(env.client(), "telegram", "1001").await;
    for state in ["pending", "active", "suspended"] {
        let sender = match state {
            "pending" => pending_sender(&mut env.session.client, Channel::Telegram).await,
            _ => insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await,
        };
        if state == "suspended" {
            suspend(env.client(), sender).await;
        }
        receive(&mut env.session.client, Uuid::now_v7(), "1001").await;
        let row = binding(env.client(), sender).await;
        let expected = if state == "pending" {
            "expired"
        } else {
            "revoked"
        };
        assert_eq!(row["status"], expected, "{state}");
        assert_eq!(row["status_reason"], "receiver_replaced", "{state}");
        assert!(row["ended_at"].is_string() && row["pairing_code_hash"].is_null());
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_receiver_with_same_source_key_still_cascades() {
    let mut env = Env::new().await;
    let old = insert_receiver(env.client(), "telegram", "1001").await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    receive(&mut env.session.client, Uuid::now_v7(), "1001").await;
    assert_eq!(binding(env.client(), old).await["status"], "revoked");
    let row = binding(env.client(), sender).await;
    assert_eq!(
        (&row["status"], &row["status_reason"]),
        (
            &serde_json::json!("revoked"),
            &serde_json::json!("receiver_replaced")
        )
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_receiver_settles_events_permissions_and_returns_open_runs_of_cascaded_senders() {
    let mut env = Env::new().await;
    insert_receiver(env.client(), "telegram", "1001").await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    dispatched(env.client(), sender, "r1", "thread-T").await;
    let queued = insert_event_for_run(env.client(), sender, "r2", "thread-T", "pending").await;
    insert_permission_row(env.client(), sender, "r1", "hp-1", 600.0).await;
    let runs = receive(&mut env.session.client, Uuid::now_v7(), "1001").await;
    assert_eq!(runs, [open("thread-T", "r1")]);
    assert_eq!(
        event(env.client(), queued).await["dispatch_status"],
        "cancelled"
    );
    let permission = permission_row_json(env.client(), "hp-1").await;
    assert_eq!(permission["decision"], "deny");
    assert_eq!(permission["decided_via"], "run_stopped");
    assert!(permission["decided_by_token"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_receiver_leaves_other_channel_untouched() {
    let mut env = Env::new().await;
    let receiver = insert_receiver(env.client(), "feishu", "cli_app").await;
    let sender = insert_sender(env.client(), "feishu", "cli_app", "feishu:ou_1", "thread-F").await;
    let receiver_before = binding(env.client(), receiver).await;
    let sender_before = binding(env.client(), sender).await;
    receive(&mut env.session.client, Uuid::now_v7(), "1001").await;
    assert_eq!(binding(env.client(), receiver).await, receiver_before);
    assert_eq!(binding(env.client(), sender).await, sender_before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_receiver_failure_rolls_back_old_receiver_and_senders() {
    let mut env = Env::new().await;
    let old = insert_receiver(env.client(), "telegram", "1001").await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let before = snapshot(env.client()).await;
    assert_eq!(
        activate_receiver(
            &mut env.session.client,
            NewReceiver {
                binding_id: sender,
                channel: Channel::Telegram,
                source_key: "1001",
                credential_envelope: "sealed-envelope",
            },
            deadline(),
        )
        .await
        .unwrap_err(),
        StoreError::BindingFailed
    );
    assert_eq!(snapshot(env.client()).await, before);
    assert_eq!(binding(env.client(), old).await["status"], "active");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn receiver_row_returns_active_and_suspended_receivers_only() {
    let mut env = Env::new().await;
    let revoked = Uuid::now_v7();
    insert_receiver_with(env.client(), revoked, "feishu", "cli_app", "old-envelope").await;
    revoke_binding(&mut env.session.client, revoked, deadline())
        .await
        .unwrap();
    let active = Uuid::now_v7();
    insert_receiver_with(env.client(), active, "telegram", "1001", "live-envelope").await;
    let row = receiver_row(env.client(), active, deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            row.binding_id,
            row.source_key.as_str(),
            row.credential_envelope.as_str()
        ),
        (active, "1001", "live-envelope")
    );
    suspend(env.client(), active).await;
    assert!(
        receiver_row(env.client(), active, deadline())
            .await
            .unwrap()
            .is_some()
    );
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let host = insert_host_binding(env.client(), "/workspaces/host").await;
    for id in [revoked, sender, host, Uuid::now_v7()] {
        assert!(
            receiver_row(env.client(), id, deadline())
                .await
                .unwrap()
                .is_none()
        );
    }
    env.stop().await;
}

async fn reset(env: &mut Env, id: Uuid, ack: &str, thread: &str) -> Result<ResetDone, StoreError> {
    reset_thread(&mut env.session.client, id, ack, thread, deadline()).await
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reset_thread_requires_latest_dispatched_event_of_current_thread_reconciliation_required() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let older = dispatched(env.client(), sender, "r0", "thread-T").await;
    set_terminal(env.client(), older, "reconciliation_required").await;
    let latest = dispatched(env.client(), sender, "r1", "thread-T").await;
    assert_eq!(
        reset(&mut env, sender, "r1", "thread-N").await.unwrap_err(),
        StoreError::BindingStateInvalid
    );
    set_terminal(env.client(), latest, "failed").await;
    assert_eq!(
        reset(&mut env, sender, "r1", "thread-N").await.unwrap_err(),
        StoreError::BindingStateInvalid
    );
    // The same run on another thread of the binding does not count.
    let other = dispatched(env.client(), sender, "r2", "thread-X").await;
    set_terminal(env.client(), other, "reconciliation_required").await;
    assert_eq!(
        reset(&mut env, sender, "r2", "thread-N").await.unwrap_err(),
        StoreError::BindingStateInvalid
    );
    let current = dispatched(env.client(), sender, "r3", "thread-T").await;
    set_terminal(env.client(), current, "reconciliation_required").await;
    assert_eq!(
        reset(&mut env, sender, "r3", "thread-N").await.unwrap(),
        ResetDone {
            thread_generation: 1,
            revision: 2
        }
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reset_thread_requires_ack_equal_to_that_run_id() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let old = dispatched(env.client(), sender, "r0", "thread-T").await;
    set_terminal(env.client(), old, "reconciliation_required").await;
    let latest = dispatched(env.client(), sender, "r1", "thread-T").await;
    set_terminal(env.client(), latest, "reconciliation_required").await;
    let before = binding(env.client(), sender).await;
    for ack in ["", "r-other", "r0"] {
        assert_eq!(
            reset(&mut env, sender, ack, "thread-N").await.unwrap_err(),
            StoreError::BindingStateInvalid,
            "{ack}"
        );
    }
    assert_eq!(binding(env.client(), sender).await, before);
    reset(&mut env, sender, "r1", "thread-N").await.unwrap();
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reset_thread_bumps_generation_and_revision_keeps_granted_generation_and_moves_pending_events()
 {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let unknown = dispatched(env.client(), sender, "r1", "thread-T").await;
    set_terminal(env.client(), unknown, "reconciliation_required").await;
    let queued = insert_event_for_run(env.client(), sender, "r2", "thread-T", "pending").await;
    let before = binding(env.client(), sender).await;
    let done = reset(&mut env, sender, "r1", "thread-N").await.unwrap();
    let after = binding(env.client(), sender).await;
    assert_eq!(
        done,
        ResetDone {
            thread_generation: 1,
            revision: 2
        }
    );
    assert_eq!(after["thread_id"], "thread-N");
    assert_eq!(after["thread_generation"], 1);
    assert_eq!(after["revision"], 2);
    assert_eq!(after["granted_generation"], before["granted_generation"]);
    let moved = event(env.client(), queued).await;
    assert_eq!(
        (&moved["thread_id"], &moved["dispatch_status"]),
        (
            &serde_json::json!("thread-N"),
            &serde_json::json!("pending")
        )
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reset_thread_leaves_old_event_row_and_old_thread_events_unchanged() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let done = dispatched(env.client(), sender, "r0", "thread-T").await;
    set_terminal(env.client(), done, "succeeded").await;
    let conflict = insert_event_for_run(env.client(), sender, "r1", "thread-T", "conflict").await;
    let unknown = dispatched(env.client(), sender, "r2", "thread-T").await;
    set_terminal(env.client(), unknown, "reconciliation_required").await;
    let mut before = Vec::new();
    for id in [done, conflict, unknown] {
        before.push(event(env.client(), id).await);
    }
    reset(&mut env, sender, "r2", "thread-N").await.unwrap();
    for (id, expected) in [done, conflict, unknown].into_iter().zip(before) {
        assert_eq!(event(env.client(), id).await, expected);
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reset_thread_refuses_host_receiver_pending_and_ended_bindings() {
    let mut env = Env::new().await;
    let receiver = insert_receiver(env.client(), "telegram", "1001").await;
    let host = insert_host_binding(env.client(), "/workspaces/host").await;
    let host_run = dispatched(env.client(), host, "rh", "thread-H").await;
    set_terminal(env.client(), host_run, "reconciliation_required").await;
    let pending = pending_sender(&mut env.session.client, Channel::Telegram).await;
    let ended = insert_sender(env.client(), "feishu", "cli_app", "feishu:ou_1", "thread-F").await;
    let ended_run = dispatched(env.client(), ended, "rf", "thread-F").await;
    set_terminal(env.client(), ended_run, "reconciliation_required").await;
    revoke_binding(&mut env.session.client, ended, deadline())
        .await
        .unwrap();
    for (id, ack) in [
        (host, "rh"),
        (receiver, "rh"),
        (pending, "rh"),
        (ended, "rf"),
    ] {
        let before = snapshot(env.client()).await;
        assert_eq!(
            reset(&mut env, id, ack, "thread-N").await.unwrap_err(),
            StoreError::BindingStateInvalid
        );
        assert_eq!(snapshot(env.client()).await, before);
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reset_thread_unknown_binding_is_binding_not_found() {
    let mut env = Env::new().await;
    assert_eq!(
        reset(&mut env, Uuid::now_v7(), "r1", "thread-N")
            .await
            .unwrap_err(),
        StoreError::BindingNotFound
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn concurrent_reset_thread_calls_have_exactly_one_winner() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-0").await;
    let mut a = env.fixture.connect().await;
    let mut b = env.fixture.connect().await;
    for round in 0..10 {
        let thread = format!("thread-{round}");
        let run = format!("r{round}");
        let unknown = dispatched(env.client(), sender, &run, &thread).await;
        set_terminal(env.client(), unknown, "reconciliation_required").await;
        let next_a = format!("thread-{}", round + 1);
        let next_b = next_a.clone();
        let (first, second) = tokio::join!(
            reset_thread(&mut a.client, sender, &run, &next_a, deadline()),
            reset_thread(&mut b.client, sender, &run, &next_b, deadline()),
        );
        let mut outcomes = [first, second];
        outcomes.sort_by_key(Result::is_err);
        assert!(outcomes[0].is_ok(), "round {round}");
        assert_eq!(
            outcomes[1],
            Err(StoreError::BindingStateInvalid),
            "round {round}"
        );
        assert_eq!(
            binding(env.client(), sender).await["thread_generation"],
            round + 1
        );
    }
    a.close().await;
    b.close().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_dispatch_is_paused_until_reset_thread() {
    let mut env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let unknown = dispatched(env.client(), sender, "r1", "thread-T").await;
    set_terminal(env.client(), unknown, "reconciliation_required").await;
    let queued = insert_event_for_run(env.client(), sender, "r2", "thread-T", "pending").await;
    assert_eq!(claimed(env.client()).await, None);
    reset(&mut env, sender, "r1", "thread-N").await.unwrap();
    assert_eq!(
        claimed(env.client()).await,
        Some((queued, "thread-N".to_owned()))
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_dispatch_pause_ignores_reconciliation_on_other_threads() {
    let env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let old = dispatched(env.client(), sender, "r1", "thread-OLD").await;
    set_terminal(env.client(), old, "reconciliation_required").await;
    let queued = insert_event_for_run(env.client(), sender, "r2", "thread-T", "pending").await;
    assert_eq!(
        claimed(env.client()).await,
        Some((queued, "thread-T".to_owned()))
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn claim_dispatch_pause_applies_to_sender_bindings_only() {
    let env = Env::new().await;
    let host = insert_host_binding(env.client(), "/workspaces/host").await;
    let unknown = dispatched(env.client(), host, "r1", "thread-H").await;
    set_terminal(env.client(), unknown, "reconciliation_required").await;
    let queued = insert_event_for_run(env.client(), host, "r2", "thread-H2", "pending").await;
    assert_eq!(
        claimed(env.client()).await,
        Some((queued, "thread-H2".to_owned()))
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn run_facts_returns_event_session_and_permission_rows() {
    let env = Env::new().await;
    let host = insert_host_binding(env.client(), "/workspaces/host").await;
    let record = dispatched(env.client(), host, "r1", "thread-H").await;
    set_terminal(env.client(), record, "failed").await;
    upsert_session(
        env.client(),
        SessionStart {
            run_id: "r1",
            binding_id: host,
            workspace_dir: "/workspaces/host",
        },
        deadline(),
    )
    .await
    .unwrap();
    insert_permission_row(env.client(), host, "r1", "hp-first", 600.0).await;
    insert_permission_row(env.client(), host, "r1", "hp-second", 600.0).await;
    insert_permission_row(env.client(), host, "r-other", "hp-other", 600.0).await;
    let facts = run_facts(env.client(), "r1", deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(facts.binding_id, host);
    assert_eq!(facts.kind, omb_store::GrantKind::Host);
    assert_eq!(facts.thread_id, "thread-H");
    assert_eq!(facts.dispatch_status, "dispatched");
    assert_eq!(facts.terminal_kind.as_deref(), Some("failed"));
    let session = facts.session.unwrap();
    assert!(session.end_reason.is_none() && session.ended_at.is_none());
    let ids: Vec<&str> = facts
        .permissions
        .iter()
        .map(|p| p.permission_id.as_str())
        .collect();
    assert_eq!(ids, ["hp-first", "hp-second"]);
    let first = &facts.permissions[0];
    assert_eq!(first.tool_name, "Write");
    assert!(first.input_summary.is_some() && first.decision.is_none());
    assert!(first.requested_at <= facts.permissions[1].requested_at);
    assert!(first.expires_at > first.requested_at);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn run_facts_for_pending_event_has_no_session_and_no_permissions() {
    let env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    insert_event_for_run(env.client(), sender, "r1", "thread-T", "pending").await;
    let facts = run_facts(env.client(), "r1", deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(facts.kind, omb_store::GrantKind::Sender);
    assert_eq!(facts.dispatch_status, "pending");
    assert!(facts.terminal_kind.is_none() && facts.session.is_none());
    assert!(facts.permissions.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn run_facts_for_unknown_run_is_none() {
    let env = Env::new().await;
    assert!(
        run_facts(env.client(), "r-missing", deadline())
            .await
            .unwrap()
            .is_none()
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn open_run_returns_the_dispatched_event_without_terminal() {
    let env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let finished = dispatched(env.client(), sender, "r0", "thread-T").await;
    set_terminal(env.client(), finished, "succeeded").await;
    dispatched(env.client(), sender, "r1", "thread-T").await;
    assert_eq!(
        open_run(env.client(), sender).await.unwrap(),
        Some(open("thread-T", "r1"))
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn open_run_is_none_for_pending_terminal_and_foreign_binding_events() {
    let env = Env::new().await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    let host = insert_host_binding(env.client(), "/workspaces/host").await;
    insert_event_for_run(env.client(), sender, "r1", "thread-T", "pending").await;
    let finished = dispatched(env.client(), sender, "r2", "thread-T").await;
    set_terminal(env.client(), finished, "cancelled").await;
    dispatched(env.client(), host, "r3", "thread-H").await;
    assert_eq!(open_run(env.client(), sender).await.unwrap(), None);
    env.stop().await;
}

async fn cancel_env() -> (Env, Uuid, Uuid) {
    let env = Env::new().await;
    let receiver = insert_receiver(env.client(), "telegram", "1001").await;
    let sender = insert_sender(env.client(), "telegram", "1001", SENDER, "thread-T").await;
    (env, receiver, sender)
}
async fn accept_cancel(env: &mut Env, receiver: Uuid, key: &str) -> AcceptOutcome {
    accept_event(
        &mut env.session.client,
        receiver,
        &command(key, "/cancel", Command::Cancel),
        &REPLIES,
        deadline(),
    )
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accept_cancel_with_open_run_replies_requested_and_returns_cancel() {
    let (mut env, receiver, sender) = cancel_env().await;
    dispatched(env.client(), sender, "r1", "thread-T").await;
    assert_eq!(
        accept_cancel(&mut env, receiver, "10").await,
        AcceptOutcome::Cancel(sender)
    );
    assert_eq!(replies(env.client()).await, [REQUESTED]);
    let stored: String = env
        .client()
        .query_one(
            "SELECT command FROM openmybot.channel_events WHERE event_key='10'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, "cancel");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accept_cancel_without_open_run_replies_none_and_returns_cancel() {
    let (mut env, receiver, sender) = cancel_env().await;
    let finished = dispatched(env.client(), sender, "r1", "thread-T").await;
    set_terminal(env.client(), finished, "succeeded").await;
    assert_eq!(
        accept_cancel(&mut env, receiver, "10").await,
        AcceptOutcome::Cancel(sender)
    );
    assert_eq!(replies(env.client()).await, [NONE]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accept_cancel_leaves_pending_events_untouched() {
    let (mut env, receiver, sender) = cancel_env().await;
    dispatched(env.client(), sender, "r1", "thread-T").await;
    let queued = insert_event_for_run(env.client(), sender, "r2", "thread-T", "pending").await;
    let before = event(env.client(), queued).await;
    accept_cancel(&mut env, receiver, "10").await;
    assert_eq!(event(env.client(), queued).await, before);
    assert_eq!(before["dispatch_status"], "pending");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accept_redelivered_cancel_returns_duplicate_without_a_second_reply() {
    let (mut env, receiver, sender) = cancel_env().await;
    dispatched(env.client(), sender, "r1", "thread-T").await;
    assert_eq!(
        accept_cancel(&mut env, receiver, "10").await,
        AcceptOutcome::Cancel(sender)
    );
    assert_eq!(
        accept_cancel(&mut env, receiver, "10").await,
        AcceptOutcome::Duplicate
    );
    assert_eq!(replies(env.client()).await.len(), 1);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn accept_cancel_on_suspended_binding_is_dropped_inactive_not_cancel() {
    let (mut env, receiver, sender) = cancel_env().await;
    dispatched(env.client(), sender, "r1", "thread-T").await;
    suspend(env.client(), sender).await;
    assert_eq!(
        accept_cancel(&mut env, receiver, "10").await,
        AcceptOutcome::Recorded(Disposition::DroppedInactive)
    );
    assert!(replies(env.client()).await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_attempt_uses_the_passed_receiver_source_key_and_reads_no_receiver_row() {
    let mut env = Env::new().await;
    insert_receiver(env.client(), "telegram", "1001").await;
    let started = pair_start(
        &mut env.session.client,
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
    .unwrap();
    env.client()
        .execute(
            "DELETE FROM openmybot.channel_bindings WHERE binding_kind='receiver'",
            &[],
        )
        .await
        .unwrap();
    let key = IdentityKey::parse(SENDER).unwrap();
    let tx = env.session.client.transaction().await.unwrap();
    let outcome = pair_attempt(
        &tx,
        PairAttempt {
            channel: Channel::Telegram,
            receiver_source_key: "1001",
            sender_key: &key,
            chat_key: &key,
            code_text: &started.code.display(),
            event: AcceptedEvent {
                event_key: "1",
                source_key: "1001",
                fingerprint: [5; 32],
                occurred_at: None,
                event_type: None,
            },
        },
        deadline(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        outcome,
        PairOutcome::Succeeded {
            binding_id: started.binding_id
        }
    );
    assert_eq!(
        binding(env.client(), started.binding_id).await["status"],
        "active"
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn testkit_insert_permission_row_satisfies_the_row_check_and_permission_row_json_reads_it() {
    let mut env = Env::new().await;
    let host = activate_host(
        &mut env.session.client,
        omb_store::HostBinding {
            workspace_dir: "/workspaces/host",
            granted_generation: 1,
            run_deadline: None,
        },
        deadline(),
    )
    .await
    .unwrap();
    insert_permission_row(env.client(), host, "r1", "hp-live", 600.0).await;
    insert_permission_row(env.client(), host, "r1", "hp-gone", -1.0).await;
    let live = permission_row_json(env.client(), "hp-live").await;
    assert_eq!(live["record_kind"], "permission");
    assert_eq!(live["binding_id"], host.to_string());
    assert_eq!(live["run_id"], "r1");
    assert!(live["decision"].is_null() && live["decided_via"].is_null());
    assert!(live["started_at"].is_null() && live["host_kind"].is_null());
    let expired: bool = env
        .client()
        .query_one(
            "SELECT expires_at<statement_timestamp() FROM openmybot.host_driver_sessions WHERE permission_id='hp-gone'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(expired);
    env.stop().await;
}
