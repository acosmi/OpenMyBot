//! Startup reconciliation rows against an own PostgreSQL 17.11 cluster: deliveries left sending,
//! runs without a terminal, orphan sessions and undecided permissions.
use omb_store::{
    Decided, Decision, EndReason, OpenRun, OrphanSession, SessionEnd, StopRecord,
    answer_permission, deny_undecided_permissions, end_session, list_orphan_sessions,
    mark_sending_unknown, migrate,
    testkit::{
        Fixture, Session, deadline, decide, insert_delivery, insert_ended_session,
        insert_event_for_run, insert_host_binding, insert_orphan_session, insert_permission_row,
        insert_sender, permission_row_json, read_row, set_terminal, shift_event,
    },
    unfinished_runs,
};
use serde_json::Value;
use time::OffsetDateTime;
use tokio_postgres::Client;
use uuid::Uuid;

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
    async fn delivery(&self, key: &str, status: &str, next: Option<f64>) -> Uuid {
        insert_delivery(
            self.client(),
            self.sender,
            "control_reply",
            key,
            Some("reply"),
            status,
            next,
        )
        .await
    }
    async fn row(&self, id: Uuid) -> Value {
        read_row(self.client(), "deliveries", "delivery_id", id).await
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}
fn ended(reason: EndReason, stop: Option<StopRecord>) -> SessionEnd<'static> {
    SessionEnd {
        reason,
        exit_code: None,
        exit_signal: None,
        stop,
        result_summary: None,
        artifact_paths: &[],
        stderr_tail: "",
    }
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn mark_sending_unknown_sets_unknown_daemon_restart_finished_at_and_clears_schedule() {
    let env = Env::new().await;
    let first = env.delivery("control_reply:1", "sending", Some(30.0)).await;
    let second = env.delivery("control_reply:2", "sending", None).await;
    assert_eq!(
        mark_sending_unknown(env.client(), deadline())
            .await
            .unwrap(),
        2
    );
    for id in [first, second] {
        let row = env.row(id).await;
        assert_eq!(row["status"], "unknown");
        assert_eq!(row["last_error_code"], "daemon_restart");
        assert!(row["finished_at"].is_string());
        assert!(row["next_attempt_at"].is_null());
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn mark_sending_unknown_leaves_other_statuses_unchanged() {
    let env = Env::new().await;
    let mut before = Vec::new();
    for status in ["pending", "sent", "failed", "unknown"] {
        let id = env
            .delivery(&format!("control_reply:{status}"), status, None)
            .await;
        before.push((id, env.row(id).await));
    }
    assert_eq!(
        mark_sending_unknown(env.client(), deadline())
            .await
            .unwrap(),
        0
    );
    for (id, row) in before {
        assert_eq!(env.row(id).await, row);
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unfinished_runs_lists_dispatched_runs_without_terminal_of_both_binding_kinds_oldest_first()
{
    let env = Env::new().await;
    let host = insert_host_binding(env.client(), "/w/host").await;
    let newer = insert_event_for_run(env.client(), env.sender, "run-s", "T1", "dispatched").await;
    shift_event(env.client(), newer, "dispatched_at", -10.0).await;
    let older = insert_event_for_run(env.client(), host, "run-h", "TH", "dispatched").await;
    shift_event(env.client(), older, "dispatched_at", -20.0).await;
    insert_event_for_run(env.client(), env.sender, "run-p", "T1", "pending").await;
    insert_event_for_run(env.client(), env.sender, "run-c", "T1", "conflict").await;
    let done = insert_event_for_run(env.client(), host, "run-d", "TH", "dispatched").await;
    shift_event(env.client(), done, "dispatched_at", -30.0).await;
    set_terminal(env.client(), done, "succeeded").await;
    env.client().execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,command,dispatch_status,dispatched_at) VALUES (gen_random_uuid(),'event','telegram','1001','runless',statement_timestamp(),$1,'control_command','status','dispatched',statement_timestamp()-interval '40 seconds')", &[&env.sender]).await.unwrap();
    assert_eq!(
        unfinished_runs(env.client(), deadline()).await.unwrap(),
        [
            OpenRun {
                thread_id: "TH".into(),
                run_id: "run-h".into(),
            },
            OpenRun {
                thread_id: "T1".into(),
                run_id: "run-s".into(),
            },
        ]
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn list_orphan_sessions_returns_unended_session_rows_only() {
    let env = Env::new().await;
    let with_group = insert_orphan_session(env.client(), env.sender, "run-1", Some(4242)).await;
    let without = insert_orphan_session(env.client(), env.sender, "run-2", None).await;
    insert_ended_session(
        env.client(),
        env.sender,
        "run-3",
        "result_success",
        None,
        &[],
    )
    .await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-1", 600.0).await;
    assert_eq!(
        list_orphan_sessions(env.client(), deadline())
            .await
            .unwrap(),
        [
            OrphanSession {
                record_id: with_group,
                run_id: "run-1".into(),
                pgid: Some(4242),
            },
            OrphanSession {
                record_id: without,
                run_id: "run-2".into(),
                pgid: None,
            },
        ]
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn ending_an_orphan_row_with_end_session_writes_the_ruled_value_combinations() {
    let env = Env::new().await;
    let at = OffsetDateTime::now_utc();
    for (index, (reason, stop, reason_text, outcome, confirmed)) in [
        (
            EndReason::ChildExited,
            Some(StopRecord::Confirmed { at }),
            "child_exited",
            Some("confirmed"),
            true,
        ),
        (
            EndReason::StopRequested,
            Some(StopRecord::Unknown),
            "stop_requested",
            Some("unknown"),
            false,
        ),
        (EndReason::ChildExited, None, "child_exited", None, false),
    ]
    .into_iter()
    .enumerate()
    {
        let record =
            insert_orphan_session(env.client(), env.sender, &format!("run-{index}"), Some(99))
                .await;
        end_session(env.client(), record, ended(reason, stop), deadline())
            .await
            .unwrap();
        let row = read_row(env.client(), "host_driver_sessions", "record_id", record).await;
        assert!(row["ended_at"].is_string());
        assert_eq!(row["end_reason"], reason_text);
        assert_eq!(row["stop_outcome"].as_str(), outcome);
        assert_eq!(row["stop_confirmed_at"].is_string(), confirmed);
    }
    assert!(
        list_orphan_sessions(env.client(), deadline())
            .await
            .unwrap()
            .is_empty()
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn deny_undecided_permissions_denies_expired_and_unexpired_as_run_stopped_without_token() {
    let env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-live", 600.0).await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-old", -5.0).await;
    assert_eq!(
        deny_undecided_permissions(env.client(), deadline())
            .await
            .unwrap(),
        2
    );
    for id in ["p-live", "p-old"] {
        let row = permission_row_json(env.client(), id).await;
        assert_eq!(row["decision"], "deny");
        assert_eq!(row["decided_via"], "run_stopped");
        assert!(row["decided_at"].is_string());
        assert!(row["decided_by_token"].is_null());
        assert!(row["answered_at"].is_null());
    }
    assert_eq!(
        deny_undecided_permissions(env.client(), deadline())
            .await
            .unwrap(),
        0
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn deny_undecided_permissions_leaves_decided_rows_including_unanswered_unchanged() {
    let env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-unanswered", 600.0).await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-answered", 600.0).await;
    assert_eq!(
        decide(env.client(), "p-unanswered", Decision::Allow).await,
        Decided::Decided
    );
    assert_eq!(
        decide(env.client(), "p-answered", Decision::Deny).await,
        Decided::Decided
    );
    answer_permission(env.client(), "p-answered", deadline())
        .await
        .unwrap();
    let before = [
        permission_row_json(env.client(), "p-unanswered").await,
        permission_row_json(env.client(), "p-answered").await,
    ];
    assert!(before[0]["answered_at"].is_null());
    assert_eq!(
        deny_undecided_permissions(env.client(), deadline())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        [
            permission_row_json(env.client(), "p-unanswered").await,
            permission_row_json(env.client(), "p-answered").await,
        ],
        before
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn deny_undecided_permissions_leaves_permission_notice_deliveries_pending() {
    let env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-1", 600.0).await;
    let notice = insert_delivery(
        env.client(),
        env.sender,
        "permission_notice",
        "perm:p-1",
        Some("approve p-1"),
        "pending",
        None,
    )
    .await;
    let before = env.row(notice).await;
    assert_eq!(
        deny_undecided_permissions(env.client(), deadline())
            .await
            .unwrap(),
        1
    );
    let after = env.row(notice).await;
    assert_eq!(after["status"], "pending");
    assert_eq!(after, before);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn decide_permission_after_deny_is_not_pending_and_deny_after_decide_changes_nothing() {
    let env = Env::new().await;
    insert_permission_row(env.client(), env.sender, "run-1", "p-denied", 600.0).await;
    assert_eq!(
        deny_undecided_permissions(env.client(), deadline())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        decide(env.client(), "p-denied", Decision::Allow).await,
        Decided::NotPending
    );
    assert_eq!(
        permission_row_json(env.client(), "p-denied").await["decided_via"],
        "run_stopped"
    );
    insert_permission_row(env.client(), env.sender, "run-2", "p-allowed", 600.0).await;
    assert_eq!(
        decide(env.client(), "p-allowed", Decision::Allow).await,
        Decided::Decided
    );
    let before = permission_row_json(env.client(), "p-allowed").await;
    assert_eq!(
        deny_undecided_permissions(env.client(), deadline())
            .await
            .unwrap(),
        0
    );
    assert_eq!(permission_row_json(env.client(), "p-allowed").await, before);
    env.stop().await;
}
