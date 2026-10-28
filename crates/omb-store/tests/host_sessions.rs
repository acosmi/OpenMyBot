//! Host driver session and permission rows against an own PostgreSQL 17.11 cluster.
use omb_store::{
    Decided, DecidedVia, Decision, EndReason, GrantKind, PermissionNew, ResumeSession, SessionEnd,
    SessionStart, StopRecord, StoreError, answer_permission, clear_resumable, decide_permission,
    end_session, insert_permission, migrate, read_permission, record_readonly_allow, resolve_run,
    revoke_binding, session_init, session_progress, session_spawned, settle_permission,
    testkit::{
        Fixture, Session, deadline, decide, insert_event_for_run, insert_host_binding,
        insert_sender_in, read_row, set_terminal,
    },
    upsert_session,
};
use std::time::Duration;
use time::OffsetDateTime;
use tokio_postgres::Client;
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(600);

struct Env {
    fixture: Fixture,
    session: Session,
    sender: Uuid,
    host: Uuid,
}
impl Env {
    /// Telegram sender on thread `T1` in `/w/sender` and the host binding in `/w/host`.
    async fn new() -> Self {
        let mut fixture = Fixture::new().await;
        let mut session = fixture.connect().await;
        migrate(&mut session.client, deadline()).await.unwrap();
        let sender = insert_sender_in(
            &session.client,
            "telegram",
            "1001",
            "telegram:42",
            "T1",
            "/w/sender",
        )
        .await;
        let host = insert_host_binding(&session.client, "/w/host").await;
        Self {
            fixture,
            session,
            sender,
            host,
        }
    }
    fn client(&self) -> &Client {
        &self.session.client
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
    async fn event(&self, binding: Uuid, run: &str, thread: &str, status: &str) -> Uuid {
        insert_event_for_run(self.client(), binding, run, thread, status).await
    }
    async fn start(&self, binding: Uuid, run: &str) -> Uuid {
        upsert_session(
            self.client(),
            SessionStart {
                run_id: run,
                binding_id: binding,
                workspace_dir: "/w/sender",
            },
            deadline(),
        )
        .await
        .unwrap()
    }
    /// A session row of `run` that ended with `reason` after an init with `native`.
    async fn ended(&self, binding: Uuid, run: &str, native: &str, reason: EndReason) -> Uuid {
        let record = self.start(binding, run).await;
        session_init(self.client(), record, native, deadline())
            .await
            .unwrap();
        end_session(self.client(), record, end(reason), deadline())
            .await
            .unwrap();
        record
    }
    async fn row(&self, record: Uuid) -> serde_json::Value {
        read_row(self.client(), "host_driver_sessions", "record_id", record).await
    }
    async fn permission(&self, permission_id: &str) -> serde_json::Value {
        self.client()
            .query_one("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE permission_id=$1", &[&permission_id])
            .await
            .unwrap()
            .get(0)
    }
    async fn count(&self, sql: &str) -> i64 {
        self.client().query_one(sql, &[]).await.unwrap().get(0)
    }
}
fn end(reason: EndReason) -> SessionEnd<'static> {
    SessionEnd {
        reason,
        exit_code: None,
        exit_signal: None,
        stop: None,
        result_summary: None,
        artifact_paths: &[],
        stderr_tail: "",
    }
}
fn request<'a>(
    run: &'a str,
    binding: Uuid,
    id: &'a str,
    native: &'a str,
    notice: Option<&'a str>,
) -> PermissionNew<'a> {
    PermissionNew {
        run_id: run,
        binding_id: binding,
        permission_id: id,
        native_request_id: native,
        tool_name: "Write",
        input_summary: "{\"file_path\":\"a.txt\"}",
        input_sha256: [7; 32],
        ttl: TTL,
        notice,
    }
}
async fn target_run(client: &Client, binding: Uuid) -> Option<String> {
    resolve_run(client, binding)
        .await
        .unwrap()
        .map(|target| target.run_id)
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resolve_run_picks_earliest_open_event_of_the_binding() {
    let env = Env::new().await;
    let done = env.event(env.sender, "r0", "T1", "dispatched").await;
    set_terminal(env.client(), done, "succeeded").await;
    let first = env.event(env.sender, "r1", "T1", "dispatched").await;
    env.event(env.sender, "r2", "T1", "pending").await;
    assert_eq!(
        target_run(env.client(), env.sender).await.as_deref(),
        Some("r1")
    );
    set_terminal(env.client(), first, "failed").await;
    assert_eq!(
        target_run(env.client(), env.sender).await.as_deref(),
        Some("r2")
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resolve_run_ignores_cancelled_conflict_and_expired_events() {
    let env = Env::new().await;
    for (run, status) in [("r1", "cancelled"), ("r2", "conflict"), ("r3", "expired")] {
        env.event(env.sender, run, "T1", status).await;
    }
    assert_eq!(target_run(env.client(), env.sender).await, None);
    env.event(env.sender, "r4", "T1", "pending").await;
    assert_eq!(
        target_run(env.client(), env.sender).await.as_deref(),
        Some("r4")
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resolve_run_works_while_dispatched_is_not_yet_written() {
    let env = Env::new().await;
    let event = env.event(env.host, "r1", "TH", "pending").await;
    assert_eq!(
        target_run(env.client(), env.host).await.as_deref(),
        Some("r1")
    );
    env.client()
        .execute("UPDATE openmybot.channel_events SET dispatch_status='dispatched',dispatched_at=statement_timestamp() WHERE record_id=$1", &[&event])
        .await
        .unwrap();
    assert_eq!(
        target_run(env.client(), env.host).await.as_deref(),
        Some("r1")
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resolve_run_returns_none_for_unknown_or_inactive_binding() {
    let mut env = Env::new().await;
    assert_eq!(target_run(env.client(), Uuid::now_v7()).await, None);
    env.event(env.sender, "r1", "T1", "dispatched").await;
    env.client()
        .execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&env.sender])
        .await
        .unwrap();
    assert_eq!(target_run(env.client(), env.sender).await, None);
    env.event(env.host, "r2", "TH", "dispatched").await;
    let host = env.host;
    revoke_binding(&mut env.session.client, host, deadline())
        .await
        .unwrap();
    assert_eq!(target_run(env.client(), env.host).await, None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resolve_run_reports_kind_workspace_chat_and_thread() {
    let env = Env::new().await;
    env.event(env.sender, "rs", "T1", "pending").await;
    env.event(env.host, "rh", "TH", "pending").await;
    let sender = resolve_run(env.client(), env.sender)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sender.binding_id, env.sender);
    assert_eq!(sender.kind, GrantKind::Sender);
    assert_eq!(sender.run_id, "rs");
    assert_eq!(sender.thread_id, "T1");
    assert_eq!(sender.workspace_dir, "/w/sender");
    assert_eq!(sender.chat_key.as_deref(), Some("telegram:42"));
    assert_eq!(sender.resume, None);
    let host = resolve_run(env.client(), env.host).await.unwrap().unwrap();
    assert_eq!(host.kind, GrantKind::Host);
    assert_eq!(host.run_id, "rh");
    assert_eq!(host.thread_id, "TH");
    assert_eq!(host.workspace_dir, "/w/host");
    assert_eq!(host.chat_key, None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resume_session_is_latest_resumable_result_success_in_same_thread() {
    let env = Env::new().await;
    for (run, native, reason) in [
        ("r1", "n1", EndReason::ResultSuccess),
        ("r2", "n2", EndReason::ResultSuccess),
        ("r3", "n3", EndReason::ResultError),
    ] {
        let event = env.event(env.sender, run, "T1", "dispatched").await;
        set_terminal(env.client(), event, "succeeded").await;
        env.ended(env.sender, run, native, reason).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let other = env.event(env.sender, "r9", "T9", "dispatched").await;
    set_terminal(env.client(), other, "succeeded").await;
    env.ended(env.sender, "r9", "n9", EndReason::ResultSuccess)
        .await;
    let second = env
        .row(
            env.client()
                .query_one(
                    "SELECT record_id FROM openmybot.host_driver_sessions WHERE run_id='r2'",
                    &[],
                )
                .await
                .unwrap()
                .get(0),
        )
        .await;
    env.event(env.sender, "r4", "T1", "pending").await;
    let target = resolve_run(env.client(), env.sender)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.run_id, "r4");
    assert_eq!(
        target.resume,
        Some(ResumeSession {
            record_id: second["record_id"].as_str().unwrap().parse().unwrap(),
            native_session_id: "n2".into(),
        })
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resume_session_is_not_taken_after_thread_changes() {
    let env = Env::new().await;
    let event = env.event(env.sender, "r1", "T1", "dispatched").await;
    set_terminal(env.client(), event, "succeeded").await;
    env.ended(env.sender, "r1", "n1", EndReason::ResultSuccess)
        .await;
    env.event(env.sender, "r2", "T1", "pending").await;
    assert!(
        resolve_run(env.client(), env.sender)
            .await
            .unwrap()
            .unwrap()
            .resume
            .is_some()
    );
    // The thread reset moves the binding and its pending events to a new thread.
    env.client()
        .execute("UPDATE openmybot.channel_bindings SET thread_id='T2',thread_generation=thread_generation+1,revision=revision+1 WHERE binding_id=$1", &[&env.sender])
        .await
        .unwrap();
    env.client()
        .execute("UPDATE openmybot.channel_events SET thread_id='T2' WHERE binding_id=$1 AND dispatch_status='pending'", &[&env.sender])
        .await
        .unwrap();
    let target = resolve_run(env.client(), env.sender)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (target.run_id.as_str(), target.thread_id.as_str()),
        ("r2", "T2")
    );
    assert_eq!(target.resume, None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn resume_session_is_never_returned_for_host_binding() {
    let env = Env::new().await;
    let event = env.event(env.host, "r1", "TH", "dispatched").await;
    set_terminal(env.client(), event, "succeeded").await;
    env.ended(env.host, "r1", "n1", EndReason::ResultSuccess)
        .await;
    env.event(env.host, "r2", "TH", "pending").await;
    let target = resolve_run(env.client(), env.host).await.unwrap().unwrap();
    assert_eq!(target.run_id, "r2");
    assert_eq!(target.resume, None);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn clear_resumable_resets_the_resumed_row() {
    let env = Env::new().await;
    let event = env.event(env.sender, "r1", "T1", "dispatched").await;
    set_terminal(env.client(), event, "succeeded").await;
    let record = env
        .ended(env.sender, "r1", "n1", EndReason::ResultSuccess)
        .await;
    assert_eq!(env.row(record).await["resumable"], true);
    env.event(env.sender, "r2", "T1", "pending").await;
    clear_resumable(env.client(), record, deadline())
        .await
        .unwrap();
    assert_eq!(env.row(record).await["resumable"], false);
    assert_eq!(
        resolve_run(env.client(), env.sender)
            .await
            .unwrap()
            .unwrap()
            .resume,
        None
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn upsert_session_satisfies_session_row_check_and_refreshes_on_retry() {
    let env = Env::new().await;
    let record = env.start(env.sender, "r1").await;
    let first = env.row(record).await;
    assert_eq!(first["record_kind"], "session");
    assert_eq!(first["host_kind"], "crabcode");
    assert_eq!(first["workspace_dir"], "/w/sender");
    assert!(first["started_at"].is_string());
    end_session(
        env.client(),
        record,
        end(EndReason::VersionRejected),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(env.row(record).await["end_reason"], "version_rejected");
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(env.start(env.sender, "r1").await, record);
    let retried = env.row(record).await;
    assert!(retried["end_reason"].is_null());
    assert!(retried["ended_at"].is_null());
    assert_ne!(retried["started_at"], first["started_at"]);
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.host_driver_sessions WHERE run_id='r1'")
            .await,
        1
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pre_spawn_failure_row_has_no_child_fields() {
    let env = Env::new().await;
    for (run, reason, text) in [
        ("r1", EndReason::VersionRejected, "version_rejected"),
        ("r2", EndReason::SpawnFailed, "spawn_failed"),
    ] {
        let record = env.start(env.host, run).await;
        end_session(env.client(), record, end(reason), deadline())
            .await
            .unwrap();
        let row = env.row(record).await;
        assert_eq!(row["end_reason"], text);
        for column in [
            "host_version",
            "args_sha256",
            "native_session_id",
            "resumed_from",
            "child_pid",
            "pgid",
            "init_at",
            "last_event_seq",
            "exit_code",
            "exit_signal",
            "resumable",
        ] {
            assert!(row[column].is_null(), "{run} {column}");
        }
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn session_updates_write_spawn_init_progress_and_end_columns() {
    let env = Env::new().await;
    let record = env.start(env.sender, "r1").await;
    session_spawned(
        env.client(),
        record,
        "1.1.16",
        [9; 32],
        Some("n0"),
        4242,
        4242,
        deadline(),
    )
    .await
    .unwrap();
    session_init(env.client(), record, "n1", deadline())
        .await
        .unwrap();
    session_progress(env.client(), record, 7, 1234, deadline())
        .await
        .unwrap();
    let at = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    end_session(
        env.client(),
        record,
        SessionEnd {
            reason: EndReason::StopRequested,
            exit_code: None,
            exit_signal: Some(15),
            stop: Some(StopRecord::Confirmed { at }),
            result_summary: Some("done"),
            artifact_paths: &["a.txt".into(), "b/c.txt".into()],
            stderr_tail: "warning",
        },
        deadline(),
    )
    .await
    .unwrap();
    let row = env.row(record).await;
    assert_eq!(row["host_version"], "1.1.16");
    assert_eq!(row["resumed_from"], "n0");
    assert_eq!(
        (row["child_pid"].as_i64(), row["pgid"].as_i64()),
        (Some(4242), Some(4242))
    );
    assert_eq!(row["native_session_id"], "n1");
    assert!(row["init_at"].is_string() && row["last_event_at"].is_string());
    assert_eq!(
        (row["last_event_seq"].as_i64(), row["output_bytes"].as_i64()),
        (Some(7), Some(1234))
    );
    assert_eq!(row["end_reason"], "stop_requested");
    assert_eq!(row["exit_signal"], 15);
    assert!(row["exit_code"].is_null());
    assert_eq!(row["stop_outcome"], "confirmed");
    assert_eq!(row["result_summary"], "done");
    assert_eq!(
        row["artifact_paths"],
        serde_json::json!(["a.txt", "b/c.txt"])
    );
    assert_eq!(row["stderr_tail"], "warning");
    assert!(row["ended_at"].is_string());
    let stored: OffsetDateTime = env
        .client()
        .query_one("SELECT stop_confirmed_at,octet_length(args_sha256) FROM openmybot.host_driver_sessions WHERE record_id=$1", &[&record])
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, at);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn end_session_truncates_summary_and_tail_on_utf8_boundary() {
    let env = Env::new().await;
    let record = env.start(env.sender, "r1").await;
    let summary = format!("{}é{}", "a".repeat(2047), "z".repeat(10));
    let tail = format!("{}é{}", "x".repeat(10), "b".repeat(2047));
    end_session(
        env.client(),
        record,
        SessionEnd {
            result_summary: Some(&summary),
            stderr_tail: &tail,
            ..end(EndReason::ResultError)
        },
        deadline(),
    )
    .await
    .unwrap();
    let row = env.row(record).await;
    assert_eq!(row["result_summary"].as_str().unwrap(), "a".repeat(2047));
    assert_eq!(row["stderr_tail"].as_str().unwrap(), "b".repeat(2047));
    let exact = "é".repeat(1024);
    end_session(
        env.client(),
        record,
        SessionEnd {
            result_summary: Some(&exact),
            stderr_tail: &exact,
            ..end(EndReason::ResultError)
        },
        deadline(),
    )
    .await
    .unwrap();
    let row = env.row(record).await;
    assert_eq!(row["result_summary"].as_str().unwrap(), exact);
    assert_eq!(row["stderr_tail"].as_str().unwrap(), exact);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn end_session_success_sets_resumable_and_other_reasons_leave_it_null() {
    let env = Env::new().await;
    let reasons = [
        EndReason::ResultSuccess,
        EndReason::ResultError,
        EndReason::StopRequested,
        EndReason::OutputLimit,
        EndReason::LineLimit,
        EndReason::Stalled,
        EndReason::ProtocolError,
        EndReason::ChildExited,
        EndReason::SpawnFailed,
        EndReason::VersionRejected,
        EndReason::InitTimeout,
        EndReason::ResumeFailed,
    ];
    for (index, reason) in reasons.into_iter().enumerate() {
        let record = env.start(env.sender, &format!("r{index}")).await;
        end_session(env.client(), record, end(reason), deadline())
            .await
            .unwrap();
        let row = env.row(record).await;
        if reason == EndReason::ResultSuccess {
            assert_eq!(row["resumable"], true);
        } else {
            assert!(row["resumable"].is_null(), "{reason:?}");
        }
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn insert_permission_satisfies_permission_row_check_and_unique_ids() {
    let env = Env::new().await;
    let expires = insert_permission(
        env.client(),
        request("r1", env.host, "hp0000000001", "q1", None),
        deadline(),
    )
    .await
    .unwrap();
    let row = env.permission("hp0000000001").await;
    assert_eq!(row["record_kind"], "permission");
    assert_eq!(row["tool_name"], "Write");
    assert_eq!(row["native_request_id"], "q1");
    assert_eq!(row["input_summary"], "{\"file_path\":\"a.txt\"}");
    assert!(row["decision"].is_null() && row["decided_via"].is_null());
    assert!(row["host_kind"].is_null() && row["started_at"].is_null());
    let ttl: f64 = env
        .client()
        .query_one("SELECT extract(epoch FROM expires_at-requested_at)::float8 FROM openmybot.host_driver_sessions WHERE permission_id='hp0000000001'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(ttl, 600.0);
    let stored: OffsetDateTime = env
        .client()
        .query_one("SELECT expires_at FROM openmybot.host_driver_sessions WHERE permission_id='hp0000000001'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, expires);
    assert_eq!(
        insert_permission(
            env.client(),
            request("r2", env.host, "hp0000000001", "q9", None),
            deadline()
        )
        .await,
        Err(StoreError::HostSessionFailed)
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn permission_native_request_is_unique_per_run() {
    let env = Env::new().await;
    insert_permission(
        env.client(),
        request("r1", env.host, "hp0000000001", "q1", None),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        insert_permission(
            env.client(),
            request("r1", env.host, "hp0000000002", "q1", None),
            deadline()
        )
        .await,
        Err(StoreError::HostSessionFailed)
    );
    insert_permission(
        env.client(),
        request("r2", env.host, "hp0000000003", "q1", None),
        deadline(),
    )
    .await
    .unwrap();
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn sender_permission_writes_notice_delivery_in_the_same_statement() {
    let env = Env::new().await;
    insert_permission(
        env.client(),
        request("r1", env.sender, "hp0000000001", "q1", Some("notice one")),
        deadline(),
    )
    .await
    .unwrap();
    let delivery: serde_json::Value = env
        .client()
        .query_one("SELECT row_to_json(d) FROM openmybot.deliveries d", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(delivery["idempotency_key"], "perm:hp0000000001");
    assert_eq!(delivery["kind"], "permission_notice");
    assert_eq!(delivery["channel_kind"], "telegram");
    assert_eq!(delivery["chat_key"], "telegram:42");
    assert_eq!(delivery["binding_id"], env.sender.to_string());
    assert_eq!(delivery["body"], "notice one");
    assert_eq!(delivery["status"], "pending");
    // Replaying the same permission writes neither a row nor a second delivery.
    assert_eq!(
        insert_permission(
            env.client(),
            request("r1", env.sender, "hp0000000001", "q7", Some("notice one")),
            deadline()
        )
        .await,
        Err(StoreError::HostSessionFailed)
    );
    // A permission row that cannot be written leaves no delivery behind.
    assert_eq!(
        insert_permission(
            env.client(),
            request("r1", env.sender, "hp0000000002", "q1", Some("notice two")),
            deadline()
        )
        .await,
        Err(StoreError::HostSessionFailed)
    );
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.deliveries").await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.host_driver_sessions")
            .await,
        1
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn host_permission_writes_no_notice_delivery() {
    let env = Env::new().await;
    insert_permission(
        env.client(),
        request("r1", env.host, "hp0000000001", "q1", None),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn decide_permission_writes_cli_token_and_refuses_not_pending_or_expired() {
    let env = Env::new().await;
    insert_permission(
        env.client(),
        request("r1", env.host, "hp0000000001", "q1", None),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        decide(env.client(), "hp0000000001", Decision::Deny).await,
        Decided::Decided
    );
    let row = env.permission("hp0000000001").await;
    assert_eq!(row["decision"], "deny");
    assert_eq!(row["decided_via"], "cli");
    assert!(row["decided_by_token"].is_string() && row["decided_at"].is_string());
    assert_eq!(
        decide(env.client(), "hp0000000001", Decision::Allow).await,
        Decided::NotPending
    );
    assert_eq!(env.permission("hp0000000001").await["decision"], "deny");
    assert_eq!(
        decide(env.client(), "hp0000000404", Decision::Allow).await,
        Decided::NotPending
    );
    insert_permission(
        env.client(),
        PermissionNew {
            ttl: Duration::from_millis(1),
            ..request("r1", env.host, "hp0000000002", "q2", None)
        },
        deadline(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        decide(env.client(), "hp0000000002", Decision::Allow).await,
        Decided::Expired
    );
    assert!(env.permission("hp0000000002").await["decision"].is_null());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn settle_permission_denies_only_while_undecided() {
    let env = Env::new().await;
    for (id, native) in [("hp0000000001", "q1"), ("hp0000000002", "q2")] {
        insert_permission(
            env.client(),
            request("r1", env.host, id, native, None),
            deadline(),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        settle_permission(
            env.client(),
            "hp0000000001",
            DecidedVia::Timeout,
            deadline()
        )
        .await,
        Ok((Decision::Deny, DecidedVia::Timeout))
    );
    assert_eq!(
        settle_permission(
            env.client(),
            "hp0000000001",
            DecidedVia::RunStopped,
            deadline()
        )
        .await,
        Ok((Decision::Deny, DecidedVia::Timeout))
    );
    decide(env.client(), "hp0000000002", Decision::Allow).await;
    assert_eq!(
        settle_permission(
            env.client(),
            "hp0000000002",
            DecidedVia::RunStopped,
            deadline()
        )
        .await,
        Ok((Decision::Allow, DecidedVia::Cli))
    );
    assert_eq!(env.permission("hp0000000002").await["decision"], "allow");
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn decide_and_timeout_race_has_exactly_one_winner() {
    let mut env = Env::new().await;
    let other = env.fixture.connect().await;
    for round in 0..10 {
        let id = format!("hp00000000{round:02}");
        insert_permission(
            env.client(),
            request("r1", env.host, &id, &format!("q{round}"), None),
            deadline(),
        )
        .await
        .unwrap();
        let (decided, settled) = tokio::join!(
            decide(env.client(), &id, Decision::Allow),
            settle_permission(&other.client, &id, DecidedVia::Timeout, deadline()),
        );
        let settled = settled.unwrap();
        let row = env.permission(&id).await;
        match decided {
            Decided::Decided => {
                assert_eq!(settled, (Decision::Allow, DecidedVia::Cli), "round {round}");
                assert_eq!(row["decided_via"], "cli", "round {round}");
            }
            Decided::NotPending => {
                assert_eq!(
                    settled,
                    (Decision::Deny, DecidedVia::Timeout),
                    "round {round}"
                );
                assert_eq!(row["decided_via"], "timeout", "round {round}");
            }
            Decided::Expired => panic!("round {round}: unexpired request reported expired"),
        }
    }
    other.close().await;
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn readonly_allow_row_is_decided_by_rule_without_token() {
    let env = Env::new().await;
    record_readonly_allow(
        env.client(),
        PermissionNew {
            tool_name: "Read",
            ..request("r1", env.sender, "hp0000000001", "q1", Some("ignored"))
        },
        deadline(),
    )
    .await
    .unwrap();
    let row = env.permission("hp0000000001").await;
    assert_eq!(row["decision"], "allow");
    assert_eq!(row["decided_via"], "readonly_rule");
    assert_eq!(row["tool_name"], "Read");
    assert!(row["decided_at"].is_string() && row["expires_at"].is_string());
    assert!(row["decided_by_token"].is_null() && row["answered_at"].is_null());
    assert_eq!(
        env.count("SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    assert_eq!(
        read_permission(env.client(), "hp0000000001").await,
        Ok(Some((Decision::Allow, DecidedVia::ReadonlyRule)))
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn answer_permission_sets_answered_at_after_decision() {
    let env = Env::new().await;
    insert_permission(
        env.client(),
        request("r1", env.host, "hp0000000001", "q1", None),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        answer_permission(env.client(), "hp0000000001", deadline()).await,
        Err(StoreError::HostSessionFailed)
    );
    assert!(env.permission("hp0000000001").await["answered_at"].is_null());
    decide(env.client(), "hp0000000001", Decision::Allow).await;
    answer_permission(env.client(), "hp0000000001", deadline())
        .await
        .unwrap();
    let ordered: bool = env
        .client()
        .query_one("SELECT answered_at>=decided_at FROM openmybot.host_driver_sessions WHERE permission_id='hp0000000001'", &[])
        .await
        .unwrap()
        .get(0);
    assert!(ordered);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn read_permission_returns_the_decision_written_by_decide() {
    let env = Env::new().await;
    insert_permission(
        env.client(),
        request("r1", env.host, "hp0000000001", "q1", None),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        read_permission(env.client(), "hp0000000001").await,
        Ok(None)
    );
    assert_eq!(
        read_permission(env.client(), "hp0000000404").await,
        Ok(None)
    );
    decide(env.client(), "hp0000000001", Decision::Allow).await;
    assert_eq!(
        read_permission(env.client(), "hp0000000001").await,
        Ok(Some((Decision::Allow, DecidedVia::Cli)))
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn store_errors_map_to_host_session_failed() {
    let env = Env::new().await;
    let failed = Err(StoreError::HostSessionFailed);
    assert_eq!(
        session_progress(env.client(), Uuid::now_v7(), 1, 1, deadline()).await,
        failed
    );
    assert_eq!(
        upsert_session(
            env.client(),
            SessionStart {
                run_id: &"r".repeat(129),
                binding_id: env.host,
                workspace_dir: "/w"
            },
            deadline()
        )
        .await
        .map(drop),
        failed
    );
    assert_eq!(
        upsert_session(
            env.client(),
            SessionStart {
                run_id: "r1",
                binding_id: Uuid::now_v7(),
                workspace_dir: "/w"
            },
            deadline()
        )
        .await
        .map(drop),
        failed
    );
    let record = env.start(env.host, "r2").await;
    assert_eq!(
        session_init(env.client(), record, &"n".repeat(129), deadline()).await,
        failed
    );
    assert_eq!(
        session_init(env.client(), record, "n1", tokio::time::Instant::now()).await,
        failed
    );
    assert_eq!(
        settle_permission(
            env.client(),
            "hp0000000404",
            DecidedVia::Timeout,
            deadline()
        )
        .await,
        Err(StoreError::HostSessionFailed)
    );
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn testkit_decide_wraps_decide_permission_with_a_control_token() {
    let env = Env::new().await;
    insert_permission(
        env.client(),
        request("r1", env.host, "hp0000000001", "q1", None),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        decide(env.client(), "hp0000000001", Decision::Allow).await,
        Decided::Decided
    );
    let linked: i64 = env
        .client()
        .query_one("SELECT count(*) FROM openmybot.host_driver_sessions h JOIN openmybot.control_tokens t ON t.token_id=h.decided_by_token WHERE h.permission_id='hp0000000001' AND h.decided_via='cli'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(linked, 1);
    // The production function itself refuses a token that names no control token row.
    insert_permission(
        env.client(),
        request("r1", env.host, "hp0000000002", "q2", None),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        decide_permission(
            env.client(),
            "hp0000000002",
            Decision::Allow,
            Uuid::now_v7(),
            deadline()
        )
        .await,
        Err(StoreError::HostSessionFailed)
    );
    env.stop().await;
}
