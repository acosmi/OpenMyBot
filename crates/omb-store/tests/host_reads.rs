//! Host binding state and run reads against an own PostgreSQL 17.11 cluster.
use omb_store::{
    Decision, EndReason, HostAccept, HostBindingState, HostMessage, MCP_LIST_MAX, OperationId,
    RunState, RunView, SessionEnd, SessionStart, StoreError, accept_host_begin, binding_run,
    binding_runs, end_session, host_binding_state, migrate, reconfirm_binding, revoke_binding,
    testkit::{
        Fixture, Session, deadline, decide, insert_event_for_run, insert_host_binding,
        insert_permission_row, insert_sender, set_terminal, shift_event, suspend_binding,
    },
    upsert_session,
};
use std::time::Duration;
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

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
    async fn sender(&self) -> Uuid {
        insert_sender(self.client(), "telegram", "1001", "telegram:42", "T1").await
    }
    async fn event(&self, binding: Uuid, run: &str, status: &str) -> Uuid {
        insert_event_for_run(
            self.client(),
            binding,
            run,
            &format!("thread-{run}"),
            status,
        )
        .await
    }
    async fn run(&self, binding: Uuid, run: &str) -> Option<RunView> {
        binding_run(self.client(), binding, run, deadline())
            .await
            .unwrap()
    }
    async fn binding_state(&self) -> HostBindingState {
        host_binding_state(self.client(), deadline()).await.unwrap()
    }
    async fn state(&self, binding: Uuid, run: &str) -> RunState {
        self.run(binding, run).await.unwrap().state
    }
    async fn runs(&self, binding: Uuid, limit: i64) -> Vec<RunView> {
        binding_runs(self.client(), binding, limit, deadline())
            .await
            .unwrap()
    }
    async fn stop(self) {
        self.session.close().await;
        self.fixture.stop().await;
    }
}

/// One host binding's events in every state the reads distinguish, with the expected state and
/// permission ids of each run.
async fn seed(env: &Env, host: Uuid) -> Vec<(&'static str, RunState, Vec<&'static str>)> {
    let client = env.client();
    env.event(host, "pending", "pending").await;
    env.event(host, "running", "dispatched").await;
    env.event(host, "asking", "dispatched").await;
    insert_permission_row(client, host, "asking", "p-one", 600.0).await;
    env.event(host, "asking-two", "dispatched").await;
    insert_permission_row(client, host, "asking-two", "p-late", 600.0).await;
    insert_permission_row(client, host, "asking-two", "p-early", 600.0).await;
    client.execute("UPDATE openmybot.host_driver_sessions SET requested_at=statement_timestamp()-make_interval(secs=>10) WHERE permission_id='p-early'", &[]).await.unwrap();
    env.event(host, "lapsed", "dispatched").await;
    insert_permission_row(client, host, "lapsed", "p-lapsed", -5.0).await;
    env.event(host, "answered", "dispatched").await;
    insert_permission_row(client, host, "answered", "p-answered", 600.0).await;
    decide(client, "p-answered", Decision::Allow).await;
    env.event(host, "queued-asking", "pending").await;
    insert_permission_row(client, host, "queued-asking", "p-queued", 600.0).await;
    env.event(host, "neighbour", "dispatched").await;
    insert_permission_row(client, host, "pending", "p-other-run", 600.0).await;
    for (run, kind) in [
        ("ok", "succeeded"),
        ("bad", "failed"),
        ("stopped", "cancelled"),
        ("unknown", "reconciliation_required"),
    ] {
        let record = env.event(host, run, "dispatched").await;
        set_terminal(client, record, kind).await;
    }
    env.event(host, "expired", "expired").await;
    env.event(host, "cancelled", "cancelled").await;
    env.event(host, "conflict", "conflict").await;
    let record = env.event(host, "queued-failed", "pending").await;
    set_terminal(client, record, "failed").await;
    let record = env.event(host, "expired-ok", "expired").await;
    set_terminal(client, record, "succeeded").await;
    vec![
        ("pending", RunState::Pending, vec![]),
        ("running", RunState::Running, vec![]),
        ("asking", RunState::AwaitingPermission, vec!["p-one"]),
        (
            "asking-two",
            RunState::AwaitingPermission,
            vec!["p-early", "p-late"],
        ),
        ("lapsed", RunState::Running, vec![]),
        ("answered", RunState::Running, vec![]),
        ("queued-asking", RunState::Pending, vec![]),
        ("neighbour", RunState::Running, vec![]),
        ("ok", RunState::Succeeded, vec![]),
        ("bad", RunState::Failed, vec![]),
        ("stopped", RunState::Cancelled, vec![]),
        ("unknown", RunState::ReconciliationRequired, vec![]),
        ("expired", RunState::Cancelled, vec![]),
        ("cancelled", RunState::Cancelled, vec![]),
        ("conflict", RunState::Failed, vec![]),
        ("queued-failed", RunState::Failed, vec![]),
        ("expired-ok", RunState::Succeeded, vec![]),
    ]
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn host_binding_state_reads_the_one_live_host_binding() {
    let mut env = Env::new().await;
    assert_eq!(env.binding_state().await, HostBindingState::NotBound);
    let host = env.host().await;
    assert_eq!(env.binding_state().await, HostBindingState::Active(host));
    suspend_binding(env.client(), host).await;
    assert_eq!(env.binding_state().await, HostBindingState::Suspended);
    reconfirm_binding(&mut env.session.client, host, 1, deadline())
        .await
        .unwrap();
    assert_eq!(env.binding_state().await, HostBindingState::Active(host));
    revoke_binding(&mut env.session.client, host, deadline())
        .await
        .unwrap();
    assert_eq!(env.binding_state().await, HostBindingState::NotBound);
    env.sender().await;
    assert_eq!(env.binding_state().await, HostBindingState::NotBound);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn run_state_is_derived_from_event_session_and_permission_rows() {
    let env = Env::new().await;
    let host = env.host().await;
    for (run, state, permissions) in seed(&env, host).await {
        let view = env.run(host, run).await.unwrap();
        assert_eq!(view.state, state, "{run}");
        assert_eq!(view.permission_ids, permissions, "{run}");
        assert_eq!(view.run_id, run);
        assert_eq!(view.thread_id, format!("thread-{run}"));
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reads_are_scoped_to_the_given_binding_and_to_accepted_messages() {
    let mut env = Env::new().await;
    let sender = env.sender().await;
    env.event(sender, "sender-run", "dispatched").await;
    let old = env.host().await;
    env.event(old, "old-run", "dispatched").await;
    revoke_binding(&mut env.session.client, old, deadline())
        .await
        .unwrap();
    let host = env.host().await;
    env.event(host, "own-run", "pending").await;
    let dropped = Uuid::now_v7();
    env.client().execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition) VALUES ($1,'event','host','crabcode',$2,statement_timestamp(),$3,'dropped_inactive')", &[&dropped, &format!("op:{dropped}"), &host]).await.unwrap();
    for run in ["sender-run", "old-run", "missing"] {
        assert_eq!(env.run(host, run).await, None, "{run}");
    }
    assert_eq!(env.state(host, "own-run").await, RunState::Pending);
    let listed: Vec<String> = env
        .runs(host, MCP_LIST_MAX)
        .await
        .into_iter()
        .map(|view| view.run_id)
        .collect();
    assert_eq!(listed, ["own-run"]);
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn summary_and_artifacts_come_from_the_session_row() {
    let env = Env::new().await;
    let host = env.host().await;
    env.event(host, "ended", "dispatched").await;
    env.event(host, "never-started", "dispatched").await;
    let start = || SessionStart {
        run_id: "ended",
        binding_id: host,
        workspace_dir: "/w/host",
    };
    let record = upsert_session(env.client(), start(), deadline())
        .await
        .unwrap();
    let artifacts = ["a.txt".to_owned(), "dir/b.md".to_owned()];
    end_session(
        env.client(),
        record,
        SessionEnd {
            reason: EndReason::ResultSuccess,
            exit_code: Some(0),
            exit_signal: None,
            stop: None,
            result_summary: Some("hello from fake"),
            artifact_paths: &artifacts,
            stderr_tail: "",
        },
        deadline(),
    )
    .await
    .unwrap();
    let view = env.run(host, "ended").await.unwrap();
    assert_eq!(view.summary.as_deref(), Some("hello from fake"));
    assert_eq!(view.artifacts, artifacts);
    env.client()
        .execute(
            "UPDATE openmybot.host_driver_sessions SET result_summary=NULL WHERE record_id=$1",
            &[&record],
        )
        .await
        .unwrap();
    let view = env.run(host, "ended").await.unwrap();
    assert_eq!(view.summary, None);
    assert_eq!(view.artifacts, artifacts);
    let view = env.run(host, "never-started").await.unwrap();
    assert_eq!(view.summary, None);
    assert!(view.artifacts.is_empty());
    upsert_session(env.client(), start(), deadline())
        .await
        .unwrap();
    let view = env.run(host, "ended").await.unwrap();
    assert_eq!(view.summary, None);
    assert!(view.artifacts.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn list_is_newest_first_capped_and_formatted_in_milliseconds() {
    let env = Env::new().await;
    let host = env.host().await;
    let sender = env.sender().await;
    let mut records = Vec::new();
    for index in 0..55 {
        let record = env
            .event(host, &format!("run-{index:02}"), "dispatched")
            .await;
        shift_event(
            env.client(),
            record,
            "accepted_at",
            -100.0 + f64::from(index),
        )
        .await;
        records.push(record);
    }
    let listed = env.runs(host, MCP_LIST_MAX).await;
    let expected: Vec<String> = (5..55)
        .rev()
        .map(|index| format!("run-{index:02}"))
        .collect();
    let ids: Vec<String> = listed.iter().map(|view| view.run_id.clone()).collect();
    assert_eq!(ids, expected);
    let shape = |text: &str| {
        let bytes = text.as_bytes();
        bytes.len() == 24
            && bytes.iter().enumerate().all(|(index, byte)| match index {
                4 | 7 => *byte == b'-',
                10 => *byte == b'T',
                13 | 16 => *byte == b':',
                19 => *byte == b'.',
                23 => *byte == b'Z',
                _ => byte.is_ascii_digit(),
            })
    };
    assert!(listed.iter().all(|view| shape(&view.accepted_at)));
    // Equal acceptance times fall back to the record id, newest first.
    env.client().execute("UPDATE openmybot.channel_events SET accepted_at=(SELECT accepted_at FROM openmybot.channel_events WHERE record_id=$2) WHERE record_id=$1", &[&records[54], &records[53]]).await.unwrap();
    let top: Vec<String> = env
        .runs(host, 2)
        .await
        .into_iter()
        .map(|view| view.run_id)
        .collect();
    assert_eq!(top, ["run-54", "run-53"]);
    env.client().execute("UPDATE openmybot.channel_events SET accepted_at='2026-01-02 03:04:05.678912+00' WHERE record_id=$1", &[&records[0]]).await.unwrap();
    let fixed = env.run(host, "run-00").await.unwrap();
    assert_eq!(fixed.accepted_at, "2026-01-02T03:04:05.678Z");
    assert_eq!(env.runs(host, 3).await.len(), 3);
    assert!(env.runs(sender, MCP_LIST_MAX).await.is_empty());
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn single_and_list_reads_agree() {
    let env = Env::new().await;
    let host = env.host().await;
    let seeded = seed(&env, host).await;
    let listed = env.runs(host, MCP_LIST_MAX).await;
    assert_eq!(listed.len(), seeded.len());
    for (run, ..) in seeded {
        let single = env.run(host, run).await.unwrap();
        let from_list = listed.iter().find(|view| view.run_id == run).unwrap();
        assert_eq!(&single, from_list, "{run}");
    }
    env.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn every_deadline_taking_store_function_refuses_a_past_deadline() {
    let mut env = Env::new().await;
    let host = env.host().await;
    let past = Instant::now() - Duration::from_secs(1);
    let operation = OperationId::parse("op-1").unwrap();
    let message = HostMessage::parse("hello").unwrap();
    assert_eq!(
        accept_host_begin(
            &mut env.session.client,
            &operation,
            &message,
            "T-host",
            past
        )
        .await,
        Err(StoreError::EventFailed)
    );
    let events: i64 = env
        .client()
        .query_one("SELECT count(*) FROM openmybot.channel_events", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(events, 0);
    assert_eq!(
        host_binding_state(env.client(), past).await,
        Err(StoreError::BindingFailed)
    );
    assert_eq!(
        binding_run(env.client(), host, "r1", past).await,
        Err(StoreError::HostSessionFailed)
    );
    assert_eq!(
        binding_runs(env.client(), host, MCP_LIST_MAX, past).await,
        Err(StoreError::HostSessionFailed)
    );
    assert!(matches!(
        accept_host_begin(
            &mut env.session.client,
            &operation,
            &message,
            "T-host",
            deadline()
        )
        .await,
        Ok(HostAccept::Accepted(_))
    ));
    env.stop().await;
}
