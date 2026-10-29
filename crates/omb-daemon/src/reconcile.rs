//! Reconciliation of OpenMyBot rows: once at startup before the dispatcher runs, and the terminal
//! backfill with the cleaner every `sweep_interval`. Runs are never created here.
use omb_channels::{ChannelError, Connection, Task, Timings};
use omb_store::{
    EndReason, OpenRun, SessionEnd, StopRecord, StoreError, TerminalKind, clear_content,
    delete_expired, deny_undecided_permissions, end_session, list_orphan_sessions,
    mark_sending_unknown, record_terminal, unfinished_runs,
};
use openbot_application::ApplicationService;
use openbot_contracts::{
    command::{
        AppCommand, AppEvent, AppReply, SubscriptionRequest, ThreadForegroundRunState,
        ThreadRunEventKind,
    },
    error::AppError,
    ids::{RunId, ThreadId},
};
use openbot_server::SingleUserAuthResolver;
use rustix::process::{Pid, Signal};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{sync::Notify, time::Instant};
use tokio_postgres::Client;

/// Deadline of one reconciliation store call.
const STORE_BUDGET: Duration = Duration::from_secs(2);
/// How long the process-group leader lookup may take.
const PS_BUDGET: Duration = Duration::from_secs(5);
/// Interval of the process-group probe while a signal takes effect.
const PROBE: Duration = Duration::from_millis(20);
/// Bound of one replay of a thread's journal.
pub(crate) const REPLAY_DEADLINE: Duration = Duration::from_secs(10);

/// What reconciliation reads and signals besides the store.
#[derive(Clone)]
pub(crate) struct Reconciler {
    pub(crate) application: Arc<dyn ApplicationService>,
    pub(crate) resolver: SingleUserAuthResolver,
    /// The configured host binary; without one no process group is ever signalled.
    pub(crate) crabcode: Option<PathBuf>,
    pub(crate) term_grace: Duration,
    pub(crate) kill_grace: Duration,
    pub(crate) replay_deadline: Duration,
    /// The dispatcher's wake-up, signalled after a first terminal write.
    pub(crate) wake: Arc<Notify>,
}

fn deadline() -> Instant {
    Instant::now() + STORE_BUDGET
}

/// Startup: rows left `sending` end unknown, missed terminals are backfilled, orphan sessions are
/// ended, and every undecided permission is denied as `run_stopped`.
pub(crate) async fn startup(
    client: &mut Client,
    reconciler: &Reconciler,
) -> Result<(), StoreError> {
    mark_sending_unknown(client, deadline()).await?;
    backfill(client, reconciler).await?;
    for orphan in list_orphan_sessions(client, deadline()).await? {
        let (reason, stop) = match orphan.pgid.and_then(Pid::from_raw) {
            None => (EndReason::ChildExited, None),
            Some(group) => end_of_group(group, reconciler).await,
        };
        end_session(
            client,
            orphan.record_id,
            SessionEnd {
                reason,
                exit_code: None,
                exit_signal: None,
                stop,
                result_summary: None,
                artifact_paths: &[],
                stderr_tail: "",
            },
            deadline(),
        )
        .await?;
    }
    deny_undecided_permissions(client, deadline()).await?;
    Ok(())
}

/// Periodic: the terminal backfill, then the cleaner; sessions, permissions and processes are
/// left alone.
pub(crate) async fn sweep(
    client: &mut Client,
    reconciler: &Reconciler,
    timings: &Timings,
) -> Result<(), StoreError> {
    backfill(client, reconciler).await?;
    clear_content(client, timings.content_retention).await?;
    delete_expired(client, timings.tombstone_retention).await?;
    Ok(())
}

/// Sweeps every `sweep_interval`, the first time one interval after the start; a store failure
/// ends the task.
pub(crate) fn start_sweeper(
    connection: Connection,
    reconciler: Reconciler,
    timings: Timings,
) -> Task {
    Task::spawn(connection, move |mut client, mut stop| async move {
        loop {
            tokio::select! {
                _ = &mut stop => return Ok(()),
                () = tokio::time::sleep(timings.sweep_interval) => {}
            }
            tokio::select! {
                _ = &mut stop => return Ok(()),
                swept = sweep(&mut client, &reconciler, &timings) => {
                    swept.map_err(|_| ChannelError::StoreFailed)?;
                }
            }
        }
    })
}

/// Writes the terminal of each dispatched run the engine has finished; a run the engine still
/// runs, or whose terminal is not seen, waits for the next reconciliation.
async fn backfill(client: &mut Client, reconciler: &Reconciler) -> Result<(), StoreError> {
    for open in unfinished_runs(client, deadline()).await? {
        let Some(kind) = engine_terminal(reconciler, &open).await else {
            continue;
        };
        let written = record_terminal(client, &open.run_id, kind, deadline()).await?;
        if written.is_some_and(|terminal| terminal.written) {
            reconciler.wake.notify_one();
        }
    }
    Ok(())
}
/// The run's terminal from the thread's journal, replayed up to the conversation snapshot; an
/// unavailable conversation read replays without a bound.
async fn engine_terminal(reconciler: &Reconciler, open: &OpenRun) -> Option<TerminalKind> {
    let thread_id = ThreadId::new(&open.thread_id);
    let run_id = RunId::new(&open.run_id);
    let conversation = reconciler
        .application
        .execute(
            reconciler.resolver.local_context().ok()?,
            AppCommand::GetThreadConversation {
                thread_id: thread_id.clone(),
            },
        )
        .await;
    let last = match conversation {
        Ok(AppReply::ThreadConversation(snapshot)) => {
            if snapshot.active_run_id.as_ref() == Some(&run_id)
                && snapshot.active_run_state
                    != Some(ThreadForegroundRunState::ReconciliationRequired)
            {
                return None;
            }
            Some(snapshot.last_event_sequence?)
        }
        Err(AppError::DependencyUnavailable { .. }) => None,
        _ => return None,
    };
    let auth = reconciler.resolver.local_context().ok()?;
    tokio::time::timeout(reconciler.replay_deadline, async {
        let mut events = reconciler
            .application
            .subscribe(
                auth,
                SubscriptionRequest::ThreadEvents {
                    thread_id,
                    after_event_sequence: None,
                },
            )
            .await
            .ok()?;
        while let Some(event) = std::future::poll_fn(|cx| events.as_mut().poll_next(cx)).await {
            let AppEvent::ThreadRunEvent(event) = event else {
                continue;
            };
            if event.run_id == run_id && event.terminal {
                return terminal_of(event.event_type);
            }
            if last.is_some_and(|last| event.event_sequence >= last) {
                return None;
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}
fn terminal_of(kind: ThreadRunEventKind) -> Option<TerminalKind> {
    match kind {
        ThreadRunEventKind::Completed => Some(TerminalKind::Succeeded),
        ThreadRunEventKind::Failed => Some(TerminalKind::Failed),
        ThreadRunEventKind::Cancelled => Some(TerminalKind::Cancelled),
        ThreadRunEventKind::ReconciliationRequired => Some(TerminalKind::ReconciliationRequired),
        ThreadRunEventKind::Started
        | ThreadRunEventKind::SemanticChunk
        | ThreadRunEventKind::Checkpoint => None,
    }
}

/// The end of an orphan session whose row names `group`: a vanished group exited; a group led by
/// the configured host binary is terminated; any other group is left untouched.
async fn end_of_group(group: Pid, reconciler: &Reconciler) -> (EndReason, Option<StopRecord>) {
    if rustix::process::test_kill_process_group(group) == Err(rustix::io::Errno::SRCH) {
        let at = SystemTime::now().into();
        return (EndReason::ChildExited, Some(StopRecord::Confirmed { at }));
    }
    let leader = tokio::time::timeout(
        PS_BUDGET,
        tokio::process::Command::new("/bin/ps")
            .args(["-o", "comm=", "-p", &group.as_raw_nonzero().to_string()])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let output = match leader {
        Ok(Ok(output)) if output.status.success() => String::from_utf8(output.stdout).ok(),
        _ => None,
    };
    if !output.is_some_and(|text| leader_matches(&text, reconciler.crabcode.as_deref())) {
        return (EndReason::ChildExited, Some(StopRecord::Unknown));
    }
    let _ = rustix::process::kill_process_group(group, Signal::TERM);
    let mut gone = settled(group, reconciler.term_grace).await;
    if !gone {
        let _ = rustix::process::kill_process_group(group, Signal::KILL);
        gone = settled(group, reconciler.kill_grace).await;
    }
    let stop = if !reconciler.kill_grace.is_zero() && gone {
        StopRecord::Confirmed {
            at: SystemTime::now().into(),
        }
    } else {
        StopRecord::Unknown
    };
    (EndReason::StopRequested, Some(stop))
}
/// Whether the group is gone within `grace`; a zero grace does not probe.
async fn settled(group: Pid, grace: Duration) -> bool {
    let until = Instant::now() + grace;
    while Instant::now() < until {
        if rustix::process::test_kill_process_group(group) == Err(rustix::io::Errno::SRCH) {
            return true;
        }
        tokio::time::sleep(PROBE).await;
    }
    false
}
/// The first line of the `ps` output names the same file as the configured binary.
fn leader_matches(ps_output: &str, binary: Option<&Path>) -> bool {
    let (Some(binary), Some(leader)) = (binary, ps_output.lines().next()) else {
        return false;
    };
    match (std::fs::canonicalize(leader), std::fs::canonicalize(binary)) {
        (Ok(leader), Ok(binary)) => leader == binary,
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        agent::{
            AgentRuntime,
            tests::{self as agent, Run},
        },
        delegation::{BOT_ID, fixture::Fixture},
    };
    use omb_channels::{SenderContext, start_sender, testkit::FakeTelegram};
    use omb_hostdriver::HostDriverConfig;
    use omb_store::{Decided, Decision, testkit};
    use openbot_application::{
        BeginDelegatedThreadRun, DelegatedUntrustedMaterial, RunTerminalKind, RunTerminalNotice,
    };
    use openbot_contracts::{
        auth::DelegationSource,
        ids::{ActorId, BotId},
    };
    use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
    use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
    use serde_json::Value;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        sync::mpsc,
    };
    use uuid::Uuid;

    /// The Bot API token sealed into the test receiver; its prefix is the receiver's source key.
    pub(crate) const TOKEN: &str = "1001:omb007-outbound-token";

    pub(crate) fn happy(root: &Path) -> HostDriverConfig {
        agent::host(root, "happy", agent::quick(), &[])
    }
    /// A host whose fake asks one `Write` permission for `approved.txt` in the workspace.
    pub(crate) fn asking(root: &Path) -> HostDriverConfig {
        agent::host(
            root,
            "permission",
            agent::quick(),
            &[(
                "FAKE_CRABCODE_INPUT",
                r#"{"file_path":"approved.txt","content":"data"}"#,
            )],
        )
    }
    /// Delivery timings with a short idle poll; every other value is the production one.
    pub(crate) fn fast() -> Timings {
        Timings {
            delivery_poll: Duration::from_millis(50),
            ..Timings::default()
        }
    }
    /// The fixture engine's reconciler: no configured binary, short graces.
    pub(crate) fn reconciler(fixture: &Fixture) -> Reconciler {
        let engine = fixture.engine();
        Reconciler {
            application: engine.assembly.application.clone(),
            resolver: engine.resolver.clone(),
            crabcode: None,
            term_grace: Duration::from_millis(300),
            kill_grace: Duration::from_secs(2),
            replay_deadline: REPLAY_DEADLINE,
            wake: Arc::new(Notify::new()),
        }
    }
    pub(crate) async fn connection(fixture: &mut Fixture, name: &str) -> Connection {
        let opened = fixture.pg.open_resident_connection(name).await.unwrap();
        Connection {
            client: opened.client,
            driver: opened.driver,
        }
    }
    pub(crate) async fn mint(fixture: &Fixture) -> ThreadId {
        let engine = fixture.engine();
        let AppReply::ThreadMinted(minted) = engine
            .assembly
            .application
            .execute(
                engine.resolver.local_context().unwrap(),
                AppCommand::MintThreadId,
            )
            .await
            .unwrap()
        else {
            panic!("mint reply");
        };
        minted.thread_id
    }
    /// An active Telegram sender on receiver source `1001` and chat `telegram:42`, on the
    /// fixture's workspace, a freshly minted thread and the owner's current generation.
    pub(crate) async fn sender(fixture: &Fixture, client: &Client) -> (Uuid, ThreadId) {
        let thread = mint(fixture).await;
        let workspace = fixture.root.join("home/ws");
        std::fs::create_dir_all(&workspace).unwrap();
        let generation = i64::try_from(
            fixture
                .engine()
                .resolver
                .local_context()
                .unwrap()
                .auth_generation()
                .get(),
        )
        .unwrap();
        let binding = Uuid::now_v7();
        client.execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,sender_key,chat_key,workspace_dir,thread_id,granted_generation,revision,status,created_at,activated_at) VALUES ($1,'sender','telegram','1001','telegram:42','telegram:42',$2,$3,$4,1,'active',statement_timestamp(),statement_timestamp())", &[&binding, &workspace.to_str().unwrap(), &thread.as_str(), &generation]).await.unwrap();
        (binding, thread)
    }
    /// A dispatched accepted message of the binding, begun through the delegated entry.
    pub(crate) async fn begun(
        fixture: &Fixture,
        client: &Client,
        binding: Uuid,
        thread: &ThreadId,
    ) -> Run {
        let run = format!("run-{}", Uuid::now_v7());
        let record =
            testkit::insert_event_for_run(client, binding, &run, thread.as_str(), "dispatched")
                .await;
        testkit::shift_event(client, record, "dispatched_at", 0.0).await;
        fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap()
            .begin(BeginDelegatedThreadRun {
                source: DelegationSource::ExternalBinding {
                    binding_id: binding.to_string(),
                },
                revision: 1,
                trigger_id: record.to_string(),
                thread_id: thread.clone(),
                run_id: RunId::new(&run),
                bot_id: BotId::new(BOT_ID),
                untrusted_material: Some(DelegatedUntrustedMaterial {
                    source_ref: format!("omb:channel_events:{record}"),
                    text: "test message".into(),
                }),
            })
            .await
            .unwrap();
        Run {
            thread: thread.clone(),
            run: RunId::new(&run),
        }
    }
    /// An active Telegram receiver on source `1001` whose envelope seals [`TOKEN`].
    pub(crate) async fn sealed(fixture: &Fixture, client: &Client) -> Uuid {
        let binding_id = Uuid::now_v7();
        let envelope = fixture
            .engine()
            .vault
            .seal(
                &binding_id,
                SecretKind::Connector,
                SecretPrincipal::Actor(ActorId::new(SINGLE_USER_ACTOR_ID)),
                SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
                &SecretBytes::new(TOKEN.as_bytes().to_vec()),
            )
            .unwrap();
        testkit::insert_receiver_with(client, binding_id, "telegram", "1001", &envelope).await;
        binding_id
    }
    pub(crate) async fn event(client: &Client, run: &RunId) -> Value {
        client
            .query_one(
                "SELECT row_to_json(e) FROM openmybot.channel_events e WHERE run_id=$1",
                &[&run.as_str()],
            )
            .await
            .unwrap()
            .get(0)
    }
    /// The `run_result` rows of the run.
    pub(crate) async fn results(client: &Client, run: &RunId) -> Vec<Value> {
        client
            .query(
                "SELECT row_to_json(d) FROM openmybot.deliveries d WHERE idempotency_key=$1",
                &[&format!("result:{}", run.as_str())],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect()
    }
    /// The permission id the run's host asked for, once its row exists.
    pub(crate) async fn permission_of(client: &Client, run: &RunId) -> String {
        let limit = Instant::now() + Duration::from_secs(90);
        loop {
            let found = client.query("SELECT permission_id FROM openmybot.host_driver_sessions WHERE record_kind='permission' AND run_id=$1", &[&run.as_str()]).await.unwrap();
            if let Some(row) = found.first() {
                return row.get(0);
            }
            assert!(Instant::now() < limit, "permission request deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    /// The `sendMessage` bodies once `count` have arrived.
    pub(crate) async fn messages(fake: &FakeTelegram, count: usize) -> Vec<String> {
        let limit = Instant::now() + Duration::from_secs(90);
        loop {
            let sent = fake.sent_messages();
            if sent.len() >= count {
                return sent.into_iter().map(|sent| sent.text).collect();
            }
            assert!(Instant::now() < limit, "{count} messages deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    /// A sender binding with one finished `happy` run whose terminal notice was never
    /// consumed: the engine has its terminal, the event row has none.
    async fn finished(fixture: &mut Fixture, client: &Client) -> (Uuid, Run) {
        drop(fixture.take_terminals());
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let (binding, thread) = sender(fixture, client).await;
        let run = begun(fixture, client, binding, &thread).await;
        agent::settled(fixture, &thread).await;
        runtime.stop().await;
        assert!(event(client, &run.run).await["terminal_kind"].is_null());
        (binding, run)
    }
    fn orphan_reconciler(fixture: &Fixture, kill_grace: Duration) -> Reconciler {
        Reconciler {
            crabcode: Some(agent::fake()),
            kill_grace,
            ..reconciler(fixture)
        }
    }
    /// An unended session row of a host binding that names process group `pgid`.
    async fn orphan(client: &Client, pgid: Option<i32>) -> Uuid {
        let host = testkit::insert_host_binding(client, "/srv/project").await;
        testkit::insert_orphan_session(client, host, "run-orphan", pgid).await
    }
    async fn session_row(client: &Client, record: Uuid) -> Value {
        testkit::read_row(client, "host_driver_sessions", "record_id", record).await
    }
    /// The fake host in a process group of its own, past its first user frame, ignoring SIGTERM.
    async fn ignoring_term(
        report: &Path,
    ) -> (
        i32,
        tokio::process::ChildStdin,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        let mut command = std::process::Command::new(agent::fake());
        command
            .env("FAKE_CRABCODE_SCENARIO", "ignore_term")
            .env("FAKE_CRABCODE_REPORT", report)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = tokio::process::Command::from(command)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"{\"type\":\"user\"}\n").await.unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let init = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(init.contains("\"init\""), "{init}");
        let pgid = i32::try_from(child.id().unwrap()).unwrap();
        (pgid, stdin, tokio::spawn(async move { child.wait().await }))
    }
    /// A store snapshot of every product table, and the engine's run count.
    async fn snapshot(client: &Client) -> (String, i64) {
        let mut all = String::new();
        for table in [
            "channel_bindings",
            "channel_events",
            "host_driver_sessions",
            "deliveries",
            "control_tokens",
        ] {
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
        let runs = client
            .query_one("SELECT count(*) FROM runs", &[])
            .await
            .unwrap()
            .get(0);
        (all, runs)
    }
    async fn accepted(client: &Client) -> i64 {
        client
            .query_one(
                "SELECT count(*) FROM openmybot.channel_events WHERE disposition='accepted_message'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn body(client: &Client, delivery: Uuid) -> Value {
        testkit::read_row(client, "deliveries", "delivery_id", delivery).await["body"].clone()
    }
    async fn exists(client: &Client, delivery: Uuid) -> bool {
        client
            .query_one(
                "SELECT count(*) FROM openmybot.deliveries WHERE delivery_id=$1",
                &[&delivery],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
            == 1
    }
    /// A finished delivery of the binding whose `finished_at` lies `age` seconds back.
    async fn finished_delivery(client: &Client, binding: Uuid, key: &str, age: f64) -> Uuid {
        let id = testkit::insert_delivery(
            client,
            binding,
            "control_reply",
            key,
            Some("reply"),
            "sent",
            None,
        )
        .await;
        testkit::shift_column(client, "deliveries", "delivery_id", id, "finished_at", -age).await;
        id
    }
    /// Clears the run's terminal columns and its `run_result` row.
    async fn unrecorded(client: &Client, run: &RunId) {
        client.execute("UPDATE openmybot.channel_events SET terminal_kind=NULL,terminal_at=NULL WHERE run_id=$1", &[&run.as_str()]).await.unwrap();
        client
            .execute(
                "DELETE FROM openmybot.deliveries WHERE idempotency_key=$1",
                &[&format!("result:{}", run.as_str())],
            )
            .await
            .unwrap();
    }
    /// Waits until the run's single `run_result` row is sent and the fake has seen exactly one
    /// more message after a quiet period.
    async fn sent_once(client: &Client, fake: &FakeTelegram, run: &RunId, before: usize) {
        let limit = Instant::now() + Duration::from_secs(30);
        loop {
            let rows = results(client, run).await;
            if rows.len() == 1 && rows[0]["status"] == "sent" {
                break;
            }
            assert!(rows.len() <= 1, "{rows:?}");
            assert!(Instant::now() < limit, "result send deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(results(client, run).await.len(), 1);
        assert_eq!(fake.sent_messages().len(), before + 1);
    }
    /// Whether `wake` holds a stored permit.
    async fn woken(wake: &Notify) -> bool {
        tokio::time::timeout(Duration::from_millis(50), wake.notified())
            .await
            .is_ok()
    }
    fn notice(fixture: &Fixture, run: &Run) -> RunTerminalNotice {
        let local = fixture.engine().resolver.local_context().unwrap();
        RunTerminalNotice {
            deployment: local.deployment().clone(),
            tenant: local.tenant().clone(),
            thread_id: run.thread.clone(),
            run_id: run.run.clone(),
            terminal: RunTerminalKind::Succeeded,
        }
    }

    #[test]
    fn terminal_event_kinds_map_to_the_four_terminal_kinds() {
        assert_eq!(
            [
                ThreadRunEventKind::Completed,
                ThreadRunEventKind::Failed,
                ThreadRunEventKind::Cancelled,
                ThreadRunEventKind::ReconciliationRequired,
            ]
            .map(terminal_of),
            [
                Some(TerminalKind::Succeeded),
                Some(TerminalKind::Failed),
                Some(TerminalKind::Cancelled),
                Some(TerminalKind::ReconciliationRequired),
            ]
        );
        for kind in [
            ThreadRunEventKind::Started,
            ThreadRunEventKind::SemanticChunk,
            ThreadRunEventKind::Checkpoint,
        ] {
            assert_eq!(terminal_of(kind), None);
        }
    }

    #[test]
    fn leader_match_uses_canonical_paths_and_never_matches_without_a_binary() {
        let dir = crate::config::test_dir();
        let binary = dir.join("crabcode");
        let other = dir.join("other");
        let link = dir.join("link");
        std::fs::write(&binary, b"binary").unwrap();
        std::fs::write(&other, b"other").unwrap();
        std::os::unix::fs::symlink(&binary, &link).unwrap();
        let missing = dir.join("missing");
        // The first `ps` output line, newline included.
        fn line(path: &Path) -> String {
            format!("{}\n", path.display())
        }
        assert!(leader_matches(&line(&binary), Some(&binary)));
        assert!(leader_matches(&line(&link), Some(&binary)));
        assert!(leader_matches(&line(&binary), Some(&link)));
        assert!(!leader_matches(&line(&other), Some(&binary)));
        assert!(!leader_matches(&line(&missing), Some(&binary)));
        assert!(!leader_matches(&line(&binary), Some(&missing)));
        assert!(!leader_matches(&line(&binary), None));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_leaves_a_run_the_engine_still_runs_without_terminal() {
        let mut fixture = Fixture::start_with_host(asking).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let mut client = fixture.client().await;
        let (binding, thread) = sender(&fixture, &client).await;
        let run = begun(&fixture, &client, binding, &thread).await;
        permission_of(&client, &run.run).await;
        let engine = fixture.engine();
        let AppReply::ThreadConversation(snapshot) = engine
            .assembly
            .application
            .execute(
                engine.resolver.local_context().unwrap(),
                AppCommand::GetThreadConversation {
                    thread_id: thread.clone(),
                },
            )
            .await
            .unwrap()
        else {
            panic!("conversation reply");
        };
        assert_eq!(snapshot.active_run_id.as_ref(), Some(&run.run));
        assert_ne!(
            snapshot.active_run_state,
            Some(ThreadForegroundRunState::ReconciliationRequired)
        );
        startup(&mut client, &reconciler(&fixture)).await.unwrap();
        assert!(event(&client, &run.run).await["terminal_kind"].is_null());
        assert!(results(&client, &run.run).await.is_empty());
        // Startup denied the waiting permission, so the run ends on its own.
        agent::settled(&fixture, &thread).await;
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_leaves_runs_without_snapshot_sequence_or_with_unreadable_thread_for_next_time()
    {
        let mut fixture = Fixture::start_with_host(happy).await;
        let mut client = fixture.client().await;
        let (_, done) = finished(&mut fixture, &client).await;
        let host = testkit::insert_host_binding(&client, "/srv/project").await;
        let quiet = mint(&fixture).await;
        for (run, thread) in [
            ("run-quiet", quiet.as_str()),
            ("run-unreadable", "not-a-thread"),
        ] {
            let record =
                testkit::insert_event_for_run(&client, host, run, thread, "dispatched").await;
            testkit::shift_event(&client, record, "dispatched_at", -60.0).await;
        }
        startup(&mut client, &reconciler(&fixture)).await.unwrap();
        for run in ["run-quiet", "run-unreadable"] {
            assert!(event(&client, &RunId::new(run)).await["terminal_kind"].is_null());
        }
        assert_eq!(
            event(&client, &done.run).await["terminal_kind"],
            "succeeded"
        );
        assert_eq!(results(&client, &done.run).await.len(), 1);
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_orphan_without_pgid_ends_child_exited_with_no_stop_outcome() {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let record = orphan(&client, None).await;
        startup(
            &mut client,
            &orphan_reconciler(&fixture, Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let row = session_row(&client, record).await;
        assert!(row["ended_at"].is_string());
        assert_eq!(row["end_reason"], "child_exited");
        assert!(row["stop_outcome"].is_null());
        assert!(row["stop_confirmed_at"].is_null());
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_orphan_with_vanished_group_ends_child_exited_confirmed() {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let mut command = std::process::Command::new("/usr/bin/true");
        command.process_group(0);
        let mut child = tokio::process::Command::from(command).spawn().unwrap();
        let pgid = i32::try_from(child.id().unwrap()).unwrap();
        assert!(child.wait().await.unwrap().success());
        let record = orphan(&client, Some(pgid)).await;
        startup(
            &mut client,
            &orphan_reconciler(&fixture, Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let row = session_row(&client, record).await;
        assert!(row["ended_at"].is_string());
        assert_eq!(row["end_reason"], "child_exited");
        assert_eq!(row["stop_outcome"], "confirmed");
        assert!(row["stop_confirmed_at"].is_string());
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_orphan_with_live_crabcode_group_is_terminated_and_ends_stop_requested_confirmed()
     {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let report = fixture.root.join("orphan.jsonl");
        let (pgid, stdin, waiter) = ignoring_term(&report).await;
        let record = orphan(&client, Some(pgid)).await;
        startup(
            &mut client,
            &orphan_reconciler(&fixture, Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let row = session_row(&client, record).await;
        assert_eq!(row["end_reason"], "stop_requested");
        assert_eq!(row["stop_outcome"], "confirmed");
        assert!(row["stop_confirmed_at"].is_string());
        let status = waiter.await.unwrap().unwrap();
        assert_eq!(status.signal(), Some(9));
        // SIGTERM arrived first and was ignored.
        assert!(
            std::fs::read_to_string(&report)
                .unwrap()
                .contains(r#""signal":15"#)
        );
        drop(stdin);
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_orphan_with_zero_kill_grace_ends_stop_requested_unknown() {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let report = fixture.root.join("orphan.jsonl");
        let (pgid, stdin, waiter) = ignoring_term(&report).await;
        let record = orphan(&client, Some(pgid)).await;
        startup(&mut client, &orphan_reconciler(&fixture, Duration::ZERO))
            .await
            .unwrap();
        let row = session_row(&client, record).await;
        assert_eq!(row["end_reason"], "stop_requested");
        assert_eq!(row["stop_outcome"], "unknown");
        assert!(row["stop_confirmed_at"].is_null());
        let status = tokio::time::timeout(Duration::from_secs(10), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(status.signal(), Some(9));
        drop(stdin);
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_orphan_with_foreign_leader_is_not_signalled_and_ends_child_exited_unknown() {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let mut command = std::process::Command::new("/bin/sleep");
        command
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = tokio::process::Command::from(command)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pgid = i32::try_from(child.id().unwrap()).unwrap();
        let record = orphan(&client, Some(pgid)).await;
        startup(
            &mut client,
            &orphan_reconciler(&fixture, Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let row = session_row(&client, record).await;
        assert_eq!(row["end_reason"], "child_exited");
        assert_eq!(row["stop_outcome"], "unknown");
        assert!(row["stop_confirmed_at"].is_null());
        assert!(child.try_wait().unwrap().is_none());
        child.kill().await.unwrap();
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_orphan_without_configured_binary_is_not_signalled_and_ends_child_exited_unknown()
     {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let report = fixture.root.join("orphan.jsonl");
        let (pgid, stdin, waiter) = ignoring_term(&report).await;
        let record = orphan(&client, Some(pgid)).await;
        // The leader is the fake itself, but no binary is configured.
        startup(&mut client, &reconciler(&fixture)).await.unwrap();
        let row = session_row(&client, record).await;
        assert_eq!(row["end_reason"], "child_exited");
        assert_eq!(row["stop_outcome"], "unknown");
        assert!(!waiter.is_finished());
        assert!(
            !std::fs::read_to_string(&report)
                .unwrap()
                .contains(r#""signal""#)
        );
        // Dropping the child kills it.
        waiter.abort();
        let _ = waiter.await;
        drop(stdin);
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_denies_undecided_permissions_and_their_notices_stay_pending() {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let binding =
            testkit::insert_sender(&client, "telegram", "1001", "telegram:42", "T1").await;
        testkit::insert_permission_row(&client, binding, "run-1", "p-open", 600.0).await;
        testkit::insert_permission_row(&client, binding, "run-1", "p-late", -5.0).await;
        testkit::insert_permission_row(&client, binding, "run-1", "p-allowed", 600.0).await;
        assert_eq!(
            testkit::decide(&client, "p-allowed", Decision::Allow).await,
            Decided::Decided
        );
        let allowed = testkit::permission_row_json(&client, "p-allowed").await;
        let notice = testkit::insert_delivery(
            &client,
            binding,
            "permission_notice",
            "perm:p-open",
            Some("approve p-open"),
            "pending",
            None,
        )
        .await;
        let before = testkit::read_row(&client, "deliveries", "delivery_id", notice).await;
        startup(&mut client, &reconciler(&fixture)).await.unwrap();
        for id in ["p-open", "p-late"] {
            let row = testkit::permission_row_json(&client, id).await;
            assert_eq!(row["decision"], "deny");
            assert_eq!(row["decided_via"], "run_stopped");
            assert!(row["decided_at"].is_string());
            assert!(row["decided_by_token"].is_null());
            assert!(row["answered_at"].is_null());
        }
        assert_eq!(
            testkit::permission_row_json(&client, "p-allowed").await,
            allowed
        );
        let after = testkit::read_row(&client, "deliveries", "delivery_id", notice).await;
        assert_eq!(after["status"], "pending");
        assert_eq!(after, before);
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_twice_changes_nothing_and_creates_no_run() {
        let mut fixture = Fixture::start_with_host(happy).await;
        let mut client = fixture.client().await;
        let (binding, run) = finished(&mut fixture, &client).await;
        testkit::insert_delivery(
            &client,
            binding,
            "control_reply",
            "control_reply:1",
            Some("reply"),
            "sending",
            None,
        )
        .await;
        orphan(&client, None).await;
        testkit::insert_permission_row(&client, binding, "run-1", "p-open", 600.0).await;
        let (_, runs) = snapshot(&client).await;
        let messages = accepted(&client).await;
        let reconciler = reconciler(&fixture);
        startup(&mut client, &reconciler).await.unwrap();
        assert_eq!(event(&client, &run.run).await["terminal_kind"], "succeeded");
        let first = snapshot(&client).await;
        startup(&mut client, &reconciler).await.unwrap();
        assert_eq!(snapshot(&client).await, first);
        assert_eq!(first.1, runs);
        assert_eq!(accepted(&client).await, messages);
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn sweep_backfills_terminal_for_dispatched_events() {
        let mut fixture = Fixture::start_with_host(happy).await;
        let mut client = fixture.client().await;
        let (_, run) = finished(&mut fixture, &client).await;
        let reconciler = reconciler(&fixture);
        sweep(&mut client, &reconciler, &Timings::default())
            .await
            .unwrap();
        let first = event(&client, &run.run).await;
        assert_eq!(first["terminal_kind"], "succeeded");
        let rows = results(&client, &run.run).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["status"], "pending");
        assert!(woken(&reconciler.wake).await);
        sweep(&mut client, &reconciler, &Timings::default())
            .await
            .unwrap();
        assert_eq!(event(&client, &run.run).await, first);
        assert_eq!(results(&client, &run.run).await, rows);
        assert!(!woken(&reconciler.wake).await);
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn sweep_leaves_live_session_process_and_undecided_permission_alone() {
        let mut fixture = Fixture::start_with_host(asking).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let mut client = fixture.client().await;
        let (run, _) = agent::begin(&mut fixture).await;
        let id = permission_of(&client, &run.run).await;
        let session = agent::session(&client, &run.run).await;
        let permission = testkit::permission_row_json(&client, &id).await;
        sweep(&mut client, &reconciler(&fixture), &Timings::default())
            .await
            .unwrap();
        assert_eq!(agent::session(&client, &run.run).await, session);
        assert_eq!(testkit::permission_row_json(&client, &id).await, permission);
        assert!(session["ended_at"].is_null());
        assert!(permission["decision"].is_null());
        assert!(!agent::group_gone(&session));
        assert_eq!(
            testkit::decide(&client, &id, Decision::Deny).await,
            Decided::Decided
        );
        agent::settled(&fixture, &run.thread).await;
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn sweep_applies_the_cleaner_with_the_timings_retention() {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let binding =
            testkit::insert_sender(&client, "telegram", "1001", "telegram:42", "T1").await;
        let cleared = finished_delivery(&client, binding, "control_reply:1", 10.0).await;
        let deleted = finished_delivery(&client, binding, "control_reply:2", 30.0).await;
        let young = finished_delivery(&client, binding, "control_reply:3", 0.0).await;
        let timings = Timings {
            content_retention: Duration::from_secs(5),
            tombstone_retention: Duration::from_secs(20),
            ..Timings::default()
        };
        sweep(&mut client, &reconciler(&fixture), &timings)
            .await
            .unwrap();
        assert!(body(&client, cleared).await.is_null());
        assert!(
            testkit::read_row(&client, "deliveries", "delivery_id", cleared).await
                ["content_cleared_at"]
                .is_string()
        );
        assert!(!exists(&client, deleted).await);
        assert_eq!(body(&client, young).await, "reply");
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn sweeper_task_runs_each_sweep_interval() {
        let mut fixture = Fixture::start().await;
        let client = fixture.client().await;
        let binding =
            testkit::insert_sender(&client, "telegram", "1001", "telegram:42", "T1").await;
        let early = finished_delivery(&client, binding, "control_reply:1", 10.0).await;
        let timings = Timings {
            sweep_interval: Duration::from_millis(150),
            content_retention: Duration::from_secs(5),
            ..Timings::default()
        };
        let task = start_sweeper(
            connection(&mut fixture, "openmybot-sweeper").await,
            reconciler(&fixture),
            timings,
        );
        // No sweep at start: the first one comes one interval later.
        assert_eq!(body(&client, early).await, "reply");
        let limit = Instant::now() + Duration::from_secs(10);
        while !body(&client, early).await.is_null() {
            assert!(Instant::now() < limit, "first sweep deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let late = finished_delivery(&client, binding, "control_reply:2", 10.0).await;
        let limit = Instant::now() + Duration::from_secs(10);
        while !body(&client, late).await.is_null() {
            assert!(Instant::now() < limit, "later sweep deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        task.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn sweeper_task_ends_with_store_failed_on_a_store_error() {
        let mut fixture = Fixture::start().await;
        let client = fixture.client().await;
        let binding =
            testkit::insert_sender(&client, "telegram", "1001", "telegram:42", "T1").await;
        // A dispatched run on a thread the engine cannot read is skipped each sweep.
        testkit::insert_event_for_run(&client, binding, "run-unreadable", "T1", "dispatched").await;
        let timings = Timings {
            sweep_interval: Duration::from_millis(100),
            tombstone_retention: Duration::from_secs(20),
            ..Timings::default()
        };
        let mut task = start_sweeper(
            connection(&mut fixture, "openmybot-sweeper").await,
            reconciler(&fixture),
            timings,
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(600), task.finished())
                .await
                .is_err()
        );
        client.batch_execute("CREATE FUNCTION openmybot.fail_row() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test failure'; END$$; CREATE TRIGGER fail_delete BEFORE DELETE ON openmybot.channel_events FOR EACH ROW EXECUTE FUNCTION openmybot.fail_row()").await.unwrap();
        let old =
            testkit::insert_event_for_run(&client, binding, "run-old", "T1", "conflict").await;
        testkit::shift_event(&client, old, "accepted_at", -60.0).await;
        let ended = tokio::time::timeout(Duration::from_secs(10), task.finished())
            .await
            .unwrap();
        assert_eq!(ended, Err(ChannelError::StoreFailed));
        task.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn race_terminal_write_and_sweep_write_once_per_round() {
        let mut fixture = Fixture::start_with_host(happy).await;
        let mut client = fixture.client().await;
        let (_, run) = finished(&mut fixture, &client).await;
        sealed(&fixture, &client).await;
        let fake = FakeTelegram::start().await;
        let (queue, terminals) = mpsc::channel(8);
        let sent = Arc::new(Notify::new());
        let sender = start_sender(
            connection(&mut fixture, "openmybot-delivery").await,
            SenderContext {
                vault: fixture.engine().vault.clone(),
                owner: ActorId::new(SINGLE_USER_ACTOR_ID),
                endpoint: fake.endpoint(),
                timings: fast(),
                wake: Arc::clone(&sent),
            },
            terminals,
        );
        let reconciler = reconciler(&fixture);
        let notice = notice(&fixture, &run);
        let timings = Timings::default();
        for round in 0..10 {
            unrecorded(&client, &run.run).await;
            let before = fake.sent_messages().len();
            let (queued, swept) = tokio::join!(
                queue.send(notice.clone()),
                sweep(&mut client, &reconciler, &timings)
            );
            queued.unwrap();
            swept.unwrap();
            sent_once(&client, &fake, &run.run, before).await;
            assert_eq!(event(&client, &run.run).await["terminal_kind"], "succeeded");
            let by_sender = woken(&sent).await;
            let by_sweep = woken(&reconciler.wake).await;
            assert!(by_sender != by_sweep, "round {round}");
        }
        sender.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn race_notice_and_sweep_duplicates_insert_one_row_and_send_one_message() {
        let mut fixture = Fixture::start_with_host(happy).await;
        let mut client = fixture.client().await;
        let (_, run) = finished(&mut fixture, &client).await;
        sealed(&fixture, &client).await;
        let fake = FakeTelegram::start().await;
        let (queue, terminals) = mpsc::channel(8);
        let sender = start_sender(
            connection(&mut fixture, "openmybot-delivery").await,
            SenderContext {
                vault: fixture.engine().vault.clone(),
                owner: ActorId::new(SINGLE_USER_ACTOR_ID),
                endpoint: fake.endpoint(),
                timings: fast(),
                wake: Arc::new(Notify::new()),
            },
            terminals,
        );
        let reconciler = reconciler(&fixture);
        let notice = notice(&fixture, &run);
        let timings = Timings::default();
        for _ in 0..10 {
            unrecorded(&client, &run.run).await;
            let before = fake.sent_messages().len();
            queue.send(notice.clone()).await.unwrap();
            sweep(&mut client, &reconciler, &timings).await.unwrap();
            sent_once(&client, &fake, &run.run, before).await;
            unrecorded(&client, &run.run).await;
            let before = fake.sent_messages().len();
            sweep(&mut client, &reconciler, &timings).await.unwrap();
            queue.send(notice.clone()).await.unwrap();
            sent_once(&client, &fake, &run.run, before).await;
        }
        sender.stop().await;
        drop(client);
        fixture.stop().await;
    }
}
