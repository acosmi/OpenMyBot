//! Real durable writers and process-local terminal wakeups on an owned database.
mod harness {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}
#[path = "support/delegated_assembly_fixture.rs"]
pub mod fixture;

use fixture::{CommitAckProxy, Fixture, Options, text};
use harness::{admin_config, with_temp_database};
use openbot_application::*;
use openbot_contracts::command::{AppCommand, CancelThreadRun};
use openbot_contracts::ids::RunId;
use openbot_infra::db::pool::{self, DatabaseConfig};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Gate {
    calls: AtomicUsize,
    open: Mutex<bool>,
    ready: Condvar,
    panic_first: bool,
}
impl Gate {
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.ready.notify_all();
    }
}
struct GateReleaseGuard(Arc<Gate>);
impl Drop for GateReleaseGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}
impl RunTerminalSubscriber for Gate {
    fn on_run_terminal(&self, _: RunTerminalNotice) {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.panic_first && n == 0 {
            panic!("controlled subscriber failure");
        }
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.ready.wait(open).unwrap();
        }
    }
}

type DurableObservation = Result<(RunTerminalNotice, String, i64), String>;
struct DurableObserver {
    config: DatabaseConfig,
    observations: Mutex<Vec<DurableObservation>>,
}
impl RunTerminalSubscriber for DurableObserver {
    fn on_run_terminal(&self, notice: RunTerminalNotice) {
        // This worker's independent connection cannot see an uncommitted terminal.
        let result: DurableObservation = (|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(text)?;
            rt.block_on(async {
                let pool = pool::connect(&self.config).await.map_err(text)?;
                let result = async {
                    let c = pool.get().await.map_err(text)?;
                    let row = c.query_one(
                        "SELECT r.status,(SELECT count(*) FROM public.run_events e WHERE e.run_id=r.run_id AND e.seq=r.terminal_event_seq) FROM public.runs r WHERE r.run_id=$1",
                        &[&notice.run_id.as_str()],
                    ).await.map_err(text)?;
                    Ok((notice, row.get(0), row.get(1)))
                }.await;
                pool.close();
                result
            })
        })();
        self.observations.lock().unwrap().push(result);
    }
}
async fn wait_calls(counter: &AtomicUsize, count: usize) -> Result<(), String> {
    tokio::time::timeout(WAIT, async {
        while counter.load(Ordering::SeqCst) < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(text)
}
async fn wait_notices(f: &Fixture, count: usize) -> Result<(), String> {
    tokio::time::timeout(WAIT, async {
        while f.notices.0.lock().unwrap().len() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(text)
}
async fn close(f: Fixture) {
    f.assembly.shutdown().await;
    f.pool.close();
}
async fn begin(f: &Fixture, id: &str) -> Result<BeginDelegatedThreadRun, String> {
    let request = f.request(id).await?;
    f.assembly
        .delegated_entry
        .as_ref()
        .ok_or("missing delegated entry")?
        .begin(request.clone())
        .await
        .map_err(text)?;
    Ok(request)
}
async fn lease(f: &Fixture, id: &str) -> Result<RunExecutionLease, String> {
    let claim = f
        .assembly
        .run_runtime
        .claim_dispatch()
        .await
        .map_err(text)?
        .ok_or("missing dispatch")?;
    assert_eq!(claim.lease().run_id().as_str(), id);
    f.assembly
        .run_runtime
        .acknowledge_dispatch(&claim)
        .await
        .map_err(text)
}
async fn status(f: &Fixture, id: &str) -> Result<(String, i64), String> {
    let c = f.pool.get().await.map_err(text)?;
    let row = c.query_one("SELECT status,(SELECT count(*) FROM public.run_events e WHERE e.run_id=r.run_id AND e.seq=r.terminal_event_seq) FROM public.runs r WHERE run_id=$1", &[&id]).await.map_err(text)?;
    Ok((row.get(0), row.get(1)))
}
async fn finish(f: &Fixture, id: &str) -> Result<(), String> {
    begin(f, id).await?;
    let l = lease(f, id).await?;
    f.assembly
        .run_runtime
        .finish_run(&l, l.next_event_sequence(), RunTerminal::Completed)
        .await
        .map_err(text)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn all_four_terminal_writers_notify_after_durable_commit() {
    with_temp_database(&admin_config("terminal_four"), "terminalfour", |config| async move {
        let observer = Arc::new(DurableObserver { config: config.clone(), observations: Mutex::new(Vec::new()) });
        let f = Fixture::with_options(&config, Options { subscriber: Some(observer.clone()), ..Options::default() }).await?;
        let result: Result<(), String> = async {
            finish(&f, "finish").await?;
            let cancelled = begin(&f, "unstarted").await?;
            f.assembly.application.execute(f.auth.clone(), AppCommand::CancelThreadRun(CancelThreadRun { thread_id: cancelled.thread_id, run_id: cancelled.run_id })).await.map_err(text)?;
            let claim = f.assembly.run_runtime.claim_cancellation().await.map_err(text)?.ok_or("missing cancellation")?;
            f.assembly.run_runtime.finish_unstarted_cancellation(&claim).await.map_err(text)?;
            begin(&f, "rejected").await?;
            let claim = f.assembly.run_runtime.claim_dispatch().await.map_err(text)?.ok_or("missing rejected dispatch")?;
            assert_eq!(claim.lease().run_id().as_str(), "rejected");
            f.assembly.run_runtime.reject_dispatch(&claim, RunFailureCode::AgentRuntimeUnavailable).await.map_err(text)?;
            let stale = begin(&f, "recovered").await?;
            lease(&f, "recovered").await?;
            let c = f.pool.get().await.map_err(text)?;
            c.execute("UPDATE public.thread_leases SET acquired_at=clock_timestamp()-interval '10 seconds',expires_at=clock_timestamp()-interval '1 second',updated_at=clock_timestamp() WHERE thread_id=$1", &[&stale.thread_id.as_str()]).await.map_err(text)?;
            drop(c);
            assert!(f.assembly.run_runtime.recover_one_stale_run().await.map_err(text)?.is_some());
            tokio::time::timeout(WAIT, async {
                while observer.observations.lock().unwrap().len() < 4 { tokio::time::sleep(Duration::from_millis(5)).await; }
            }).await.map_err(text)?;
            let observed = observer.observations.lock().unwrap();
            for (id, kind, db_status) in [
                ("finish", RunTerminalKind::Succeeded, "completed"),
                ("unstarted", RunTerminalKind::Cancelled, "cancelled"),
                ("rejected", RunTerminalKind::Failed, "failed"),
                ("recovered", RunTerminalKind::ReconciliationRequired, "reconciliation_required"),
            ] {
                let (notice, status, terminal_events) = observed.iter().filter_map(|r| r.as_ref().ok()).find(|(n,_,_)| n.run_id.as_str()==id).ok_or_else(|| format!("missing durable observation {id}: {observed:?}"))?;
                assert_eq!(notice.terminal, kind);
                assert_eq!(notice.deployment, *f.auth.deployment());
                assert_eq!(notice.tenant, *f.auth.tenant());
                assert_eq!(status, db_status);
                assert_eq!(*terminal_events, 1);
            }
            assert_eq!(observed.len(), 4);
            assert!(observed.iter().all(Result::is_ok));
            Ok(())
        }.await;
        f.assembly.shutdown().await; f.pool.close(); result
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn terminal_replay_and_unknown_commit_never_duplicate_notice() {
    with_temp_database(
        &admin_config("terminal_replay"),
        "terminalreplay",
        |config| async move {
            let f = Fixture::new(&config).await?;
            let result: Result<(), String> = async {
                for round in 0..10 {
                    let id = format!("replay-{round}");
                    begin(&f, &id).await?;
                    let l = lease(&f, &id).await?;
                    let first = f
                        .assembly
                        .run_runtime
                        .finish_run(&l, l.next_event_sequence(), RunTerminal::Completed)
                        .await
                        .map_err(text)?;
                    assert!(!first.replayed);
                    let replay = f
                        .assembly
                        .run_runtime
                        .finish_run(&l, l.next_event_sequence(), RunTerminal::Completed)
                        .await
                        .map_err(text)?;
                    assert!(replay.replayed);
                    wait_notices(&f, round + 1).await?;
                    assert_eq!(status(&f, &id).await?, ("completed".into(), 1));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert_eq!(f.notices.0.lock().unwrap().len(), 10);
                Ok(())
            }
            .await;
            close(f).await;
            result?;
            let proxy = CommitAckProxy::start(&config).await?;
            let unknown = Fixture::reopen(&proxy.config).await?;
            begin(&unknown, "lost-terminal-ack").await?;
            let l = lease(&unknown, "lost-terminal-ack").await?;
            proxy.drop_next_commit_ack();
            assert_eq!(
                unknown
                    .assembly
                    .run_runtime
                    .finish_run(&l, l.next_event_sequence(), RunTerminal::Completed)
                    .await,
                Err(RunRuntimeError::CommitUnknown)
            );
            assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
            let control = pool::connect(&config).await.map_err(text)?;
            let c = control.get().await.map_err(text)?;
            let row = c
                .query_one(
                    "SELECT status FROM public.runs WHERE run_id='lost-terminal-ack'",
                    &[],
                )
                .await
                .map_err(text)?;
            assert_eq!(row.get::<_, String>(0), "completed");
            drop(c);
            control.close();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                unknown.notices.0.lock().unwrap().is_empty(),
                "unacknowledged commit cannot publish a notice"
            );
            let replay = unknown
                .assembly
                .run_runtime
                .finish_run(&l, l.next_event_sequence(), RunTerminal::Completed)
                .await
                .map_err(text)?;
            assert!(replay.replayed);
            assert!(unknown.notices.0.lock().unwrap().is_empty());
            close(unknown).await;
            proxy.stop().await?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn slow_and_panicking_subscriber_cannot_delay_terminal_or_readers() {
    with_temp_database(
        &admin_config("terminal_slow"),
        "terminalslow",
        |config| async move {
            let gate = Arc::new(Gate {
                panic_first: true,
                ..Gate::default()
            });
            let f = Fixture::with_options(
                &config,
                Options {
                    subscriber: Some(gate.clone()),
                    ..Options::default()
                },
            )
            .await?;
            let gate_release = GateReleaseGuard(gate.clone());
            let result: Result<(), String> = async {
                finish(&f, "panic").await?;
                wait_calls(&gate.calls, 1).await?;
                finish(&f, "blocked").await?;
                wait_calls(&gate.calls, 2).await?;
                // Overflow the real bounded worker queue while its consumer is gated.
                let mut remaining = Duration::from_secs(30);
                let mut terminal_elapsed = Duration::ZERO;
                let mut completed = 0;
                for n in 0..140 {
                    let diagnostic = |phase: &str, elapsed: Duration, left: Duration, done| {
                        format!(
                            "phase={phase} index={n} completed={done} terminal_elapsed_ms={} remaining_ms={}",
                            elapsed.as_millis(),
                            left.as_millis()
                        )
                    };
                    let id = format!("queue-{n}");
                    begin(&f, &id).await.map_err(|error| {
                        format!("{} cause={error}", diagnostic("begin", terminal_elapsed, remaining, completed))
                    })?;
                    let l = lease(&f, &id).await.map_err(|error| {
                        format!("{} cause={error}", diagnostic("claim_ack", terminal_elapsed, remaining, completed))
                    })?;
                    if remaining.is_zero() {
                        return Err(diagnostic(
                            "finish_budget_exhausted",
                            terminal_elapsed,
                            remaining,
                            completed,
                        ));
                    }
                    let allotted = remaining;
                    let started = Instant::now();
                    let terminal = tokio::time::timeout(
                        remaining,
                        f.assembly.run_runtime.finish_run(
                            &l,
                            l.next_event_sequence(),
                            RunTerminal::Completed,
                        ),
                    )
                    .await;
                    let spent = started.elapsed();
                    terminal_elapsed += spent;
                    remaining = remaining.saturating_sub(spent);
                    let receipt = terminal.map_err(|error| {
                        format!("{} cause={error}", diagnostic("finish_timeout", terminal_elapsed, remaining, completed))
                    })?
                    .map_err(|error| {
                        format!("{} cause={error}", diagnostic("finish_error", terminal_elapsed, remaining, completed))
                    })?;
                    if spent > allotted {
                        return Err(diagnostic(
                            "finish_budget_exceeded",
                            terminal_elapsed,
                            remaining,
                            completed,
                        ));
                    }
                    if receipt.replayed {
                        return Err(diagnostic(
                            "finish_replayed",
                            terminal_elapsed,
                            remaining,
                            completed,
                        ));
                    }
                    completed += 1;
                }
                assert_eq!(completed, 140);
                for n in 0..140 {
                    let id = format!("queue-{n}");
                    if status(&f, &id).await.map_err(|error| {
                        format!("phase=durable_read index={n} completed={completed} terminal_elapsed_ms={} remaining_ms={} cause={error}", terminal_elapsed.as_millis(), remaining.as_millis())
                    })? != ("completed".into(), 1) {
                        return Err(format!("phase=durable_check index={n} completed={completed} terminal_elapsed_ms={} remaining_ms={}", terminal_elapsed.as_millis(), remaining.as_millis()));
                    }
                }
                assert_eq!(gate.calls.load(Ordering::SeqCst), 2);
                assert_eq!(status(&f, "queue-139").await?, ("completed".into(), 1));
                let reply = tokio::time::timeout(
                    Duration::from_secs(2),
                    f.assembly
                        .application
                        .execute(f.auth.clone(), AppCommand::GetCurrentUser),
                )
                .await
                .map_err(text)?
                .map_err(text)?;
                assert!(matches!(
                    reply,
                    openbot_contracts::command::AppReply::CurrentUser(_)
                ));
                assert_eq!(gate.calls.load(Ordering::SeqCst), 2);
                Ok(())
            }
            .await;
            gate.release();
            f.assembly.shutdown().await;
            assert!(gate.calls.load(Ordering::SeqCst) <= 130);
            f.pool.close();
            drop(gate_release);
            result
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn subscriber_shutdown_and_restart_do_not_replay_or_leak() {
    with_temp_database(
        &admin_config("terminal_shutdown"),
        "terminalshutdown",
        |config| async move {
            let f = Fixture::new(&config).await?;
            finish(&f, "old-terminal").await?;
            wait_notices(&f, 1).await?;
            let weak_runtime = Arc::downgrade(&f.assembly.run_runtime);
            let weak_subscriber = Arc::downgrade(&f.notices);
            close(f).await;
            assert!(
                weak_runtime.upgrade().is_none(),
                "callback binding must not retain runtime"
            );
            assert!(
                weak_subscriber.upgrade().is_none(),
                "terminal worker must release subscriber"
            );
            let restarted = Fixture::reopen(&config).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(restarted.notices.0.lock().unwrap().is_empty());
            finish(&restarted, "new-terminal").await?;
            wait_notices(&restarted, 1).await?;
            assert_eq!(
                restarted.notices.0.lock().unwrap()[0].run_id,
                RunId::new("new-terminal")
            );
            restarted.assembly.shutdown().await;
            restarted.pool.close();
            let none = Fixture::reopen_with_options(
                &config,
                Options {
                    subscribe: false,
                    ..Options::default()
                },
            )
            .await?;
            let weak_none = Arc::downgrade(&none.notices);
            finish(&none, "without-subscriber").await?;
            assert!(none.notices.0.lock().unwrap().is_empty());
            close(none).await;
            assert!(weak_none.upgrade().is_none());
            let gate = Arc::new(Gate::default());
            let gated = Fixture::reopen_with_options(
                &config,
                Options {
                    subscriber: Some(gate.clone()),
                    ..Options::default()
                },
            )
            .await?;
            let gate_release = GateReleaseGuard(gate.clone());
            finish(&gated, "gated-stop").await?;
            wait_calls(&gate.calls, 1).await?;
            gate.release();
            tokio::time::timeout(Duration::from_secs(2), close(gated))
                .await
                .map_err(text)?;
            drop(gate_release);
            assert_eq!(Arc::strong_count(&gate), 1);
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn terminal_race_emits_at_most_one_wakeup() {
    with_temp_database(
        &admin_config("terminal_race"),
        "terminalrace",
        |config| async move {
            let f = Fixture::new(&config).await?;
            let result: Result<(), String> = async {
                for round in 0..10 {
                    let id = format!("race-{round}");
                    begin(&f, &id).await?;
                    let l = lease(&f, &id).await?;
                    let runtime = &f.assembly.run_runtime;
                    let (a, b) = tokio::join!(
                        runtime.finish_run(&l, l.next_event_sequence(), RunTerminal::Completed),
                        runtime.finish_run(
                            &l,
                            l.next_event_sequence(),
                            RunTerminal::Failed(RunFailureCode::ProviderUnavailable)
                        )
                    );
                    assert_eq!(
                        usize::from(a.is_ok()) + usize::from(b.is_ok()),
                        1,
                        "{a:?}/{b:?}"
                    );
                    assert!(
                        a == Err(RunRuntimeError::Conflict) || b == Err(RunRuntimeError::Conflict)
                    );
                    wait_notices(&f, round + 1).await?;
                    assert_eq!(status(&f, &id).await?.1, 1);
                    let ns = f.notices.0.lock().unwrap();
                    assert_eq!(ns.iter().filter(|n| n.run_id.as_str() == id).count(), 1);
                }
                Ok(())
            }
            .await;
            f.assembly.shutdown().await;
            f.pool.close();
            result
        },
    )
    .await;
}
