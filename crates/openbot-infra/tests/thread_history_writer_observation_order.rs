//! PostgreSQL 17 evidence that writer transactions observe the current schema before
//! their first row lock. A real ACCESS EXCLUSIVE holder on the migration ledger stops
//! the observation; while the writer waits there, independent NOWAIT probes must
//! acquire the very Run/Thread/lease/channel rows and per-thread advisory lock the
//! writer uses afterwards. A built-in control proves the probe refuses real holders.
#![cfg(feature = "server-runtime")]

mod harness;

use std::future::Future;
use std::time::{Duration, Instant};

use harness::{admin_config, with_temp_database};
use openbot_application::{
    BeginThreadRunRequest, RunRuntime, RunSemanticChannel, RunTerminal, ThreadDirectory,
};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_infra::db::pool::{self, DatabasePool};
use openbot_infra::db::{baseline, native};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

const WAIT_BUDGET: Duration = Duration::from_secs(10);
const CHANNEL: &str = "channel-main";

async fn provision(pool: &DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.channels(
               id,name,description,last_message,last_message_at,last_message_agent_id
             ) VALUES('channel-main','Main','observation order',NULL,NULL,NULL);",
        )
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.users(id,email) VALUES('actor-a','a@example.test');
             INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user');
             INSERT INTO public.agents(id,name,type,configuration)
               VALUES('bot-1','Bot 1','built_in','{}'::jsonb);
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES('bot-1',NULL,'Bot 1','test role','seed','public',NULL);
             INSERT INTO public.channel_agents(channel_id,agent_id)
               VALUES('channel-main','bot-1');
             INSERT INTO public.channel_memberships(channel_id,user_id)
               VALUES('channel-main','actor-a');",
        )
        .await
        .map_err(|error| error.to_string())
}

fn request(entropy_tail: u8, run_id: &str, anchor: ThreadRunAnchor) -> BeginThreadRunRequest {
    let deployment = DeploymentId::new("dep-a");
    let mut entropy = [0_u8; 16];
    entropy[15] = entropy_tail;
    BeginThreadRunRequest {
        auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
        deployment: deployment.clone(),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new("actor-a"),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            thread_id: ThreadIdentity::new(&deployment).mint_from_entropy(entropy),
            run_id: RunId::new(run_id),
            bot_id: BotId::new("bot-1"),
            anchor,
            message: format!("observation order {run_id}"),
        },
    }
}

fn channel_anchor() -> ThreadRunAnchor {
    ThreadRunAnchor::Channel {
        channel_id: ChannelId::new(CHANNEL),
    }
}

/// The exact rows and advisory key a writer locks after its observation.
#[derive(Clone, Copy)]
struct Target<'a> {
    thread_id: &'a str,
    run_id: Option<&'a str>,
    channel_id: Option<&'a str>,
}

/// Holds ACCESS EXCLUSIVE on the migration ledger, which only the schema observation reads.
struct LedgerBlocker {
    client: pool::PooledClient,
    pid: i32,
}

impl LedgerBlocker {
    async fn hold(control: &DatabasePool) -> Result<Self, String> {
        let client = control.get().await.map_err(|error| error.to_string())?;
        let pid: i32 = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|error| error.to_string())?
            .try_get(0)
            .map_err(|error| error.to_string())?;
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| error.to_string())?;
        if let Err(error) = client
            .batch_execute("LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE")
            .await
        {
            let _ = client.batch_execute("ROLLBACK").await;
            return Err(error.to_string());
        }
        Ok(Self { client, pid })
    }

    async fn release(self) -> Result<(), String> {
        self.client
            .batch_execute("ROLLBACK")
            .await
            .map_err(|error| error.to_string())
    }
}

/// The real backend waiting on the ledger lock, blocked by exactly this blocker.
async fn ledger_waiter(control: &DatabasePool, blocker: i32) -> Result<i32, String> {
    let client = control.get().await.map_err(|error| error.to_string())?;
    let started = Instant::now();
    loop {
        let row = client
            .query_opt(
                "SELECT pid FROM pg_catalog.pg_locks \
                 WHERE locktype='relation' AND NOT granted \
                   AND relation='openbot_internal.schema_migrations'::regclass \
                   AND pg_catalog.pg_blocking_pids(pid)=ARRAY[$1::integer] \
                 ORDER BY pid LIMIT 1",
                &[&blocker],
            )
            .await
            .map_err(|error| error.to_string())?;
        if let Some(row) = row {
            return row.try_get(0).map_err(|error| error.to_string());
        }
        if started.elapsed() > WAIT_BUDGET {
            return Err("writer never waited on the schema observation".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// NOWAIT probes for the exact rows and advisory key `holder` must not hold.
async fn probe_unlocked(
    control: &DatabasePool,
    holder: i32,
    target: Target<'_>,
) -> Result<(), String> {
    let mut client = control.get().await.map_err(|error| error.to_string())?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let held: i64 = transaction
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_locks \
             WHERE pid=$1 AND granted AND (locktype IN ('tuple','advisory') \
               OR (locktype='relation' AND mode IN ('RowShareLock','RowExclusiveLock') \
                 AND relation IN ('public.runs'::regclass,'public.threads'::regclass, \
                   'public.thread_leases'::regclass,'public.channels'::regclass)))",
            &[&holder],
        )
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())?;
    if held != 0 {
        return Err(format!(
            "pid {holder} held {held} Run/Thread/lease/channel/advisory locks while observing"
        ));
    }
    let rows = [
        (
            "SELECT 1 FROM public.threads WHERE thread_id=$1 FOR UPDATE NOWAIT",
            Some(target.thread_id),
        ),
        (
            "SELECT 1 FROM public.thread_leases WHERE thread_id=$1 FOR UPDATE NOWAIT",
            Some(target.thread_id),
        ),
        (
            "SELECT 1 FROM public.runs WHERE run_id=$1 FOR UPDATE NOWAIT",
            target.run_id,
        ),
        (
            "SELECT 1 FROM public.channels WHERE id=$1 FOR UPDATE NOWAIT",
            target.channel_id,
        ),
    ];
    for (sql, key) in rows {
        if let Some(key) = key {
            transaction
                .query_one(sql, &[&key])
                .await
                .map_err(|error| format!("`{sql}` for {key} was locked: {error}"))?;
        }
    }
    let advisory: bool = transaction
        .query_one(
            "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
            &[&target.thread_id],
        )
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())?;
    if !advisory {
        return Err("per-thread advisory lock was held during observation".to_owned());
    }
    transaction
        .rollback()
        .await
        .map_err(|error| error.to_string())
}

/// The probe is not vacuous: a real holder of the writer's locks makes it fail.
async fn probe_refuses_real_holder(
    control: &DatabasePool,
    target: Target<'_>,
) -> Result<(), String> {
    let mut client = control.get().await.map_err(|error| error.to_string())?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())?;
    transaction
        .query_one(
            "SELECT 1 FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id \
             JOIN public.thread_leases l ON l.thread_id=r.thread_id \
             WHERE r.run_id=$1 FOR UPDATE OF r,t,l",
            &[&target.run_id.ok_or("control needs a Run")?],
        )
        .await
        .map_err(|error| error.to_string())?;
    let probed = probe_unlocked(control, pid, target).await;
    transaction
        .rollback()
        .await
        .map_err(|error| error.to_string())?;
    match probed {
        Err(message) if message.contains("held") => Ok(()),
        other => Err(format!("probe accepted a real r/t/l holder: {other:?}")),
    }
}

/// Starts `writer`, proves it waits in the observation without row locks, then lets it finish.
async fn assert_observes_unlocked<T, F>(
    control: &DatabasePool,
    target: Target<'_>,
    writer: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
{
    let blocker = LedgerBlocker::hold(control).await?;
    let task = tokio::spawn(writer);
    let probed = async {
        let waiter = ledger_waiter(control, blocker.pid).await?;
        probe_unlocked(control, waiter, target).await
    }
    .await;
    let released = blocker.release().await;
    let written = tokio::time::timeout(WAIT_BUDGET, task)
        .await
        .map_err(|_| "blocked writer did not finish after release".to_owned())?
        .map_err(|error| error.to_string())?;
    released?;
    probed?;
    written
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn writers_observe_current_schema_before_their_first_row_lock() {
    let admin = admin_config("writers_observe_current_schema_before_their_first_row_lock");
    with_temp_database(&admin, "observeorder", |config| async move {
        let pool = pool::connect(&config.clone().with_max_pool_size(2))
            .await
            .map_err(|error| error.to_string())?;
        let control = pool::connect(&config.clone().with_max_pool_size(3))
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-a".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime = PostgresRunRuntime::new(
                pool.clone(),
                "runtime-a".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
                DEFAULT_DISPATCH_CLAIM_DURATION,
            )
            .map_err(|error| error.to_string())?;

            // One direct and one channel Thread, each with an acknowledged running Run.
            let mut leases = Vec::new();
            let mut threads = Vec::new();
            for (tail, run, anchor) in [
                (7, "run-d1", ThreadRunAnchor::DirectBot),
                (8, "run-c1", channel_anchor()),
            ] {
                let begin = request(tail, run, anchor);
                threads.push(begin.command.thread_id.as_str().to_owned());
                directory
                    .begin_thread_run(begin)
                    .await
                    .map_err(|error| error.to_string())?;
                let claim = runtime
                    .claim_dispatch()
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or("dispatch was not claimed")?;
                if claim.lease().run_id().as_str() != run {
                    return Err(format!("claimed {:?} instead of {run}", claim.lease()));
                }
                leases.push(
                    runtime
                        .acknowledge_dispatch(&claim)
                        .await
                        .map_err(|error| error.to_string())?,
                );
            }
            let direct = Target {
                thread_id: &threads[0],
                run_id: Some("run-d1"),
                channel_id: None,
            };
            let channel = Target {
                thread_id: &threads[1],
                run_id: Some("run-c1"),
                channel_id: Some(CHANNEL),
            };
            probe_refuses_real_holder(&control, direct).await?;

            for (target, lease) in [(direct, &leases[0]), (channel, &leases[1])] {
                // Chunk append: the observation precedes lock_run.
                let chunk_runtime = runtime.clone();
                let chunk_lease = lease.clone();
                let chunk = assert_observes_unlocked(&control, target, async move {
                    chunk_runtime
                        .append_semantic_chunk(&chunk_lease, 1, RunSemanticChannel::Text, "hello")
                        .await
                        .map_err(|error| error.to_string())
                })
                .await?;
                if chunk.replayed || chunk.run_event_sequence != 1 {
                    return Err(format!("blocked chunk append drifted: {chunk:?}"));
                }
                // Finish with assistant text: lock_run, the joint and, on the channel
                // Thread, the channel source all consume the one earlier observation.
                let finish_runtime = runtime.clone();
                let finish_lease = lease.clone();
                let finished = assert_observes_unlocked(&control, target, async move {
                    finish_runtime
                        .finish_run(&finish_lease, 2, RunTerminal::Completed)
                        .await
                        .map_err(|error| error.to_string())
                })
                .await?;
                if finished.replayed || finished.message_sequence != Some(1) {
                    return Err(format!("blocked finish drifted: {finished:?}"));
                }
            }

            // Begin on each existing Thread: the single observation precedes the per-thread
            // advisory lock, the Thread row lock, the lease upsert and the channel lock.
            for (tail, run, anchor, target) in [
                (7, "run-d2", ThreadRunAnchor::DirectBot, direct),
                (8, "run-c2", channel_anchor(), channel),
            ] {
                let begin_directory = directory.clone();
                let begin = request(tail, run, anchor);
                let target = Target {
                    run_id: None,
                    ..target
                };
                assert_observes_unlocked(&control, target, async move {
                    begin_directory
                        .begin_thread_run(begin)
                        .await
                        .map_err(|error| error.to_string())
                })
                .await?;
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let rows = client
                .query("SELECT run_id,status FROM public.runs ORDER BY run_id", &[])
                .await
                .map_err(|error| error.to_string())?;
            let states = rows
                .iter()
                .map(|row| -> Result<(String, String), String> {
                    Ok((
                        row.try_get(0).map_err(|error| error.to_string())?,
                        row.try_get(1).map_err(|error| error.to_string())?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let expected = [
                ("run-c1", "completed"),
                ("run-c2", "running"),
                ("run-d1", "completed"),
                ("run-d2", "running"),
            ]
            .map(|(run, status)| (run.to_owned(), status.to_owned()));
            if states != expected {
                return Err(format!(
                    "unexpected Run states after blocked writers: {states:?}"
                ));
            }
            let source: String = client
                .query_one(
                    "SELECT run_id FROM openbot_internal.channel_history_sources \
                     WHERE channel_id=$1",
                    &[&CHANNEL],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if source != "run-c2" {
                return Err(format!(
                    "channel source did not follow the newest message: {source}"
                ));
            }
            Ok(())
        }
        .await;
        control.close();
        pool.close();
        result
    })
    .await;
}
