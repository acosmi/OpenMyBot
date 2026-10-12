//! PostgreSQL 17 evidence that writer transactions observe the current schema before
//! their first row lock. A real ACCESS EXCLUSIVE holder on the migration ledger stops
//! the observation; while the writer waits there, independent NOWAIT probes must
//! acquire the very Run/Thread rows and per-thread advisory lock the writer will use.
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
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_infra::db::pool::{self, DatabasePool};
use openbot_infra::db::{baseline, native};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

const WAIT_BUDGET: Duration = Duration::from_secs(10);

async fn provision(pool: &DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
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
             ) VALUES('bot-1',NULL,'Bot 1','test role','seed','public',NULL);",
        )
        .await
        .map_err(|error| error.to_string())
}

fn request(deployment: &DeploymentId, run_id: &str) -> BeginThreadRunRequest {
    let mut entropy = [0_u8; 16];
    entropy[15] = 7;
    BeginThreadRunRequest {
        auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
        deployment: deployment.clone(),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new("actor-a"),
        command: BeginThreadRun {
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            thread_id: ThreadIdentity::new(deployment).mint_from_entropy(entropy),
            run_id: RunId::new(run_id),
            bot_id: BotId::new("bot-1"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "observation order".to_owned(),
        },
    }
}

/// Holds ACCESS EXCLUSIVE on the migration ledger, which only the schema observation reads.
struct LedgerBlocker {
    client: pool::PooledClient,
}

impl LedgerBlocker {
    async fn hold(control: &DatabasePool) -> Result<Self, String> {
        let client = control.get().await.map_err(|error| error.to_string())?;
        client
            .batch_execute(
                "BEGIN; LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE",
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self { client })
    }

    async fn release(self) -> Result<(), String> {
        self.client
            .batch_execute("ROLLBACK")
            .await
            .map_err(|error| error.to_string())
    }
}

/// The real waiting backend on the ledger lock, observed from `pg_locks`.
async fn ledger_waiter(control: &DatabasePool) -> Result<i32, String> {
    let client = control.get().await.map_err(|error| error.to_string())?;
    let started = Instant::now();
    loop {
        let row = client
            .query_opt(
                "SELECT pid FROM pg_catalog.pg_locks \
                 WHERE locktype='relation' AND NOT granted \
                   AND relation='openbot_internal.schema_migrations'::regclass \
                 ORDER BY pid LIMIT 1",
                &[],
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

/// NOWAIT probes for the exact rows the blocked writer locks after its observation.
async fn probe_unlocked(
    control: &DatabasePool,
    waiter: i32,
    thread_id: &str,
    run_id: Option<&str>,
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
                 AND relation IN ( \
                 'public.runs'::regclass,'public.threads'::regclass, \
                 'public.thread_leases'::regclass)))",
            &[&waiter],
        )
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())?;
    if held != 0 {
        return Err(format!(
            "writer pid {waiter} held {held} Run/Thread/lease/advisory locks while observing"
        ));
    }
    transaction
        .query_one(
            "SELECT thread_id FROM public.threads WHERE thread_id=$1 FOR UPDATE NOWAIT",
            &[&thread_id],
        )
        .await
        .map_err(|error| format!("Thread row was locked during observation: {error}"))?;
    transaction
        .query_one(
            "SELECT thread_id FROM public.thread_leases WHERE thread_id=$1 FOR UPDATE NOWAIT",
            &[&thread_id],
        )
        .await
        .map_err(|error| format!("lease row was locked during observation: {error}"))?;
    if let Some(run_id) = run_id {
        transaction
            .query_one(
                "SELECT run_id FROM public.runs WHERE run_id=$1 FOR UPDATE NOWAIT",
                &[&run_id],
            )
            .await
            .map_err(|error| format!("Run row was locked during observation: {error}"))?;
    }
    let advisory: bool = transaction
        .query_one(
            "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
            &[&thread_id],
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

/// Starts `writer`, proves it waits in the observation without row locks, then lets it finish.
async fn assert_observes_unlocked<T, F>(
    control: &DatabasePool,
    thread_id: &str,
    run_id: Option<&str>,
    writer: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
{
    let blocker = LedgerBlocker::hold(control).await?;
    let task = tokio::spawn(writer);
    let probed = async {
        let waiter = ledger_waiter(control).await?;
        probe_unlocked(control, waiter, thread_id, run_id).await
    }
    .await;
    blocker.release().await?;
    let written = task.await.map_err(|error| error.to_string())?;
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
            let deployment = DeploymentId::new("dep-a");
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
            let first = request(&deployment, "run-1");
            let thread_id = first.command.thread_id.as_str().to_owned();
            directory
                .begin_thread_run(first)
                .await
                .map_err(|error| error.to_string())?;
            let claim = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("dispatch was not claimed")?;
            let lease = runtime
                .acknowledge_dispatch(&claim)
                .await
                .map_err(|error| error.to_string())?;

            // Chunk append: the observation precedes lock_run.
            let chunk_runtime = runtime.clone();
            let chunk_lease = lease.clone();
            let chunk = assert_observes_unlocked(&control, &thread_id, Some("run-1"), async move {
                chunk_runtime
                    .append_semantic_chunk(&chunk_lease, 1, RunSemanticChannel::Text, "hello")
                    .await
                    .map_err(|error| error.to_string())
            })
            .await?;
            if chunk.replayed || chunk.run_event_sequence != 1 {
                return Err(format!("blocked chunk append drifted: {chunk:?}"));
            }

            // Terminal finish: the observation precedes lock_run.
            let finish_runtime = runtime.clone();
            let finish_lease = lease.clone();
            let finished =
                assert_observes_unlocked(&control, &thread_id, Some("run-1"), async move {
                    finish_runtime
                        .finish_run(&finish_lease, 2, RunTerminal::Completed)
                        .await
                        .map_err(|error| error.to_string())
                })
                .await?;
            if finished.replayed || finished.message_sequence != Some(1) {
                return Err(format!("blocked finish drifted: {finished:?}"));
            }

            // Begin on the existing Thread: the single observation precedes the
            // per-thread advisory lock, the Thread row lock and the lease upsert.
            let begin_directory = directory.clone();
            let second = request(&deployment, "run-2");
            assert_observes_unlocked(&control, &thread_id, None, async move {
                begin_directory
                    .begin_thread_run(second)
                    .await
                    .map_err(|error| error.to_string())
            })
            .await?;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let rows = client
                .query(
                    "SELECT run_id,status FROM public.runs WHERE thread_id=$1 ORDER BY run_id",
                    &[&thread_id],
                )
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
            let expected = vec![
                ("run-1".to_owned(), "completed".to_owned()),
                ("run-2".to_owned(), "running".to_owned()),
            ];
            if states != expected {
                return Err(format!(
                    "unexpected Run states after blocked writers: {states:?}"
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
