//! V7-COMP-007: current Memory authority after a real users-row lock wait.
//! The independent role/deny controller deliberately does NOT advance auth_generation. It is
//! a valid persisted-state counterexample, not the production People revocation operation:
//! People changes advance the generation in the same transaction and remain tested separately.
//! Only owned synthetic PostgreSQL databases are used; no guard or migration is removed.

mod harness;
#[path = "remember_effect_receipts/support.rs"]
mod tool_support;

use std::{future::Future, sync::Arc, time::Duration};

use openbot_application::{
    ApplicationService, BeginThreadRunRequest, MemoryAdministration,
    MemoryAdministrationError as MemoryError, OpenBotApplication, PeopleAdministration,
    RememberMemoryRequest, RememberToolMemory, RememberToolMemoryRequest, RunExecutionLease,
    RunFailureCode, RunRuntime, RunTerminal, ThreadDirectory,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor},
    error::AppError,
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ToolCallId},
    memory::{
        CorrectMemory, MemoryKind, MemoryMutation, MemoryScope, MemorySensitivity, MemorySource,
        RecallMemories, RememberMemory, UpdateMemoryControl,
    },
    tool::ToolInvocation,
};
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::{
    db::{baseline, native, pool, pool::DatabaseConfig},
    memory_admin::PostgresMemoryAdministration,
    repo::{ChannelRepo, people_admin::PostgresPeopleAdministration},
    run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime},
    thread_directory::PostgresThreadDirectory,
};
use serde_json::{Value, json};
use tokio::{task::JoinHandle, time::timeout};
use tokio_postgres::{Client, IsolationLevel, NoTls, Transaction};

const ACTOR: &str = "actor-memory-current";
const ADMIN: &str = "admin-memory-current";
const EMAIL: &str = "memory-current@example.test";
const WAIT: Duration = Duration::from_secs(4);
const CONTENT: &str = "currentauthority synthetic remembered content";

#[derive(Clone, Copy, Debug)]
enum Operation {
    Control,
    UpdateControl,
    List,
    Remember,
    Correct,
    Forbid,
    Delete,
    Recall,
}

const READS: [Operation; 3] = [Operation::Control, Operation::List, Operation::Recall];
const WRITES: [Operation; 5] = [
    Operation::UpdateControl,
    Operation::Remember,
    Operation::Correct,
    Operation::Forbid,
    Operation::Delete,
];
const OPERATIONS: [Operation; 8] = [
    Operation::Control,
    Operation::UpdateControl,
    Operation::List,
    Operation::Remember,
    Operation::Correct,
    Operation::Forbid,
    Operation::Delete,
    Operation::Recall,
];

#[derive(Clone, Copy, Debug)]
enum Change {
    RemoveRole,
    Deny,
    AdvanceGeneration,
}

struct DirectConnection {
    client: Client,
    driver: JoinHandle<()>,
    pid: i32,
}

impl DirectConnection {
    async fn new(config: &DatabaseConfig, label: &str) -> Result<Self, String> {
        let (client, connection) = config
            .clone()
            .with_application_name(label)
            .to_pg_config()
            .connect(NoTls)
            .await
            .map_err(|error| error.to_string())?;
        let driver = tokio::spawn(async move {
            connection
                .await
                .expect("owned direct PostgreSQL connection");
        });
        let pid = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        Ok(Self {
            client,
            driver,
            pid,
        })
    }

    async fn close(self) -> Result<(), String> {
        drop(self.client);
        self.driver.await.map_err(|error| error.to_string())
    }
}

struct Fixture {
    pool: Pool,
    config: DatabaseConfig,
    begin: BeginThreadRunRequest,
    runtime: PostgresRunRuntime,
    lease: RunExecutionLease,
    message_id: String,
    memory_id: String,
}

impl Fixture {
    async fn new(config: DatabaseConfig) -> Result<Self, String> {
        let config = config.with_max_pool_size(4);
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,auth_generation) VALUES
                     ('actor-memory-current','memory-current@example.test',0),
                     ('admin-memory-current','memory-current-admin@example.test',0);
                     INSERT INTO public.user_roles(user_id,role) VALUES
                     ('actor-memory-current','user'),('admin-memory-current','admin');
                     INSERT INTO public.agents(id,name,type,configuration)
                     VALUES('bot-memory-current','Current authority','built_in','{}');
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                     VALUES('bot-memory-current',NULL,'Current authority','synthetic','current','public');",
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        let deployment = DeploymentId::new("dep-memory-current");
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: TenantId::new("tenant-memory-current"),
            actor: ActorId::new(ACTOR),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([107; 16]),
                run_id: RunId::new("run-memory-current-authority"),
                bot_id: BotId::new("bot-memory-current"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "owned source for current authority".into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "memory-current-owner".into(),
            time::Duration::minutes(10),
        )
        .map_err(|error| error.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|error| error.to_string())?;
        let runtime = PostgresRunRuntime::new(
            pool.clone(),
            "memory-current-owner".into(),
            time::Duration::minutes(10),
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|error| error.to_string())?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|error| error.to_string())?
            .ok_or("owned run dispatch missing")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|error| error.to_string())?;
        let message_id = pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .query_one(
                "SELECT message_id FROM public.messages WHERE run_id=$1 AND role='user'",
                &[&begin.command.run_id.as_str()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        let mut fixture = Self {
            pool,
            config,
            begin,
            runtime,
            lease,
            message_id,
            memory_id: String::new(),
        };
        fixture.memory_id = fixture.seed(0).await?;
        Ok(fixture)
    }

    fn auth(&self, generation: u64) -> AuthContext {
        AuthContextBuilder::from_verified_session(
            self.begin.deployment.clone(),
            self.begin.tenant.clone(),
            self.begin.actor.clone(),
            AuthGeneration::new(generation),
            false,
        )
        .with_role(Role::User)
        .build()
    }

    fn input(&self) -> RememberMemory {
        RememberMemory {
            memory_kind: MemoryKind::Fact,
            scope: MemoryScope::User,
            content: CONTENT.into(),
            tags: vec!["current-authority".into()],
            sensitivity: MemorySensitivity::Normal,
            source: Some(MemorySource {
                thread_id: self.begin.command.thread_id.clone(),
                message_id: self.message_id.clone(),
            }),
            expires_at: None,
        }
    }

    async fn seed(&self, generation: u64) -> Result<String, String> {
        PostgresMemoryAdministration::new(self.pool.clone())
            .remember(RememberMemoryRequest {
                deployment: self.begin.deployment.clone(),
                tenant: self.begin.tenant.clone(),
                actor: self.begin.actor.clone(),
                auth_generation: AuthGeneration::new(generation),
                input: self.input(),
            })
            .await
            .map(|record| record.memory_id)
            .map_err(|error| error.to_string())
    }

    fn command(&self, operation: Operation, memory_id: &str) -> AppCommand {
        match operation {
            Operation::Control => AppCommand::GetMemoryControl,
            Operation::UpdateControl => AppCommand::UpdateMemoryControl(UpdateMemoryControl {
                writes_enabled: true,
            }),
            Operation::List => AppCommand::ListMemories {
                cursor: None,
                limit: Some(100),
            },
            Operation::Remember => AppCommand::RememberMemory(self.input()),
            Operation::Correct => AppCommand::CorrectMemory {
                memory_id: memory_id.into(),
                correction: CorrectMemory {
                    content: "currentauthority synthetic corrected content".into(),
                    tags: vec![],
                    sensitivity: MemorySensitivity::Normal,
                    expires_at: None,
                },
            },
            Operation::Forbid | Operation::Delete => AppCommand::MutateMemory {
                memory_id: memory_id.into(),
                mutation: if matches!(operation, Operation::Forbid) {
                    MemoryMutation::Forbid
                } else {
                    MemoryMutation::Delete
                },
            },
            Operation::Recall => AppCommand::RecallMemories(RecallMemories {
                query: "currentauthority".into(),
                tags: vec![],
                bot_id: None,
                thread_id: None,
                limit: Some(100),
            }),
        }
    }

    async fn capture(&self) -> Result<RememberToolMemoryRequest, String> {
        tool_support::capture(
            &self.pool,
            &self.auth(0),
            ToolInvocation {
                call_id: ToolCallId::new(uuid::Uuid::now_v7().to_string()),
                run_id: self.begin.command.run_id.clone(),
                bot_id: self.begin.command.bot_id.clone(),
                call_seq: 0,
                tool_name: "remember".into(),
                arguments: json!({
                    "memoryKind":"fact","scope":"user","content":CONTENT,
                    "tags":["current-authority"],"sensitivity":"normal"
                }),
            },
        )
        .await
    }

    async fn terminal(&self) -> Result<(), String> {
        self.runtime
            .finish_run(
                &self.lease,
                self.lease.next_event_sequence(),
                RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown),
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

async fn fixture<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config).await?;
        let pool = fixture.pool.clone();
        let result = body(fixture).await;
        pool.close();
        result
    })
    .await;
}

async fn worker(config: &DatabaseConfig, label: &str) -> Result<(Pool, i32), String> {
    let pool = pool::connect(
        &config
            .clone()
            .with_max_pool_size(1)
            .with_application_name(label),
    )
    .await
    .map_err(|error| error.to_string())?;
    let client = pool.get().await.map_err(|error| error.to_string())?;
    client
        .batch_execute("SET default_transaction_isolation='repeatable read'")
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(
        client
            .query_one("SHOW default_transaction_isolation", &[])
            .await
            .map_err(|error| error.to_string())?
            .get::<_, String>(0),
        "repeatable read"
    );
    let pid = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    drop(client);
    Ok((pool, pid))
}

async fn controller(client: &mut Client) -> Result<Transaction<'_>, String> {
    let transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(
        transaction
            .query_one("SHOW transaction_isolation", &[])
            .await
            .map_err(|error| error.to_string())?
            .get::<_, String>(0),
        "read committed"
    );
    transaction
        .query_one(
            "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
            &[&ACTOR],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(transaction)
}

async fn change(transaction: &Transaction<'_>, change: Change) -> Result<(), String> {
    match change {
        Change::RemoveRole => {
            assert_eq!(
                transaction
                    .execute("DELETE FROM public.user_roles WHERE user_id=$1", &[&ACTOR])
                    .await
                    .map_err(|error| error.to_string())?,
                1
            );
        }
        Change::Deny => {
            transaction
                .execute(
                    "INSERT INTO public.revoked_access(email,revoked_by) VALUES($1,$2)",
                    &[&EMAIL, &ADMIN],
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        Change::AdvanceGeneration => {
            transaction
                .execute(
                    "UPDATE public.users SET auth_generation=1 WHERE id=$1",
                    &[&ACTOR],
                )
                .await
                .map_err(|error| error.to_string())?;
        }
    }
    let generation: i64 = transaction
        .query_one(
            "SELECT coalesce(auth_generation,0) FROM public.users WHERE id=$1",
            &[&ACTOR],
        )
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    assert_eq!(
        generation,
        i64::from(matches!(change, Change::AdvanceGeneration)),
        "the role/deny fixture must not silently become a generation-change test"
    );
    Ok(())
}

async fn wait_for(observer: &Client, waiting: i32, blocker: i32) -> Result<(), String> {
    timeout(WAIT, async {
        loop {
            observer.batch_execute("SELECT pg_stat_clear_snapshot()")
                .await.map_err(|error| error.to_string())?;
            let row = observer.query_opt(
                "SELECT pg_blocking_pids(pid) AS blockers FROM pg_stat_activity
                 WHERE pid=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid))",
                &[&waiting, &blocker]).await.map_err(|error| error.to_string())?;
            if let Some(row) = row {
                let actual: Vec<i32> = row.get("blockers");
                assert!(actual.contains(&blocker));
                eprintln!("007 actual PostgreSQL wait: worker PID {waiting} -> recorded control PID {blocker}");
                return Ok(());
            }
            // Polling merely yields while PostgreSQL proves the recorded exact lock edge.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.map_err(|_| format!("missing real PostgreSQL wait {waiting} -> {blocker}"))?
}

async fn finish<T>(task: JoinHandle<T>) -> Result<T, String> {
    timeout(WAIT, task)
        .await
        .map_err(|_| "production Memory request did not finish after lock release".to_owned())?
        .map_err(|error| error.to_string())
}

async fn execute(
    pool: &Pool,
    auth: AuthContext,
    command: AppCommand,
) -> Result<AppReply, AppError> {
    let application: Arc<dyn ApplicationService> = Arc::new(
        OpenBotApplication::new(ChannelRepo::new(pool.clone()))
            .with_memory(PostgresMemoryAdministration::new(pool.clone())),
    );
    application.execute(auth, command).await
}

async fn snapshot(pool: &Pool) -> Result<Value, String> {
    let client = pool.get().await.map_err(|error| error.to_string())?;
    let mut snapshot = serde_json::Map::new();
    // users/roles/deny are the controller's intended fixture change. Every business/source row,
    // provenance JSON, control, historical receipt and audit/checkpoint is compared in full.
    for table in [
        "memories",
        "memory_events",
        "user_memory_controls",
        "remember_effect_receipts",
        "tool_calls",
        "tool_attempts",
        "runs",
        "run_events",
        "messages",
        "threads",
        "thread_leases",
        "thread_run_occupancy",
        "outbox",
        "audit_events",
        "audit_checkpoints",
    ] {
        let row = client.query_one(&format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM public.{table} t"
        ), &[]).await.map_err(|error| error.to_string())?;
        snapshot.insert(table.into(), row.get(0));
    }
    Ok(Value::Object(snapshot))
}

fn independent(worker: i32, control: i32, observer: i32) {
    assert_ne!(worker, control);
    assert_ne!(worker, observer);
    assert_ne!(control, observer);
    eprintln!(
        "007 independent PIDs: worker {worker}, RC controller {control}, observer {observer}"
    );
}

fn positive(operation: Operation, reply: &AppReply, before: &Value, after: &Value) {
    match (operation, reply) {
        (Operation::Control | Operation::UpdateControl, AppReply::MemoryControl(control)) => {
            assert!(control.writes_enabled);
        }
        (Operation::List, AppReply::Memories(page)) => assert!(!page.memories.is_empty()),
        (Operation::Recall, AppReply::MemoryRecall(recall)) => assert!(!recall.memories.is_empty()),
        (
            Operation::Remember | Operation::Correct | Operation::Forbid | Operation::Delete,
            AppReply::Memory(_),
        ) => {}
        _ => panic!("incorrect positive reply for {operation:?}"),
    }
    let allowed: &[&str] = match operation {
        Operation::Control | Operation::List | Operation::Recall => &[],
        Operation::UpdateControl => &["user_memory_controls"],
        _ => &["memories", "memory_events"],
    };
    for (key, value) in before.as_object().unwrap() {
        if !allowed.contains(&key.as_str()) {
            assert_eq!(
                &after[key], value,
                "positive {operation:?} changed unrelated {key}"
            );
        }
    }
    if !allowed.is_empty() {
        assert_ne!(after, before, "positive {operation:?} must actually write");
    }
}

async fn reject(operation: Operation, modification: Change, disabled: bool) {
    fixture("memorycurrentreject", move |fixture| async move {
        if disabled {
            execute(&fixture.pool, fixture.auth(0), AppCommand::UpdateMemoryControl(
                UpdateMemoryControl { writes_enabled: false })).await.map_err(|error| error.to_string())?;
        }
        let (worker_pool, worker_pid) = worker(&fixture.config, "007-memory-current-worker").await?;
        let mut control = DirectConnection::new(&fixture.config, "007-memory-current-controller").await?;
        let observer = DirectConnection::new(&fixture.config, "007-memory-current-observer").await?;
        independent(worker_pid, control.pid, observer.pid);
        let before = snapshot(&fixture.pool).await?;
        let transaction = controller(&mut control.client).await?;
        change(&transaction, modification).await?;
        let command = fixture.command(operation, &fixture.memory_id);
        let auth = fixture.auth(0);
        let work = worker_pool.clone();
        eprintln!("007 case: {operation:?}/{modification:?}, disabled={disabled}");
        let request = tokio::spawn(async move { execute(&work, auth, command).await });
        wait_for(&observer.client, worker_pid, control.pid).await?;
        transaction.commit().await.map_err(|error| error.to_string())?;
        let observed = finish(request).await?;
        let after = snapshot(&fixture.pool).await?;
        eprintln!("007 durable before/after {operation:?}/{modification:?}: {}",
            json!({"before": &before, "after": &after}));
        assert!(matches!(observed, Err(AppError::NotVisible)),
            "{operation:?}/{modification:?} must refuse current actor before returning any data or result: {observed:?}");
        assert_eq!(after, before,
            "{operation:?}/{modification:?} changed a business/source/receipt/audit/checkpoint row");
        worker_pool.close();
        control.close().await?;
        observer.close().await?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL via the approved runner"]
async fn role_change_after_actor_wait_refuses_all_three_shared_reads() {
    for operation in READS {
        reject(operation, Change::RemoveRole, false).await;
    }
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL via the approved runner"]
async fn role_change_after_actor_wait_refuses_all_five_shared_write_branches() {
    for operation in WRITES {
        reject(operation, Change::RemoveRole, false).await;
    }
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL via the approved runner"]
async fn deny_change_after_actor_wait_refuses_all_eight_shared_operations() {
    for operation in OPERATIONS {
        reject(operation, Change::Deny, false).await;
    }
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL via the approved runner"]
async fn authority_refusal_precedes_disabled_write_control_after_actor_wait() {
    for modification in [Change::RemoveRole, Change::Deny] {
        for operation in [Operation::Remember, Operation::Correct] {
            reject(operation, modification, true).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL via the approved runner"]
async fn real_tool_fresh_effect_and_positive_historical_duplicate_recheck_current_actor() {
    for historical in [false, true] {
        for modification in [Change::RemoveRole, Change::Deny, Change::AdvanceGeneration] {
            fixture("memorycurrenttool", move |fixture| async move {
                let request = fixture.capture().await?;
                if historical {
                    let first = tool_support::store(&fixture.pool).remember_from_tool(request.clone())
                        .await.map_err(|error| error.to_string())?;
                    assert!(!first.receipt_id.is_empty());
                    fixture.terminal().await?;
                }
                let (work, worker_pid) = worker(&fixture.config, "007-memory-tool-worker").await?;
                let mut control = DirectConnection::new(&fixture.config, "007-memory-tool-controller").await?;
                let observer = DirectConnection::new(&fixture.config, "007-memory-tool-observer").await?;
                independent(worker_pid, control.pid, observer.pid);
                let before = snapshot(&fixture.pool).await?;
                assert_eq!(before["remember_effect_receipts"].as_array().unwrap().len(), usize::from(historical));
                let transaction = controller(&mut control.client).await?;
                change(&transaction, modification).await?;
                let memory = tool_support::store(&work);
                eprintln!("007 case: actual private tool request, historical={historical}/{modification:?}");
                let task = tokio::spawn(async move { memory.remember_from_tool(request).await });
                wait_for(&observer.client, worker_pid, control.pid).await?;
                transaction.commit().await.map_err(|error| error.to_string())?;
                let observed = finish(task).await?;
                let after = snapshot(&fixture.pool).await?;
                eprintln!("007 durable before/after tool historical={historical}/{modification:?}: {}",
                    json!({"before": &before, "after": &after}));
                assert_eq!(observed, Err(MemoryError::NotVisible),
                    "a historical receipt must not bypass the newly current independent role/deny refusal");
                assert_eq!(after, before,
                    "current refusal rewrote original effect/provenance/terminal/receipt or audit");
                work.close();
                control.close().await?;
                observer.close().await?;
                Ok(())
            }).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL via the approved runner"]
async fn generation_fence_and_real_people_revocation_keep_their_separate_guarantee() {
    for operation in OPERATIONS {
        reject(operation, Change::AdvanceGeneration, false).await;
    }
    fixture("memorycurrentpeople", |fixture| async move {
        let request = fixture.capture().await?;
        let people = PostgresPeopleAdministration::new(
            fixture.pool.clone(),
            None,
            b"owned-current-authority-people-audit".to_vec(),
        )
        .map_err(|error| error.to_string())?;
        people
            .change_access(&ActorId::new(ADMIN), &ActorId::new(ACTOR), true)
            .await
            .map_err(|error| error.to_string())?;
        let generation: i64 = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .query_one(
                "SELECT auth_generation FROM public.users WHERE id=$1",
                &[&ACTOR],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        assert_eq!(
            generation, 1,
            "production People revocation advances generation"
        );
        let before = snapshot(&fixture.pool).await?;
        assert_eq!(
            tool_support::store(&fixture.pool)
                .remember_from_tool(request.clone())
                .await,
            Err(MemoryError::NotVisible)
        );
        for operation in OPERATIONS {
            assert!(matches!(
                execute(
                    &fixture.pool,
                    fixture.auth(0),
                    fixture.command(operation, &fixture.memory_id)
                )
                .await,
                Err(AppError::NotVisible)
            ));
        }
        assert_eq!(snapshot(&fixture.pool).await?, before);
        people
            .change_access(&ActorId::new(ADMIN), &ActorId::new(ACTOR), false)
            .await
            .map_err(|error| error.to_string())?;
        let restored = snapshot(&fixture.pool).await?;
        assert!(matches!(
            execute(
                &fixture.pool,
                fixture.auth(0),
                fixture.command(Operation::List, &fixture.memory_id)
            )
            .await,
            Err(AppError::NotVisible)
        ));
        assert_eq!(
            tool_support::store(&fixture.pool)
                .remember_from_tool(request)
                .await,
            Err(MemoryError::NotVisible)
        );
        assert_eq!(snapshot(&fixture.pool).await?, restored);
        let reply = execute(
            &fixture.pool,
            fixture.auth(1),
            fixture.command(Operation::List, &fixture.memory_id),
        )
        .await
        .map_err(|error| error.to_string())?;
        assert!(matches!(reply, AppReply::Memories(_)));
        assert_eq!(snapshot(&fixture.pool).await?, restored);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL via the approved runner"]
async fn rolled_back_independent_role_or_deny_controller_keeps_all_operations_authorized() {
    for operation in OPERATIONS {
        for modification in [Change::RemoveRole, Change::Deny] {
            fixture("memorycurrentrollback", move |fixture| async move {
                let (work, worker_pid) =
                    worker(&fixture.config, "007-memory-rollback-worker").await?;
                let mut control =
                    DirectConnection::new(&fixture.config, "007-memory-rollback-controller")
                        .await?;
                let observer =
                    DirectConnection::new(&fixture.config, "007-memory-rollback-observer").await?;
                independent(worker_pid, control.pid, observer.pid);
                let before = snapshot(&fixture.pool).await?;
                let transaction = controller(&mut control.client).await?;
                change(&transaction, modification).await?;
                let (command, auth, executing) = (
                    fixture.command(operation, &fixture.memory_id),
                    fixture.auth(0),
                    work.clone(),
                );
                eprintln!("007 case: rollback {operation:?}/{modification:?}");
                let task = tokio::spawn(async move { execute(&executing, auth, command).await });
                wait_for(&observer.client, worker_pid, control.pid).await?;
                transaction
                    .rollback()
                    .await
                    .map_err(|error| error.to_string())?;
                let reply = finish(task).await?.map_err(|error| error.to_string())?;
                positive(operation, &reply, &before, &snapshot(&fixture.pool).await?);
                work.close();
                control.close().await?;
                observer.close().await?;
                Ok(())
            })
            .await;
        }
    }
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL via the approved runner"]
async fn admitted_gui_share_and_tool_update_order_real_control_then_preserve_erasure_and_receipt() {
    for tool in [false, true] {
        fixture("memorycurrentadmitted", move |fixture| async move {
            let request = if tool { Some(fixture.capture().await?) } else { None };
            let (work, worker_pid) = worker(&fixture.config, "007-memory-admitted-worker").await?;
            let (control_work, control_pid) = worker(&fixture.config, "007-memory-control-writer").await?;
            let mut barrier = DirectConnection::new(&fixture.config, "007-memory-event-barrier").await?;
            let observer = DirectConnection::new(&fixture.config, "007-memory-admitted-observer").await?;
            independent(worker_pid, barrier.pid, observer.pid);
            assert_ne!(control_pid, worker_pid);
            assert_ne!(control_pid, barrier.pid);
            assert_ne!(control_pid, observer.pid);
            let transaction = barrier.client.build_transaction().isolation_level(IsolationLevel::ReadCommitted)
                .start().await.map_err(|error| error.to_string())?;
            assert_eq!(transaction.query_one("SHOW transaction_isolation", &[])
                .await.map_err(|error| error.to_string())?.get::<_, String>(0), "read committed");
            transaction.batch_execute("LOCK TABLE public.memory_events IN ACCESS EXCLUSIVE MODE")
                .await.map_err(|error| error.to_string())?;
            eprintln!("007 case: actual {} actor admission first, control PID {control_pid}", if tool { "tool UPDATE" } else { "GUI SHARE" });
            let (auth, command, executing, original_request) = (
                fixture.auth(0), fixture.command(Operation::Remember, &fixture.memory_id), work.clone(), request.clone(),
            );
            let task = tokio::spawn(async move {
                if let Some(request) = original_request {
                    tool_support::store(&executing).remember_from_tool(request).await
                        .map(|effect| effect.memory_id).map_err(|error| error.to_string())
                } else {
                    match execute(&executing, auth, command).await.map_err(|error| error.to_string())? {
                        AppReply::Memory(memory) => Ok(memory.memory_id),
                        _ => Err("incorrect admitted GUI reply".into()),
                    }
                }
            });
            wait_for(&observer.client, worker_pid, barrier.pid).await?;
            let (control_auth, controller_pool) = (fixture.auth(0), control_work.clone());
            let control_task = tokio::spawn(async move {
                execute(&controller_pool, control_auth, AppCommand::UpdateMemoryControl(
                    UpdateMemoryControl { writes_enabled: false })).await
            });
            wait_for(&observer.client, control_pid, worker_pid).await?;
            // The real chain is controller -> admitted actor owner -> independent table barrier.
            transaction.commit().await.map_err(|error| error.to_string())?;
            let memory_id = finish(task).await??;
            let reply = finish(control_task).await?.map_err(|error| error.to_string())?;
            assert!(matches!(reply, AppReply::MemoryControl(control) if !control.writes_enabled));
            let before = snapshot(&fixture.pool).await?;
            for operation in [Operation::Remember, Operation::Correct] {
                assert!(matches!(execute(&work, fixture.auth(0), fixture.command(operation, &memory_id)).await,
                    Err(AppError::PolicyRefused { rule, decision: None }) if rule == "memory_writes_disabled"));
            }
            assert_eq!(snapshot(&fixture.pool).await?, before);
            if let Some(request) = request {
                let duplicate = tool_support::store(&work).remember_from_tool(request).await
                    .map_err(|error| error.to_string())?;
                assert_eq!(duplicate.memory_id, memory_id);
                assert_eq!(snapshot(&fixture.pool).await?, before,
                    "valid exact duplicate must not create another receipt when future writes are disabled");
            }
            for operation in [Operation::Forbid, Operation::Delete] {
                let reply = execute(&work, fixture.auth(0), fixture.command(operation, &memory_id))
                    .await.map_err(|error| error.to_string())?;
                assert!(matches!(reply, AppReply::Memory(_)), "write control cannot block owner erasure");
            }
            let after = snapshot(&fixture.pool).await?;
            for table in ["remember_effect_receipts", "audit_events", "audit_checkpoints", "runs", "run_events", "messages", "thread_run_occupancy", "outbox", "tool_calls", "tool_attempts"] {
                assert_eq!(after[table], before[table], "owner erasure changed historical {table}");
            }
            work.close();
            control_work.close();
            barrier.close().await?;
            observer.close().await?;
            Ok(())
        }).await;
    }
}
