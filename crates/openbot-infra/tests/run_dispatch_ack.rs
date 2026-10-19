//! Real relay/ACK boundaries against a new owned PostgreSQL database per case.
//! The controlled consumer proves reserve/activate/revoke ordering, not built-in Agent/provider
//! execution. A frame proxy observes the actual server commit; no runtime result is fabricated.
mod harness;

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use openbot_application::{
    BeginThreadRunRequest, RunCancellationDisposition, RunDispatchConsumer, RunDispatchDecision,
    RunExecutionLease, RunFailureCode, RunReconciliationRequest, RunRuntime,
    ThreadConversationRequest, ThreadDirectory, ThreadDirectoryError,
};
use openbot_contracts::{
    auth::AuthGeneration,
    command::{BeginThreadRun, ThreadRunAnchor},
    ids::{ActorId, BotId, DeploymentId, RunId, TenantId, thread::ThreadIdentity},
    reconciliation::RunReconciliationStatus,
};
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::{
    db::{fresh, pool, pool::DatabaseConfig},
    repo::run::RunRepo,
    run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay},
    thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, Semaphore, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_postgres::{Client, IsolationLevel, NoTls};

const OWNER: &str = "dispatch-ack-owned-runtime";
const ACTOR: &str = "dispatch-ack-owner";
const BOT: &str = "dispatch-ack-bot";
const BOUND: Duration = Duration::from_secs(10);
const TABLES: [&str; 15] = [
    "runs",
    "threads",
    "thread_leases",
    "thread_run_occupancy",
    "messages",
    "run_events",
    "outbox",
    "tool_calls",
    "tool_attempts",
    "remember_effect_receipts",
    "memories",
    "memory_events",
    "user_memory_controls",
    "audit_events",
    "audit_checkpoints",
];

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}

fn rows<'a>(snapshot: &'a Value, table: &str) -> &'a [Value] {
    snapshot[table].as_array().expect("owned snapshot array")
}

fn only<'a>(snapshot: &'a Value, table: &str) -> Result<&'a Value, String> {
    let rows = rows(snapshot, table);
    require(
        rows.len() == 1,
        &format!("expected one original {table} row"),
    )?;
    Ok(&rows[0])
}

fn same_except(before: &Value, after: &Value, allowed: &[&str]) -> Result<(), String> {
    for table in TABLES {
        if !allowed.contains(&table) {
            require(
                before[table] == after[table],
                &format!("unexpected {table} mutation"),
            )?;
        }
    }
    Ok(())
}

// One independent, unproxied connection; each observation uses an explicit RC, read-only
// transaction and one aggregate statement, so all fifteen tables share the same statement view.
struct Observer {
    client: tokio::sync::Mutex<Option<Client>>,
    connection: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    pid: i32,
}

impl Observer {
    async fn new(config: &DatabaseConfig) -> Result<Arc<Self>, String> {
        let (client, connection) = config
            .to_pg_config()
            .connect(NoTls)
            .await
            .map_err(|e| e.to_string())?;
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let pid = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        Ok(Arc::new(Self {
            client: tokio::sync::Mutex::new(Some(client)),
            connection: tokio::sync::Mutex::new(Some(connection)),
            pid,
        }))
    }

    async fn snapshot(&self) -> Result<Value, String> {
        let mut guard = self.client.lock().await;
        let client = guard.as_mut().ok_or("owned observer closed")?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .read_only(true)
            .start()
            .await
            .map_err(|e| e.to_string())?;
        let isolation: String = tx
            .query_one("SHOW transaction_isolation", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        require(
            isolation == "read committed",
            "observer must explicitly use RC",
        )?;
        let fields = TABLES.into_iter().map(|table| format!("'{table}',coalesce((SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.{table} t),'[]'::jsonb)")).collect::<Vec<_>>().join(",");
        let snapshot = tx
            .query_one(&format!("SELECT jsonb_build_object({fields})"), &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(snapshot)
    }

    async fn expire(&self, thread: &str) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let client = guard.as_mut().ok_or("owned observer closed")?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|e| e.to_string())?;
        require(
            tx.query_one("SHOW transaction_isolation", &[])
                .await
                .map_err(|e| e.to_string())?
                .get::<_, String>(0)
                == "read committed",
            "expiry controller must explicitly use RC",
        )?;
        require(tx.execute("UPDATE public.thread_leases SET acquired_at=now()-interval '10 seconds',expires_at=now()-interval '1 second',updated_at=now()-interval '1 second' WHERE thread_id=$1", &[&thread]).await.map_err(|e| e.to_string())? == 1, "expiry must target only original owned lease")?;
        tx.commit().await.map_err(|e| e.to_string())
    }

    async fn close(&self) -> Result<(), String> {
        self.client.lock().await.take();
        if let Some(connection) = self.connection.lock().await.take() {
            tokio::time::timeout(BOUND, connection)
                .await
                .map_err(|_| "observer connection did not stop")?
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct WireEvidence {
    ack_phase: AtomicBool,
    drop_commit: AtomicBool,
    suppressed: AtomicUsize,
    opened: AtomicUsize,
    finished: AtomicUsize,
    events: Mutex<Vec<Value>>,
}

impl WireEvidence {
    fn record(&self, event: Value) {
        self.events.lock().expect("owned wire mutex").push(event);
    }
    fn events(&self) -> Vec<Value> {
        self.events.lock().expect("owned wire mutex").clone()
    }
    fn arm_at_accepted_reservation(&self, lose_response: bool) {
        self.record(json!({"phase":"accepting_consumer_immediately_before_ack","suppress_commit":lose_response}));
        self.drop_commit.store(lose_response, Ordering::SeqCst);
        self.ack_phase.store(true, Ordering::SeqCst);
    }
}

struct OwnedFrameProxy {
    port: u16,
    evidence: Arc<WireEvidence>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Drop for OwnedFrameProxy {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl OwnedFrameProxy {
    async fn start(config: &DatabaseConfig) -> Result<Self, String> {
        require(
            config.host == "127.0.0.1" || config.host == "localhost" || config.host == "::1",
            "frame proxy requires the explicitly supplied owned loopback PG",
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let host = config.host.clone();
        let server_port = config.port;
        let evidence = Arc::new(WireEvidence::default());
        let captured = evidence.clone();
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    changed = stopping.changed() => { if changed.is_err() || *stopping.borrow() { break; } }
                    child = children.join_next(), if !children.is_empty() => { let _ = child; }
                    accepted = listener.accept() => {
                        let Ok((client, _)) = accepted else { break; };
                        let Ok(server) = tokio::net::TcpStream::connect((host.as_str(),server_port)).await else { break; };
                        let wire = captured.clone();
                        wire.opened.fetch_add(1, Ordering::SeqCst);
                        children.spawn(async move {
                            let (mut cr, mut cw) = client.into_split();
                            let (mut sr, mut sw) = server.into_split();
                            let frontend = async {
                                // NoTls sends one startup packet, then framed client messages.
                                let length = cr.read_u32().await?;
                                let mut startup = frame_payload(length)?;
                                cr.read_exact(&mut startup).await?;
                                sw.write_u32(length).await?;
                                sw.write_all(&startup).await?;
                                loop {
                                    let kind = cr.read_u8().await?;
                                    let length = cr.read_u32().await?;
                                    let mut payload = frame_payload(length)?;
                                    cr.read_exact(&mut payload).await?;
                                    if wire.ack_phase.load(Ordering::SeqCst) && matches!(kind,b'Q'|b'P') {
                                        let sql = if kind == b'P' { payload.splitn(2, |b| *b == 0).nth(1).unwrap_or_default() } else { &payload };
                                        let sql = sql.split(|b| *b == 0).next().unwrap_or_default();
                                        wire.record(json!({"frontend_sql":String::from_utf8_lossy(sql)}));
                                    }
                                    sw.write_u8(kind).await?;
                                    sw.write_u32(length).await?;
                                    sw.write_all(&payload).await?;
                                    if kind == b'X' {
                                        return Ok::<(), std::io::Error>(());
                                    }
                                }
                            };
                            let backend = async {
                                loop {
                                    let kind = sr.read_u8().await?;
                                    let length = sr.read_u32().await?;
                                    let mut payload = frame_payload(length)?;
                                    sr.read_exact(&mut payload).await?;
                                    if kind == b'K' && payload.len() == 8 {
                                        let pid = i32::from_be_bytes(payload[..4].try_into().expect("four pid bytes"));
                                        wire.record(json!({"backend_pid":pid})); // Never record the cancellation secret.
                                    }
                                    if wire.ack_phase.load(Ordering::SeqCst) && kind == b'E' {
                                        let mut fields = serde_json::Map::new();
                                        let mut remaining = payload.as_slice();
                                        while let Some((&field, rest)) = remaining.split_first() {
                                            if field == 0 { break; }
                                            let Some(end) = rest.iter().position(|b| *b == 0) else { break; };
                                            if matches!(field,b'C'|b'M') { fields.insert((field as char).to_string(), json!(String::from_utf8_lossy(&rest[..end]))); }
                                            remaining = &rest[end+1..];
                                        }
                                        wire.record(json!({"backend_error":fields}));
                                    }
                                    if wire.ack_phase.load(Ordering::SeqCst) && kind == b'C' && payload == b"COMMIT\0" {
                                        let suppressed = wire.drop_commit.swap(false,Ordering::SeqCst);
                                        wire.record(json!({"backend_command":"COMMIT","suppressed":suppressed}));
                                        if suppressed {
                                            wire.suppressed.fetch_add(1, Ordering::SeqCst);
                                            return Ok::<(), std::io::Error>(());
                                        }
                                    }
                                    cw.write_u8(kind).await?;
                                    cw.write_u32(length).await?;
                                    cw.write_all(&payload).await?;
                                }
                            };
                            tokio::select! { _ = frontend => {}, _ = backend => {} }
                            wire.finished.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                }
            }
            // Runtime pool has been closed before normal stop. Every connection child must finish;
            // do not leave detached forwarding tasks behind when the listener exits.
            while children.join_next().await.is_some() {}
        });
        Ok(Self {
            port,
            evidence,
            stop,
            task: Some(task),
        })
    }

    async fn close(mut self) -> Result<(), String> {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            tokio::time::timeout(BOUND, task)
                .await
                .map_err(|_| "owned proxy children did not stop")?
                .map_err(|e| e.to_string())?;
        }
        require(
            self.evidence.opened.load(Ordering::SeqCst)
                == self.evidence.finished.load(Ordering::SeqCst),
            "owned proxy forwarding child leaked",
        )
    }
}

fn frame_payload(length: u32) -> Result<Vec<u8>, std::io::Error> {
    if !(4..=16 * 1024 * 1024).contains(&length) {
        return Err(std::io::Error::other("invalid owned PG frame"));
    }
    Ok(vec![0; (length - 4) as usize])
}

#[derive(Default)]
struct ConsumerEvidence {
    reserved: Vec<RunExecutionLease>,
    activated: Vec<RunExecutionLease>,
    revoked: Vec<RunExecutionLease>,
    controlled_execution_started: Vec<RunExecutionLease>,
    durable_at_completion: Option<Result<Value, String>>,
}

struct AcceptingConsumer {
    worker: Pool,
    observer: Arc<Observer>,
    wire: Arc<WireEvidence>,
    lose_response: bool,
    evidence: Mutex<ConsumerEvidence>,
    reserved: Notify,
    gate: Semaphore,
    done: Notify,
}

impl AcceptingConsumer {
    fn new(
        worker: Pool,
        observer: Arc<Observer>,
        wire: Arc<WireEvidence>,
        lose_response: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            worker,
            observer,
            wire,
            lose_response,
            evidence: Mutex::new(ConsumerEvidence::default()),
            reserved: Notify::new(),
            gate: Semaphore::new(0),
            done: Notify::new(),
        })
    }

    async fn completion(&self) {
        let snapshot = self.observer.snapshot().await;
        self.evidence
            .lock()
            .expect("owned consumer mutex")
            .durable_at_completion = Some(snapshot);
        // Fixture convergence only: relay stop is checked outside its batch, and a delivering
        // claim may safely be reclaimed by this owner. Closing this dedicated pool prevents a
        // second fixture claim; reserve=1 does not certify that production never reclaims.
        self.worker.close();
        self.done.notify_one();
    }
}

#[async_trait]
impl RunDispatchConsumer for AcceptingConsumer {
    async fn dispatch(&self, lease: RunExecutionLease) -> RunDispatchDecision {
        self.evidence
            .lock()
            .expect("owned consumer mutex")
            .reserved
            .push(lease);
        self.reserved.notify_one();
        let permit = self
            .gate
            .acquire()
            .await
            .expect("owned reservation gate open");
        permit.forget();
        self.wire.arm_at_accepted_reservation(self.lose_response);
        RunDispatchDecision::Accepted
    }

    async fn activate(&self, lease: &RunExecutionLease) -> Result<(), RunFailureCode> {
        {
            let mut evidence = self.evidence.lock().expect("owned consumer mutex");
            evidence.activated.push(lease.clone());
            // This is a controlled execution-start observation, not a provider/tool operation.
            evidence.controlled_execution_started.push(lease.clone());
        }
        self.completion().await;
        Ok(())
    }

    async fn revoke(&self, lease: &RunExecutionLease) -> RunCancellationDisposition {
        self.evidence
            .lock()
            .expect("owned consumer mutex")
            .revoked
            .push(lease.clone());
        self.completion().await;
        RunCancellationDisposition::ChildSignalled
    }
}

struct Fixture {
    config: DatabaseConfig,
    reads: Pool,
    directory: PostgresThreadDirectory,
    begin: BeginThreadRunRequest,
    observer: Arc<Observer>,
    worker: Pool,
    proxy: Option<OwnedFrameProxy>,
    consumer: Arc<AcceptingConsumer>,
    relay: Option<RunRelay>,
    worker_pid: i32,
}

impl Fixture {
    async fn new(config: DatabaseConfig, tag: &str, lose_response: bool) -> Result<Self, String> {
        let reads = pool::connect(&config.clone().with_max_pool_size(2))
            .await
            .map_err(|e| e.to_string())?;
        {
            let mut c = reads.get().await.map_err(|e| e.to_string())?;
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('dispatch-ack-owner','owner@dispatch-ack.example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('dispatch-ack-owner','user'); INSERT INTO public.agents(id,name,type,configuration) VALUES('dispatch-ack-bot','Dispatch ACK fixture','built_in','{}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('dispatch-ack-bot',NULL,'Dispatch ACK fixture','owned synthetic','dispatch-ack','public')").await.map_err(|e| e.to_string())?;
        }
        let deployment = DeploymentId::new("dispatch-ack-deployment");
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: TenantId::new("dispatch-ack-tenant"),
            actor: ActorId::new(ACTOR),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([108; 16]),
                run_id: RunId::new(format!("dispatch-ack-original-{tag}")),
                bot_id: BotId::new(BOT),
                anchor: ThreadRunAnchor::DirectBot,
                message: "owned synthetic dispatch ACK source".into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            reads.clone(),
            config.clone(),
            OWNER.into(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let observer = Observer::new(&config).await?;
        let proxy = OwnedFrameProxy::start(&config).await?;
        let mut worker_config = config
            .clone()
            .with_max_pool_size(1)
            .with_application_name("owned-dispatch-ack-worker");
        worker_config.host = "127.0.0.1".into();
        worker_config.port = proxy.port;
        let worker = pool::connect(&worker_config)
            .await
            .map_err(|e| e.to_string())?;
        let worker_pid = {
            let c = worker.get().await.map_err(|e| e.to_string())?;
            c.batch_execute("SET default_transaction_isolation='repeatable read'")
                .await
                .map_err(|e| e.to_string())?;
            require(
                c.query_one("SHOW default_transaction_isolation", &[])
                    .await
                    .map_err(|e| e.to_string())?
                    .get::<_, String>(0)
                    == "repeatable read",
                "explicit directed worker default RR missing",
            )?;
            c.query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|e| e.to_string())?
                .get::<_, i32>(0)
        };
        require(
            worker_pid != observer.pid,
            "observer must be independent from worker backend",
        )?;
        println!(
            "ACK_FIXTURE {tag} worker_pid={worker_pid} observer_pid={} worker_default=repeatable_read observer_transaction=explicit_read_committed; runtime inherits default, begin uses explicit RC",
            observer.pid
        );
        let consumer = AcceptingConsumer::new(
            worker.clone(),
            observer.clone(),
            proxy.evidence.clone(),
            lose_response,
        );
        Ok(Self {
            config,
            reads,
            directory,
            begin,
            observer,
            worker,
            proxy: Some(proxy),
            consumer,
            relay: None,
            worker_pid,
        })
    }

    async fn run_to_reserved(&mut self) -> Result<Value, String> {
        let runtime = PostgresRunRuntime::new(
            self.worker.clone(),
            OWNER.into(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|e| e.to_string())?;
        self.relay = Some(RunRelay::start(Arc::new(runtime), self.consumer.clone()));
        tokio::time::timeout(BOUND, self.consumer.reserved.notified())
            .await
            .map_err(|_| "real relay never reserved original dispatch")?;
        let snapshot = self.observer.snapshot().await?;
        self.assert_identity(&snapshot)?;
        let outbox = only(&snapshot, "outbox")?;
        require(
            outbox["status"] == "delivering"
                && outbox["claimed_by"] == OWNER
                && outbox["attempt_count"] == 1
                && !outbox["claim_expires_at"].is_null(),
            "real original claim not durably visible before ACK",
        )?;
        println!(
            "ACK_RESERVED {}",
            json!({"run":self.begin.command.run_id,"snapshot":snapshot})
        );
        Ok(snapshot)
    }

    fn assert_identity(&self, snapshot: &Value) -> Result<(), String> {
        let run = only(snapshot, "runs")?;
        let thread = only(snapshot, "threads")?;
        let lease = only(snapshot, "thread_leases")?;
        let outbox = only(snapshot, "outbox")?;
        let slot = only(snapshot, "thread_run_occupancy")?;
        require(
            run["run_id"] == self.begin.command.run_id.as_str()
                && run["thread_id"] == self.begin.command.thread_id.as_str()
                && run["actor_id"] == ACTOR
                && run["bot_id"] == BOT,
            "original run/actor/Bot/thread identity changed",
        )?;
        require(
            thread["thread_id"] == run["thread_id"]
                && thread["deployment_id"] == self.begin.deployment.as_str()
                && thread["tenant_id"] == self.begin.tenant.as_str(),
            "original thread scope changed",
        )?;
        require(
            slot["thread_id"] == run["thread_id"]
                && slot["run_id"] == run["run_id"]
                && lease["thread_id"] == run["thread_id"]
                && lease["fencing_token"] == run["fencing_token"],
            "original occupancy/fencing pair changed",
        )?;
        require(
            outbox["outbox_id"] == format!("{}:agent_run_dispatch", self.begin.command.run_id)
                && outbox["aggregate_id"] == run["thread_id"]
                && outbox["aggregate_kind"] == "thread"
                && outbox["destination"] == "agent_run_dispatch"
                && outbox["delivery_class"] == "internal"
                && outbox["payload"]["runId"] == run["run_id"]
                && outbox["payload"]["threadId"] == run["thread_id"],
            "original durable outbox binding changed",
        )?;
        require(
            rows(snapshot, "messages").len() == 1
                && rows(snapshot, "messages")[0]["role"] == "user"
                && rows(snapshot, "messages")[0]["run_id"] == run["run_id"],
            "new or repeated prompt/effect appeared",
        )?;
        for table in [
            "tool_calls",
            "tool_attempts",
            "remember_effect_receipts",
            "memories",
            "memory_events",
            "user_memory_controls",
            "audit_events",
            "audit_checkpoints",
        ] {
            require(
                rows(snapshot, table).is_empty(),
                &format!("controlled consumer manufactured {table}"),
            )?;
        }
        Ok(())
    }

    async fn finish_ack(&mut self, positive: bool) -> Result<Value, String> {
        self.consumer.gate.add_permits(1);
        tokio::time::timeout(BOUND, self.consumer.done.notified())
            .await
            .map_err(|_| "actual ACK never reached activation/revocation")?;
        if let Some(relay) = self.relay.take() {
            tokio::time::timeout(BOUND, relay.stop())
                .await
                .map_err(|_| "real relay did not stop")?;
        }
        let evidence = self.consumer.evidence.lock().expect("owned consumer mutex");
        require(
            evidence.reserved.len() == 1
                && evidence.activated.len() == usize::from(positive)
                && evidence.revoked.len() == usize::from(!positive)
                && evidence.controlled_execution_started.len() == usize::from(positive),
            "wrong controlled reserve/activate/revoke/execution counts",
        )?;
        let original = &evidence.reserved[0];
        require(
            original.run_id() == &self.begin.command.run_id
                && original.thread_id() == &self.begin.command.thread_id
                && original.actor_id().as_str() == ACTOR
                && original.bot_id().as_str() == BOT,
            "reserved lease has different original identity",
        )?;
        require(
            evidence
                .activated
                .iter()
                .chain(evidence.revoked.iter())
                .all(|lease| lease == original),
            "completion lease differs from actual reservation",
        )?;
        let snapshot = evidence
            .durable_at_completion
            .clone()
            .ok_or("no independent completion observation")??;
        println!(
            "ACK_COMPLETION {}",
            json!({"run":original.run_id(),"fencing":original.fencing().get(),"reserve":evidence.reserved.len(),"activate":evidence.activated.len(),"revoke":evidence.revoked.len(),"controlled_execution_start":evidence.controlled_execution_started.len(),"snapshot":snapshot})
        );
        Ok(snapshot)
    }

    async fn commit_rejection_trigger(&self) -> Result<(), String> {
        let c = self.reads.get().await.map_err(|e| e.to_string())?;
        let outbox_id = format!("{}:agent_run_dispatch", self.begin.command.run_id);
        // The literal is a newly generated synthetic id, never user input or a production fixture.
        let escaped = outbox_id.replace('\'', "''");
        c.batch_execute(&format!("CREATE FUNCTION public.owned_dispatch_ack_commit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.status='delivering' AND NEW.status='delivered' AND NEW.outbox_id='{escaped}' THEN RAISE EXCEPTION 'owned ACK COMMIT rejection outbox=% tx=% isolation=%',NEW.outbox_id,txid_current(),current_setting('transaction_isolation') USING ERRCODE='P0001'; END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER owned_dispatch_ack_commit_reject AFTER UPDATE ON public.outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owned_dispatch_ack_commit_reject();")).await.map_err(|e| e.to_string())?;
        let row = c.query_one("SELECT tgdeferrable,tginitdeferred FROM pg_trigger WHERE tgrelid='public.outbox'::regclass AND tgname='owned_dispatch_ack_commit_reject'",&[]).await.map_err(|e| e.to_string())?;
        require(
            row.get::<_, bool>(0) && row.get::<_, bool>(1),
            "COMMIT fault must be a deferred constraint trigger",
        )
    }

    fn wire(&self) -> &WireEvidence {
        &self.proxy.as_ref().expect("owned live proxy").evidence
    }

    async fn close(&mut self) -> Result<(), String> {
        self.worker.close();
        self.consumer.gate.add_permits(1);
        if let Some(relay) = self.relay.take() {
            tokio::time::timeout(BOUND, relay.stop())
                .await
                .map_err(|_| "cleanup relay did not stop")?;
        }
        if let Some(proxy) = self.proxy.take() {
            proxy.close().await?;
        }
        self.reads.close();
        self.observer.close().await
    }
}

async fn fixture<F, Fut>(tag: &str, lose_response: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        body(Fixture::new(config, tag, lose_response).await?).await
    })
    .await;
}

fn assert_delivered_delta(before: &Value, after: &Value) -> Result<(), String> {
    same_except(before, after, &["outbox"])?;
    let before = only(before, "outbox")?;
    let after = only(after, "outbox")?;
    require(
        after["status"] == "delivered"
            && after["claimed_by"].is_null()
            && after["claim_expires_at"].is_null()
            && after["last_error_code"].is_null()
            && !after["delivered_at"].is_null()
            && after["updated_at"] == after["delivered_at"],
        "ACK not actually durable delivered",
    )?;
    for (key, value) in before.as_object().ok_or("original outbox not object")? {
        if ![
            "status",
            "claimed_by",
            "claim_expires_at",
            "delivered_at",
            "updated_at",
            "last_error_code",
        ]
        .contains(&key.as_str())
        {
            require(
                after[key] == *value,
                &format!("ACK changed outbox binding field {key}"),
            )?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn real_relay_activates_original_reservation_only_after_durable_ack() {
    fixture("dispatch_ack_positive", false, |mut f| async move {
        let outcome = async {
            let initial = f.observer.snapshot().await?;
            println!("ACK_INITIAL {initial}");
            let before = f.run_to_reserved().await?;
            same_except(&initial, &before, &["outbox", "thread_leases"])?;
            let after = f.finish_ack(true).await?;
            assert_delivered_delta(&before, &after)?;
            f.assert_identity(&after)?;
            require(
                f.observer.snapshot().await? == after,
                "post-activation durable facts changed",
            )?;
            let events = f.wire().events();
            println!(
                "ACK_WIRE {}",
                json!({"case":"positive","worker_pid":f.worker_pid,"events":events})
            );
            require(
                events
                    .iter()
                    .filter(|e| e["backend_command"] == "COMMIT" && e["suppressed"] == false)
                    .count()
                    == 1
                    && !events.iter().any(|e| !e["backend_error"].is_null()),
                "positive control did not observe exactly the ACK COMMIT success",
            )?;
            require(
                f.wire().suppressed.load(Ordering::SeqCst) == 0,
                "positive control unexpectedly lost response",
            )
        }
        .await;
        let closed = f.close().await;
        outcome.and(closed)
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn real_ack_commit_rejection_revokes_without_activation_and_rolls_back_ack_only() {
    fixture("dispatch_ack_commit_reject", false, |mut f| async move {
        let outcome = async {
            f.commit_rejection_trigger().await?;
            let before = f.run_to_reserved().await?;
            let after = f.finish_ack(false).await?;
            require(
                before == after,
                "deferred ACK COMMIT rejection did not roll back all ACK effects",
            )?;
            f.assert_identity(&after)?;
            require(
                only(&after, "runs")?["status"] == "running"
                    && only(&after, "outbox")?["status"] == "delivering",
                "prior committed begin/claim must remain original running/delivering",
            )?;
            require(
                f.observer.snapshot().await? == before,
                "rejected ACK gained a late durable effect",
            )?;
            let events = f.wire().events();
            println!(
                "ACK_WIRE {}",
                json!({"case":"commit_rejection","worker_pid":f.worker_pid,"events":events})
            );
            let commit = events
                .iter()
                .position(|e| e["frontend_sql"] == "COMMIT")
                .ok_or("no actual frontend COMMIT attempted")?;
            let rejection = events
                .iter()
                .position(|e| {
                    e["backend_error"]["C"] == "P0001"
                        && e["backend_error"]["M"].as_str().is_some_and(|message| {
                            message.contains("owned ACK COMMIT rejection")
                                && message.contains("isolation=repeatable read")
                        })
                })
                .ok_or("no actual deferred ACK error from backend")?;
            require(
                commit < rejection
                    && !events.iter().any(|e| e["backend_command"] == "COMMIT")
                    && f.wire().suppressed.load(Ordering::SeqCst) == 0,
                "server rejection confused with successful/lost COMMIT response",
            )
        }
        .await;
        let closed = f.close().await;
        outcome.and(closed)
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn real_committed_ack_response_loss_revokes_and_original_run_recovers_once_without_replay() {
    fixture("dispatch_ack_response_lost",true,|mut f| async move {
        let outcome = async {
            let before = f.run_to_reserved().await?;
            let after = f.finish_ack(false).await?;
            assert_delivered_delta(&before,&after)?;
            f.assert_identity(&after)?;
            require(f.observer.snapshot().await? == after,"independent unproxied read did not confirm actual delivered ACK")?;
            let events = f.wire().events();
            println!("ACK_WIRE {}",json!({"case":"response_lost","worker_pid":f.worker_pid,"events":events}));
            require(f.wire().suppressed.load(Ordering::SeqCst) == 1 && events.iter().filter(|e| e["backend_command"] == "COMMIT" && e["suppressed"] == true).count() == 1,"proxy must suppress exactly one already successful ACK COMMIT frame")?;
            require(!events.iter().any(|e| !e["backend_error"].is_null()),"response loss had a backend SQL failure")?;
            let recovery_pool = pool::connect(&f.config.clone().with_max_pool_size(1)).await.map_err(|e| e.to_string())?;
            let recovery = async {
                let c = recovery_pool.get().await.map_err(|e| e.to_string())?;
                c.batch_execute("SET default_transaction_isolation='repeatable read'").await.map_err(|e| e.to_string())?;
                require(c.query_one("SHOW default_transaction_isolation",&[]).await.map_err(|e| e.to_string())?.get::<_,String>(0) == "repeatable read","recovery directed default RR not verified")?;
                let pid: i32 = c.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e| e.to_string())?.get(0);
                require(pid != f.worker_pid && pid != f.observer.pid,"new recovery connection must be independent")?;
                drop(c);
                let runtime = PostgresRunRuntime::new(recovery_pool.clone(),OWNER.into(),DEFAULT_THREAD_LEASE_DURATION,DEFAULT_DISPATCH_CLAIM_DURATION).map_err(|e| e.to_string())?;
                // A different real connection using the original owner must not reclaim delivered
                // dispatch, independently of the closed experiment worker pool.
                require(runtime.claim_dispatch().await.map_err(|e| e.to_string())?.is_none(),"same-owner real runtime reclaimed delivered dispatch before expiry")?;
                require(f.observer.snapshot().await? == after,"delivered no-claim probe mutated any durable table")?;
                println!("ACK_NO_RECLAIM {}",json!({"phase":"delivered_before_expiry","runtime_pid":pid,"owner":OWNER,"claim":"none","snapshot":after}));
                f.observer.expire(f.begin.command.thread_id.as_str()).await?;
                let expired = f.observer.snapshot().await?;
                same_except(&after,&expired,&["thread_leases"])?;
                let receipt = runtime.recover_one_stale_run().await.map_err(|e| e.to_string())?.ok_or("original delivered expired run not recovered")?;
                require(!receipt.replayed && receipt.message_sequence.is_none(),"recovery must create one terminal without assistant or prompt")?;
                let terminal = f.observer.snapshot().await?;
                require(runtime.recover_one_stale_run().await.map_err(|e| e.to_string())?.is_none(),"recovery repeated original terminal")?;
                require(f.observer.snapshot().await? == terminal,"second recovery mutated durable facts")?;
                require(runtime.claim_dispatch().await.map_err(|e| e.to_string())?.is_none(),"same-owner real runtime reclaimed original RR dispatch")?;
                require(f.observer.snapshot().await? == terminal,"RR no-claim probe mutated any durable table")?;
                println!("ACK_NO_RECLAIM {}",json!({"phase":"reconciliation_required_after_recovery","runtime_pid":pid,"owner":OWNER,"claim":"none","snapshot":terminal}));
                same_except(&expired,&terminal,&["runs","threads","thread_leases","run_events"])?;
                f.assert_identity(&terminal)?;
                let original = only(&terminal,"runs")?;
                require(original["status"] == "reconciliation_required" && original["error_code"] == RunFailureCode::RuntimeLeaseExpired.as_str() && original["terminal_event_seq"] == receipt.run_event_sequence,"lost ACK rewrote original Unknown terminal")?;
                require(rows(&terminal,"run_events").len() == 2 && rows(&terminal,"run_events").iter().filter(|event| event["terminal"] == true && event["event_type"] == "reconciliation_required").count() == 1,"recovery not exactly one original RR terminal event")?;
                println!("ACK_RECOVERY {}",json!({"recovery_pid":pid,"original":f.begin.command.run_id,"before_expiry":after,"expired":expired,"terminal":terminal}));
                let query = RunReconciliationRequest { deployment:f.begin.deployment.clone(),tenant:f.begin.tenant.clone(),actor:f.begin.actor.clone(),auth_generation:f.begin.auth_generation,thread:f.begin.command.thread_id.clone(),run:f.begin.command.run_id.clone(),after:None,limit:50 };
                let facts = f.directory.run_reconciliation(query.clone()).await.map_err(|e| e.to_string())?;
                let receipts = f.directory.run_effect_receipts(query).await.map_err(|e| e.to_string())?;
                require(facts.status == RunReconciliationStatus::ReconciliationRequired && receipts.status == facts.status && facts.thread_id == f.begin.command.thread_id && facts.run_id == f.begin.command.run_id && receipts.thread_id == facts.thread_id && receipts.run_id == facts.run_id && facts.terminal_event_sequence == receipt.run_event_sequence && receipts.terminal_event_sequence == facts.terminal_event_sequence && facts.foreground_blocked && receipts.foreground_blocked && facts.attempts.is_empty() && receipts.receipts.is_empty() && facts.available_actions.is_empty() && receipts.available_actions.is_empty(),"074/075 did not preserve original blocked Unknown/empty facts")?;
                let conversation = f.directory.thread_conversation(ThreadConversationRequest { deployment:f.begin.deployment.clone(),tenant:f.begin.tenant.clone(),actor:f.begin.actor.clone(),thread:f.begin.command.thread_id.clone() }).await.map_err(|e| e.to_string())?;
                require(conversation.active_run_id == Some(f.begin.command.run_id.clone()),"conversation lost exact original foreground owner")?;
                let active = RunRepo::new(f.reads.clone()).active_foreground_for_thread(f.begin.command.thread_id.as_str()).await.map_err(|e| e.to_string())?.ok_or("internal occupancy lost original")?;
                require(active.run_id == f.begin.command.run_id.as_str() && active.status == "reconciliation_required","internal occupancy selected a successor")?;
                let replay = f.directory.begin_thread_run(f.begin.clone()).await.map_err(|e| e.to_string())?;
                require(replay.run_id == f.begin.command.run_id && replay.replayed,"exact original begin did not replay original")?;
                let mut competing = f.begin.clone();
                competing.command.run_id = RunId::new("dispatch-ack-must-never-requeue-successor");
                require(f.directory.begin_thread_run(competing).await == Err(ThreadDirectoryError::LeaseConflict),"Unknown allowed a new foreground run")?;
                require(f.observer.snapshot().await? == terminal,"five occupancy consumers/read-only original replay created a write or retry")?;
                println!("ACK_READ_ONLY_FACTS {}",json!({"reconciliation":facts,"effect_receipts":receipts,"foreground_run":active.run_id,"original_begin_replay":replay.run_id,"new_begin":"lease_conflict","no_effect_inference":"empty page is not NotCommitted"}));
                Ok(())
            }.await;
            recovery_pool.close();
            recovery
        }.await;
        let closed = f.close().await;
        outcome.and(closed)
    }).await;
}
