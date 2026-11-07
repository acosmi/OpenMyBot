use super::*;
use openbot_application::artifacts::NoArtifactAdministration;
use openbot_application::{PendingInputDispatcher, PendingInputWake, RunRuntime};

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn w06_generation_change_holds_frozen_input() {
    harness::with_temp_database(&harness::admin_config("pending_w06"), "pendingw06", |config| async move {
        let f = Fixture::new(config, 8).await;
        let model = f.model(CustomModelProtocol::OpenaiResponses).await;
        let first = f.request(1, false, &model);
        f.directory.submit_thread_input(first.clone(), None).await.unwrap();
        let mut queued = first.clone();
        queued.command.run_id = RunId::new("generation-frozen-input");
        queued.command.message = "Preserve this frozen message".into();
        f.directory.submit_thread_input(queued.clone(), None).await.unwrap();
        let dispatcher = Arc::new(PendingInputDispatcher::new(Arc::new(f.directory.clone()), Arc::new(NoArtifactAdministration)));
        let runtime = openbot_infra::run_runtime::PostgresRunRuntime::new(
            f.pool.clone(), "owned-v2-runtime".into(), time::Duration::seconds(30),
            openbot_infra::run_runtime::DEFAULT_DISPATCH_CLAIM_DURATION,
        ).unwrap().with_pending_input_dispatcher(dispatcher.clone());
        let claim = runtime.claim_dispatch().await.unwrap().unwrap();
        let lease = runtime.acknowledge_dispatch(&claim).await.unwrap();
        let c = f.pool.get().await.unwrap();
        c.execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'", &[]).await.unwrap();
        drop(c);
        runtime.finish_run(&lease, 1, openbot_application::RunTerminal::Failed(openbot_application::RunFailureCode::ProviderUnavailable)).await.unwrap();
        let c = f.pool.get().await.unwrap();
        let row = c.query_one("SELECT state,held_reason,message,auth_generation FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&queued.command.run_id.as_str()]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "held");
        assert_eq!(row.get::<_, String>(1), "authority_stale");
        assert_eq!(row.get::<_, String>(2), queued.command.message);
        assert_eq!(row.get::<_, i64>(3), 7);
        assert!(c.query_opt("SELECT 1 FROM public.runs WHERE run_id=$1", &[&queued.command.run_id.as_str()]).await.unwrap().is_none());
        drop(c);
        drop(runtime);
        drop(dispatcher);
        f.finish().await;
        Ok(())
    }).await;
}

async fn queue_idle(f: &Fixture, index: u64, model: &ModelConnection) -> BeginThreadRunV2Request {
    let first = f.request(index, false, model);
    f.directory
        .submit_thread_input(first.clone(), None)
        .await
        .unwrap();
    let mut queued = first.clone();
    queued.command.run_id = RunId::new(format!("dispatcher-pending-{index}"));
    f.directory
        .submit_thread_input(queued.clone(), None)
        .await
        .unwrap();
    let runtime = openbot_infra::run_runtime::PostgresRunRuntime::new(
        f.pool.clone(),
        "owned-v2-runtime".into(),
        time::Duration::seconds(30),
        openbot_infra::run_runtime::DEFAULT_DISPATCH_CLAIM_DURATION,
    )
    .unwrap();
    let claim = runtime.claim_dispatch().await.unwrap().unwrap();
    assert_eq!(claim.lease().run_id(), &first.command.run_id);
    let lease = runtime.acknowledge_dispatch(&claim).await.unwrap();
    runtime
        .finish_run(
            &lease,
            1,
            openbot_application::RunTerminal::Failed(
                openbot_application::RunFailureCode::ProviderUnavailable,
            ),
        )
        .await
        .unwrap();
    queued
}

struct RejectInput(openbot_contracts::error::AppError);
#[async_trait]
impl openbot_application::PendingInputConsumer for RejectInput {
    async fn begin(
        &self,
        _: openbot_application::VerifiedPendingInput,
    ) -> Result<
        (
            BeginThreadRunV2Request,
            Vec<openbot_application::RunInputArtifactMaterial>,
        ),
        openbot_contracts::error::AppError,
    > {
        Err(self.0.clone())
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn dispatch_errors_preserve_or_hold_inputs() {
    use openbot_contracts::error::AppError;
    harness::with_temp_database(&harness::admin_config("pending_errors"), "pendingerrors", |config| async move {
        let f = Fixture::new(config, 8).await;
        let model = f.model(CustomModelProtocol::OpenaiResponses).await;
        let cases = [
            (AppError::LeaseConflict { holder: None }, "pending", None),
            (AppError::DependencyUnavailable { dependency: "artifact_store" }, "pending", None),
            (AppError::ForbiddenRole { required: Role::Admin }, "held", Some("authority_unavailable")),
            (AppError::NotVisible, "held", Some("authority_unavailable")),
            (AppError::MalformedPayload { field: "message" }, "held", Some("dispatch_rejected")),
            (AppError::RequestConflict { resource: "run" }, "held", Some("dispatch_rejected")),
        ];
        for (i, (error, state, reason)) in cases.into_iter().enumerate() {
            let input = queue_idle(&f, i as u64 + 1, &model).await;
            let code = error.code().as_str().to_owned();
            f.directory.dispatch_pending_input(&input.command.thread_id, &RejectInput(error)).await.unwrap();
            let c = f.pool.get().await.unwrap();
            let row = c.query_one("SELECT state,held_reason,last_error,message FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&input.command.run_id.as_str()]).await.unwrap();
            assert_eq!(row.get::<_, String>(0), state);
            assert_eq!(row.get::<_, Option<String>>(1).as_deref(), reason);
            // last_error is written only for 503; a lease conflict leaves the row unchanged.
            assert_eq!(row.get::<_, Option<String>>(2), (code != "lease_conflict").then_some(code));
            assert_eq!(row.get::<_, String>(3), input.command.message);
            assert!(c.query_opt("SELECT 1 FROM public.runs WHERE run_id=$1", &[&input.command.run_id.as_str()]).await.unwrap().is_none());
        }
        f.finish().await;
        Ok(())
    }).await;
}

struct KeepRunning;
#[async_trait]
impl openbot_application::RunDispatchConsumer for KeepRunning {
    async fn dispatch(
        &self,
        _: openbot_application::RunExecutionLease,
    ) -> openbot_application::RunDispatchDecision {
        openbot_application::RunDispatchDecision::Accepted
    }
    async fn activate(
        &self,
        _: &openbot_application::RunExecutionLease,
    ) -> Result<(), openbot_application::RunFailureCode> {
        Ok(())
    }
    async fn revoke(
        &self,
        _: &openbot_application::RunExecutionLease,
    ) -> openbot_application::RunCancellationDisposition {
        openbot_application::RunCancellationDisposition::ChildSignalled
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn startup_scan_dispatches_idle_threads_once() {
    harness::with_temp_database(&harness::admin_config("pending_startup"), "pendingstartup", |config| async move {
        let f = Fixture::new(config, 8).await;
        let model = f.model(CustomModelProtocol::OpenaiResponses).await;
        let mut inputs = Vec::new();
        for index in 1..=3 {
            let input = queue_idle(&f, index, &model).await;
            // Keep two durable rows in each idle thread before starting the original relay.
            let mut follower = input.clone();
            follower.command.run_id = RunId::new(format!("startup-follower-{index}"));
            f.directory.submit_thread_input(follower.clone(), None).await.unwrap();
            inputs.push((input, follower));
        }
        let relay = openbot_infra::run_runtime::RunRelay::start(f.assembly.run_runtime.clone(), Arc::new(KeepRunning));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let c = f.pool.get().await.unwrap();
                let n: i64 = c.query_one("SELECT count(*) FROM openbot_internal.thread_pending_inputs WHERE state='dispatched'", &[]).await.unwrap().get(0);
                if n == 3 { break; }
                drop(c);
                tokio::task::yield_now().await;
            }
        }).await.expect("original RunRelay startup did not dispatch each enrolled idle thread");
        relay.stop().await;
        let c = f.pool.get().await.unwrap();
        for (input, follower) in inputs {
            for (run, state) in [(&input.command.run_id, "dispatched"), (&follower.command.run_id, "pending")] {
                assert_eq!(c.query_one("SELECT state FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&run.as_str()]).await.unwrap().get::<_, String>(0), state);
            }
        }
        drop(c);
        f.finish().await;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn wake_waits_for_a_submit_holding_the_conversation_lock() {
    harness::with_temp_database(&harness::admin_config("pending_lock_wait"), "pendinglockwait", |config| async move {
        let f = Fixture::new(config, 8).await;
        let model = f.model(CustomModelProtocol::OpenaiResponses).await;
        let input = queue_idle(&f, 1, &model).await;
        let dispatcher = PendingInputDispatcher::new(Arc::new(f.directory.clone()), Arc::new(NoArtifactAdministration));
        // Hold the conversation lock exactly as an in-flight SubmitThreadInput does.
        let mut holder = f.pool.get().await.unwrap();
        let tx = holder.transaction().await.unwrap();
        tx.query_one("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", &[&input.command.thread_id.as_str()]).await.unwrap();
        let observer = f.pool.get().await.unwrap();
        let release = async {
            tokio::time::timeout(Duration::from_secs(4), async {
                while observer.query_one("SELECT count(*) FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_database d ON d.oid=l.database WHERE d.datname=current_database() AND l.locktype='advisory' AND NOT l.granted", &[]).await.unwrap().get::<_, i64>(0) == 0 {
                    tokio::task::yield_now().await;
                }
            }).await.expect("wake returned without waiting for the held conversation lock");
            tx.commit().await.unwrap();
        };
        let (woken, ()) = tokio::join!(dispatcher.wake(&input.command.thread_id), release);
        woken.unwrap();
        drop(observer);
        drop(holder);
        let c = f.pool.get().await.unwrap();
        assert_eq!(c.query_one("SELECT state FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&input.command.run_id.as_str()]).await.unwrap().get::<_, String>(0), "dispatched");
        assert!(c.query_opt("SELECT 1 FROM public.runs WHERE run_id=$1", &[&input.command.run_id.as_str()]).await.unwrap().is_some());
        drop(c);
        drop(dispatcher);
        f.finish().await;
        Ok(())
    }).await;
}

struct MustNotConsume;
#[async_trait]
impl openbot_application::PendingInputConsumer for MustNotConsume {
    async fn begin(
        &self,
        _: openbot_application::VerifiedPendingInput,
    ) -> Result<
        (
            BeginThreadRunV2Request,
            Vec<openbot_application::RunInputArtifactMaterial>,
        ),
        openbot_contracts::error::AppError,
    > {
        panic!("occupied or clearing thread exposed a pending row to the consumer")
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn w03_occupancy_and_clear_intent_block_dispatch() {
    harness::with_temp_database(&harness::admin_config("pending_w03"), "pendingw03", |config| async move {
        let f = Fixture::new(config, 8).await;
        let model = f.model(CustomModelProtocol::OpenaiResponses).await;
        let runtime = openbot_infra::run_runtime::PostgresRunRuntime::new(f.pool.clone(), "owned-v2-runtime".into(), time::Duration::seconds(30), openbot_infra::run_runtime::DEFAULT_DISPATCH_CLAIM_DURATION).unwrap();
        let mut retained = Vec::new();
        for index in 1..=4 {
            let first = f.request(index, false, &model);
            f.directory.submit_thread_input(first.clone(), None).await.unwrap();
            let mut input = first.clone();
            input.command.run_id = RunId::new(format!("occupied-pending-{index}"));
            f.directory.submit_thread_input(input.clone(), None).await.unwrap();
            if index > 1 {
                let claim = runtime.claim_dispatch().await.unwrap().unwrap();
                let lease = runtime.acknowledge_dispatch(&claim).await.unwrap();
                // Claim FIFO also claims the previously unclaimed case; advance it to running,
                // then select this thread's dispatch rather than mutating any run status.
                let lease = if lease.run_id() != &first.command.run_id {
                    let claim = runtime.claim_dispatch().await.unwrap().unwrap();
                    let current = runtime.acknowledge_dispatch(&claim).await.unwrap();
                    assert_eq!(current.run_id(), &first.command.run_id);
                    current
                } else { lease };
                if index == 3 {
                    f.directory.cancel_thread_run(openbot_application::CancelThreadRunRequest {
                        deployment: first.deployment.clone(), tenant: first.tenant.clone(), actor: first.actor.clone(),
                        command: openbot_contracts::command::CancelThreadRun { thread_id: first.command.thread_id.clone(), run_id: first.command.run_id.clone() },
                    }).await.unwrap();
                }
                if index == 4 {
                    runtime.finish_run(&lease, 1, openbot_application::RunTerminal::ReconciliationRequired(openbot_application::RunFailureCode::ProviderCommitUnknown)).await.unwrap();
                }
            }
            let c = f.pool.get().await.unwrap();
            assert_eq!(c.query_one("SELECT status FROM public.runs WHERE run_id=$1", &[&first.command.run_id.as_str()]).await.unwrap().get::<_, String>(0), if index == 4 { "reconciliation_required" } else { "running" });
            assert_eq!(c.query_one("SELECT count(*) FROM public.thread_run_occupancy WHERE thread_id=$1", &[&first.command.thread_id.as_str()]).await.unwrap().get::<_, i64>(0), 1);
            drop(c);
            if index == 3 {
                let page = openbot_application::use_cases::thread::list_bot_threads(&f.directory, &auth(), BotId::new("bot"), None, None, None).await.unwrap();
                assert_eq!(page.threads.iter().find(|t| t.thread_id == first.command.thread_id).unwrap().foreground.as_ref().unwrap().state, openbot_contracts::command::ThreadForegroundRunState::Cancelling);
            }
            f.directory.dispatch_pending_input(&input.command.thread_id, &MustNotConsume).await.unwrap();
            retained.push(input);
        }
        let clearing = queue_idle(&f, 5, &model).await;
        let mut c = f.pool.get().await.unwrap();
        let tx = c.transaction().await.unwrap();
        let operation = Uuid::now_v7().to_string();
        let request = Uuid::now_v7().to_string();
        let at: time::OffsetDateTime = tx.query_one("SELECT clock_timestamp()", &[]).await.unwrap().get(0);
        assert_eq!(tx.execute("INSERT INTO openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at) SELECT deployment_id,tenant_id,thread_id,1,'stop_clear',$2,$3,'alice',7,anchor_kind,anchor_id,thread_created_at,$4 FROM openbot_internal.thread_history_heads WHERE thread_id=$1", &[&clearing.command.thread_id.as_str(), &operation, &request, &at]).await.unwrap(), 1);
        tx.execute("UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id=$2,closure_request_id=$3,closure_actor_id='alice',closure_auth_generation=7,closed_at=$4 WHERE thread_id=$1", &[&clearing.command.thread_id.as_str(), &operation, &request, &at]).await.unwrap();
        tx.commit().await.unwrap();
        drop(c);
        f.directory.dispatch_pending_input(&clearing.command.thread_id, &MustNotConsume).await.unwrap();
        retained.push(clearing);
        // Historical queued is an existing legal state. Initialize this owned fixture
        // as bot_threads does; terminal transitions and wake hooks above remain real.
        let queued_thread = &retained[0].command.thread_id;
        let c = f.pool.get().await.unwrap();
        assert_eq!(c.execute("UPDATE public.runs SET status='queued',started_at=NULL WHERE run_id=$1", &[&f.request(1, false, &model).command.run_id.as_str()]).await.unwrap(), 1);
        assert_eq!(c.query_one("SELECT status FROM public.runs WHERE run_id=$1", &[&f.request(1, false, &model).command.run_id.as_str()]).await.unwrap().get::<_, String>(0), "queued");
        drop(c);
        f.directory.dispatch_pending_input(queued_thread, &MustNotConsume).await.unwrap();
        drop(runtime);
        let c = f.pool.get().await.unwrap();
        for input in retained {
            assert_eq!(c.query_one("SELECT state FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&input.command.run_id.as_str()]).await.unwrap().get::<_, String>(0), "pending");
            assert!(c.query_opt("SELECT 1 FROM public.runs WHERE run_id=$1", &[&input.command.run_id.as_str()]).await.unwrap().is_none());
        }
        drop(c);
        f.finish().await;
        Ok(())
    }).await;
}

include!("pending_input_dispatcher_w02.rs");
