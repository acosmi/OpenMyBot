//! Owned PostgreSQL control tests. Provider execution is outside this fixture.
use super::*;
use openbot_application::artifacts::NoArtifactAdministration;
use openbot_application::{PendingInputDispatcher, RunRuntime, RunTerminal};
use openbot_contracts::command::{
    AppCommand, AppReply, PendingInputState, ThreadForegroundRunState, ThreadStatusFilter,
};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};

fn runtime(f: &Fixture) -> PostgresRunRuntime {
    PostgresRunRuntime::new(
        f.pool.clone(),
        "owned-v2-runtime".into(),
        time::Duration::seconds(30),
        DEFAULT_DISPATCH_CLAIM_DURATION,
        openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&f.pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
    )
    .unwrap()
}
async fn queued(
    f: &Fixture,
    index: u64,
    model: &ModelConnection,
) -> (BeginThreadRunV2Request, BeginThreadRunV2Request) {
    let first = f.request(index, false, model);
    f.directory
        .submit_thread_input(first.clone(), None)
        .await
        .unwrap();
    let mut pending = first.clone();
    pending.command.run_id = RunId::new(format!("work-pending-{index}"));
    pending.command.message = format!("  frozen input {index} café\n  ");
    f.directory
        .submit_thread_input(pending.clone(), None)
        .await
        .unwrap();
    (first, pending)
}
async fn queued_application(
    f: &Fixture,
    index: u64,
    model: &ModelConnection,
) -> (BeginThreadRunV2Request, BeginThreadRunV2Request) {
    let first = f.request(index, false, model);
    assert!(matches!(
        f.assembly
            .application
            .execute(auth(), AppCommand::SubmitThreadInput(first.command.clone()))
            .await
            .unwrap(),
        AppReply::ThreadInputOutcome(openbot_contracts::command::ThreadInputOutcome::Started(_))
    ));
    let mut pending = first.clone();
    pending.command.run_id = RunId::new(format!("application-work-pending-{index}"));
    pending.command.message = format!("  frozen input {index} café\n  ");
    assert!(matches!(
        f.assembly
            .application
            .execute(
                auth(),
                AppCommand::SubmitThreadInput(pending.command.clone())
            )
            .await
            .unwrap(),
        AppReply::ThreadInputOutcome(openbot_contracts::command::ThreadInputOutcome::Queued { .. })
    ));
    (first, pending)
}
async fn finish(runtime: &dyn RunRuntime, expected: &RunId, terminal: RunTerminal) {
    let claim = runtime.claim_dispatch().await.unwrap().unwrap();
    assert_eq!(claim.lease().run_id(), expected);
    let lease = runtime.acknowledge_dispatch(&claim).await.unwrap();
    runtime
        .finish_run(&lease, lease.next_event_sequence(), terminal)
        .await
        .unwrap();
}

struct RejectPayload;
#[async_trait]
impl openbot_application::PendingInputConsumer for RejectPayload {
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
        Err(openbot_contracts::error::AppError::MalformedPayload { field: "message" })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn w04_stop_holds_and_cancels_atomically() {
    harness::with_temp_database(&harness::admin_config("work_w04"), "workw04", |config| async move {
        let f = Fixture::new(config, 12).await;
        let model = f.model(CustomModelProtocol::OpenaiResponses).await;
        let dispatcher = Arc::new(PendingInputDispatcher::new(Arc::new(f.directory.clone()), Arc::new(NoArtifactAdministration)));
        let rt = runtime(&f).with_pending_input_dispatcher(dispatcher.clone());
        for index in 1..=12 {
            let (first, pending) = queued(&f, index, &model).await;
            let claim=rt.claim_dispatch().await.unwrap().unwrap();
            assert_eq!(claim.lease().run_id(),&first.command.run_id);
            let lease=rt.acknowledge_dispatch(&claim).await.unwrap();
            // A failure after the hold UPDATE must roll back both halves.
            let no_runtime = PostgresThreadDirectory::new(f.pool.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&f.pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")));
            assert!(matches!(no_runtime.stop_thread_work(&auth(), &first.command.thread_id, Some(&first.command.run_id)).await, Err(ThreadDirectoryError::Unavailable)));
            let c = f.pool.get().await.unwrap();
            assert_eq!(c.query_one("SELECT state FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&pending.command.run_id.as_str()]).await.unwrap().get::<_,String>(0), "pending");
            assert_eq!(c.query_one("SELECT count(*) FROM public.outbox WHERE aggregate_id=$1 AND destination='agent_run_cancel'", &[&first.command.run_id.as_str()]).await.unwrap().get::<_,i64>(0), 0);
            drop(c);
            let held = f.directory.stop_thread_work(&auth(), &first.command.thread_id, None).await.unwrap();
            assert_eq!(held.held, 1);
            assert!(held.cancellation.is_none());
            let mut next = pending.clone();
            next.command.run_id = RunId::new(format!("work-race-{index}"));
            // Two real transactions contend on the original per-thread advisory lock.
            let a = auth();
            let (stopped, submitted) = tokio::join!(
                f.directory.stop_thread_work(&a, &first.command.thread_id, Some(&first.command.run_id)),
                f.directory.submit_thread_input(next.clone(), None),
            );
            submitted.unwrap();
            let stopped = stopped.unwrap();
            let cancellation = stopped.cancellation.as_ref().unwrap();
            assert_eq!(cancellation.thread_id, first.command.thread_id);
            assert_eq!(cancellation.run_id, first.command.run_id);
            assert_eq!(cancellation.state, openbot_contracts::command::ThreadRunCancellationState::Requested);
            assert!(stopped.held <= 1);
            let c = f.pool.get().await.unwrap();
            let row = c.query_one("SELECT state,held_reason FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&pending.command.run_id.as_str()]).await.unwrap();
            assert_eq!(row.get::<_,String>(0), "held");
            assert_eq!(row.get::<_,String>(1), "stopped_by_user");
            assert_eq!(c.query_one("SELECT count(*) FROM public.outbox WHERE aggregate_id=$1 AND destination='agent_run_cancel'", &[&first.command.run_id.as_str()]).await.unwrap().get::<_,i64>(0),1);
            let state: String = c.query_one("SELECT state FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&next.command.run_id.as_str()]).await.unwrap().get(0);
            assert_eq!(state, if stopped.held == 1 { "held" } else { "pending" });
            drop(c);
            let repeated=f.directory.stop_thread_work(&auth(), &first.command.thread_id, Some(&first.command.run_id)).await.unwrap();
            assert_eq!(repeated.held, if stopped.held==0 {1} else {0});
            assert_eq!(repeated.cancellation.unwrap().state,openbot_contracts::command::ThreadRunCancellationState::AlreadyRequested);
            rt.finish_run(&lease,lease.next_event_sequence(),RunTerminal::Cancelled).await.unwrap();
            let c = f.pool.get().await.unwrap();
            assert_eq!(c.query_one("SELECT count(*) FROM public.runs WHERE thread_id=$1", &[&first.command.thread_id.as_str()]).await.unwrap().get::<_,i64>(0),1);
            assert_eq!(c.query_one("SELECT count(*) FROM openbot_internal.thread_pending_inputs WHERE thread_id=$1 AND state='held'", &[&first.command.thread_id.as_str()]).await.unwrap().get::<_,i64>(0),2);
            drop(c);
        }
        // Existing held reasons survive Stop without being relabelled.
        let (first, rejected) = queued(&f, 90, &model).await;
        let bare = runtime(&f);
        finish(&bare, &first.command.run_id, RunTerminal::Completed).await;
        f.directory.dispatch_pending_input(&first.command.thread_id, &RejectPayload).await.unwrap();
        // Held rows do not block a direct start; queue one more input behind that new Run.
        let mut next = rejected.clone(); next.command.run_id = RunId::new("after-held-rejection");
        assert!(matches!(f.directory.submit_thread_input(next, None).await.unwrap(), openbot_application::SubmitThreadInputAttempt::Accepted(openbot_contracts::command::ThreadInputOutcome::Started(_))));
        let mut behind = rejected.clone(); behind.command.run_id = RunId::new("behind-held-rejection");
        f.directory.submit_thread_input(behind, None).await.unwrap();
        let stopped=f.directory.stop_thread_work(&auth(), &first.command.thread_id, Some(&first.command.run_id)).await.unwrap();
        assert_eq!(stopped.held,1);assert!(stopped.cancellation.is_none());
        let c=f.pool.get().await.unwrap();
        let row=c.query_one("SELECT state,held_reason,last_error FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&rejected.command.run_id.as_str()]).await.unwrap();
        assert_eq!(row.get::<_,String>(0),"held");assert_eq!(row.get::<_,String>(1),"dispatch_rejected");assert_eq!(row.get::<_,String>(2),"malformed_payload");
        drop(c);drop(bare);
        drop(rt); drop(dispatcher); f.finish().await; Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn w05_release_requeues_and_dispatches() {
    harness::with_temp_database(&harness::admin_config("work_w05"), "workw05", |config| async move {
        let f = Fixture::new(config, 8).await;
        let model = f.model(CustomModelProtocol::OpenaiResponses).await;
        let (first, held) = queued_application(&f, 1, &model).await;
        f.directory.stop_thread_work(&auth(), &first.command.thread_id, None).await.unwrap();
        let mut follower = held.clone(); follower.command.run_id = RunId::new("release-follower");
        f.directory.submit_thread_input(follower.clone(), None).await.unwrap();
        let receipt = f.directory.release_pending_input(&auth(), &first.command.thread_id, &held.command.run_id).await.unwrap();
        assert_eq!(receipt.state, PendingInputState::Pending);
        let c=f.pool.get().await.unwrap();
        let rows=c.query("SELECT run_id,auth_generation,held_reason,last_error FROM openbot_internal.thread_pending_inputs WHERE thread_id=$1 ORDER BY queued_at,run_id", &[&first.command.thread_id.as_str()]).await.unwrap();
        assert_eq!(rows[0].get::<_,String>(0),follower.command.run_id.as_str());
        assert_eq!(rows[1].get::<_,String>(0),held.command.run_id.as_str());
        assert_eq!(rows[1].get::<_,i64>(1),7);
        assert_eq!(rows[1].get::<_,Option<String>>(2),None);
        assert_eq!(rows[1].get::<_,Option<String>>(3),None);
        drop(c);
        f.directory.stop_thread_work(&auth(), &first.command.thread_id, None).await.unwrap();
        finish(f.assembly.run_runtime.as_ref(),&first.command.run_id,RunTerminal::Completed).await;
        f.directory.release_pending_input(&auth(), &first.command.thread_id, &held.command.run_id).await.unwrap();
        f.directory.dispatch_pending_input(&first.command.thread_id, &RejectPayload).await.unwrap();
        let c=f.pool.get().await.unwrap();
        let row=c.query_one("SELECT held_reason,last_error FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&held.command.run_id.as_str()]).await.unwrap();
        assert_eq!(row.get::<_,String>(0),"dispatch_rejected");
        assert_eq!(row.get::<_,String>(1),"malformed_payload");
        drop(c);
        // Only Application execute performs the post-commit wake. No manual wake here.
        let reply=f.assembly.application.execute(auth(),AppCommand::ReleasePendingInput { thread_id:first.command.thread_id.clone(),run_id:held.command.run_id.clone() }).await.unwrap();
        assert!(matches!(reply,AppReply::PendingInputState(_)));
        let c=f.pool.get().await.unwrap();
        let row=c.query_one("SELECT state,held_reason,last_error FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&held.command.run_id.as_str()]).await.unwrap();
        assert_eq!(row.get::<_,String>(0),"dispatched");assert_eq!(row.get::<_,Option<String>>(1),None);assert_eq!(row.get::<_,Option<String>>(2),None);
        assert!(c.query_opt("SELECT 1 FROM public.runs WHERE run_id=$1", &[&held.command.run_id.as_str()]).await.unwrap().is_some());
        drop(c);
        assert!(matches!(f.directory.withdraw_pending_input(&auth(),&first.command.thread_id,&held.command.run_id).await,Err(ThreadDirectoryError::PendingInputState)));
        assert!(matches!(f.directory.release_pending_input(&auth(),&first.command.thread_id,&held.command.run_id).await,Err(ThreadDirectoryError::PendingInputState)));
        f.finish().await; Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn w06_release_adopts_current_generation() {
    harness::with_temp_database(&harness::admin_config("work_w06"), "workw06", |config| async move {
        let f=Fixture::new(config,8).await;
        let model=f.model(CustomModelProtocol::OpenaiResponses).await;
        let (first,pending)=queued_application(&f,1,&model).await;
        let c=f.pool.get().await.unwrap(); c.execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'",&[]).await.unwrap(); drop(c);
        finish(f.assembly.run_runtime.as_ref(),&first.command.run_id,RunTerminal::Completed).await;
        let c=f.pool.get().await.unwrap();
        let row=c.query_one("SELECT state,held_reason,last_error FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&pending.command.run_id.as_str()]).await.unwrap();
        assert_eq!(row.get::<_,String>(0),"held"); assert_eq!(row.get::<_,String>(1),"authority_stale");
        assert_eq!(row.get::<_,Option<String>>(2),None); drop(c);
        assert!(matches!(f.directory.release_pending_input(&auth(),&first.command.thread_id,&pending.command.run_id).await,Err(ThreadDirectoryError::NotVisible)));
        let fresh=AuthContextBuilder::from_verified_session(DeploymentId::new(DEP),TenantId::new(TENANT),ActorId::new("alice"),AuthGeneration::new(8),false).with_roles([Role::User]).build();
        f.assembly.application.execute(fresh,AppCommand::ReleasePendingInput{thread_id:first.command.thread_id.clone(),run_id:pending.command.run_id.clone()}).await.unwrap();
        let c=f.pool.get().await.unwrap();
        let row=c.query_one("SELECT state,auth_generation,message,model_selection,held_reason,last_error FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&pending.command.run_id.as_str()]).await.unwrap();
        assert_eq!(row.get::<_,String>(0),"dispatched");assert_eq!(row.get::<_,i64>(1),8);
        assert_eq!(row.get::<_,String>(2),pending.command.message);
        assert_eq!(row.get::<_,Value>(3),serde_json::to_value(&pending.command.model_selection).unwrap());
        assert_eq!(row.get::<_,Option<String>>(4),None);assert_eq!(row.get::<_,Option<String>>(5),None);
        let body:Value=c.query_one("SELECT content FROM public.messages WHERE message_id=$1||':input'", &[&pending.command.run_id.as_str()]).await.unwrap().get(0);
        assert_eq!(body["text"], pending.command.message);
        assert_eq!(body["modelSelection"],serde_json::to_value(&pending.command.model_selection).unwrap());
        let frozen=c.query_one("SELECT selected_skill_slugs,artifact_refs FROM openbot_internal.thread_pending_inputs WHERE run_id=$1", &[&pending.command.run_id.as_str()]).await.unwrap();
        assert_eq!(frozen.get::<_,Vec<String>>(0),pending.command.selected_skill_slugs);
        assert_eq!(frozen.get::<_,Vec<String>>(1),pending.command.artifact_refs);
        // Existing begin omits empty optional input arrays.
        assert_eq!(body.get("selectedSkillSlugs"),None);
        assert_eq!(body.get("artifactRefs"),None);
        assert!(c.query_opt("SELECT 1 FROM public.runs WHERE run_id=$1", &[&pending.command.run_id.as_str()]).await.unwrap().is_some());
        drop(c);f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn w08_complete_reopens_and_reports_busy() {
    harness::with_temp_database(
        &harness::admin_config("work_w08"),
        "workw08",
        |config| async move {
            let f = Fixture::new(config, 8).await;
            let model = f.model(CustomModelProtocol::OpenaiResponses).await;
            let (first, pending) = queued(&f, 1, &model).await;
            let rt = runtime(&f);
            let claim = rt.claim_dispatch().await.unwrap().unwrap();
            assert_eq!(claim.lease().run_id(), &first.command.run_id);
            let lease = rt.acknowledge_dispatch(&claim).await.unwrap();
            assert!(matches!(
                f.directory
                    .complete_thread(&auth(), &first.command.thread_id)
                    .await,
                Err(ThreadDirectoryError::ThreadNotIdle {
                    foreground: Some(ThreadForegroundRunState::Running),
                    pending_inputs: 1
                })
            ));
            f.directory
                .stop_thread_work(
                    &auth(),
                    &first.command.thread_id,
                    Some(&first.command.run_id),
                )
                .await
                .unwrap();
            assert!(matches!(
                f.directory
                    .complete_thread(&auth(), &first.command.thread_id)
                    .await,
                Err(ThreadDirectoryError::ThreadNotIdle {
                    foreground: Some(ThreadForegroundRunState::Cancelling),
                    pending_inputs: 1
                })
            ));
            rt.finish_run(&lease, lease.next_event_sequence(), RunTerminal::Cancelled)
                .await
                .unwrap();
            assert!(matches!(
                f.directory
                    .complete_thread(&auth(), &first.command.thread_id)
                    .await,
                Err(ThreadDirectoryError::ThreadNotIdle {
                    foreground: None,
                    pending_inputs: 1
                })
            ));
            f.directory
                .withdraw_pending_input(&auth(), &first.command.thread_id, &pending.command.run_id)
                .await
                .unwrap();
            let done = f
                .directory
                .complete_thread(&auth(), &first.command.thread_id)
                .await
                .unwrap();
            assert_eq!(done.status, ThreadStatusFilter::Archived);
            let c = f.pool.get().await.unwrap();
            assert_eq!(
                c.query_one(
                    "SELECT status FROM public.threads WHERE thread_id=$1",
                    &[&first.command.thread_id.as_str()]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
                "archived"
            );
            drop(c);
            let mut reopened = first.clone();
            reopened.command.run_id = RunId::new("reopen-work");
            f.directory
                .submit_thread_input(reopened.clone(), None)
                .await
                .unwrap();
            let c = f.pool.get().await.unwrap();
            assert_eq!(
                c.query_one(
                    "SELECT status FROM public.threads WHERE thread_id=$1",
                    &[&first.command.thread_id.as_str()]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
                "active"
            );
            drop(c);
            finish(&rt, &reopened.command.run_id, RunTerminal::Completed).await;
            let other = AuthContextBuilder::from_verified_session(
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                ActorId::new("bob"),
                AuthGeneration::new(7),
                false,
            )
            .with_roles([Role::Admin])
            .build();
            assert!(matches!(
                f.directory
                    .complete_thread(&other, &first.command.thread_id)
                    .await,
                Err(ThreadDirectoryError::NotVisible)
            ));
            let channel = f.request(2, true, &model);
            f.directory
                .begin_thread_run_v2(channel.clone())
                .await
                .unwrap();
            assert!(matches!(
                f.directory
                    .complete_thread(&auth(), &channel.command.thread_id)
                    .await,
                Err(ThreadDirectoryError::AnchorUnsupported)
            ));
            drop(rt);
            f.finish().await;
            Ok(())
        },
    )
    .await;
}
