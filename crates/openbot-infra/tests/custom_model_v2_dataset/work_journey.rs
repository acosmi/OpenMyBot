//! Two-work control journey over the real application and owned PostgreSQL.
//! Runtime terminals are driven by this test, without a provider or browser.

use super::*;
use openbot_application::RunTerminal;
use openbot_contracts::command::{
    AppCommand, AppReply, PendingInputState, ThreadInputOutcome, ThreadRunCancellationState,
    ThreadStatusFilter,
};
use openbot_contracts::error::AppError;

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn two_work_journey_preserves_held_inputs_and_other_work() {
    harness::with_temp_database(
        &harness::admin_config("work_journey"),
        "workjourney",
        |config| async move {
            let f = Fixture::new(config, 8).await;
            let model = f.model(CustomModelProtocol::OpenaiResponses).await;
            let mut a = f.request(501, false, &model);
            a.command.message = "Work A: make the requested change".into();
            let mut b = f.request(502, false, &model);
            b.command.message = "Work B: keep its independent instructions".into();
            let app = &f.assembly.application;
            let runtime = f.assembly.run_runtime.as_ref();

            for input in [&a, &b] {
                let reply = app
                    .execute(auth(), AppCommand::SubmitThreadInput(input.command.clone()))
                    .await
                    .unwrap();
                let AppReply::ThreadInputOutcome(ThreadInputOutcome::Started(started)) = reply else {
                    panic!("an idle work must start")
                };
                assert_eq!(started.run_id, input.command.run_id);
            }
            let claim_a = runtime.claim_dispatch().await.unwrap().unwrap();
            assert_eq!(claim_a.lease().run_id(), &a.command.run_id);
            let lease_a = runtime.acknowledge_dispatch(&claim_a).await.unwrap();
            let claim_b = runtime.claim_dispatch().await.unwrap().unwrap();
            assert_eq!(claim_b.lease().run_id(), &b.command.run_id);
            let lease_b = runtime.acknowledge_dispatch(&claim_b).await.unwrap();

            let mut b_queued = b.command.clone();
            b_queued.run_id = RunId::new("journey-b-queued");
            b_queued.message = "Work B: a queued follow-up that A must not touch".into();
            assert!(matches!(app.execute(auth(), AppCommand::SubmitThreadInput(b_queued.clone())).await.unwrap(),
                AppReply::ThreadInputOutcome(ThreadInputOutcome::Queued { .. })));

            let b_snapshot = "SELECT jsonb_build_object('thread',to_jsonb(t),'run',to_jsonb(r),\
                 'messages',(SELECT jsonb_agg(to_jsonb(m) ORDER BY seq) FROM public.messages m WHERE m.thread_id=t.thread_id),\
                 'members',(SELECT jsonb_agg(to_jsonb(tm) ORDER BY user_id) FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id),\
                 'pending',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.run_id) FROM openbot_internal.thread_pending_inputs p WHERE p.thread_id=t.thread_id),\
                 'cancel_outbox',(SELECT count(*) FROM public.outbox o WHERE o.aggregate_id=r.run_id AND o.destination='agent_run_cancel')) \
                 FROM public.threads t JOIN public.runs r ON r.thread_id=t.thread_id WHERE r.run_id=$1";
            let c = f.pool.get().await.unwrap();
            let b_before: Value = c.query_one(b_snapshot, &[&b.command.run_id.as_str()]).await.unwrap().get(0);
            assert_eq!(b_before["pending"][0]["state"], "pending");
            assert_eq!(b_before["cancel_outbox"], 0);
            drop(c);

            let mut held = Vec::new();
            for (run_id, message) in [
                ("journey-held-1", "A: preserve the first supplement"),
                ("journey-held-2", "A: keep the second supplement held"),
            ] {
                let mut input = a.command.clone();
                input.run_id = RunId::new(run_id);
                input.message = message.into();
                let reply = app
                    .execute(auth(), AppCommand::SubmitThreadInput(input.clone()))
                    .await
                    .unwrap();
                assert!(matches!(reply, AppReply::ThreadInputOutcome(ThreadInputOutcome::Queued { .. })));
                held.push(input);
            }

            // A fresh directory reads committed inputs; this is not a process restart.
            let reopened = PostgresThreadDirectory::with_runtime(
                f.pool.clone(),
                f.config.clone(),
                "owned-v2-runtime".into(),
                time::Duration::seconds(30),
            )
            .unwrap()
            .with_model_dataset_binding(f.binding.clone())
            .unwrap();
            let reread = reopened
                .list_pending_inputs(&auth(), &a.command.thread_id)
                .await
                .unwrap();
            assert_eq!(reread.items.len(), 2);
            for (item, input) in reread.items.iter().zip(&held) {
                assert_eq!(item.run_id, input.run_id);
                assert_eq!(item.message, input.message);
                assert_eq!(item.model_selection, input.model_selection);
            }
            let AppReply::BotThreadPage(page) = app
                .execute(auth(), AppCommand::ListBotThreads {
                    bot_id: BotId::new("bot"), status: None, cursor: None, limit: Some(100),
                })
                .await
                .unwrap() else { panic!("work list reply required") };
            assert_eq!(page.threads.len(), 2);
            assert_eq!(page.threads.iter().find(|row| row.thread_id == a.command.thread_id).unwrap().pending_inputs, 2);
            assert_eq!(page.threads.iter().find(|row| row.thread_id == b.command.thread_id).unwrap().pending_inputs, 1);

            let AppReply::ThreadWorkStopped(stopped) = app
                .execute(auth(), AppCommand::StopThreadWork {
                    thread_id: a.command.thread_id.clone(), run_id: Some(a.command.run_id.clone()),
                })
                .await
                .unwrap() else { panic!("stop receipt required") };
            assert_eq!(stopped.held, 2);
            assert_eq!(stopped.cancellation.unwrap().state, ThreadRunCancellationState::Requested);
            runtime
                .finish_run(&lease_a, lease_a.next_event_sequence(), RunTerminal::Cancelled)
                .await
                .unwrap();
            assert!(matches!(app.execute(auth(), AppCommand::CompleteThread {
                thread_id: a.command.thread_id.clone(),
            }).await, Err(AppError::ThreadNotIdle { .. })));

            let mut continued = a.command.clone();
            continued.run_id = RunId::new("journey-after-human-edit");
            continued.message = "A: the human edit is done; continue with this requirement".into();
            assert!(matches!(app.execute(auth(), AppCommand::SubmitThreadInput(continued.clone())).await.unwrap(),
                AppReply::ThreadInputOutcome(ThreadInputOutcome::Started(_))));
            let claim = runtime.claim_dispatch().await.unwrap().unwrap();
            assert_eq!(claim.lease().run_id(), &continued.run_id);
            let lease = runtime.acknowledge_dispatch(&claim).await.unwrap();

            let mut follower = continued.clone();
            follower.run_id = RunId::new("journey-new-follow-up");
            follower.message = "A: this fresh requirement precedes the released supplement".into();
            assert!(matches!(app.execute(auth(), AppCommand::SubmitThreadInput(follower.clone())).await.unwrap(),
                AppReply::ThreadInputOutcome(ThreadInputOutcome::Queued { position: 1, .. })));
            let AppReply::PendingInputState(released) = app.execute(auth(), AppCommand::ReleasePendingInput {
                thread_id: a.command.thread_id.clone(), run_id: held[0].run_id.clone(),
            }).await.unwrap() else { panic!("release receipt required") };
            assert_eq!(released.state, PendingInputState::Pending);
            let pending = reopened.list_pending_inputs(&auth(), &a.command.thread_id).await.unwrap();
            assert_eq!(pending.items.iter().filter(|item| item.state == PendingInputState::Pending)
                .map(|item| &item.run_id).collect::<Vec<_>>(), vec![&follower.run_id, &held[0].run_id]);
            assert_eq!(pending.items.iter().find(|item| item.run_id == held[1].run_id).unwrap().state, PendingInputState::Held);

            runtime.finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed).await.unwrap();
            for expected in [&follower, &held[0]] {
                let claim = runtime.claim_dispatch().await.unwrap().unwrap();
                assert_eq!(claim.lease().run_id(), &expected.run_id);
                let lease = runtime.acknowledge_dispatch(&claim).await.unwrap();
                let c = f.pool.get().await.unwrap();
                let body: Value = c.query_one("SELECT content FROM public.messages WHERE message_id=$1||':input'",
                    &[&expected.run_id.as_str()]).await.unwrap().get(0);
                assert_eq!(body["text"], expected.message);
                drop(c);
                runtime.finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed).await.unwrap();
            }
            assert!(runtime.claim_dispatch().await.unwrap().is_none(), "unreleased held input must never start");
            let AppReply::PendingInputState(withdrawn) = app.execute(auth(), AppCommand::WithdrawPendingInput {
                thread_id: a.command.thread_id.clone(), run_id: held[1].run_id.clone(),
            }).await.unwrap() else { panic!("withdraw receipt required") };
            assert_eq!(withdrawn.state, PendingInputState::Withdrawn);
            let AppReply::ThreadCompleted(done) = app.execute(auth(), AppCommand::CompleteThread {
                thread_id: a.command.thread_id.clone(),
            }).await.unwrap() else { panic!("completion receipt required") };
            assert_eq!(done.status, ThreadStatusFilter::Archived);

            let mut next = continued.clone();
            next.run_id = RunId::new("journey-reopen-archived-work");
            next.message = "A: a new request reopens the completed work".into();
            app.execute(auth(), AppCommand::SubmitThreadInput(next)).await.unwrap();
            let c = f.pool.get().await.unwrap();
            assert_eq!(c.query_one("SELECT status FROM public.threads WHERE thread_id=$1",
                &[&a.command.thread_id.as_str()]).await.unwrap().get::<_, String>(0), "active");
            let b_after: Value = c.query_one(b_snapshot, &[&b.command.run_id.as_str()]).await.unwrap().get(0);
            assert_eq!(b_after, b_before, "A must not modify B's Run, queue, thread or permissions");
            assert_eq!(c.query_one("SELECT count(*) FROM public.runs WHERE run_id=$1",
                &[&held[1].run_id.as_str()]).await.unwrap().get::<_, i64>(0), 0);
            drop(c);
            runtime.finish_run(&lease_b, lease_b.next_event_sequence(), RunTerminal::Completed).await.unwrap();
            let c = f.pool.get().await.unwrap();
            assert_eq!(c.query_one("SELECT state FROM openbot_internal.thread_pending_inputs WHERE run_id=$1",
                &[&b_queued.run_id.as_str()]).await.unwrap().get::<_, String>(0), "dispatched");
            drop(c);
            drop(reopened);
            f.finish().await;
            Ok(())
        },
    )
    .await;
}
