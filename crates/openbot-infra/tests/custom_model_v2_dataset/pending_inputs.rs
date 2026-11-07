//! Durable input acceptance using the original v2 dataset fixture and real PostgreSQL.

use super::*;
use openbot_application::{RunRuntime, SubmitThreadInputAttempt};
use openbot_contracts::command::{PendingInputState, ThreadInputOutcome};
use openbot_infra::db::{baseline, native};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};

#[track_caller]
fn accepted(value: Result<SubmitThreadInputAttempt, ThreadDirectoryError>) -> ThreadInputOutcome {
    match value.unwrap() {
        SubmitThreadInputAttempt::Accepted(outcome) => outcome,
        SubmitThreadInputAttempt::NeedsArtifacts => panic!("unexpected material preread"),
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn w01_atomic_start_queue_and_replay() {
    harness::with_temp_database(&harness::admin_config("pending_w01"), "pendingw01", |config| async move {
        let f = Fixture::new(config, 8).await;
        let model = f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        for index in 1..=10 {
            let first = f.request(index, false, &model);
            let (left,right) = tokio::join!(
                f.directory.submit_thread_input(first.clone(), None),
                f.directory.submit_thread_input(first.clone(), None),
            );
            let (ThreadInputOutcome::Started(left),ThreadInputOutcome::Started(right)) = (accepted(left),accepted(right))
                else {panic!("idle duplicate must replay one Run")};
            assert_ne!(left.replayed,right.replayed);
            assert_eq!(left.run_id,right.run_id);
            let page = openbot_application::use_cases::thread::list_bot_threads(
                &f.directory, &auth(), BotId::new("bot"), None, None, None,
            ).await.unwrap();
            let work = page.threads.iter().find(|work| work.thread_id == first.command.thread_id).unwrap();
            assert_eq!(work.title.as_deref(), Some("Exact owned words"));
            assert_eq!(work.pending_inputs, 0);
            let mut queued = first.clone();
            queued.command.run_id = RunId::new(format!("queued-{index}"));
            queued.command.message = format!("frozen follow-up {index}");
            queued.command.selected_skill_slugs = vec!["pending-skill".into()];
            queued.command.artifact_refs = vec![Uuid::now_v7().to_string()];
            let before = f.counts().await;
            let (left,right) = tokio::join!(
                f.directory.submit_thread_input(queued.clone(), None),
                f.directory.submit_thread_input(queued.clone(), None),
            );
            assert_eq!(accepted(left), ThreadInputOutcome::Queued {run_id:queued.command.run_id.clone(),position:1});
            assert_eq!(accepted(right), ThreadInputOutcome::Queued {run_id:queued.command.run_id.clone(),position:1});
            assert_eq!(f.counts().await,before,"queued input created Run business rows");
            let items = f.directory.list_pending_inputs(&auth(),&first.command.thread_id).await.unwrap().items;
            assert_eq!(items.len(),1);
            assert_eq!(items[0].message,queued.command.message);
            assert_eq!(items[0].selected_skill_slugs,queued.command.selected_skill_slugs);
            assert_eq!(items[0].model_selection,queued.command.model_selection);
            assert_eq!(items[0].artifact_refs,queued.command.artifact_refs);
            let c=f.pool.get().await.unwrap();
            let row=c.query_one("SELECT actor_id,auth_generation,anchor_kind FROM openbot_internal.thread_pending_inputs WHERE run_id=$1",
                &[&queued.command.run_id.as_str()]).await.unwrap();
            assert_eq!(row.get::<_,String>(0),"alice");assert_eq!(row.get::<_,i64>(1),7);assert_eq!(row.get::<_,String>(2),"direct_bot");
            drop(c);
            let mut changed=queued.clone();changed.command.message.push('!');
            assert!(matches!(f.directory.submit_thread_input(changed,None).await,Err(ThreadDirectoryError::RequestConflict)));

            let mut competing = f.request(100+index,false,&model);
            let one=competing.clone();competing.command.run_id=RunId::new(format!("competitor-{index}"));
            let (left,right)=tokio::join!(f.directory.submit_thread_input(one,None),f.directory.submit_thread_input(competing,None));
            assert!(matches!((accepted(left),accepted(right)),
                (ThreadInputOutcome::Started(_),ThreadInputOutcome::Queued {position:1,..}) |
                (ThreadInputOutcome::Queued {position:1,..},ThreadInputOutcome::Started(_))));

            // The same submission identity cannot be accepted into both storage paths.
            let identity=RunId::new(format!("mixed-path-identity-{index}"));
            let mut busy=first.clone();busy.command.run_id=identity.clone();
            let mut idle=f.request(200+index,false,&model);idle.command.run_id=identity.clone();
            let (left,right)=tokio::join!(f.directory.submit_thread_input(busy,None),f.directory.submit_thread_input(idle,None));
            assert!(matches!((&left,&right),
                (Ok(SubmitThreadInputAttempt::Accepted(_)),Err(ThreadDirectoryError::RequestConflict)) |
                (Err(ThreadDirectoryError::RequestConflict),Ok(SubmitThreadInputAttempt::Accepted(_)))),
                "mixed-path identity {index}: {left:?} / {right:?}");
            let c=f.pool.get().await.unwrap();
            let accepted_count:i64=c.query_one("SELECT (SELECT count(*) FROM public.runs WHERE run_id=$1)+(SELECT count(*) FROM openbot_internal.thread_pending_inputs WHERE run_id=$1)",&[&identity.as_str()]).await.unwrap().get(0);
            assert_eq!(accepted_count,1);drop(c);
        }
        f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn w07_pending_capacity_and_withdrawal() {
    harness::with_temp_database(&harness::admin_config("pending_w07"), "pendingw07", |config| async move {
        let f=Fixture::new(config,4).await;
        let model=f.model(CustomModelProtocol::OpenaiResponses).await;
        let first=f.request(1,false,&model);
        assert!(matches!(accepted(f.directory.submit_thread_input(first.clone(),None).await),ThreadInputOutcome::Started(_)));
        let mut inputs=Vec::new();
        for index in 0..20 {
            let mut input=first.clone();input.command.run_id=RunId::new(format!("capacity-{index}"));
            assert!(matches!(accepted(f.directory.submit_thread_input(input.clone(),None).await),ThreadInputOutcome::Queued {position,..} if position==index+1));
            inputs.push(input);
        }
        let c=f.pool.get().await.unwrap();
        c.execute("UPDATE openbot_internal.thread_pending_inputs SET state='held',held_reason='stopped_by_user' WHERE run_id=$1",
            &[&inputs[0].command.run_id.as_str()]).await.unwrap();drop(c);
        let mut overflow=first.clone();overflow.command.run_id=RunId::new("overflow");
        assert!(matches!(f.directory.submit_thread_input(overflow.clone(),None).await,Err(ThreadDirectoryError::PendingInputLimit)));
        assert_eq!(f.directory.list_pending_inputs(&auth(),&first.command.thread_id).await.unwrap().items.len(),20);
        let page = openbot_application::use_cases::thread::list_bot_threads(
            &f.directory, &auth(), BotId::new("bot"), None, None, None,
        ).await.unwrap();
        assert_eq!(page.threads.len(), 1);
        assert_eq!(page.threads[0].pending_inputs, 20);
        assert!(matches!(accepted(f.directory.submit_thread_input(inputs[0].clone(),None).await),ThreadInputOutcome::Queued {..}));
        for input in [&inputs[0],&inputs[1]] {
            let receipt=f.directory.withdraw_pending_input(&auth(),&first.command.thread_id,&input.command.run_id).await.unwrap();
            assert_eq!(receipt.state,PendingInputState::Withdrawn);
            assert_eq!(f.directory.withdraw_pending_input(&auth(),&first.command.thread_id,&input.command.run_id).await.unwrap(),receipt);
            // An exact submission replay must never resurrect a withdrawn input.
            accepted(f.directory.submit_thread_input(input.clone(),None).await);
        }
        let c=f.pool.get().await.unwrap();
        c.execute("UPDATE openbot_internal.thread_pending_inputs SET state='dispatched' WHERE run_id=$1",&[&inputs[2].command.run_id.as_str()]).await.unwrap();
        drop(c);
        assert!(matches!(f.directory.withdraw_pending_input(&auth(),&first.command.thread_id,&inputs[2].command.run_id).await,Err(ThreadDirectoryError::PendingInputState)));
        assert_eq!(f.directory.list_pending_inputs(&auth(),&first.command.thread_id).await.unwrap().items.len(),17);
        let page = openbot_application::use_cases::thread::list_bot_threads(
            &f.directory, &auth(), BotId::new("bot"), None, None, None,
        ).await.unwrap();
        assert_eq!(page.threads.len(), 1);
        assert_eq!(page.threads[0].pending_inputs, 17);
        assert!(matches!(accepted(f.directory.submit_thread_input(overflow,None).await),ThreadInputOutcome::Queued {..}));
        f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn pending_input_migration_and_visibility() {
    harness::with_temp_database(&harness::admin_config("pending_upgrade"), "pendingupgrade", |config| async move {
        let p=pool::connect(&config).await.unwrap();let mut c=p.get().await.unwrap();
        baseline::apply(&c).await.unwrap();native::apply_through(&mut c,52).await.unwrap();
        assert!(c.query_one("SELECT to_regclass('openbot_internal.thread_pending_inputs') IS NULL",&[]).await.unwrap().get::<_,bool>(0));
        assert_eq!(native::apply(&mut c).await.unwrap(),native::ApplyOutcome::Applied);
        assert_eq!(native::apply(&mut c).await.unwrap(),native::ApplyOutcome::AlreadyApplied);
        // The explicit historical target must not admit a database with the new suffix.
        assert!(native::apply_through(&mut c,52).await.is_err());
        let row=c.query_one("SELECT name,checksum FROM openbot_internal.schema_migrations WHERE version=$1",&[&native::NATIVE_0053_VERSION]).await.unwrap();
        assert_eq!(row.get::<_,String>(0),native::NATIVE_0053_NAME);
        assert_eq!(row.get::<_,String>(1),native::native_0053_checksum());
        assert_eq!(c.query_one("SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid='openbot_internal.thread_pending_inputs'::regclass AND NOT tgisinternal",&[]).await.unwrap().get::<_,i64>(0),0);
        drop(c);p.close();Ok(())
    }).await;
    harness::with_temp_database(&harness::admin_config("pending_visibility"), "pendingvisible", |config| async move {
        let f=Fixture::new(config,4).await;
        let model=f.model(CustomModelProtocol::AnthropicMessages).await;
        let first=f.request(1,false,&model);
        accepted(f.directory.submit_thread_input(first.clone(),None).await);
        let runtime=PostgresRunRuntime::new(f.pool.clone(),"owned-v2-runtime".into(),time::Duration::seconds(30),DEFAULT_DISPATCH_CLAIM_DURATION).unwrap();
        let claim=runtime.claim_dispatch().await.unwrap().unwrap();
        let lease=runtime.acknowledge_dispatch(&claim).await.unwrap();
        runtime.finish_run(&lease,1,openbot_application::RunTerminal::Failed(openbot_application::RunFailureCode::ProviderUnavailable)).await.unwrap();
        let c=f.pool.get().await.unwrap();
        c.execute("UPDATE public.threads SET status='archived' WHERE thread_id=$1",&[&first.command.thread_id.as_str()]).await.unwrap();
        c.execute("UPDATE public.thread_leases SET owner_id='other-runtime',expires_at=clock_timestamp()+interval '1 minute' WHERE thread_id=$1",&[&first.command.thread_id.as_str()]).await.unwrap();drop(c);
        let mut next=first.clone();next.command.run_id=RunId::new("lease-conflict-retained");
        assert!(matches!(accepted(f.directory.submit_thread_input(next.clone(),None).await),ThreadInputOutcome::Queued {position:1,..}));
        let c=f.pool.get().await.unwrap();
        assert_eq!(c.query_one("SELECT status FROM public.threads WHERE thread_id=$1",&[&first.command.thread_id.as_str()]).await.unwrap().get::<_,String>(0),"active");
        assert!(c.query_opt("SELECT 1 FROM public.runs WHERE run_id=$1",&[&next.command.run_id.as_str()]).await.unwrap().is_none());
        c.execute("UPDATE public.thread_leases SET expires_at=clock_timestamp() WHERE thread_id=$1",&[&first.command.thread_id.as_str()]).await.unwrap();
        c.execute("UPDATE openbot_internal.thread_pending_inputs SET state='held',held_reason='stopped_by_user' WHERE run_id=$1",&[&next.command.run_id.as_str()]).await.unwrap();drop(c);
        let mut held_follower=first.clone();held_follower.command.run_id=RunId::new("behind-held");
        assert!(matches!(accepted(f.directory.submit_thread_input(held_follower.clone(),None).await),ThreadInputOutcome::Queued {position:1,..}));
        f.directory.withdraw_pending_input(&auth(),&first.command.thread_id,&next.command.run_id).await.unwrap();
        f.directory.withdraw_pending_input(&auth(),&first.command.thread_id,&held_follower.command.run_id).await.unwrap();
        let mut c=f.pool.get().await.unwrap();
        let tx=c.transaction().await.unwrap();
        let operation=Uuid::now_v7().to_string();let request_id=Uuid::now_v7().to_string();
        let at:time::OffsetDateTime=tx.query_one("SELECT clock_timestamp()",&[]).await.unwrap().get(0);
        assert_eq!(tx.execute("INSERT INTO openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at) SELECT deployment_id,tenant_id,thread_id,1,'stop_clear',$2,$3,'alice',7,anchor_kind,anchor_id,thread_created_at,$4 FROM openbot_internal.thread_history_heads WHERE thread_id=$1",&[&first.command.thread_id.as_str(),&operation,&request_id,&at]).await.unwrap(),1);
        tx.execute("UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id=$2,closure_request_id=$3,closure_actor_id='alice',closure_auth_generation=7,closed_at=$4 WHERE thread_id=$1",&[&first.command.thread_id.as_str(),&operation,&request_id,&at]).await.unwrap();
        tx.commit().await.unwrap();drop(c);
        let before=f.counts().await;
        let mut clearing=first.clone();clearing.command.run_id=RunId::new("behind-clear");
        assert!(matches!(accepted(f.directory.submit_thread_input(clearing,None).await),ThreadInputOutcome::Queued {position:1,..}));
        assert_eq!(f.counts().await,before);
        let bob=AuthContextBuilder::from_verified_session(DeploymentId::new(DEP),TenantId::new(TENANT),ActorId::new("bob"),AuthGeneration::new(7),false).with_roles([Role::Admin]).build();
        assert!(matches!(f.directory.list_pending_inputs(&bob,&first.command.thread_id).await,Err(ThreadDirectoryError::NotVisible)));
        let channel=f.request(2,true,&model);f.directory.begin_thread_run_v2(channel.clone()).await.unwrap();
        assert!(matches!(f.directory.list_pending_inputs(&auth(),&channel.command.thread_id).await,Err(ThreadDirectoryError::AnchorUnsupported)));
        let mut channel_input=channel.clone();channel_input.command.run_id=RunId::new("channel-input");channel_input.command.anchor=ThreadRunAnchor::DirectBot;
        assert!(matches!(f.directory.submit_thread_input(channel_input,None).await,Err(ThreadDirectoryError::AnchorUnsupported)));
        assert!(matches!(f.directory.withdraw_pending_input(&auth(),&channel.command.thread_id,&next.command.run_id).await,Err(ThreadDirectoryError::AnchorUnsupported)));
        let c=f.pool.get().await.unwrap();c.execute("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp() WHERE thread_id=$1",&[&first.command.thread_id.as_str()]).await.unwrap();drop(c);
        assert!(matches!(f.directory.list_pending_inputs(&auth(),&first.command.thread_id).await,Err(ThreadDirectoryError::NotVisible)));
        assert!(matches!(f.directory.submit_thread_input(next,None).await,Err(ThreadDirectoryError::NotVisible)));
        drop(runtime);f.finish().await;Ok(())
    }).await;
}
