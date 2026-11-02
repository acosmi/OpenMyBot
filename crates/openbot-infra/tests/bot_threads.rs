//! Actor-scoped directory, title and foreground projection checks against isolated PostgreSQL.

mod harness;

use openbot_application::use_cases::thread::{list_bot_threads, set_thread_title};
use openbot_application::{
    BeginThreadRunRequest, RunExecutionLease, RunFailureCode, RunRuntime, RunTerminal,
    ThreadDirectory,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor, ThreadStatusFilter};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

fn auth(actor: &str) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("dep"),
        TenantId::new("tenant"),
        ActorId::new(actor),
        AuthGeneration::new(0),
        false,
    )
    .with_roles([Role::User])
    .build()
}

async fn fixture(
    config: pool::DatabaseConfig,
) -> (
    pool::DatabasePool,
    PostgresThreadDirectory,
    PostgresRunRuntime,
) {
    let pool = pool::connect(&config).await.unwrap();
    let mut client = pool.get().await.unwrap();
    baseline::apply(&client).await.unwrap();
    native::apply(&mut client).await.unwrap();
    client.batch_execute(
        "INSERT INTO public.users(id,email) VALUES('actor','actor@example.test'),('other','other@example.test');
         INSERT INTO public.user_roles(user_id,role) VALUES('actor','user'),('other','user');
         INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
           VALUES('01900000-0000-7000-8000-000000000001','different-tenant','fixture',repeat('a',64));
         INSERT INTO public.agents(id,name,type,configuration) VALUES
           ('bot','Bot','built_in','{}'),('other-bot','Other','built_in','{}'),('private-bot','Private','built_in','{}'),('foreign-bot','Foreign','built_in','{}');
         UPDATE public.agents SET package_id='01900000-0000-7000-8000-000000000001' WHERE id='foreign-bot';
         INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES
           ('bot',NULL,'Bot','','bot','public'),('other-bot',NULL,'Other','','other','public'),
           ('private-bot','other','Private','','private','private'),('foreign-bot',NULL,'Foreign','','foreign','public');
         INSERT INTO public.channels(id,name,description) VALUES('channel','Channel','');
         INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','actor');
         INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');"
    ).await.unwrap();
    drop(client);
    let directory = PostgresThreadDirectory::with_runtime(
        pool.clone(),
        config,
        "bot-directory-test".into(),
        DEFAULT_THREAD_LEASE_DURATION,
    )
    .unwrap();
    let runtime = PostgresRunRuntime::new(
        pool.clone(),
        "bot-directory-test".into(),
        DEFAULT_THREAD_LEASE_DURATION,
        DEFAULT_DISPATCH_CLAIM_DURATION,
    )
    .unwrap();
    (pool, directory, runtime)
}

async fn begin(
    directory: &PostgresThreadDirectory,
    runtime: &PostgresRunRuntime,
    actor: &AuthContext,
    entropy: u8,
    bot: &str,
    message: &str,
    anchor: ThreadRunAnchor,
) -> (BeginThreadRunRequest, RunExecutionLease) {
    let request = BeginThreadRunRequest {
        deployment: actor.deployment().clone(),
        tenant: actor.tenant().clone(),
        actor: actor.actor().clone(),
        auth_generation: actor.auth_generation(),
        command: BeginThreadRun {
            thread_id: ThreadIdentity::new(actor.deployment()).mint_from_entropy([entropy; 16]),
            run_id: RunId::new(format!("run-{entropy}")),
            bot_id: BotId::new(bot),
            anchor,
            message: message.into(),
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            artifact_refs: Vec::new(),
        },
    };
    directory.begin_thread_run(request.clone()).await.unwrap();
    let claim = runtime.claim_dispatch().await.unwrap().unwrap();
    let lease = runtime.acknowledge_dispatch(&claim).await.unwrap();
    assert_eq!(lease.run_id(), &request.command.run_id);
    (request, lease)
}

#[tokio::test]
#[ignore = "requires an explicitly owned PostgreSQL 17 database"]
async fn direct_bot_threads_scope_visibility_and_keyset_pagination() {
    harness::with_temp_database(&harness::admin_config("bot_thread_directory"), "botthreads", |config| async move {
        let (pool, directory, runtime) = fixture(config).await;
        let actor = auth("actor");
        let mut expected = Vec::new();
        for entropy in 1..=3 {
            expected.push(begin(&directory, &runtime, &actor, entropy, "bot", "work", ThreadRunAnchor::DirectBot).await.0.command.thread_id);
        }
        begin(&directory, &runtime, &actor, 4, "other-bot", "other Bot", ThreadRunAnchor::DirectBot).await;
        begin(&directory, &runtime, &auth("other"), 5, "bot", "other actor", ThreadRunAnchor::DirectBot).await;
        let (archived, archived_lease) = begin(&directory, &runtime, &actor, 6, "bot", "archived", ThreadRunAnchor::DirectBot).await;
        let (deleted, deleted_lease) = begin(&directory, &runtime, &actor, 7, "bot", "deleted", ThreadRunAnchor::DirectBot).await;
        runtime.finish_run(&archived_lease, 1, RunTerminal::Failed(RunFailureCode::ProviderUnavailable)).await.unwrap();
        runtime.finish_run(&deleted_lease, 1, RunTerminal::Failed(RunFailureCode::ProviderUnavailable)).await.unwrap();
        let client = pool.get().await.unwrap();
        client.execute("UPDATE public.threads SET status='archived' WHERE thread_id=$1", &[&archived.command.thread_id.as_str()]).await.unwrap();
        client.execute("UPDATE public.threads SET status='deleted',deleted_at=now() WHERE thread_id=$1", &[&deleted.command.thread_id.as_str()]).await.unwrap();
        // Equal recency makes the identity tie breaker observable across pages.
        client.batch_execute("UPDATE public.threads SET updated_at=(SELECT max(updated_at) FROM public.threads)").await.unwrap();
        drop(client);
        expected.sort_by(|a,b| a.as_str().cmp(b.as_str()));
        let first = list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, Some(2)).await.unwrap();
        assert_eq!(first.threads.iter().map(|t| &t.thread_id).collect::<Vec<_>>(), expected[..2].iter().collect::<Vec<_>>());
        let last = list_bot_threads(&directory, &actor, BotId::new("bot"), None, first.next_cursor, Some(2)).await.unwrap();
        assert_eq!(last.threads.len(), 1);
        assert_eq!(last.threads[0].thread_id, expected[2]);
        assert!(last.next_cursor.is_none());
        let complete = list_bot_threads(&directory, &actor, BotId::new("bot"), Some(ThreadStatusFilter::Archived), None, None).await.unwrap();
        assert_eq!(complete.threads.len(), 1);
        assert_eq!(complete.threads[0].thread_id, archived.command.thread_id);
        let other = list_bot_threads(&directory, &auth("other"), BotId::new("bot"), None, None, None).await.unwrap();
        assert_eq!(other.threads.len(), 1);
        for bot in ["missing", "private-bot", "foreign-bot"] {
            assert_eq!(list_bot_threads(&directory, &actor, BotId::new(bot), None, None, None).await, Err(AppError::NotVisible));
        }
        for limit in [0, 101] {
            assert_eq!(list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, Some(limit)).await, Err(AppError::MalformedPayload { field: "limit" }));
        }
        assert_eq!(list_bot_threads(&directory, &actor, BotId::new("bot"), None, Some("invalid".into()), None).await, Err(AppError::MalformedPayload { field: "cursor" }));
        let client = pool.get().await.unwrap();
        client.execute("UPDATE public.users SET auth_generation=1 WHERE id='actor'", &[]).await.unwrap();
        drop(client);
        assert_eq!(list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, None).await, Err(AppError::NotVisible));
        pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an explicitly owned PostgreSQL 17 database"]
async fn thread_titles_default_and_rename_bounds() {
    harness::with_temp_database(&harness::admin_config("bot_thread_titles"), "bottitles", |config| async move {
        let (pool, directory, runtime) = fixture(config).await;
        let actor = auth("actor");
        let message = format!("\u{2003}{} \nnot the title", "😀".repeat(121));
        let (first, first_lease) = begin(&directory, &runtime, &actor, 11, "bot", &message, ThreadRunAnchor::DirectBot).await;
        let page = list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, None).await.unwrap();
        assert_eq!(page.threads[0].title, Some("😀".repeat(120)));
        let renamed = set_thread_title(&directory, &actor, first.command.thread_id.clone(), "\u{2003}renamed\u{2003}".into()).await.unwrap();
        assert_eq!(renamed.title, "renamed");
        let again = directory.begin_thread_run(first.clone()).await.unwrap();
        assert!(again.replayed);
        for bad in ["".into(), "  ".into(), "x\ny".into(), "x\ty".into(), "a".repeat(121), "😀".repeat(121)] {
            assert_eq!(set_thread_title(&directory, &actor, first.command.thread_id.clone(), bad).await, Err(AppError::MalformedPayload { field: "title" }));
        }
        assert_eq!(set_thread_title(&directory, &actor, first.command.thread_id.clone(), "😀".repeat(120)).await.unwrap().title.len(), 480);
        assert_eq!(set_thread_title(&directory, &auth("other"), first.command.thread_id.clone(), "not mine".into()).await, Err(AppError::NotVisible));
        runtime.finish_run(&first_lease, 1, RunTerminal::Failed(RunFailureCode::ProviderUnavailable)).await.unwrap();
        // Historical null titles can have an injected user-role artifact frame before the input.
        let (legacy, legacy_lease) = begin(&directory, &runtime, &actor, 12, "bot", "Human task title\nDetails", ThreadRunAnchor::DirectBot).await;
        runtime.finish_run(&legacy_lease, 1, RunTerminal::Failed(RunFailureCode::ProviderUnavailable)).await.unwrap();
        let mut client = pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        let input_id = format!("{}:input", legacy.command.run_id);
        tx.execute("UPDATE public.messages SET seq=1 WHERE message_id=$1", &[&input_id]).await.unwrap();
        let injected = serde_json::json!({"text":"Injected material must not become the title", "artifactRef":{"artifactId":"01900000-0000-7000-8000-000000000002"}});
        tx.execute("INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at) SELECT $1,thread_id,0,'user',$2,$3,run_id,actor_id,created_at FROM public.messages WHERE message_id=$4",
            &[&format!("{}:artifact_ref:0", legacy.command.run_id), &injected, &"Injected material must not become the title", &input_id]).await.unwrap();
        tx.execute("UPDATE public.threads SET title=NULL,next_message_seq=2 WHERE thread_id=$1", &[&legacy.command.thread_id.as_str()]).await.unwrap();
        tx.commit().await.unwrap();drop(client);
        let mut legacy_next = legacy.clone();
        legacy_next.command.run_id = RunId::new("legacy-follow-up");
        legacy_next.command.message = "A later request".into();
        directory.begin_thread_run(legacy_next).await.unwrap();
        let client = pool.get().await.unwrap();
        assert_eq!(client.query_one("SELECT title FROM public.threads WHERE thread_id=$1", &[&legacy.command.thread_id.as_str()]).await.unwrap().get::<_,String>(0), "Human task title");
        drop(client);
        let client = pool.get().await.unwrap();
        let before:time::OffsetDateTime = client.query_one("UPDATE public.threads SET title=NULL,updated_at=created_at WHERE thread_id=$1 RETURNING updated_at", &[&first.command.thread_id.as_str()]).await.unwrap().get(0);
        drop(client);
        let mut second = first.clone();
        second.command.run_id = RunId::new("second");
        second.command.message = "later input must not replace the original default".into();
        directory.begin_thread_run(second).await.unwrap();
        let page = list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, None).await.unwrap();
        assert_eq!(page.threads[0].title, Some("😀".repeat(120)));
        assert!(page.threads[0].updated_at > before);
        set_thread_title(&directory, &actor, first.command.thread_id.clone(), "kept".into()).await.unwrap();
        assert!(directory.begin_thread_run(first).await.unwrap().replayed);
        let page = list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, None).await.unwrap();
        assert_eq!(page.threads[0].title.as_deref(), Some("kept"));
        pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an explicitly owned PostgreSQL 17 database"]
async fn bot_thread_foreground_projection_and_channel_refusal() {
    use openbot_application::CancelThreadRunRequest;
    use openbot_contracts::command::{CancelThreadRun, ThreadForegroundRunState};
    harness::with_temp_database(
        &harness::admin_config("bot_thread_projection"),
        "botprojection",
        |config| async move {
            let (pool, directory, runtime) = fixture(config).await;
            let actor = auth("actor");
            let (first, _) = begin(
                &directory,
                &runtime,
                &actor,
                21,
                "bot",
                "running",
                ThreadRunAnchor::DirectBot,
            )
            .await;
            let page = list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, None)
                .await
                .unwrap();
            let foreground = page.threads[0].foreground.as_ref().unwrap();
            assert_eq!(foreground.state, ThreadForegroundRunState::Running);
            assert_eq!(foreground.run_id, first.command.run_id);
            directory
                .cancel_thread_run(CancelThreadRunRequest {
                    deployment: actor.deployment().clone(),
                    tenant: actor.tenant().clone(),
                    actor: actor.actor().clone(),
                    command: CancelThreadRun {
                        thread_id: first.command.thread_id.clone(),
                        run_id: first.command.run_id,
                    },
                })
                .await
                .unwrap();
            assert_eq!(
                list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, None)
                    .await
                    .unwrap()
                    .threads[0]
                    .foreground
                    .as_ref()
                    .unwrap()
                    .state,
                ThreadForegroundRunState::Cancelling
            );
            let (_, rr_lease) = begin(
                &directory,
                &runtime,
                &actor,
                22,
                "bot",
                "unknown",
                ThreadRunAnchor::DirectBot,
            )
            .await;
            let (queued, _) = begin(
                &directory,
                &runtime,
                &actor,
                23,
                "bot",
                "queued",
                ThreadRunAnchor::DirectBot,
            )
            .await;
            let (channel, _) = begin(
                &directory,
                &runtime,
                &actor,
                24,
                "bot",
                "channel",
                ThreadRunAnchor::Channel {
                    channel_id: openbot_contracts::ids::ChannelId::new("channel"),
                },
            )
            .await;
            runtime
                .finish_run(
                    &rr_lease,
                    1,
                    RunTerminal::ReconciliationRequired(RunFailureCode::ProviderCommitUnknown),
                )
                .await
                .unwrap();
            let client = pool.get().await.unwrap();
            client
                .execute(
                    "UPDATE public.runs SET status='queued',started_at=NULL WHERE run_id=$1",
                    &[&queued.command.run_id.as_str()],
                )
                .await
                .unwrap();
            drop(client);
            let page = list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, None)
                .await
                .unwrap();
            assert_eq!(page.threads.len(), 3);
            assert!(
                page.threads
                    .iter()
                    .any(|t| t.foreground.as_ref().unwrap().state
                        == ThreadForegroundRunState::ReconciliationRequired)
            );
            assert!(
                page.threads
                    .iter()
                    .any(|t| t.foreground.as_ref().unwrap().state
                        == ThreadForegroundRunState::Queued)
            );
            let refusal = set_thread_title(
                &directory,
                &actor,
                channel.command.thread_id,
                "channel title".into(),
            )
            .await
            .unwrap_err();
            assert_eq!(refusal.code().as_str(), "anchor_unsupported");
            assert_eq!(refusal.http_status(), 400);
            let client = pool.get().await.unwrap();
            client
                .batch_execute("ALTER TABLE public.thread_run_occupancy DISABLE TRIGGER USER")
                .await
                .unwrap();
            client
                .execute(
                    "DELETE FROM public.thread_run_occupancy WHERE thread_id=$1",
                    &[&queued.command.thread_id.as_str()],
                )
                .await
                .unwrap();
            client
                .batch_execute("ALTER TABLE public.thread_run_occupancy ENABLE TRIGGER USER")
                .await
                .unwrap();
            drop(client);
            assert_eq!(
                list_bot_threads(&directory, &actor, BotId::new("bot"), None, None, None)
                    .await
                    .unwrap_err()
                    .code()
                    .as_str(),
                "dependency_unavailable"
            );
            pool.close();
            Ok(())
        },
    )
    .await;
}
