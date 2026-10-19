//! PostgreSQL 17 evidence for atomic conversation snapshot → cursor replay/live → history.

mod harness;

use std::future::poll_fn;
use std::time::Duration as StdDuration;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    AppEventStream, BeginThreadRunRequest, ProviderRemoteProjection, ProviderRemoteProjectionKind,
    RunRuntime, RunSemanticChannel, RunTerminal, ThreadConversationRequest, ThreadDirectory,
    ThreadEventSubscription,
};
use openbot_contracts::command::{
    AppEvent, BeginThreadRun, ThreadForegroundRunState, ThreadRunAnchor, ThreadRunEventKind,
};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

async fn next_event(stream: &mut AppEventStream) -> Result<AppEvent, String> {
    tokio::time::timeout(
        StdDuration::from_secs(3),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    .map_err(|_| "conversation event timed out".to_owned())?
    .ok_or_else(|| "conversation stream ended".to_owned())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn atomic_snapshot_bridges_active_text_cursor_live_terminal_and_materialized_history() {
    let admin = admin_config(
        "atomic_snapshot_bridges_active_text_cursor_live_terminal_and_materialized_history",
    );
    with_temp_database(&admin, "threadconversation", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email) VALUES
                       ('actor','actor@example.test'),('outsider','outsider@example.test');
                     INSERT INTO public.user_roles(user_id,role) VALUES('actor','user');
                     INSERT INTO public.agents(id,name,type,configuration)
                       VALUES('bot-1','Bot One','built_in','{}');
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                     ) VALUES('bot-1',NULL,'Bot One','conversation role','seed','public');
                     INSERT INTO public.channels(id,name,description)
                       VALUES('channel-1','Bot One','Private agent channel.');
                     INSERT INTO public.channel_memberships(channel_id,user_id)
                       VALUES('channel-1','actor');
                     INSERT INTO public.channel_agents(channel_id,agent_id)
                       VALUES('channel-1','bot-1');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let deployment = DeploymentId::new("dep");
            let thread = ThreadIdentity::new(&deployment).mint_from_entropy([0x34; 16]);
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-conversation".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            directory
                .begin_thread_run(BeginThreadRunRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    deployment: deployment.clone(),
                    tenant: TenantId::new("tenant"),
                    actor: ActorId::new("actor"),
                    command: BeginThreadRun {
                        artifact_refs: Vec::new(),
                        model_selection: None,
                        selected_skill_slugs: Vec::new(),
                        thread_id: thread.clone(),
                        run_id: RunId::new("run-1"),
                        bot_id: BotId::new("bot-1"),
                        anchor: ThreadRunAnchor::Channel {
                            channel_id: ChannelId::new("channel-1"),
                        },
                        message: "hello".to_owned(),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            let request = ThreadConversationRequest {
                deployment: deployment.clone(),
                tenant: TenantId::new("tenant"),
                actor: ActorId::new("actor"),
                thread: thread.clone(),
            };
            let started = directory
                .thread_conversation(request.clone())
                .await
                .map_err(|error| error.to_string())?;
            if started.messages.len() != 1
                || started.messages[0].content != "hello"
                || started.active_run_id != Some(RunId::new("run-1"))
                || started.active_run_state != Some(ThreadForegroundRunState::Running)
                || !started.active_run_cancellable
                || !started.active_run_text.is_empty()
                || started.last_event_sequence != Some(0)
            {
                return Err(format!("started snapshot drifted: {started:?}"));
            }

            let runtime = PostgresRunRuntime::new(
                pool.clone(),
                "runtime-conversation".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
                DEFAULT_DISPATCH_CLAIM_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let claim = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "conversation dispatch missing".to_owned())?;
            let lease = runtime
                .acknowledge_dispatch(&claim)
                .await
                .map_err(|error| error.to_string())?;
            runtime
                .append_semantic_chunk(&lease, 1, RunSemanticChannel::Text, "hel")
                .await
                .map_err(|error| error.to_string())?;
            let projection = ProviderRemoteProjection::new(
                ProviderRemoteProjectionKind::State,
                None,
                None,
                serde_json::json!({"phase":"working"}),
            )
            .map_err(|error| error.to_string())?;
            runtime
                .append_remote_projection(&lease, 2, &projection)
                .await
                .map_err(|error| error.to_string())?;
            let partial = directory
                .thread_conversation(request.clone())
                .await
                .map_err(|error| error.to_string())?;
            if partial.active_run_text != "hel" || partial.last_event_sequence != Some(2) {
                return Err(format!("partial snapshot drifted: {partial:?}"));
            }

            let mut events = directory
                .subscribe_thread_events(ThreadEventSubscription {
                    deployment: deployment.clone(),
                    tenant: TenantId::new("tenant"),
                    actor: ActorId::new("actor"),
                    thread: thread.clone(),
                    after_event_sequence: partial.last_event_sequence,
                })
                .await
                .map_err(|error| error.to_string())?;
            runtime
                .append_semantic_chunk(&lease, 3, RunSemanticChannel::Text, "lo")
                .await
                .map_err(|error| error.to_string())?;
            runtime
                .finish_run(&lease, 4, RunTerminal::Completed)
                .await
                .map_err(|error| error.to_string())?;
            match next_event(&mut events).await? {
                AppEvent::ThreadRunEvent(event)
                    if event.event_sequence == 3
                        && event.event_type == ThreadRunEventKind::SemanticChunk => {}
                event => return Err(format!("first live event drifted: {event:?}")),
            }
            match next_event(&mut events).await? {
                AppEvent::ThreadRunEvent(event)
                    if event.event_sequence == 4
                        && event.event_type == ThreadRunEventKind::Completed => {}
                event => return Err(format!("terminal live event drifted: {event:?}")),
            }

            let completed = directory
                .thread_conversation(request)
                .await
                .map_err(|error| error.to_string())?;
            if completed.messages.len() != 2
                || completed.messages[0].content != "hello"
                || completed.messages[1].content != "hello"
                || completed.active_run_id.is_some()
                || completed.active_run_state.is_some()
                || completed.active_run_cancellable
                || !completed.active_run_text.is_empty()
                || completed.last_event_sequence != Some(4)
            {
                return Err(format!("completed snapshot drifted: {completed:?}"));
            }
            let outsider = directory
                .thread_conversation(ThreadConversationRequest {
                    deployment,
                    tenant: TenantId::new("tenant"),
                    actor: ActorId::new("outsider"),
                    thread,
                })
                .await
                .map_err(|error| error.to_string())?;
            if outsider != Default::default() {
                return Err(format!("outsider snapshot was enumerable: {outsider:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
