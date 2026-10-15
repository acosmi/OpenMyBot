//! Channel detail/current native thread projection 的 PostgreSQL 17 证据。

mod harness;

use std::future::poll_fn;
use std::time::Duration as StdDuration;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    AppEventStream, BeginThreadRunRequest, ChannelReadScope, ChannelReader, ThreadDirectory,
    ThreadEventSubscription, ThreadHistoryRequest,
};
use openbot_contracts::command::{AppEvent, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::ChannelRepo;
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

async fn next_event(stream: &mut AppEventStream) -> Result<AppEvent, String> {
    tokio::time::timeout(
        StdDuration::from_secs(3),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    .map_err(|_| "waiting for shared channel thread event timed out".to_owned())?
    .ok_or_else(|| "shared channel thread stream ended".to_owned())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn detail_is_member_only_and_projects_only_the_matching_native_thread() {
    let admin = admin_config("detail_is_member_only_and_projects_only_the_matching_native_thread");
    with_temp_database(&admin, "channeldetail", |config| async move {
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
                       ('actor-a','a@example.test'),
                       ('actor-b','b@example.test'),
                       ('actor-c','c@example.test'),
                       ('actor-d','d@example.test');
                     INSERT INTO public.agents(id,name,type,configuration) VALUES
                       ('bot-a','A','built_in','{}'::jsonb),
                       ('bot-b','B','built_in','{}'::jsonb);
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                     ) VALUES
                       ('bot-a',NULL,'A','role','a','public',NULL),
                       ('bot-b',NULL,'B','role','b','public','2026-08-25T00:00:00Z');
                     INSERT INTO public.channels(id,name,description,created_at) VALUES
                       ('channel-main','Main','','2026-08-26T02:00:00Z'),
                       ('channel-empty','Empty','','2026-08-26T01:00:00Z'),
                       ('channel-other','Other','','2026-08-26T00:00:00Z');
                     INSERT INTO public.channel_memberships(channel_id,user_id) VALUES
                       ('channel-main','actor-a'),('channel-main','actor-c'),
                       ('channel-main','actor-d'),
                       ('channel-empty','actor-a'),
                       ('channel-other','actor-b');
                     INSERT INTO public.channel_agents(channel_id,agent_id) VALUES
                       ('channel-main','bot-b'),('channel-main','bot-a');
                     INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       created_at,updated_at,deleted_at
                     ) VALUES
                       ('thread-match','tenant-a','dep-a','actor-a','channel','channel-main','active',
                        '2026-08-26T02:01:00Z','2026-08-26T02:01:00Z',NULL),
                       ('thread-foreign-deployment','tenant-a','dep-b','actor-a','channel','channel-main','active',
                        '2026-08-26T02:02:00Z','2026-08-26T02:02:00Z',NULL),
                       ('thread-foreign-tenant','tenant-b','dep-a','actor-a','channel','channel-main','active',
                        '2026-08-26T02:03:00Z','2026-08-26T02:03:00Z',NULL),
                       ('thread-shared','tenant-a','dep-a','actor-c','channel','channel-main','active',
                        '2026-08-26T02:04:00Z','2026-08-26T02:04:00Z',NULL),
                       ('thread-deleted','tenant-a','dep-a','actor-a','channel','channel-main','deleted',
                        '2026-08-26T02:05:00Z','2026-08-26T02:05:00Z','2026-08-26T02:05:00Z');
                     INSERT INTO public.thread_memberships(thread_id,user_id) VALUES
                       ('thread-match','actor-a'),
                       ('thread-foreign-deployment','actor-a'),
                       ('thread-foreign-tenant','actor-a'),
                       ('thread-shared','actor-c'),
                       ('thread-deleted','actor-a');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let repo = ChannelRepo::new(pool.clone());
            let scope = ChannelReadScope {
                deployment: DeploymentId::new("dep-a"),
                tenant: TenantId::new("tenant-a"),
                actor: ActorId::new("actor-a"),
            };
            let detail = repo
                .get_visible_channel(&scope, &ChannelId::new("channel-main"))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "member detail missing".to_owned())?;
            let agent_ids: Vec<&str> = detail.agent_ids.iter().map(|id| id.as_str()).collect();
            if detail.id != ChannelId::new("channel-main")
                || detail.name != "Main"
                || agent_ids != ["bot-a", "bot-b"]
                || detail.active
                || detail.thread_id.as_ref().map(|id| id.as_str()) != Some("thread-shared")
            {
                return Err(format!("scoped detail projection drifted: {detail:?}"));
            }
            if repo
                .get_visible_channel(&scope, &ChannelId::new("channel-other"))
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("outsider channel was exposed".to_owned());
            }

            let page = repo
                .list_visible_channels_scoped(&scope, 50, None)
                .await
                .map_err(|error| error.to_string())?;
            if page.len() != 2
                || page[0].id != ChannelId::new("channel-main")
                || page[0].thread_id.as_ref().map(|id| id.as_str()) != Some("thread-shared")
                || page[1].id != ChannelId::new("channel-empty")
                || page[1].thread_id.is_some()
            {
                return Err(format!("scoped roster/native thread drifted: {page:?}"));
            }
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-channel-detail".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            if !directory
                .thread_known(
                    &DeploymentId::new("dep-a"),
                    &TenantId::new("tenant-a"),
                    &ActorId::new("actor-a"),
                    &openbot_contracts::ids::ThreadId::new("thread-shared"),
                )
                .await
                .map_err(|error| error.to_string())?
            {
                return Err("current channel member must see a shared native thread".to_owned());
            }
            directory
                .begin_thread_run(BeginThreadRunRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    deployment: DeploymentId::new("dep-a"),
                    tenant: TenantId::new("tenant-a"),
                    actor: ActorId::new("actor-a"),
                    command: BeginThreadRun {
                        artifact_refs: Vec::new(),
                        model_selection: None,
                        selected_skill_slugs: Vec::new(),
                        thread_id: openbot_contracts::ids::ThreadId::new("thread-shared"),
                        run_id: RunId::new("run-shared-member"),
                        bot_id: BotId::new("bot-a"),
                        anchor: ThreadRunAnchor::Channel {
                            channel_id: ChannelId::new("channel-main"),
                        },
                        message: "shared channel message".to_owned(),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let materialized: bool = client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM public.thread_memberships
                     WHERE thread_id='thread-shared' AND user_id='actor-a')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if !materialized {
                return Err("channel begin did not materialize downstream run membership".to_owned());
            }
            let shared_request = ThreadHistoryRequest {
                deployment: DeploymentId::new("dep-a"),
                tenant: TenantId::new("tenant-a"),
                actor: ActorId::new("actor-d"),
                thread: openbot_contracts::ids::ThreadId::new("thread-shared"),
            };
            let shared_history = directory
                .thread_history(shared_request.clone())
                .await
                .map_err(|error| error.to_string())?;
            if shared_history.messages.len() != 1
                || shared_history.messages[0].content != "shared channel message"
            {
                return Err(format!(
                    "channel-only member did not receive shared history: {shared_history:?}"
                ));
            }
            let mut shared_events = directory
                .subscribe_thread_events(ThreadEventSubscription {
                    deployment: shared_request.deployment.clone(),
                    tenant: shared_request.tenant.clone(),
                    actor: shared_request.actor.clone(),
                    thread: shared_request.thread.clone(),
                    after_event_sequence: None,
                })
                .await
                .map_err(|error| error.to_string())?;
            if !matches!(
                next_event(&mut shared_events).await?,
                AppEvent::ThreadRunEvent(ref event) if event.event_sequence == 0
            ) {
                return Err("channel-only member did not replay event zero".to_owned());
            }
            client
                .execute(
                    "DELETE FROM public.channel_memberships
                     WHERE channel_id='channel-main' AND user_id IN ('actor-a','actor-d')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            match next_event(&mut shared_events).await? {
                AppEvent::ThreadStreamError { code } if code == "not_visible" => {}
                other => {
                    return Err(format!(
                        "revoked channel member stream did not fail closed: {other:?}"
                    ));
                }
            }
            let revoked_history = directory
                .thread_history(shared_request)
                .await
                .map_err(|error| error.to_string())?;
            if !revoked_history.messages.is_empty() {
                return Err("revoked channel member retained history".to_owned());
            }
            if directory
                .thread_known(
                    &DeploymentId::new("dep-a"),
                    &TenantId::new("tenant-a"),
                    &ActorId::new("actor-a"),
                    &openbot_contracts::ids::ThreadId::new("thread-shared"),
                )
                .await
                .map_err(|error| error.to_string())?
                || repo
                    .get_visible_channel(&scope, &ChannelId::new("channel-main"))
                    .await
                    .map_err(|error| error.to_string())?
                    .is_some()
            {
                return Err("revoked channel membership was widened by stale thread membership".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
