//! Channel roster activity 的 PostgreSQL 17 事务、LISTEN/NOTIFY 与动态 membership 证据。

mod harness;

use std::future::poll_fn;
use std::time::Duration as StdDuration;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    AppEventStream, BeginThreadRunRequest, ChannelActivitySubscription, ChannelReader, RunRuntime,
    RunSemanticChannel, RunTerminal, ThreadDirectory, ThreadDirectoryError,
};
use openbot_contracts::command::{AppEvent, BeginThreadRun, ChannelActivityEvent, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::ChannelRepo;
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

async fn next_activity(
    label: &'static str,
    stream: &mut AppEventStream,
) -> Result<ChannelActivityEvent, String> {
    let event = tokio::time::timeout(
        StdDuration::from_secs(5),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    .map_err(|_| format!("{label}: 等待 channel activity 超时"))?
    .ok_or_else(|| format!("{label}: channel activity stream 提前结束"))?;
    match event {
        AppEvent::ChannelActivity(event) => Ok(event),
        other => Err(format!("{label}: 收到非 channel activity：{other:?}")),
    }
}

async fn expect_no_activity(
    label: &'static str,
    stream: &mut AppEventStream,
) -> Result<(), String> {
    match tokio::time::timeout(
        StdDuration::from_secs(1),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    {
        Err(_) => Ok(()),
        Ok(None) => Err(format!("{label}: channel activity stream 提前结束")),
        Ok(Some(event)) => Err(format!("{label}: 不应收到 event：{event:?}")),
    }
}

async fn expect_listener_count(
    pool: &openbot_infra::db::pool::DatabasePool,
    expected: i64,
) -> Result<(), String> {
    for _ in 0..50 {
        let client = pool.get().await.map_err(|error| error.to_string())?;
        let actual: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM pg_stat_activity
                 WHERE application_name='channel-activity-listener'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?
            .try_get(0)
            .map_err(|error| error.to_string())?;
        drop(client);
        if actual == expected {
            return Ok(());
        }
        tokio::time::sleep(StdDuration::from_millis(20)).await;
    }
    Err(format!("channel activity LISTEN 连接数未收敛到 {expected}"))
}

fn subscription(actor: &str) -> ChannelActivitySubscription {
    ChannelActivitySubscription {
        deployment: DeploymentId::new("dep-a"),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new(actor),
    }
}

fn request(
    entropy_tail: u64,
    run_id: &str,
    channel_id: &str,
    message: &str,
) -> BeginThreadRunRequest {
    let deployment = DeploymentId::new("dep-a");
    let mut entropy = [0_u8; 16];
    entropy[8..].copy_from_slice(&entropy_tail.to_be_bytes());
    BeginThreadRunRequest {
        auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
        deployment: deployment.clone(),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new("actor-a"),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            thread_id: ThreadIdentity::new(&deployment).mint_from_entropy(entropy),
            run_id: RunId::new(run_id),
            bot_id: BotId::new("bot-1"),
            anchor: ThreadRunAnchor::Channel {
                channel_id: ChannelId::new(channel_id),
            },
            message: message.to_owned(),
        },
    }
}

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    // The unregistered future preview is real legacy input, created before native migration.
    client
        .batch_execute(
            "INSERT INTO public.channels(
               id,name,description,last_message,last_message_at,last_message_agent_id
             ) VALUES
               ('channel-main','Main','activity test',NULL,NULL,NULL),
               ('channel-stale','Stale','stale activity test','future wins',
                '2100-01-01T00:00:00Z',NULL);",
        )
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
               ('actor-c','c@example.test');
             INSERT INTO public.user_roles(user_id,role) VALUES
               ('actor-a','user'),('actor-b','user'),('actor-c','user');
             INSERT INTO public.agents(id,name,type,configuration)
               VALUES
                 ('bot-1','Bot 1','built_in','{}'::jsonb),
                 ('bot-unlinked','Unlinked','built_in','{}'::jsonb);
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES
                 ('bot-1',NULL,'Bot 1','test role','seed','public',NULL),
                 ('bot-unlinked',NULL,'Unlinked','test role','seed-2','public',NULL);
             INSERT INTO public.channel_agents(channel_id,agent_id) VALUES
               ('channel-main','bot-1'),('channel-stale','bot-1');
             INSERT INTO public.channel_memberships(channel_id,user_id) VALUES
               ('channel-main','actor-a'),('channel-main','actor-c'),
               ('channel-stale','actor-a');",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn committed_user_and_assistant_activity_fan_out_by_current_membership() {
    let admin = admin_config("committed_user_and_assistant_activity_fan_out_by_current_membership");
    with_temp_database(&admin, "channelactivity", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config.with_application_name("channel-activity-listener"),
                "runtime-a".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;

            let mut member_a = directory
                .subscribe_channel_activity(subscription("actor-a"))
                .await
                .map_err(|error| error.to_string())?;
            let mut outsider_b = directory
                .subscribe_channel_activity(subscription("actor-b"))
                .await
                .map_err(|error| error.to_string())?;
            let mut member_c = directory
                .subscribe_channel_activity(subscription("actor-c"))
                .await
                .map_err(|error| error.to_string())?;
            let mut member_c_second = directory
                .subscribe_channel_activity(subscription("actor-c"))
                .await
                .map_err(|error| error.to_string())?;
            expect_listener_count(&pool, 4).await?;

            let mut outsider_write = request(
                1,
                "run-channel-outsider",
                "channel-main",
                "must not be recorded",
            );
            outsider_write.actor = ActorId::new("actor-b");
            if directory.begin_thread_run(outsider_write).await
                != Err(ThreadDirectoryError::NotVisible)
            {
                return Err("非 channel member 不得写 activity".to_owned());
            }
            let mut unlinked_agent = request(
                2,
                "run-channel-unlinked",
                "channel-main",
                "must not be recorded",
            );
            unlinked_agent.command.bot_id = BotId::new("bot-unlinked");
            if directory.begin_thread_run(unlinked_agent).await
                != Err(ThreadDirectoryError::NotVisible)
            {
                return Err("未挂入 channel 的 Bot 不得写 activity".to_owned());
            }

            let long_user_message = format!("line one\nline two \u{001b}[31m {}", "x".repeat(400));
            let begin = request(3, "run-channel-1", "channel-main", &long_user_message);
            directory
                .begin_thread_run(begin.clone())
                .await
                .map_err(|error| error.to_string())?;

            for (label, stream) in [
                ("user member-a", &mut member_a),
                ("user member-c", &mut member_c),
                ("user member-c-second", &mut member_c_second),
            ] {
                let event = next_activity(label, stream).await?;
                if event.channel_id != ChannelId::new("channel-main")
                    || event.last_message_at.is_none()
                    || event.last_message_agent_id.is_some()
                {
                    return Err(format!("{label}: user activity 投影漂移：{event:?}"));
                }
                let preview = event
                    .last_message
                    .as_deref()
                    .ok_or_else(|| format!("{label}: preview 缺失"))?;
                if preview.chars().count() != 200
                    || !preview.starts_with("line one line two [31m")
                    || preview.chars().any(char::is_control)
                {
                    return Err(format!("{label}: bounded preview 漂移：{preview:?}"));
                }
            }
            expect_no_activity("user outsider-b", &mut outsider_b).await?;
            drop(member_c_second);
            expect_listener_count(&pool, 3).await?;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "DELETE FROM public.channel_memberships
                       WHERE channel_id='channel-main' AND user_id='actor-a';",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let runtime = PostgresRunRuntime::new(
                pool.clone(),
                "runtime-a".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
                DEFAULT_DISPATCH_CLAIM_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let claim = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "channel dispatch 未被 claim".to_owned())?;
            let lease = runtime
                .acknowledge_dispatch(&claim)
                .await
                .map_err(|error| error.to_string())?;
            runtime
                .append_semantic_chunk(&lease, 1, RunSemanticChannel::Text, "assistant\nreply")
                .await
                .map_err(|error| error.to_string())?;
            runtime
                .finish_run(&lease, 2, RunTerminal::Completed)
                .await
                .map_err(|error| error.to_string())?;

            let assistant = next_activity("assistant member-c", &mut member_c).await?;
            if assistant.channel_id != ChannelId::new("channel-main")
                || assistant.last_message.as_deref() != Some("assistant reply")
                || assistant.last_message_at.is_none()
                || assistant.last_message_agent_id != Some(BotId::new("bot-1"))
            {
                return Err(format!(
                    "assistant member-c: assistant activity 投影漂移：{assistant:?}"
                ));
            }
            expect_no_activity("revoked member-a", &mut member_a).await?;
            expect_no_activity("assistant outsider-b", &mut outsider_b).await?;

            let repo = ChannelRepo::new(pool.clone());
            let roster = repo
                .list_visible_channels(&ActorId::new("actor-c"), 50, None)
                .await
                .map_err(|error| error.to_string())?;
            if roster.len() != 1
                || roster[0].id != ChannelId::new("channel-main")
                || roster[0].last_message != assistant.last_message
                || roster[0].last_message_at != assistant.last_message_at
                || roster[0].last_message_agent_id != assistant.last_message_agent_id
            {
                return Err(format!("authoritative roster 投影漂移：{roster:?}"));
            }
            let outsider_roster = repo
                .list_visible_channels(&ActorId::new("actor-b"), 50, None)
                .await
                .map_err(|error| error.to_string())?;
            if !outsider_roster.is_empty() {
                return Err(format!("非 member 看到了 roster：{outsider_roster:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT last_message,last_message_at,last_message_agent_id
                     FROM public.channels WHERE id='channel-main'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let stored = (
                row.try_get::<_, Option<String>>(0)
                    .map_err(|error| error.to_string())?,
                row.try_get::<_, Option<time::OffsetDateTime>>(1)
                    .map_err(|error| error.to_string())?,
                row.try_get::<_, Option<String>>(2)
                    .map_err(|error| error.to_string())?,
            );
            if stored
                != (
                    assistant.last_message.clone(),
                    assistant.last_message_at,
                    Some("bot-1".to_owned()),
                )
            {
                return Err(format!("authoritative roster 与通知不一致：{stored:?}"));
            }
            drop(client);
            drop(member_c);
            expect_listener_count(&pool, 2).await?;

            // Future activity is deliberately newer than this real DB clock. The begin transaction
            // still commits its native run, but the stale roster report must change no row and emit
            // no channel notification.
            directory
                .begin_thread_run(request(
                    4,
                    "run-channel-stale",
                    "channel-stale",
                    "must not replace the future",
                ))
                .await
                .map_err(|error| error.to_string())?;
            expect_no_activity("stale report", &mut member_a).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let stale = client
                .query_one(
                    "SELECT last_message,last_message_at,last_message_agent_id
                     FROM public.channels WHERE id='channel-stale'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if stale
                .try_get::<_, Option<String>>(0)
                .map_err(|e| e.to_string())?
                != Some("future wins".to_owned())
                || stale
                    .try_get::<_, Option<String>>(2)
                    .map_err(|e| e.to_string())?
                    .is_some()
            {
                return Err("stale activity 覆盖了 roster 真源".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
