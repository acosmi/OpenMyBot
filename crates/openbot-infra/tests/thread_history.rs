//! Native thread history 的顺序、scope、空列表与结构验证真库证据。

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{ThreadDirectory, ThreadDirectoryError, ThreadHistoryRequest};
use openbot_contracts::command::ThreadHistoryRole;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId, ThreadId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::thread_directory::PostgresThreadDirectory;

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn history_is_ordered_scope_aware_empty_on_absence_and_structurally_validated() {
    let admin =
        admin_config("history_is_ordered_scope_aware_empty_on_absence_and_structurally_validated");
    with_temp_database(&admin, "threadhistory", |config| async move {
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
                       ('actor-a','a@example.test'),('actor-b','b@example.test');
                     INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,
                       next_message_seq
                     ) VALUES
                       ('550e8400-e29b-41d4-a716-446655440000','tenant-a','dep-a','actor-a',
                        'direct_bot','bot-1',5),
                       ('550e8400-e29b-41d4-a716-446655440001','tenant-a','dep-a','actor-a',
                        'direct_bot','bot-1',0);
                     INSERT INTO public.thread_memberships(thread_id,user_id) VALUES
                       ('550e8400-e29b-41d4-a716-446655440000','actor-a'),
                       ('550e8400-e29b-41d4-a716-446655440001','actor-a');
                     INSERT INTO public.agents(id,name,type,configuration)
                       VALUES('bot-1','Bot 1','built_in','{}');
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                     ) VALUES('bot-1',NULL,'Bot 1','role','seed','public');
                     INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at
                     ) VALUES('run-history','550e8400-e29b-41d4-a716-446655440000','bot-1',
                              'actor-a',false,'running',1,clock_timestamp());
                     INSERT INTO public.messages(
                       message_id,thread_id,seq,role,content,search_text,run_id
                     ) VALUES
                       ('m-user','550e8400-e29b-41d4-a716-446655440000',0,'user',
                        '{\"text\":\"hello\"}'::jsonb,'hello','run-history'),
                       ('m-assistant','550e8400-e29b-41d4-a716-446655440000',1,'assistant',
                        '{\"text\":\"\",\"toolCalls\":[{\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"showQuote\",\"arguments\":{\"quote\":\"q\",\"attribution\":\"a\"}}}]}'::jsonb,'','run-history'),
                       ('m-system','550e8400-e29b-41d4-a716-446655440000',2,'system',
                        '{\"text\":\"standing role\"}'::jsonb,'standing role',NULL),
                       ('m-summary','550e8400-e29b-41d4-a716-446655440000',3,'summary',
                        '{\"text\":\"prior context\"}'::jsonb,'prior context',NULL),
                       ('m-tool','550e8400-e29b-41d4-a716-446655440000',4,'tool',
                        '{\"text\":\"done\",\"toolCallId\":\"c1\",\"toolName\":\"showQuote\"}'::jsonb,'done','run-history');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let directory = PostgresThreadDirectory::new(pool.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")));
            let visible = ThreadHistoryRequest {
                deployment: DeploymentId::new("dep-a"),
                tenant: TenantId::new("tenant-a"),
                actor: ActorId::new("actor-a"),
                thread: ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
            };
            let history = directory
                .thread_history(visible.clone())
                .await
                .map_err(|error| error.to_string())?;
            let roles: Vec<_> = history.messages.iter().map(|message| message.role).collect();
            if roles
                != [
                    ThreadHistoryRole::User,
                    ThreadHistoryRole::Assistant,
                    ThreadHistoryRole::System,
                    ThreadHistoryRole::System,
                    ThreadHistoryRole::Tool,
                ]
            {
                return Err(format!("history role/order 漂移：{roles:?}"));
            }
            if history.messages[0].content != "hello"
                || history.messages[0].agent_id != Some(BotId::new("bot-1"))
                || history.messages[1].tool_calls.as_ref().map(Vec::len) != Some(1)
                || history.messages[1].agent_id != Some(BotId::new("bot-1"))
                || history.messages[4].tool_call_id.as_deref() != Some("c1")
                || history.messages[4].tool_name.as_deref() != Some("showQuote")
                || history.messages[4].agent_id != Some(BotId::new("bot-1"))
                || history.messages[2].agent_id.is_some()
                || history.messages[3].agent_id.is_some()
            {
                return Err(format!("history content/tool projection 错误：{history:?}"));
            }

            for request in [
                ThreadHistoryRequest {
                    actor: ActorId::new("actor-b"),
                    ..visible.clone()
                },
                ThreadHistoryRequest {
                    tenant: TenantId::new("tenant-b"),
                    ..visible.clone()
                },
                ThreadHistoryRequest {
                    deployment: DeploymentId::new("dep-b"),
                    ..visible.clone()
                },
                ThreadHistoryRequest {
                    thread: ThreadId::new("550e8400-e29b-41d4-a716-446655440099"),
                    ..visible.clone()
                },
                ThreadHistoryRequest {
                    thread: ThreadId::new("550e8400-e29b-41d4-a716-446655440001"),
                    ..visible.clone()
                },
            ] {
                let empty = directory
                    .thread_history(request)
                    .await
                    .map_err(|error| error.to_string())?;
                if !empty.messages.is_empty() {
                    return Err("不可见/不存在/空 thread 必须统一 messages=[]".to_owned());
                }
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.messages SET content='{\"text\":\"done\"}'::jsonb \
                     WHERE message_id='m-tool'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if directory.thread_history(visible.clone()).await
                != Err(ThreadDirectoryError::Corrupt {
                    field: "toolCallId",
                })
            {
                return Err("tool history 缺 toolCallId 必须结构错误而非静默跳过".to_owned());
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.threads SET status='deleted',deleted_at=now(),updated_at=now() \
                     WHERE thread_id=$1",
                    &[&visible.thread.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let deleted = directory
                .thread_history(visible)
                .await
                .map_err(|error| error.to_string())?;
            if !deleted.messages.is_empty() {
                return Err("deleted thread history 必须与不存在统一为空".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
