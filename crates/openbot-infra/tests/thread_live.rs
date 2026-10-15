//! Durable cursor → replay → LISTEN/NOTIFY wake → replay 的真库矩阵。

mod harness;

use std::future::poll_fn;
use std::time::Duration as StdDuration;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    AppEventStream, BeginThreadRunRequest, ThreadDirectory, ThreadEventSubscription,
};
use openbot_contracts::command::{AppEvent, BeginThreadRun, ThreadRunAnchor, ThreadRunEventKind};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::thread_directory::PostgresThreadDirectory;
use time::Duration;

async fn next(label: &'static str, stream: &mut AppEventStream) -> Result<AppEvent, String> {
    tokio::time::timeout(
        StdDuration::from_secs(5),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    .map_err(|_| format!("{label}: 等待 thread event 超时"))?
    .ok_or_else(|| format!("{label}: thread event stream 提前结束"))
}

fn sequence(event: &AppEvent) -> Option<u64> {
    match event {
        AppEvent::ThreadRunEvent(event) => Some(event.event_sequence),
        AppEvent::Heartbeat { .. }
        | AppEvent::ThreadStreamError { .. }
        | AppEvent::ChannelActivity(_)
        | AppEvent::ChannelStreamError { .. }
        | AppEvent::ToolApprovalActivity(_)
        | AppEvent::ToolApprovalStreamError { .. } => None,
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn lost_notify_replays_and_one_commit_wakes_two_replicas_without_duplicates() {
    let admin =
        admin_config("lost_notify_replays_and_one_commit_wakes_two_replicas_without_duplicates");
    with_temp_database(&admin, "threadlive", |config| async move {
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
                    "INSERT INTO public.users(id,email) VALUES('actor-a','a@example.test');
                     INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user');
                     INSERT INTO public.agents(id,name,type,configuration)
                       VALUES('bot-1','Bot 1','built_in','{}'::jsonb);
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                     ) VALUES('bot-1',NULL,'Bot 1','test role','seed','public',NULL);",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let actor = ActorId::new("actor-a");
            let mut entropy = [0_u8; 16];
            entropy[15] = 1;
            let thread = ThreadIdentity::new(&deployment).mint_from_entropy(entropy);
            let run = RunId::new("run-live-1");
            let listener_config = config
                .clone()
                .with_application_name("thread-live-replica");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                listener_config,
                "runtime-a".to_owned(),
                Duration::seconds(30),
            )
            .map_err(|error| error.to_string())?;
            directory
                .begin_thread_run(BeginThreadRunRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    command: BeginThreadRun {
                        artifact_refs: Vec::new(),
                        model_selection: None,
                        selected_skill_slugs: Vec::new(),
                        thread_id: thread.clone(),
                        run_id: run.clone(),
                        bot_id: BotId::new("bot-1"),
                        anchor: ThreadRunAnchor::DirectBot,
                        message: "hello".to_owned(),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;

            let subscription = ThreadEventSubscription {
                deployment: deployment.clone(),
                tenant: tenant.clone(),
                actor: actor.clone(),
                thread: thread.clone(),
                after_event_sequence: None,
            };
            // event 0 的 NOTIFY 发生在两条订阅建立前，必然已丢；仍须从 durable 表 replay。
            let mut replica_a = directory
                .subscribe_thread_events(subscription.clone())
                .await
                .map_err(|error| error.to_string())?;
            let mut replica_b = directory
                .subscribe_thread_events(subscription.clone())
                .await
                .map_err(|error| error.to_string())?;
            if sequence(&next("initial replica-a", &mut replica_a).await?) != Some(0)
                || sequence(&next("initial replica-b", &mut replica_b).await?) != Some(0)
            {
                return Err("丢失的 initial NOTIFY 没由两 replica replay event 0".to_owned());
            }

            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            let transaction = client
                .transaction()
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "UPDATE public.threads SET next_event_seq=2 WHERE thread_id=$1",
                    &[&thread.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "UPDATE public.runs SET next_event_seq=2 WHERE run_id=$1",
                    &[&run.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO public.run_events(
                       run_id,seq,thread_id,event_seq,event_type,payload,terminal
                     ) VALUES($1,1,$2,1,'semantic_chunk','{\"text\":\"live\"}'::jsonb,false)",
                    &[&run.as_str(), &thread.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .query_one("SELECT pg_notify('openbot_thread_events','')", &[])
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .commit()
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            for (label, stream) in [
                ("live replica-a", &mut replica_a),
                ("live replica-b", &mut replica_b),
            ] {
                let event = next(label, stream).await?;
                match event {
                    AppEvent::ThreadRunEvent(event)
                        if event.event_sequence == 1
                            && event.event_type == ThreadRunEventKind::SemanticChunk => {}
                    other => return Err(format!("live wake 没补回 event 1：{other:?}")),
                }
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let listener_pids: Vec<i32> = client
                .query(
                    "SELECT pid FROM pg_stat_activity \
                     WHERE application_name='thread-live-replica' ORDER BY pid",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|row| row.try_get(0).map_err(|error| error.to_string()))
                .collect::<Result<_, _>>()?;
            if listener_pids.len() != 2 {
                return Err(format!(
                    "强制断线前应有 2 条 LISTEN，会话实际 {listener_pids:?}"
                ));
            }
            for pid in listener_pids {
                let terminated: bool = client
                    .query_one("SELECT pg_terminate_backend($1)", &[&pid])
                    .await
                    .map_err(|error| error.to_string())?
                    .try_get(0)
                    .map_err(|error| error.to_string())?;
                if !terminated {
                    return Err(format!("未能终止 listener pid={pid}"));
                }
            }
            drop(client);

            // 两条 LISTEN 都已断开；故意不发 NOTIFY，只写 durable event 2。
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            let transaction = client
                .transaction()
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "UPDATE public.threads SET next_event_seq=3 WHERE thread_id=$1",
                    &[&thread.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "UPDATE public.runs SET next_event_seq=3 WHERE run_id=$1",
                    &[&run.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO public.run_events(
                       run_id,seq,thread_id,event_seq,event_type,payload,terminal
                     ) VALUES($1,2,$2,2,'checkpoint','{\"phase\":\"reconnected\"}'::jsonb,false)",
                    &[&run.as_str(), &thread.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .commit()
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            for (label, stream) in [
                ("reconnected replica-a", &mut replica_a),
                ("reconnected replica-b", &mut replica_b),
            ] {
                let event = next(label, stream).await?;
                match event {
                    AppEvent::ThreadRunEvent(event)
                        if event.event_sequence == 2
                            && event.event_type == ThreadRunEventKind::Checkpoint => {}
                    other => return Err(format!("listener 重连没补回 event 2：{other:?}")),
                }
            }

            let mut reconnected = directory
                .subscribe_thread_events(ThreadEventSubscription {
                    after_event_sequence: Some(1),
                    ..subscription
                })
                .await
                .map_err(|error| error.to_string())?;
            if sequence(&next("cursor reconnect", &mut reconnected).await?) != Some(2) {
                return Err("last cursor=1 的 reconnect 必须从 2 replay".to_owned());
            }

            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            let listeners: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM pg_stat_activity \
                     WHERE application_name='thread-live-replica'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if listeners != 3 {
                return Err(format!("撤权前应有 3 条 LISTEN 会话，实际 {listeners}"));
            }
            let revoke = client
                .transaction()
                .await
                .map_err(|error| error.to_string())?;
            revoke
                .execute(
                    "DELETE FROM public.thread_memberships WHERE thread_id=$1 AND user_id=$2",
                    &[&thread.as_str(), &actor.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            revoke
                .query_one("SELECT pg_notify('openbot_thread_events','')", &[])
                .await
                .map_err(|error| error.to_string())?;
            revoke
                .commit()
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if directory
                .thread_known(&deployment, &tenant, &actor, &thread)
                .await
                .map_err(|error| error.to_string())?
            {
                return Err("撤权 commit 后 direct thread_known 仍为 true".to_owned());
            }
            for (label, stream) in [
                ("revoke replica-a", &mut replica_a),
                ("revoke replica-b", &mut replica_b),
                ("revoke reconnected", &mut reconnected),
            ] {
                match next(label, stream).await? {
                    AppEvent::ThreadStreamError { code } if code == "not_visible" => {}
                    other => return Err(format!("撤权后必须显式 not_visible 并断流：{other:?}")),
                }
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
