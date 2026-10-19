//! PostgreSQL evidence for durable, actor-owned run cancellation and missed-NOTIFY polling.

mod harness;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    BeginThreadRunRequest, CancelThreadRunRequest, NoRunDispatchConsumer, RunRuntime,
    ThreadConversationRequest, ThreadDirectory,
};
use openbot_contracts::command::{
    BeginThreadRun, CancelThreadRun, ThreadForegroundRunState, ThreadRunAnchor,
    ThreadRunCancellationState,
};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn durable_cancel_is_scoped_idempotent_and_poll_terminalizes_when_no_child_exists() {
    let admin = admin_config(
        "durable_cancel_is_scoped_idempotent_and_poll_terminalizes_when_no_child_exists",
    );
    with_temp_database(&admin, "runcancel", |config| async move {
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
                       ('actor','actor@example.test'),('other','other@example.test');
                     INSERT INTO public.user_roles(user_id,role) VALUES('actor','user');
                     INSERT INTO public.agents(id,name,type,configuration)
                       VALUES('bot-1','Bot One','built_in','{}');
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                     ) VALUES('bot-1',NULL,'Bot One','cancel role','seed','public');
                     INSERT INTO public.channels(id,name,description)
                       VALUES('channel-1','Bot One','Private agent channel.');
                     INSERT INTO public.channel_memberships(channel_id,user_id)
                       VALUES('channel-1','actor'),('channel-1','other');
                     INSERT INTO public.channel_agents(channel_id,agent_id)
                       VALUES('channel-1','bot-1');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let deployment = DeploymentId::new("dep");
            let tenant = TenantId::new("tenant");
            let actor = ActorId::new("actor");
            let thread = ThreadIdentity::new(&deployment).mint_from_entropy([0x35; 16]);
            let owner = "runtime-cancel-owner".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
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
                        run_id: RunId::new("run-cancel-1"),
                        bot_id: BotId::new("bot-1"),
                        anchor: ThreadRunAnchor::Channel {
                            channel_id: ChannelId::new("channel-1"),
                        },
                        message: "please stop later".to_owned(),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;

            let command = CancelThreadRun {
                thread_id: thread.clone(),
                run_id: RunId::new("run-cancel-1"),
            };
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.outbox( \
                       outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class, \
                       payload,status,delivered_at \
                     ) VALUES( \
                       'run-cancel-1:agent_run_cancel','run','run-cancel-1',0, \
                       'agent_run_cancel','internal',$1,'delivered',clock_timestamp() \
                     )",
                    &[&serde_json::json!({
                        "runId":"run-cancel-1",
                        "threadId":thread.as_str(),
                        "requestedBy":"actor",
                    })],
                )
                .await
                .map_err(|error| error.to_string())?;
            let delivered_while_active = directory
                .cancel_thread_run(CancelThreadRunRequest {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    command: command.clone(),
                })
                .await
                .expect_err("a delivered control row cannot coexist with an active run");
            if delivered_while_active
                != (openbot_application::ThreadDirectoryError::Corrupt {
                    field: "run_cancel_outbox",
                })
            {
                return Err(format!(
                    "delivered active cancellation was not corruption: {delivered_while_active:?}"
                ));
            }
            client
                .execute(
                    "DELETE FROM public.outbox WHERE outbox_id='run-cancel-1:agent_run_cancel'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let other_error = directory
                .cancel_thread_run(CancelThreadRunRequest {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: ActorId::new("other"),
                    command: command.clone(),
                })
                .await
                .expect_err("a channel member who did not start the run cannot stop it");
            if other_error != openbot_application::ThreadDirectoryError::NotVisible {
                return Err(format!("other actor cancellation drifted: {other_error:?}"));
            }

            let first = directory
                .cancel_thread_run(CancelThreadRunRequest {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    command: command.clone(),
                })
                .await
                .map_err(|error| error.to_string())?;
            let replay = directory
                .cancel_thread_run(CancelThreadRunRequest {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    command: command.clone(),
                })
                .await
                .map_err(|error| error.to_string())?;
            if first.state != ThreadRunCancellationState::Requested
                || replay.state != ThreadRunCancellationState::AlreadyRequested
            {
                return Err(format!("cancel request states drifted: {first:?} {replay:?}"));
            }
            let cancelling = directory
                .thread_conversation(ThreadConversationRequest {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    thread: thread.clone(),
                })
                .await
                .map_err(|error| error.to_string())?;
            if cancelling.active_run_state != Some(ThreadForegroundRunState::Cancelling)
                || cancelling.active_run_cancellable
            {
                return Err(format!("cancelling snapshot drifted: {cancelling:?}"));
            }

            // Deliberately use the poll-only constructor: this is the lost-NOTIFY proof.
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let original_dispatch: serde_json::Value = client
                .query_one(
                    "SELECT payload FROM public.outbox \
                     WHERE outbox_id='run-cancel-1:agent_run_dispatch'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.outbox SET payload=jsonb_set( \
                       payload,'{threadId}','\"tampered-thread\"'::jsonb \
                     ) WHERE outbox_id='run-cancel-1:agent_run_dispatch'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let corrupt_relay =
                RunRelay::start(runtime.clone(), Arc::new(NoRunDispatchConsumer));
            tokio::time::sleep(StdDuration::from_millis(200)).await;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let blocked = client
                .query_one(
                    "SELECT r.status, \
                            (SELECT status FROM public.outbox \
                              WHERE outbox_id='run-cancel-1:agent_run_cancel'), \
                            (SELECT count(*)::bigint FROM public.run_events \
                              WHERE run_id='run-cancel-1' AND terminal) \
                     FROM public.runs r WHERE r.run_id='run-cancel-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let blocked_shape: (String, String, i64) = (
                blocked.try_get(0).map_err(|error| error.to_string())?,
                blocked.try_get(1).map_err(|error| error.to_string())?,
                blocked.try_get(2).map_err(|error| error.to_string())?,
            );
            if blocked_shape.0 != "running"
                || blocked_shape.1 == "delivered"
                || blocked_shape.2 != 0
            {
                return Err(format!(
                    "tampered dispatch did not fail closed: {blocked_shape:?}"
                ));
            }
            corrupt_relay.stop().await;
            client
                .execute(
                    "UPDATE public.outbox SET payload=$1 \
                     WHERE outbox_id='run-cancel-1:agent_run_dispatch'",
                    &[&original_dispatch],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let crash_claim = runtime
                .claim_cancellation()
                .await
                .map_err(|error| error.to_string())?;
            if crash_claim.is_none() {
                return Err("repaired cancellation was not claimable before restart".to_owned());
            }
            drop(crash_claim);
            let relay = RunRelay::start(runtime, Arc::new(NoRunDispatchConsumer));
            let mut final_shape = None;
            for _ in 0..80 {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                let row = client
                    .query_one(
                        "SELECT r.status,
                                (SELECT status FROM public.outbox
                                  WHERE outbox_id='run-cancel-1:agent_run_cancel'),
                                (SELECT status FROM public.outbox
                                  WHERE outbox_id='run-cancel-1:agent_run_dispatch'),
                                (SELECT count(*)::bigint FROM public.run_events
                                  WHERE run_id='run-cancel-1' AND terminal)
                         FROM public.runs r WHERE r.run_id='run-cancel-1'",
                        &[],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let shape: (String, String, String, i64) = (
                    row.try_get(0).map_err(|error| error.to_string())?,
                    row.try_get(1).map_err(|error| error.to_string())?,
                    row.try_get(2).map_err(|error| error.to_string())?,
                    row.try_get(3).map_err(|error| error.to_string())?,
                );
                if shape.0 == "cancelled" && shape.1 == "delivered" {
                    final_shape = Some(shape);
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(25)).await;
            }
            relay.stop().await;
            let Some((status, cancel_outbox, dispatch_outbox, terminals)) = final_shape else {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                let row = client
                    .query_one(
                        "SELECT r.status, \
                                (SELECT status || ':' || coalesce(last_error_code,'-') || ':' || \
                                        coalesce(claimed_by,'-') \
                                   FROM public.outbox \
                                  WHERE outbox_id='run-cancel-1:agent_run_cancel'), \
                                (SELECT status || ':' || coalesce(last_error_code,'-') \
                                   FROM public.outbox \
                                  WHERE outbox_id='run-cancel-1:agent_run_dispatch'), \
                                (SELECT count(*)::bigint FROM public.run_events \
                                  WHERE run_id='run-cancel-1' AND terminal), \
                                l.owner_id,l.fencing_token,r.fencing_token, \
                                l.expires_at <= clock_timestamp() \
                         FROM public.runs r \
                         JOIN public.thread_leases l ON l.thread_id=r.thread_id \
                         WHERE r.run_id='run-cancel-1'",
                        &[],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let shape: (String, String, String, i64, String, i64, i64, bool) = (
                    row.try_get(0).map_err(|error| error.to_string())?,
                    row.try_get(1).map_err(|error| error.to_string())?,
                    row.try_get(2).map_err(|error| error.to_string())?,
                    row.try_get(3).map_err(|error| error.to_string())?,
                    row.try_get(4).map_err(|error| error.to_string())?,
                    row.try_get(5).map_err(|error| error.to_string())?,
                    row.try_get(6).map_err(|error| error.to_string())?,
                    row.try_get(7).map_err(|error| error.to_string())?,
                );
                return Err(format!("poll-only cancellation did not settle: {shape:?}"));
            };
            if status != "cancelled"
                || cancel_outbox != "delivered"
                || dispatch_outbox != "delivered"
                || terminals != 1
            {
                return Err(format!(
                    "cancelled durable shape drifted: {status}/{cancel_outbox}/{dispatch_outbox}/{terminals}"
                ));
            }

            let terminal_replay = directory
                .cancel_thread_run(CancelThreadRunRequest {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor,
                    command,
                })
                .await
                .map_err(|error| error.to_string())?;
            if terminal_replay.state != ThreadRunCancellationState::AlreadyTerminal {
                return Err(format!("terminal cancel replay drifted: {terminal_replay:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let cancel_rows: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.outbox
                     WHERE destination='agent_run_cancel' AND aggregate_id='run-cancel-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if cancel_rows != 1 {
                return Err(format!("cancel outbox duplicated: {cancel_rows}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
