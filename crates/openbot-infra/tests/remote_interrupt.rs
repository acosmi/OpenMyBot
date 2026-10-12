//! Durable remote AG-UI interrupt request/answer/wait PostgreSQL evidence.

mod harness;

use std::sync::Arc;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    ProviderRemoteInterrupt, ProviderRemoteInterruptBatch, ProviderRemoteInterruptInput,
    ProviderRemoteResume, ProviderRemoteResumeStatus, RemoteInterruptCoordinator,
    RemoteInterruptError, RunExecutionLease,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::thread::FencingToken;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::remote_interrupt::PostgresRemoteInterruptCoordinator;

fn auth(actor: &str, generation: u64) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("deployment-a"),
        TenantId::new("tenant-a"),
        ActorId::new(actor),
        AuthGeneration::new(generation),
        false,
    )
    .with_role(Role::User)
    .build()
}

fn interrupt(id: &str, message: &str) -> ProviderRemoteInterrupt {
    ProviderRemoteInterrupt::new(ProviderRemoteInterruptInput {
        id: id.to_owned(),
        reason: "human_input".to_owned(),
        message: Some(message.to_owned()),
        tool_call_id: None,
        response_schema: Some(serde_json::json!({"type":"object"})),
        expires_at: Some("2099-01-01T00:00:00Z".to_owned()),
        metadata: Some(serde_json::json!({"authority":"remote-only"})),
    })
    .expect("fixture interrupt")
}

/// A SERIALIZABLE poll that races a concurrent answer may hit a real 40001. The product
/// rolls that transaction back and reports it without retrying (§4.2 item 3); only an
/// explicitly new public caller may wait again, and it must observe the same durable rows.
async fn resume_after_original_terminal(
    original: tokio::task::JoinHandle<Result<ProviderRemoteResume, RemoteInterruptError>>,
    port: &PostgresRemoteInterruptCoordinator,
    lease: &RunExecutionLease,
    batch: &ProviderRemoteInterruptBatch,
) -> Result<ProviderRemoteResume, String> {
    let original = tokio::time::timeout(core::time::Duration::from_secs(3), original)
        .await
        .map_err(|_| "durable waiter did not reach a terminal".to_owned())?
        .map_err(|error| error.to_string())?;
    match original {
        Ok(resume) => Ok(resume),
        Err(RemoteInterruptError::Unavailable) => {
            eprintln!("original waiter rejected as unavailable; one new public caller waits");
            tokio::time::timeout(
                core::time::Duration::from_secs(3),
                port.persist_and_wait(lease, batch),
            )
            .await
            .map_err(|_| "new public waiter did not resume".to_owned())?
            .map_err(|error| error.to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn interrupts_are_actor_scoped_audited_and_cross_replica_resumable() {
    let admin = admin_config("interrupts_are_actor_scoped_audited_and_cross_replica_resumable");
    with_temp_database(&admin, "remoteinterrupt", |config| async move {
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
                    "INSERT INTO public.users(id,email,auth_generation)
                       VALUES('actor-a','actor-a@example.test',0),
                             ('actor-b','actor-b@example.test',0);
                     INSERT INTO public.user_roles(user_id,role)
                       VALUES('actor-a','user'),('actor-b','user');
                     INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                       VALUES('tenant-a','/fixture',repeat('a',64));
                     INSERT INTO public.agents(id,name,type,configuration,package_id)
                       SELECT 'bot-1','Bot 1','remote_ag_ui','{}',id
                         FROM public.deployment_packages WHERE tenant_id='tenant-a';
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                     ) VALUES('bot-1',NULL,'Bot 1','role','seed','public',NULL);
                     INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       next_message_seq,next_event_seq,created_at,updated_at
                     ) VALUES('thread-1','tenant-a','deployment-a','actor-a','direct_bot','bot-1',
                              'active',0,0,clock_timestamp(),clock_timestamp());
                     INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('thread-1','actor-a');
                     INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                       next_event_seq,created_at,started_at
                     ) VALUES('run-1','thread-1','bot-1','actor-a',true,'running',1,0,
                              clock_timestamp(),clock_timestamp());
                     INSERT INTO public.thread_leases(
                       thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
                     ) VALUES('thread-1','fixture-owner',1,clock_timestamp(),
                              clock_timestamp()+interval '10 minutes',clock_timestamp());",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let lease = RunExecutionLease::new(
                RunId::new("run-1"),
                ThreadId::new("thread-1"),
                BotId::new("bot-1"),
                ActorId::new("actor-a"),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let batch = ProviderRemoteInterruptBatch::new(
                "run-1".to_owned(),
                vec![
                    interrupt("remote-1", "REMOTE_MESSAGE_CANARY_ONE"),
                    interrupt("remote-2", "REMOTE_MESSAGE_CANARY_TWO"),
                ],
            )
            .map_err(|error| error.to_string())?;
            let requester = Arc::new(
                PostgresRemoteInterruptCoordinator::new(
                    pool.clone(),
                    "fixture-owner".to_owned(),
                    vec![0x52; 32],
                )
                .map_err(|error| error.to_string())?,
            );
            let answerer = PostgresRemoteInterruptCoordinator::new(
                pool.clone(),
                "other-replica".to_owned(),
                vec![0x52; 32],
            )
            .map_err(|error| error.to_string())?;
            let wait_port = requester.clone();
            let wait_lease = lease.clone();
            let wait_batch = batch.clone();
            let waiter = tokio::spawn(async move {
                wait_port.persist_and_wait(&wait_lease, &wait_batch).await
            });

            let pending = tokio::time::timeout(core::time::Duration::from_secs(3), async {
                loop {
                    let pending = answerer.list_pending(&auth("actor-a", 0)).await?;
                    if pending.len() == 2 {
                        return Ok::<_, RemoteInterruptError>(pending);
                    }
                    tokio::time::sleep(core::time::Duration::from_millis(25)).await;
                }
            })
            .await
            .map_err(|_| "pending rows did not become visible".to_owned())?
            .map_err(|error| error.to_string())?;
            if !answerer
                .list_pending(&auth("actor-b", 0))
                .await
                .map_err(|error| error.to_string())?
                .is_empty()
                || pending[0].interrupt_id() != "remote-1"
                || pending[1].interrupt_id() != "remote-2"
            {
                return Err("remote interrupt actor scope/order drifted".to_owned());
            }
            let first_request = pending[0].request_id().to_owned();
            let second_request = pending[1].request_id().to_owned();
            let payload = serde_json::json!({"answer":"RESUME_PAYLOAD_CANARY"});
            if answerer
                .resolve(
                    &auth("actor-b", 0),
                    &first_request,
                    ProviderRemoteResumeStatus::Resolved,
                    Some(payload.clone()),
                )
                .await
                != Err(RemoteInterruptError::Stale)
            {
                return Err("another actor must not resolve the request handle".to_owned());
            }
            let first = answerer
                .resolve(
                    &auth("actor-a", 0),
                    &first_request,
                    ProviderRemoteResumeStatus::Resolved,
                    Some(payload.clone()),
                )
                .await
                .map_err(|error| error.to_string())?;
            if first.replayed() {
                return Err("first interrupt answer was reported as replay".to_owned());
            }
            let replay = answerer
                .resolve(
                    &auth("actor-a", 0),
                    &first_request,
                    ProviderRemoteResumeStatus::Resolved,
                    Some(payload.clone()),
                )
                .await
                .map_err(|error| error.to_string())?;
            if !replay.replayed() {
                return Err("exact answer replay was not recognized".to_owned());
            }
            if answerer
                .resolve(
                    &auth("actor-a", 0),
                    &first_request,
                    ProviderRemoteResumeStatus::Cancelled,
                    None,
                )
                .await
                != Err(RemoteInterruptError::Conflict)
            {
                return Err("different replay must conflict".to_owned());
            }
            answerer
                .resolve(
                    &auth("actor-a", 0),
                    &second_request,
                    ProviderRemoteResumeStatus::Cancelled,
                    None,
                )
                .await
                .map_err(|error| error.to_string())?;

            let resume = resume_after_original_terminal(waiter, &requester, &lease, &batch).await?;
            if resume.parent_protocol_run_id() != "run-1"
                || resume.protocol_run_id() == "run-1"
                || resume.entries().len() != 2
                || resume.entries()[0].interrupt_id() != "remote-1"
                || resume.entries()[0].status() != ProviderRemoteResumeStatus::Resolved
                || resume.entries()[0].payload() != Some(&payload)
                || resume.entries()[1].interrupt_id() != "remote-2"
                || resume.entries()[1].status() != ProviderRemoteResumeStatus::Cancelled
                || resume.entries()[1].payload().is_some()
            {
                return Err(format!("resume batch drifted: {resume:?}"));
            }

            let expiry_batch = ProviderRemoteInterruptBatch::new(
                "protocol-expiry".to_owned(),
                vec![interrupt("remote-expiry", "REMOTE_EXPIRY_CANARY")],
            )
            .map_err(|error| error.to_string())?;
            let expiry_port = requester.clone();
            let expiry_lease = lease.clone();
            let expiry_wait_batch = expiry_batch.clone();
            let expiry_waiter = tokio::spawn(async move {
                expiry_port
                    .persist_and_wait(&expiry_lease, &expiry_wait_batch)
                    .await
            });
            let expiry_request = tokio::time::timeout(core::time::Duration::from_secs(3), async {
                loop {
                    let pending = answerer.list_pending(&auth("actor-a", 0)).await?;
                    if let Some(interrupt) = pending
                        .into_iter()
                        .find(|interrupt| interrupt.interrupt_id() == "remote-expiry")
                    {
                        return Ok::<_, RemoteInterruptError>(interrupt.request_id().to_owned());
                    }
                    tokio::time::sleep(core::time::Duration::from_millis(25)).await;
                }
            })
            .await
            .map_err(|_| "expiry row did not become visible".to_owned())?
            .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.remote_agent_interrupts
                        SET created_at=clock.now-interval '2 hours',
                            requested_at=clock.now-interval '2 hours',
                            expires_at=clock.now-interval '1 hour',updated_at=clock.now
                       FROM (SELECT clock_timestamp() AS now) clock
                      WHERE request_id=$1",
                    &[&expiry_request],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let expired_resume =
                resume_after_original_terminal(expiry_waiter, &requester, &lease, &expiry_batch)
                    .await?;
            if expired_resume.parent_protocol_run_id() != expiry_batch.protocol_run_id()
                || expired_resume.entries().len() != 1
                || expired_resume.entries()[0].status()
                    != ProviderRemoteResumeStatus::Cancelled
                || expired_resume.entries()[0].payload().is_some()
            {
                return Err(format!("expired resume drifted: {expired_resume:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let audits = client
                .query(
                    "SELECT event_type,payload::text AS payload FROM public.audit_events
                      WHERE event_type LIKE 'agent.remote_interrupt_%' ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let types = audits
                .iter()
                .map(|row| row.get::<_, String>("event_type"))
                .collect::<Vec<_>>();
            if types
                != [
                    "agent.remote_interrupt_requested",
                    "agent.remote_interrupt_resolved",
                    "agent.remote_interrupt_cancelled",
                    "agent.remote_interrupt_requested",
                    "agent.remote_interrupt_expired",
                ]
                || audits.iter().any(|row| {
                    let payload: String = row.get("payload");
                    payload.contains("CANARY") || payload != "{}"
                })
            {
                return Err(format!("interrupt audit drifted: {types:?}"));
            }
            let distinct_resume: i64 = client
                .query_one(
                    "SELECT count(DISTINCT resume_protocol_run_id)::bigint
                       FROM public.remote_agent_interrupts
                      WHERE run_id='run-1' AND protocol_run_id='run-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if distinct_resume != 1 {
                return Err("batch did not persist one resume protocol id".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
