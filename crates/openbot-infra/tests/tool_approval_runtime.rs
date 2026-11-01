//! Durable human proof-of-intent: actor isolation, wait/wake, reuse, denial, expiry and revocation.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use core::future::poll_fn;
use std::sync::Arc;

use openbot_application::{
    AppEventStream, ToolApprovalAdministration, ToolApprovalAdministrationError,
    ToolApprovalPresentation, ToolApprovalRequest,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::AppEvent;
use openbot_contracts::ids::{
    ActorId, BotId, CatalogGeneration, ComputerGeneration, DeploymentId, RunId, TenantId, ThreadId,
    ToolCallId,
};
use openbot_contracts::tool::{
    ToolApprovalActivityEvent, ToolApprovalDecision, ToolApprovalEffect,
};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::tool::approval::{ApprovalTarget, PolicyVersionTag};
use openbot_domain::tool::metadata::{ApprovalClass, Effect, ToolName};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::tool_approval::{DurableHumanDecision, PostgresToolApprovalCoordinator};

const ACTOR: &str = "approval-owner";
const OTHER: &str = "approval-other";
const BOT: &str = "approval-bot";
const RUN: &str = "approval-run";
const THREAD: &str = "approval-thread";
const AUDIT_KEY: &[u8] = b"approval-runtime-audit-key-at-least-32";

fn auth(actor: &str, generation: u64) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("approval-deployment"),
        TenantId::new("approval-tenant"),
        ActorId::new(actor),
        AuthGeneration::new(generation),
        false,
    )
    .with_role(Role::User)
    .build()
}

fn request(call: &str, class: ApprovalClass) -> ToolApprovalRequest {
    ToolApprovalRequest {
        call_id: ToolCallId::new(call),
        actor: ActorId::new(ACTOR),
        auth_generation: AuthGeneration::new(1),
        bot: BotId::new(BOT),
        run: RunId::new(RUN),
        thread: ThreadId::new(THREAD),
        tool: ToolName::new("mcp__notes__delete_note").unwrap(),
        args_hash: Sha256Digest::of(br#"{"id":"note-1"}"#),
        target: ApprovalTarget {
            kind: "mcp_tool",
            id: "notes/delete_note".to_owned(),
        },
        effect: Effect::Write,
        approval_class: class,
        computer_generation: ComputerGeneration::new(0),
        catalog_generation: CatalogGeneration::new(7),
        target_document_generation: None,
        policy_version: PolicyVersionTag::new("a".repeat(64)),
        presentation: ToolApprovalPresentation {
            arguments_summary: serde_json::json!({"id":"note-1","secret":"[redacted]"}),
            change_summary: Some(serde_json::json!({"kind":"delete","count":1})),
        },
    }
}

async fn wait_for_pending(
    coordinator: &PostgresToolApprovalCoordinator,
    auth: &AuthContext,
) -> Result<openbot_contracts::tool::PendingToolApproval, String> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let page = coordinator
                .list_pending(auth)
                .await
                .map_err(|error| error.to_string())?;
            if let Some(pending) = page.approvals.into_iter().next() {
                return Ok(pending);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "pending approval did not become visible".to_owned())?
}

async fn next_approval_activity(
    label: &str,
    stream: &mut AppEventStream,
) -> Result<ToolApprovalActivityEvent, String> {
    let event = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    .map_err(|_| format!("{label}: approval activity timeout"))?
    .ok_or_else(|| format!("{label}: approval activity stream ended"))?;
    match event {
        AppEvent::ToolApprovalActivity(event) => Ok(event),
        other => Err(format!("{label}: unexpected approval event {other:?}")),
    }
}

async fn expect_no_approval_activity(stream: &mut AppEventStream) -> Result<(), String> {
    match tokio::time::timeout(
        std::time::Duration::from_millis(1_200),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    {
        Err(_) => Ok(()),
        Ok(Some(event)) => Err(format!("other actor received approval activity: {event:?}")),
        Ok(None) => Err("other actor approval stream ended".to_owned()),
    }
}

async fn next_approval_stream_error(stream: &mut AppEventStream) -> Result<String, String> {
    let event = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    .map_err(|_| "approval stream revocation timeout".to_owned())?
    .ok_or_else(|| "approval stream ended before its terminal error".to_owned())?;
    let AppEvent::ToolApprovalStreamError { code } = event else {
        return Err(format!(
            "approval stream emitted data after revocation: {event:?}"
        ));
    };
    match tokio::time::timeout(
        std::time::Duration::from_millis(100),
        poll_fn(|cx| stream.as_mut().poll_next(cx)),
    )
    .await
    {
        Ok(None) => {}
        Ok(Some(_)) => return Err("approval stream emitted after its terminal error".to_owned()),
        Err(_) => return Err("approval stream did not end after its terminal error".to_owned()),
    }
    Ok(code)
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn durable_wait_grant_reuse_deny_expire_and_generation_cancel_are_real() {
    let admin = harness::admin_config(
        "durable_wait_grant_reuse_deny_expire_and_generation_cancel_are_real",
    );
    harness::with_temp_database(&admin, "approvalruntime", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut pg = pool
                .get()
                .await
                .map_err(|error| format!("approval setup pool: {error:?}"))?;
            baseline::apply(&pg)
                .await
                .map_err(|error| format!("approval baseline: {error:?}"))?;
            native::apply(&mut pg)
                .await
                .map_err(|error| format!("approval native: {error:?}"))?;
            pg.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES
                   ('approval-owner','approval-owner@example.test',1),
                   ('approval-other','approval-other@example.test',1);
                 INSERT INTO public.user_roles(user_id,role) VALUES
                   ('approval-owner','user'),('approval-other','user');
                 INSERT INTO public.agents(id,name,type,configuration)
                   VALUES('approval-bot','Approval Bot','built_in','{}');
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                 ) VALUES('approval-bot',NULL,'Approval Bot','role','seed','public');
                 INSERT INTO public.threads(
                   thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status
                 ) VALUES('approval-thread','approval-tenant','approval-deployment',
                          'approval-owner','direct_bot','approval-bot','active');
                 INSERT INTO public.thread_memberships(thread_id,user_id) VALUES
                   ('approval-thread','approval-owner');
                 INSERT INTO public.runs(
                   run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at
                 ) VALUES('approval-run','approval-thread','approval-bot','approval-owner',
                          true,'running',1,clock_timestamp());
                 INSERT INTO public.thread_leases(
                   thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
                 ) VALUES('approval-thread','runtime',1,clock_timestamp(),
                          clock_timestamp()+interval '10 minutes',clock_timestamp());",
            )
            .await
            .map_err(|error| format!("approval fixture setup: {error:?}"))?;
            drop(pg);

            let coordinator = Arc::new(
                PostgresToolApprovalCoordinator::new(
                    pool.clone(),
                    DeploymentId::new("approval-deployment"),
                    TenantId::new("approval-tenant"),
                    AUDIT_KEY.to_vec(),
                    openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                        &pool,
                        &openbot_contracts::ids::DeploymentId::new("outside"),
                        &openbot_contracts::ids::TenantId::new("outside"),
                    ),
                )
                .map_err(|error| error.to_string())?,
            );
            let owner = auth(ACTOR, 1);
            let other = auth(OTHER, 1);
            let replica = PostgresToolApprovalCoordinator::new(
                pool.clone(),
                DeploymentId::new("approval-deployment"),
                TenantId::new("approval-tenant"),
                AUDIT_KEY.to_vec(),
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                    &pool,
                    &openbot_contracts::ids::DeploymentId::new("outside"),
                    &openbot_contracts::ids::TenantId::new("outside"),
                ),
            )
            .map_err(|error| error.to_string())?;
            let mut owner_activity = replica
                .subscribe_activity(&owner)
                .await
                .map_err(|error| error.to_string())?;
            let mut other_activity = replica
                .subscribe_activity(&other)
                .await
                .map_err(|error| error.to_string())?;
            if next_approval_activity("owner initial", &mut owner_activity)
                .await?
                .pending_count
                != 0
                || next_approval_activity("other initial", &mut other_activity)
                    .await?
                    .pending_count
                    != 0
            {
                return Err("approval activity initial snapshot was not empty".to_owned());
            }

            let first_request = request("approval-call-1", ApprovalClass::OncePerRun);
            let waiting = {
                let coordinator = coordinator.clone();
                let request = first_request.clone();
                tokio::spawn(async move { coordinator.request_and_wait(&request).await })
            };
            let pending = wait_for_pending(&coordinator, &owner).await?;
            if next_approval_activity("owner pending", &mut owner_activity)
                .await?
                .pending_count
                != 1
            {
                return Err("cross-replica approval activity missed pending state".to_owned());
            }
            expect_no_approval_activity(&mut other_activity).await?;
            if pending.effect != ToolApprovalEffect::Write
                || pending.arguments_summary["id"] != "note-1"
                || pending.arguments_summary["secret"] != "[redacted]"
                || pending
                    .change_summary
                    .as_ref()
                    .and_then(|value| value.get("kind"))
                    != Some(&serde_json::Value::String("delete".to_owned()))
                || !coordinator
                    .list_pending(&other)
                    .await
                    .map_err(|error| error.to_string())?
                    .approvals
                    .is_empty()
            {
                return Err("pending approval projection or actor isolation drift".to_owned());
            }
            if coordinator
                .decide(&other, &pending.approval_id, ToolApprovalDecision::Grant)
                .await
                .is_ok()
            {
                return Err("other actor granted somebody else's approval".to_owned());
            }
            coordinator
                .decide(&owner, &pending.approval_id, ToolApprovalDecision::Grant)
                .await
                .map_err(|error| error.to_string())?;
            if next_approval_activity("owner granted", &mut owner_activity)
                .await?
                .pending_count
                != 0
            {
                return Err("cross-replica approval activity missed resolution".to_owned());
            }
            if !matches!(
                waiting.await.map_err(|error| error.to_string())?,
                Ok(DurableHumanDecision::Granted { .. })
            ) {
                return Err("durable grant did not wake the waiter".to_owned());
            }

            let reused = coordinator
                .request_and_wait(&request("approval-call-2", ApprovalClass::OncePerRun))
                .await
                .map_err(|error| error.to_string())?;
            if !matches!(reused, DurableHumanDecision::Granted { .. }) {
                return Err("exact once-per-run binding was not reused".to_owned());
            }

            let deny_request = request("approval-call-3", ApprovalClass::EveryCall);
            let denied_waiter = {
                let coordinator = coordinator.clone();
                let request = deny_request.clone();
                tokio::spawn(async move { coordinator.request_and_wait(&request).await })
            };
            let deny_pending = wait_for_pending(&coordinator, &owner).await?;
            coordinator
                .decide(
                    &owner,
                    &deny_pending.approval_id,
                    ToolApprovalDecision::Deny,
                )
                .await
                .map_err(|error| error.to_string())?;
            if denied_waiter
                .await
                .map_err(|error| format!("approval expiry pool: {error:?}"))?
                .map_err(|error| error.to_string())?
                != DurableHumanDecision::Denied
            {
                return Err("human denial did not stop the waiter".to_owned());
            }

            let expiry_request = request("approval-call-4", ApprovalClass::EveryCall);
            let expiry_waiter = {
                let coordinator = coordinator.clone();
                let request = expiry_request.clone();
                tokio::spawn(async move { coordinator.request_and_wait(&request).await })
            };
            let expiring = wait_for_pending(&coordinator, &owner).await?;
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "WITH ts AS MATERIALIZED (SELECT clock_timestamp() AS now)
                     UPDATE public.tool_approvals SET
                       created_at=ts.now-interval '10 minutes',
                       requested_at=ts.now-interval '10 minutes',
                       expires_at=ts.now-interval '5 minutes',updated_at=ts.now
                      FROM ts WHERE approval_id=$1",
                    &[&expiring.approval_id],
                )
                .await
                .map_err(|error| format!("approval expiry update: {error:?}"))?;
            if tokio::time::timeout(std::time::Duration::from_secs(3), expiry_waiter)
                .await
                .map_err(|_| "expiry waiter timed out".to_owned())?
                .map_err(|error| format!("approval cancellation pool: {error:?}"))?
                .map_err(|error| error.to_string())?
                != DurableHumanDecision::Denied
            {
                return Err("expired approval did not stop the waiter".to_owned());
            }

            let cancel_request = request("approval-call-5", ApprovalClass::EveryCall);
            let cancel_waiter = {
                let coordinator = coordinator.clone();
                let request = cancel_request.clone();
                tokio::spawn(async move { coordinator.request_and_wait(&request).await })
            };
            let _ = wait_for_pending(&coordinator, &owner).await?;
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "UPDATE public.users SET auth_generation=2 WHERE id='approval-owner'",
                    &[],
                )
                .await
                .map_err(|error| format!("approval generation update: {error:?}"))?;
            let revoked_code = next_approval_stream_error(&mut owner_activity).await?;
            let expected_revoked_code = ToolApprovalAdministrationError::NotVisible
                .into_app_error()
                .code()
                .as_str();
            if revoked_code != expected_revoked_code {
                return Err(format!(
                    "approval stream revocation code drift: {revoked_code}"
                ));
            }
            if !matches!(
                replica.subscribe_activity(&owner).await,
                Err(ToolApprovalAdministrationError::NotVisible)
            ) {
                return Err("stale generation opened a new approval stream".to_owned());
            }
            if tokio::time::timeout(std::time::Duration::from_secs(3), cancel_waiter)
                .await
                .map_err(|_| "cancel waiter timed out".to_owned())?
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?
                != DurableHumanDecision::Denied
            {
                return Err("auth-generation change did not cancel approval".to_owned());
            }

            let pg = pool
                .get()
                .await
                .map_err(|error| format!("approval evidence pool: {error:?}"))?;
            let evidence = pg
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.tool_approvals),
                       (SELECT count(*)::bigint FROM public.tool_approvals
                         WHERE state<>'pending' AND arguments_summary IS NULL
                           AND change_summary IS NULL),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='tool.approval_requested'),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='tool.approval_granted'),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='tool.approval_denied'),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='tool.approval_expired'),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='tool.approval_cancelled'),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE payload::text LIKE '%note-1%')",
                    &[],
                )
                .await
                .map_err(|error| format!("approval evidence query: {error:?}"))?;
            let counts = (0..8)
                .map(|index| {
                    evidence
                        .try_get::<_, i64>(index)
                        .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if counts != [4, 4, 4, 1, 1, 1, 1, 0] {
                return Err(format!("approval durable/audit evidence drift: {counts:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
