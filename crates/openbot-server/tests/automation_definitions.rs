//! Real authenticated router and isolated PostgreSQL evidence for the manual control plane.

#[path = "../../openbot-infra/tests/support/delegated_assembly_fixture.rs"]
pub mod assembly_fixture;
#[path = "support/transport_fixture.rs"]
mod transport_fixture;
mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::{sync::Arc, time::Duration};

use axum::body::{Body, to_bytes};
use http::{HeaderMap, Request, StatusCode};
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_server::{PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ORIGIN: &str = "https://app.example.test";
const OWNER: &str = "owned-automation-http-session-owner";
const OLD: &str = "owned-automation-http-session-aged";
const ADMIN: &str = "owned-automation-http-session-admin";
const SESSION_KEY: &[u8] = b"automation-outer-fixture-session-hash-key";
const DEFINITIONS: &str = "/api/automations";
const DEFINITION: &str = "/api/automations/manual-http";
const MANUAL: &str = "/api/automations/manual-http/runs";

async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: &str,
    origin: Option<&str>,
    body: Body,
) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::COOKIE, format!("openbot_session={token}"))
        .header(http::header::CONTENT_TYPE, "application/json");
    if let Some(origin) = origin {
        request = request.header(http::header::ORIGIN, origin);
    }
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.unwrap();
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (parts.status, parts.headers, json)
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn owner_cookie_fresh_origin_body_and_manual_receipt_use_real_pg() {
    let admin = harness::admin_config("automation_http");
    harness::with_temp_database(&admin, "automation_http", |database| async move {
        let f = assembly_fixture::Fixture::with_options(&database, assembly_fixture::Options {
            single_user: false, automation: true, subscribe: false, ..Default::default()
        }).await?;
        let client = f.pool.get().await.unwrap();
        client.execute("INSERT INTO public.user_roles(user_id,role) VALUES('other-owner','user')", &[]).await.unwrap();
        let now: time::OffsetDateTime = client.query_one("SELECT statement_timestamp()", &[]).await.unwrap().get(0);
        for (session, actor, token, age) in [
            ("owner", "other-owner", OWNER, 1),
            ("aged", "other-owner", OLD, 30),
            ("admin", "dev-local-user", ADMIN, 1),
        ] {
            let hash = SessionTokenHash::compute(SessionToken::new(token.as_bytes()), SessionHashKey::new(SESSION_KEY)).to_column_value();
            client.execute(
                "INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation)
                 VALUES($1,$2,$3,$4,$5,$6,0)",
                &[&session, &actor, &hash, &(now + time::Duration::hours(1)),
                    &(now - time::Duration::minutes(age)), &now],
            ).await.unwrap();
        }
        drop(client);
        let budget = openbot_domain::automation::AutomationBudgets::try_from(
            serde_json::from_value::<openbot_contracts::automation::AutomationBudgetsFile>(json!({
                "schemaVersion":1,"revision":1,
                "workspaces":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),
                    "budget":[{"metric":"sampling_calls","totalLimit":"20"}]}],
                "owners":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),"ownerId":"other-owner",
                    "budget":[{"metric":"sampling_calls","totalLimit":"20"}]}]
            })).unwrap(),
        ).unwrap();
        f.assembly.automations.as_ref().unwrap().install_budgets(Some(&budget)).await.unwrap();
        let resolver = PostgresSessionAuthResolver::new(f.pool.clone(), SESSION_KEY,
            default_session_lifetime(), f.auth.deployment().clone(), f.auth.tenant().clone()).unwrap();
        let security = SensitiveWriteSecurity::new(default_session_lifetime(), TrustedOrigins::from_configured([ORIGIN]).unwrap());
        let app = transport_fixture::loopback_router(ServerBuilder::new(f.assembly.application.clone(), Arc::new(resolver))
            .with_transport_policy(transport_fixture::loopback_policy())
            .with_sensitive_write_security(security).build());
        let definition = json!({"automationId":"manual-http","config":{"schemaVersion":1,
            "title":"Manual through HTTP","botId":"delegated-bot","promptTemplate":"Inspect the original owner input.",
            "trigger":{"kind":"manual"},"modelPolicy":"bot_current","permissionCeiling":{"toolIds":[],"dataScopes":[]},
            "budget":[{"metric":"sampling_calls","totalLimit":"10"}],"runDeadlineSeconds":60}});
        let body = |value: &Value| Body::from(value.to_string());
        let (status, _, error) = send(&app, "POST", DEFINITIONS, OWNER, None, body(&definition)).await;
        assert_eq!((status.as_u16(), error["code"].as_str()), (403, Some("identity_sensitive_write_origin_missing")));
        let (status, _, error) = send(&app, "POST", DEFINITIONS, OWNER, Some("https://foreign.example.test"), body(&definition)).await;
        assert_eq!((status.as_u16(), error["code"].as_str()), (403, Some("identity_sensitive_write_origin_untrusted")));
        let (status, headers, error) = send(&app, "POST", DEFINITIONS, OWNER, Some(ORIGIN), Body::from(vec![b' '; 64 * 1024 + 1])).await;
        assert_eq!((status.as_u16(), error["code"].as_str()), (413, Some("payload_too_large")));
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        let mut forged = definition.clone();
        forged["ownerId"] = json!("dev-local-user");
        let (status, _, error) = send(&app, "POST", DEFINITIONS, OWNER, Some(ORIGIN), body(&forged)).await;
        assert_eq!((status.as_u16(), error["code"].as_str()), (400, Some("malformed_payload")));
        let mut max_body = definition.to_string().into_bytes();
        max_body.resize(64 * 1024, b' ');
        let (status, headers, created) = send(
            &app, "POST", DEFINITIONS, OWNER, Some(ORIGIN), Body::from(max_body),
        ).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        assert_eq!(created["state"], "paused");
        assert_eq!(created["revision"], 1);
        let (status, _, replay) = send(&app, "POST", DEFINITIONS, OWNER, Some(ORIGIN), body(&definition)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["threadId"], created["threadId"]);
        let (status, _, invisible) = send(&app, "GET", DEFINITION, ADMIN, None, Body::empty()).await;
        assert_eq!((status.as_u16(), invisible["code"].as_str()), (404, Some("not_visible")));
        let (status, _, empty) = send(&app, "GET", DEFINITIONS, ADMIN, None, Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(empty["items"], json!([]));
        let (status, headers, _) = send(&app, "HEAD", DEFINITION, OWNER, None, Body::empty()).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        let enable = json!({"action":"enable","expectedRevision":1,"grantConsent":{"validity":{"kind":"until_revoked"}}});
        let (status, _, stale) = send(&app, "PATCH", DEFINITION, OLD, Some(ORIGIN), body(&enable)).await;
        assert_eq!((status.as_u16(), stale["code"].as_str()), (401, Some("identity_sensitive_write_session_not_fresh")));
        let (status, _, enabled) = send(&app, "PATCH", DEFINITION, OWNER, Some(ORIGIN), body(&enable)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(enabled["revision"], 2);
        let (status, _, stale_revision) = send(&app, "PATCH", DEFINITION, OWNER, Some(ORIGIN), body(&enable)).await;
        assert_eq!((status.as_u16(), stale_revision["code"].as_str()), (409, Some("automation_revision_conflict")));
        let manual = json!({"operationId":"same-intent","expectedRevision":2});
        let (status, _, accepted) = send(&app, "POST", MANUAL, OLD, Some(ORIGIN), body(&manual)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(accepted["occurrence"]["state"], "pending");
        let (status, _, replay) = send(&app, "POST", MANUAL, OWNER, Some(ORIGIN), body(&manual)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay, accepted);
        let receipt = format!("/api/automation-deliveries/{}", accepted["receiptId"].as_str().unwrap());
        let (status, _, read) = send(&app, "GET", &receipt, OWNER, None, Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(read, accepted);
        let (status, _, _) = send(&app, "GET", &receipt, ADMIN, None, Body::empty()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, rejected) = send(&app, "POST", MANUAL, OWNER, Some(ORIGIN), body(&json!({
            "operationId":"unknown-disposition","expectedRevision":2,"supersedesReceiptId":null
        }))).await;
        assert_eq!((status.as_u16(), rejected["code"].as_str()), (400, Some("unknown_disposition_unavailable")));

        let mut client = f.pool.get().await.unwrap();
        let held = client.transaction().await.unwrap();
        held.query_one("SELECT pending_count FROM openbot_internal.automation_workspace_capacity FOR UPDATE", &[]).await.unwrap();
        let (status, headers, blocked) = tokio::time::timeout(Duration::from_secs(8), send(
            &app, "POST", MANUAL, OWNER, Some(ORIGIN), body(&json!({"operationId":"lock-timeout","expectedRevision":2})),
        )).await.unwrap();
        assert_eq!((status.as_u16(), blocked["code"].as_str()), (503, Some("dependency_unavailable")));
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        held.rollback().await.unwrap();
        assert_eq!(client.query_one("SELECT count(*) FROM openbot_internal.automation_occurrences", &[]).await.unwrap().get::<_,i64>(0), 1);
        assert_eq!(client.query_one("SELECT count(*) FROM public.runs", &[]).await.unwrap().get::<_,i64>(0), 0);
        drop(client);
        drop(app);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17 and exact invocation"]
async fn tool_budget_recovers_original_acknowledged_journal_once() {
    use openbot_application::automation::{
        AutomationDispatchQueue, AutomationDispatcher, AutomationExecutionBudgets,
        AutomationToolIdentity,
    };
    use openbot_application::{ToolDecisionDraft, ToolJournal, ToolOutcomeDraft};
    use openbot_contracts::automation::{
        AutomationBudgetsFile, AutomationGrantConsent, AutomationGrantValidity,
        CreateAutomationDefinition, TriggerAutomationDefinition, UpdateAutomationDefinition,
    };
    use openbot_contracts::command::AppCommand;
    use openbot_contracts::ids::{CapabilityId, CatalogGeneration, ToolCallId};
    use openbot_domain::audit::hash::Sha256Digest;
    use openbot_domain::automation::AutomationBudgets;
    use openbot_domain::tool::approval::{ApprovalTarget, PolicyVersionTag};
    use openbot_domain::tool::commit::CommitState;
    use openbot_domain::tool::metadata::{
        ApprovalClass, Effect, EffectClassification, Idempotency, SandboxRequirement, ToolLimits,
        ToolMetadata, ToolName,
    };
    use openbot_domain::tool::pipeline::ToolOutcome;
    use openbot_infra::repo::tools::PostgresToolJournal;

    let admin = harness::admin_config("automation_tool_budget_recovery");
    harness::with_temp_database(&admin, "automation_tool_budget_recovery", |database| async move {
        let f = assembly_fixture::Fixture::with_options(
            &database,
            assembly_fixture::Options { automation: true, ..Default::default() },
        ).await?;
        let store = f.assembly.automations.as_ref().unwrap();
        let budget = json!([
            {"metric":"sampling_calls","totalLimit":"10"},
            {"metric":"tool_calls","totalLimit":"10"},
        ]);
        let startup_file: AutomationBudgetsFile = serde_json::from_value(json!({
            "schemaVersion":1,
            "revision":1,
            "workspaces":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),"budget":budget}],
            "owners":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),
                       "ownerId":f.auth.actor(),"budget":budget}],
        })).unwrap();
        store.install_budgets(Some(&AutomationBudgets::try_from(startup_file).unwrap()))
            .await.unwrap();
        let create: CreateAutomationDefinition = serde_json::from_value(json!({
            "automationId":"tool-budget",
            "config":{
                "schemaVersion":1,"title":"Tool budget recovery","botId":"delegated-bot",
                "promptTemplate":"Inspect the owner input.","trigger":{"kind":"manual"},
                "modelPolicy":"bot_current","runDeadlineSeconds":60,
                "permissionCeiling":{"toolIds":["computer.read"],"dataScopes":["owned-document"]},
                "budget":budget,
            },
        })).unwrap();
        let automation_id = create.automation_id.clone();
        let application = &f.assembly.application;
        application.execute(f.auth.clone(), AppCommand::CreateAutomationDefinition(create))
            .await.unwrap();
        application.execute(f.auth.clone(), AppCommand::UpdateAutomationDefinition {
            automation_id: automation_id.clone(),
            input: UpdateAutomationDefinition::Enable {
                expected_revision: 1.try_into().unwrap(),
                grant_consent: AutomationGrantConsent { validity: AutomationGrantValidity::UntilRevoked {} },
            },
        }).await.unwrap();
        application.execute(f.auth.clone(), AppCommand::TriggerAutomationDefinition {
            automation_id,
            input: TriggerAutomationDefinition {
                operation_id: "recover-tools".to_owned().try_into().unwrap(),
                expected_revision: 2.try_into().unwrap(),
            },
        }).await.unwrap();
        let dispatcher = AutomationDispatcher::new(
            store.clone(), f.assembly.delegated_entry.as_ref().unwrap().clone(),
        );
        assert_eq!(dispatcher.scan().await.unwrap(), 1);
        let runtime = &f.assembly.run_runtime;
        let claim = runtime.claim_dispatch().await.unwrap().unwrap();
        let lease = runtime.acknowledge_dispatch(&claim).await.unwrap();
        let journal = PostgresToolJournal::new(f.pool.clone(), vec![0x51;32]).unwrap();
        for (call_seq, commit_state) in [(0, CommitState::Committed), (1, CommitState::Unknown)] {
            let decision = ToolDecisionDraft {
                call_id: ToolCallId::new(format!("owned-tool-budget-call-{call_seq}")),
                run_id: lease.run_id().clone(),
                call_seq,
                actor: f.auth.actor().clone(),
                bot: lease.bot_id().clone(),
                metadata: ToolMetadata {
                    name: ToolName::new("computer.read").unwrap(),
                    schema_hash: Sha256Digest::of(b"owned journal schema"),
                    catalog_generation: CatalogGeneration::new(1),
                    effect: EffectClassification::declared(Effect::Read),
                    idempotency: Idempotency::NonIdempotent,
                    parallel_safe: false,
                    timeout: Duration::from_secs(5),
                    approval_class: ApprovalClass::NotRequired,
                    sandbox: SandboxRequirement::RequiredNoEgress,
                    limits: ToolLimits {
                        max_input_bytes: 1024, max_output_bytes: 1024, max_model_visible_bytes: 1024,
                    },
                    resource_locks: Vec::new(),
                },
                args_hash: Sha256Digest::of(b"owned journal arguments"),
                target: ApprovalTarget { kind: "document", id: "owned-document".to_owned() },
                policy_version: PolicyVersionTag::new("owned-tool-policy"),
                approval_id: None,
                idempotency_key: None,
            };
            let receipt = journal.record_decision(&decision).await.unwrap();
            let capability_id = CapabilityId::new(format!("owned-tool-budget-capability-{call_seq}"));
            journal.attach_capability(&decision.call_id, &capability_id).await.unwrap();
            store.reserve_tool(&f.auth, &AutomationToolIdentity {
                run_id: decision.run_id.clone(), call_id: decision.call_id.clone(), bot_id: decision.bot.clone(),
            }).await.unwrap();
            // Persist an outcome through the original journal to reproduce the settlement gap.
            journal.record_outcome(&ToolOutcomeDraft {
                decision, receipt, capability_id,
                outcome: ToolOutcome {
                    commit_state, output_bytes: 0, duration: Duration::from_millis(1), error_code: None,
                },
            }).await.unwrap();
        }

        let client = f.pool.get().await.unwrap();
        let ledger = "SELECT b.state,b.actual_usage,b.settled_at
                      FROM openbot_internal.automation_budget_attempts b
                      JOIN public.tool_attempts a ON a.attempt_id=b.source_attempt_ref
                      JOIN public.tool_calls c ON c.tool_call_id=a.tool_call_id
                      WHERE b.run_id=$1 AND b.usage_kind='tool'
                      ORDER BY c.call_seq";
        let run = lease.run_id().as_str();
        let before = client.query(ledger, &[&run]).await.unwrap();
        assert_eq!(before.len(), 2);
        assert!(before.iter().all(|row| row.get::<_, String>("state") == "unknown"));
        drop(client);
        store.maintain().await.unwrap();
        let client = f.pool.get().await.unwrap();
        let recovered = client.query(ledger, &[&run]).await.unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].get::<_, String>("state"), "settled");
        assert_eq!(recovered[0].get::<_, Value>("actual_usage")["tool_calls"], json!(1));
        assert_eq!(recovered[1].get::<_, String>("state"), "unknown");
        assert_eq!(recovered[1].get::<_, Option<Value>>("actual_usage"), None);
        let settled_at: time::OffsetDateTime = recovered[0].get("settled_at");
        drop(client);
        store.maintain().await.unwrap();
        let client = f.pool.get().await.unwrap();
        let repeated = client.query(ledger, &[&run]).await.unwrap();
        assert_eq!(repeated.len(), 2);
        assert_eq!(repeated[0].get::<_, time::OffsetDateTime>("settled_at"), settled_at);
        assert_eq!(repeated[1].get::<_, String>("state"), "unknown");
        let journal_rows: i64 = client.query_one("SELECT count(*) FROM public.tool_attempts", &[])
            .await.unwrap().get(0);
        assert_eq!(journal_rows, 2);
        drop(client);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}
