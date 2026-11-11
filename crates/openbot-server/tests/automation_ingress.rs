//! Sender-key ingress, receiver lifecycle and retention against the real router and owned PG.

#[path = "../../openbot-infra/tests/support/delegated_assembly_fixture.rs"]
pub mod assembly_fixture;
#[path = "support/transport_fixture.rs"]
mod transport_fixture;
mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use http::{HeaderMap, Request, StatusCode};
use openbot_application::automation::{
    AutomationDeliveryEntry, AutomationDispatchQueue, AutomationDispatcher,
};
use openbot_contracts::{
    automation::*,
    command::{AppCommand, AppReply},
    error::AppError,
};
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::vault::{KeyVersion, SecretKind, SecretPrincipal, ServiceId, WrappingKey};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::{PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ORIGIN: &str = "https://app.example.test";
const OWNER: &str = "owned-ingress-session-owner";
const OLD: &str = "owned-ingress-session-aged";
const ADMIN: &str = "owned-ingress-session-admin";
const SESSION_KEY: &[u8] = b"automation-ingress-fixture-session-hash-key";

fn vault(f: &assembly_fixture::Fixture) -> CredentialRecordVault {
    CredentialRecordVault::single_key(
        f.auth.tenant().clone(),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x42; 32]).unwrap(),
    )
}

fn router(
    f: &assembly_fixture::Fixture,
    delivery: Option<AutomationDeliveryEntry>,
) -> axum::Router {
    let resolver = PostgresSessionAuthResolver::new(
        f.pool.clone(),
        SESSION_KEY,
        default_session_lifetime(),
        f.auth.deployment().clone(),
        f.auth.tenant().clone(),
    )
    .unwrap();
    let security = SensitiveWriteSecurity::new(
        default_session_lifetime(),
        TrustedOrigins::from_configured([ORIGIN]).unwrap(),
    );
    transport_fixture::loopback_router(
        ServerBuilder::new(f.assembly.application.clone(), Arc::new(resolver))
            .with_transport_policy(transport_fixture::loopback_policy())
            .with_sensitive_write_security(security)
            .with_automation_delivery(delivery)
            .build(),
    )
}

async fn send(
    app: &axum::Router,
    request: http::request::Builder,
    body: impl Into<Body>,
) -> (StatusCode, HeaderMap, Value) {
    let response = app
        .clone()
        .oneshot(request.body(body.into()).unwrap())
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

fn owner_request(
    method: &str,
    path: &str,
    token: &str,
    origin: Option<&str>,
) -> http::request::Builder {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::COOKIE, format!("openbot_session={token}"))
        .header(http::header::CONTENT_TYPE, "application/json");
    match origin {
        Some(origin) => request.header(http::header::ORIGIN, origin),
        None => request,
    }
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn event(id: &str, event_type: &str, data: &str, occurred: &str) -> String {
    format!(
        r#"{{"eventId":"{id}","eventType":"{event_type}","occurredAt":"{occurred}","data":{data}}}"#
    )
}

async fn deliver(
    app: &axum::Router,
    receiver: &str,
    key: &str,
    body: String,
) -> (u16, HeaderMap, Value) {
    let request = Request::post(format!("/api/automation-ingress/{receiver}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::AUTHORIZATION, format!("Bearer {key}"));
    let (status, headers, value) = send(app, request, body).await;
    (status.as_u16(), headers, value)
}

fn config(trigger: Value) -> Value {
    json!({"schemaVersion":1,"title":"Event","botId":"delegated-bot",
        "promptTemplate":"Summarize the delivered event.","trigger":trigger,"modelPolicy":"bot_current",
        "permissionCeiling":{"toolIds":[],"dataScopes":[]},
        "budget":[{"metric":"sampling_calls","totalLimit":"10"}],"runDeadlineSeconds":60})
}

async fn install_budgets(f: &assembly_fixture::Fixture, owner: &str) {
    let wire: AutomationBudgetsFile = serde_json::from_value(json!({"schemaVersion":1,"revision":1,
        "workspaces":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),"budget":[{"metric":"sampling_calls","totalLimit":"500"}]}],
        "owners":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),"ownerId":owner,"budget":[{"metric":"sampling_calls","totalLimit":"500"}]}]})).unwrap();
    let budgets = openbot_domain::automation::AutomationBudgets::try_from(wire).unwrap();
    f.assembly
        .automations
        .as_ref()
        .unwrap()
        .install_budgets(Some(&budgets))
        .await
        .unwrap();
}

async fn execute(f: &assembly_fixture::Fixture, command: AppCommand) -> Result<AppReply, AppError> {
    f.assembly
        .application
        .execute(f.auth.clone(), command)
        .await
}

/// Create, enable and attach one receiver as the fixture owner; return the one-time key.
async fn enabled_receiver(
    f: &assembly_fixture::Fixture,
    automation: &str,
    receiver: &str,
    matches: Value,
) -> String {
    install_budgets(f, f.auth.actor().as_str()).await;
    execute(
        f,
        AppCommand::CreateAutomationDefinition(
            serde_json::from_value(json!({
        "automationId":automation,"config":config(json!({"kind":"event"}))}))
            .unwrap(),
        ),
    )
    .await
    .unwrap();
    execute(
        f,
        AppCommand::UpdateAutomationDefinition {
            automation_id: automation.to_owned().try_into().unwrap(),
            input: serde_json::from_value(json!({"action":"enable","expectedRevision":1,
            "grantConsent":{"validity":{"kind":"until_revoked"}}}))
            .unwrap(),
        },
    )
    .await
    .unwrap();
    new_receiver(f, automation, receiver, 2, matches).await
}

async fn new_receiver(
    f: &assembly_fixture::Fixture,
    automation: &str,
    receiver: &str,
    revision: i64,
    matches: Value,
) -> String {
    let AppReply::AutomationReceiverSecret(secret) = execute(
        f,
        AppCommand::CreateAutomationReceiver {
            automation_id: automation.to_owned().try_into().unwrap(),
            input: serde_json::from_value(
                json!({"receiverId":receiver,"expectedRevision":revision,
            "source":{"adapter":"sender_key","eventTypes":["push"],"matches":matches}}),
            )
            .unwrap(),
        },
    )
    .await
    .unwrap() else {
        panic!("receiver reply")
    };
    secret.sender_key.expose().to_owned()
}

async fn count(f: &assembly_fixture::Fixture, sql: &str) -> i64 {
    f.pool
        .get()
        .await
        .unwrap()
        .query_one(sql, &[])
        .await
        .unwrap()
        .get(0)
}

async fn facts(f: &assembly_fixture::Fixture) -> Value {
    f.pool.get().await.unwrap().query_one("SELECT jsonb_build_object(
        'deliveries',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY receipt_id),'[]') FROM openbot_internal.automation_deliveries t),
        'occurrences',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY occurrence_id),'[]') FROM openbot_internal.automation_occurrences t),
        'receivers',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY receiver_id),'[]') FROM openbot_internal.automation_receivers t),
        'outbox',(SELECT count(*) FROM public.outbox),'runs',(SELECT count(*) FROM public.runs),
        'capacity',(SELECT to_jsonb(c) FROM openbot_internal.automation_workspace_capacity c))", &[]).await.unwrap().get(0)
}

async fn receivers(f: &assembly_fixture::Fixture, automation: &str) -> Vec<AutomationReceiver> {
    let AppReply::AutomationDeliveries(page) = execute(
        f,
        AppCommand::ListAutomationDeliveries {
            automation_id: automation.to_owned().try_into().unwrap(),
            query: AutomationPageQuery::default(),
        },
    )
    .await
    .unwrap() else {
        panic!("deliveries reply")
    };
    page.receivers
}

fn refusal(receiver: &AutomationReceiver, reason: AutomationRefusalReason) -> u64 {
    receiver
        .refusals
        .iter()
        .find(|r| r.reason == reason)
        .map_or(0, |r| {
            assert!(r.first_at <= r.last_at);
            r.count
        })
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn event_delivery_runs_once_with_untrusted_material_and_replays_after_clearing() {
    let admin = harness::admin_config("automation_ingress_run");
    harness::with_temp_database(&admin, "automation_ingress_run", |database| async move {
        let f = assembly_fixture::Fixture::with_options(&database, assembly_fixture::Options {
            automation: true, subscribe: false, ..Default::default()
        }).await?;
        let app = router(&f, f.assembly.automation_delivery.clone());
        let key = enabled_receiver(&f, "event", "receiver-run", json!([{"path":["repo"],"op":"eq","value":"wrok"}])).await;
        assert_eq!(key.len(), 64);
        let at = now();

        let first = event("e-1", "push", r#"{"repo":"wrok","n":1.0,"note":"BODY-CANARY"}"#, &at);
        let (status, headers, accepted) = deliver(&app, "receiver-run", &key, first.clone()).await;
        assert_eq!(status, 202);
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        let receipt = accepted["receiptId"].as_str().unwrap().to_owned();
        assert!(receipt.starts_with("adel:"));
        assert_eq!(accepted, json!({"receiptId":receipt,"status":"accepted"}));
        let before = facts(&f).await;
        let (status, _, replay) = deliver(&app, "receiver-run", &key, first.clone()).await;
        assert_eq!((status, &replay), (200, &accepted));
        assert_eq!(facts(&f).await, before, "an exact replay takes no capacity and writes nothing");

        // Same receiver and event key delivered concurrently: one acceptance, one original receipt.
        let second = event("e-2", "push", r#"{"repo":"wrok"}"#, &at);
        let (a, b) = tokio::join!(deliver(&app, "receiver-run", &key, second.clone()), deliver(&app, "receiver-run", &key, second));
        let mut statuses = [a.0, b.0];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 202]);
        assert_eq!(a.2, b.2);

        // Number spelling and key order share one fingerprint; a different value conflicts.
        let (status, _, three) = deliver(&app, "receiver-run", &key, event("e-3", "push", r#"{"n":1,"repo":"wrok"}"#, &at)).await;
        assert_eq!(status, 202);
        let (status, _, replay) = deliver(&app, "receiver-run", &key, event("e-3", "push", r#"{"repo":"wrok","n":1.000}"#, &at)).await;
        assert_eq!((status, &replay), (200, &three));
        let (status, _, conflict) = deliver(&app, "receiver-run", &key, event("e-3", "push", r#"{"repo":"wrok","n":2}"#, &at)).await;
        assert_eq!((status, conflict["code"].as_str()), (409, Some("automation_event_conflict")));
        let stored: Value = f.pool.get().await.unwrap().query_one(
            "SELECT normalized_data FROM openbot_internal.automation_deliveries WHERE receipt_id=$1", &[&receipt]).await.unwrap().get(0);
        assert_eq!(stored["data"], json!({"repo":"wrok","n":1,"note":"BODY-CANARY"}));
        assert_eq!(stored["eventType"], "push");
        assert_eq!(count(&f, "SELECT count(*) FROM openbot_internal.automation_deliveries").await, 3);
        assert_eq!(count(&f, "SELECT count(*) FROM openbot_internal.automation_occurrences WHERE trigger_kind='event' AND state='pending'").await, 3);
        assert_eq!(count(&f, "SELECT count(*) FROM public.audit_events WHERE payload::text LIKE '%BODY-CANARY%'").await, 0);

        // Two workers scanning the same oldest occurrence create exactly one Run.
        let queue = f.assembly.automations.as_ref().unwrap().clone();
        let worker = AutomationDispatcher::new(queue.clone(), f.assembly.delegated_entry.as_ref().unwrap().clone());
        let second = worker.clone();
        let (x, y) = tokio::join!(worker.scan(), second.scan());
        x.unwrap();
        y.unwrap();
        let client = f.pool.get().await.unwrap();
        let row = client.query_one("SELECT o.run_id,o.state,
              (SELECT content->>'text' FROM public.messages WHERE message_id=o.run_id||':delegated_material') AS material,
              (SELECT count(*) FROM public.messages m WHERE m.run_id=o.run_id AND m.role='user' AND m.content::text LIKE '%BODY-CANARY%'
                 AND m.message_id<>o.run_id||':delegated_material') AS initial_with_data
            FROM openbot_internal.automation_occurrences o WHERE o.delivery_receipt_id=$1", &[&receipt]).await.unwrap();
        assert_eq!(row.get::<_, String>("state"), "run_created");
        let material: String = row.get("material");
        assert!(material.starts_with("Untrusted external material follows."));
        let text: Value = serde_json::from_str(material.split_once('\n').unwrap().1).unwrap();
        assert_eq!(text, stored, "the Run reads the fingerprinted interpretation");
        assert_eq!(row.get::<_, i64>("initial_with_data"), 0);
        assert_eq!(count(&f, "SELECT count(*) FROM public.runs").await, 1);
        drop(client);
        let AppReply::AutomationReceipt(read) = execute(&f, AppCommand::GetAutomationReceipt { receipt_id: receipt.clone().try_into().unwrap() }).await.unwrap() else { panic!() };
        assert_eq!(read.source, AutomationReceiptSource::Event { receiver_id: "receiver-run".to_owned().try_into().unwrap(), event_id: "e-1".to_owned().try_into().unwrap() });
        let occurrence = read.occurrence.clone().unwrap();
        assert_eq!(occurrence.state, AutomationOccurrenceState::RunCreated);
        let AppReply::AutomationReceipt(by_occurrence) = execute(&f, AppCommand::GetAutomationReceipt { receipt_id: occurrence.id.clone() }).await.unwrap() else { panic!() };
        assert_eq!(by_occurrence.occurrence, read.occurrence);
        let deliveries = receivers(&f, "event").await;
        assert_eq!(deliveries.len(), 1);

        // Pause and tombstone refuse new events, while exact replays still return 200.
        execute(&f, AppCommand::UpdateAutomationDefinition { automation_id: "event".to_owned().try_into().unwrap(),
            input: serde_json::from_value(json!({"action":"pause","expectedRevision":2})).unwrap() }).await.unwrap();
        assert_eq!(deliver(&app, "receiver-run", &key, first.clone()).await.0, 200);
        let (status, _, paused) = deliver(&app, "receiver-run", &key, event("e-4", "push", r#"{"repo":"wrok"}"#, &at)).await;
        assert_eq!((status, paused["code"].as_str()), (403, Some("automation_not_accepting")));
        execute(&f, AppCommand::TombstoneAutomationDefinition { automation_id: "event".to_owned().try_into().unwrap(),
            input: TombstoneAutomationDefinition { expected_revision: 3_i64.try_into().unwrap() } }).await.unwrap();
        assert_eq!(deliver(&app, "receiver-run", &key, first.clone()).await.0, 200);

        // Retention: six days keeps the body, seven days clears it once with one audit row.
        let client = f.pool.get().await.unwrap();
        let audits = "SELECT count(*) FROM public.audit_events WHERE payload::text LIKE '%automation_event_data_cleared%'";
        client.execute("UPDATE openbot_internal.automation_deliveries SET terminal_at=statement_timestamp()-interval '6 days 23 hours' WHERE receipt_id=$1", &[&receipt]).await.unwrap();
        queue.maintain().await.unwrap();
        assert_eq!(count(&f, "SELECT count(*) FROM openbot_internal.automation_deliveries WHERE normalized_data IS NULL").await, 0);
        client.execute("UPDATE openbot_internal.automation_deliveries SET terminal_at=statement_timestamp()-interval '7 days' WHERE receipt_id=$1", &[&receipt]).await.unwrap();
        let fingerprint: Vec<u8> = client.query_one("SELECT fingerprint FROM openbot_internal.automation_deliveries WHERE receipt_id=$1", &[&receipt]).await.unwrap().get(0);
        queue.maintain().await.unwrap();
        queue.maintain().await.unwrap();
        let cleared = client.query_one("SELECT normalized_data IS NULL AS gone,data_cleared_at IS NOT NULL AS marked,fingerprint FROM openbot_internal.automation_deliveries WHERE receipt_id=$1", &[&receipt]).await.unwrap();
        assert!(cleared.get::<_, bool>("gone") && cleared.get::<_, bool>("marked"));
        assert_eq!(cleared.get::<_, Vec<u8>>("fingerprint"), fingerprint);
        assert_eq!(count(&f, audits).await, 1);
        assert_eq!(count(&f, "SELECT count(*) FROM openbot_internal.automation_deliveries WHERE normalized_data IS NULL").await, 1);
        drop(client);
        let AppReply::AutomationReceipt(read) = execute(&f, AppCommand::GetAutomationReceipt { receipt_id: receipt.clone().try_into().unwrap() }).await.unwrap() else { panic!() };
        assert!(read.data_cleared);
        let (status, _, replay) = deliver(&app, "receiver-run", &key, first).await;
        assert_eq!((status, &replay), (200, &accepted));
        let (status, _, conflict) = deliver(&app, "receiver-run", &key, event("e-1", "push", r#"{"repo":"other"}"#, &at)).await;
        assert_eq!((status, conflict["code"].as_str()), (409, Some("automation_event_conflict")));
        drop(app);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn rejection_order_refusal_counters_and_limits() {
    let admin = harness::admin_config("automation_ingress_refusals");
    harness::with_temp_database(&admin, "automation_ingress_refusals", |database| async move {
        let f = assembly_fixture::Fixture::with_options(&database, assembly_fixture::Options {
            automation: true, subscribe: false, ..Default::default()
        }).await?;
        let app = router(&f, f.assembly.automation_delivery.clone());
        let key = enabled_receiver(&f, "refusals", "receiver-a", json!([{"path":["repo"],"op":"in","value":["wrok",7]}])).await;
        let at = now();
        let ok = |id: &str| event(id, "push", r#"{"repo":"wrok"}"#, &at);
        let wrong = "f".repeat(64);
        let before = facts(&f).await;
        let past = (time::OffsetDateTime::now_utc() - time::Duration::hours(25)).format(&time::format_description::well_known::Rfc3339).unwrap();
        let future = (time::OffsetDateTime::now_utc() + time::Duration::minutes(10)).format(&time::format_description::well_known::Rfc3339).unwrap();
        for (receiver, key, body, status, code) in [
            ("receiver-a", wrong.as_str(), ok("r-1"), 401, "automation_source_unauthorized"),
            ("unknown-receiver", key.as_str(), ok("r-1"), 401, "automation_source_unauthorized"),
            ("receiver-a", key.as_str(), event("r-1", "pull", r#"{"repo":"wrok"}"#, &at), 403, "event_not_accepted"),
            ("receiver-a", key.as_str(), event("r-1", "push", r#"{"repo":"7.0"}"#, &at), 403, "event_not_accepted"),
            ("receiver-a", key.as_str(), event("r-1", "push", r#"{"repo":"wrok"}"#, &past), 400, "event_outside_window"),
            ("receiver-a", key.as_str(), event("r-1", "push", r#"{"repo":"wrok"}"#, &future), 400, "event_outside_window"),
            ("receiver-a", key.as_str(), event("r-1", "push", r#"{"repo":"wrok","a":{"x":1,"x":2}}"#, &at), 400, "malformed_payload"),
            ("receiver-a", key.as_str(), event("r-1", "push", r#"{"repo":"wrok","\u0000":1}"#, &at), 400, "malformed_payload"),
            ("receiver-a", key.as_str(), event("r-1", "push", r#"{"repo":"wrok","v":"\u0000"}"#, &at), 400, "malformed_payload"),
            ("receiver-a", key.as_str(), event("r-1", "push", &format!(r#"{{"repo":"wrok","v":"{}"}}"#, "x".repeat(64 * 1024)), &at), 413, "payload_too_large"),
        ] {
            let (actual, headers, error) = deliver(&app, receiver, key, body).await;
            assert_eq!((actual, error["code"].as_str()), (status, Some(code)));
            assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        }
        let mut after = facts(&f).await;
        after["receivers"] = before["receivers"].clone();
        assert_eq!(after, before, "refusals write no delivery, occurrence, key or outbox");
        assert_eq!(count(&f, "SELECT count(*) FROM openbot_internal.automation_receiver_refusals WHERE receiver_id<>'receiver-a'").await, 0);

        // Authentication precedes replay, and an authenticated replay is still validated first.
        let (status, _, accepted) = deliver(&app, "receiver-a", &key, ok("r-1")).await;
        assert_eq!(status, 202);
        assert_eq!(deliver(&app, "receiver-a", &wrong, ok("r-1")).await.0, 401);
        let dup = event("r-1", "push", r#"{"repo":"wrok","a":{"x":1,"x":1}}"#, &at);
        assert_eq!(deliver(&app, "receiver-a", &key, dup).await.0, 400);
        let (status, _, replay) = deliver(&app, "receiver-a", &key, ok("r-1")).await;
        assert_eq!((status, &replay), (200, &accepted));

        // Dedup ceiling and pending capacity reject without evicting the old key.
        let key_b = new_receiver(&f, "refusals", "receiver-b", 2, json!([])).await;
        let (status, _, kept) = deliver(&app, "receiver-b", &key_b, ok("b-1")).await;
        assert_eq!(status, 202);
        let client = f.pool.get().await.unwrap();
        client.execute("UPDATE openbot_internal.automation_receivers SET dedup_count=1000000 WHERE receiver_id='receiver-b'", &[]).await.unwrap();
        let (status, _, full) = deliver(&app, "receiver-b", &key_b, ok("b-2")).await;
        assert_eq!((status, full["code"].as_str()), (429, Some("automation_receiver_full")));
        assert_eq!(deliver(&app, "receiver-b", &key_b, ok("b-1")).await.2, kept);
        client.execute("UPDATE openbot_internal.automation_receivers SET dedup_count=1 WHERE receiver_id='receiver-b'", &[]).await.unwrap();
        let pending: i64 = client.query_one("SELECT pending_count FROM openbot_internal.automation_definitions WHERE automation_id='refusals'", &[]).await.unwrap().get(0);
        client.execute("UPDATE openbot_internal.automation_definitions SET pending_count=100 WHERE automation_id='refusals'", &[]).await.unwrap();
        let (status, _, capacity) = deliver(&app, "receiver-b", &key_b, ok("b-3")).await;
        assert_eq!((status, capacity["code"].as_str()), (429, Some("automation_capacity_exceeded")));
        client.execute("UPDATE openbot_internal.automation_definitions SET pending_count=$1 WHERE automation_id='refusals'", &[&pending]).await.unwrap();
        drop(client);
        execute(&f, AppCommand::UpdateAutomationDefinition { automation_id: "refusals".to_owned().try_into().unwrap(),
            input: serde_json::from_value(json!({"action":"pause","expectedRevision":2})).unwrap() }).await.unwrap();
        assert_eq!(deliver(&app, "receiver-b", &key_b, ok("b-4")).await.0, 403);

        let projected = receivers(&f, "refusals").await;
        let a = projected.iter().find(|r| r.id.as_str() == "receiver-a").unwrap();
        assert_eq!(refusal(a, AutomationRefusalReason::SourceUnauthorized), 2);
        assert_eq!(refusal(a, AutomationRefusalReason::EventNotAccepted), 2);
        assert_eq!(refusal(a, AutomationRefusalReason::EventOutsideWindow), 2);
        assert_eq!(refusal(a, AutomationRefusalReason::MalformedPayload), 4);
        assert_eq!(refusal(a, AutomationRefusalReason::PayloadTooLarge), 1);
        let b = projected.iter().find(|r| r.id.as_str() == "receiver-b").unwrap();
        assert_eq!(refusal(b, AutomationRefusalReason::NotAccepting), 1);
        assert_eq!(b.refusals.len(), 1, "capacity and dedup ceilings are not refusal reasons");
        drop(app);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn sender_storm_answers_accept_or_rate_limit_without_extra_writes() {
    let admin = harness::admin_config("automation_ingress_storm");
    harness::with_temp_database(&admin, "automation_ingress_storm", |database| async move {
        let f = assembly_fixture::Fixture::with_options(
            &database,
            assembly_fixture::Options {
                automation: true,
                subscribe: false,
                ..Default::default()
            },
        )
        .await?;
        let app = router(&f, f.assembly.automation_delivery.clone());
        let key = enabled_receiver(&f, "storm", "receiver-storm", json!([])).await;
        let at = now();
        // Burst 20, refill 10 per second, taken inside the serialized acceptance transaction.
        // Requests stay under the definition's 100 pending. Whether any request is limited
        // depends on how fast this build commits acceptances (the limiter arithmetic is covered
        // by the infra unit test), so the storm asserts only timing-independent facts: every
        // answer is an acceptance or a rate limit, and a rate limit writes nothing but its counter.
        let (mut accepted, mut limited) = (0_i64, 0_u64);
        for wave in 0..99_usize.div_ceil(8) {
            let mut tasks = Vec::new();
            for index in wave * 8..(wave * 8 + 8).min(99) {
                let (app, key) = (app.clone(), key.clone());
                let body = event(&format!("storm-{index}"), "push", r#"{"repo":"wrok"}"#, &at);
                tasks.push(tokio::spawn(async move {
                    deliver(&app, "receiver-storm", &key, body).await
                }));
            }
            for task in tasks {
                let (status, headers, body) = task.await.unwrap();
                match status {
                    202 => accepted += 1,
                    429 => {
                        limited += 1;
                        assert_eq!(body["code"], "automation_rate_limited");
                        assert_eq!(headers[http::header::RETRY_AFTER], "1");
                    }
                    other => panic!("unexpected storm status {other}: {body}"),
                }
            }
        }
        assert_eq!(accepted + i64::try_from(limited).unwrap(), 99);
        assert!(accepted >= 20, "{accepted} accepted, {limited} limited");
        assert_eq!(
            count(
                &f,
                "SELECT count(*) FROM openbot_internal.automation_deliveries"
            )
            .await,
            accepted
        );
        assert_eq!(
            count(
                &f,
                "SELECT count(*) FROM openbot_internal.automation_occurrences"
            )
            .await,
            accepted
        );
        let projected = receivers(&f, "storm").await;
        assert_eq!(
            refusal(&projected[0], AutomationRefusalReason::RateLimited),
            limited
        );
        assert_eq!(projected[0].refusals.len(), usize::from(limited > 0));
        drop(app);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn receiver_lifecycle_fresh_origin_cas_and_vault_storage() {
    let admin = harness::admin_config("automation_ingress_receivers");
    harness::with_temp_database(&admin, "automation_ingress_receivers", |database| async move {
        let f = assembly_fixture::Fixture::with_options(&database, assembly_fixture::Options {
            single_user: false, automation: true, subscribe: false, ..Default::default()
        }).await?;
        let client = f.pool.get().await.unwrap();
        client.execute("INSERT INTO public.user_roles(user_id,role) VALUES('other-owner','user')", &[]).await.unwrap();
        let pg_now: time::OffsetDateTime = client.query_one("SELECT statement_timestamp()", &[]).await.unwrap().get(0);
        for (session, actor, token, age) in [("owner", "other-owner", OWNER, 1), ("aged", "other-owner", OLD, 30), ("admin", "dev-local-user", ADMIN, 1)] {
            let hash = SessionTokenHash::compute(SessionToken::new(token.as_bytes()), SessionHashKey::new(SESSION_KEY)).to_column_value();
            client.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$6,0)",
                &[&session, &actor, &hash, &(pg_now + time::Duration::hours(1)), &(pg_now - time::Duration::minutes(age)), &pg_now]).await.unwrap();
        }
        drop(client);
        install_budgets(&f, "other-owner").await;
        let app = router(&f, f.assembly.automation_delivery.clone());
        let body = |value: Value| value.to_string();
        for (id, trigger) in [("event-http", json!({"kind":"event"})), ("manual-http", json!({"kind":"manual"}))] {
            let (status, _, _) = send(&app, owner_request("POST", "/api/automations", OWNER, Some(ORIGIN)),
                body(json!({"automationId":id,"config":config(trigger)}))).await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let enable = body(json!({"action":"enable","expectedRevision":1,"grantConsent":{"validity":{"kind":"until_revoked"}}}));
        assert_eq!(send(&app, owner_request("PATCH", "/api/automations/event-http", OWNER, Some(ORIGIN)), enable).await.0, StatusCode::OK);

        let create = |receiver: &str, revision: i64, adapter: &str| body(json!({"receiverId":receiver,"expectedRevision":revision,
            "source":{"adapter":adapter,"eventTypes":["push"],"matches":[]}}));
        let path = "/api/automations/event-http/receivers";
        for (token, origin, input, status, code) in [
            (OLD, Some(ORIGIN), create("http-r", 2, "sender_key"), 401, "identity_sensitive_write_session_not_fresh"),
            (OWNER, None, create("http-r", 2, "sender_key"), 403, "identity_sensitive_write_origin_missing"),
            (ADMIN, Some(ORIGIN), create("http-r", 2, "sender_key"), 404, "not_visible"),
            (OWNER, Some(ORIGIN), create("http-r", 2, "github"), 400, "event_adapter_unavailable"),
            (OWNER, Some(ORIGIN), create("http-r", 1, "sender_key"), 409, "automation_revision_conflict"),
            (OWNER, Some(ORIGIN), body(json!({"receiverId":"http-r","expectedRevision":2,"senderKey":"x","source":{"adapter":"sender_key","eventTypes":["push"],"matches":[]}})), 400, "malformed_payload"),
        ] {
            let (actual, headers, error) = send(&app, owner_request("POST", path, token, origin), input).await;
            assert_eq!((actual.as_u16(), error["code"].as_str()), (status, Some(code)));
            assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        }
        let (status, _, error) = send(&app, owner_request("POST", "/api/automations/manual-http/receivers", OWNER, Some(ORIGIN)), create("manual-r", 1, "sender_key")).await;
        assert_eq!((status.as_u16(), error["code"].as_str()), (400, Some("malformed_payload")));
        let (status, headers, created) = send(&app, owner_request("POST", path, OWNER, Some(ORIGIN)), create("http-r", 2, "sender_key")).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        assert_eq!((created["keyRevision"].as_i64(), created["adapter"].as_str()), (Some(1), Some("sender_key")));
        assert_eq!(created["sourcePrincipal"], json!({"adapter":"sender_key","receiverId":"http-r"}));
        let key = created["senderKey"].as_str().unwrap().to_owned();
        assert!(key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        let (_, _, definition) = send(&app, owner_request("GET", "/api/automations/event-http", OWNER, None), "").await;
        assert_eq!(definition["revision"], 2, "creating a receiver does not advance the definition");
        let (status, _, error) = send(&app, owner_request("POST", path, OWNER, Some(ORIGIN)), create("http-r", 2, "sender_key")).await;
        assert_eq!((status.as_u16(), error["code"].as_str()), (409, Some("automation_operation_conflict")));

        // Storage: one existing Vault row per key revision; no secret outside its ciphertext.
        let client = f.pool.get().await.unwrap();
        let row = client.query_one("SELECT c.id,c.encrypted_value FROM public.credentials c JOIN openbot_internal.automation_receivers r ON c.id=r.vault_record_ref::uuid
            WHERE r.receiver_id='http-r' AND c.kind='agent' AND c.provider='automation_receiver' AND c.key_id='http-r' AND c.metadata='{}'::jsonb AND c.revoked_at IS NULL", &[]).await.unwrap();
        let credential: uuid::Uuid = row.get(0);
        let sealed: String = row.get(1);
        assert!(!sealed.contains(&key));
        for table in ["openbot_internal.automation_receivers", "openbot_internal.automation_definitions", "openbot_internal.automation_definition_revisions", "public.audit_events", "public.credentials"] {
            let leaked: i64 = client.query_one(&format!("SELECT count(*) FROM {table} t WHERE to_jsonb(t)::text LIKE '%'||$1||'%'"), &[&key]).await.unwrap().get(0);
            assert_eq!(leaked, 0, "{table}");
        }
        let vault = vault(&f);
        let owner = SecretPrincipal::Actor(openbot_contracts::ids::ActorId::new("other-owner"));
        let opened = vault.open(&credential, SecretKind::Agent, owner.clone(), SecretPrincipal::Service(ServiceId::new("automation_receiver:http-r")), &sealed).unwrap();
        assert_eq!(opened.into_secret().expose(), key.as_bytes());
        assert!(vault.open(&credential, SecretKind::Agent, owner, SecretPrincipal::Service(ServiceId::new("http-r")), &sealed).is_err(),
            "Agent lifecycle AAD cannot open a receiver key");
        drop(client);

        let at = now();
        let first = event("h-1", "push", "{}", &at);
        assert_eq!(deliver(&app, "http-r", &key, first.clone()).await.0, 202);

        // Rotation: CAS, fresh session, immediate invalidation, no overlap.
        let rotate = "/api/automation-receivers/http-r/rotate-key";
        let (status, _, error) = send(&app, owner_request("POST", rotate, OWNER, Some(ORIGIN)), body(json!({"expectedKeyRevision":2}))).await;
        assert_eq!((status.as_u16(), error["code"].as_str()), (409, Some("automation_key_revision_conflict")));
        assert_eq!(send(&app, owner_request("POST", rotate, OLD, Some(ORIGIN)), body(json!({"expectedKeyRevision":1}))).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(send(&app, owner_request("POST", rotate, ADMIN, Some(ORIGIN)), body(json!({"expectedKeyRevision":1}))).await.0, StatusCode::NOT_FOUND);
        let (status, headers, rotated) = send(&app, owner_request("POST", rotate, OWNER, Some(ORIGIN)), body(json!({"expectedKeyRevision":1}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        assert_eq!(rotated["keyRevision"], 2);
        let key2 = rotated["senderKey"].as_str().unwrap().to_owned();
        assert_ne!(key2, key);
        assert_eq!(count(&f, &format!("SELECT count(*) FROM public.credentials WHERE id='{credential}' AND revoked_at IS NOT NULL")).await, 1);
        assert_eq!(count(&f, "SELECT count(*) FROM public.credentials WHERE key_id='http-r' AND revoked_at IS NULL").await, 1);
        assert_eq!(deliver(&app, "http-r", &key, first.clone()).await.0, 401, "the old key cannot even replay");
        assert_eq!(deliver(&app, "http-r", &key2, first.clone()).await.0, 200);

        // The administrator inventory lists the row as metadata, cannot replace it, and can revoke it.
        let AppReply::Credentials(page) = execute(&f, AppCommand::ListCredentials(Default::default())).await.unwrap() else { panic!() };
        let listed = page.credentials.iter().find(|c| c.key_id == "http-r" && c.revoked_at.is_none()).unwrap();
        assert_eq!(listed.provider, "automation_receiver");
        // Credential retirement runs under the request's recovery admission, so both writes
        // go through the admin routes with a real session binding.
        let replacement = json!({"kind":"connector","provider":"automation_receiver","keyId":"http-r","metadata":{},"plaintext":"replacement"});
        let (status, _, _) = send(&app, owner_request("POST", &format!("/api/admin/credentials/{}/rotate", listed.id), ADMIN, Some(ORIGIN)), body(replacement)).await;
        assert!(!status.is_success(), "a managed row was replaced: {status}");
        assert_eq!(deliver(&app, "http-r", &key2, first.clone()).await.0, 200);
        let (status, _, _) = send(&app, owner_request("POST", &format!("/api/admin/credentials/{}/revoke", listed.id), ADMIN, Some(ORIGIN)), Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(deliver(&app, "http-r", &key2, first.clone()).await.0, 401);

        // Owner rotation restores delivery; revoke is CAS-checked and permanent.
        let (_, _, rotated) = send(&app, owner_request("POST", rotate, OWNER, Some(ORIGIN)), body(json!({"expectedKeyRevision":2}))).await;
        let key3 = rotated["senderKey"].as_str().unwrap().to_owned();
        assert_eq!(deliver(&app, "http-r", &key3, first.clone()).await.0, 200);
        let revoke = "/api/automation-receivers/http-r";
        let (status, _, error) = send(&app, owner_request("DELETE", revoke, OWNER, Some(ORIGIN)), body(json!({"expectedKeyRevision":2}))).await;
        assert_eq!((status.as_u16(), error["code"].as_str()), (409, Some("automation_key_revision_conflict")));
        assert_eq!(send(&app, owner_request("DELETE", revoke, ADMIN, Some(ORIGIN)), body(json!({"expectedKeyRevision":3}))).await.0, StatusCode::NOT_FOUND);
        let (status, _, revoked) = send(&app, owner_request("DELETE", revoke, OWNER, Some(ORIGIN)), body(json!({"expectedKeyRevision":3}))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(revoked["revokedAt"].is_string());
        assert!(revoked.get("senderKey").is_none());
        assert_eq!(deliver(&app, "http-r", &key3, first.clone()).await.0, 401);
        assert_eq!(count(&f, "SELECT count(*) FROM public.credentials WHERE key_id='http-r' AND revoked_at IS NULL").await, 0);
        let (status, _, rotated) = send(&app, owner_request("POST", rotate, OWNER, Some(ORIGIN)), body(json!({"expectedKeyRevision":3}))).await;
        assert_eq!((status.as_u16(), rotated["code"].as_str()), (409, Some("automation_key_revision_conflict")));

        // The owner deliveries read carries receivers and their refusal counters; admin sees 404.
        let (status, _, page) = send(&app, owner_request("GET", "/api/automations/event-http/deliveries", OWNER, None), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(page["receivers"][0]["id"], "http-r");
        assert!(page["receivers"][0].get("senderKey").is_none());
        let unauthorized = page["receivers"][0]["refusals"].as_array().unwrap().iter()
            .find(|r| r["reason"] == "automation_source_unauthorized").unwrap()["count"].as_u64().unwrap();
        assert_eq!(unauthorized, 3);
        assert_eq!(send(&app, owner_request("GET", "/api/automations/event-http/deliveries", ADMIN, None), "").await.0, StatusCode::NOT_FOUND);
        drop(app);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn commit_unknown_and_restart_converge_on_one_run() {
    let admin = harness::admin_config("automation_ingress_commit");
    harness::with_temp_database(&admin, "automation_ingress_commit", |database| async move {
        let options = || assembly_fixture::Options { automation: true, subscribe: false, ..Default::default() };
        let f = assembly_fixture::Fixture::with_options(&database, options()).await?;
        let key = enabled_receiver(&f, "commit", "receiver-c", json!([])).await;
        let body = event("c-1", "push", r#"{"n":1}"#, &now());

        // The owned proxy withholds the real backend COMMIT acknowledgment, not the write.
        let proxy = assembly_fixture::CommitAckProxy::start(&database).await.unwrap();
        let proxy_pool = openbot_infra::db::pool::connect(&proxy.config).await.unwrap();
        let through_proxy = openbot_infra::automation::PostgresAutomations::new(
            proxy_pool.clone(), f.auth.deployment().clone(), f.auth.tenant().clone(),
            openbot_domain::vault::SecretBytes::new(vec![0x51; 32]), vault(&f),
            openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&proxy_pool, f.auth.deployment(), f.auth.tenant())).unwrap();
        let unknown = router(&f, Some(AutomationDeliveryEntry::new(Arc::new(through_proxy))));
        proxy.drop_next_commit_ack();
        let (status, _, error) = deliver(&unknown, "receiver-c", &key, body.clone()).await;
        assert_eq!((status, error["code"].as_str()), (503, Some("dependency_unavailable")));
        assert_eq!(proxy.dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(unknown);
        proxy_pool.close();
        drop(proxy_pool);
        proxy.stop().await.unwrap();
        let original: String = f.pool.get().await.unwrap().query_one(
            "SELECT receipt_id FROM openbot_internal.automation_deliveries WHERE source_event_key='c-1'", &[]).await.unwrap().get(0);
        let app = router(&f, f.assembly.automation_delivery.clone());
        let (status, _, replay) = deliver(&app, "receiver-c", &key, body.clone()).await;
        assert_eq!((status, replay["receiptId"].as_str()), (200, Some(original.as_str())));
        drop(app);
        f.assembly.shutdown().await;
        f.pool.close();

        // A restarted process has no in-memory dedup: PG alone returns the original receipt.
        let f = assembly_fixture::Fixture::reopen_with_options(&database, options()).await?;
        let app = router(&f, f.assembly.automation_delivery.clone());
        let (status, _, replay) = deliver(&app, "receiver-c", &key, body.clone()).await;
        assert_eq!((status, replay["receiptId"].as_str()), (200, Some(original.as_str())));
        let worker = AutomationDispatcher::new(f.assembly.automations.as_ref().unwrap().clone(), f.assembly.delegated_entry.as_ref().unwrap().clone());
        assert_eq!(worker.scan().await.unwrap(), 1);
        assert_eq!(deliver(&app, "receiver-c", &key, body).await.0, 200);
        assert_eq!(worker.scan().await.unwrap(), 0);
        assert_eq!(count(&f, "SELECT count(*) FROM public.runs").await, 1);
        assert_eq!(count(&f, "SELECT count(*) FROM openbot_internal.automation_deliveries").await, 1);
        drop(app);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}
