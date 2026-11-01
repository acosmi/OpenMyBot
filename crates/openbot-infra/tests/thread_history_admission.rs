//! Finite native0050 storage admission on owned synthetic PostgreSQL17.11.
//! Internal metadata and permanent IDs; this suite grants no current Host or ACK.
#![cfg(feature = "server-runtime")]
mod harness;
use async_trait::async_trait;
use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{
    BeginThreadRunRequest, BeginThreadRunV2Request, INTELLIGENCE_SOURCE_COMMIT,
    IntelligenceImportError, IntelligenceImportProgress, IntelligenceImportReportStatus,
    IntelligenceImportStore, IntelligenceThreadImportReceipt, IntelligenceThreadImportRequest,
    IntelligenceToolRunFkReport, RunRuntime, RunTerminal, ThreadDirectory, ThreadDirectoryError,
    VerifiedIntelligenceBundle, compute_intelligence_thread_checksum, import_intelligence_bundle,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRun, BeginThreadRunV2, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId},
    intelligence::{
        INTELLIGENCE_BUNDLE_SCHEMA_VERSION, IntelligenceBundlePayload,
        IntelligenceBundleProvenance, IntelligenceImportMapping, IntelligenceThreadAnchor,
        IntelligenceThreadChecksum, IntelligenceThreadExport, IntelligenceThreadStatus,
    },
    model_connections::{CreateModelConnection, CustomModelProtocol, ModelApiKey, ModelConnection},
    versioned_model_selection::{ModelSelectionIntentSource, RunModelSelectionV2},
};
use openbot_domain::{
    remote_callback::RemoteRunAssertionSigner,
    vault::{KeyVersion, SecretBytes, WrappingKey},
};
use openbot_infra::{
    application_assembly::{
        ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
        assemble_postgres_application,
    },
    artifact_registry::ArtifactDatasetRegistry,
    model_connections::PostgresModelConnections,
    model_dataset::PostgresModelDatasetBinding,
    policy::PolicyStore,
    vault::CredentialRecordVault,
};
use openbot_infra::{
    db::{InfraError, baseline, desktop_vault_canary, fresh, native, pool, schema_facts},
    intelligence_import::PostgresIntelligenceImportStore,
    repo::ChannelRepo,
    run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime},
    thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory},
};
use serde_json::{Value, json};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::macros::datetime;
use tokio_postgres::Client;
use uuid::Uuid;
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, String>;
const DEP: &str = "owned-origin-deployment";
const TENANT: &str = "owned-origin-tenant";
const PROCESS: &str = "owned-origin-runtime";
const ORIGIN_COLUMNS: &str = "thread_id,deployment_id,tenant_id,creator_actor_id,anchor_kind,anchor_id,thread_created_at,origin_kind,origin_schema,recorded_at,import_bundle_id,import_payload_sha256,import_signing_key_id,import_thread_checksum";
use openbot_infra::db::thread_history_admission_schema as admission_schema;
include!("support/thread_history_admission_schema_fixture.rs");

const THREAD_INSERT: &str = "INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status,next_message_seq,next_event_seq,created_at,updated_at,deleted_at) VALUES($1,'owned-origin-tenant','owned-origin-deployment','origin-a','direct_bot',$2,'Owned permanent ID','active',0,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z',NULL)";
const OP: &str = "019a1234-5678-7abc-8abc-000000000001";
const REQUEST: &str = "019a1234-5678-7abc-8abc-000000000002";

fn portable_admission(observation: &Value) -> TestResult<Value> {
    let mut schema = observation["schema"].clone();
    let indexes = schema["indexes"]
        .as_array_mut()
        .ok_or("admission indexes absent")?;
    let exact = [
        "thread_history_heads_pkey",
        "thread_history_heads_thread_id_key",
        "thread_history_heads_base_key",
        "thread_history_clear_intents_pkey",
        "thread_history_clear_intents_thread_key",
        "thread_history_clear_intents_request_key",
        "thread_history_clear_intents_closed_binding_key",
    ];
    require(
        indexes.len() == exact.len(),
        "HOT exception cannot absorb unknown index",
    )?;
    let mut seen = std::collections::BTreeSet::new();
    for index in indexes {
        let name = index["identity"]["name"]
            .as_str()
            .ok_or("index identity absent")?;
        require(
            index["identity"]["schema"] == "openbot_internal"
                && exact.contains(&name)
                && seen.insert(name.to_owned())
                && index["checkXmin"].is_boolean(),
            "HOT exception identity/uniqueness/runtime type differs",
        )?;
        index["checkXmin"] = json!({"predicate":"pg17_hot_runtime_boolean_v1"});
    }
    Ok(schema)
}
async fn check_admission(c: &Client) -> TestResult<Value> {
    let actual = admission_schema::capture(c)
        .await
        .map_err(|e| e.to_string())?;
    let expected: Value = serde_json::from_str(include_str!(
        "../../../fixtures/db/thread-history-admission-0050.json"
    ))
    .map_err(|e| e.to_string())?;
    println!(
        "THREAD_HISTORY50_CAPTURE {}",
        serde_json::to_string(&actual).map_err(|e| e.to_string())?
    );
    require(
        actual["format"] == "thread-history-admission-observation-v1"
            && actual.as_object().map(|x| x.len()) == Some(4),
        "admission observation shape differs",
    )?;
    require(
        portable_admission(&actual)? == expected["schema"],
        "complete independent admission oracle differs",
    )?;
    let states = actual["tableAclStates"]
        .as_array()
        .ok_or("two raw ACL states absent")?;
    require(states.len() == 2, "table ACL state collection not closed")?;
    let mut names = std::collections::BTreeSet::new();
    for state in states {
        let name = state["relation"]["name"]
            .as_str()
            .ok_or("ACL relation missing")?;
        require(
            state["relation"]["schema"] == "openbot_internal"
                && ["thread_history_heads", "thread_history_clear_intents"].contains(&name)
                && names.insert(name),
            "ACL relation identity differs",
        )?;
        require(
            expected["allowedTableAclStates"]
                .as_array()
                .ok_or("expected ACL states absent")?
                .contains(&state["state"]),
            "raw table ACL state unregistered",
        )?;
    }
    require(actual["rawFacts"].is_object(), "raw graph proof absent")?;
    let ledger = native::validate_known_prefix(c, 50)
        .await
        .map_err(|e| e.to_string())?;
    require(
        ledger.latest_version() == 50,
        "historical0050 prefix is not exact50/38",
    )?;
    Ok(actual)
}
async fn head(c: &Client, id: &str) -> TestResult<Option<Value>> {
    c.query_opt("SELECT to_jsonb(h)||jsonb_build_object('storageXmin',xmin::text) FROM openbot_internal.thread_history_heads h WHERE thread_id=$1",&[&id]).await.map_err(|e|e.to_string())?.map(|r|r.try_get(0).map_err(|e|e.to_string())).transpose()
}
async fn check_base_head(c: &Client, id: &str) -> TestResult<Value> {
    let h = head(c, id)
        .await?
        .ok_or("real Thread has no permanent head")?;
    require(
        h.as_object().map(|x| x.len()) == Some(15) && h["head_schema"] == 1 && h["phase"] == "open",
        "head stored shape/schema/phase differs",
    )?;
    let r=c.query_one("SELECT (h.deployment_id,h.tenant_id,h.thread_id,h.anchor_kind,h.anchor_id,h.thread_created_at)=(t.deployment_id,t.tenant_id,t.thread_id,t.anchor_kind,t.anchor_id,t.created_at),isfinite(h.recorded_at),h.closure_operation_id IS NULL AND h.closure_request_id IS NULL AND h.closure_actor_id IS NULL AND h.closure_auth_generation IS NULL AND h.closed_at IS NULL FROM openbot_internal.thread_history_heads h JOIN public.threads t USING(thread_id) WHERE h.thread_id=$1",&[&id]).await.map_err(|e|e.to_string())?;
    require(
        (0..3).all(|i| r.get::<_, bool>(i)),
        "actual Thread/full base/head open tuple differs",
    )?;
    Ok(h)
}
async fn immediate_refusal(c: &Client, sql: &str, accepted_codes: &[&str]) -> TestResult {
    c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
    let result = c.batch_execute(sql).await;
    c.batch_execute("ROLLBACK")
        .await
        .map_err(|e| e.to_string())?;
    let error = result
        .err()
        .ok_or("actual statement unexpectedly accepted")?;
    require(
        error
            .code()
            .is_some_and(|code| accepted_codes.contains(&code.code())),
        "actual refusal SQLSTATE outside registered cause",
    )
}
async fn deferred_refusal(c: &Client, sql: &str) -> TestResult {
    c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
    if let Err(error) = c.batch_execute(sql).await {
        c.batch_execute("ROLLBACK")
            .await
            .map_err(|e| e.to_string())?;
        return Err(format!(
            "deferred premise failed before real COMMIT: {error}"
        ));
    }
    let result = c.batch_execute("COMMIT").await;
    c.batch_execute("ROLLBACK")
        .await
        .map_err(|e| e.to_string())?;
    let error = result
        .err()
        .ok_or("deferred invalid pair actually committed")?;
    require(
        error
            .code()
            .is_some_and(|code| matches!(code.code(), "23503" | "55000")),
        "deferred refusal has wrong cause",
    )
}
fn intent_sql(id: &str) -> String {
    // All identifiers here are owned fixed ASCII fixtures, never user-controlled input.
    format!(
        "INSERT INTO openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at) SELECT deployment_id,tenant_id,thread_id,1,'stop_clear','{OP}','{REQUEST}','owned-close-actor',7,anchor_kind,anchor_id,thread_created_at,'2026-09-01T00:00:01Z' FROM openbot_internal.thread_history_heads WHERE thread_id='{id}';"
    )
}
fn closed_sql(id: &str) -> String {
    format!(
        "UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id='{OP}',closure_request_id='{REQUEST}',closure_actor_id='owned-close-actor',closure_auth_generation=7,closed_at='2026-09-01T00:00:01Z' WHERE thread_id='{id}';"
    )
}
async fn close_metadata(c: &Client, id: &str) -> TestResult {
    c.batch_execute(&format!(
        "BEGIN;{}{}COMMIT;",
        intent_sql(id),
        closed_sql(id)
    ))
    .await
    .map_err(|e| e.to_string())?;
    require(
        head(c, id).await?.ok_or("closed metadata vanished")?["phase"] == "closed",
        "metadata close did not commit",
    )
}
async fn raw_thread(c: &Client, id: &str) -> TestResult {
    c.execute(THREAD_INSERT, &[&id, &"origin-bot"])
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
async fn owned_raw_catalog(c: &Client) -> TestResult<Value> {
    // This is a finite before/after observation of owned synthetic metadata, not an
    // expected oracle and not a scan of application/user tables or arbitrary schemas.
    c.query_one("WITH relations AS (SELECT oid FROM pg_class WHERE oid IN ('openbot_internal.thread_history_heads'::regclass,'openbot_internal.thread_history_clear_intents'::regclass,'public.threads'::regclass)), functions AS (SELECT oid FROM pg_proc WHERE pronamespace='openbot_internal'::regnamespace AND proname IN ('guard_thread_history_head_mutation','prevent_thread_history_intent_mutation','require_thread_history_intent_closed_head','bind_thread_history_head_on_insert','retain_thread_history_head_on_delete','protect_thread_history_base_identity','prevent_thread_history_base_truncate')) SELECT jsonb_build_object(
        'relations',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.oid) FROM pg_class x WHERE x.oid IN (SELECT oid FROM relations) OR x.oid IN (SELECT indexrelid FROM pg_index WHERE indrelid IN (SELECT oid FROM relations))),
        'attributes',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.attrelid,x.attnum) FROM pg_attribute x WHERE x.attrelid IN (SELECT oid FROM relations)),
        'defaults',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.oid) FROM pg_attrdef x WHERE x.adrelid IN (SELECT oid FROM relations)),
        'constraints',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.oid) FROM pg_constraint x WHERE x.conrelid IN (SELECT oid FROM relations) OR x.confrelid IN (SELECT oid FROM relations)),
        'indexes',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.indexrelid) FROM pg_index x WHERE x.indrelid IN (SELECT oid FROM relations)),
        'triggers',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.oid) FROM pg_trigger x WHERE x.tgrelid IN (SELECT oid FROM relations) OR x.tgfoid IN (SELECT oid FROM functions)),
        'functions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.oid) FROM pg_proc x WHERE x.oid IN (SELECT oid FROM functions)))",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())
}
// Helpers used only by this suite; the shared fixture is also included by thread_history_writer.
async fn record_import(
    p: &pool::DatabasePool,
    index: u64,
) -> TestResult<(
    RecordingImport,
    VerifiedIntelligenceBundle,
    IntelligenceImportMapping,
    IntelligenceThreadExport,
    IntelligenceThreadImportRequest,
)> {
    let (verified, mapping, normalized) = import_fixture(index)?;
    let store = RecordingImport {
        store: PostgresIntelligenceImportStore::new(p.clone()),
        request: std::sync::Mutex::new(None),
    };
    let report = import_intelligence_bundle(&store, verified.clone(), mapping.clone())
        .await
        .map_err(|e| e.to_string())?;
    require(
        report.status == IntelligenceImportReportStatus::Completed && report.thread_count == 1,
        "original maintenance application did not truly complete",
    )?;
    let captured = store
        .request
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or("original app never reached import_thread")?;
    require(
        captured.thread == normalized && captured.checksum == normalized.checksum,
        "original app target normalization differs independently mapped fixture",
    )?;
    Ok((store, verified, mapping, normalized, captured))
}
async fn origin(c: &Client, thread: &str) -> TestResult<Option<Value>> {
    let query = format!(
        "SELECT to_jsonb(o) FROM (SELECT {ORIGIN_COLUMNS},xmin::text AS \"storageXmin\" FROM openbot_internal.thread_origins WHERE thread_id=$1) o"
    );
    c.query_opt(&query, &[&thread])
        .await
        .map_err(|e| e.to_string())?
        .map(|row| row.try_get(0).map_err(|e| e.to_string()))
        .transpose()
}
async fn counts(p: &pool::DatabasePool) -> TestResult<Vec<i64>> {
    let c = p.get().await.map_err(|e| e.to_string())?;
    let mut out = vec![];
    for table in [
        "public.threads",
        "public.thread_memberships",
        "public.thread_leases",
        "public.messages",
        "public.runs",
        "public.run_events",
        "public.outbox",
        "openbot_internal.thread_origins",
        "public.run_model_selections",
        "openbot_internal.run_model_selection_v2_snapshots",
        "public.channels",
        "public.channel_memberships",
        "public.channel_agents",
        "openbot_internal.thread_history_heads",
        "openbot_internal.thread_history_clear_intents",
    ] {
        out.push(
            c.query_one(&format!("SELECT count(*)::bigint FROM {table}"), &[])
                .await
                .map_err(|e| e.to_string())?
                .try_get(0)
                .map_err(|e| e.to_string())?,
        );
    }
    Ok(out)
}
async fn verify_native_origin(
    c: &Client,
    thread: &str,
    creator: &str,
    kind: &str,
) -> TestResult<Value> {
    let value = origin(c, thread)
        .await?
        .ok_or("actual new Thread has no origin")?;
    require(
        value.as_object().map(|v| v.len()) == Some(15),
        "origin must preserve exactly14 stored columns plus observed xmin",
    )?;
    require(
        value["thread_id"] == thread
            && value["deployment_id"] == DEP
            && value["tenant_id"] == TENANT
            && value["creator_actor_id"] == creator
            && value["origin_kind"] == kind
            && value["origin_schema"] == 1,
        "origin identity/creator/kind differ",
    )?;
    let r=c.query_one("SELECT o.thread_created_at=t.created_at AND o.creator_actor_id=t.created_by AND o.anchor_kind=t.anchor_kind AND o.anchor_id=t.anchor_id,isfinite(o.thread_created_at) AND isfinite(o.recorded_at),o.import_bundle_id IS NULL AND o.import_payload_sha256 IS NULL AND o.import_signing_key_id IS NULL AND o.import_thread_checksum IS NULL FROM openbot_internal.thread_origins o JOIN public.threads t USING(thread_id) WHERE o.thread_id=$1",&[&thread]).await.map_err(|e|e.to_string())?;
    require(
        r.try_get::<_, bool>(0).map_err(|e| e.to_string())?
            && r.try_get::<_, bool>(1).map_err(|e| e.to_string())?
            && r.try_get::<_, bool>(2).map_err(|e| e.to_string())?,
        "base tuple/finite timestamps/import NULL facts differ",
    )?;
    Ok(value)
}
async fn settle(p: &pool::DatabasePool, run: &str) -> TestResult {
    let runtime = PostgresRunRuntime::new(
        p.clone(),
        PROCESS.to_owned(),
        DEFAULT_THREAD_LEASE_DURATION,
        DEFAULT_DISPATCH_CLAIM_DURATION,
        openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
            &p,
            &openbot_contracts::ids::DeploymentId::new("outside"),
            &openbot_contracts::ids::TenantId::new("outside"),
        ),
    )
    .map_err(|e| e.to_string())?;
    let claim = runtime
        .claim_dispatch()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("real pending dispatch absent")?;
    let lease = runtime
        .acknowledge_dispatch(&claim)
        .await
        .map_err(|e| e.to_string())?;
    require(
        lease.run_id().as_str() == run,
        "claimed different original Run",
    )?;
    runtime
        .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s01_fresh50_complete_independent_schema_and_original_owner() {
    owned("history50oracle", |p, _| async move {
        initialize(&p, 50).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        let first = check_admission(&c).await?;
        require(
            first["schema"]["relations"].as_array().map(|x| x.len()) == Some(2)
                && first["schema"]["constraints"].as_array().map(|x| x.len()) == Some(25)
                && first["schema"]["triggers"].as_array().map(|x| x.len()) == Some(17)
                && first["schema"]["functions"].as_array().map(|x| x.len()) == Some(11),
            "full catalog closure counts differ",
        )?;
        require(
            first["tableAclStates"]
                .as_array()
                .ok_or("ACL absent")?
                .iter()
                .all(|x| x["state"]["aclIsNull"] == true),
            "fresh ACL not rawNULL",
        )?;
        for table in ["thread_history_heads", "thread_history_clear_intents"] {
            c.batch_execute(&format!(
                "GRANT ALL PRIVILEGES ON openbot_internal.{table} TO CURRENT_USER"
            ))
            .await
            .map_err(|e| e.to_string())?;
            check_admission(&c).await?;
        }
        let public: schema_facts::SchemaFacts =
            serde_json::from_str(include_str!("../../../fixtures/db/schema-0050.json"))
                .map_err(|e| e.to_string())?;
        require(
            schema_facts::fetch(&c).await.map_err(|e| e.to_string())? == public,
            "independent public0050 facts differ",
        )?;
        Ok(())
    })
    .await;
    owned("history50portableowner",|p,_|async move {
        let mut c=p.get().await.map_err(|e|e.to_string())?;
        let name=format!("openbot_it_history_{}",Uuid::new_v4().simple());
        let renamed=format!("{name}_r");
        let database:String=c.query_one("SELECT current_database()",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(renamed.len()<63&&database.starts_with("openbot_it_")&&database.chars().all(|x|x.is_ascii_alphanumeric()||x=='_'),"owned role/database identifier escaped")?;
        c.batch_execute(&format!("CREATE ROLE \"{name}\" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;GRANT CREATE ON DATABASE \"{database}\" TO \"{name}\";GRANT USAGE,CREATE ON SCHEMA public TO \"{name}\";SET ROLE \"{name}\";")).await.map_err(|e|e.to_string())?;
        let result:TestResult=async {
            baseline::apply(&c).await.map_err(|e|e.to_string())?;
            native::apply_through(&mut c, 50).await.map_err(|e|e.to_string())?;
            let old:String=c.query_one("SELECT relowner::text FROM pg_class WHERE oid='public.threads'::regclass",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
            require(old!="10","owner O not distinct from PG bootstrap")?;
            check_admission(&c).await?;
            c.batch_execute(&format!("RESET ROLE;ALTER ROLE \"{name}\" RENAME TO \"{renamed}\";SET ROLE \"{renamed}\";")).await.map_err(|e|e.to_string())?;
            let same:String=c.query_one("SELECT relowner::text FROM pg_class WHERE oid='public.threads'::regclass",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
            require(same==old,"owner rename changed OID")?;
            check_admission(&c).await?;
            Ok(())
        }.await;
        let reset=c.batch_execute("RESET ROLE").await.map_err(|e|e.to_string());
        let cleanup=if reset.is_ok() {
            let actual:String=c.query_one("SELECT rolname FROM pg_roles WHERE rolname=$1 OR rolname=$2",&[&name,&renamed]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
            c.batch_execute(&format!("DROP OWNED BY \"{actual}\" CASCADE;DROP ROLE \"{actual}\";")).await.map_err(|e|e.to_string())
        } else {Err("owned RESET failed".into())};
        result.and(reset).and(cleanup)
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s02_historical49_upgrade50_and_zero_ddl_replay() {
    owned("history50upgrade",|p,_|async move {
        initialize(&p,49).await?;
        let mut c=p.get().await.map_err(|e|e.to_string())?;
        let old:Value=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM openbot_internal.schema_migrations m",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(native::apply_through(&mut c,49).await.map_err(|e|e.to_string())?==native::ApplyOutcome::AlreadyApplied,"historical49 replay drifted")?;
        require(c.query_one("SELECT to_regclass('openbot_internal.thread_history_heads') IS NULL AND to_regclass('openbot_internal.thread_history_clear_intents') IS NULL",&[]).await.map_err(|e|e.to_string())?.get::<_,bool>(0),"explicit49 fabricated50")?;
        require(native::apply_through(&mut c, 50).await.map_err(|e|e.to_string())?==native::ApplyOutcome::Applied,"actual49->50 did not apply")?;
        let retained:Value=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM openbot_internal.schema_migrations m WHERE version<=49",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(retained==old,"upgrade rewrote old ledger bytes")?;
        let r=c.query_one("SELECT count(*),max(version) FROM openbot_internal.schema_migrations",&[]).await.map_err(|e|e.to_string())?;
        require(r.get::<_,i64>(0)==38&&r.get::<_,i32>(1)==50,"ordinary ledger not exact38/50")?;
        check_admission(&c).await?;
        c.batch_execute("CREATE TABLE openbot_internal.owned_history_ddl(tag text);CREATE FUNCTION openbot_internal.owned_history_ddl_probe() RETURNS event_trigger LANGUAGE plpgsql AS $$BEGIN INSERT INTO openbot_internal.owned_history_ddl SELECT command_tag FROM pg_event_trigger_ddl_commands();END$$;CREATE EVENT TRIGGER owned_history_ddl_probe ON ddl_command_end EXECUTE FUNCTION openbot_internal.owned_history_ddl_probe();TRUNCATE openbot_internal.owned_history_ddl;").await.map_err(|e|e.to_string())?;
        require(native::apply_through(&mut c, 50).await.map_err(|e|e.to_string())?==native::ApplyOutcome::AlreadyApplied,"current50 replay outcome differs")?;
        require(c.query_one("SELECT count(*) FROM openbot_internal.owned_history_ddl",&[]).await.map_err(|e|e.to_string())?.get::<_,i64>(0)==0,"exact current replay issued actual DDL")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s03_four_real_producers_atomically_bind_heads_without_creator_adoption() {
    owned("history50producers",|p,config|async move {
        provision(&p).await?;
        let d=directory(&p,&config)?;
        let req=request("origin-a",3501);
        d.begin_thread_run(req.clone()).await.map_err(|e|e.to_string())?;
        {let c=p.get().await.map_err(|e|e.to_string())?;check_base_head(&c,req.command.thread_id.as_str()).await?;verify_native_origin(&c,req.command.thread_id.as_str(),"origin-a","native_begin_v1").await?;}
        let created=openbot_application::create_channel(&ChannelRepo::new(p.clone()),&current_owned_auth(&p,"origin-a").await?,vec![BotId::new("origin-bot")]).await.map_err(|e|e.to_string())?;
        {let c=p.get().await.map_err(|e|e.to_string())?;let id=created.thread_id.as_ref().ok_or("real channel no Thread")?;check_base_head(&c,id.as_str()).await?;verify_native_origin(&c,id.as_str(),"origin-a","private_agent_channel").await?;}
        let (_,_,_,normalized,_)=record_import(&p,3502).await?;
        {let c=p.get().await.map_err(|e|e.to_string())?;check_base_head(&c,&normalized.thread_id).await?;require(origin(&c,&normalized.thread_id).await?.ok_or("real import origin missing")?["origin_kind"]=="maintenance_import","real import origin kind differs")?;}
        let f=ModelFixture::new(p.clone(),config.clone()).await;
        let result:TestResult=async {
            let model=f.model(CustomModelProtocol::OpenaiResponses).await;
            let req=f.request(3503,false,&model);
            f.directory.begin_thread_run_v2(req.clone()).await.map_err(|e|e.to_string())?;
            let c=p.get().await.map_err(|e|e.to_string())?;
            check_base_head(&c,req.command.thread_id.as_str()).await?;
            verify_native_origin(&c,req.command.thread_id.as_str(),"alice","native_begin_v2").await?;
            require(c.query_one("SELECT count(*) FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?.get::<_,i64>(0)==1,"original V2 snapshot missing")?;
            Ok(())
        }.await;
        f.finish().await;
        result?;
        let failed=request("origin-a",3504);
        {let c=p.get().await.map_err(|e|e.to_string())?;c.execute("INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload) VALUES($1,'test','owned-preexisting',0,'agent_run_dispatch','internal','{}'::jsonb)",&[&format!("{}:agent_run_dispatch",failed.command.run_id.as_str())]).await.map_err(|e|e.to_string())?;}
        let before=counts(&p).await?;
        require(d.begin_thread_run(failed.clone()).await==Err(ThreadDirectoryError::RequestConflict),"real late outbox fault not refused")?;
        require(counts(&p).await?==before,"late original transaction left business/origin/H/Q rows")?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        require(head(&c,failed.command.thread_id.as_str()).await?.is_none()&&origin(&c,failed.command.thread_id.as_str()).await?.is_none(),"late FAIL left durable H/origin")?;
        raw_thread(&c,"owned-synthetic-no-origin").await?;
        check_base_head(&c,"owned-synthetic-no-origin").await?;
        require(origin(&c,"owned-synthetic-no-origin").await?.is_none(),"SQL metadata silently adopted creator provenance")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s04_closed_head_intent_commit_requires_exact_deferred_pair() {
    owned("history50joint",|p,_|async move {
        initialize(&p,50).await?;let c=p.get().await.map_err(|e|e.to_string())?;
        raw_thread(&c,"owned-joint").await?;
        let before=head(&c,"owned-joint").await?;
        let q=intent_sql("owned-joint");let h=closed_sql("owned-joint");
        let mut negatives=vec![q.clone(),h.clone()];
        for wrong_h in [h.replace(OP,"019a1234-5678-7abc-8abc-000000000003"),h.replace(REQUEST,"019a1234-5678-7abc-8abc-000000000004"),h.replace("owned-close-actor","wrong-actor"),h.replace("closure_auth_generation=7","closure_auth_generation=8"),h.replace("00:00:01Z","00:00:02Z")] {negatives.push(format!("{q}{wrong_h}"));}
        for wrong_q in [q.replace("SELECT deployment_id,tenant_id,thread_id", "SELECT 'wrong-deployment',tenant_id,thread_id"),q.replace("SELECT deployment_id,tenant_id,thread_id", "SELECT deployment_id,'wrong-tenant',thread_id"),
            q.replace("SELECT deployment_id,tenant_id,thread_id", "SELECT deployment_id,tenant_id,'wrong-thread'"),q.replace("7,anchor_kind,anchor_id", "7,'channel',anchor_id"),
            q.replace("anchor_kind,anchor_id,thread_created_at,'2026", "anchor_kind,'wrong-anchor',thread_created_at,'2026"),q.replace("anchor_id,thread_created_at,'2026", "anchor_id,thread_created_at+interval '1 second','2026")] {negatives.push(format!("{wrong_q}{h}"));}
        for sql in negatives {
            deferred_refusal(&c,&sql).await?;
            require(head(&c,"owned-joint").await?==before,"failed COMMIT modified original H/xmin")?;
            require(c.query_one("SELECT count(*) FROM openbot_internal.thread_history_clear_intents",&[]).await.map_err(|e|e.to_string())?.get::<_,i64>(0)==0,"failed COMMIT retained Q half")?;
        }
        close_metadata(&c,"owned-joint").await?;
        require(origin(&c,"owned-joint").await?.is_none(),"closed internal metadata minted creator/current Host")?;
        // Storage-only foundation intentionally permits body changes until the next writer task.
        c.execute("UPDATE public.threads SET title='Owned body after metadata close' WHERE thread_id='owned-joint'",&[]).await.map_err(|e|e.to_string())?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s05_head_intent_identity_uuid_generation_time_and_null_shape() {
    owned("history50shape",|p,_|async move {
        initialize(&p,50).await?;let c=p.get().await.map_err(|e|e.to_string())?;
        let h="INSERT INTO openbot_internal.thread_history_heads(deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES('d','t','owned-shape',1,'open','direct_bot','a','2026-09-01')";
        c.batch_execute(h).await.map_err(|e|e.to_string())?;
        require(origin(&c,"owned-shape").await?.is_none(),"free H metadata granted provenance")?;
        for boundary in ["repeat('x',512)","repeat('界',170)||'xx'"] {c.batch_execute(&h.replace("'owned-shape'",boundary)).await.map_err(|e|e.to_string())?;}
        for sql in [h.replace("'owned-shape'","''"),h.replace("'owned-shape'","repeat('x',513)"),h.replace("'owned-shape'","E'bad\\n'"),
            h.replace("'owned-shape'","repeat('界',171)"),h.replace("'owned-shape'","'bad'||chr(159)"),h.replace(",1,'open'",",2,'open'"),h.replace("'direct_bot'","'unsupported'"),h.replace("'2026-09-01'","'infinity'"),h.replace("'open'","'closed'")] {
            immediate_refusal(&c,&sql,&["23514"]).await?;
        }
        raw_thread(&c,"owned-shape-q").await?;
        let q=intent_sql("owned-shape-q");
        for sql in [q.replace(OP,"019a1234-5678-4abc-8abc-000000000001"),q.replace(REQUEST,"019A1234-5678-7abc-8abc-000000000002"),
            q.replace("'owned-close-actor',7","'owned-close-actor',-1"),q.replace("'owned-close-actor',7","'owned-close-actor',9223372036854775808"),q.replace("'stop_clear'","'stop_only'"),q.replace(",1,'stop_clear'",",2,'stop_clear'"),q.replace("'2026-09-01T00:00:01Z'","'-infinity'"),q.replace("'owned-close-actor'","NULL")] {
            immediate_refusal(&c,&sql,&["23514","23502","22003"]).await?;
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s06_metadata_irreversible_noop_delete_and_empty_truncate_are_refused() {
    owned("history50irreversible", |p, _| async move {
        initialize(&p, 50).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        for table in ["thread_history_heads", "thread_history_clear_intents"] {
            immediate_refusal(
                &c,
                &format!("TRUNCATE openbot_internal.{table}"),
                &["55000", "0A000"],
            )
            .await?;
            immediate_refusal(
                &c,
                &format!("TRUNCATE openbot_internal.{table} CASCADE"),
                &["55000"],
            )
            .await?;
        }
        raw_thread(&c, "owned-immutable").await?;
        immediate_refusal(
            &c,
            "UPDATE openbot_internal.thread_history_heads SET phase=phase",
            &["55000"],
        )
        .await?;
        close_metadata(&c, "owned-immutable").await?;
        let before = head(&c, "owned-immutable").await?;
        for sql in [
            "UPDATE openbot_internal.thread_history_heads SET phase='open'",
            "UPDATE openbot_internal.thread_history_heads SET closed_at=closed_at",
            "DELETE FROM openbot_internal.thread_history_heads",
            "UPDATE openbot_internal.thread_history_clear_intents SET operation_id=operation_id",
            "DELETE FROM openbot_internal.thread_history_clear_intents",
            "TRUNCATE openbot_internal.thread_history_heads CASCADE",
            "TRUNCATE openbot_internal.thread_history_clear_intents CASCADE",
        ] {
            immediate_refusal(&c, sql, &["55000"]).await?;
        }
        immediate_refusal(
            &c,
            &intent_sql("owned-immutable")
                .replace(OP, "019a1234-5678-7abc-8abc-000000000003")
                .replace(REQUEST, "019a1234-5678-7abc-8abc-000000000004"),
            &["23505"],
        )
        .await?;
        require(
            head(&c, "owned-immutable").await? == before,
            "refused reverse/noop/delete changed closed H/xmin",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s07_live_replay_preserves_head_and_bad_tuple_refuses() {
    owned("history50replay",|p,_|async move {
        initialize(&p,49).await?;let mut c=p.get().await.map_err(|e|e.to_string())?;
        raw_thread(&c,"owned-live").await?;
        raw_thread(&c,"owned-bad-head").await?;
        native::apply(&mut c).await.map_err(|e|e.to_string())?;
        require(head(&c,"owned-live").await?.is_none(),"migration backfilled unknown creator/head eagerly")?;
        require(c.execute(&format!("{THREAD_INSERT} ON CONFLICT(thread_id) DO NOTHING"),&[&"owned-live",&"origin-bot"]).await.map_err(|e|e.to_string())?==0,"live replay inserted duplicate Thread")?;
        let original=check_base_head(&c,"owned-live").await?;
        for _ in 0..2 {c.execute(&format!("{THREAD_INSERT} ON CONFLICT(thread_id) DO NOTHING"),&[&"owned-live",&"origin-bot"]).await.map_err(|e|e.to_string())?;}
        require(head(&c,"owned-live").await?==Some(original),"exact replay rewrote H/xmin")?;
        let result=c.execute(&format!("{THREAD_INSERT} ON CONFLICT(thread_id) DO NOTHING"),&[&"owned-live",&"wrong-anchor"]).await;
        require(result.is_err_and(|e|e.code().is_some_and(|x|x.code()=="55000")),"bad fulltuple replay accepted")?;
        c.execute("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp() WHERE thread_id='owned-live'",&[]).await.map_err(|e|e.to_string())?;
        c.execute(&format!("{THREAD_INSERT} ON CONFLICT(thread_id) DO NOTHING"),&[&"owned-live",&"origin-bot"]).await.map_err(|e|e.to_string())?;
        require(origin(&c,"owned-live").await?.is_none(),"live metadata replay retrofilled origin/creator")?;
        c.batch_execute("INSERT INTO openbot_internal.thread_history_heads(deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) SELECT 'wrong-deployment',tenant_id,thread_id,1,'open',anchor_kind,anchor_id,created_at FROM public.threads WHERE thread_id='owned-bad-head'").await.map_err(|e|e.to_string())?;
        let replay=c.execute(&format!("{THREAD_INSERT} ON CONFLICT(thread_id) DO NOTHING"),&[&"owned-bad-head",&"origin-bot"]).await;
        require(replay.is_err_and(|e|e.code().is_some_and(|x|x.code()=="55000")),"bad stored fulltuple accepted actual replay")?;
        immediate_refusal(&c,"DELETE FROM public.threads WHERE thread_id='owned-bad-head'",&["55000"]).await?;
        immediate_refusal(&c,"UPDATE public.threads SET anchor_id='changed-anchor' WHERE thread_id='owned-bad-head'",&["55000"]).await?;
        require(origin(&c,"owned-bad-head").await?.is_none(),"bad free SQL head granted creator provenance")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s08_hard_delete_keeps_permanent_id_and_recreation_refuses() {
    owned("history50permanent", |p, _| async move {
        initialize(&p, 49).await?;
        let mut c = p.get().await.map_err(|e| e.to_string())?;
        raw_thread(&c, "owned-old-delete").await?;
        native::apply(&mut c).await.map_err(|e| e.to_string())?;
        require(
            head(&c, "owned-old-delete").await?.is_none(),
            "old unknown eagerly filled",
        )?;
        c.execute(
            "DELETE FROM public.threads WHERE thread_id='owned-old-delete'",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
        let retained = head(&c, "owned-old-delete")
            .await?
            .ok_or("actual DELETE did not retain ID")?;
        require(
            retained["anchor_id"] == "origin-bot"
                && origin(&c, "owned-old-delete").await?.is_none(),
            "DELETE retention fabricated provenance",
        )?;
        require(
            c.execute(THREAD_INSERT, &[&"owned-old-delete", &"origin-bot"])
                .await
                .is_err(),
            "permanent identical ID reused after hard delete",
        )?;
        raw_thread(&c, "owned-new-delete").await?;
        let original = head(&c, "owned-new-delete").await?;
        c.batch_execute(
            "BEGIN;DELETE FROM public.threads WHERE thread_id='owned-new-delete';ROLLBACK",
        )
        .await
        .map_err(|e| e.to_string())?;
        require(
            head(&c, "owned-new-delete").await? == original,
            "ROLLBACK altered permanent H",
        )?;
        c.execute(
            "DELETE FROM public.threads WHERE thread_id='owned-new-delete'",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
        require(
            head(&c, "owned-new-delete").await? == original,
            "actual hard delete rewrote retained H",
        )?;
        require(
            c.execute(THREAD_INSERT, &[&"owned-new-delete", &"origin-bot"])
                .await
                .is_err(),
            "new permanent ID reused after hard delete",
        )?;
        c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
        raw_thread(&c, "owned-insert-rollback").await?;
        require(
            head(&c, "owned-insert-rollback").await?.is_some(),
            "same original Tx lacked provisional H",
        )?;
        c.batch_execute("ROLLBACK")
            .await
            .map_err(|e| e.to_string())?;
        require(
            head(&c, "owned-insert-rollback").await?.is_none(),
            "INSERT ROLLBACK retained permanent H",
        )?;
        Ok(())
    })
    .await;
    owned("history50knownpermanent",|p,config|async move {
        provision(&p).await?;let d=directory(&p,&config)?;
        for (index,closed) in [(3508,false),(3509,true)] {
            let req=request("origin-a",index);
            d.begin_thread_run(req.clone()).await.map_err(|e|e.to_string())?;
            settle(&p,req.command.run_id.as_str()).await?;
            let c=p.get().await.map_err(|e|e.to_string())?;
            let id=req.command.thread_id.as_str();
            let o=verify_native_origin(&c,id,"origin-a","native_begin_v1").await?;
            if closed {close_metadata(&c,id).await?;}
            let h=head(&c,id).await?;
            require(c.execute("DELETE FROM public.threads WHERE thread_id=$1",&[&id]).await.map_err(|e|e.to_string())?==1,"Known hard DELETE did not affect real Thread")?;
            require(head(&c,id).await?==h&&origin(&c,id).await?==Some(o),"Known hard DELETE altered H/origin identities")?;
            let same=c.execute("INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status,next_message_seq,next_event_seq,created_at,updated_at,deleted_at) SELECT thread_id,tenant_id,deployment_id,creator_actor_id,anchor_kind,anchor_id,'Owned same tuple','active',0,0,thread_created_at,thread_created_at,NULL FROM openbot_internal.thread_origins WHERE thread_id=$1",&[&id]).await;
            require(same.is_err_and(|e|e.code().is_some_and(|x|x.code()=="55000")),"Known same ID/fulltuple recreated after source DELETE")?;
            let different=c.execute(THREAD_INSERT,&[&id,&"other-anchor"]).await;
            require(different.is_err_and(|e|e.code().is_some_and(|x|x.code()=="55000")),"Known old ID recreated with foreign tuple")?;
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s09_thread_identity_update_and_truncate_cannot_escape_retention() {
    owned("history50identity",|p,_|async move {
        initialize(&p,50).await?;let c=p.get().await.map_err(|e|e.to_string())?;
        immediate_refusal(&c,"TRUNCATE public.threads",&["55000","0A000"]).await?;
        immediate_refusal(&c,"TRUNCATE public.threads CASCADE",&["55000"]).await?;
        raw_thread(&c,"owned-identity").await?;
        for sql in ["UPDATE public.threads SET thread_id='changed-id'","UPDATE public.threads SET tenant_id='changed-tenant'","UPDATE public.threads SET deployment_id='changed-deployment'",
            "UPDATE public.threads SET anchor_kind='channel'","UPDATE public.threads SET anchor_id='changed-anchor'","UPDATE public.threads SET created_at=created_at+interval '1 second'","TRUNCATE public.threads CASCADE"] {
            immediate_refusal(&c,sql,&["55000"]).await?;
        }
        c.execute("UPDATE public.threads SET title='Owned metadata',created_by='owned-other-creator',status='deleted',deleted_at=clock_timestamp() WHERE thread_id='owned-identity'",&[]).await.map_err(|e|e.to_string())?;
        require(origin(&c,"owned-identity").await?.is_none(),"unscoped metadata update granted current/creator authority")?;
        Ok(())
    }).await;
}

async fn observed_lock(c: &Client, pid: i32) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let waiting:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0)",&[&pid]).await.map_err(|e|e.to_string())?.get(0);
        if waiting {
            return Ok(());
        }
        require(
            Instant::now() < deadline,
            "actual PostgreSQL blocker wait was not observed",
        )?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn wait_round(
    p: &pool::DatabasePool,
    id: &'static str,
    existing: bool,
    commit: bool,
) -> TestResult {
    let a = p.get().await.map_err(|e| e.to_string())?;
    a.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(|e| e.to_string())?;
    if existing {
        a.execute(
            "UPDATE public.threads SET anchor_id='changed-anchor' WHERE thread_id=$1",
            &[&id],
        )
        .await
        .map_err(|e| e.to_string())?;
    } else {
        a.execute(THREAD_INSERT, &[&id, &"origin-bot"])
            .await
            .map_err(|e| e.to_string())?;
    }
    let (send, recv) = tokio::sync::oneshot::channel();
    let waiter_pool = p.clone();
    let waiter = tokio::spawn(async move {
        let b = waiter_pool.get().await.map_err(|e| e.to_string())?;
        b.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await
            .map_err(|e| e.to_string())?;
        let r = b
            .query_one(
                "SELECT pg_backend_pid(),current_setting('transaction_isolation')",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        require(
            r.get::<_, String>(1) == "read committed",
            "waiter lost original RC",
        )?;
        send.send(r.get::<_, i32>(0))
            .map_err(|_| "waiter PID receiver disappeared".to_owned())?;
        let result = b
            .execute(
                &format!("{THREAD_INSERT} ON CONFLICT(thread_id) DO NOTHING"),
                &[&id, &"origin-bot"],
            )
            .await;
        let success = result.is_ok();
        b.batch_execute(if success { "COMMIT" } else { "ROLLBACK" })
            .await
            .map_err(|e| e.to_string())?;
        Ok::<_, String>(result.map_err(|e| (e.code().map(|x| x.code().to_owned()), e.to_string())))
    });
    let pid = tokio::time::timeout(Duration::from_secs(10), recv)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let observer = p.get().await.map_err(|e| e.to_string())?;
    let observed = observed_lock(&observer, pid).await;
    let release = a
        .batch_execute(if observed.is_ok() && commit {
            "COMMIT"
        } else {
            "ROLLBACK"
        })
        .await
        .map_err(|e| e.to_string());
    let joined = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())??;
    observed?;
    release?;
    if existing && commit {
        require(
            matches!(joined,Err((Some(ref state),_)) if state=="55000"),
            "wait resumed stale base or refused for an unrelated cause",
        )?;
        require(
            head(&observer, id).await?.is_none(),
            "bad fresh base wait minted H",
        )?;
    } else {
        require(
            joined.map_err(|(_, message)| message)? == if existing || commit { 0 } else { 1 },
            "unique/base wait returned wrong actual insert result",
        )?;
        check_base_head(&observer, id).await?;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s10_concurrent_unique_and_base_waits_refresh_original_read_committed() {
    owned("history50wait", |p, _| async move {
        initialize(&p, 49).await?;
        {
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            raw_thread(&c, "owned-base-commit").await?;
            raw_thread(&c, "owned-base-rollback").await?;
            // Original 0050 storage wait semantics stay on explicit 50 (0051 writer guards
            // would lazily register H before this legacy anchor change and refuse it).
            native::apply_through(&mut c, 50)
                .await
                .map_err(|e| e.to_string())?;
        }
        wait_round(&p, "owned-unique-commit", false, true).await?;
        wait_round(&p, "owned-unique-rollback", false, false).await?;
        wait_round(&p, "owned-base-commit", true, true).await?;
        wait_round(&p, "owned-base-rollback", true, false).await?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s11_complete_schema_acl_function_and_ri_tamper_refuses_without_repair() {
    owned("history50tamper",|p,_|async move {
        initialize(&p,50).await?;let mut c=p.get().await.map_err(|e|e.to_string())?;
        check_admission(&c).await?;
        let mutations=[
            "ALTER TABLE openbot_internal.thread_history_heads RENAME COLUMN phase TO wrong_phase",
            "ALTER TABLE openbot_internal.thread_history_heads ADD COLUMN unexpected text",
            "ALTER TABLE openbot_internal.thread_history_heads ALTER COLUMN phase DROP NOT NULL",
            "ALTER TABLE openbot_internal.thread_history_heads ALTER COLUMN recorded_at SET DEFAULT now()",
            "ALTER TABLE openbot_internal.thread_history_clear_intents ALTER COLUMN recorded_at DROP DEFAULT",
            "ALTER TABLE openbot_internal.thread_history_heads ALTER COLUMN tenant_id TYPE text COLLATE \"default\"",
            "ALTER TABLE openbot_internal.thread_history_heads RENAME CONSTRAINT thread_history_heads_phase_check TO wrong_phase_check",
            "ALTER TABLE openbot_internal.thread_history_heads DROP CONSTRAINT thread_history_heads_phase_check",
            "ALTER TABLE openbot_internal.thread_history_heads ALTER CONSTRAINT thread_history_heads_closed_intent_fkey NOT DEFERRABLE",
            "ALTER TABLE openbot_internal.thread_history_clear_intents ALTER CONSTRAINT thread_history_clear_intents_head_base_fkey INITIALLY IMMEDIATE",
            "ALTER TABLE openbot_internal.thread_history_heads DROP CONSTRAINT thread_history_heads_closed_intent_fkey",
            "CREATE INDEX owned_unregistered_history_index ON openbot_internal.thread_history_heads(phase)",
            "ALTER INDEX openbot_internal.thread_history_heads_pkey SET (fillfactor=70)",
            "ALTER TABLE openbot_internal.thread_history_heads DISABLE TRIGGER thread_history_heads_guard_update_delete",
            "ALTER TABLE openbot_internal.thread_history_clear_intents DISABLE TRIGGER thread_history_clear_intents_require_closed_head",
            "ALTER TABLE public.threads DISABLE TRIGGER threads_history_bind_insert",
            "ALTER TABLE public.threads DISABLE TRIGGER threads_history_protect_identity_update",
            "CREATE TRIGGER owned_extra_history_trigger BEFORE INSERT ON public.threads FOR EACH ROW EXECUTE FUNCTION openbot_internal.bind_thread_history_head_on_insert()",
            "ALTER FUNCTION openbot_internal.guard_thread_history_head_mutation() SECURITY DEFINER",
            "ALTER FUNCTION openbot_internal.guard_thread_history_head_mutation() SET search_path=public",
            "ALTER FUNCTION openbot_internal.guard_thread_history_head_mutation() IMMUTABLE",
            "ALTER FUNCTION openbot_internal.guard_thread_history_head_mutation() STRICT",
            "ALTER FUNCTION openbot_internal.guard_thread_history_head_mutation() PARALLEL SAFE",
            "ALTER FUNCTION openbot_internal.guard_thread_history_head_mutation() COST 17",
            "CREATE OR REPLACE FUNCTION openbot_internal.guard_thread_history_head_mutation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW;END$$",
            "CREATE FUNCTION openbot_internal.guard_thread_history_head_mutation(text) RETURNS text LANGUAGE sql AS $$SELECT $1$$",
            "GRANT SELECT ON openbot_internal.thread_history_heads TO PUBLIC",
            "GRANT SELECT(deployment_id) ON openbot_internal.thread_history_clear_intents TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION openbot_internal.guard_thread_history_head_mutation() FROM PUBLIC",
            "CREATE TABLE public.owned_incoming_history_fk(deployment_id text,tenant_id text,thread_id text,FOREIGN KEY(deployment_id,tenant_id,thread_id) REFERENCES openbot_internal.thread_history_heads(deployment_id,tenant_id,thread_id))",
        ];
        for sql in mutations {
            c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
            let mutation=c.batch_execute(sql).await;
            if let Err(e)=mutation {c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;return Err(format!("tamper fixture never formed: {sql}: {e}"));}
            let refusal=check_admission(&c).await;
            // No nested transaction: these complete raw catalog values observe only the
            // frozen relevant graph, including facts normalization may refuse to return.
            let before=owned_raw_catalog(&c).await?;
            let second=check_admission(&c).await;
            let after=owned_raw_catalog(&c).await?;
            c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
            require(refusal.is_err()&&second.is_err(),"tampered schema accepted ordinary current observer")?;
            require(before==after,"refusal silently repaired physical tamper")?;
            check_admission(&c).await?;
        }
        let trigger:String=c.query_one("SELECT t.tgname FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint WHERE k.conrelid='openbot_internal.thread_history_heads'::regclass AND k.conname='thread_history_heads_closed_intent_fkey' AND t.tgisinternal AND t.tgtype=5",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(trigger.starts_with("RI_ConstraintTrigger_c_")&&trigger.chars().all(|x|x.is_ascii_alphanumeric()||x=='_'),"actual owned RI identity escaped")?;
        c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        c.batch_execute(&format!("ALTER TABLE openbot_internal.thread_history_heads DISABLE TRIGGER \"{trigger}\"")).await.map_err(|e|e.to_string())?;
        let rejected=check_admission(&c).await.is_err();
        c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        require(rejected,"disabled real RI trigger accepted")?;
        check_admission(&c).await?;
        // One committed fault proves the migration replay also refuses without repair.
        c.batch_execute("ALTER TABLE openbot_internal.thread_history_heads RENAME CONSTRAINT thread_history_heads_phase_check TO owned_committed_wrong_phase_check").await.map_err(|e|e.to_string())?;
        let refused=native::apply_through(&mut c, 50).await;
        let still_wrong:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='openbot_internal.thread_history_heads'::regclass AND conname='owned_committed_wrong_phase_check')",&[]).await.map_err(|e|e.to_string())?.get(0);
        c.batch_execute("ALTER TABLE openbot_internal.thread_history_heads RENAME CONSTRAINT owned_committed_wrong_phase_check TO thread_history_heads_phase_check").await.map_err(|e|e.to_string())?;
        require(refused.is_err()&&still_wrong,"native replay repaired/accepted committed exact fault")?;
        check_admission(&c).await?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn s12_explicit49_historical_canary_and_current50_admission_are_distinct() {
    owned("history50canary",|p,_|async move {
        initialize(&p,49).await?;
        require(desktop_vault_canary::verify_pre_upgrade_layout(&p).await.map_err(|e|e.to_string())?.native_version()==49,"actual49 historical canary missing")?;
        require(desktop_vault_canary::verify_current_layout(&p).await.is_err(),"actual49 accepted current50")?;
        let mut c=p.get().await.map_err(|e|e.to_string())?;
        require(native::validate_known_prefix(&c,49).await.map_err(|e|e.to_string())?.latest_version()==49,"explicit49 not exactknown prefix")?;
        let count:i64=c.query_one("SELECT count(*) FROM openbot_internal.schema_migrations",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(count==37,"historical49 not37 rows")?;
        require(admission_schema::verify(&c).await.is_err(),"current50 admission granted at49")?;
        native::apply(&mut c).await.map_err(|e|e.to_string())?;
        drop(c);desktop_vault_canary::verify_current_layout(&p).await.map_err(|e|e.to_string())?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        for sql in ["DELETE FROM openbot_internal.schema_migrations WHERE version=46","UPDATE openbot_internal.schema_migrations SET name='wrong50' WHERE version=50",
            "UPDATE openbot_internal.schema_migrations SET checksum=repeat('a',64) WHERE version=50","INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(53,'unknown53',repeat('b',64))",
            "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(12,'unexpected12',repeat('c',64))"] {
            c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;c.batch_execute(sql).await.map_err(|e|e.to_string())?;
            let result=admission_schema::verify(&c).await;
            c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
            require(matches!(result,Err(InfraError::NativeMigration(_))|Err(InfraError::RepositoryInvariant{..})),"current50 drift structural classification lost")?;
            admission_schema::verify(&c).await.map_err(|e|e.to_string())?;
        }
        admission_schema::verify(&c).await.map_err(|e|e.to_string())?;
        Ok(())
    }).await;
}
