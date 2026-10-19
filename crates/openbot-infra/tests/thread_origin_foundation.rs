//! Finite historical thread-origin foundation on owned synthetic PostgreSQL17.11.
//! The complete oracle is authored independently before any candidate observation.
#![cfg(feature = "server-runtime")]

mod harness;

use async_trait::async_trait;
use openbot_application::AgentContextSource;
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
    provider::context::PostgresAgentContextSource,
    vault::CredentialRecordVault,
};
use openbot_infra::{
    db::{
        self, InfraError, baseline, desktop_vault_canary, fresh, native, pool, schema_facts,
        thread_origin_schema as origin_schema,
    },
    intelligence_import::PostgresIntelligenceImportStore,
    repo::{ChannelRepo, thread::ThreadRepo},
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

fn require(value: bool, reason: &'static str) -> TestResult {
    if value {
        Ok(())
    } else {
        Err(reason.to_owned())
    }
}

// This fixture observes the original application's normalized request, forwards every
// real store operation, and never supplies schema expected facts or a production grant.
struct RecordingImport {
    store: PostgresIntelligenceImportStore,
    request: std::sync::Mutex<Option<IntelligenceThreadImportRequest>>,
}
#[async_trait]
impl IntelligenceImportStore for RecordingImport {
    async fn load_progress(
        &self,
        b: &str,
        d: &str,
        h: &str,
    ) -> Result<Option<IntelligenceImportProgress>, IntelligenceImportError> {
        self.store.load_progress(b, d, h).await
    }
    async fn import_thread(
        &self,
        r: IntelligenceThreadImportRequest,
    ) -> Result<IntelligenceThreadImportReceipt, IntelligenceImportError> {
        *self.request.lock().expect("owned recording mutex") = Some(r.clone());
        self.store.import_thread(r).await
    }
    async fn verify_thread(
        &self,
        id: &str,
    ) -> Result<IntelligenceThreadChecksum, IntelligenceImportError> {
        self.store.verify_thread(id).await
    }
    async fn complete_bundle(
        &self,
        b: &str,
        d: &str,
        h: &str,
        p: &IntelligenceImportProgress,
    ) -> Result<(), IntelligenceImportError> {
        self.store.complete_bundle(b, d, h, p).await
    }
    async fn mark_failed(&self, b: &str, d: &str, h: &str) -> Result<(), IntelligenceImportError> {
        self.store.mark_failed(b, d, h).await
    }
    async fn validate_tool_run_fk(
        &self,
    ) -> Result<IntelligenceToolRunFkReport, IntelligenceImportError> {
        self.store.validate_tool_run_fk().await
    }
}
fn import_fixture(
    index: u64,
) -> TestResult<(
    VerifiedIntelligenceBundle,
    IntelligenceImportMapping,
    IntelligenceThreadExport,
)> {
    let mut empty = IntelligenceThreadChecksum {
        projection_hash: "0".repeat(64),
        message_count: 0,
        message_hash: "0".repeat(64),
        event_count: 0,
        event_hash: "0".repeat(64),
        terminal_state_hash: "0".repeat(64),
        memory_count: 0,
        memory_hash: "0".repeat(64),
        sample_render_hash: "0".repeat(64),
    };
    let id = request("origin-a", index)
        .command
        .thread_id
        .as_str()
        .to_owned();
    let mut source = IntelligenceThreadExport {
        thread_id: id,
        created_by: "legacy-creator".into(),
        members: vec!["legacy-creator".into()],
        title: Some("Owned maintenance provenance".into()),
        anchor: IntelligenceThreadAnchor::DirectBot {
            bot_id: "legacy-bot".into(),
        },
        status: IntelligenceThreadStatus::Active,
        messages: vec![],
        runs: vec![],
        memories: vec![],
        checksum: empty.clone(),
        created_at: datetime!(2026-09-01 00:00 UTC),
        updated_at: datetime!(2026-09-01 00:00 UTC),
        deleted_at: None,
    };
    source.checksum = compute_intelligence_thread_checksum(&source).map_err(|e| e.to_string())?;
    let mut normalized = source.clone();
    normalized.created_by = "origin-a".into();
    normalized.members = vec!["origin-a".into()];
    normalized.anchor = IntelligenceThreadAnchor::DirectBot {
        bot_id: "origin-bot".into(),
    };
    empty = compute_intelligence_thread_checksum(&normalized).map_err(|e| e.to_string())?;
    normalized.checksum = empty;
    let payload = IntelligenceBundlePayload {
        schema_version: INTELLIGENCE_BUNDLE_SCHEMA_VERSION,
        bundle_id: format!("owned-origin-bundle-{index}"),
        source_deployment_id: "owned-legacy-source-deployment".into(),
        exported_at: datetime!(2026-09-01 01:00 UTC),
        provenance: IntelligenceBundleProvenance {
            upstream_commit: INTELLIGENCE_SOURCE_COMMIT.into(),
            exporter_version: "owned-origin-exporter-v1".into(),
            project_id: "owned-origin-project".into(),
        },
        threads: vec![source],
    };
    let verified = VerifiedIntelligenceBundle::new(
        payload,
        "c".repeat(64),
        "owned-origin-maintenance-key".into(),
    )
    .map_err(|e| e.to_string())?;
    let mapping = IntelligenceImportMapping {
        target_deployment_id: DEP.into(),
        target_tenant_id: TENANT.into(),
        users: [("legacy-creator".into(), "origin-a".into())]
            .into_iter()
            .collect(),
        bots: [("legacy-bot".into(), "origin-bot".into())]
            .into_iter()
            .collect(),
        channels: Default::default(),
        claimed_thread_ids: Default::default(),
    };
    Ok((verified, mapping, normalized))
}
async fn insert_legacy(p: &pool::DatabasePool, thread: &IntelligenceThreadExport) -> TestResult {
    let (kind, anchor) = match &thread.anchor {
        IntelligenceThreadAnchor::DirectBot { bot_id } => ("direct_bot", bot_id.as_str()),
        IntelligenceThreadAnchor::Channel { channel_id } => ("channel", channel_id.as_str()),
    };
    let row = db::tables::threads::Row {
        thread_id: thread.thread_id.clone(),
        tenant_id: TENANT.into(),
        deployment_id: DEP.into(),
        created_by: thread.created_by.clone(),
        anchor_kind: kind.into(),
        anchor_id: anchor.into(),
        title: thread.title.clone(),
        status: "active".into(),
        next_message_seq: 0,
        next_event_seq: 0,
        created_at: thread.created_at,
        updated_at: thread.updated_at,
        deleted_at: None,
    };
    ThreadRepo::new(p.clone())
        .insert(&row)
        .await
        .map_err(|e| e.to_string())?;
    let c = p.get().await.map_err(|e| e.to_string())?;
    for member in &thread.members {
        c.execute(
            "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,$2)",
            &[&thread.thread_id, member],
        )
        .await
        .map_err(|e| e.to_string())?;
    }
    require(
        origin(&c, &thread.thread_id).await?.is_none(),
        "generic ThreadRepo insert fabricated creator authority",
    )
}
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
async fn numeric_checksum_vectors(c: &Client, reference: &str) -> TestResult {
    for field in ["messageCount", "eventCount", "memoryCount"] {
        for (number, accepted) in [
            ("0.0", true),
            ("1.0", true),
            ("1.5", false),
            ("-1", false),
            ("18446744073709551616", false),
        ] {
            c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
            let sql = format!(
                "INSERT INTO openbot_internal.thread_origins({ORIGIN_COLUMNS}) SELECT thread_id||'-owned-numeric',deployment_id,tenant_id,creator_actor_id,anchor_kind,anchor_id,thread_created_at,origin_kind,origin_schema,clock_timestamp(),import_bundle_id,import_payload_sha256,import_signing_key_id,jsonb_set(import_thread_checksum,ARRAY[$2],$3::text::jsonb) FROM openbot_internal.thread_origins WHERE thread_id=$1"
            );
            let result = c.execute(&sql, &[&reference, &field, &number]).await;
            c.batch_execute("ROLLBACK")
                .await
                .map_err(|e| e.to_string())?;
            if accepted {
                require(
                    result.map_err(|e| e.to_string())? == 1,
                    "valid JSONB u64 integer numeric vector not accepted",
                )?;
            } else {
                require(
                    matches!(result,Err(ref e)if e.code()==Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)),
                    "non-u64 numeric vector did not reach real CHECK refusal",
                )?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o07_new_maintenance_import_retains_mapped_provenance() {
    owned("origin49maintenance",|p,_|async move{
        provision(&p).await?;
        let (_,verified,_,normalized,_)=record_import(&p,701).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        let value=origin(&c,&normalized.thread_id).await?.ok_or("actual RETURNING maintenance Thread omitted origin")?;
        require(value["creator_actor_id"]=="origin-a"&&value["origin_kind"]=="maintenance_import"&&value["deployment_id"]==DEP&&value["tenant_id"]==TENANT,"maintenance target-normalized creator/J differs")?;
        require(value["import_bundle_id"]==verified.payload().bundle_id&&value["import_payload_sha256"]==verified.payload_sha256()&&value["import_signing_key_id"]==verified.signing_key_id(),"maintenance bundle provenance differs")?;
        require(value["import_thread_checksum"]==serde_json::to_value(&normalized.checksum).map_err(|e|e.to_string())?&&value["import_thread_checksum"].as_object().map(|m|m.len())==Some(9),"complete independent normalized source checksum differs")?;
        let binding:bool=c.query_one("SELECT o.thread_created_at=t.created_at AND o.creator_actor_id=t.created_by AND o.anchor_kind=t.anchor_kind AND o.anchor_id=t.anchor_id AND isfinite(o.recorded_at) FROM openbot_internal.thread_origins o JOIN public.threads t USING(thread_id) WHERE o.thread_id=$1",&[&normalized.thread_id]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(binding,"maintenance original base/time binding differs")?;
        require(value.as_object().map(|m|m.len())==Some(15),"maintenance origin unexpectedly stores source body")?;
        numeric_checksum_vectors(&c,&normalized.thread_id).await
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o08_import_conflict_never_remints_origin() {
    owned("origin49importconflict",|p,_|async move{
        provision(&p).await?;
        let (store,_,_,normalized,captured)=record_import(&p,801).await?;
        let original={let c=p.get().await.map_err(|e|e.to_string())?;origin(&c,&normalized.thread_id).await?.ok_or("known original missing")?};
        let mut conflict=captured.clone();conflict.bundle_id.push_str("-actual-conflict");
        require(store.store.load_progress(&conflict.bundle_id,DEP,&conflict.payload_sha256).await.map_err(|e|e.to_string())?.is_none(),"no-progress ON CONFLICT premise absent")?;
        require(!store.store.import_thread(conflict.clone()).await.map_err(|e|e.to_string())?.replayed,"ON CONFLICT request incorrectly took equal-progress shortcut")?;
        {let c=p.get().await.map_err(|e|e.to_string())?;require(origin(&c,&normalized.thread_id).await?==Some(original.clone()),"ON CONFLICT rewrote complete known origin/xmin")?;}
        let (legacy_verified,legacy_mapping,legacy)=import_fixture(802)?;insert_legacy(&p,&legacy).await?;
        require(store.store.load_progress(&legacy_verified.payload().bundle_id,DEP,legacy_verified.payload_sha256()).await.map_err(|e|e.to_string())?.is_none(),"legacy Application conflict unexpectedly had progress")?;
        require(import_intelligence_bundle(&store,legacy_verified,legacy_mapping).await.map_err(|e|e.to_string())?.status==IntelligenceImportReportStatus::Completed,"real Application legacy conflict did not complete")?;
        let mut legacy_request=store.request.lock().map_err(|e|e.to_string())?.clone().ok_or("Application legacy import request absent")?;
        legacy_request.bundle_id.push_str("-legacy-no-progress");
        require(!store.store.import_thread(legacy_request.clone()).await.map_err(|e|e.to_string())?.replayed,"generic conflict did not reach actual INSERT None")?;
        {let c=p.get().await.map_err(|e|e.to_string())?;require(origin(&c,&legacy.thread_id).await?.is_none(),"matching legacy conflict was adopted")?;}
        for mode in 0..3{
            let before=counts(&p).await?;
            let mut bad=captured.clone();bad.bundle_id.push_str(&format!("-drift-{mode}"));
            match mode{0=>{bad.thread.created_by="origin-b".into();},1=>{bad.thread.anchor=IntelligenceThreadAnchor::DirectBot{bot_id:"origin-other-bot".into()};let c=p.get().await.map_err(|e|e.to_string())?;c.execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('origin-other-bot','Owned other bot','built_in','{}')",&[]).await.map_err(|e|e.to_string())?;},_=>{bad.thread.created_at+=time::Duration::seconds(1);bad.thread.updated_at=bad.thread.created_at;}}
            bad.checksum=compute_intelligence_thread_checksum(&bad.thread).map_err(|e|e.to_string())?;bad.thread.checksum=bad.checksum.clone();
            require(store.store.import_thread(bad.clone()).await.is_err(),"actual ON CONFLICT base creator/anchor/time drift accepted")?;
            require(counts(&p).await?==before,"import drift left partial business/origin")?;
            require(store.store.load_progress(&bad.bundle_id,DEP,&bad.payload_sha256).await.map_err(|e|e.to_string())?.is_none(),"failed drift wrote cursor")?;
            let c=p.get().await.map_err(|e|e.to_string())?;require(origin(&c,&normalized.thread_id).await?==Some(original.clone()),"refused drift changed original origin")?;
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o09_equal_progress_and_completed_verify_without_mint() {
    owned("origin49replay",|p,_|async move{
        provision(&p).await?;
        let (store,verified,mapping,normalized,captured)=record_import(&p,901).await?;
        let original={let c=p.get().await.map_err(|e|e.to_string())?;origin(&c,&normalized.thread_id).await?.ok_or("actual Known missing")?};
        let mut running=captured.clone();running.bundle_id.push_str("-equal-running");
        require(!store.store.import_thread(running.clone()).await.map_err(|e|e.to_string())?.replayed,"running fixture did not truly reach import branch")?;
        require(store.store.import_thread(running.clone()).await.map_err(|e|e.to_string())?.replayed,"equal-progress branch not actually reached")?;
        let report=import_intelligence_bundle(&store,verified.clone(),mapping.clone()).await.map_err(|e|e.to_string())?;
        require(report.status==IntelligenceImportReportStatus::Completed,"actual completed replay failed")?;
        require(store.store.verify_thread(&normalized.thread_id).await.map_err(|e|e.to_string())?==normalized.checksum,"completed store checksum differs")?;
        {let c=p.get().await.map_err(|e|e.to_string())?;require(origin(&c,&normalized.thread_id).await?==Some(original),"equal/completed replay rewrote historical origin/xmin")?;numeric_checksum_vectors(&c,&normalized.thread_id).await?;}
        let (legacy_verified,legacy_mapping,legacy)=import_fixture(902)?;insert_legacy(&p,&legacy).await?;
        let first=import_intelligence_bundle(&store,legacy_verified.clone(),legacy_mapping.clone()).await.map_err(|e|e.to_string())?;
        require(first.status==IntelligenceImportReportStatus::Completed,"legacy completed fixture did not complete")?;
        let mut legacy_running=store.request.lock().map_err(|e|e.to_string())?.clone().ok_or("Application legacy import request absent")?;
        let legacy_captured=legacy_running.clone();legacy_running.bundle_id.push_str("-legacy-equal");
        require(!store.store.import_thread(legacy_running.clone()).await.map_err(|e|e.to_string())?.replayed,"legacy running fixture did not reach conflict")?;
        require(store.store.import_thread(legacy_running).await.map_err(|e|e.to_string())?.replayed,"legacy equal-progress not reached")?;
        let replay=import_intelligence_bundle(&store,legacy_verified,legacy_mapping).await.map_err(|e|e.to_string())?;
        require(replay.status==IntelligenceImportReportStatus::Completed,"legacy completed replay failed")?;
        // Structural fixture for the actual Known reader, separate from O07's real mint proof.
        // JSONB 0.0 equals integer zero; immutable guards stay enabled throughout.
        let (decimal_verified,_,decimal)=import_fixture(903)?;insert_legacy(&p,&decimal).await?;
        {let c=p.get().await.map_err(|e|e.to_string())?;let checksum=serde_json::to_value(&decimal.checksum).map_err(|e|e.to_string())?;
            let inserted=c.execute("INSERT INTO openbot_internal.thread_origins(thread_id,deployment_id,tenant_id,creator_actor_id,anchor_kind,anchor_id,thread_created_at,origin_kind,origin_schema,recorded_at,import_bundle_id,import_payload_sha256,import_signing_key_id,import_thread_checksum) SELECT thread_id,deployment_id,tenant_id,created_by,anchor_kind,anchor_id,created_at,'maintenance_import',1,clock_timestamp(),$2,$3,$4,jsonb_set(jsonb_set(jsonb_set($5::jsonb,'{messageCount}','0.0'::jsonb),'{eventCount}','0.0'::jsonb),'{memoryCount}','0.0'::jsonb) FROM public.threads WHERE thread_id=$1",&[&decimal.thread_id,&decimal_verified.payload().bundle_id,&decimal_verified.payload_sha256(),&decimal_verified.signing_key_id(),&checksum]).await.map_err(|e|e.to_string())?;
            require(inserted==1,"actual decimal Known fixture not inserted")?;
            origin_schema::verify(&c).await.map_err(|e|e.to_string())?;
        }
        require(store.store.verify_thread(&decimal.thread_id).await.map_err(|e|e.to_string())?==decimal.checksum,"Known reader rejected valid0.0 u64 numeric facts")?;
        {let c=p.get().await.map_err(|e|e.to_string())?;
            require(origin(&c,&legacy.thread_id).await?.is_none(),"LegacyUnknown equal/completed paths adopted creator")?;
            // Explicit negative fixture: base mismatch while both immutable guards remain normal.
            c.execute("INSERT INTO openbot_internal.thread_origins(thread_id,deployment_id,tenant_id,creator_actor_id,anchor_kind,anchor_id,thread_created_at,origin_kind,origin_schema,recorded_at) SELECT thread_id,deployment_id,tenant_id,'origin-b',anchor_kind,anchor_id,created_at,'native_begin_v1',1,clock_timestamp() FROM public.threads WHERE thread_id=$1",&[&legacy.thread_id]).await.map_err(|e|e.to_string())?;
            origin_schema::verify(&c).await.map_err(|e|e.to_string())?;
        }
        let before=counts(&p).await?;
        require(store.store.verify_thread(&legacy.thread_id).await.is_err(),"known malformed binding was downgraded to Unknown on verify")?;
        require(store.store.import_thread({let mut r=legacy_captured;r.bundle_id.push_str("-bad-known");r}).await.is_err(),"known malformed binding accepted actual import")?;
        require(counts(&p).await?==before,"Known binding refusal changed business/origin")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o11_legacy_unknown_and_source_hard_delete_keep_only_ids() {
    owned("origin49sourceerase",|p,config|async move{
        provision(&p).await?;
        let (_,_,legacy)=import_fixture(1101)?;insert_legacy(&p,&legacy).await?;
        let dir=directory(&p,&config)?;
        let mut later=request("origin-a",1102);later.command.thread_id=openbot_contracts::ids::ThreadId::new(&legacy.thread_id);
        dir.begin_thread_run(later.clone()).await.map_err(|e|e.to_string())?;
        settle(&p,later.command.run_id.as_str()).await?;
        {let c=p.get().await.map_err(|e|e.to_string())?;require(origin(&c,&legacy.thread_id).await?.is_none(),"later ordinary activity adopted legacy origin")?;}
        let original_req=request("origin-a",1103);
        dir.begin_thread_run(original_req.clone()).await.map_err(|e|e.to_string())?;
        settle(&p,original_req.command.run_id.as_str()).await?;
        let original={let c=p.get().await.map_err(|e|e.to_string())?;verify_native_origin(&c,original_req.command.thread_id.as_str(),"origin-a","native_begin_v1").await?};
        {let c=p.get().await.map_err(|e|e.to_string())?;
            require(c.execute("DELETE FROM public.threads WHERE thread_id=$1",&[&original_req.command.thread_id.as_str()]).await.map_err(|e|e.to_string())?==1,"source hard-delete did not delete true Thread")?;
            c.execute("DELETE FROM public.outbox WHERE aggregate_id=$1",&[&original_req.command.thread_id.as_str()]).await.map_err(|e|e.to_string())?;
            // Keep unrelated owned source fixtures; remove this user's referencing profile before its row.
            c.execute("DELETE FROM public.agent_profiles WHERE owner_user_id='origin-a'",&[]).await.map_err(|e|e.to_string())?;
            require(c.execute("DELETE FROM public.users WHERE id='origin-a'",&[]).await.map_err(|e|e.to_string())?==1,"source user deletion failed")?;
            require(origin(&c,original_req.command.thread_id.as_str()).await?==Some(original.clone()),"source hard-delete changed retained identifiers/times/kind")?;
            let r=c.query_one("SELECT NOT EXISTS(SELECT 1 FROM public.threads WHERE thread_id=$1),NOT EXISTS(SELECT 1 FROM public.messages WHERE thread_id=$1),NOT EXISTS(SELECT 1 FROM public.runs WHERE thread_id=$1),NOT EXISTS(SELECT 1 FROM public.users WHERE id='origin-a')",&[&original_req.command.thread_id.as_str()]).await.map_err(|e|e.to_string())?;
            require((0..4).all(|i|r.get::<_,bool>(i)),"actual source Thread/body/User remained")?;
            require(original.as_object().map(|m|m.len())==Some(15),"retained origin contains source body fields")?;
            // Restore a distinct current eligible principal/profile for a reachable old-ID retry.
            c.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('origin-bot','origin-b','Owned replacement bot','','owned-replacement','public')",&[]).await.map_err(|e|e.to_string())?;
        }
        let before=counts(&p).await?;
        let mut reuse=request("origin-b",1104);reuse.command.thread_id=original_req.command.thread_id.clone();
        require(dir.begin_thread_run(reuse).await.is_err(),"source-erased old Thread ID was reminted/reused")?;
        require(counts(&p).await?==before,"old-ID refusal left partial new Thread/origin")?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        require(origin(&c,original_req.command.thread_id.as_str()).await?==Some(original),"old-ID retry rewrote retained origin")
    }).await;
}

async fn actual_guard_refuses(c: &Client, sql: &str) -> TestResult {
    c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
    let refusal = c.batch_execute(sql).await;
    c.batch_execute("ROLLBACK")
        .await
        .map_err(|e| e.to_string())?;
    require(
        matches!(refusal,Err(ref error) if error.code()==Some(&tokio_postgres::error::SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE)
        &&error.as_db_error().map(|db|db.message())==Some("thread_origin_mutation_refused")),
        "actual guard did not return fixed55000/static reason",
    )
}
async fn schema_refuses_actual_mutation(c: &Client, sql: &str) -> TestResult {
    c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
    let mutation = c.batch_execute(sql).await;
    let observation = if mutation.is_ok() {
        Some(origin_schema::verify(c).await)
    } else {
        None
    };
    c.batch_execute("ROLLBACK")
        .await
        .map_err(|e| e.to_string())?;
    mutation.map_err(|e| format!("schema mutation did not actually apply: {e}"))?;
    require(
        matches!(observation,Some(Err(ref e))if structurally_invalid(e)),
        "actual schema drift was not RepositoryInvariant schema refusal",
    )?;
    origin_schema::verify(c).await.map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o12_real_immutable_guards_and_full_schema_tamper_refusal() {
    owned("origin49immutability",|p,config|async move{
        provision(&p).await?;
        let dir=directory(&p,&config)?;let req=request("origin-a",1201);
        dir.begin_thread_run(req.clone()).await.map_err(|e|e.to_string())?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        let original=origin(&c,req.command.thread_id.as_str()).await?.ok_or("actual guarded origin absent")?;
        for sql in ["UPDATE openbot_internal.thread_origins SET creator_actor_id='origin-b'",
            "UPDATE openbot_internal.thread_origins SET origin_schema=origin_schema",
            "DELETE FROM openbot_internal.thread_origins","TRUNCATE openbot_internal.thread_origins"]{
            actual_guard_refuses(&c,sql).await?;
            require(origin(&c,req.command.thread_id.as_str()).await?==Some(original.clone()),"refused guard changed actual complete origin/xmin")?;
        }
        let mutations=[
            "ALTER TABLE openbot_internal.thread_origins DISABLE TRIGGER thread_origins_no_update_delete",
            "DROP TRIGGER thread_origins_no_update_delete ON openbot_internal.thread_origins",
            "DROP TRIGGER thread_origins_no_update_delete ON openbot_internal.thread_origins;CREATE TRIGGER thread_origins_no_update_delete BEFORE UPDATE OR DELETE ON openbot_internal.thread_origins FOR EACH ROW WHEN (false) EXECUTE FUNCTION openbot_internal.prevent_thread_origin_mutation()",
            "CREATE FUNCTION openbot_internal.owned_origin_rebind() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW;END$$;DROP TRIGGER thread_origins_no_update_delete ON openbot_internal.thread_origins;CREATE TRIGGER thread_origins_no_update_delete BEFORE UPDATE OR DELETE ON openbot_internal.thread_origins FOR EACH ROW EXECUTE FUNCTION openbot_internal.owned_origin_rebind()",
            "DROP TRIGGER thread_origins_no_truncate ON openbot_internal.thread_origins",
            "CREATE INDEX owned_origin_extra_index ON openbot_internal.thread_origins(creator_actor_id)",
            "ALTER TABLE openbot_internal.thread_origins ADD COLUMN owned_extra text",
            "ALTER TABLE openbot_internal.thread_origins ADD CONSTRAINT owned_extra_check CHECK(origin_schema>0)",
            "CREATE TABLE openbot_internal.owned_origin_reverse_fk(thread_id text REFERENCES openbot_internal.thread_origins(thread_id))",
            "CREATE POLICY owned_origin_policy ON openbot_internal.thread_origins USING(true)",
            "CREATE RULE owned_origin_rule AS ON INSERT TO openbot_internal.thread_origins DO ALSO SELECT 1",
            "CREATE TABLE openbot_internal.owned_origin_parent() ;ALTER TABLE openbot_internal.thread_origins INHERIT openbot_internal.owned_origin_parent",
            "ALTER TABLE openbot_internal.thread_origins OWNER TO pg_database_owner",
            "GRANT SELECT ON openbot_internal.thread_origins TO PUBLIC",
            "GRANT SELECT(thread_id) ON openbot_internal.thread_origins TO PUBLIC",
            "GRANT SELECT ON openbot_internal.thread_origins TO CURRENT_USER WITH GRANT OPTION",
            "ALTER FUNCTION openbot_internal.prevent_thread_origin_mutation() SECURITY DEFINER",
            "ALTER FUNCTION openbot_internal.prevent_thread_origin_mutation() SET search_path=pg_catalog",
            "CREATE OR REPLACE FUNCTION openbot_internal.prevent_thread_origin_mutation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='different_owned_reason';END$$",
            "REVOKE EXECUTE ON FUNCTION openbot_internal.prevent_thread_origin_mutation() FROM PUBLIC",
            "ALTER FUNCTION openbot_internal.prevent_thread_origin_mutation() OWNER TO pg_database_owner",
            "CREATE FUNCTION openbot_internal.prevent_thread_origin_mutation(integer) RETURNS integer LANGUAGE sql AS $$SELECT $1$$",
            "CREATE TABLE openbot_internal.owned_origin_reverse_trigger(id int);CREATE TRIGGER owned_origin_external BEFORE UPDATE ON openbot_internal.owned_origin_reverse_trigger FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_thread_origin_mutation()",
        ];
        for sql in mutations{schema_refuses_actual_mutation(&c,sql).await?;}
        check_oracle(&c).await?;
        let observer_role=format!("openbot_it_origin_query_{}",Uuid::new_v4().simple());
        c.batch_execute(&format!("CREATE ROLE \"{observer_role}\" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;SET ROLE \"{observer_role}\";")).await.map_err(|e|e.to_string())?;
        let query_refusal=origin_schema::verify(&c).await;
        let reset=c.batch_execute("RESET ROLE").await.map_err(|e|e.to_string());
        let cleanup=if reset.is_ok(){c.batch_execute(&format!("DROP ROLE \"{observer_role}\";")).await.map_err(|e|e.to_string())}else{Err("owned Query role RESET failed".into())};
        reset.and(cleanup)?;
        require(matches!(query_refusal,Err(InfraError::Query{..})),"actual permission query failure lost Query classification")?;
        origin_schema::verify(&c).await.map_err(|e|e.to_string())?;
        Ok(())
    }).await;
    owned("origin49emptytruncate", |p, _| async move {
        initialize(&p, 49).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        let count: i64 = c
            .query_one("SELECT count(*) FROM openbot_internal.thread_origins", &[])
            .await
            .map_err(|e| e.to_string())?
            .try_get(0)
            .map_err(|e| e.to_string())?;
        require(count == 0, "empty TRUNCATE prerequisite not actual")?;
        actual_guard_refuses(&c, "TRUNCATE openbot_internal.thread_origins").await
    })
    .await;
}
async fn close_pool(p: pool::DatabasePool) -> TestResult {
    let observations = p.connection_observations();
    p.close();
    let deadline = Instant::now() + Duration::from_secs(10);
    for observation in observations {
        require(
            observation
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|e| e.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "owned connection destruction unobserved",
        )?;
    }
    Ok(())
}
async fn owned<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(pool::DatabasePool, pool::DatabaseConfig) -> Fut,
    Fut: Future<Output = TestResult>,
{
    let admin = harness::admin_config(tag);
    require(
        matches!(admin.host.as_str(), "127.0.0.1" | "::1"),
        "literal loopback required",
    )
    .expect("owned fixture prerequisite");
    harness::with_temp_database(&admin,tag,|config|async move{
        require(config.dbname.starts_with("openbot_it_"),"owned database name missing")?;
        let config=config.with_max_pool_size(4);
        let p=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let prerequisite=async{
            let c=p.get().await.map_err(|e|e.to_string())?;
            let r=c.query_one("SELECT current_setting('server_version_num')::int,current_setting('server_encoding'),current_setting('block_size')::int",&[]).await.map_err(|e|e.to_string())?;
            require(r.try_get::<_,i32>(0).map_err(|e|e.to_string())?==170011
                &&r.try_get::<_,String>(1).map_err(|e|e.to_string())?=="UTF8"
                &&r.try_get::<_,i32>(2).map_err(|e|e.to_string())?==8192,"frozen PG17.11 prerequisites differ")
        }.await;
        let result=match prerequisite{Ok(())=>body(p.clone(),config).await,Err(e)=>Err(e)};
        result.and(close_pool(p).await)
    }).await;
}
async fn initialize(p: &pool::DatabasePool, version: i32) -> TestResult {
    let mut c = p.get().await.map_err(|e| e.to_string())?;
    if version == 51 {
        require(
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?
                == fresh::FreshApplyOutcome::Applied(native::ApplyOutcome::Applied),
            "fresh51 did not apply",
        )?;
    } else {
        require(matches!(version, 47..=50), "unregistered historical prefix")?;
        baseline::apply(&c).await.map_err(|e| e.to_string())?;
        require(
            native::apply_through(&mut c, version)
                .await
                .map_err(|e| e.to_string())?
                == native::ApplyOutcome::Applied,
            "historical prefix did not apply",
        )?;
    }
    Ok(())
}
async fn provision(p: &pool::DatabasePool) -> TestResult {
    initialize(p, 51).await?;
    let c = p.get().await.map_err(|e| e.to_string())?;
    c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES
        ('origin-a','origin-a@example.test',7),('origin-b','origin-b@example.test',7),
        ('origin-admin','origin-admin@example.test',7),('origin-roleless','origin-roleless@example.test',7),
        ('origin-denied','origin-denied@example.test',7);
        INSERT INTO public.user_roles(user_id,role) VALUES('origin-a','user'),('origin-b','user'),('origin-admin','admin'),('origin-denied','user');
        INSERT INTO public.revoked_access(email,revoked_by) VALUES('origin-denied@example.test','origin-admin');
        INSERT INTO public.agents(id,name,type,configuration) VALUES('origin-bot','Owned origin bot','built_in','{\"systemPrompt\":\"Owned origin prompt\",\"providerSource\":\"managed\"}');
        INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('origin-bot','origin-a','Owned origin bot','','owned-origin','public');")
        .await.map_err(|e|e.to_string())?;
    Ok(())
}
fn request(actor: &str, index: u64) -> BeginThreadRunRequest {
    let deployment = DeploymentId::new(DEP);
    let mut entropy = [0u8; 16];
    entropy[8..].copy_from_slice(&index.to_be_bytes());
    BeginThreadRunRequest {
        deployment: deployment.clone(),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(actor),
        auth_generation: AuthGeneration::new(7),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            thread_id: ThreadIdentity::new(&deployment).mint_from_entropy(entropy),
            run_id: RunId::new(format!("owned-origin-run-{index}")),
            bot_id: BotId::new("origin-bot"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "Owned finite origin words".to_owned(),
            selected_skill_slugs: vec![],
            model_selection: None,
        },
    }
}
fn directory(
    p: &pool::DatabasePool,
    config: &pool::DatabaseConfig,
) -> TestResult<PostgresThreadDirectory> {
    PostgresThreadDirectory::with_runtime(
        p.clone(),
        config.clone(),
        PROCESS.to_owned(),
        DEFAULT_THREAD_LEASE_DURATION,
    )
    .map_err(|e| e.to_string())
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
async fn current_owned_auth(p: &pool::DatabasePool, actor: &str) -> TestResult<AuthContext> {
    let c = p.get().await.map_err(|e| e.to_string())?;
    let generation: i64 = c
        .query_one(
            "SELECT coalesce(auth_generation,0) FROM public.users WHERE id=$1",
            &[&actor],
        )
        .await
        .map_err(|e| e.to_string())?
        .try_get(0)
        .map_err(|e| e.to_string())?;
    let mut roles = vec![];
    for row in c
        .query(
            "SELECT role::text FROM public.user_roles WHERE user_id=$1 ORDER BY role",
            &[&actor],
        )
        .await
        .map_err(|e| e.to_string())?
    {
        let role: String = row.try_get(0).map_err(|e| e.to_string())?;
        roles.push(match role.as_str() {
            "user" => Role::User,
            "admin" => Role::Admin,
            _ => return Err("owned role outside enum".into()),
        });
    }
    Ok(AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        ActorId::new(actor),
        AuthGeneration::new(u64::try_from(generation).map_err(|e| e.to_string())?),
        false,
    )
    .with_roles(roles)
    .build())
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
fn structurally_invalid(e: &InfraError) -> bool {
    matches!(
        e,
        InfraError::RepositoryInvariant {
            code: "thread_origin_schema_invalid"
        }
    )
}
fn oracle_schema(observation: &Value) -> TestResult<Value> {
    let mut schema = observation["schema"].clone();
    let indexes = schema["indexes"].as_array_mut().ok_or("indexes absent")?;
    require(indexes.len() == 1, "extra index cannot use HOT marker")?;
    let index = &mut indexes[0];
    require(
        index["identity"]["schema"] == "openbot_internal"
            && index["identity"]["name"] == "thread_origins_pkey"
            && index["checkXmin"].is_boolean(),
        "only original PK may use HOT marker",
    )?;
    index["checkXmin"] = json!({"predicate":"pg17_hot_runtime_boolean_v1"});
    Ok(schema)
}
fn independent_oracle() -> TestResult<Value> {
    serde_json::from_str(include_str!(
        "../../../fixtures/db/thread-origins-0049.json"
    ))
    .map_err(|e| e.to_string())
}
async fn check_oracle(c: &Client) -> TestResult<Value> {
    let observed = origin_schema::capture(c).await.map_err(|e| e.to_string())?;
    let expected = independent_oracle()?;
    println!(
        "THREAD_ORIGINS49_CAPTURE {}",
        serde_json::to_string(&observed).map_err(|e| e.to_string())?
    );
    require(
        observed["format"] == "thread-origins-observation-v1"
            && observed.as_object().map(|o| o.len()) == Some(4),
        "observation shape differs",
    )?;
    require(
        oracle_schema(&observed)? == expected["schema"],
        "complete independent schema oracle differs",
    )?;
    require(
        expected["allowedTableAclStates"]
            .as_array()
            .ok_or("oracle table ACL states absent")?
            .contains(&observed["tableAclState"]),
        "raw table ACL state not registered",
    )?;
    require(
        observed["rawFacts"]["format"] == "thread-origins-raw-v1"
            && observed["rawFacts"]["ownerAnchorRaw"]["ownerOidRaw"].is_string(),
        "actual full raw facts/original owner OID absent",
    )?;
    let ledger = native::validate_known_prefix(c, 49)
        .await
        .map_err(|e| e.to_string())?;
    if ledger.latest_version() != 49 {
        origin_schema::verify(c).await.map_err(|e| e.to_string())?;
    }
    Ok(observed)
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o01_fresh49_origin_schema_and_portable_acl() {
    owned("origin49oracle", |p, _| async move {
        initialize(&p, 49).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        let first = check_oracle(&c).await?;
        require(
            first["tableAclState"]["aclIsNull"] == true,
            "fresh origin table ACL not rawNULL",
        )?;
        let functions = first["schema"]["functions"]
            .as_array()
            .ok_or("functions absent")?;
        require(
            functions.len() == 1
                && functions[0]["ownerRef"] == "original_threads_owner"
                && functions[0]["aclIsNull"] == true
                && functions[0]["rawAcl"].is_null(),
            "normal guard owner/default ACL lost",
        )?;
        let acl = first["schema"]["relations"][0]["acl"]
            .as_array()
            .ok_or("portable table ACL missing")?;
        require(
            acl.len() == 8 && acl.iter().any(|v| v["privilege"] == "MAINTAIN"),
            "PG17 owner8 MAINTAIN missing",
        )?;
        c.batch_execute("GRANT ALL PRIVILEGES ON openbot_internal.thread_origins TO CURRENT_USER")
            .await
            .map_err(|e| e.to_string())?;
        let second = check_oracle(&c).await?;
        require(
            second["tableAclState"]["aclIsNull"] == false,
            "explicit owner8 not materialized",
        )?;
        require(
            oracle_schema(&first)? == oracle_schema(&second)?,
            "raw equivalent ACL changed portable schema",
        )
    })
    .await;
    owned("origin49portableowner",|p,_|async move{
        let mut c=p.get().await.map_err(|e|e.to_string())?;
        let name=format!("openbot_it_origin_{}",Uuid::new_v4().simple());
        let renamed=format!("{name}_r");
        require(renamed.len()<63&&renamed.chars().all(|x|x.is_ascii_lowercase()||x.is_ascii_digit()||x=='_'),"owned role escaped identifier")?;
        let database:String=c.query_one("SELECT current_database()",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(database.starts_with("openbot_it_")&&database.chars().all(|x|x.is_ascii_alphanumeric()||x=='_'),"owned role escaped database")?;
        c.batch_execute(&format!("CREATE ROLE \"{name}\" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;GRANT CREATE ON DATABASE \"{database}\" TO \"{name}\";GRANT USAGE,CREATE ON SCHEMA public TO \"{name}\";SET ROLE \"{name}\";")).await.map_err(|e|e.to_string())?;
        let result=async{
            baseline::apply(&c).await.map_err(|e|e.to_string())?;
            native::apply_through(&mut c,49).await.map_err(|e|e.to_string())?;
            let original_oid:String=c.query_one("SELECT relowner::text FROM pg_class WHERE oid='public.threads'::regclass",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
            require(original_oid!="10","owner O was not actually distinct from PG bootstrap")?;
            check_oracle(&c).await?;
            c.batch_execute(&format!("RESET ROLE;ALTER ROLE \"{name}\" RENAME TO \"{renamed}\";SET ROLE \"{renamed}\";")).await.map_err(|e|e.to_string())?;
            let same_oid:String=c.query_one("SELECT relowner::text FROM pg_class WHERE oid='public.threads'::regclass",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
            require(original_oid==same_oid,"role rename changed original owner identity")?;
            check_oracle(&c).await?;
            Ok(())
        }.await;
        let reset=c.batch_execute("RESET ROLE").await.map_err(|e|e.to_string());
        let cleanup=if reset.is_ok(){
            // Resolve the actual remaining owned role after a body failure before rename.
            let actual:String=c.query_one("SELECT rolname FROM pg_roles WHERE rolname=$1 OR rolname=$2",&[&name,&renamed]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
            c.batch_execute(&format!("DROP OWNED BY \"{actual}\" CASCADE;DROP ROLE \"{actual}\";")).await.map_err(|e|e.to_string())
        }else{Err("owned role RESET failed".to_owned())};
        result.and(reset).and(cleanup)
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o02_historical48_upgrade49_and_exact_prefix_replay() {
    owned("origin49upgrade",|p,_|async move{
        initialize(&p,48).await?;
        let mut c=p.get().await.map_err(|e|e.to_string())?;
        let old_ledger:Value=c.query_one("SELECT jsonb_agg(jsonb_build_array(version,name,checksum) ORDER BY version) FROM openbot_internal.schema_migrations",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        let public_before=schema_facts::fetch(&c).await.map_err(|e|e.to_string())?;
        let independent_public:schema_facts::SchemaFacts=serde_json::from_str(include_str!("../../../fixtures/db/schema-0046.json")).map_err(|e|e.to_string())?;
        require(public_before==independent_public,"historical48 not exact public0046 oracle")?;
        require(desktop_vault_canary::verify_pre_upgrade_layout(&p).await.map_err(|e|e.to_string())?.native_version()==48,"actual48 not preupgrade recognized")?;
        require(desktop_vault_canary::verify_current_layout(&p).await.is_err(),"actual48 accepted current49")?;
        require(native::apply_through(&mut c,48).await.map_err(|e|e.to_string())?==native::ApplyOutcome::AlreadyApplied,"explicit historical48 replay failed")?;
        let absent:bool=c.query_one("SELECT to_regclass('openbot_internal.thread_origins') IS NULL",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(absent,"historical48 replay unexpectedly created49")?;
        require(native::apply_through(&mut c,49).await.map_err(|e|e.to_string())?==native::ApplyOutcome::Applied,"actual48->49 did not apply")?;
        let r=c.query_one("SELECT count(*),max(version) FROM openbot_internal.schema_migrations",&[]).await.map_err(|e|e.to_string())?;
        require(r.try_get::<_,i64>(0).map_err(|e|e.to_string())?==37&&r.try_get::<_,i32>(1).map_err(|e|e.to_string())?==49,"current ledger not37/49")?;
        let unchanged:Value=c.query_one("SELECT jsonb_agg(jsonb_build_array(version,name,checksum) ORDER BY version) FROM openbot_internal.schema_migrations WHERE version<=48",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(old_ledger==unchanged,"migration altered original13..48 ledger")?;
        require(schema_facts::fetch(&c).await.map_err(|e|e.to_string())?==public_before,"49 altered public typed schema")?;
        require(desktop_vault_canary::verify_pre_upgrade_layout(&p).await.map_err(|e|e.to_string())?.native_version()==49,"historical49 canary not recognized")?;
        require(desktop_vault_canary::verify_current_layout(&p).await.is_err(),"historical49 accepted current50")?;
        check_oracle(&c).await?;
        c.batch_execute("CREATE TABLE openbot_internal.owned_origin_ddl_observations(tag text);CREATE FUNCTION openbot_internal.owned_origin_ddl_probe() RETURNS event_trigger LANGUAGE plpgsql AS $$BEGIN INSERT INTO openbot_internal.owned_origin_ddl_observations SELECT command_tag FROM pg_event_trigger_ddl_commands(); END$$;CREATE EVENT TRIGGER owned_origin_ddl_probe ON ddl_command_end EXECUTE FUNCTION openbot_internal.owned_origin_ddl_probe();TRUNCATE openbot_internal.owned_origin_ddl_observations;").await.map_err(|e|e.to_string())?;
        require(native::apply_through(&mut c,49).await.map_err(|e|e.to_string())?==native::ApplyOutcome::AlreadyApplied,"exact49 replay did not return AlreadyApplied")?;
        let ddl:i64=c.query_one("SELECT count(*) FROM openbot_internal.owned_origin_ddl_observations",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(ddl==0,"current49 replay issued actual object DDL")?;
        for mutation in ["DELETE FROM openbot_internal.schema_migrations WHERE version=46",
            "UPDATE openbot_internal.schema_migrations SET name='known47_wrong' WHERE version=47",
            "UPDATE openbot_internal.schema_migrations SET checksum=repeat('a',64) WHERE version=47",
            "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(51,'unknown51',repeat('b',64))",
            "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(12,'extra12',repeat('c',64))"]{
            c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
            c.batch_execute(mutation).await.map_err(|e|e.to_string())?;
            let refused=native::validate_known_prefix(&c,49).await;
            c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
            require(matches!(refused,Err(InfraError::NativeMigration(_))|Err(InfraError::RepositoryInvariant{..})),"exact current prefix drift lost its structural classification")?;
            check_oracle(&c).await?;
        }
        Ok(())
    }).await;
    owned("origin49history47", |p, _| async move {
        initialize(&p, 47).await?;
        let mut c = p.get().await.map_err(|e| e.to_string())?;
        require(
            native::apply_through(&mut c, 47)
                .await
                .map_err(|e| e.to_string())?
                == native::ApplyOutcome::AlreadyApplied,
            "exact47 replay drifted",
        )?;
        require(
            native::apply_through(&mut c, 48)
                .await
                .map_err(|e| e.to_string())?
                == native::ApplyOutcome::Applied,
            "real historical47->48 did not apply",
        )?;
        require(
            native::apply_through(&mut c, 48)
                .await
                .map_err(|e| e.to_string())?
                == native::ApplyOutcome::AlreadyApplied,
            "explicit48 replay drifted",
        )?;
        let absent: bool = c
            .query_one(
                "SELECT to_regclass('openbot_internal.thread_origins') IS NULL",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .try_get(0)
            .map_err(|e| e.to_string())?;
        require(absent, "explicit historical prefixes created current49")
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o03_plain_v1_new_origin_and_current_actor() {
    owned("origin49plainv1",|p,config|async move{
        provision(&p).await?;
        let directory=directory(&p,&config)?;
        let req=request("origin-a",301);
        require(req.command.model_selection.is_none()&&req.command.selected_skill_slugs.is_empty(),"plain V1 premise missing")?;
        let before_clock={let c=p.get().await.map_err(|e|e.to_string())?;c.query_one("SELECT clock_timestamp()",&[]).await.map_err(|e|e.to_string())?.try_get::<_,time::OffsetDateTime>(0).map_err(|e|e.to_string())?};
        require(!directory.begin_thread_run(req.clone()).await.map_err(|e|e.to_string())?.replayed,"actual new plain V1 replayed")?;
        let original={let c=p.get().await.map_err(|e|e.to_string())?;let original=verify_native_origin(&c,req.command.thread_id.as_str(),"origin-a","native_begin_v1").await?;
            let in_clock:bool=c.query_one("SELECT recorded_at >= $2 AND recorded_at <= clock_timestamp() FROM openbot_internal.thread_origins WHERE thread_id=$1",&[&req.command.thread_id.as_str(),&before_clock]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;require(in_clock,"recorded_at not actual PG acceptance clock")?;original};
        require(directory.begin_thread_run(req.clone()).await.map_err(|e|e.to_string())?.replayed,"exact V1 replay absent")?;
        {let c=p.get().await.map_err(|e|e.to_string())?;require(origin(&c,req.command.thread_id.as_str()).await?==Some(original),"exact replay rewrote historical origin/xmin")?;}
        for (actor,generation,index) in [("origin-missing",7,302),("origin-roleless",7,303),("origin-denied",7,304),("origin-a",6,305)]{
            let before=counts(&p).await?;
            let mut candidate=request(actor,index);candidate.auth_generation=AuthGeneration::new(generation);
            require(directory.begin_thread_run(candidate).await==Err(ThreadDirectoryError::NotVisible),"actual new plain V1 did not reject current actor drift")?;
            require(counts(&p).await?==before,"current actor rejection left partial business/origin")?;
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o05_private_channel_atomic_origin_and_current_scope() {
    owned("origin49channel",|p,_|async move{
        provision(&p).await?;
        let repo=ChannelRepo::new(p.clone());
        let auth=current_owned_auth(&p,"origin-a").await?;
        let before=counts(&p).await?;
        let created=openbot_application::create_channel(&repo,&auth,vec![BotId::new("origin-bot")]).await.map_err(|e|e.to_string())?;
        let thread=created.thread_id.as_ref().ok_or("actual channel omitted new Thread")?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        let value=verify_native_origin(&c,thread.as_str(),"origin-a","private_agent_channel").await?;
        require(value["anchor_kind"]=="channel"&&value["anchor_id"]==created.id.as_str(),"channel origin anchor differs")?;
        let r=c.query_one("SELECT (SELECT count(*) FROM public.channels WHERE id=$1),(SELECT count(*) FROM public.channel_memberships WHERE channel_id=$1 AND user_id='origin-a'),(SELECT count(*) FROM public.channel_agents WHERE channel_id=$1 AND agent_id='origin-bot'),(SELECT count(*) FROM public.threads WHERE thread_id=$2)",&[&created.id.as_str(),&thread.as_str()]).await.map_err(|e|e.to_string())?;
        require((0..4).all(|i|r.get::<_,i64>(i)==1),"channel surfaces not atomically committed")?;
        drop(c);
        let after=counts(&p).await?;
        require(after[0]==before[0]+1&&after[7]==before[7]+1,"channel created unexpected Thread/origin count")?;
        for (actor,generation,roles) in [("origin-a",6,vec![Role::User]),("origin-a",7,vec![Role::Admin]),("origin-denied",7,vec![Role::User])]{
            let stale=AuthContextBuilder::from_verified_session(DeploymentId::new(DEP),TenantId::new(TENANT),ActorId::new(actor),AuthGeneration::new(generation),false).with_roles(roles).build();
            let before=counts(&p).await?;
            require(openbot_application::create_channel(&repo,&stale,vec![BotId::new("origin-bot")]).await.is_err(),"stale/current admin mismatch channel accepted")?;
            require(counts(&p).await?==before,"rejected channel left partial Thread/origin")?;
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o10_late_outbox_failure_rolls_back_origin_and_business() {
    owned("origin49lateoutbox",|p,config|async move{
        provision(&p).await?;
        let directory=directory(&p,&config)?;
        let failed=request("origin-a",1001);
        {let c=p.get().await.map_err(|e|e.to_string())?;
            c.execute("INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload) VALUES($1,'test','owned-preexisting',0,'agent_run_dispatch','internal','{}'::jsonb)",&[&format!("{}:agent_run_dispatch",failed.command.run_id.as_str())]).await.map_err(|e|e.to_string())?;}
        let before=counts(&p).await?;
        require(directory.begin_thread_run(failed.clone()).await==Err(ThreadDirectoryError::RequestConflict),"actual late outbox collision did not refuse")?;
        require(counts(&p).await?==before,"late outbox rollback left origin or business")?;
        {let c=p.get().await.map_err(|e|e.to_string())?;require(origin(&c,failed.command.thread_id.as_str()).await?.is_none(),"late failure left new origin")?;}
        let succeeds=request("origin-a",1002);
        require(!directory.begin_thread_run(succeeds.clone()).await.map_err(|e|e.to_string())?.replayed,"same form positive did not truly commit")?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        verify_native_origin(&c,succeeds.command.thread_id.as_str(),"origin-a","native_begin_v1").await?;
        Ok(())
    }).await;
}

// Original production assembly and original registry enrollment, adapted only to this owned pool.
struct ClosedProbe;
#[async_trait]
impl RemoteAguiTransport for ClosedProbe {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o04_v2_origin_preserves_original_dataset_consumer() {
    owned("origin49v2dataset",|p,config|async move{
        provision(&p).await?;
        let mut f=ModelFixture::new(p.clone(),config.clone()).await;
        let result=async{
            let model=f.model(CustomModelProtocol::OpenaiResponses).await;
            let req=f.request(401,false,&model);
            f.directory.begin_thread_run_v2(req.clone()).await.map_err(|e|e.to_string())?;
            {let c=p.get().await.map_err(|e|e.to_string())?;
                verify_native_origin(&c,req.command.thread_id.as_str(),"alice","native_begin_v2").await?;
                let input:Value=c.query_one("SELECT content FROM public.messages WHERE message_id=$1||':input'",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
                require(input["modelSelection"]==serde_json::to_value(&req.command.model_selection).map_err(|e|e.to_string())?,"original RunInput custom selection differs")?;
                let snapshot_count:i64=c.query_one("SELECT count(*) FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
                require(snapshot_count==1,"actual original V2 snapshot absent")?;
            }
            let runtime=PostgresRunRuntime::new(p.clone(),PROCESS.into(),DEFAULT_THREAD_LEASE_DURATION,DEFAULT_DISPATCH_CLAIM_DURATION).map_err(|e|e.to_string())?;
            let claim=runtime.claim_dispatch().await.map_err(|e|e.to_string())?.ok_or("actual V2 dispatch absent")?;
            let lease=runtime.acknowledge_dispatch(&claim).await.map_err(|e|e.to_string())?;
            require(lease.run_id().as_str()==req.command.run_id.as_str(),"V2 claim/ack reached another Run")?;
            let context=PostgresAgentContextSource::new(p.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),Some(32)).map_err(|e|e.to_string())?.with_model_dataset_binding(f.binding.clone()).map_err(|e|e.to_string())?;
            let loaded=context.load(&lease).await.map_err(|e|e.to_string())?;
            require(matches!(&loaded.route,openbot_application::ProviderRoute::CustomModel(binding)
                if binding.connection_id()==model.id&&binding.connection_revision()==model.revision
                    &&binding.protocol()==CustomModelProtocol::OpenaiResponses&&binding.model()==model.model),"original context consumer lost original V2 selection")?;
            runtime.finish_run(&lease,lease.next_event_sequence(),RunTerminal::Completed).await.map_err(|e|e.to_string())?;
            let before=counts(&f.pool).await?;
            let other_pool=pool::connect(&f.config).await.map_err(|e|e.to_string())?;
            let mismatch=PostgresThreadDirectory::with_runtime(other_pool.clone(),config.clone(),PROCESS.into(),DEFAULT_THREAD_LEASE_DURATION).map_err(|e|e.to_string())?.with_model_dataset_binding(f.binding.clone());
            require(mismatch.is_err(),"different original Pool accepted original binding")?;
            close_pool(other_pool).await?;
            require(counts(&p).await?==before,"pool mismatch added business/origin")?;
            let mut wrong=f.request(402,false,&model);
            wrong.tenant=TenantId::new("owned-origin-other-tenant");
            require(f.directory.begin_thread_run_v2(wrong).await.is_err(),"wrong namespace accepted original dataset")?;
            require(counts(&p).await?==before,"namespace mismatch added business/origin")?;
            drop(f.registry.take());
            require(f.directory.begin_thread_run_v2(f.request(403,false,&model)).await.is_err(),"dropped original owner still accepted new V2")?;
            require(counts(&p).await?==before,"closed binding added business/origin")?;
            Ok(())
        }.await;
        f.finish().await;
        result
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn o06_later_member_and_v1_to_v2_keep_original_creator() {
    owned("origin49latermember",|p,config|async move{
        provision(&p).await?;
        let f=ModelFixture::new(p.clone(),config.clone()).await;
        let result=async{
            let mut first=request("origin-a",601);first.command.bot_id=BotId::new("bot");
            f.directory.begin_thread_run(first.clone()).await.map_err(|e|e.to_string())?;
            let original={let c=p.get().await.map_err(|e|e.to_string())?;verify_native_origin(&c,first.command.thread_id.as_str(),"origin-a","native_begin_v1").await?};
            settle(&p,first.command.run_id.as_str()).await?;
            {let c=p.get().await.map_err(|e|e.to_string())?;
                c.execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,'origin-b')",&[&first.command.thread_id.as_str()]).await.map_err(|e|e.to_string())?;}
            let mut later=request("origin-b",602);later.command.thread_id=first.command.thread_id.clone();later.command.bot_id=BotId::new("bot");
            f.directory.begin_thread_run(later.clone()).await.map_err(|e|e.to_string())?;
            settle(&p,later.command.run_id.as_str()).await?;
            let b_auth=current_owned_auth(&p,"origin-b").await?;
            let model=f.models.create(&b_auth,&CreateModelConnection{name:"Owned later B".into(),protocol:CustomModelProtocol::OpenaiChatCompletions,endpoint:"https://owned-origin.example.test/v1".into(),model:"owned-later-model".into(),enabled:true,api_key:ModelApiKey::new(Zeroizing::new("OWNED_ORIGIN_LATER_B_KEY".into())).map_err(|e|e.to_string())?}).await.map_err(|e|e.to_string())?;
            let mut v2=f.request(603,false,&model);v2.actor=ActorId::new("origin-b");v2.command.thread_id=first.command.thread_id.clone();
            f.directory.begin_thread_run_v2(v2.clone()).await.map_err(|e|e.to_string())?;
            require(f.directory.begin_thread_run_v2(v2.clone()).await.map_err(|e|e.to_string())?.replayed,"exact later B V2 did not replay")?;
            let c=p.get().await.map_err(|e|e.to_string())?;
            require(origin(&c,first.command.thread_id.as_str()).await?==Some(original),"later member/V1->V2 rewrote creator/kind/recorded_at/xmin")?;
            for run in [later.command.run_id.as_str(),v2.command.run_id.as_str()]{
                let actor:String=c.query_one("SELECT actor_id FROM public.runs WHERE run_id=$1",&[&run]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
                require(actor=="origin-b","later accepted Run did not actually belong to B")?;
            }
            let membership:i64=c.query_one("SELECT count(*) FROM public.thread_memberships WHERE thread_id=$1 AND user_id='origin-b'",&[&first.command.thread_id.as_str()]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
            require(membership==1,"later B membership premise absent")
        }.await;
        f.finish().await;
        result
    }).await;
}
fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        ActorId::new("alice"),
        AuthGeneration::new(7),
        false,
    )
    .with_roles([Role::User])
    .build()
}
struct ModelFixture {
    pool: pool::DatabasePool,
    config: pool::DatabaseConfig,
    assembly: PostgresApplicationAssembly,
    registry: Option<Arc<ArtifactDatasetRegistry>>,
    binding: Arc<PostgresModelDatasetBinding>,
    directory: PostgresThreadDirectory,
    models: PostgresModelConnections,
}
impl ModelFixture {
    async fn new(p: pool::DatabasePool, config: pool::DatabaseConfig) -> Self {
        let c = p.get().await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','owned-v2-alice@example.test',7),('bob','owned-v2-bob@example.test',7);
            INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
            INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
            INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Owned bot','','owned','public');
            INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES('channel','Owned channel','',ARRAY[]::text[],ARRAY[]::text[]);
            INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');
            INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
        drop(c);
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x61; 32]).unwrap(),
        );
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                p.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .unwrap(),
        );
        let policy_store = PolicyStore::postgres(p.clone(), None);
        policy_store.load().await.unwrap();
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: p.clone(),
            listener_database: config.clone().into(),
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            single_user: false,
            admin_floor: None,
            model: "owned-model".into(),
            credential_key_id: "owned-key-ref".into(),
            credential_vault: vault.clone(),
            audit_key: SecretBytes::new(vec![0x62; 32]),
            remote_assertions: Arc::new(RemoteRunAssertionSigner::new(vec![0x63; 32]).unwrap()),
            mcp_oauth_state_key: SecretBytes::new(vec![0x64; 32]),
            policy_store,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(ClosedProbe),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: url::Url::parse("http://127.0.0.1:9/v1/chat/completions").unwrap(),
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".into()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .unwrap();
        let binding = assembly.model_dataset_binding.clone();
        binding.enroll_original_registry(&registry).unwrap();
        let directory = PostgresThreadDirectory::with_runtime(
            p.clone(),
            config.clone(),
            PROCESS.into(),
            time::Duration::seconds(30),
        )
        .unwrap()
        .with_model_dataset_binding(binding.clone())
        .unwrap();
        let models = PostgresModelConnections::new(
            p.clone(),
            vault,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x62; 32]),
        )
        .unwrap();
        Self {
            pool: p,
            config,
            assembly,
            registry: Some(registry),
            binding,
            directory,
            models,
        }
    }
    async fn model(&self, protocol: CustomModelProtocol) -> ModelConnection {
        self.models
            .create(
                &auth(),
                &CreateModelConnection {
                    name: "Owned choice".into(),
                    protocol,
                    endpoint: "https://owned-v2.example.test/v1".into(),
                    model: "owned-selected-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new("OWNED_V2_SYNTHETIC_KEY".into()))
                        .unwrap(),
                },
            )
            .await
            .unwrap()
    }
    fn request(
        &self,
        index: u64,
        channel: bool,
        model: &ModelConnection,
    ) -> BeginThreadRunV2Request {
        let mut entropy = [0u8; 16];
        entropy[8..].copy_from_slice(&index.to_be_bytes());
        BeginThreadRunV2Request {
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            actor: ActorId::new("alice"),
            auth_generation: AuthGeneration::new(7),
            command: BeginThreadRunV2 {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),
                run_id: RunId::new(format!("owned-v2-run-{index}")),
                bot_id: BotId::new("bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: "Exact owned words".into(),
                selected_skill_slugs: vec![],
                model_selection: RunModelSelectionV2::new(
                    ModelSelectionIntentSource::Custom,
                    model.id.clone(),
                    model.revision,
                    format!("custom:{}", model.id),
                    1,
                )
                .unwrap(),
            },
        }
    }
    async fn finish(self) {
        self.assembly.shutdown().await;
        drop(self.directory);
        drop(self.models);
        drop(self.binding);
        drop(self.registry);
    }
}
