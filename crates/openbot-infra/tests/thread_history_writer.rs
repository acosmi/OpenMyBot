//! Native0051 body writers and canonical channel sources on owned PostgreSQL17.11.
//! Internal metadata and permanent IDs; this suite grants no current Host or ACK.
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
use openbot_application::provider::{ProviderRemoteProjection, ProviderRemoteProjectionKind};
use openbot_application::{
    COMPONENT_HUMAN_DECISION_TTL, ComponentAdministration, ComponentAdministrationError,
    ComponentHumanDecisionDraft, ComponentHumanDecisionScope, ProviderRemoteInterrupt,
    ProviderRemoteInterruptBatch, ProviderRemoteInterruptInput, ProviderRemoteResumeStatus,
    RemoteInterruptCoordinator, RemoteInterruptError, RunExecutionLease, RunFailureCode,
    RunRuntimeError, RunSemanticChannel, RunToolExchange,
};
use openbot_contracts::components::{
    ASK_APPROVAL_COMPONENT_DESCRIPTION, ASK_APPROVAL_COMPONENT_NAME, ASK_APPROVAL_COMPONENT_TITLE,
    ComponentApprovalAnswer, ComponentApprovalDecision, ComponentHumanDecisionAnswer,
};
use openbot_contracts::ids::{ThreadId, ToolCallId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::tool::args::ToolArguments;
use openbot_infra::component_catalogue::PostgresComponentAdministration;
use openbot_infra::db::thread_history_admission_schema as admission_schema;
use openbot_infra::remote_interrupt::PostgresRemoteInterruptCoordinator;
use openbot_infra::repo::run::{RunEventRepo, RunRepo};
use openbot_infra::repo::thread::MessageRepo;
include!("support/thread_history_writer_schema_fixture.rs");

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w01_fresh51_upgrade50_and_complete_prior_graph() {
    for prior in [50, 51] {
        owned(&format!("writer51graph{prior}"),move|p,_|async move {
            initialize(&p,prior).await?;
            let mut c=p.get().await.map_err(|e|e.to_string())?;
            if prior==50 {
                let pure=admission_schema::capture(&c).await.map_err(|e|e.to_string())?;
                let old:Value=serde_json::from_str(include_str!("../../../fixtures/db/thread-history-admission-0050.json")).map_err(|e|e.to_string())?;
                require(pure["schema"]["relations"]==old["schema"]["relations"],"explicit0050 relations altered before upgrade")?;
                require(native::apply(&mut c).await.map_err(|e|e.to_string())?==native::ApplyOutcome::Applied,"real50 to51 upgrade was not applied")?;
            }
            writer_check(&c).await?;
            let rows:i64=c.query_one("SELECT count(*) FROM openbot_internal.channel_history_sources",&[]).await.map_err(|e|e.to_string())?.get(0);
            require(rows==0,"migration fabricated channel source backfill")?;
            let faults=[
                "ALTER TABLE openbot_internal.channel_history_sources ADD COLUMN owned_unregistered text",
                "ALTER TABLE openbot_internal.channel_history_sources ALTER COLUMN recorded_at SET DEFAULT now()",
                "ALTER TABLE openbot_internal.channel_history_sources ALTER COLUMN source_schema DROP NOT NULL",
                "ALTER TABLE openbot_internal.channel_history_sources RENAME CONSTRAINT channel_history_sources_role_check TO owned_wrong_role",
                "ALTER TABLE openbot_internal.channel_history_sources DISABLE TRIGGER channel_history_sources_require_final",
                "ALTER TABLE public.messages DISABLE TRIGGER messages_history_canonical_before",
                "ALTER TABLE public.runs DISABLE TRIGGER runs_history_terminal_final",
                "ALTER TABLE public.channels DISABLE TRIGGER channels_history_projection_before",
                "ALTER FUNCTION openbot_internal.thread_history_preview(text) COST 17",
                "ALTER FUNCTION openbot_internal.thread_history_preview(text) SECURITY DEFINER",
                "GRANT EXECUTE ON FUNCTION openbot_internal.thread_history_preview(text) TO PUBLIC",
                "CREATE FUNCTION openbot_internal.thread_history_preview(text,integer) RETURNS text LANGUAGE sql AS 'SELECT $1'",
                "CREATE INDEX owned_extra_source_idx ON openbot_internal.channel_history_sources(message_id)",
                "GRANT SELECT ON openbot_internal.channel_history_sources TO PUBLIC",
                "ALTER FUNCTION pg_catalog.plpgsql_call_handler() STRICT",
                "ALTER FUNCTION pg_catalog.plpgsql_inline_handler(internal) COST 19",
                "ALTER FUNCTION pg_catalog.plpgsql_validator(oid) PARALLEL SAFE",
                "REVOKE USAGE ON LANGUAGE plpgsql FROM PUBLIC",
                "REVOKE EXECUTE ON FUNCTION pg_catalog.plpgsql_call_handler() FROM PUBLIC",
            ];
            for fault in faults {
                c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
                c.batch_execute(fault).await.map_err(|e|format!("owned fault did not form: {fault}: {e}"))?;
                let before:Value=c.query_one("SELECT jsonb_build_object('c',(SELECT jsonb_agg(to_jsonb(x) ORDER BY oid) FROM pg_constraint x WHERE conrelid='openbot_internal.channel_history_sources'::regclass),'f',(SELECT jsonb_agg(to_jsonb(x) ORDER BY oid) FROM pg_proc x WHERE pronamespace='openbot_internal'::regnamespace),'t',(SELECT jsonb_agg(to_jsonb(x) ORDER BY oid) FROM pg_trigger x WHERE tgrelid IN('openbot_internal.channel_history_sources'::regclass,'public.messages'::regclass,'public.runs'::regclass,'public.channels'::regclass)),'l',(SELECT to_jsonb(x) FROM pg_language x WHERE lanname='plpgsql'),'lf',(SELECT jsonb_agg(to_jsonb(x) ORDER BY oid) FROM pg_proc x WHERE pronamespace=11 AND proname IN('plpgsql_call_handler','plpgsql_inline_handler','plpgsql_validator')))",&[]).await.map_err(|e|e.to_string())?.get(0);
                let rejected=writer_check(&c).await.is_err();
                let after:Value=c.query_one("SELECT jsonb_build_object('c',(SELECT jsonb_agg(to_jsonb(x) ORDER BY oid) FROM pg_constraint x WHERE conrelid='openbot_internal.channel_history_sources'::regclass),'f',(SELECT jsonb_agg(to_jsonb(x) ORDER BY oid) FROM pg_proc x WHERE pronamespace='openbot_internal'::regnamespace),'t',(SELECT jsonb_agg(to_jsonb(x) ORDER BY oid) FROM pg_trigger x WHERE tgrelid IN('openbot_internal.channel_history_sources'::regclass,'public.messages'::regclass,'public.runs'::regclass,'public.channels'::regclass)),'l',(SELECT to_jsonb(x) FROM pg_language x WHERE lanname='plpgsql'),'lf',(SELECT jsonb_agg(to_jsonb(x) ORDER BY oid) FROM pg_proc x WHERE pronamespace=11 AND proname IN('plpgsql_call_handler','plpgsql_inline_handler','plpgsql_validator')))",&[]).await.map_err(|e|e.to_string())?.get(0);
                c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
                require(rejected&&before==after,"current full graph accepted or repaired exact tamper")?;
                writer_check(&c).await?;
            }
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w02_real_v1_v2_begin_and_channel_message_are_atomic() {
    owned("writer51begin",|p,config|async move{
        provision(&p).await?;writer_channel(&p,"writer-begin-channel").await?;
        let d=directory(&p,&config)?;
        let mut first=request("origin-a",360201);first.command.anchor=ThreadRunAnchor::Channel{channel_id:ChannelId::new("writer-begin-channel")};
        d.begin_thread_run(first.clone()).await.map_err(|e|e.to_string())?;
        { let c=p.get().await.map_err(|e|e.to_string())?;
          check_base_head(&c,first.command.thread_id.as_str()).await?;
          let r=c.query_one("SELECT s.thread_id=$1 AND s.run_id=$2 AND s.message_role='user' AND s.last_message_agent_id IS NULL AND s.preview_utf8_bytes=octet_length(c.last_message),s.preview_checksum=encode(sha256(convert_to(c.last_message,'UTF8')),'hex') FROM openbot_internal.channel_history_sources s JOIN public.channels c ON c.id=s.channel_id WHERE c.id='writer-begin-channel'",&[&first.command.thread_id.as_str(),&first.command.run_id.as_str()]).await.map_err(|e|e.to_string())?;
          require(r.get::<_,bool>(0)&&r.get::<_,bool>(1),"real V1 user source/projection not atomically bound")?;
          close_writer_head(&c,first.command.thread_id.as_str()).await?;
        }
        let before=writer_snapshot(&p).await?;
        let mut successor=first.clone();successor.command.run_id=RunId::new("writer-after-closed");successor.command.message="must remain absent".into();
        require(d.begin_thread_run(successor).await==Err(ThreadDirectoryError::NotVisible),"closed V1 newRun accepted")?;
        require(writer_snapshot(&p).await?==before,"closed begin changed body/lease/origin/projection/outbox")?;
        let denied=request("origin-roleless",360202);
        require(d.begin_thread_run(denied).await.is_err(),"H registration replaced original role authority")?;
        require(writer_snapshot(&p).await?==before,"original role refusal changed persistent rows")?;
        let late=request("origin-a",360203);
        {let c=p.get().await.map_err(|e|e.to_string())?;c.execute("INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload) VALUES($1,'test','owned-existing',0,'agent_run_dispatch','internal','{}')",&[&format!("{}:agent_run_dispatch",late.command.run_id.as_str())]).await.map_err(|e|e.to_string())?;}
        let before_late=writer_snapshot(&p).await?;
        require(d.begin_thread_run(late).await==Err(ThreadDirectoryError::RequestConflict),"late original outbox unique error accepted")?;
        require(writer_snapshot(&p).await?==before_late,"late begin failure did not roll back complete aggregate")?;
        let f=ModelFixture::new(p.clone(),config.clone()).await;
        let result:TestResult=async{
            let model=f.model(CustomModelProtocol::OpenaiResponses).await;
            for (n,channel) in [(360204,false),(360205,true)] {
                let req=f.request(n,channel,&model);f.directory.begin_thread_run_v2(req.clone()).await.map_err(|e|e.to_string())?;
                let c=p.get().await.map_err(|e|e.to_string())?;check_base_head(&c,req.command.thread_id.as_str()).await?;
                require(c.query_one("SELECT count(*) FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?.get::<_,i64>(0)==1,"real V2 dataset snapshot absent")?;
                close_writer_head(&c,req.command.thread_id.as_str()).await?;drop(c);
                let before=writer_snapshot(&p).await?;let mut next=req;next.command.run_id=RunId::new(format!("writer-v2-closed-{n}"));
                require(f.directory.begin_thread_run_v2(next).await.is_err(),"closed V2 accepted newRun/body")?;
                require(writer_snapshot(&p).await?==before,"closed V2 changed complete aggregate")?;
            } Ok(())
        }.await;f.finish().await;result
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w03_typed_and_raw_seven_body_actual_joint_and_old_new() {
    owned("writer51body",|p,_|async move{
        provision(&p).await?;writer_components(&p).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        writer_raw_open(&c,"writer-body-open","writer-body-run").await?;
        writer_raw_open(&c,"writer-body-other","writer-body-other-run").await?;
        // All seven positive raw statements really commit before the same seven closed refusals.
        for (_,sql) in writer_raw_body_sql("writer-body-open","writer-body-run") { c.batch_execute(&sql).await.map_err(|e|format!("open body fixture never formed: {e}"))?; }
        let messages=MessageRepo::new(p.clone());let runs=RunRepo::new(p.clone());let events=RunEventRepo::new(p.clone());
        let m=openbot_infra::db::tables::messages::Row{message_id:"writer-typed-open".into(),thread_id:"writer-body-open".into(),seq:2,role:"user".into(),content:json!({"text":"typed open"}),search_text:"typed open".into(),run_id:Some("writer-body-run".into()),actor_id:Some("origin-a".into()),created_at:datetime!(2026-09-01 00:00:02 UTC)};
        messages.insert(&m).await.map_err(|e|e.to_string())?;
        let e=openbot_infra::db::tables::run_events::Row{run_id:"writer-body-run".into(),seq:2,thread_id:"writer-body-open".into(),event_seq:2,event_type:"checkpoint".into(),payload:json!({"owned":"typed open"}),terminal:false,created_at:datetime!(2026-09-01 00:00:02 UTC)};
        events.insert(&e).await.map_err(|e|e.to_string())?;
        let base_run=runs.find_by_id("writer-body-run").await.map_err(|e|e.to_string())?.ok_or("original typed Run absent")?;
        close_writer_head(&c,"writer-body-open").await?;drop(c);
        let before=writer_snapshot(&p).await?;let c=p.get().await.map_err(|e|e.to_string())?;
        for (_,sql) in writer_raw_body_sql("writer-body-open","writer-body-run") {writer_refusal(&c,&sql.replace("new-body","closed-new-body"),"thread_history_writer_closed").await?;}
        let mut new_m=m.clone();new_m.message_id="writer-typed-closed".into();new_m.seq=3;
        require(matches!(messages.insert(&new_m).await,Err(InfraError::RepositoryInvariant{code:"thread_history_writer_closed"})),"typed MessageRepo accepted closed actual J")?;
        let mut new_e=e.clone();new_e.seq=3;new_e.event_seq=3;
        require(matches!(events.insert(&new_e).await,Err(InfraError::RepositoryInvariant{code:"thread_history_writer_closed"})),"typed RunEventRepo accepted closed J")?;
        let mut new_run=base_run.clone();new_run.run_id="writer-typed-newrun-closed".into();
        require(matches!(runs.insert(&new_run).await,Err(InfraError::RepositoryInvariant{code:"thread_history_writer_closed"})),"typed newRun accepted closed referenced Thread")?;
        let mut forged=new_m;forged.thread_id="writer-body-other".into();
        require(messages.insert(&forged).await.is_err(),"open forged row.Thread bypassed actual closed Run.thread")?;
        writer_refusal(&c,"UPDATE public.messages SET thread_id='writer-body-other' WHERE message_id='writer-typed-open'","thread_history_writer_binding_invalid").await?;
        writer_refusal(&c,"UPDATE public.messages SET thread_id='writer-body-other',run_id='writer-body-other-run' WHERE message_id='writer-typed-open'","thread_history_writer_closed").await?;
        writer_refusal(&c,"UPDATE public.runs SET thread_id='writer-body-other' WHERE run_id='writer-body-run'","thread_history_writer_closed").await?;
        writer_refusal(&c,"INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id) VALUES('writer-bad-joint','writer-body-other',99,'user','{}','x','writer-body-run','origin-a')","thread_history_writer_binding_invalid").await?;
        c.execute("UPDATE public.threads SET status='archived',updated_at=updated_at WHERE thread_id='writer-body-open'",&[]).await.map_err(|e|e.to_string())?;
        c.execute("UPDATE public.threads SET status='active' WHERE thread_id='writer-body-open'",&[]).await.map_err(|e|e.to_string())?;drop(c);
        require(writer_snapshot(&p).await?==before,"closed/raw/typed/malformed joint refusals or metadata replay changed persistent values")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w04_actual_chunk_remote_projection_tool_pair_admission() {
    owned("writer51runtime",|p,config|async move{
        provision(&p).await?;let(req,runtime,lease)=writer_running(&p,&config,360401,None).await?;
        require(runtime.append_semantic_chunk(&lease,1,RunSemanticChannel::Text,"owned\0nul").await==Err(RunRuntimeError::InvalidInput{field:"semantic_chunk"}),"Rust NUL premise reached SQL history writer")?;
        let projection=ProviderRemoteProjection::new(ProviderRemoteProjectionKind::State,None,None,json!({"phase":"working"})).map_err(|e|e.to_string())?;
        let exchange=RunToolExchange::new(ToolCallId::new("writer-call"),"writer-provider-call".into(),"computer.write".into(),json!({"message":"hello"}),"redacted owned result".into(),None).map_err(|e|e.to_string())?;
        runtime.append_semantic_chunk(&lease,1,RunSemanticChannel::Text,"actual owned text").await.map_err(|e|e.to_string())?;
        runtime.append_remote_projection(&lease,2,&projection).await.map_err(|e|e.to_string())?;
        runtime.append_tool_exchange(&lease,3,&exchange).await.map_err(|e|e.to_string())?;
        {let c=p.get().await.map_err(|e|e.to_string())?;require(c.query_one("SELECT count(*) FROM public.messages WHERE run_id=$1 AND role IN('assistant','tool')",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?.get::<_,i64>(0)==2,"actual tool pair absent")?;close_writer_head(&c,req.command.thread_id.as_str()).await?;}
        let before=writer_snapshot(&p).await?;
        for seq in [1,4] {require(runtime.append_semantic_chunk(&lease,seq,RunSemanticChannel::Text,"actual owned text").await==Err(RunRuntimeError::StaleLease),"closed chunk new/replay body admitted")?;}
        require(runtime.append_remote_projection(&lease,2,&projection).await==Err(RunRuntimeError::StaleLease),"closed remote projection replay admitted")?;
        require(runtime.append_tool_exchange(&lease,3,&exchange).await==Err(RunRuntimeError::StaleLease),"closed tool pair replay admitted")?;
        require(writer_snapshot(&p).await?==before,"closed runtime calls changed body/sequence/lease/outbox")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w05_closed_finish_and_terminal_replay_read_no_body() {
    owned("writer51finish",|p,config|async move{
        provision(&p).await?;
        for(index,terminal) in [RunTerminal::Completed,RunTerminal::Failed(RunFailureCode::ProviderGenerationFailed),RunTerminal::Cancelled,RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)].into_iter().enumerate() {
            let(req,runtime,lease)=writer_running(&p,&config,360501+index as u64,None).await?;
            runtime.append_semantic_chunk(&lease,1,RunSemanticChannel::Text,"BODY_MUST_NOT_BE_READ_WHEN_CLOSED").await.map_err(|e|e.to_string())?;
            runtime.append_semantic_chunk(&lease,2,RunSemanticChannel::Reasoning,"PRIVATE_OWNED_REASONING").await.map_err(|e|e.to_string())?;
            {let c=p.get().await.map_err(|e|e.to_string())?;close_writer_head(&c,req.command.thread_id.as_str()).await?;}
            let receipt=runtime.finish_run(&lease,3,terminal).await.map_err(|e|e.to_string())?;
            require(!receipt.replayed,"first actual closed terminal was replay")?;
            {let c=p.get().await.map_err(|e|e.to_string())?;
              require(c.query_one("SELECT NOT EXISTS(SELECT 1 FROM public.messages WHERE run_id=$1 AND role='assistant')",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?.get::<_,bool>(0),"closed finish materialized assistant from old body")?;
              let payload:Value=c.query_one("SELECT payload FROM public.run_events WHERE run_id=$1 AND terminal",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?.get(0);
              let expected=match terminal.error_code(){Some(code)=>json!({"status":terminal.as_str(),"errorCode":code.as_str()}),None=>json!({"status":terminal.as_str()})};
              require(payload==expected,"closed terminal is not actual fixed payload")?;
              let reason:Value=c.query_one("SELECT payload FROM public.run_events WHERE run_id=$1 AND seq=2",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?.get(0);
              require(reason==json!({"channel":"reasoning","delta":"","retained":false}),"closed finish did not fixed reasoning scrub")?;
            }
            let before=writer_snapshot(&p).await?;
            require(runtime.finish_run(&lease,3,terminal).await.map_err(|e|e.to_string())?.replayed,"closed exact terminal replay not accepted")?;
            require(writer_snapshot(&p).await?==before,"closed terminal replay rewrote old body or metadata")?;
            // Reconciliation remains foreground. Its isolated next case must release that
            // original occupancy without manufacturing a different lease/terminal.
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w06_approval_component_remote_and_local_fixed_cleanup() {
    owned("writer51human",|p,config|async move{
        provision(&p).await?;writer_components(&p).await?;
        let(req,runtime,lease)=writer_running(&p,&config,360601,None).await?;
        let component=PostgresComponentAdministration::new(p.clone(),vec![0x47;32]).map_err(|e|e.to_string())?;
        let scope=writer_component_scope(&req);let draft=writer_decision("writer-decision");
        component.request_component_human_decision(&scope,&draft).await.map_err(|e|e.to_string())?;
        let remote=Arc::new(PostgresRemoteInterruptCoordinator::new(p.clone(),PROCESS.into(),vec![0x52;32]).map_err(|e|e.to_string())?);
        let batch=writer_interrupt(req.command.run_id.as_str(),"writer-remote")?;
        let wait_port=remote.clone();let wait_lease=lease.clone();let wait_batch=batch.clone();
        let mut waiter=tokio::spawn(async move{wait_port.persist_and_wait(&wait_lease,&wait_batch).await});
        let actor=current_owned_auth(&p,"origin-a").await?;
        let pending=tokio::time::timeout(Duration::from_secs(5),async{loop{let r=remote.list_pending(&actor).await.map_err(|e|e.to_string())?;if !r.is_empty(){return Ok::<_,String>(r);}tokio::task::yield_now().await;}}).await.map_err(|_|"actual remote request did not commit".to_owned())??;
        remote.resolve(&actor,pending[0].request_id(),ProviderRemoteResumeStatus::Resolved,Some(json!({"owned":"answer"}))).await.map_err(|e|e.to_string())?;
        tokio::time::timeout(Duration::from_secs(5),&mut waiter).await.map_err(|_|"actual remote waiter not closed".to_owned())?.map_err(|e|e.to_string())?.map_err(|e|e.to_string())?;
        {let c=p.get().await.map_err(|e|e.to_string())?;close_writer_head(&c,req.command.thread_id.as_str()).await?;}
        let before=writer_snapshot(&p).await?;
        require(component.request_component_human_decision(&scope,&writer_decision("writer-late-decision")).await==Err(ComponentAdministrationError::NotVisible),"closed actual component request accepted")?;
        let answer=ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer{decision:ComponentApprovalDecision::Approved,note:None});
        require(component.resolve_component_human_decision(&actor,&draft.decision_id,&answer).await==Err(ComponentAdministrationError::NotVisible),"closed actual component answer accepted")?;
        require(remote.persist_and_wait(&lease,&writer_interrupt(req.command.run_id.as_str(),"writer-late-remote")?).await==Err(RemoteInterruptError::Stale),"closed actual remote request accepted")?;
        require(writer_snapshot(&p).await?==before,"closed human APIs changed audit/body/metadata")?;
        runtime.finish_run(&lease,1,RunTerminal::Cancelled).await.map_err(|e|e.to_string())?;
        require(component.wait_component_human_decision(&scope,&draft.decision_id).await==Err(ComponentAdministrationError::NotVisible),"original component waiter did not retire cancelled Run")?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        let r=c.query_one("SELECT (SELECT bool_and(state='cancelled' AND answer IS NULL) FROM public.component_human_decisions WHERE run_id=$1),(SELECT bool_and(state='retired' AND descriptor IS NULL AND response_payload IS NULL) FROM public.remote_agent_interrupts WHERE run_id=$1)",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?;
        require(r.get::<_,Option<bool>>(0)==Some(true)&&r.get::<_,Option<bool>>(1)==Some(true),"closed fixed component/remote cleanup did not commit")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w07_real_rc_head_and_unique_wait_refresh_joint() {
    owned("writer51rc", |p, config| async move {
        provision(&p).await?;
        let (req, _, lease) = writer_running(&p, &config, 360701, None).await?;
        let owner = p.get().await.map_err(|e| e.to_string())?;
        let owner_pid: i32 = owner
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        owner
            .batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await
            .map_err(|e| e.to_string())?;
        writer_stage_close(&owner, req.command.thread_id.as_str()).await?;
        let (worker_pool, worker_pid) =
            writer_dedicated(&config, "writer51_actual_rc_wait").await?;
        let worker_runtime = writer_runtime(&worker_pool)?;
        let worker_lease = lease.clone();
        let worker = tokio::spawn(async move {
            worker_runtime
                .append_semantic_chunk(
                    &worker_lease,
                    1,
                    RunSemanticChannel::Text,
                    "must be refused after real wait",
                )
                .await
        });
        let observer = p.get().await.map_err(|e| e.to_string())?;
        let blocked = writer_blocked(&observer, worker_pid, owner_pid).await;
        owner
            .batch_execute(if blocked.is_ok() {
                "COMMIT"
            } else {
                "ROLLBACK"
            })
            .await
            .map_err(|e| e.to_string())?;
        let result = tokio::time::timeout(Duration::from_secs(8), worker)
            .await
            .map_err(|_| "actual RC writer remained blocked".to_owned())?
            .map_err(|e| e.to_string())?;
        blocked?;
        require(
            result == Err(RunRuntimeError::StaleLease),
            "real RC writer did not refresh closed H after wait",
        )?;
        require(
            observer
                .query_one(
                    "SELECT count(*) FROM public.run_events WHERE run_id=$1 AND seq=1",
                    &[&req.command.run_id.as_str()],
                )
                .await
                .map_err(|e| e.to_string())?
                .get::<_, i64>(0)
                == 0,
            "blocked actual writer inserted body",
        )?;
        drop(observer);
        drop(owner);
        drop(worker_pool);
        Ok(())
    })
    .await;
    owned("writer51unique", |p, _| async move {
        initialize(&p, 49).await?;
        {
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            raw_thread(&c, "writer-lazy-unique").await?;
            native::apply(&mut c).await.map_err(|e| e.to_string())?;
            require(
                head(&c, "writer-lazy-unique").await?.is_none(),
                "51 eagerly backfilled old H",
            )?;
        }
        let a = p.get().await.map_err(|e| e.to_string())?;
        let owner_pid: i32 = a
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        a.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await
            .map_err(|e| e.to_string())?;
        a.query_one(
            "SELECT openbot_internal.thread_history_lock_joint('writer-lazy-unique',NULL)",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
        writer_stage_close(&a, "writer-lazy-unique").await?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let p2 = p.clone();
        let worker = tokio::spawn(async move {
            let b = p2.get().await.map_err(|e| e.to_string())?;
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
                "unique worker changed original RC",
            )?;
            tx.send(r.get::<_, i32>(0))
                .map_err(|_| "PID observer closed".to_owned())?;
            let result = b
                .query_one(
                    "SELECT openbot_internal.thread_history_lock_joint('writer-lazy-unique',NULL)",
                    &[],
                )
                .await;
            let out = result.map(|r| r.get::<_, bool>(0)).map_err(|e| {
                (
                    e.code().map(|c| c.code().to_owned()),
                    e.as_db_error().map(|d| d.message().to_owned()),
                )
            });
            b.batch_execute("ROLLBACK")
                .await
                .map_err(|e| e.to_string())?;
            Ok::<_, String>(out)
        });
        let worker_pid = rx.await.map_err(|e| e.to_string())?;
        let observer = p.get().await.map_err(|e| e.to_string())?;
        let blocked = writer_blocked(&observer, worker_pid, owner_pid).await;
        a.batch_execute(if blocked.is_ok() {
            "COMMIT"
        } else {
            "ROLLBACK"
        })
        .await
        .map_err(|e| e.to_string())?;
        let actual = tokio::time::timeout(Duration::from_secs(8), worker)
            .await
            .map_err(|_| "unique worker remained blocked".to_owned())?
            .map_err(|e| e.to_string())??;
        blocked?;
        require(
            actual == Ok(false),
            "original unique wait did not reobserve closed H in fresh RC statement",
        )?;
        require(
            head(&observer, "writer-lazy-unique")
                .await?
                .ok_or("lazy H missing")?["phase"]
                == "closed",
            "lazy conflict replaced closed permanent H",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w08_actual_serializable_component_remote_roll_back() {
    owned("writer51serial",|p,config|async move{
        provision(&p).await?;writer_components(&p).await?;
        for remote_case in [false,true] {
            let index=if remote_case{360802}else{360801};let(req,_,lease)=writer_running(&p,&config,index,None).await?;
            let owner=p.get().await.map_err(|e|e.to_string())?;let owner_pid:i32=owner.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            owner.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;writer_stage_close(&owner,req.command.thread_id.as_str()).await?;
            let(worker_pool,pid)=writer_dedicated(&config,if remote_case{"writer51_actual_remote_ser"}else{"writer51_actual_component_ser"}).await?;
            let scope=writer_component_scope(&req);let batch=writer_interrupt(req.command.run_id.as_str(),"writer-serialization")?;
            let component=PostgresComponentAdministration::new(worker_pool.clone(),vec![0x47;32]).map_err(|e|e.to_string())?;
            let remote=PostgresRemoteInterruptCoordinator::new(worker_pool.clone(),PROCESS.into(),vec![0x52;32]).map_err(|e|e.to_string())?;
            let worker=tokio::spawn(async move{if remote_case {Ok::<_,String>(remote.persist_and_wait(&lease,&batch).await==Err(RemoteInterruptError::Unavailable))}else{Ok(component.request_component_human_decision(&scope,&writer_decision("writer-serialization")).await==Err(ComponentAdministrationError::Unavailable))}});
            let observer=p.get().await.map_err(|e|e.to_string())?;let blocked=writer_blocked(&observer,pid,owner_pid).await;
            // Real H update commits after the actual caller's SERIALIZABLE snapshot.
            // A later row-lock read has a natural serialization failure; adapters retain
            // their public Unavailable error and the whole original transaction rolls back.
            owner.batch_execute(if blocked.is_ok(){"COMMIT"}else{"ROLLBACK"}).await.map_err(|e|e.to_string())?;
            let result=tokio::time::timeout(Duration::from_secs(8),worker).await.map_err(|_|"actual SER caller remained blocked".to_owned())?.map_err(|e|e.to_string())??;blocked?;
            require(result,"actual SERIALIZABLE caller retried/switched isolation or changed error class")?;
            let r=observer.query_one("SELECT (SELECT count(*) FROM public.component_human_decisions WHERE run_id=$1),(SELECT count(*) FROM public.remote_agent_interrupts WHERE run_id=$1),(SELECT count(*) FROM public.audit_events WHERE event_type IN('component.human_requested','agent.remote_interrupt_requested'))",&[&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?;
            require((0..3).all(|i|r.get::<_,i64>(i)==0),"SER refusal retained human body/audit rows")?;
            drop(observer);drop(owner);drop(worker_pool);
        }Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w09_import_new_conflict_and_observation_never_bypass() {
    owned("writer51import",|p,_|async move{
        provision(&p).await?;let store=PostgresIntelligenceImportStore::new(p.clone());
        let(bundle,mapping,id,run)=writer_import_terminal(360901)?;
        let recording=RecordingImport{store:PostgresIntelligenceImportStore::new(p.clone()),request:std::sync::Mutex::new(None)};
        let first=import_intelligence_bundle(&recording,bundle.clone(),mapping.clone()).await.map_err(|e|e.to_string())?;
        let first_request=recording.request.lock().map_err(|_|"owned request mutex")?.clone().ok_or("actual normalized terminal import request not observed")?;
        require(first.status==IntelligenceImportReportStatus::Completed,"real valid open arbitrary terminal import refused")?;
        let mut normalized=bundle.payload().threads[0].clone();normalized.created_by="origin-a".into();normalized.members=vec!["origin-a".into()];normalized.anchor=IntelligenceThreadAnchor::DirectBot{bot_id:"origin-bot".into()};normalized.runs[0].bot_id="origin-bot".into();normalized.runs[0].actor_id="origin-a".into();
        require(store.verify_thread(&id).await.map_err(|e|e.to_string())?==compute_intelligence_thread_checksum(&normalized).map_err(|e|e.to_string())?,"independent imported checksum differs")?;
        let c=p.get().await.map_err(|e|e.to_string())?;close_writer_head(&c,&id).await?;
        let terminal:Value=c.query_one("SELECT payload FROM public.run_events WHERE run_id=$1 AND terminal",&[&run]).await.map_err(|e|e.to_string())?.get(0);
        // Closed metadata replay and fixed nonterminal scrub must not reinterpret
        // valid historical terminal object/error as the new fixed21 exception.
        c.execute("UPDATE public.runs SET finished_at=finished_at WHERE run_id=$1",&[&run]).await.map_err(|e|e.to_string())?;
        c.execute("UPDATE public.run_events SET created_at=created_at WHERE run_id=$1 AND terminal",&[&run]).await.map_err(|e|e.to_string())?;
        c.execute(r#"UPDATE public.run_events SET payload='{"channel":"reasoning","delta":"","retained":false}' WHERE run_id=$1 AND seq=1"#,&[&run]).await.map_err(|e|e.to_string())?;
        require(c.query_one("SELECT payload FROM public.run_events WHERE run_id=$1 AND terminal",&[&run]).await.map_err(|e|e.to_string())?.get::<_,Value>(0)==terminal,"closed nonterminal scrub changed/read-restricted old terminal")?;drop(c);
        let observed=store.verify_thread(&id).await.map_err(|e|e.to_string())?;
        require(observed.event_count==3,"closed pure checksum observation denied or changed old denominator")?;
        let progress=store.load_progress(&bundle.payload().bundle_id,DEP,bundle.payload_sha256()).await.map_err(|e|e.to_string())?.ok_or("completed cursor missing")?;
        require(progress.status==openbot_application::IntelligenceImportCursorStatus::Completed,"completed report pure observation refused by closed H")?;
        // Completed progress is observation only. A distinct bundle which needs
        // this same aggregate to be written must reach the real existing-row lock.
        let mut new_payload=bundle.payload().clone();new_payload.bundle_id="writer-new-bundle-closed".into();
        let distinct=VerifiedIntelligenceBundle::new(new_payload,"e".repeat(64),"owned-writer-maintenance-key".into()).map_err(|e|e.to_string())?;
        // The original use case emitted this complete normalized request. Reusing
        // it as input changes only a new bundle's envelope/provenance, not expected
        // schema, body, checksum, cursor-chain counts or canonical thread data.
        let mut request=first_request;request.bundle_id=distinct.payload().bundle_id.clone();request.payload_sha256=distinct.payload_sha256().into();request.provenance["payloadSha256"]=json!(distinct.payload_sha256());
        let before=writer_snapshot(&p).await?;
        require(store.import_thread(request).await==Err(IntelligenceImportError::Conflict{field:"thread_history_closed"}),"real store accepted existing closed aggregate or refused before exact writer admission")?;
        require(writer_snapshot(&p).await?==before,"closed import changed aggregate/body/cursor/memory")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w10_three_channel_callers_require_complete_source_pair() {
    owned("writer51source",|p,config|async move{
        provision(&p).await?;writer_channel(&p,"writer-source-real").await?;
        let(req,runtime,lease)=writer_running(&p,&config,361001,Some("writer-source-real")).await?;
        runtime.append_semantic_chunk(&lease,1,RunSemanticChannel::Text,"actual assistant canonical answer").await.map_err(|e|e.to_string())?;
        runtime.finish_run(&lease,2,RunTerminal::Completed).await.map_err(|e|e.to_string())?;
        {let c=p.get().await.map_err(|e|e.to_string())?;let r=c.query_one("SELECT s.message_role='assistant' AND s.last_message_agent_id='origin-bot' AND s.thread_id=$1 AND s.run_id=$2 AND m.actor_id IS NULL AND m.content->>'text'=m.search_text AND s.message_created_at=m.created_at AND s.preview_checksum=encode(sha256(convert_to(c.last_message,'UTF8')),'hex') FROM openbot_internal.channel_history_sources s JOIN public.channels c ON c.id=s.channel_id JOIN public.messages m ON m.message_id=s.message_id WHERE c.id='writer-source-real'",&[&req.command.thread_id.as_str(),&req.command.run_id.as_str()]).await.map_err(|e|e.to_string())?;require(r.get::<_,bool>(0),"real finish assistant did not bind canonical full tuple")?;close_writer_head(&c,req.command.thread_id.as_str()).await?;}
        // V1 and V2 real user callers are both exercised by w02; this case
        // executes the third production caller and both halves' final constraints.
        writer_channel(&p,"writer-source-pair").await?;
        writer_canonical(&p,"writer-source-pair","writer-pair-thread","writer-pair-run","writer-pair-message","owned canonical user","user",1).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        writer_refusal(&c,"UPDATE public.channels SET last_message='forged',last_message_at='2026-09-01T00:00:01Z' WHERE id='writer-source-pair'","thread_history_writer_binding_invalid").await?;
        c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        let projection_first=writer_pair_sql(&c,"writer-source-pair","writer-pair-message",false).await;
        c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        require(projection_first.is_err(),"projection-before-source fabricated a source authority")?;
        c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        writer_pair_sql(&c,"writer-source-pair","writer-pair-message",true).await?;
        c.batch_execute("COMMIT").await.map_err(|e|e.to_string())?;
        // Referenced role/actor/joint/search/time changes are ordinary DML denials,
        // even if a proposed tuple preserves the same rendered preview.
        for sql in [
            "UPDATE public.messages SET role='assistant' WHERE message_id='writer-pair-message'",
            "UPDATE public.messages SET actor_id='origin-b' WHERE message_id='writer-pair-message'",
            "UPDATE public.messages SET search_text='forged' WHERE message_id='writer-pair-message'",
            "UPDATE public.messages SET created_at=created_at+interval '1 microsecond' WHERE message_id='writer-pair-message'",
            "UPDATE public.runs SET bot_id='changed-bot' WHERE run_id='writer-pair-run'",
            "UPDATE public.threads SET anchor_id='another-channel' WHERE thread_id='writer-pair-thread'",
        ] {writer_refusal(&c,sql,"thread_history_writer_source_mutation_refused").await?;}
        c.batch_execute("BEGIN;DELETE FROM openbot_internal.channel_history_sources WHERE channel_id='writer-source-pair'").await.map_err(|e|e.to_string())?;
        let half=c.batch_execute("COMMIT").await;
        c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        require(half.is_err_and(|e|e.as_db_error().is_some_and(|d|d.code().code()=="55000"&&d.message()=="thread_history_writer_binding_invalid")),"source-delete half actually committed")?;
        c.batch_execute("BEGIN;UPDATE public.channels SET last_message=NULL,last_message_at=NULL,last_message_agent_id=NULL WHERE id='writer-source-pair'").await.map_err(|e|e.to_string())?;
        let half=c.batch_execute("COMMIT").await;
        c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        require(half.is_err_and(|e|e.code().is_some_and(|d|d.code()=="55000")),"projection-NULL half actually committed")?;
        c.batch_execute("BEGIN;DELETE FROM openbot_internal.channel_history_sources WHERE channel_id='writer-source-pair';UPDATE public.channels SET last_message=NULL,last_message_at=NULL,last_message_agent_id=NULL WHERE id='writer-source-pair';COMMIT").await.map_err(|e|e.to_string())?;
        drop(c);
        let(new_req,new_runtime,new_lease)=writer_running(&p,&config,361002,Some("writer-source-real")).await?;
        {let c=p.get().await.map_err(|e|e.to_string())?;require(c.query_one("SELECT thread_id=$1 FROM openbot_internal.channel_history_sources WHERE channel_id='writer-source-real'",&[&new_req.command.thread_id.as_str()]).await.map_err(|e|e.to_string())?.get::<_,bool>(0),"newer open J could not replace closed J preview")?;}
        new_runtime.finish_run(&new_lease,1,RunTerminal::Cancelled).await.map_err(|e|e.to_string())?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w11_unicode_reverse_changes_truncate_and_actual_two_tx() {
    owned("writer51reverse",|p,config|async move{
        provision(&p).await?;
        let controls="\u{0001}\u{001f}\u{007f}\u{009f}";
        let whitespace="\u{0085}\u{00a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}";
        let vectors=vec![
            (format!("  a{controls}{whitespace}b  "),"a b".to_owned()),
            ("\u{200b}\u{feff}".to_owned(),"\u{200b}\u{feff}".to_owned()),
            ("界".repeat(199),"界".repeat(199)),("界".repeat(200),"界".repeat(200)),
            ("界".repeat(201),format!("{}…","界".repeat(199))),
            ("😀".repeat(200),"😀".repeat(200)),("😀".repeat(201),format!("{}…","😀".repeat(199))),
            ("e\u{0301}".repeat(101),format!("{}e…","e\u{0301}".repeat(99))),
        ];
        for(index,(input,expected)) in vectors.into_iter().enumerate() {
            let channel=format!("writer-vector-{index}");writer_channel(&p,&channel).await?;
            let mut req=request("origin-a",361100+index as u64);req.command.anchor=ThreadRunAnchor::Channel{channel_id:ChannelId::new(&channel)};req.command.message=input.clone();
            directory(&p,&config)?.begin_thread_run(req.clone()).await.map_err(|e|e.to_string())?;
            let c=p.get().await.map_err(|e|e.to_string())?;
            let r=c.query_one("SELECT openbot_internal.thread_history_preview($1),last_message FROM public.channels WHERE id=$2",&[&input,&channel]).await.map_err(|e|e.to_string())?;
            require(r.get::<_,String>(0)==expected&&r.get::<_,Option<String>>(1).as_deref()==Some(expected.as_str()),"independent Unicode vector differs in SQL or actual Rust caller")?;
        }
        let c=p.get().await.map_err(|e|e.to_string())?;
        require(c.query_one("SELECT openbot_internal.thread_history_preview(chr(0))",&[]).await.is_err_and(|e|e.code().is_some_and(|s|s.code()=="54000")),"SQL NUL premise did not refuse at PostgreSQL text boundary")?;
        drop(c);
        writer_channel(&p,"writer-reverse-channel").await?;
        let long="😀".repeat(201);
        writer_canonical(&p,"writer-reverse-channel","writer-reverse-thread","writer-reverse-run","writer-reverse-message",&long,"assistant",1).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;writer_pair_sql(&c,"writer-reverse-channel","writer-reverse-message",true).await?;c.batch_execute("COMMIT").await.map_err(|e|e.to_string())?;
        for sql in [
            "UPDATE public.messages SET content=jsonb_set(content,'{text}',to_jsonb(left(search_text,200)||'x')),search_text=left(search_text,200)||'x' WHERE message_id='writer-reverse-message'",
            "UPDATE public.messages SET content=content||'{\"extra\":true}' WHERE message_id='writer-reverse-message'",
            "UPDATE public.runs SET actor_id='origin-b' WHERE run_id='writer-reverse-run'",
            "UPDATE public.runs SET bot_id='another-bot' WHERE run_id='writer-reverse-run'",
        ] {writer_refusal(&c,sql,"thread_history_writer_source_mutation_refused").await?;}
        for table in ["messages","runs","run_events","channels"] {writer_refusal(&c,&format!("TRUNCATE public.{table} CASCADE"),"thread_history_writer_truncate_refused").await?;}
        writer_refusal(&c,"TRUNCATE openbot_internal.channel_history_sources","thread_history_writer_truncate_refused").await?;
        // UPDATE is admissible only after the actual pointer is removed and its
        // final projection is NULL; DELETE may instead reach that final state later.
        c.batch_execute("BEGIN;DELETE FROM openbot_internal.channel_history_sources WHERE channel_id='writer-reverse-channel';UPDATE public.channels SET last_message=NULL,last_message_at=NULL,last_message_agent_id=NULL WHERE id='writer-reverse-channel';UPDATE public.messages SET content=content||'{\"extra\":true}' WHERE message_id='writer-reverse-message';COMMIT").await.map_err(|e|e.to_string())?;
        c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;writer_pair_sql(&c,"writer-reverse-channel","writer-reverse-message",true).await?;c.batch_execute("COMMIT").await.map_err(|e|e.to_string())?;
        c.batch_execute("BEGIN;DELETE FROM public.messages WHERE message_id='writer-reverse-message';UPDATE public.channels SET last_message=NULL,last_message_at=NULL,last_message_agent_id=NULL WHERE id='writer-reverse-channel';DELETE FROM openbot_internal.channel_history_sources WHERE channel_id='writer-reverse-channel';COMMIT").await.map_err(|e|e.to_string())?;
        drop(c);
        // Two actual transactions share the channel mutex in both directions.
        writer_channel(&p,"writer-two-tx").await?;
        writer_canonical(&p,"writer-two-tx","writer-two-thread","writer-two-run","writer-two-message","two Tx canonical","assistant",1).await?;
        let a=p.get().await.map_err(|e|e.to_string())?;a.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        a.query_one("SELECT id FROM public.channels WHERE id='writer-two-tx' FOR UPDATE",&[]).await.map_err(|e|e.to_string())?;
        let b=p.get().await.map_err(|e|e.to_string())?;b.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        let reverse=b.execute("UPDATE public.runs SET actor_id='origin-b' WHERE run_id='writer-two-run'",&[]).await;
        b.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        require(reverse.is_err_and(|e|e.code().is_some_and(|s|s.code()=="55P03")),"reverse Run with no source row did not share channel NOWAIT mutex")?;
        writer_pair_sql(&a,"writer-two-tx","writer-two-message",true).await?;a.batch_execute("COMMIT").await.map_err(|e|e.to_string())?;
        b.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        b.query_one("SELECT run_id FROM public.runs WHERE run_id='writer-two-run' FOR UPDATE",&[]).await.map_err(|e|e.to_string())?;
        a.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        let r=a.execute("UPDATE openbot_internal.channel_history_sources SET preview_utf8_bytes=preview_utf8_bytes WHERE channel_id='writer-two-tx'",&[]).await;
        a.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        // A no-op source UPDATE does not inspect canonical body; a real replacement
        // below obtains m/r/t SHARE NOWAIT and is refused by the original Run lock.
        require(r.is_ok(),"exact unchanged source metadata unexpectedly reread body")?;
        a.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        let r=a.execute("UPDATE public.channels SET last_message='forged replacement',last_message_at=last_message_at+interval '1 microsecond' WHERE id='writer-two-tx'",&[]).await;
        a.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;b.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        require(r.is_err_and(|e|e.code().is_some_and(|s|s.code()=="55P03")),"projection validator did not obtain canonical Run SHARE NOWAIT")?;
        drop(a);drop(b);
        writer_reverse_matrix(&p).await?;
        // Only actual production callbacks notify. Seed a later, valid canonical
        // pair, then a real older Begin must preserve it and produce no wake.
        writer_channel(&p,"writer-notify-channel").await?;
        writer_canonical(&p,"writer-notify-channel","writer-notify-seed","writer-notify-seed-run","writer-notify-seed-msg","owned future canonical","assistant",2_000_000_000).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;writer_pair_sql(&c,"writer-notify-channel","writer-notify-seed-msg",true).await?;c.batch_execute("COMMIT").await.map_err(|e|e.to_string())?;drop(c);
        let(listener,mut notes,driver)=writer_listen(&config).await?;
        writer_channel(&p,"writer-notify-positive").await?;
        let mut positive=request("origin-a",361198);positive.command.anchor=ThreadRunAnchor::Channel{channel_id:ChannelId::new("writer-notify-positive")};
        directory(&p,&config)?.begin_thread_run(positive).await.map_err(|e|e.to_string())?;
        let note=tokio::time::timeout(Duration::from_secs(5),notes.recv()).await.map_err(|_|"actual positive producer NOTIFY absent".to_owned())?.ok_or("LISTEN driver closed before actual producer")?;
        let note:Value=serde_json::from_str(&note).map_err(|e|e.to_string())?;
        require(note["channelId"]=="writer-notify-positive","actual producer notification differs in typed channel")?;
        writer_notify_barrier(&listener,&mut notes).await?;
        let mut req=request("origin-a",361199);req.command.anchor=ThreadRunAnchor::Channel{channel_id:ChannelId::new("writer-notify-channel")};req.command.message="actual older source".into();
        directory(&p,&config)?.begin_thread_run(req.clone()).await.map_err(|e|e.to_string())?;
        writer_notify_barrier(&listener,&mut notes).await?;
        writer_canonical(&p,"writer-notify-channel","writer-notify-equal","writer-notify-equal-run","writer-notify-equal-msg","owned equal canonical","assistant",2_000_000_000).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        let equal=writer_pair_sql_pg(&c,"writer-notify-channel","writer-notify-equal-msg",true).await;c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        require(equal.is_err_and(|e|e.as_db_error().is_some_and(|d|d.code().code()=="55000"&&d.message()=="thread_history_writer_source_order_refused")),"equal timestamp source replacement bypassed strict ordering")?;
        writer_notify_barrier(&listener,&mut notes).await?;
        let source:Value=c.query_one("SELECT to_jsonb(s) FROM openbot_internal.channel_history_sources s WHERE channel_id='writer-notify-channel'",&[]).await.map_err(|e|e.to_string())?.get(0);
        require(source["message_id"]=="writer-notify-seed-msg","older/equal producer replaced canonical pointer")?;
        drop(c);
        // A real SQL transaction emits the same channel topic only after its
        // canonical pair exists, then fails its native deferred final constraint.
        // This is an owned transaction rollback witness, not a Rust late-outbox
        // fault: production Begin inserts its outbox before record_from_message.
        writer_channel(&p,"writer-notify-rollback").await?;
        writer_canonical(&p,"writer-notify-rollback","writer-notify-rollback-thread","writer-notify-rollback-run","writer-notify-rollback-msg","owned rollback body","assistant",9).await?;
        let before=writer_snapshot(&p).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
        writer_pair_sql(&c,"writer-notify-rollback","writer-notify-rollback-msg",true).await?;
        let wake=json!({"channelId":"writer-notify-rollback"}).to_string();
        c.query_one("SELECT pg_notify('openbot_channel_activity',$1)",&[&wake]).await.map_err(|e|e.to_string())?;
        c.execute("DELETE FROM openbot_internal.channel_history_sources WHERE channel_id='writer-notify-rollback'",&[]).await.map_err(|e|e.to_string())?;
        let rollback=c.batch_execute("COMMIT").await;
        require(rollback.is_err_and(|e|e.as_db_error().is_some_and(|d|d.code().code()=="55000"&&d.message()=="thread_history_writer_binding_invalid")),"post-notify deferred final constraint did not refuse incomplete source pair")?;
        c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
        drop(c);
        require(writer_snapshot(&p).await?==before,"real source+NOTIFY transaction rollback changed aggregate")?;
        writer_notify_barrier(&listener,&mut notes).await?;
        drop(listener);

        tokio::time::timeout(Duration::from_secs(5),driver).await.map_err(|_|"LISTEN driver did not naturally close".to_owned())?.map_err(|e|e.to_string())??;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn w12_current51_explicit50_and_original_host_id_regression() {
    for version in [47, 48, 49, 50, 51] {
        owned(&format!("writer51boundary{version}"),move|p,_|async move{
            initialize(&p,version).await?;
            let mut c=p.get().await.map_err(|e|e.to_string())?;
            let historical=native::validate_known_prefix(&c,version).await.map_err(|e|e.to_string())?;
            require(historical.latest_version()==version,"explicit original prefix changed")?;
            if version==50 {
                require(admission_schema::capture(&c).await.map_err(|e|e.to_string())?["schema"]["functions"].as_array().is_some_and(|f|f.len()==7),"explicit0050 no longer pure seven-function history")?;
                require(admission_schema::verify(&c).await.is_err(),"explicit0050 current consumer bypassed new whole0051")?;
            }
            if version<51 {native::apply(&mut c).await.map_err(|e|e.to_string())?;}
            writer_check(&c).await?;
            raw_thread(&c,"writer-original-permanent-id").await?;
            close_writer_head(&c,"writer-original-permanent-id").await?;
            let h=head(&c,"writer-original-permanent-id").await?;
            writer_refusal(&c,"UPDATE public.threads SET title='must not write closed body' WHERE thread_id='writer-original-permanent-id'","thread_history_writer_closed").await?;
            c.execute("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp(),updated_at=clock_timestamp() WHERE thread_id='writer-original-permanent-id'",&[]).await.map_err(|e|e.to_string())?;
            c.execute("DELETE FROM public.threads WHERE thread_id='writer-original-permanent-id'",&[]).await.map_err(|e|e.to_string())?;
            require(head(&c,"writer-original-permanent-id").await?==h,"current51 changed original permanent closed H/ID")?;
            require(c.execute(THREAD_INSERT,&[&"writer-original-permanent-id",&"origin-bot"]).await.is_err_and(|e|e.code().is_some_and(|s|s.code()=="55000")),"closed/deleted exact ID reused")?;
            // H/Q contains no current Host/window/session/lease permission. The
            // original current-authority regression functions remain selected separately.
            require(c.query_one("SELECT count(*) FROM openbot_internal.thread_origins WHERE thread_id='writer-original-permanent-id'",&[]).await.map_err(|e|e.to_string())?.get::<_,i64>(0)==0,"raw history metadata fabricated origin creator authority")?;
            Ok(())
        }).await;
    }
}
