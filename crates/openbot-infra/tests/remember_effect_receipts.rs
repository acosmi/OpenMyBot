//! Real remember producer evidence, using owned PostgreSQL fixtures and the actual capability,
//! memory, journal and run adapters. Capture-only fixtures never certify a business effect.
mod harness;
#[path = "remember_effect_receipts/process_restart.rs"]
mod process_restart;
#[path = "remember_effect_receipts/races.rs"]
mod races;
#[path = "remember_effect_receipts/recovery.rs"]
mod recovery;
#[path = "remember_effect_receipts/support.rs"]
mod support;

use openbot_application::{
    BeginThreadRunRequest, CancelThreadRunRequest, MemoryAdministration,
    MemoryAdministrationError as MemoryError, MutateMemoryRequest, RememberToolMemory,
    RememberToolMemoryRequest, RunEffectReceiptsRequest, RunExecutionLease, RunFailureCode,
    RunRuntime, RunTerminal, ThreadDirectory, ThreadDirectoryError, ToolJournal,
    UpdateMemoryControlRequest,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRun, CancelThreadRun, ThreadRunAnchor},
    error::AppError,
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ToolCallId},
    memory::{MemoryMutation, UpdateMemoryControl},
    reconciliation::RunEffectReceiptsSnapshot,
    tool::ToolInvocation,
};
use openbot_domain::tool::commit::CommitState;
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::{
    db::pool::DatabaseConfig,
    db::{baseline, native, pool},
    memory_admin::PostgresMemoryAdministration,
    repo::tools::PostgresToolJournal,
    run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime},
    thread_directory::PostgresThreadDirectory,
};
use serde_json::{Value, json};
use std::{future::Future, sync::Arc, time::Duration};
use support::{KEY, store};

const CONTENT: &str = "PRIVATE_REMEMBER_EFFECT_CONTENT_075";

struct Fixture {
    pool: Pool,
    config: DatabaseConfig,
    directory: PostgresThreadDirectory,
    runtime: PostgresRunRuntime,
    lease: RunExecutionLease,
    begin: BeginThreadRunRequest,
}

impl Fixture {
    async fn new(config: DatabaseConfig) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut c = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply(&mut c).await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('actor-a','a@example.test',0),('actor-b','b@example.test',0);
                INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user'),('actor-b','admin');
                INSERT INTO public.agents(id,name,type,configuration) VALUES('bot-a','A','built_in','{}'),('bot-b','B','built_in','{}');
                INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('bot-a',NULL,'A','synthetic','a','public'),('bot-b',NULL,'B','synthetic','b','public');
                INSERT INTO public.channels(id,name,description) VALUES('channel-a','A','synthetic');
                INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel-a','actor-a');
                INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel-a','bot-a');").await.map_err(|e|e.to_string())?;
        }
        let deployment = DeploymentId::new("dep-a");
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: TenantId::new("tenant-a"),
            actor: ActorId::new("actor-a"),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([75; 16]),
                run_id: RunId::new("run-effect-075"),
                bot_id: BotId::new("bot-a"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "synthetic source".into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "effect-owner".into(),
            time::Duration::minutes(10),
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let runtime = PostgresRunRuntime::new(
            pool.clone(),
            "effect-owner".into(),
            time::Duration::minutes(10),
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|e| e.to_string())?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no dispatch")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self {
            pool,
            config,
            directory,
            runtime,
            lease,
            begin,
        })
    }
    fn auth(&self) -> AuthContext {
        AuthContextBuilder::from_verified_session(
            self.begin.deployment.clone(),
            self.begin.tenant.clone(),
            self.begin.actor.clone(),
            AuthGeneration::new(0),
            false,
        )
        .with_role(Role::User)
        .build()
    }
    fn invocation(&self, seq: u64, scope: &str) -> ToolInvocation {
        ToolInvocation {
            call_id: ToolCallId::new(format!("effect-call-{seq}")),
            run_id: self.begin.command.run_id.clone(),
            bot_id: self.begin.command.bot_id.clone(),
            call_seq: seq,
            tool_name: "remember".into(),
            arguments: json!({"memoryKind":"preference","scope":scope,"content":CONTENT,"tags":["private-tag"],"sensitivity":"normal"}),
        }
    }
    async fn capture(&self, seq: u64) -> Result<RememberToolMemoryRequest, String> {
        support::capture(&self.pool, &self.auth(), self.invocation(seq, "user")).await
    }
    fn query(&self) -> RunEffectReceiptsRequest {
        RunEffectReceiptsRequest {
            deployment: self.begin.deployment.clone(),
            tenant: self.begin.tenant.clone(),
            actor: self.begin.actor.clone(),
            auth_generation: AuthGeneration::new(0),
            thread: self.begin.command.thread_id.clone(),
            run: self.begin.command.run_id.clone(),
            after: None,
            limit: 50,
        }
    }
    async fn terminal(&self) -> Result<(), String> {
        self.runtime
            .finish_run(
                &self.lease,
                self.lease.next_event_sequence(),
                RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown),
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    async fn read(&self) -> Result<RunEffectReceiptsSnapshot, String> {
        self.directory
            .run_effect_receipts(self.query())
            .await
            .map_err(|e| e.to_string())
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|e| e.to_string())
    }
    async fn tamper_thread_identity(&self, sql: &str) -> Result<(), String> {
        let mut client = self.pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tamper_owned_thread_identity(&tx, sql, &[]).await?;
        tx.commit().await.map_err(|e| e.to_string())
    }
}

async fn fixture<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let f = Fixture::new(config).await?;
        let pool = f.pool.clone();
        let result = body(f).await;
        pool.close();
        result
    })
    .await;
}

// Atomic-effect snapshots intentionally exclude durable decision records from request capture.
async fn effects(pool: &Pool) -> Result<Value, String> {
    pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT jsonb_build_object(
      'memories',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY memory_id),'[]') FROM public.memories m),
      'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY memory_id,seq),'[]') FROM public.memory_events e),
      'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY receipt_id),'[]') FROM public.remember_effect_receipts r),
      'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY created_at,id),'[]') FROM public.audit_events a))",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())
}

async fn lifecycle(pool: &Pool) -> Result<Value, String> {
    pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT jsonb_build_object(
      'runs',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY run_id),'[]') FROM public.runs r),
      'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY attempt_id),'[]') FROM public.tool_attempts a),
      'calls',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY tool_call_id),'[]') FROM public.tool_calls c),
      'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY outbox_id),'[]') FROM public.outbox o),
      'threads',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY thread_id),'[]') FROM public.threads t),
      'leases',(SELECT coalesce(jsonb_agg(to_jsonb(l) ORDER BY thread_id),'[]') FROM public.thread_leases l),
      'run_events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY run_id,seq),'[]') FROM public.run_events e))",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL"]
async fn tool_source_never_borrows_a_user_message_from_another_run_or_thread() {
    fixture("remembersourceboundary", |f| async move {
        let request=f.capture(0).await?;
        let mut c=f.pool.get().await.map_err(|e|e.to_string())?;
        let foreign=ThreadIdentity::new(&f.begin.deployment).mint_from_entropy([117;16]);
        c.execute("INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,next_message_seq)
            VALUES($1,$2,$3,$4,'direct_bot',$5,1)",&[&foreign.as_str(),&f.begin.tenant.as_str(),
            &f.begin.deployment.as_str(),&f.begin.actor.as_str(),&f.begin.command.bot_id.as_str()]).await.unwrap();
        let tx=c.transaction().await.map_err(|e|e.to_string())?;
        tamper_owned_message_joint(&tx, "INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id)
            VALUES('other-thread-source',$1,0,'user','{}','synthetic',$2,$3)",&[&foreign.as_str(),
            &f.begin.command.run_id.as_str(),&f.begin.actor.as_str()]).await?;
        tamper_owned_message_joint(&tx, "UPDATE public.messages SET run_id='another-source-run' WHERE thread_id=$1 AND role='user'",
            &[&f.begin.command.thread_id.as_str()]).await?;
        tx.commit().await.map_err(|e|e.to_string())?;
        let before=effects(&f.pool).await?;
        assert_eq!(store(&f.pool).remember_from_tool(request).await,
            Err(openbot_application::MemoryAdministrationError::Corrupt {field:"remember_source_message"}));
        assert_eq!(effects(&f.pool).await?,before);
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn real_pipeline_commits_memory_event_receipt_audit_and_keeps_model_reply_unchanged() {
    fixture("rememberpipeline",|f|async move {
        for (seq,scope) in ["user","bot","thread"].into_iter().enumerate() {
            let (result,request,_) = support::pipeline(&f.pool,&f.auth(),f.invocation(seq as u64,scope),Some(store(&f.pool)),false).await?;
            let reply=result.map_err(|e|e.to_string())?;
            assert_eq!(reply.commit_state,openbot_contracts::tool::ToolCommitState::Committed);
            let c=f.pool.get().await.map_err(|e|e.to_string())?;
            let row=c.query_one("SELECT source_thread_id,source_run_id,source_message_id,source_authorization_snapshot
                FROM public.memories WHERE scope_kind=$1",&[&scope]).await.map_err(|e|e.to_string())?;
            assert_eq!(row.get::<_,String>("source_thread_id"),f.begin.command.thread_id.as_str());
            assert_eq!(row.get::<_,String>("source_run_id"),f.begin.command.run_id.as_str());
            let message:String=row.get("source_message_id");
            assert!(c.query_one("SELECT EXISTS(SELECT 1 FROM public.messages WHERE message_id=$1 AND thread_id=$2
                AND run_id=$3 AND role='user')",&[&message,&f.begin.command.thread_id.as_str(),&f.begin.command.run_id.as_str()]).await.unwrap().get::<_,bool>(0));
            let snapshot:Value=row.get("source_authorization_snapshot");
            assert_eq!(snapshot["actorId"],f.begin.actor.as_str()); assert_eq!(snapshot["authGeneration"],0);
            drop(c);
            let output:Value=serde_json::from_str(&reply.content).unwrap();
            assert_eq!(output["status"],"remembered");assert_eq!(output.as_object().unwrap().len(),2);
            assert!(!reply.content.contains("receipt"));
            let c=f.pool.get().await.map_err(|e|e.to_string())?;
            let r=c.query_one("SELECT r.*,m.scope_kind,m.scope_id,e.event_type AS memory_event_type,a.event_type AS audit_type,a.target_id AS audit_target,a.payload FROM public.remember_effect_receipts r JOIN public.memories m USING(memory_id) JOIN public.memory_events e ON e.memory_id=r.memory_id AND e.seq=r.memory_event_seq JOIN public.audit_events a ON a.id::text=r.audit_event_id WHERE r.attempt_id=$1",&[&request.attempt().as_str()]).await.map_err(|e|e.to_string())?;
            assert_eq!(r.get::<_,String>("memory_id"),output["memoryId"].as_str().unwrap());
            assert_eq!(r.get::<_,String>("scope_kind"),scope);
            assert_eq!(r.get::<_,String>("audit_type"),"memory.effect_committed");
            assert_eq!(r.get::<_,String>("memory_event_type"),"create");
            assert_eq!(r.get::<_,String>("receipt_id"),r.get::<_,String>("audit_target"));
            let payload:Value=r.get("payload");
            assert_eq!(payload["tool_attempt_id"],request.attempt().as_str());assert_eq!(payload["memory_event_sequence"],0);
            assert!(!payload.to_string().contains(CONTENT));
            assert_eq!(r.get::<_,String>("args_hash"),request.args_hash().to_hex());
            let historical=store(&f.pool).remember_from_tool(request).await.map_err(|e|e.to_string())?;
            assert_eq!(historical.memory_id,output["memoryId"].as_str().unwrap());
        }
        let counts=f.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT (SELECT count(*) FROM public.memories),(SELECT count(*) FROM public.remember_effect_receipts),(SELECT count(*) FROM public.audit_events WHERE event_type='memory.effect_committed')",&[]).await.map_err(|e|e.to_string())?;
        for i in 0..3 {assert_eq!(counts.get::<_,i64>(i),3);}
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn effect_survives_later_outcome_failure_reconnect_erasure_and_duplicate_without_unlock() {
    fixture("rememberhistory",|f|async move {
        // Only the later ordinary outcome audit fails; the business receipt audit commits normally.
        f.sql("CREATE FUNCTION public.owned_reject_late_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='memory.remember_succeeded' THEN RAISE EXCEPTION 'owned late audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_reject_late_audit BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.owned_reject_late_audit();").await?;
        let (result,request,_) = support::pipeline(&f.pool,&f.auth(),f.invocation(0,"user"),Some(store(&f.pool)),false).await?;
        assert!(matches!(result,Err(AppError::ReconciliationRequired {..})));
        let attempt=f.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT status,commit_state FROM public.tool_attempts",&[]).await.map_err(|e|e.to_string())?;
        assert_eq!(attempt.get::<_,String>("status"),"executing");assert_eq!(attempt.get::<_,Option<String>>("commit_state"),None);
        f.sql("DROP TRIGGER owned_reject_late_audit ON public.audit_events; DROP FUNCTION public.owned_reject_late_audit();").await?;
        let historical=store(&f.pool).remember_from_tool(request.clone()).await.map_err(|e|e.to_string())?;
        f.terminal().await?;
        let snapshot=f.read().await?;assert_eq!(snapshot.receipts.len(),1);assert!(snapshot.foreground_blocked);assert!(snapshot.available_actions.is_empty());
        assert_eq!(snapshot.receipts[0].receipt_id,historical.receipt_id);
        let before=effects(&f.pool).await?;let original_lifecycle=lifecycle(&f.pool).await?;
        let mut competing=f.begin.clone();competing.command.run_id=RunId::new("blocked-second-run");
        assert!(matches!(f.directory.begin_thread_run(competing).await,Err(ThreadDirectoryError::LeaseConflict)));
        assert_eq!(effects(&f.pool).await?,before);assert_eq!(lifecycle(&f.pool).await?,original_lifecycle);
        // Unknown keeps its occupancy after a fresh connection/process adapter.
        let reconnected=pool::connect(&f.config).await.map_err(|e|e.to_string())?;
        let directory=PostgresThreadDirectory::with_runtime(reconnected.clone(),f.config.clone(),"readback-only".into(),time::Duration::minutes(10)).map_err(|e|e.to_string())?;
        assert_eq!(directory.run_effect_receipts(f.query()).await.map_err(|e|e.to_string())?.receipts,snapshot.receipts);
        let replacement=store(&f.pool).correct(openbot_application::CorrectMemoryRequest { deployment: openbot_contracts::ids::DeploymentId::new("dep-a"),
            tenant:f.begin.tenant.clone(),actor:f.begin.actor.clone(),auth_generation:AuthGeneration::new(0),memory_id:historical.memory_id.clone(),
            correction:openbot_contracts::memory::CorrectMemory {content:"synthetic corrected preference".into(),tags:vec![],sensitivity:openbot_contracts::memory::MemorySensitivity::Normal,expires_at:None},
        }).await.map_err(|e|e.to_string())?;
        assert_eq!(replacement.supersedes_id.as_deref(),Some(historical.memory_id.as_str()));
        let old=f.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT status FROM public.memories WHERE memory_id=$1",&[&historical.memory_id]).await.map_err(|e|e.to_string())?;
        assert_eq!(old.get::<_,String>(0),"superseded");
        let after_correction=effects(&f.pool).await?;
        assert_eq!(store(&f.pool).remember_from_tool(request.clone()).await.map_err(|e|e.to_string())?,historical);
        assert_eq!(f.read().await?.receipts,snapshot.receipts);assert_eq!(effects(&f.pool).await?,after_correction);
        store(&f.pool).mutate(MutateMemoryRequest {tenant:f.begin.tenant.clone(),actor:f.begin.actor.clone(),auth_generation:AuthGeneration::new(0),memory_id:historical.memory_id.clone(),mutation:MemoryMutation::Delete}).await.map_err(|e|e.to_string())?;
        store(&f.pool).update_memory_control(UpdateMemoryControlRequest {tenant:f.begin.tenant.clone(),actor:f.begin.actor.clone(),auth_generation:AuthGeneration::new(0),update:UpdateMemoryControl {writes_enabled:false}}).await.map_err(|e|e.to_string())?;
        f.sql("DELETE FROM public.thread_leases").await?;
        let before=effects(&f.pool).await?;let original_lifecycle=lifecycle(&f.pool).await?;
        assert_eq!(store(&f.pool).remember_from_tool(request.clone()).await.map_err(|e|e.to_string())?,historical);
        assert_eq!(effects(&f.pool).await?,before);assert_eq!(f.read().await?.receipts,snapshot.receipts);assert_eq!(lifecycle(&f.pool).await?,original_lifecycle);
        f.sql("UPDATE public.tool_calls SET args_hash=repeat('f',64)").await?;
        assert!(matches!(store(&f.pool).remember_from_tool(request).await,Err(MemoryError::Corrupt {..})));
        assert!(matches!(f.directory.run_effect_receipts(f.query()).await,Err(ThreadDirectoryError::Corrupt {..})));
        reconnected.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn receipt_or_audit_insert_failure_rolls_back_all_business_effects() {
    fixture("rememberrollback",|f|async move {
        let request=f.capture(0).await?;
        let before=effects(&f.pool).await?;
        assert_eq!(PostgresMemoryAdministration::new(f.pool.clone()).remember_from_tool(request.clone()).await,Err(MemoryError::Unavailable));
        for table in ["remember_effect_receipts","audit_events"] {
            f.sql(&format!("CREATE FUNCTION public.owned_reject_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned synthetic insertion failure'; END $$; CREATE TRIGGER owned_reject_effect BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.owned_reject_effect();")).await?;
            assert_eq!(store(&f.pool).remember_from_tool(request.clone()).await,Err(MemoryError::Unavailable));
            assert_eq!(effects(&f.pool).await?,before);
            f.sql(&format!("DROP TRIGGER owned_reject_effect ON public.{table}; DROP FUNCTION public.owned_reject_effect();")).await?;
        }
        let result=store(&f.pool).remember_from_tool(request).await.map_err(|e|e.to_string())?;
        assert!(!result.receipt_id.is_empty());Ok(())
    }).await;
}

// Privileged corruption control is confined to this owned disposable test DB.
// Probe the real guard for every change/restore and re-enable it in the same transaction.

// Finite privileged joint corruption in this disposable test DB. Ordinary
// open direct-source metadata changes stay ordinary DML; missing actual Run or
// referenced canonical mutations first prove their precise new55000 refusal.
async fn tamper_owned_message_joint(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    const GUARDS: [&str; 3] = [
        "messages_history_body_before",
        "messages_history_canonical_before",
        "messages_history_source_final",
    ];
    for guard in GUARDS {
        let state:String=tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.messages'::regclass AND tgname=$1 AND NOT tgisinternal",&[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!("owned message guard {guard} was not enabled"));
        }
    }
    tx.batch_execute("SAVEPOINT owned_message_joint_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, params).await;
    if matches!(&ordinary,Ok(n) if *n>0) {
        tx.batch_execute("RELEASE SAVEPOINT owned_message_joint_probe")
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_message_joint_probe; RELEASE SAVEPOINT owned_message_joint_probe").await.map_err(|e|e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && matches!(
                    e.message(),
                    "thread_history_writer_binding_invalid"
                        | "thread_history_writer_source_mutation_refused"
                )
        })
    {
        return Err(
            "message joint control did not encounter its explicit registered refusal".into(),
        );
    }
    for guard in GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.messages DISABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    let n = tx.execute(sql, params).await.map_err(|e| e.to_string())?;
    for guard in GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.messages ENABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    for guard in GUARDS {
        let state:String=tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.messages'::regclass AND tgname=$1 AND NOT tgisinternal",&[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "message guard {guard} was not restored before natural COMMIT/product reader"
            ));
        }
    }
    if n == 0 {
        return Err("owned message corruption changed no row".into());
    }
    Ok(())
}
async fn tamper_owned_thread_identity(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    const NEW_GUARDS: [&str; 3] = [
        "threads_history_body_before_update",
        "threads_history_canonical_before",
        "threads_history_source_final",
    ];
    const OLD: &str = "threads_history_protect_identity_update";
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned registered Thread guard {guard} was not normally enabled"
            ));
        }
    }
    tx.batch_execute("SAVEPOINT owned_current_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_current_identity_probe; RELEASE SAVEPOINT owned_current_identity_probe").await.map_err(|e|e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && matches!(
                    e.message(),
                    "thread_history_state_binding_invalid"
                        | "thread_history_writer_binding_invalid"
                        | "thread_history_writer_source_mutation_refused"
                )
        })
    {
        return Err("ordinary current Thread identity DML was not explicitly refused".into());
    }
    // Suppress only these owned fixture events BEFORE corrupting DML. Re-enabling
    // at COMMIT cannot remove an already queued deferred event; none is bypassed.
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads DISABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.batch_execute("SAVEPOINT owned_original50_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let original = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_original50_identity_probe; RELEASE SAVEPOINT owned_original50_identity_probe").await.map_err(|e|e.to_string())?;
    if !original
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000" && e.message() == "thread_history_state_binding_invalid"
        })
    {
        return Err("original0050 single identity guard control lost its exact refusal".into());
    }
    tx.batch_execute(
        "ALTER TABLE public.threads DISABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    let changed = tx.execute(sql, params).await.map_err(|e| e.to_string())?;
    tx.batch_execute(
        "ALTER TABLE public.threads ENABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads ENABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned Thread guard {guard} was not restored before product entry"
            ));
        }
    }
    if changed == 0 {
        return Err("owned identity control changed no row".into());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn exact_original_binding_and_current_actor_are_required_before_effect() {
    fixture("rememberbindings",|f|async move {
        let request=f.capture(0).await?;
        let before=effects(&f.pool).await?;
        let call=f.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT args_hash,schema_hash,decision_id,capability_id FROM public.tool_calls JOIN public.tool_attempts USING(tool_call_id)",&[]).await.map_err(|e|e.to_string())?;
        let mutations:Vec<(String,String)>=vec![
            ("UPDATE public.users SET auth_generation=1".into(),"UPDATE public.users SET auth_generation=0".into()),
            ("DELETE FROM public.user_roles WHERE user_id='actor-a'".into(),"INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user')".into()),
            ("INSERT INTO public.revoked_access(email,revoked_by) VALUES('a@example.test','actor-b')".into(),"DELETE FROM public.revoked_access".into()),
            ("UPDATE public.runs SET actor_id='actor-b'".into(),"UPDATE public.runs SET actor_id='actor-a'".into()),
            ("UPDATE public.runs SET bot_id='bot-b'".into(),"UPDATE public.runs SET bot_id='bot-a'".into()),
            ("UPDATE public.threads SET tenant_id='tenant-b'".into(),"UPDATE public.threads SET tenant_id='tenant-a'".into()),
            ("UPDATE public.threads SET deployment_id='dep-b'".into(),"UPDATE public.threads SET deployment_id='dep-a'".into()),
            ("UPDATE public.tool_calls SET args_hash=repeat('f',64)".into(),format!("UPDATE public.tool_calls SET args_hash='{}'",call.get::<_,String>("args_hash"))),
            ("UPDATE public.tool_calls SET schema_hash=repeat('e',64)".into(),format!("UPDATE public.tool_calls SET schema_hash='{}'",call.get::<_,String>("schema_hash"))),
            ("UPDATE public.tool_calls SET decision_id='wrong-decision'".into(),format!("UPDATE public.tool_calls SET decision_id='{}'",call.get::<_,String>("decision_id"))),
            ("UPDATE public.tool_attempts SET capability_id='wrong-capability'".into(),format!("UPDATE public.tool_attempts SET capability_id='{}'",call.get::<_,String>("capability_id"))),
            ("UPDATE public.tool_calls SET catalog_generation=catalog_generation+1".into(),"UPDATE public.tool_calls SET catalog_generation=catalog_generation-1".into()),
            ("UPDATE public.tool_calls SET target_id='actor-b'".into(),"UPDATE public.tool_calls SET target_id='actor-a'".into()),
            ("UPDATE public.agent_profiles SET visibility='private',owner_user_id='actor-b' WHERE agent_id='bot-a'".into(),"UPDATE public.agent_profiles SET visibility='public',owner_user_id=NULL WHERE agent_id='bot-a'".into()),
            ("UPDATE public.agent_profiles SET deleted_at=clock_timestamp() WHERE agent_id='bot-a'".into(),"UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='bot-a'".into()),
        ];
        for (change,restore) in mutations {
            let corrupts_thread_identity = matches!(change.as_str(),
                "UPDATE public.threads SET tenant_id='tenant-b'"
                | "UPDATE public.threads SET deployment_id='dep-b'");
            if corrupts_thread_identity {f.tamper_thread_identity(&change).await?;} else {f.sql(&change).await?;}
            assert!(store(&f.pool).remember_from_tool(request.clone()).await.is_err(),"bad binding admitted");
            assert_eq!(effects(&f.pool).await?,before);
            if corrupts_thread_identity {f.tamper_thread_identity(&restore).await?;} else {f.sql(&restore).await?;}
        }
        // Keep the real run FK intact: create another owned run through the production entry.
        let mut foreign=f.begin.clone();
        foreign.command.run_id=RunId::new("foreign-run");
        foreign.command.thread_id=ThreadIdentity::new(&f.begin.deployment).mint_from_entropy([76;16]);
        f.directory.begin_thread_run(foreign).await.map_err(|e|e.to_string())?;
        for (change,restore) in [
            ("UPDATE public.tool_calls SET run_id='foreign-run'".to_owned(),format!("UPDATE public.tool_calls SET run_id='{}'",request.run().as_str())),
            ("UPDATE public.tool_attempts SET attempt_id='different-attempt'".to_owned(),format!("UPDATE public.tool_attempts SET attempt_id='{}'",request.attempt().as_str())),
        ] {
            f.sql(&change).await?;
            assert!(matches!(store(&f.pool).remember_from_tool(request.clone()).await,Err(MemoryError::Corrupt {..})));
            assert_eq!(effects(&f.pool).await?,before);f.sql(&restore).await?;
        }
        let other=f.capture(1).await?;
        let before=effects(&f.pool).await?;
        f.pool.get().await.map_err(|e|e.to_string())?.execute("UPDATE public.tool_attempts SET tool_call_id=$2,attempt_seq=1 WHERE attempt_id=$1",&[&request.attempt().as_str(),&other.call().as_str()]).await.map_err(|e|e.to_string())?;
        assert!(matches!(store(&f.pool).remember_from_tool(request.clone()).await,Err(MemoryError::Corrupt {..})));
        assert_eq!(effects(&f.pool).await?,before);
        f.pool.get().await.map_err(|e|e.to_string())?.execute("UPDATE public.tool_attempts SET tool_call_id=$2,attempt_seq=0 WHERE attempt_id=$1",&[&request.attempt().as_str(),&request.call().as_str()]).await.map_err(|e|e.to_string())?;
        // Channel membership and installation are independently required, even with a direct member.
        f.tamper_thread_identity("UPDATE public.threads SET anchor_kind='channel',anchor_id='channel-a'").await?;
        f.sql("DELETE FROM public.channel_memberships").await?;
        assert_eq!(store(&f.pool).remember_from_tool(request.clone()).await,Err(MemoryError::NotVisible));
        f.sql("INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel-a','actor-a'); DELETE FROM public.channel_agents").await?;
        assert_eq!(store(&f.pool).remember_from_tool(request).await,Err(MemoryError::NotVisible));
        assert_eq!(effects(&f.pool).await?,before);Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn positive_receipt_fences_negative_or_late_outcome_and_journal_first_fences_producer() {
    fixture("rememberoutcome", |f| async move {
        let (_, request, mut draft) =
            support::pipeline(&f.pool, &f.auth(), f.invocation(0, "user"), None, true).await?;
        store(&f.pool)
            .remember_from_tool(request.clone())
            .await
            .map_err(|e| e.to_string())?;
        let journal =
            PostgresToolJournal::new(f.pool.clone(), KEY.to_vec()).map_err(|e| e.to_string())?;
        let before = effects(&f.pool).await?;
        let original_lifecycle = lifecycle(&f.pool).await?;
        draft.outcome.commit_state = CommitState::NotCommitted;
        assert_eq!(
            journal.record_outcome(&draft).await,
            Err(openbot_application::ToolPortError::Conflict)
        );
        assert_eq!(effects(&f.pool).await?, before);
        assert_eq!(lifecycle(&f.pool).await?, original_lifecycle);
        draft.outcome.commit_state = CommitState::Unknown;
        journal
            .record_outcome(&draft)
            .await
            .map_err(|e| e.to_string())?;
        let historical = store(&f.pool)
            .remember_from_tool(request)
            .await
            .map_err(|e| e.to_string())?;
        assert!(!historical.receipt_id.is_empty());
        f.terminal().await?;
        let before = effects(&f.pool).await?;
        let original_lifecycle = lifecycle(&f.pool).await?;
        draft.outcome.commit_state = CommitState::Committed;
        assert_eq!(
            journal.record_outcome(&draft).await,
            Err(openbot_application::ToolPortError::Conflict)
        );
        assert_eq!(effects(&f.pool).await?, before);
        assert_eq!(lifecycle(&f.pool).await?, original_lifecycle);
        Ok(())
    })
    .await;
    fixture("rememberjournalfirst", |f| async move {
        let (_, request, mut draft) =
            support::pipeline(&f.pool, &f.auth(), f.invocation(0, "user"), None, true).await?;
        draft.outcome.commit_state = CommitState::NotCommitted;
        PostgresToolJournal::new(f.pool.clone(), KEY.to_vec())
            .map_err(|e| e.to_string())?
            .record_outcome(&draft)
            .await
            .map_err(|e| e.to_string())?;
        let before = effects(&f.pool).await?;
        assert_eq!(
            store(&f.pool).remember_from_tool(request).await,
            Err(MemoryError::Conflict)
        );
        assert_eq!(effects(&f.pool).await?, before);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn producer_and_journal_use_the_actual_nonzero_attempt_sequence() {
    fixture("rememberattemptsequence", |f| async move {
        let (_, request, draft) =
            support::pipeline(&f.pool, &f.auth(), f.invocation(0, "user"), None, true).await?;
        // The same genuine capability-bound attempt is represented at a nonzero legacy position.
        // No new attempt, capability redemption or effect is fabricated by this fixture update.
        f.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .execute(
                "UPDATE public.tool_attempts SET attempt_seq=7 WHERE attempt_id=$1",
                &[&request.attempt().as_str()],
            )
            .await
            .map_err(|e| e.to_string())?;
        let committed = store(&f.pool)
            .remember_from_tool(request)
            .await
            .map_err(|e| e.to_string())?;
        let row = f
            .pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT attempt_seq FROM public.remember_effect_receipts WHERE receipt_id=$1",
                &[&committed.receipt_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(row.get::<_, i64>(0), 7);
        PostgresToolJournal::new(f.pool.clone(), KEY.to_vec())
            .map_err(|e| e.to_string())?
            .record_outcome(&draft)
            .await
            .map_err(|e| e.to_string())?;
        let row = f
            .pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT attempt_seq,status,commit_state FROM public.tool_attempts",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(row.get::<_, i64>(0), 7);
        assert_eq!(row.get::<_, String>(1), "reconciliation_required");
        assert_eq!(row.get::<_, String>(2), "unknown");
        f.terminal().await?;
        assert_eq!(f.read().await?.receipts[0].attempt_sequence, 7);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn oversized_legacy_attempt_or_decision_audit_identifier_refuses_before_business_effect() {
    for attempt in [false, true] {
        fixture(
            if attempt {
                "rememberlongattempt"
            } else {
                "rememberlongdecision"
            },
            |f| async move {
                let long = "x".repeat(257);
                let ids = support::JournalIds {
                    attempt: attempt.then(|| long.clone()),
                    decision: (!attempt).then(|| long.clone()),
                };
                let (result, request, _) = support::pipeline_with_journal_ids(
                    &f.pool,
                    &f.auth(),
                    f.invocation(0, "user"),
                    Some(store(&f.pool)),
                    false,
                    ids,
                )
                .await?;
                assert!(matches!(
                    result,
                    Err(AppError::ReconciliationRequired { .. })
                ));
                assert_eq!(
                    if attempt {
                        request.attempt().as_str()
                    } else {
                        request.decision().as_str()
                    },
                    long
                );
                assert!(matches!(
                    store(&f.pool).remember_from_tool(request).await,
                    Err(MemoryError::Corrupt { .. })
                ));
                let state = effects(&f.pool).await?;
                for field in ["memories", "events", "receipts"] {
                    assert!(state[field].as_array().unwrap().is_empty());
                }
                assert!(
                    !state["audit"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|a| a["event_type"] == "memory.effect_committed")
                );
                Ok(())
            },
        )
        .await;
    }
}
