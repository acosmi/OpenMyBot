//! Bounded history clearing on explicitly owned PostgreSQL 17.11.
//! Fixtures are synthetic; immutable prior schemas remain independently authored.
#![cfg(feature = "server-runtime")]
mod harness;

use openbot_application::{
    CorrectMemoryRequest, MemoryAdministration, RememberMemoryRequest, ThreadConversationRequest,
    ThreadDirectory, ThreadDirectoryError, ThreadEventSubscription, ThreadHistoryRequest,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId, ThreadId};
use openbot_contracts::memory::{
    CorrectMemory, MemoryKind, MemoryRecord, MemoryScope, MemorySensitivity, MemorySource,
    RememberMemory,
};
use openbot_domain::vault::SecretBytes;
use openbot_infra::db::thread_history_admission_schema as writer_schema;
use openbot_infra::db::{baseline, fresh, native, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::thread_history_authority::{
    PostgresThreadHistoryAuthority, ThreadHistoryClearProgress, ThreadHistoryStopClearError,
};
use serde_json::{Value, json};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_postgres::Client;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, String>;
const DEP: &str = "owned-clear-deployment";
const TENANT: &str = "owned-clear-tenant";
const ACTOR: &str = "clear-actor";
const BOT: &str = "clear-bot";
const INSERT_BATCH: &str = "INSERT INTO openbot_internal.thread_history_clear_batches(operation_id,batch_seq,threads_cleared,messages_cleared,run_events_cleared,tool_approvals_cleared,component_decisions_cleared,remote_interrupts_cleared,channel_sources_cleared,channels_cleared,memories_cleared,run_output_expired) VALUES($1,$2,$3,$4,0,0,0,0,0,0,$5,0)";
const INSERT_COMPLETION: &str = "INSERT INTO openbot_internal.thread_history_clear_completions(operation_id,deployment_id,tenant_id,thread_id,completion_schema,source,batches,threads_cleared,messages_cleared,run_events_cleared,tool_approvals_cleared,component_decisions_cleared,remote_interrupts_cleared,channel_sources_cleared,channels_cleared,memories_cleared,run_output_expired) SELECT q.operation_id,q.deployment_id,q.tenant_id,q.thread_id,1,'stop_clear',count(*),sum(b.threads_cleared),sum(b.messages_cleared),sum(b.run_events_cleared),sum(b.tool_approvals_cleared),sum(b.component_decisions_cleared),sum(b.remote_interrupts_cleared),sum(b.channel_sources_cleared),sum(b.channels_cleared),sum(b.memories_cleared),sum(b.run_output_expired) FROM openbot_internal.thread_history_clear_intents q JOIN openbot_internal.thread_history_clear_batches b USING(operation_id) WHERE q.operation_id=$1 GROUP BY q.operation_id,q.deployment_id,q.tenant_id,q.thread_id";
fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn require(value: bool, reason: &'static str) -> TestResult {
    if value {
        Ok(())
    } else {
        Err(reason.to_owned())
    }
}
fn thread(index: u64) -> ThreadId {
    let mut entropy = [0u8; 16];
    entropy[8..].copy_from_slice(&index.to_be_bytes());
    ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(120)
}
fn receipt(case: &str, detail: &str) {
    println!("THREAD_HISTORY_CLEAR id={case} {detail}");
}
async fn close_pool(p: pool::DatabasePool) -> TestResult {
    let observations = p.connection_observations();
    p.close();
    for observation in observations {
        require(
            observation
                .wait_for_destruction_before(Instant::now() + Duration::from_secs(10))
                .await
                .map_err(text)?
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
    .expect("owned prerequisite");
    harness::with_temp_database(&admin,tag,|config|async move {
        require(config.dbname.starts_with("openbot_it_"),"owned database name missing")?;
        let config=config.with_max_pool_size(8); let p=pool::connect(&config).await.map_err(text)?;
        let prerequisite=async {
            let c=p.get().await.map_err(text)?;
            let r=c.query_one("SELECT current_setting('server_version_num')::int,current_setting('server_encoding'),current_setting('block_size')::int",&[]).await.map_err(text)?;
            require(r.get::<_,i32>(0)==170011&&r.get::<_,String>(1)=="UTF8"&&r.get::<_,i32>(2)==8192,"frozen PG17.11 prerequisites differ")
        }.await;
        let result=match prerequisite { Ok(())=>body(p.clone(),config).await,Err(e)=>Err(e) };
        result.and(close_pool(p).await)
    }).await;
}
async fn initialize(p: &pool::DatabasePool, prior: i32) -> TestResult {
    let mut c = p.get().await.map_err(text)?;
    if prior == 52 {
        require(
            fresh::apply(&mut c).await.map_err(text)?
                == fresh::FreshApplyOutcome::Applied(native::ApplyOutcome::Applied),
            "fresh52 did not apply",
        )?;
    } else {
        require(prior == 51, "unregistered historical prefix")?;
        baseline::apply(&c).await.map_err(text)?;
        require(
            native::apply_through(&mut c, 51).await.map_err(text)? == native::ApplyOutcome::Applied,
            "explicit51 did not apply",
        )?;
    }
    Ok(())
}
async fn seed(p: &pool::DatabasePool) -> TestResult {
    initialize(p, 52).await?;
    let c = p.get().await.map_err(text)?;
    c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('clear-actor','clear-actor@example.test',7),('clear-other','clear-other@example.test',7); INSERT INTO public.user_roles(user_id,role) VALUES('clear-actor','user'),('clear-other','user'); INSERT INTO public.agents(id,name,type,configuration) VALUES('clear-bot','Owned clear bot','built_in','{}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('clear-bot','clear-actor','Owned clear bot','','clear','public');").await.map_err(text)
}
async fn insert_thread(c: &Client, t: &ThreadId, channel: Option<&str>) -> TestResult {
    let kind = if channel.is_some() {
        "channel"
    } else {
        "direct_bot"
    };
    let anchor = channel.unwrap_or(BOT);
    c.execute("INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,next_message_seq,next_event_seq,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'Owned title',0,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')",&[&t.as_str(),&TENANT,&DEP,&ACTOR,&kind,&anchor]).await.map_err(text)?;
    c.execute(
        "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,$2)",
        &[&t.as_str(), &ACTOR],
    )
    .await
    .map_err(text)?;
    Ok(())
}
async fn terminal_thread(p: &pool::DatabasePool, index: u64, rr: bool) -> TestResult<ThreadId> {
    let t = thread(index);
    let run = format!("clear-run-{index}");
    let c = p.get().await.map_err(text)?;
    insert_thread(&c, &t, None).await?;
    let status = if rr {
        "reconciliation_required"
    } else {
        "completed"
    };
    let code: Option<&str> = rr.then_some("journal_commit_unknown");
    let payload = if let Some(code) = code {
        json!({"status":status,"errorCode":code})
    } else {
        json!({"status":status})
    };
    c.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(text)?;
    c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,terminal_event_seq,error_code,created_at,started_at,finished_at) VALUES($1,$2,$3,$4,$5,$6,1,3,2,$7,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z','2026-09-01T00:01:00Z')",&[&run,&t.as_str(),&BOT,&ACTOR,&rr,&status,&code]).await.map_err(text)?;
    c.execute("INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at) VALUES($1,$2,0,'user','{\"text\":\"Owned body\"}','Owned body',$3,$4,'2026-09-01T00:00:00Z')",&[&format!("clear-message-{index}"),&t.as_str(),&run,&ACTOR]).await.map_err(text)?;
    for (seq, kind, body, terminal) in [
        (0i64, "started", json!({"owned":"input"}), false),
        (
            1,
            "semantic_chunk",
            json!({"channel":"text","delta":"owned reply","secret":"extra"}),
            false,
        ),
        (2, status, payload, true),
    ] {
        c.execute("INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal,created_at) VALUES($1,$2,$3,$2,$4,$5,$6,'2026-09-01T00:01:00Z')",&[&run,&seq,&t.as_str(),&kind,&body,&terminal]).await.map_err(text)?;
    }
    c.batch_execute("SET CONSTRAINTS ALL IMMEDIATE; COMMIT")
        .await
        .map_err(text)?;
    Ok(t)
}
async fn close_history(c: &Client, t: &ThreadId) -> TestResult<String> {
    let op = Uuid::now_v7().to_string();
    let request = Uuid::now_v7().to_string();
    c.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(text)?;
    let at: time::OffsetDateTime = c
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(text)?
        .get(0);
    c.execute("INSERT INTO openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at) SELECT deployment_id,tenant_id,thread_id,1,'stop_clear',$2,$3,$4,7,anchor_kind,anchor_id,thread_created_at,$5 FROM openbot_internal.thread_history_heads WHERE thread_id=$1",&[&t.as_str(),&op,&request,&ACTOR,&at]).await.map_err(text)?;
    c.execute("UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id=$2,closure_request_id=$3,closure_actor_id=$4,closure_auth_generation=7,closed_at=$5 WHERE thread_id=$1",&[&t.as_str(),&op,&request,&ACTOR,&at]).await.map_err(text)?;
    c.batch_execute("SET CONSTRAINTS ALL IMMEDIATE; COMMIT")
        .await
        .map_err(text)?;
    Ok(op)
}
fn authority(p: &pool::DatabasePool) -> TestResult<Arc<PostgresThreadHistoryAuthority>> {
    let a = Arc::new(
        PostgresThreadHistoryAuthority::new(
            p.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )
        .map_err(text)?,
    );
    a.enroll_clear_audit_checkpoint_key(SecretBytes::new(vec![0x41; 32]))
        .map_err(text)?;
    Ok(a)
}
async fn completed(a: &Arc<PostgresThreadHistoryAuthority>, t: &ThreadId, op: &str) -> TestResult {
    require(
        matches!(a.clear_closed_history_before(t.as_str(),deadline()).await.map_err(text)?,ThreadHistoryClearProgress::Completed{operation_id} if operation_id==op),
        "clear did not acknowledge exact completion",
    )
}
async fn batch(
    c: &Client,
    op: &str,
    seq: i64,
    threads: i64,
    messages: i64,
    memories: i64,
) -> TestResult {
    c.execute(INSERT_BATCH, &[&op, &seq, &threads, &messages, &memories])
        .await
        .map_err(text)?;
    Ok(())
}
async fn rejected(c: &Client, sql: &str, code: &str, message: Option<&str>) -> TestResult {
    c.batch_execute("SAVEPOINT owned_refusal")
        .await
        .map_err(text)?;
    let result = c.batch_execute(sql).await;
    c.batch_execute("ROLLBACK TO SAVEPOINT owned_refusal; RELEASE SAVEPOINT owned_refusal")
        .await
        .map_err(text)?;
    let e = result.err().ok_or("negative SQL unexpectedly accepted")?;
    require(
        e.as_db_error()
            .is_some_and(|d| d.code().code() == code && message.is_none_or(|m| d.message() == m)),
        "negative SQL had wrong native cause",
    )
}
async fn snapshot(c: &Client, tables: &[&str]) -> TestResult<Value> {
    let mut map = serde_json::Map::new();
    for table in tables {
        let v:Value=c.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb) FROM {table} x"),&[]).await.map_err(text)?.get(0);
        map.insert((*table).to_owned(), v);
    }
    Ok(Value::Object(map))
}
fn remember_request(scope: MemoryScope) -> RememberMemoryRequest {
    RememberMemoryRequest {
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(ACTOR),
        deployment: DeploymentId::new(DEP),
        auth_generation: AuthGeneration::new(7),
        input: RememberMemory {
            memory_kind: MemoryKind::Preference,
            scope,
            content: "Owned independent preference".into(),
            tags: vec![],
            sensitivity: MemorySensitivity::Normal,
            source: None,
            expires_at: None,
        },
    }
}
fn correct_request(record: &MemoryRecord) -> CorrectMemoryRequest {
    CorrectMemoryRequest {
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(ACTOR),
        deployment: DeploymentId::new(DEP),
        auth_generation: AuthGeneration::new(7),
        memory_id: record.memory_id.clone(),
        correction: CorrectMemory {
            content: "Owned corrected preference".into(),
            tags: vec![],
            sensitivity: MemorySensitivity::Normal,
            expires_at: None,
        },
    }
}
async fn insert_preference(c: &Client, t: &ThreadId, id: &str, scope: &str) -> TestResult {
    let scope_id: Option<&str> = match scope {
        "user" => None,
        "bot" => Some(BOT),
        _ => Some(t.as_str()),
    };
    c.execute("INSERT INTO public.memories(memory_id,tenant_id,owner_user_id,scope_kind,scope_id,memory_kind,content,sensitivity,origin,created_by,status) VALUES($1,$2,$3,$4,$5,'preference','Owned raw preference','normal','user_action',$3,'active')",&[&id,&TENANT,&ACTOR,&scope,&scope_id]).await.map_err(text)?;
    Ok(())
}
async fn auxiliary_bodies(c: &Client, t: &ThreadId) -> TestResult {
    use openbot_contracts::components::{
        ASK_APPROVAL_COMPONENT_DESCRIPTION, ASK_APPROVAL_COMPONENT_NAME,
        ASK_APPROVAL_COMPONENT_TITLE,
    };
    c.execute("INSERT INTO public.components(name,title,kind,draft_description,published_description,published,published_at,updated_by,created_at,updated_at) VALUES($1,$2,'decision',$3,$3,true,clock_timestamp(),'owned-test',clock_timestamp(),clock_timestamp())",&[&ASK_APPROVAL_COMPONENT_NAME,&ASK_APPROVAL_COMPONENT_TITLE,&ASK_APPROVAL_COMPONENT_DESCRIPTION]).await.map_err(text)?;
    c.execute("WITH stamp AS(SELECT clock_timestamp() at) INSERT INTO public.tool_approvals(approval_id,tool_call_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,auth_generation,tool_name,args_hash,target_kind,target_id,effect,approval_class,computer_generation,catalog_generation,policy_version,arguments_summary,change_summary,state,requested_at,expires_at,created_at,updated_at) SELECT 'clear-pending-approval','clear-pending-call',$1,$2,$3,'clear-run-410301',$4,$5,7,'computer.write',repeat('a',64),'thread',$3,'write','every_call',1,1,repeat('b',64),'{\"summary\":\"Owned private tool arguments\"}','{\"summary\":\"Owned private change\"}','pending',at,at+interval '1 hour',at,at FROM stamp",&[&DEP,&TENANT,&t.as_str(),&ACTOR,&BOT]).await.map_err(text)?;
    c.execute("WITH stamp AS(SELECT clock_timestamp() at) INSERT INTO public.component_human_decisions(decision_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,auth_generation,provider_call_id,component_name,arguments,arguments_hash,state,answer,requested_at,expires_at,resolved_at,resolved_by,created_at,updated_at) SELECT 'clear-answered-component',$1,$2,$3,'clear-run-410301',$4,$5,7,'clear-provider-decision','askApproval','{\"title\":\"Owned private question\"}',repeat('a',64),'answered','{\"decision\":\"approved\",\"note\":\"Owned private answer\"}',at,at+interval '1 hour',at,$4,at,at FROM stamp",&[&DEP,&TENANT,&t.as_str(),&ACTOR,&BOT]).await.map_err(text)?;
    c.execute("WITH stamp AS(SELECT clock_timestamp() at) INSERT INTO public.remote_agent_interrupts(request_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,auth_generation,protocol_run_id,interrupt_id,position,descriptor,state,response_status,response_payload,requested_at,expires_at,resolved_at,resolved_by,created_at,updated_at) SELECT $1,$2,$3,$4,'clear-run-410301',$5,$6,7,'clear-protocol-run','clear-interrupt',0,'{\"id\":\"clear-interrupt\",\"reason\":\"human_input\",\"message\":\"Owned private descriptor\"}','resolved','resolved','{\"answer\":\"Owned private response\"}',at,at+interval '1 hour',at,$5,at,at FROM stamp",&[&Uuid::now_v7().to_string(),&DEP,&TENANT,&t.as_str(),&ACTOR,&BOT]).await.map_err(text)?;
    Ok(())
}

async fn assert_held_lock(c: &Client, pid: i32, relation: &str) -> TestResult {
    require(c.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation=$2::regclass AND granted)",&[&pid,&relation]).await.map_err(text)?.get::<_,bool>(0),"owned locker did not hold actual relation lock")
}

// This finite probe retains only the clearing objects and the original C01 guards.
// Raw rows, including duplicate dependency edges, are compared without deparsing.
const CLEAR_CATALOG: &str = r#"
WITH clear_tables AS (
 SELECT c.* FROM pg_catalog.pg_class c WHERE c.oid IN
 ('openbot_internal.thread_history_clear_batches'::regclass,
  'openbot_internal.thread_history_clear_completions'::regclass)
), clear_toast AS (
 SELECT c.* FROM pg_catalog.pg_class c WHERE c.oid IN
 (SELECT reltoastrelid FROM clear_tables)
), clear_indexes AS (
 SELECT i.* FROM pg_catalog.pg_index i WHERE i.indrelid IN
 (SELECT oid FROM clear_tables UNION ALL SELECT oid FROM clear_toast)
), clear_classes AS (
 SELECT oid FROM clear_tables UNION SELECT oid FROM clear_toast
 UNION SELECT indexrelid FROM clear_indexes
), clear_types AS (
 SELECT t.* FROM pg_catalog.pg_type t WHERE t.oid IN
 (SELECT reltype FROM clear_tables UNION ALL
  SELECT t.typarray FROM clear_tables c JOIN pg_catalog.pg_type t ON t.oid=c.reltype)
), clear_constraints AS (
 SELECT c.* FROM pg_catalog.pg_constraint c WHERE c.conrelid IN
 (SELECT oid FROM clear_tables)
), clear_triggers AS (
 SELECT t.* FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN
 (SELECT oid FROM clear_tables UNION ALL SELECT 'public.memories'::regclass)
 OR t.tgconstraint IN(SELECT oid FROM clear_constraints WHERE contype='f')
), clear_defaults AS (
 SELECT d.* FROM pg_catalog.pg_attrdef d WHERE d.adrelid IN
 (SELECT oid FROM clear_tables)
), clear_functions AS (
 SELECT f.* FROM pg_catalog.pg_proc f WHERE f.pronamespace='openbot_internal'::regnamespace
 AND (f.proname LIKE '%thread_history_clear%' OR f.proname='guard_thread_history_memory_body')
), addresses(classid,objid) AS (
 SELECT 'pg_catalog.pg_class'::regclass,oid FROM clear_classes
 UNION ALL SELECT 'pg_catalog.pg_type'::regclass,oid FROM clear_types
 UNION ALL SELECT 'pg_catalog.pg_constraint'::regclass,oid FROM clear_constraints
 UNION ALL SELECT 'pg_catalog.pg_trigger'::regclass,oid FROM clear_triggers
 UNION ALL SELECT 'pg_catalog.pg_attrdef'::regclass,oid FROM clear_defaults
 UNION ALL SELECT 'pg_catalog.pg_proc'::regclass,oid FROM clear_functions
)
SELECT jsonb_build_object(
 'relations',(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_catalog.pg_class c
  WHERE c.oid IN(SELECT oid FROM clear_classes UNION ALL SELECT 'public.memories'::regclass)),
 'types',(SELECT jsonb_agg(to_jsonb(t) ORDER BY oid) FROM clear_types t),
 'attributes',(SELECT jsonb_agg(to_jsonb(a) ORDER BY attrelid,attnum)
  FROM pg_catalog.pg_attribute a WHERE a.attnum>0 AND a.attrelid IN(SELECT oid FROM clear_classes)),
 'indexes',(SELECT jsonb_agg(to_jsonb(i) ORDER BY indexrelid) FROM clear_indexes i),
 'constraints',(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM clear_constraints c),
 'defaults',(SELECT jsonb_agg(to_jsonb(d) ORDER BY oid) FROM clear_defaults d),
 'triggers',(SELECT jsonb_agg(to_jsonb(t) ORDER BY oid) FROM clear_triggers t),
 'functions',(SELECT jsonb_agg(to_jsonb(f) ORDER BY oid) FROM clear_functions f),
 'dependencies',(SELECT coalesce(jsonb_agg(to_jsonb(d)
  ORDER BY classid,objid,objsubid,refclassid,refobjid,refobjsubid,deptype),'[]'::jsonb)
  FROM pg_catalog.pg_depend d WHERE EXISTS(SELECT 1 FROM addresses a
   WHERE (a.classid=d.classid AND a.objid=d.objid) OR (a.classid=d.refclassid AND a.objid=d.refobjid))),
 'sharedDependencies',(SELECT coalesce(jsonb_agg(to_jsonb(d)
  ORDER BY classid,objid,objsubid,refclassid,refobjid,deptype),'[]'::jsonb)
  FROM pg_catalog.pg_shdepend d WHERE d.dbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
  AND EXISTS(SELECT 1 FROM addresses a WHERE a.classid=d.classid AND a.objid=d.objid)))
"#;

async fn clear_catalog_fault(c: &Client, fault: &str, exact_row: bool) -> TestResult {
    let pristine: Value = c.query_one(CLEAR_CATALOG, &[]).await.map_err(text)?.get(0);
    c.batch_execute("BEGIN").await.map_err(text)?;
    let result = async {
        if exact_row {
            require(
                c.execute(fault, &[]).await.map_err(text)? == 1,
                "raw clear catalog fault did not change exactly one row",
            )?;
        } else {
            c.batch_execute(fault).await.map_err(text)?;
        }
        let before_fault: Value = c.query_one(CLEAR_CATALOG, &[]).await.map_err(text)?.get(0);
        require(
            before_fault != pristine,
            "clear catalog fault did not change the raw probe",
        )?;
        let refused = matches!(
            writer_schema::verify(c).await,
            Err(openbot_infra::db::InfraError::RepositoryInvariant {
                code: "thread_history_writer_schema_invalid"
            })
        );
        let after_fault: Value = c.query_one(CLEAR_CATALOG, &[]).await.map_err(text)?.get(0);
        require(
            refused && before_fault == after_fault,
            "current52 observer accepted or repaired exact clear graph tamper",
        )
    }
    .await;
    // Even a failed mutation or assertion cannot commit a system-catalog change.
    c.batch_execute("ROLLBACK").await.map_err(text)?;
    result?;
    let restored: Value = c.query_one(CLEAR_CATALOG, &[]).await.map_err(text)?.get(0);
    require(
        restored == pristine,
        "clear catalog rollback changed original raw facts",
    )?;
    writer_schema::verify(c).await.map_err(text)
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_fresh52_upgrade51_complete_clear_schema_and_zero_ddl_replay() {
    for prior in [51, 52] {
        owned(&format!("clear52schema{prior}"), move |p, _| async move {
            initialize(&p, prior).await?;
            let mut c = p.get().await.map_err(text)?;
            let old: Value = c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM openbot_internal.schema_migrations m WHERE version<=51", &[]).await.map_err(text)?.get(0);
            if prior == 51 {
                require(native::apply(&mut c).await.map_err(text)? == native::ApplyOutcome::Applied,
                    "51 to52 upgrade not applied")?;
            }
            native::validate_current(&c).await.map_err(text)?;
            writer_schema::verify(&c).await.map_err(text)?;
            let retained: Value = c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM openbot_internal.schema_migrations m WHERE version<=51", &[]).await.map_err(text)?.get(0);
            require(old == retained, "upgrade changed prior migration evidence")?;
            let row = c.query_one("SELECT count(*),max(version),(SELECT count(*) FROM openbot_internal.thread_history_clear_batches),(SELECT count(*) FROM openbot_internal.thread_history_clear_completions) FROM openbot_internal.schema_migrations", &[]).await.map_err(text)?;
            require(row.get::<_, i64>(0) == 40 && row.get::<_, i32>(1) == 52 && row.get::<_, i64>(2) == 0 && row.get::<_, i64>(3) == 0,
                "52 prefix not exact or invented clearing facts")?;
            for fault in [
                "ALTER TABLE openbot_internal.thread_history_clear_batches ALTER COLUMN xact_id DROP DEFAULT",
                "ALTER TABLE openbot_internal.thread_history_clear_batches DISABLE TRIGGER thread_history_clear_batches_guard",
                "ALTER TABLE openbot_internal.thread_history_clear_completions DISABLE TRIGGER thread_history_clear_completions_require_final",
                "ALTER TABLE public.memories DISABLE TRIGGER memories_history_body_before",
                "ALTER FUNCTION openbot_internal.thread_history_clear_readers_quiescent(text) SECURITY DEFINER",
                "GRANT SELECT ON openbot_internal.thread_history_clear_completions TO PUBLIC",
            ] {
                clear_catalog_fault(&c, fault, false).await?;
            }
            for (name, other) in [
                ("thread_history_clear_batches", "thread_history_clear_completions"),
                ("thread_history_clear_completions", "thread_history_clear_batches"),
            ] {
                // All names are this fixed pair in an owned temporary database.
                let relation = format!("'openbot_internal.{name}'::regclass");
                let peer = format!("'openbot_internal.{other}'::regclass");
                let rowtype = format!("(SELECT reltype FROM pg_catalog.pg_class WHERE oid={relation})");
                let arraytype = format!("(SELECT typarray FROM pg_catalog.pg_type WHERE oid={rowtype})");
                let row_edge = format!("classid='pg_catalog.pg_type'::regclass AND objid={rowtype} AND objsubid=0 AND refclassid='pg_catalog.pg_class'::regclass AND refobjid={relation} AND refobjsubid=0 AND deptype='i'");
                let faults = [
                    format!("UPDATE pg_catalog.pg_type SET typrelid={peer} WHERE oid={rowtype}"),
                    format!("UPDATE pg_catalog.pg_type SET typelem=(SELECT reltype FROM pg_catalog.pg_class WHERE oid={peer}) WHERE oid={arraytype}"),
                    format!("UPDATE pg_catalog.pg_type SET typinput='pg_catalog.record_in'::regproc WHERE oid={arraytype}"),
                    format!("UPDATE pg_catalog.pg_attribute SET attstorage='p' WHERE attrelid={relation} AND attname='operation_id' AND attnum=1 AND NOT attisdropped"),
                    format!("UPDATE pg_catalog.pg_class SET reloptions=ARRAY['autovacuum_enabled=false'] WHERE oid=(SELECT reltoastrelid FROM pg_catalog.pg_class WHERE oid={relation})"),
                    format!("UPDATE pg_catalog.pg_index SET indisvalid=false WHERE indrelid=(SELECT reltoastrelid FROM pg_catalog.pg_class WHERE oid={relation})"),
                    format!("DELETE FROM pg_catalog.pg_depend WHERE {row_edge}"),
                    format!("UPDATE pg_catalog.pg_depend SET deptype='n' WHERE classid='pg_catalog.pg_type'::regclass AND objid={arraytype} AND objsubid=0 AND refclassid='pg_catalog.pg_type'::regclass AND refobjid={rowtype} AND refobjsubid=0 AND deptype='i'"),
                    format!("INSERT INTO pg_catalog.pg_depend(classid,objid,objsubid,refclassid,refobjid,refobjsubid,deptype) SELECT classid,objid,objsubid,refclassid,refobjid,refobjsubid,deptype FROM pg_catalog.pg_depend WHERE {row_edge}"),
                ];
                for (index, fault) in faults.into_iter().enumerate() {
                    clear_catalog_fault(&c, &fault, true).await.map_err(|e| format!("{name} raw fault {}: {e}", index + 1))?;
                }
            }
            // The original full writer verification also requires the other 22
            // helpers to remain plpgsql; only this helper uses pinned SQL14.
            let sql_language = c.query_one("SELECT p.prolang=14,NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_proc'::regclass AND d.objid=p.oid AND d.refclassid='pg_catalog.pg_language'::regclass AND d.refobjid=14) FROM pg_catalog.pg_proc p WHERE p.oid='openbot_internal.thread_history_clear_batch_active(text)'::regprocedure", &[]).await.map_err(text)?;
            require(sql_language.get::<_, bool>(0) && sql_language.get::<_, bool>(1),
                "batch_active is not the legal pinned SQL14 binding without an ordinary language edge")?;
            for fault in [
                "UPDATE pg_catalog.pg_proc SET prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql') WHERE oid='openbot_internal.thread_history_clear_batch_active(text)'::regprocedure",
                "INSERT INTO pg_catalog.pg_depend(classid,objid,objsubid,refclassid,refobjid,refobjsubid,deptype) SELECT 'pg_catalog.pg_proc'::regclass,p.oid,0,'pg_catalog.pg_language'::regclass,14,0,'n' FROM pg_catalog.pg_proc p WHERE p.oid='openbot_internal.thread_history_clear_batch_active(text)'::regprocedure",
            ] {
                clear_catalog_fault(&c, fault, true).await.map_err(|e| format!("batch_active language binding: {e}"))?;
            }
            c.batch_execute("CREATE TABLE openbot_internal.owned_clear_ddl(tag text); CREATE FUNCTION openbot_internal.owned_clear_ddl_probe() RETURNS event_trigger LANGUAGE plpgsql AS $$BEGIN INSERT INTO openbot_internal.owned_clear_ddl SELECT command_tag FROM pg_event_trigger_ddl_commands();END$$; CREATE EVENT TRIGGER owned_clear_ddl_probe ON ddl_command_end EXECUTE FUNCTION openbot_internal.owned_clear_ddl_probe(); TRUNCATE openbot_internal.owned_clear_ddl;").await.map_err(text)?;
            require(native::apply(&mut c).await.map_err(text)? == native::ApplyOutcome::AlreadyApplied,
                "exact52 replay outcome differs")?;
            require(c.query_one("SELECT count(*) FROM openbot_internal.owned_clear_ddl", &[]).await.map_err(text)?.get::<_, i64>(0) == 0,
                "exact52 replay emitted DDL")?;
            receipt("C01", "prior ledger retained; exact52; raw catalog faults refused and rolled back; zero DDL");
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_narrow_window_admits_only_fixed_tombstones_inside_current_xact_batch()
{
    owned("clear52narrow",|p,_|async move {
        seed(&p).await?;let t=terminal_thread(&p,410201,false).await?;
        let store=PostgresMemoryAdministration::new(p.clone());
        let record=store.remember(remember_request(MemoryScope::Thread{thread_id:t.clone()})).await.map_err(text)?;
        let c=p.get().await.map_err(text)?;
        let before_open=snapshot(&c,&["public.memories","public.memory_events"]).await?;
        let locker=p.get().await.map_err(text)?;locker.batch_execute("BEGIN").await.map_err(text)?;
        locker.query_one("SELECT thread_id FROM openbot_internal.thread_history_heads WHERE thread_id=$1 FOR UPDATE",&[&t.as_str()]).await.map_err(text)?;
        let pid:i32=locker.query_one("SELECT pg_backend_pid()",&[]).await.map_err(text)?.get(0);
        assert_held_lock(&c,pid,"openbot_internal.thread_history_heads").await?;
        require(matches!(store.remember(remember_request(MemoryScope::Thread{thread_id:t.clone()})).await,Err(openbot_application::MemoryAdministrationError::Unavailable)),"source=None remember did not preserve H NOWAIT contention")?;
        require(matches!(store.correct(correct_request(&record)).await,Err(openbot_application::MemoryAdministrationError::Unavailable)),"Thread correction did not preserve H NOWAIT contention")?;
        require(snapshot(&c,&["public.memories","public.memory_events"]).await?==before_open,"H contention changed source=None Thread memory")?;
        locker.batch_execute("ROLLBACK").await.map_err(text)?;drop(locker);
        let other=terminal_thread(&p,410202,false).await?;let other_op=close_history(&c,&other).await?;
        let op=close_history(&c,&t).await?;
        let before=snapshot(&c,&["public.memories","public.memory_events"]).await?;
        require(store.remember(remember_request(MemoryScope::Thread{thread_id:t.clone()})).await.is_err(),"source=None Thread remember wrote after close")?;
        require(store.correct(correct_request(&record)).await.is_err(),"Thread CorrectMemory wrote after close")?;
        require(snapshot(&c,&["public.memories","public.memory_events"]).await?==before,"closed source=None remember/correct changed rows")?;
        c.batch_execute("BEGIN").await.map_err(text)?;
        let fixed=format!("UPDATE public.messages SET content='{{\"text\":\"\",\"retained\":false}}',search_text='' WHERE thread_id='{}'",t.as_str());
        rejected(&c,&fixed,"55000",Some("thread_history_writer_closed")).await?;
        rejected(&c,&format!("UPDATE public.memories SET content='new' WHERE scope_id='{}'",t.as_str()),"55000",Some("thread_history_writer_closed")).await?;
        batch(&c,&op,1,0,0,0).await?;
        require(op!=other_op,"owned operation identities collided")?;
        rejected(&c,&format!("UPDATE public.messages SET content='{{\"text\":\"\",\"retained\":false}}',search_text='' WHERE thread_id='{}'",other.as_str()),"55000",Some("thread_history_writer_closed")).await?;
        for bad in ["'{}'::jsonb","'{\"text\":\"\"}'::jsonb","'{\"text\":\"\",\"retained\":false,\"extra\":1}'::jsonb"] {
            rejected(&c,&format!("UPDATE public.messages SET content={bad},search_text='' WHERE thread_id='{}'",t.as_str()),"55000",Some("thread_history_writer_closed")).await?;
        }
        c.batch_execute(&fixed).await.map_err(text)?;
        c.execute("UPDATE public.memories SET status='deleted',content=NULL WHERE memory_id=$1",&[&record.memory_id.as_str()]).await.map_err(text)?;
        rejected(&c,&format!("UPDATE public.memories SET scope_kind='user',scope_id=NULL WHERE memory_id='{}'",record.memory_id.as_str()),"23514",None).await?;
        c.batch_execute("ROLLBACK").await.map_err(text)?;
        require(snapshot(&c,&["public.memories","public.memory_events"]).await?==before,"rolled-back current batch changed memory")?;
        c.batch_execute("BEGIN").await.map_err(text)?;batch(&c,&op,1,0,0,0).await?;c.batch_execute("COMMIT").await.map_err(text)?;
        c.batch_execute("BEGIN").await.map_err(text)?;rejected(&c,&fixed,"55000",Some("thread_history_writer_closed")).await?;c.batch_execute("ROLLBACK").await.map_err(text)?;
        receipt("C02","fixed current xact only; prior xact and source=None closed writes refused");Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_direct_thread_clear_keeps_ids_seq_fk_rr_and_receipts() {
    owned("clear52identity",|p,_|async move {
        seed(&p).await?;let t=terminal_thread(&p,410301,true).await?;let c=p.get().await.map_err(text)?;
        c.execute("INSERT INTO public.memories(memory_id,tenant_id,owner_user_id,scope_kind,scope_id,memory_kind,content,sensitivity,origin,created_by,status,source_thread_id,source_message_id,source_run_id) VALUES('owned-thread-memory',$1,$2,'thread',$3,'fact','Owned sourced fact','normal','user_action',$2,'active',$3,'clear-message-410301','clear-run-410301')",&[&TENANT,&ACTOR,&t.as_str()]).await.map_err(text)?;
        c.batch_execute("BEGIN").await.map_err(text)?;
        c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,terminal_event_seq,error_code,started_at,finished_at) VALUES('clear-imported-terminal',$1,$2,$3,false,'failed',1,1,0,'historical_imported_failure',clock_timestamp(),clock_timestamp())",&[&t.as_str(),&BOT,&ACTOR]).await.map_err(text)?;
        c.execute("INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal) VALUES('clear-imported-terminal',0,$1,3,'failed','{\"legacyBody\":\"Owned imported private body\"}',true)",&[&t.as_str()]).await.map_err(text)?;
        c.batch_execute("SET CONSTRAINTS ALL IMMEDIATE; COMMIT").await.map_err(text)?;
        auxiliary_bodies(&c,&t).await?;
        c.execute("INSERT INTO public.remember_effect_receipts(receipt_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,auth_generation,tool_call_id,call_seq,attempt_id,attempt_seq,decision_id,capability_id,args_hash,schema_hash,catalog_generation,target_kind,target_id,memory_id,memory_event_seq,audit_event_id,recorded_at) VALUES($1,$2,$3,$4,'clear-run-410301',$5,$6,7,'owned-call',0,'owned-attempt',0,'owned-decision','memory.remember',repeat('a',64),repeat('b',64),1,'memory_thread',$4,$7,0,$8,clock_timestamp())",&[&Uuid::now_v7().to_string(),&DEP,&TENANT,&t.as_str(),&ACTOR,&BOT,&Uuid::now_v7().to_string(),&Uuid::now_v7().to_string()]).await.map_err(text)?;
        let before=snapshot(&c,&["public.runs","public.thread_run_occupancy","public.remember_effect_receipts"]).await?;
        let auxiliary_ids:Value=c.query_one("SELECT jsonb_build_object('approval',(SELECT to_jsonb(a)-ARRAY['arguments_summary','change_summary','state','decided_at','decided_by'] FROM public.tool_approvals a WHERE approval_id='clear-pending-approval'),'component',(SELECT to_jsonb(d)-ARRAY['arguments','answer'] FROM public.component_human_decisions d WHERE decision_id='clear-answered-component'),'interrupt',(SELECT to_jsonb(i)-ARRAY['descriptor','response_payload','state','resolved_by','resume_protocol_run_id'] FROM public.remote_agent_interrupts i WHERE interrupt_id='clear-interrupt'))",&[]).await.map_err(text)?.get(0);
        let identities:Value=c.query_one("SELECT jsonb_build_object('messages',(SELECT jsonb_agg(to_jsonb(x)-'content'-'search_text' ORDER BY seq) FROM public.messages x WHERE thread_id=$1),'events',(SELECT jsonb_agg(to_jsonb(x)-'payload' ORDER BY seq) FROM public.run_events x WHERE thread_id=$1))",&[&t.as_str()]).await.map_err(text)?.get(0);
        let op=close_history(&c,&t).await?;drop(c);completed(&authority(&p)?,&t,&op).await?;let c=p.get().await.map_err(text)?;
        require(snapshot(&c,&["public.runs","public.thread_run_occupancy","public.remember_effect_receipts"]).await?==before,"clear changed RR/occupancy/receipt metadata")?;
        let auxiliary_retained:Value=c.query_one("SELECT jsonb_build_object('approval',(SELECT to_jsonb(a)-ARRAY['arguments_summary','change_summary','state','decided_at','decided_by'] FROM public.tool_approvals a WHERE approval_id='clear-pending-approval'),'component',(SELECT to_jsonb(d)-ARRAY['arguments','answer'] FROM public.component_human_decisions d WHERE decision_id='clear-answered-component'),'interrupt',(SELECT to_jsonb(i)-ARRAY['descriptor','response_payload','state','resolved_by','resume_protocol_run_id'] FROM public.remote_agent_interrupts i WHERE interrupt_id='clear-interrupt'))",&[]).await.map_err(text)?.get(0);
        require(auxiliary_retained==auxiliary_ids,"clear changed auxiliary permanent ID/binding/hash/sequence/time fields")?;
        let fixed_aux=c.query_one("SELECT (SELECT arguments_summary IS NULL AND change_summary IS NULL AND state='cancelled' AND decided_by IS NULL AND decided_at IS NOT NULL FROM public.tool_approvals WHERE approval_id='clear-pending-approval'),(SELECT arguments='{\"retained\":false}'::jsonb AND answer='{\"retained\":false}'::jsonb AND state='answered' FROM public.component_human_decisions WHERE decision_id='clear-answered-component'),(SELECT descriptor IS NULL AND response_payload IS NULL AND state='retired' AND resolved_by IS NULL FROM public.remote_agent_interrupts WHERE interrupt_id='clear-interrupt'),(SELECT threads_cleared=1 AND messages_cleared=1 AND run_events_cleared=3 AND tool_approvals_cleared=1 AND component_decisions_cleared=1 AND remote_interrupts_cleared=1 AND memories_cleared=1 FROM openbot_internal.thread_history_clear_completions WHERE operation_id=$1)",&[&op]).await.map_err(text)?;
        require((0..4).all(|n|fixed_aux.get::<_,bool>(n)),"seven-body fixed values or exact completion counts differed")?;
        let retained:Value=c.query_one("SELECT jsonb_build_object('messages',(SELECT jsonb_agg(to_jsonb(x)-'content'-'search_text' ORDER BY seq) FROM public.messages x WHERE thread_id=$1),'events',(SELECT jsonb_agg(to_jsonb(x)-'payload' ORDER BY seq) FROM public.run_events x WHERE thread_id=$1))",&[&t.as_str()]).await.map_err(text)?.get(0);
        require(retained==identities,"clear changed permanent identity/seq/time/FK tuple")?;
        let row=c.query_one("SELECT (SELECT bool_and(content='{\"text\":\"\",\"retained\":false}'::jsonb AND search_text='') FROM public.messages WHERE thread_id=$1),(SELECT payload FROM public.run_events WHERE thread_id=$1 AND run_id='clear-run-410301' AND terminal),(SELECT count(*) FROM public.memory_events WHERE memory_id='owned-thread-memory' AND event_type='delete'),(SELECT content IS NULL AND status='deleted' FROM public.memories WHERE memory_id='owned-thread-memory'),(SELECT run_output_expired FROM openbot_internal.thread_history_clear_completions WHERE operation_id=$2)",&[&t.as_str(),&op]).await.map_err(text)?;
        require(row.get::<_,bool>(0)&&row.get::<_,Value>(1)==json!({"status":"reconciliation_required","errorCode":"journal_commit_unknown"})&&row.get::<_,i64>(2)==1&&row.get::<_,bool>(3)&&row.get::<_,i64>(4)==0,"fixed body/terminal/memory delete/zero expiry differs")?;
        require(c.query_one("SELECT payload='{\"status\":\"failed\",\"errorCode\":\"historical_imported_failure\"}'::jsonb FROM public.run_events WHERE run_id='clear-imported-terminal'",&[]).await.map_err(text)?.get::<_,bool>(0),"imported terminal retained noncanonical old body or discarded its actual Run reason")?;
        require(c.query_one("SELECT m.source_thread_id=$1 AND m.source_message_id='clear-message-410301' AND m.source_run_id='clear-run-410301' FROM public.memories m JOIN public.messages j ON (j.thread_id,j.message_id)=(m.source_thread_id,m.source_message_id) WHERE m.memory_id='owned-thread-memory'",&[&t.as_str()]).await.map_err(text)?.get::<_,bool>(0),"clear discarded memory source FK tombstone reference")?;
        receipt("C03","IDs seq FKs RR occupancy receipts retained; native/imported terminal fixed; memory delete once");Ok(())
    }).await;
}

async fn canonical_channel(
    p: &pool::DatabasePool,
    index: u64,
    channel: &str,
) -> TestResult<ThreadId> {
    let c = p.get().await.map_err(text)?;
    let t = thread(index);
    let run = format!("clear-channel-run-{index}");
    let message = format!("clear-channel-message-{index}");
    c.execute("INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES($1,'Owned channel','',ARRAY[]::text[],ARRAY[]::text[])",&[&channel]).await.map_err(text)?;
    c.execute(
        "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES($1,$2)",
        &[&channel, &ACTOR],
    )
    .await
    .map_err(text)?;
    insert_thread(&c, &t, Some(channel)).await?;
    c.batch_execute("BEGIN").await.map_err(text)?;
    c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,terminal_event_seq,created_at,started_at,finished_at) VALUES($1,$2,$3,$4,false,'completed',1,1,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z','2026-09-01T00:01:00Z')",&[&run,&t.as_str(),&BOT,&ACTOR]).await.map_err(text)?;
    c.execute("INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal) VALUES($1,0,$2,0,'completed','{\"status\":\"completed\"}',true)",&[&run,&t.as_str()]).await.map_err(text)?;
    c.execute("INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at) VALUES($1,$2,0,'user','{\"text\":\"Owned channel preview\"}','Owned channel preview',$3,$4,'2026-09-01T00:00:00Z')",&[&message,&t.as_str(),&run,&ACTOR]).await.map_err(text)?;
    c.execute("INSERT INTO openbot_internal.channel_history_sources(channel_id,source_schema,deployment_id,tenant_id,thread_id,run_id,message_id,message_role,message_created_at,last_message_agent_id,preview_checksum,preview_utf8_bytes) SELECT $1,1,t.deployment_id,t.tenant_id,t.thread_id,r.run_id,m.message_id,m.role,m.created_at,NULL,encode(sha256(convert_to(openbot_internal.thread_history_preview(m.search_text),'UTF8')),'hex'),octet_length(openbot_internal.thread_history_preview(m.search_text)) FROM public.threads t JOIN public.runs r USING(thread_id) JOIN public.messages m ON m.run_id=r.run_id WHERE m.message_id=$2",&[&channel,&message]).await.map_err(text)?;
    c.execute("UPDATE public.channels SET last_message='Owned channel preview',last_message_at='2026-09-01T00:00:00Z',last_message_agent_id=NULL WHERE id=$1",&[&channel]).await.map_err(text)?;
    c.batch_execute("SET CONSTRAINTS ALL IMMEDIATE; COMMIT")
        .await
        .map_err(text)?;
    Ok(t)
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_channel_source_of_j_removed_other_thread_source_kept_and_nowait_unavailable()
 {
    owned("clear52channel",|p,_|async move {
        seed(&p).await?;let t=canonical_channel(&p,410401,"clear-channel-j").await?;
        let other=canonical_channel(&p,410402,"clear-channel-other").await?;
        let c=p.get().await.map_err(text)?;let op=close_history(&c,&t).await?;
        let unrelated:Value=c.query_one("SELECT jsonb_build_object('source',to_jsonb(s),'channel',to_jsonb(ch),'message',to_jsonb(m)) FROM openbot_internal.channel_history_sources s JOIN public.channels ch ON ch.id=s.channel_id JOIN public.messages m USING(message_id) WHERE s.thread_id=$1",&[&other.as_str()]).await.map_err(text)?.get(0);
        let locker=p.get().await.map_err(text)?;
        locker.batch_execute("BEGIN").await.map_err(text)?;
        locker.query_one("SELECT id FROM public.channels WHERE id='clear-channel-j' FOR UPDATE",&[]).await.map_err(text)?;
        let pid:i32=locker.query_one("SELECT pg_backend_pid()",&[]).await.map_err(text)?.get(0);
        assert_held_lock(&c,pid,"public.channels").await?;
        let before=snapshot(&c,&["public.messages","public.channels","openbot_internal.channel_history_sources","openbot_internal.thread_history_clear_batches"]).await?;
        let a=authority(&p)?;
        require(matches!(a.clear_closed_history_before(t.as_str(),deadline()).await,Err(ThreadHistoryStopClearError::Unavailable)),"channel lock contention was not Unavailable")?;
        require(snapshot(&c,&["public.messages","public.channels","openbot_internal.channel_history_sources","openbot_internal.thread_history_clear_batches"]).await?==before,"NOWAIT failed batch leaked source/body progress")?;
        locker.batch_execute("ROLLBACK").await.map_err(text)?;drop(locker);
        let qlocker=p.get().await.map_err(text)?;qlocker.batch_execute("BEGIN").await.map_err(text)?;
        qlocker.query_one("SELECT operation_id FROM openbot_internal.thread_history_clear_intents WHERE operation_id=$1 FOR UPDATE",&[&op]).await.map_err(text)?;
        require(matches!(a.clear_closed_history_before(t.as_str(),deadline()).await,Err(ThreadHistoryStopClearError::Unavailable)),"same-Q serialization contention did not remain Unavailable")?;
        require(snapshot(&c,&["public.messages","public.channels","openbot_internal.channel_history_sources","openbot_internal.thread_history_clear_batches"]).await?==before,"same-Q contention leaked batch sequence or source changes")?;
        qlocker.batch_execute("ROLLBACK").await.map_err(text)?;drop(qlocker);drop(c);
        completed(&a,&t,&op).await?;let c=p.get().await.map_err(text)?;
        require(c.query_one("SELECT NOT EXISTS(SELECT 1 FROM openbot_internal.channel_history_sources WHERE thread_id=$1),(SELECT ROW(last_message,last_message_at,last_message_agent_id)=ROW(NULL::text,NULL::timestamptz,NULL::text) FROM public.channels WHERE id='clear-channel-j')",&[&t.as_str()]).await.map_err(text)?.get::<_,bool>(0),"J channel source not removed")?;
        require(c.query_one("SELECT last_message IS NULL AND last_message_at IS NULL AND last_message_agent_id IS NULL FROM public.channels WHERE id='clear-channel-j'",&[]).await.map_err(text)?.get::<_,bool>(0),"J channel projection not cleared")?;
        let retained:Value=c.query_one("SELECT jsonb_build_object('source',to_jsonb(s),'channel',to_jsonb(ch),'message',to_jsonb(m)) FROM openbot_internal.channel_history_sources s JOIN public.channels ch ON ch.id=s.channel_id JOIN public.messages m USING(message_id) WHERE s.thread_id=$1",&[&other.as_str()]).await.map_err(text)?.get(0);
        require(unrelated==retained,"clear modified other history's channel source or body")?;
        receipt("C04","owned channel lock NOWAIT; rollback; J source removed; other J retained");Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_bounded_batches_resume_after_abort_and_exact_rerun_idempotent() {
    owned("clear52resume",|p,_|async move {
        seed(&p).await?;let t=terminal_thread(&p,410501,false).await?;let c=p.get().await.map_err(text)?;
        c.execute("INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,actor_id) SELECT 'clear-bounded-'||n,$1,n,'system','{\"text\":\"Owned many\"}','Owned many',$2 FROM generate_series(1,8193) n",&[&t.as_str(),&ACTOR]).await.map_err(text)?;
        let op=close_history(&c,&t).await?;
        let before=snapshot(&c,&["public.messages","openbot_internal.thread_history_clear_batches"]).await?;
        c.batch_execute("BEGIN").await.map_err(text)?;batch(&c,&op,1,0,1,0).await?;
        c.execute("UPDATE public.messages SET content='{\"text\":\"\",\"retained\":false}',search_text='' WHERE message_id='clear-bounded-1'",&[]).await.map_err(text)?;
        c.batch_execute("ROLLBACK").await.map_err(text)?;
        require(snapshot(&c,&["public.messages","openbot_internal.thread_history_clear_batches"]).await?==before,"abort changed old body or batch history")?;
        drop(c);let a=authority(&p)?;
        require(matches!(a.clear_closed_history_before(t.as_str(),deadline()).await.map_err(text)?,ThreadHistoryClearProgress::BatchCommitted{more:true}),"first call exceeded64 batches or lost continuation")?;
        let c=p.get().await.map_err(text)?;
        let r=c.query_one("SELECT count(*),max(batch_seq),max(messages_cleared),sum(messages_cleared)::bigint,(SELECT count(*) FROM openbot_internal.thread_history_clear_completions WHERE operation_id=$1) FROM openbot_internal.thread_history_clear_batches WHERE operation_id=$1",&[&op]).await.map_err(text)?;
        require(r.get::<_,i64>(0)==64&&r.get::<_,Option<i64>>(1)==Some(64)&&r.get::<_,Option<i64>>(2).is_some_and(|n|n<=128)&&r.get::<_,Option<i64>>(3)==Some(8192)&&r.get::<_,i64>(4)==0,"batch cap/counts/sequence differed")?;
        let committed:Value=c.query_one("SELECT jsonb_agg(to_jsonb(b) ORDER BY batch_seq) FROM openbot_internal.thread_history_clear_batches b WHERE operation_id=$1",&[&op]).await.map_err(text)?.get(0);drop(c);
        completed(&a,&t,&op).await?;let c=p.get().await.map_err(text)?;
        let retained:Value=c.query_one("SELECT jsonb_agg(to_jsonb(b) ORDER BY batch_seq) FROM openbot_internal.thread_history_clear_batches b WHERE operation_id=$1 AND batch_seq<=64",&[&op]).await.map_err(text)?.get(0);
        require(committed==retained,"resume rewrote previously acknowledged batches")?;
        let final_state=snapshot(&c,&["public.messages","public.memory_events","openbot_internal.thread_history_clear_batches","openbot_internal.thread_history_clear_completions","public.audit_events","public.audit_checkpoints"]).await?;drop(c);
        completed(&a,&t,&op).await?;let c=p.get().await.map_err(text)?;
        require(snapshot(&c,&["public.messages","public.memory_events","openbot_internal.thread_history_clear_batches","openbot_internal.thread_history_clear_completions","public.audit_events","public.audit_checkpoints"]).await?==final_state,"exact completed replay emitted batch/audit or rewrote body")?;
        receipt("C05","aborted batch absent;64x128 cap; exact resume; replay zero writes");Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_completion_refused_with_live_run_residual_body_or_old_snapshot_reader()
 {
    owned("clear52barriers",|p,_|async move {
        seed(&p).await?;let live=thread(410601);let c=p.get().await.map_err(text)?;
        insert_thread(&c,&live,None).await?;
        c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at) VALUES('clear-live',$1,$2,$3,false,'running',1,clock_timestamp())",&[&live.as_str(),&BOT,&ACTOR]).await.map_err(text)?;
        let live_op=close_history(&c,&live).await?;drop(c);let a=authority(&p)?;
        require(matches!(a.clear_closed_history_before(live.as_str(),deadline()).await.map_err(text)?,ThreadHistoryClearProgress::AwaitingDrain),"live Run published completion")?;
        let queued=thread(410603);let c=p.get().await.map_err(text)?;insert_thread(&c,&queued,None).await?;
        c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token) VALUES('clear-corrupt-queued',$1,$2,$3,false,'queued',1)",&[&queued.as_str(),&BOT,&ACTOR]).await.map_err(text)?;
        close_history(&c,&queued).await?;drop(c);
        require(matches!(a.clear_closed_history_before(queued.as_str(),deadline()).await,Err(ThreadHistoryStopClearError::Corrupt{field:"run_status"})),"queued damaged Run incorrectly awaited drain")?;
        let t=terminal_thread(&p,410602,false).await?;let c=p.get().await.map_err(text)?;insert_preference(&c,&t,"clear-residual-memory","thread").await?;
        let op=close_history(&c,&t).await?;
        c.batch_execute("BEGIN").await.map_err(text)?;batch(&c,&op,1,0,0,0).await?;c.batch_execute("COMMIT").await.map_err(text)?;
        c.batch_execute("BEGIN").await.map_err(text)?;
        c.execute(INSERT_COMPLETION,&[&op]).await.map_err(text)?;
        let refused=c.batch_execute("SET CONSTRAINTS ALL IMMEDIATE").await;
        c.batch_execute("ROLLBACK").await.map_err(text)?;
        require(refused.err().is_some_and(|e|e.as_db_error().is_some_and(|d|d.message()=="thread_history_clear_body_remaining")),"residual message/thread memory accepted completion")?;
        let locker=p.get().await.map_err(text)?;locker.batch_execute("BEGIN").await.map_err(text)?;
        locker.query_one("SELECT thread_id FROM openbot_internal.thread_history_heads WHERE thread_id=$1 FOR UPDATE",&[&t.as_str()]).await.map_err(text)?;
        let pid:i32=locker.query_one("SELECT pg_backend_pid()",&[]).await.map_err(text)?.get(0);
        assert_held_lock(&c,pid,"openbot_internal.thread_history_heads").await?;
        require(matches!(a.clear_closed_history_before(t.as_str(),deadline()).await,Err(ThreadHistoryStopClearError::Unavailable)),"H NOWAIT contention accepted or reclassified")?;
        locker.batch_execute("ROLLBACK").await.map_err(text)?;drop(locker);
        let reader=p.get().await.map_err(text)?;reader.batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ").await.map_err(text)?;
        reader.query_one("SELECT count(*) FROM public.messages WHERE thread_id=$1",&[&t.as_str()]).await.map_err(text)?;
        let reader_pid:i32=reader.query_one("SELECT pg_backend_pid()",&[]).await.map_err(text)?.get(0);
        require(c.query_one("SELECT backend_xmin IS NOT NULL FROM pg_stat_activity WHERE pid=$1",&[&reader_pid]).await.map_err(text)?.get::<_,bool>(0),"RR reader did not own real snapshot")?;
        require(matches!(a.clear_closed_history_before(t.as_str(),deadline()).await.map_err(text)?,ThreadHistoryClearProgress::AwaitingReaders),"old RR snapshot published ACK2")?;
        require(c.query_one("SELECT NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_completions WHERE operation_id IN($1,$2)) AND EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_batches WHERE operation_id=$2)",&[&live_op,&op]).await.map_err(text)?.get::<_,bool>(0),"waiting barriers lost committed progress or leaked completion")?;
        require(reader.query_one("SELECT content->>'text' FROM public.messages WHERE thread_id=$1",&[&t.as_str()]).await.map_err(text)?.get::<_,String>(0)=="Owned body","old RR snapshot unexpectedly changed")?;
        reader.batch_execute("ROLLBACK").await.map_err(text)?;drop(reader);drop(c);completed(&a,&t,&op).await?;
        receipt("C06","live Run drain; residual source=None memory; H NOWAIT; real old RR snapshot barrier");Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_completion_and_batches_immutable_and_deferred_proof() {
    owned("clear52immutable",|p,_|async move {
        seed(&p).await?;let t=terminal_thread(&p,410701,false).await?;let c=p.get().await.map_err(text)?;let op=close_history(&c,&t).await?;drop(c);
        completed(&authority(&p)?,&t,&op).await?;let c=p.get().await.map_err(text)?;
        let before=snapshot(&c,&["openbot_internal.thread_history_heads","openbot_internal.thread_history_clear_intents","openbot_internal.thread_history_clear_batches","openbot_internal.thread_history_clear_completions","public.audit_events"]).await?;
        c.batch_execute("BEGIN").await.map_err(text)?;
        for table in ["thread_history_clear_batches","thread_history_clear_completions"] {
            for sql in [format!("UPDATE openbot_internal.{table} SET operation_id=operation_id"),format!("DELETE FROM openbot_internal.{table}"),format!("TRUNCATE openbot_internal.{table}")] {
                rejected(&c,&sql,"55000",Some("thread_history_clear_fact_mutation_refused")).await?;
            }
        }
        rejected(&c,"UPDATE openbot_internal.thread_history_clear_intents SET actor_id='clear-other'","55000",None).await?;
        rejected(&c,"UPDATE openbot_internal.thread_history_heads SET phase='open' WHERE phase='closed'","55000",None).await?;
        let result=c.execute(INSERT_BATCH,&[&op,&2i64,&0i64,&0i64,&0i64]).await;
        require(result.err().is_some_and(|e|e.as_db_error().is_some_and(|d|d.message()=="thread_history_clear_binding_invalid")),"completed operation admitted new batch")?;
        c.batch_execute("ROLLBACK").await.map_err(text)?;
        require(snapshot(&c,&["openbot_internal.thread_history_heads","openbot_internal.thread_history_clear_intents","openbot_internal.thread_history_clear_batches","openbot_internal.thread_history_clear_completions","public.audit_events"]).await?==before,"refused fact mutation changed immutable data")?;
        let trigger=c.query_one("SELECT tgdeferrable,tginitdeferred FROM pg_trigger WHERE tgname='thread_history_clear_completions_require_final' AND tgrelid='openbot_internal.thread_history_clear_completions'::regclass",&[]).await.map_err(text)?;
        require(trigger.get::<_,bool>(0)&&trigger.get::<_,bool>(1),"completion proof is not initially deferred")?;
        let audit_count:i64=c.query_one("SELECT count(*) FROM public.audit_events WHERE event_type='thread_history.clear_completed'",&[]).await.map_err(text)?.get(0);
        require(audit_count==1,"completion audit not exactly one")?;
        receipt("C07","immutable batches completion H Q; postcompletion batches refused; deferred proof; one audit");Ok(())
    }).await;
}

async fn explicit_saved(c: &Client, t: &ThreadId) -> TestResult {
    let store = Uuid::now_v7().to_string();
    let op = Uuid::now_v7().to_string();
    let request = Uuid::now_v7().to_string();
    let artifact = Uuid::now_v7().to_string();
    c.execute("INSERT INTO openbot_internal.artifact_store_bindings(deployment_id,tenant_id,dataset_id,store_id,root_device,root_inode,root_uid) VALUES($1,$2,'owned-clear-artifacts',$3,'1','1','1')",&[&DEP,&TENANT,&store]).await.map_err(text)?;
    c.execute("INSERT INTO openbot_internal.artifact_save_operations(deployment_id,tenant_id,dataset_id,request_id,operation_id,artifact_id,owner_actor_id,source_thread_id,source_run_id,source_message_id,state,store_id,workspace_kind,workspace_id,expected_sha256,expected_bytes,charged_bytes,created_at) VALUES($1,$2,'owned-clear-artifacts',$3,$4,$5,$6,$7,'clear-run-410801','clear-message-410801','available',$8,'thread',$7,repeat('a',64),1,1,clock_timestamp())",&[&DEP,&TENANT,&request,&op,&artifact,&ACTOR,&t.as_str(),&store]).await.map_err(text)?;
    c.execute("INSERT INTO openbot_internal.artifact_records(deployment_id,tenant_id,dataset_id,artifact_id,operation_id,request_id,owner_actor_id,source_thread_id,source_run_id,source_message_id,status,workspace_kind,workspace_id,media_type,byte_length,sha256,retention_class,saved_by,saved_at) VALUES($1,$2,'owned-clear-artifacts',$3,$4,$5,$6,$7,'clear-run-410801','clear-message-410801','available','thread',$7,'text/plain; charset=utf-8',1,repeat('a',64),'explicit_saved',$6,clock_timestamp())",&[&DEP,&TENANT,&artifact,&op,&request,&ACTOR,&t.as_str()]).await.map_err(text)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_run_output_noop_assertion_explicit_saved_and_user_bot_memory_untouched()
 {
    owned("clear52copies",|p,_|async move {
        seed(&p).await?;let t=terminal_thread(&p,410801,false).await?;
        let store=PostgresMemoryAdministration::new(p.clone());
        let mut user_request=remember_request(MemoryScope::User);
        user_request.input.memory_kind=MemoryKind::Fact;
        user_request.input.source=Some(MemorySource{thread_id:t.clone(),message_id:"clear-message-410801".into()});
        let mut bot_request=remember_request(MemoryScope::Bot{bot_id:BotId::new(BOT)});
        bot_request.input.memory_kind=MemoryKind::Fact;
        bot_request.input.source=user_request.input.source.clone();
        let user=store.remember(user_request).await.map_err(text)?;
        let bot=store.remember(bot_request).await.map_err(text)?;
        require(user.source.as_ref().is_some_and(|s|s.thread_id==t)&&bot.source.as_ref().is_some_and(|s|s.thread_id==t),"independent User/Bot copy lacked actual source J reference")?;
        let scoped=store.remember(remember_request(MemoryScope::Thread{thread_id:t.clone()})).await.map_err(text)?;
        let c=p.get().await.map_err(text)?;explicit_saved(&c,&t).await?;
        let independent:Value=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY memory_id) FROM public.memories m WHERE scope_kind IN('user','bot')",&[]).await.map_err(text)?.get(0);
        let artifacts=snapshot(&c,&["openbot_internal.artifact_store_bindings","openbot_internal.artifact_save_operations","openbot_internal.artifact_records"]).await?;
        c.batch_execute("BEGIN").await.map_err(text)?;
        let future_run_output=format!("INSERT INTO openbot_internal.artifact_records SELECT (jsonb_populate_record(NULL::openbot_internal.artifact_records,to_jsonb(r)||jsonb_build_object('artifact_id','{}','retention_class','run_output'))).* FROM openbot_internal.artifact_records r WHERE dataset_id='owned-clear-artifacts'",Uuid::now_v7());
        rejected(&c,&future_run_output,"23514",None).await?;
        c.batch_execute("ROLLBACK").await.map_err(text)?;
        let op=close_history(&c,&t).await?;drop(c);let a=authority(&p)?;completed(&a,&t,&op).await?;
        require(store.remember(remember_request(MemoryScope::Thread{thread_id:t.clone()})).await.is_err(),"new source=None Thread preference wrote after ACK2")?;
        require(store.correct(correct_request(&scoped)).await.is_err(),"Thread correction revived cleared body")?;
        let c=p.get().await.map_err(text)?;
        let retained:Value=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY memory_id) FROM public.memories m WHERE scope_kind IN('user','bot')",&[]).await.map_err(text)?.get(0);
        require(retained==independent&&snapshot(&c,&["openbot_internal.artifact_store_bindings","openbot_internal.artifact_save_operations","openbot_internal.artifact_records"]).await?==artifacts,"clear altered explicit saved/User/Bot independent copies")?;
        require(c.query_one("SELECT run_output_expired=0 AND memories_cleared=1 FROM openbot_internal.thread_history_clear_completions WHERE operation_id=$1",&[&op]).await.map_err(text)?.get::<_,bool>(0),"clear expiry/count did not respect current producer scope")?;
        c.batch_execute("BEGIN").await.map_err(text)?;
        rejected(&c,&format!("UPDATE public.memories SET status='forbidden',content=NULL WHERE memory_id='{}'",scoped.memory_id),"55000",Some("thread_history_writer_closed")).await?;
        c.batch_execute("ROLLBACK").await.map_err(text)?;drop(c);
        store.correct(correct_request(&user)).await.map_err(text)?;store.correct(correct_request(&bot)).await.map_err(text)?;
        receipt("C08","current0042 refuses run_output; expiry0; explicit_saved User/Bot retained and editable; Thread source=None closed");Ok(())
    }).await;
}

fn history_request(t: &ThreadId) -> ThreadHistoryRequest {
    ThreadHistoryRequest {
        deployment: DeploymentId::new(DEP),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(ACTOR),
        thread: t.clone(),
    }
}
fn conversation_request(t: &ThreadId) -> ThreadConversationRequest {
    ThreadConversationRequest {
        deployment: DeploymentId::new(DEP),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(ACTOR),
        thread: t.clone(),
    }
}
fn subscription_request(t: &ThreadId) -> ThreadEventSubscription {
    ThreadEventSubscription {
        deployment: DeploymentId::new(DEP),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(ACTOR),
        thread: t.clone(),
        after_event_sequence: None,
    }
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_reads_after_completion_return_not_visible() {
    owned("clear52reads",|p,config|async move {
        seed(&p).await?;let t=terminal_thread(&p,411001,false).await?;let empty=thread(411002);
        let deleted=thread(411003);
        let c=p.get().await.map_err(text)?;insert_thread(&c,&empty,None).await?;insert_thread(&c,&deleted,None).await?;
        c.execute("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp(),updated_at=clock_timestamp() WHERE thread_id=$1",&[&deleted.as_str()]).await.map_err(text)?;drop(c);
        let d=PostgresThreadDirectory::with_runtime(p.clone(),config,"owned-clear-reader".into(),DEFAULT_THREAD_LEASE_DURATION).map_err(text)?;
        require(!d.thread_history(history_request(&t)).await.map_err(text)?.messages.is_empty(),"positive history absent before completion")?;
        require(d.thread_history(history_request(&empty)).await.map_err(text)?.messages.is_empty(),"visible empty history was denied")?;
        require(d.thread_conversation(conversation_request(&empty)).await.map_err(text)?==openbot_contracts::command::ThreadConversationSnapshot::default(),"visible empty conversation not original default")?;
        let missing=thread(411099);
        for h in [history_request(&missing),history_request(&deleted),ThreadHistoryRequest{actor:ActorId::new("clear-other"),..history_request(&t)},ThreadHistoryRequest{tenant:TenantId::new("foreign-tenant"),..history_request(&t)},ThreadHistoryRequest{deployment:DeploymentId::new("foreign-deployment"),..history_request(&t)}] {
            require(d.thread_history(h).await.map_err(text)?.messages.is_empty(),"noncompleted missing/invisible/deleted history changed original empty success")?;
        }
        for q in [conversation_request(&missing),conversation_request(&deleted),ThreadConversationRequest{actor:ActorId::new("clear-other"),..conversation_request(&t)},ThreadConversationRequest{tenant:TenantId::new("foreign-tenant"),..conversation_request(&t)},ThreadConversationRequest{deployment:DeploymentId::new("foreign-deployment"),..conversation_request(&t)}] {
            require(d.thread_conversation(q).await.map_err(text)?==openbot_contracts::command::ThreadConversationSnapshot::default(),"noncompleted missing/invisible/deleted conversation changed original default")?;
        }
        let c=p.get().await.map_err(text)?;let op=close_history(&c,&t).await?;drop(c);
        completed(&authority(&p)?,&t,&op).await?;
        require(d.thread_history(history_request(&t)).await==Err(ThreadDirectoryError::NotVisible),"completed history did not return NotVisible")?;
        require(d.thread_conversation(conversation_request(&t)).await==Err(ThreadDirectoryError::NotVisible),"completed conversation did not return NotVisible")?;
        require(matches!(d.subscribe_thread_events(subscription_request(&t)).await,Err(ThreadDirectoryError::NotVisible)),"completed SSE subscription not refused")?;
        for h in [ThreadHistoryRequest{actor:ActorId::new("clear-other"),..history_request(&t)},ThreadHistoryRequest{tenant:TenantId::new("foreign-tenant"),..history_request(&t)},ThreadHistoryRequest{deployment:DeploymentId::new("foreign-deployment"),..history_request(&t)}] {
            require(d.thread_history(h).await.map_err(text)?.messages.is_empty(),"unauthorized completed history became distinguishable")?;
        }
        for q in [ThreadConversationRequest{actor:ActorId::new("clear-other"),..conversation_request(&t)},ThreadConversationRequest{tenant:TenantId::new("foreign-tenant"),..conversation_request(&t)},ThreadConversationRequest{deployment:DeploymentId::new("foreign-deployment"),..conversation_request(&t)}] {
            require(d.thread_conversation(q).await.map_err(text)?==openbot_contracts::command::ThreadConversationSnapshot::default(),"unauthorized completed conversation became distinguishable")?;
        }
        let store=PostgresMemoryAdministration::new(p.clone());
        require(store.remember(remember_request(MemoryScope::Thread{thread_id:t.clone()})).await.is_err(),"source=None Thread remember revived completed J")?;
        let c=p.get().await.map_err(text)?;
        require(c.query_one("SELECT NOT EXISTS(SELECT 1 FROM public.memories WHERE scope_kind='thread' AND scope_id=$1)",&[&t.as_str()]).await.map_err(text)?.get::<_,bool>(0),"completion leaked revived Thread preference")?;
        let stream=d.subscribe_thread_events(subscription_request(&empty)).await.map_err(text)?;drop(stream);
        require(matches!(d.subscribe_thread_events(ThreadEventSubscription{actor:ActorId::new("clear-other"),..subscription_request(&empty)}).await,Err(ThreadDirectoryError::NotVisible)),"invisible SSE changed original NotVisible")?;
        receipt("C10","history conversation SSE NotVisible; visible empty J preserved; source=None cannot revive");Ok(())
    }).await;
}
