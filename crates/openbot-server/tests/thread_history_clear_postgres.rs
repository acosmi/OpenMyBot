//! Trusted maintenance CLI clearing on an explicitly owned loopback PostgreSQL 17.11.
//! Synthetic bodies and identities only; no real Host, account, backup or user data is read.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::process::Command;

use openbot_contracts::artifacts::canonical_artifact_uuid_v7;
use openbot_contracts::ids::DeploymentId;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_infra::db::{baseline, native, pool};
use serde_json::{Value, json};

const DEPLOYMENT: &str = "owned-clear-cli-deployment";
const TENANT: &str = "wrok-bot-local";
const MASTER: &str = "Qm91bmRlZCBzeW50aGV0aWMgY2xlYXIgY2xpIGtleSE=";

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn thread_history_clear_maintenance_source_clears_soft_deleted_thread_and_audits_without_auth()
 {
    let admin = harness::admin_config("thread_history_clear_maintenance");
    assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
    assert!(
        admin
            .password
            .as_ref()
            .is_some_and(|value| !value.is_empty())
    );
    harness::with_temp_database(&admin, "clear52cli", |config| async move {
        let database = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let result = async {
            require(config.dbname.starts_with("openbot_it_"), "owned database name missing")?;
            let thread = ThreadIdentity::new(&DeploymentId::new(DEPLOYMENT)).mint_from_entropy([9; 16]);
            let live = ThreadIdentity::new(&DeploymentId::new(DEPLOYMENT)).mint_from_entropy([10; 16]);
            let mut client = database.get().await.map_err(|error| error.to_string())?;
            let version: i32 = client.query_one("SELECT current_setting('server_version_num')::int", &[])
                .await.map_err(|error| error.to_string())?.get(0);
            require(version == 170011, "frozen PostgreSQL17.11 prerequisite differs")?;
            baseline::apply(&client).await.map_err(|error| error.to_string())?;
            native::apply_through(&mut client, 49).await.map_err(|error| error.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('clear-cli-owner','owned-clear-cli@example.test',0);")
                .await.map_err(|error| error.to_string())?;
            for (id, status, title) in [(thread.as_str(), "deleted", "OWNED_CLEAR_CLI_BODY"), (live.as_str(), "active", "OWNED_LIVE_BODY")] {
                client.execute(
                    "INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status,next_message_seq,deleted_at) VALUES($1,$2,$3,'clear-cli-owner','direct_bot','clear-cli-bot',$4,$5,1,CASE WHEN $5='deleted' THEN now() ELSE NULL END)",
                    &[&id, &TENANT, &DEPLOYMENT, &title, &status],
                ).await.map_err(|error| error.to_string())?;
            }
            client.execute(
                "INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,actor_id) VALUES('clear-cli-message',$1,0,'user','{\"text\":\"OWNED_CLEAR_CLI_BODY\"}','OWNED_CLEAR_CLI_BODY','clear-cli-owner')",
                &[&thread.as_str()],
            ).await.map_err(|error| error.to_string())?;
            client.execute(
                "INSERT INTO public.memories(memory_id,tenant_id,owner_user_id,scope_kind,scope_id,memory_kind,content,sensitivity,origin,created_by) VALUES('clear-cli-memory',$1,'clear-cli-owner','thread',$2,'preference','OWNED_CLEAR_CLI_MEMORY','normal','user_action','clear-cli-owner')",
                &[&TENANT, &thread.as_str()],
            ).await.map_err(|error| error.to_string())?;
            client.execute(
                "INSERT INTO public.memories(memory_id,tenant_id,owner_user_id,scope_kind,memory_kind,content,sensitivity,origin,created_by) VALUES('clear-cli-independent',$1,'clear-cli-owner','user','preference','OWNED_INDEPENDENT_MEMORY','normal','user_action','clear-cli-owner')",
                &[&TENANT],
            ).await.map_err(|error| error.to_string())?;
            native::apply(&mut client).await.map_err(|error| error.to_string())?;
            let absent: bool = client.query_one(
                "SELECT NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads WHERE thread_id=$1)",
                &[&thread.as_str()],
            ).await.map_err(|error| error.to_string())?.get(0);
            require(absent, "legacy deleted fixture unexpectedly had H before maintenance")?;
            drop(client);

            let url = connection_string(&config);
            let output = run_cli(&url, thread.as_str())?;
            require(output.status.code() == Some(0), "maintenance CLI did not complete")?;
            require(output.stderr.is_empty(), "maintenance CLI emitted an error")?;
            require(output.stdout == b"thread_history_clear_completed\n", "maintenance CLI result drifted")?;
            let client = database.get().await.map_err(|error| error.to_string())?;
            let row = client.query_one(
                "SELECT c.operation_id,c.source,c.threads_cleared,c.messages_cleared,c.memories_cleared,c.run_output_expired,h.phase,q.intent_kind,q.actor_id,q.auth_generation,t.title,m.content,mem.status,mem.content AS memory_content FROM openbot_internal.thread_history_clear_completions c JOIN openbot_internal.thread_history_heads h USING(thread_id) JOIN openbot_internal.thread_history_clear_intents q ON q.operation_id=c.operation_id JOIN public.threads t ON t.thread_id=c.thread_id JOIN public.messages m ON m.thread_id=t.thread_id JOIN public.memories mem ON mem.scope_kind='thread' AND mem.scope_id=t.thread_id WHERE c.thread_id=$1",
                &[&thread.as_str()],
            ).await.map_err(|error| error.to_string())?;
            let operation: String = row.get("operation_id");
            require(canonical_artifact_uuid_v7(&operation).as_deref() == Some(operation.as_str()), "maintenance operation is not canonical UUIDv7")?;
            require(row.get::<_, String>("source") == "maintenance"
                && row.get::<_, String>("phase") == "closed"
                && row.get::<_, String>("intent_kind") == "maintenance_clear"
                && row.get::<_, String>("actor_id") == "system:thread-history-clear"
                && row.get::<_, i64>("auth_generation") == 0, "maintenance H/Q/completion binding drifted")?;
            require(row.get::<_, i64>("threads_cleared") == 1
                && row.get::<_, i64>("messages_cleared") == 1
                && row.get::<_, i64>("memories_cleared") == 1
                && row.get::<_, i64>("run_output_expired") == 0, "actual maintenance counts differ")?;
            require(row.get::<_, Option<String>>("title").is_none()
                && row.get::<_, Value>("content") == json!({"text":"", "retained":false})
                && row.get::<_, String>("status") == "deleted"
                && row.get::<_, Option<String>>("memory_content").is_none(), "maintenance left body")?;
            let event = client.query_one("SELECT actor_user_id,payload,prev_hash,row_hash FROM public.audit_events WHERE event_type='thread_history.clear_completed' AND target_id=$1", &[&thread.as_str()])
                .await.map_err(|error| error.to_string())?;
            let payload: Value = event.get("payload");
            let expected = json!({
                "operation_id": operation, "source": "maintenance", "batches": 1,
                "threads_cleared": 1, "messages_cleared": 1, "memories_cleared": 1,
                "run_events_cleared": 0, "tool_approvals_cleared": 0,
                "component_decisions_cleared": 0, "remote_interrupts_cleared": 0,
                "channel_sources_cleared": 0, "channels_cleared": 0, "run_output_expired": 0,
            });
            require(event.get::<_, Option<String>>("actor_user_id").is_none()
                && payload == expected
                && event.get::<_, Option<String>>("row_hash").is_some(), "typed maintenance audit missing or drifted")?;
            let untouched: bool = client.query_one(
                "SELECT (SELECT content='OWNED_INDEPENDENT_MEMORY' AND status='active' FROM public.memories WHERE memory_id='clear-cli-independent') AND NOT EXISTS(SELECT 1 FROM public.users WHERE id='system:thread-history-clear') AND NOT EXISTS(SELECT 1 FROM public.user_roles WHERE user_id='system:thread-history-clear')",
                &[],
            ).await.map_err(|error| error.to_string())?.get(0);
            require(untouched, "maintenance touched independent memory or created a system user/role")?;
            let before = facts_snapshot(&client).await?;
            drop(client);
            let replay = run_cli(&url, thread.as_str())?;
            require(replay.status.code() == Some(0), "maintenance exact replay refused")?;
            let refused = run_cli(&url, live.as_str())?;
            require(refused.status.code() == Some(65), "maintenance accepted live base")?;
            let client = database.get().await.map_err(|error| error.to_string())?;
            require(facts_snapshot(&client).await? == before, "replay or live refusal rewrote H/Q/batch/completion/audit")?;
            println!("THREAD_HISTORY_CLEAR id=C09 completed=true replay=true live_refused=true source=maintenance");
            Ok(())
        }.await;
        database.close();
        result
    }).await;
}

async fn facts_snapshot(client: &tokio_postgres::Client) -> Result<Value, String> {
    client.query_one("SELECT jsonb_build_object('heads',(SELECT jsonb_agg(to_jsonb(h) ORDER BY thread_id) FROM openbot_internal.thread_history_heads h),'intents',(SELECT jsonb_agg(to_jsonb(q) ORDER BY operation_id) FROM openbot_internal.thread_history_clear_intents q),'batches',(SELECT jsonb_agg(to_jsonb(b) ORDER BY operation_id,batch_seq) FROM openbot_internal.thread_history_clear_batches b),'completions',(SELECT jsonb_agg(to_jsonb(c) ORDER BY operation_id) FROM openbot_internal.thread_history_clear_completions c),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY created_at,id) FROM public.audit_events a),'memory_events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY memory_id,seq) FROM public.memory_events e))", &[])
        .await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())
}

fn connection_string(config: &pool::DatabaseConfig) -> String {
    fn quoted(value: &str) -> String {
        format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
    }
    format!(
        "host={} port={} user={} password={} dbname={}",
        quoted(&config.host),
        config.port,
        quoted(&config.user),
        quoted(config.password.as_deref().unwrap_or("")),
        quoted(&config.dbname)
    )
}

fn run_cli(database_url: &str, thread: &str) -> Result<std::process::Output, String> {
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/wrok-bot");
    Command::new(env!("CARGO_BIN_EXE_openbot-migrate"))
        .env_clear()
        .env("DATABASE_URL", database_url)
        .env("DEPLOYMENT_ID", DEPLOYMENT)
        .env("TENANT_PACKAGE_DIR", package)
        .env("KEY_ENCRYPTION_KEY", MASTER)
        .args(["thread-history-clear-deleted", thread])
        .output()
        .map_err(|_| "owned maintenance CLI spawn failed".to_owned())
}
