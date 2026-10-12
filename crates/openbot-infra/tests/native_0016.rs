//! Native 0016（thread/realtime/memory base）的 PostgreSQL 17 真库验收。

mod harness;

use std::collections::BTreeSet;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::tables::{
    intelligence_import_cursors, memories, memory_events, messages, outbox, run_events, runs,
    thread_memberships, threads,
};
use openbot_infra::db::{baseline, pool, schema_facts};
use openbot_infra::repo::import::ImportCursorRepo;
use openbot_infra::repo::memory::{MemoryEventRepo, MemoryRecallQuery, MemoryRepo};
use openbot_infra::repo::outbox::OutboxRepo;
use openbot_infra::repo::run::{RunEventRepo, RunRepo};
use openbot_infra::repo::thread::{MessageRepo, ThreadLeaseRepo, ThreadMembershipRepo, ThreadRepo};
use serde_json::json;
use time::{Duration, OffsetDateTime};

const POST_0015: &str = include_str!("../../../fixtures/db/schema-0015.json");
const POST_0016: &str = include_str!("../../../fixtures/db/schema-0016.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture 必须合法")
}

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0016_is_exact_expand_only_and_tool_fk_is_staged_not_validated() {
    let admin = admin_config("post_0016_is_exact_expand_only_and_tool_fk_is_staged_not_validated");
    with_temp_database(&admin, "native0016facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0015_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0015) {
                return Err("0016 前提事实漂移".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0016_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("从 0015 升 0016 应施加一条 migration".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if after != facts(POST_0016) {
                return Err("0016 活库与 fixture 不相等".to_owned());
            }
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0016 丢表 {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!("0016 改写旧列 {}.{}", old.name, column.name));
                    }
                }
            }
            let expected: BTreeSet<&str> = [
                "intelligence_import_cursors",
                "memories",
                "memory_events",
                "messages",
                "outbox",
                "run_events",
                "runs",
                "thread_leases",
                "thread_memberships",
                "threads",
            ]
            .into_iter()
            .collect();
            let actual: BTreeSet<&str> = after
                .tables
                .iter()
                .filter(|table| before.table(&table.name).is_none())
                .map(|table| table.name.as_str())
                .collect();
            if actual != expected {
                return Err(format!("0016 新表集合漂移：{actual:?}"));
            }
            let fk_validated: bool = client
                .query_one(
                    "SELECT convalidated FROM pg_constraint \
                     WHERE conname='tool_calls_run_id_fkey'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if fk_validated {
                return Err("历史 tool call 未 backfill 前 FK 不得伪装已 VALIDATE".to_owned());
            }
            let ledger: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM openbot_internal.schema_migrations",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if ledger != 4 {
                return Err(format!("native 账本应有四行，实际 {ledger}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn native_constraints_and_repositories_enforce_fencing_replay_outbox_and_memory_scope() {
    let admin = admin_config(
        "native_constraints_and_repositories_enforce_fencing_replay_outbox_and_memory_scope",
    );
    with_temp_database(&admin, "native0016behavior", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.users(id,email) VALUES('user-1','user-1@example.test')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;

            let thread = threads::Row {
                thread_id: "thread-1".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                deployment_id: "deployment-1".to_owned(),
                created_by: "user-1".to_owned(),
                anchor_kind: "direct_bot".to_owned(),
                anchor_id: "bot-1".to_owned(),
                title: Some("MARKER-VISIBLE".to_owned()),
                status: "active".to_owned(),
                next_message_seq: 1,
                next_event_seq: 2,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            };
            ThreadRepo::new(pool.clone())
                .insert(&thread)
                .await
                .map_err(|error| error.to_string())?;
            let membership = thread_memberships::Row {
                thread_id: "thread-1".to_owned(),
                user_id: "user-1".to_owned(),
                created_at: now,
            };
            ThreadMembershipRepo::new(pool.clone())
                .insert(&membership)
                .await
                .map_err(|error| error.to_string())?;

            let message = messages::Row {
                message_id: "message-1".to_owned(),
                thread_id: "thread-1".to_owned(),
                seq: 0,
                role: "user".to_owned(),
                content: json!({"text":"The office is closed Friday"}),
                search_text: "The office is closed Friday".to_owned(),
                run_id: None,
                actor_id: Some("user-1".to_owned()),
                created_at: now,
            };
            let message_repo = MessageRepo::new(pool.clone());
            message_repo
                .insert(&message)
                .await
                .map_err(|error| error.to_string())?;
            if message_repo
                .list_after("thread-1", -1, 10)
                .await
                .map_err(|error| error.to_string())?
                .len()
                != 1
            {
                return Err("message replay 没从持久化 sequence 补回".to_owned());
            }

            let run = runs::Row {
                run_id: "run-1".to_owned(),
                thread_id: "thread-1".to_owned(),
                bot_id: "bot-1".to_owned(),
                actor_id: "user-1".to_owned(),
                foreground: true,
                status: "running".to_owned(),
                fencing_token: 1,
                next_event_seq: 2,
                next_tool_call_seq: None,
                terminal_event_seq: None,
                error_code: None,
                created_at: now,
                started_at: Some(now),
                finished_at: None,
                budget_max_output_tokens: None,
                usage_input_tokens: 0,
                usage_output_tokens: 0,
                usage_total_tokens: 0,
                usage_next_sampling: 0,
                usage_last_sampling: None,
                usage_last_input_tokens: None,
                usage_last_output_tokens: None,
                usage_last_total_tokens: None,
                cost_currency: None,
                cost_provider: None,
                cost_model: None,
                cost_max_input_micro_units_per_million_tokens: None,
                cost_max_output_micro_units_per_million_tokens: None,
                cost_source_url: None,
                cost_source_sha256: None,
                cost_observed_at: None,
                usage_cost_upper_bound_micro_units: None,
                usage_cost_upper_bound_remainder_millionths: None,
                budget_cost_currency: None,
                budget_max_cost_micro_units: None,
            };
            RunRepo::new(pool.clone())
                .insert(&run)
                .await
                .map_err(|error| error.to_string())?;
            let duplicate = client
                .execute(
                    "INSERT INTO public.runs(\
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at) \
                     VALUES('run-2','thread-1','bot-1','user-1',true,'running',1,$1)",
                    &[&now],
                )
                .await
                .expect_err("第二个 active foreground run 必须拒绝");
            if duplicate.as_db_error().and_then(|error| error.constraint())
                != Some("runs_one_foreground_active_per_thread")
            {
                return Err("foreground 唯一索引未命中".to_owned());
            }

            let events = RunEventRepo::new(pool.clone());
            events
                .insert(&run_events::Row {
                    run_id: "run-1".to_owned(),
                    seq: 0,
                    thread_id: "thread-1".to_owned(),
                    event_seq: 0,
                    event_type: "started".to_owned(),
                    payload: json!({}),
                    terminal: false,
                    created_at: now,
                })
                .await
                .map_err(|error| error.to_string())?;
            // Like the real finish, the exactly-once terminal event and the Run terminal
            // state settle in one transaction; neither half may commit alone.
            client
                .execute(
                    "WITH r AS (UPDATE public.runs SET status='completed',terminal_event_seq=1, \
                       finished_at=$2 WHERE run_id=$1 RETURNING run_id,thread_id) \
                     INSERT INTO public.run_events( \
                       run_id,seq,thread_id,event_seq,event_type,payload,terminal,created_at) \
                     SELECT run_id,1,thread_id,1,'completed','{}'::jsonb,true,$2 FROM r",
                    &[&"run-1", &(now + Duration::SECOND)],
                )
                .await
                .map_err(|error| error.to_string())?;
            events
                .insert(&run_events::Row {
                    run_id: "run-1".to_owned(),
                    seq: 2,
                    thread_id: "thread-1".to_owned(),
                    event_seq: 2,
                    event_type: "failed".to_owned(),
                    payload: json!({}),
                    terminal: true,
                    created_at: now + Duration::seconds(2),
                })
                .await
                .expect_err("第二 terminal event 必须拒绝");
            if events
                .replay_after("thread-1", -1, 10)
                .await
                .map_err(|error| error.to_string())?
                .len()
                != 2
            {
                return Err("run event replay 没按 cursor 补回两条".to_owned());
            }

            let leases = ThreadLeaseRepo::new(pool.clone());
            let first = leases
                .acquire_or_renew("thread-1", "replica-a", now, now + Duration::MINUTE)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "首个 lease 没拿到".to_owned())?;
            if first.fencing_token != 1
                || leases
                    .acquire_or_renew(
                        "thread-1",
                        "replica-b",
                        now,
                        now + Duration::MINUTE,
                    )
                    .await
                    .map_err(|error| error.to_string())?
                    .is_some()
            {
                return Err("活 lease 被另一 replica 接管".to_owned());
            }
            let takeover = leases
                .acquire_or_renew(
                    "thread-1",
                    "replica-b",
                    now + Duration::minutes(2),
                    now + Duration::minutes(3),
                )
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "过期 lease 未被接管".to_owned())?;
            if takeover.fencing_token != 2 {
                return Err("过期接管没有推进 fencing token".to_owned());
            }

            let invalid_outbox = client
                .execute(
                    "INSERT INTO public.outbox(\
                       outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload) \
                     VALUES('out-invalid','run','run-1',0,'vendor','non_idempotent','{}')",
                    &[],
                )
                .await
                .expect_err("非幂等 external effect 不得进普通 outbox");
            if invalid_outbox
                .as_db_error()
                .and_then(|error| error.constraint())
                != Some("outbox_delivery_class_replay_safe")
            {
                return Err("outbox replay-safe CHECK 未命中".to_owned());
            }
            let outbox_repo = OutboxRepo::new(pool.clone());
            outbox_repo
                .insert(&outbox::Row {
                    outbox_id: "out-1".to_owned(),
                    aggregate_kind: "run".to_owned(),
                    aggregate_id: "run-1".to_owned(),
                    seq: 0,
                    destination: "realtime".to_owned(),
                    delivery_class: "internal".to_owned(),
                    payload: json!({"eventSeq":1}),
                    status: "pending".to_owned(),
                    attempt_count: 0,
                    available_at: now,
                    claimed_by: None,
                    claim_expires_at: None,
                    delivered_at: None,
                    last_error_code: None,
                    created_at: now,
                    updated_at: now,
                })
                .await
                .map_err(|error| error.to_string())?;
            let claimed = outbox_repo
                .claim_ready("relay-a", now, now + Duration::MINUTE)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "ready outbox 未被 claim".to_owned())?;
            if claimed.attempt_count != 1 || claimed.status != "delivering" {
                return Err("outbox claim 状态不符".to_owned());
            }
            if outbox_repo
                .mark_delivered("out-1", "relay-a", now + Duration::SECOND)
                .await
                .map_err(|error| error.to_string())?
                .as_ref()
                .map(|row| row.status.as_str())
                != Some("delivered")
            {
                return Err("outbox delivery CAS 未完成".to_owned());
            }

            let invalid_memory = client
                .execute(
                    "INSERT INTO public.memories(\
                       memory_id,tenant_id,owner_user_id,scope_kind,memory_kind,content,\
                       sensitivity,origin,created_by) \
                     VALUES('memory-invalid','tenant-1','user-1','user','fact','orphan',\
                            'normal','user_action','user-1')",
                    &[],
                )
                .await
                .expect_err("无 provenance fact 必须拒绝");
            if invalid_memory
                .as_db_error()
                .and_then(|error| error.constraint())
                != Some("memories_fact_source_required")
            {
                return Err("memory fact source CHECK 未命中".to_owned());
            }
            let memory_repo = MemoryRepo::new(pool.clone());
            memory_repo
                .insert(&memories::Row {
                    memory_id: "memory-1".to_owned(),
                    tenant_id: "tenant-1".to_owned(),
                    owner_user_id: "user-1".to_owned(),
                    scope_kind: "user".to_owned(),
                    scope_id: None,
                    memory_kind: "fact".to_owned(),
                    content: Some("The office is closed Friday".to_owned()),
                    tags: vec![Some("schedule".to_owned())],
                    sensitivity: "normal".to_owned(),
                    source_run_id: None,
                    source_authorization_snapshot: None,
                    source_thread_id: Some("thread-1".to_owned()),
                    source_message_id: Some("message-1".to_owned()),
                    origin: "user_action".to_owned(),
                    created_by: "user-1".to_owned(),
                    supersedes_id: None,
                    status: "active".to_owned(),
                    expires_at: None,
                    created_at: now,
                    updated_at: now,
                })
                .await
                .map_err(|error| error.to_string())?;
            if memory_repo
                .recall(
                    &MemoryRecallQuery::new(
                        "tenant-1",
                        "user-1",
                        "user",
                        None,
                        "office",
                        now,
                        10,
                    )
                    .map_err(|error| error.to_string())?,
                )
                .await
                .map_err(|error| error.to_string())?
                .len()
                != 1
            {
                return Err("memory recall 没有命中同 owner/scope/source fact".to_owned());
            }
            if memory_repo
                .delete_content(
                    "memory-1",
                    "somebody-else",
                    now + Duration::seconds(2),
                )
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("非 owner 删除了 memory".to_owned());
            }
            let deleted_memory = memory_repo
                .delete_content("memory-1", "user-1", now + Duration::seconds(2))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "owner 删除 memory 没命中".to_owned())?;
            if deleted_memory.status != "deleted" || deleted_memory.content.is_some() {
                return Err("memory 删除没有同写擦除 content".to_owned());
            }
            MemoryEventRepo::new(pool.clone())
                .insert(&memory_events::Row {
                    memory_id: "memory-1".to_owned(),
                    seq: 0,
                    event_type: "create".to_owned(),
                    actor_id: "user-1".to_owned(),
                    metadata: json!({"origin":"user_action"}),
                    created_at: now,
                })
                .await
                .map_err(|error| error.to_string())?;
            ImportCursorRepo::new(pool.clone())
                .insert(&intelligence_import_cursors::Row {
                    bundle_id: "bundle-1".to_owned(),
                    aggregate_kind: "thread".to_owned(),
                    deployment_id: "deployment-1".to_owned(),
                    cursor: "cursor-1".to_owned(),
                    last_hash: "a".repeat(64),
                    imported_count: 1,
                    status: "completed".to_owned(),
                    provenance: json!({"verified":true}),
                    updated_at: now,
                })
                .await
                .map_err(|error| error.to_string())?;

            let tool_fk = client
                .execute(
                    "INSERT INTO public.tool_calls(\
                       tool_call_id,run_id,call_seq,decision_id,actor_id,bot_id,tool_name,\
                       schema_hash,catalog_generation,args_hash,target_kind,target_id,effect,\
                       effect_downgraded,idempotency,approval_class,policy_version) \
                     VALUES('call-orphan','run-missing',0,'decision-orphan','user-1','bot-1',\
                       'tool','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',0,\
                       'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',\
                       'run','run-missing','read',false,'idempotent','not_required','pv-1')",
                    &[],
                )
                .await
                .expect_err("0016 后新 tool call 必须引用真实 run");
            if tool_fk.as_db_error().and_then(|error| error.constraint())
                != Some("tool_calls_run_id_fkey")
            {
                return Err("tool_calls staged FK 没约束新写".to_owned());
            }
            let deleted_thread = ThreadRepo::new(pool.clone())
                .soft_delete("thread-1", now + Duration::minutes(4))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "thread 软删除没命中".to_owned())?;
            if deleted_thread.status != "deleted"
                || deleted_thread.deleted_at.is_none()
                || message_repo
                    .find_by_id("message-1")
                    .await
                    .map_err(|error| error.to_string())?
                    .is_none()
            {
                return Err("thread 删除不是保留历史的软删除".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn two_replicas_apply_0013_through_0016_exactly_once() {
    let admin = admin_config("two_replicas_apply_0013_through_0016_exactly_once");
    with_temp_database(&admin, "native0016race", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                baseline::apply(&client)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            let mut first = pool.get().await.map_err(|error| error.to_string())?;
            let mut second = pool.get().await.map_err(|error| error.to_string())?;
            let (left, right) = tokio::join!(native::apply(&mut first), native::apply(&mut second));
            let mut outcomes = vec![
                left.map_err(|error| error.to_string())?,
                right.map_err(|error| error.to_string())?,
            ];
            outcomes.sort_by_key(|outcome| match outcome {
                ApplyOutcome::Applied => 0,
                ApplyOutcome::AlreadyApplied => 1,
            });
            if outcomes != vec![ApplyOutcome::Applied, ApplyOutcome::AlreadyApplied] {
                return Err(format!("并发 current migration 结果不符：{outcomes:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
