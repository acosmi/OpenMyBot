//! G3 outbox dispatch、fencing、semantic chunk、terminal/recovery 的 PostgreSQL 17 证据。

mod harness;

use std::sync::Arc;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    BeginThreadRunRequest, NoRunDispatchConsumer, ProviderBillingFamily, ProviderRateCard,
    ProviderRateCardInput, ProviderRemoteProjection, ProviderRemoteProjectionKind, ProviderUsage,
    RunExecutionLease, RunFailureCode, RunRuntime, RunRuntimeError, RunSemanticChannel,
    RunTerminal, RunTokenUsage, RunTokenUsageReceipt, ThreadDirectory,
};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_domain::thread::FencingToken;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use serde_json::{Value, json};
use time::macros::datetime;

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.users(id,email) VALUES('actor-a','a@example.test');
             INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user');
             INSERT INTO public.agents(id,name,type,configuration)
               VALUES('bot-1','Bot 1','built_in','{}'::jsonb);
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES('bot-1',NULL,'Bot 1','test role','seed','public',NULL);",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn request(deployment: &DeploymentId, entropy_tail: u64, run_id: &str) -> BeginThreadRunRequest {
    let mut entropy = [0_u8; 16];
    entropy[8..].copy_from_slice(&entropy_tail.to_be_bytes());
    BeginThreadRunRequest {
        auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
        deployment: deployment.clone(),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new("actor-a"),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            thread_id: ThreadIdentity::new(deployment).mint_from_entropy(entropy),
            run_id: RunId::new(run_id),
            bot_id: BotId::new("bot-1"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "hello runtime".to_owned(),
        },
    }
}

fn runtime(
    pool: &openbot_infra::db::pool::DatabasePool,
    owner: &str,
) -> Result<PostgresRunRuntime, String> {
    PostgresRunRuntime::new(
        pool.clone(),
        owner.to_owned(),
        DEFAULT_THREAD_LEASE_DURATION,
        DEFAULT_DISPATCH_CLAIM_DURATION,
    )
    .map_err(|error| error.to_string())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn provider_usage_is_run_wide_exact_replayable_and_budget_fenced() {
    let admin = admin_config("provider_usage_is_run_wide_exact_replayable_and_budget_fenced");
    with_temp_database(&admin, "runusage", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-usage");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-usage".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            directory
                .begin_thread_run(request(&deployment, 91, "run-usage"))
                .await
                .map_err(|error| error.to_string())?;
            let runtime = runtime(&pool, "runtime-usage")?;
            let claim = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("usage dispatch 未被 claim")?;
            let lease = runtime
                .acknowledge_dispatch(&claim)
                .await
                .map_err(|error| error.to_string())?;
            let rate_card = ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::OpenAiCompatible,
                model: "model-priced".to_owned(),
                currency: "USD".to_owned(),
                max_input_micro_units_per_million_tokens: 1_500_000,
                max_output_micro_units_per_million_tokens: 2_000_000,
                source_url: "https://prices.example.test/archive/2026-08-30".to_owned(),
                source_sha256: "a".repeat(64),
                observed_at: datetime!(2026-08-30 12:00 UTC),
            })
            .map_err(|error| error.to_string())?;
            let future_rate = ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::OpenAiCompatible,
                model: "model-priced".to_owned(),
                currency: "USD".to_owned(),
                max_input_micro_units_per_million_tokens: 1_500_000,
                max_output_micro_units_per_million_tokens: 2_000_000,
                source_url: "https://prices.example.test/future".to_owned(),
                source_sha256: "f".repeat(64),
                observed_at: datetime!(9999-01-01 0:00 UTC),
            })
            .map_err(|error| error.to_string())?;
            if runtime
                .record_provider_usage(
                    &lease,
                    0,
                    ProviderUsage {
                        input_tokens: 2,
                        output_tokens: 1,
                        total_tokens: 3,
                    },
                    Some(5),
                    Some(&future_rate),
                    None,
                )
                .await
                != Err(RunRuntimeError::InvalidInput {
                    field: "provider_rate_observed_at",
                })
            {
                return Err("future rate snapshot must fail before usage write".to_owned());
            }
            if runtime
                .record_provider_usage(
                    &lease,
                    0,
                    ProviderUsage {
                        input_tokens: 2,
                        output_tokens: 1,
                        total_tokens: 2,
                    },
                    Some(5),
                    Some(&rate_card),
                    None,
                )
                .await
                != Err(RunRuntimeError::InvalidInput {
                    field: "provider_usage",
                })
                || runtime
                    .record_provider_usage(
                        &lease,
                        0,
                        ProviderUsage {
                            input_tokens: 2,
                            output_tokens: 1,
                            total_tokens: 3,
                        },
                        Some(0),
                        Some(&rate_card),
                        None,
                    )
                    .await
                    != Err(RunRuntimeError::InvalidInput {
                        field: "provider_usage",
                    })
            {
                return Err("invalid usage/cap 必须在写入前拒绝".to_owned());
            }
            let first_usage = ProviderUsage {
                input_tokens: 10,
                output_tokens: 2,
                total_tokens: 12,
            };
            let first = RunTokenUsage {
                input_tokens: 10,
                output_tokens: 2,
                total_tokens: 12,
            };
            if runtime
                .record_provider_usage(&lease, 0, first_usage, Some(5), Some(&rate_card), None)
                .await
                .map_err(|error| error.to_string())?
                != RunTokenUsageReceipt::Recorded(first)
            {
                return Err("首个 sampling usage 未精确记录".to_owned());
            }
            if runtime
                .record_provider_usage(&lease, 0, first_usage, Some(5), Some(&rate_card), None)
                .await
                .map_err(|error| error.to_string())?
                != RunTokenUsageReceipt::Replayed(first)
            {
                return Err("同一 sampling usage 未精确回放".to_owned());
            }
            let exceeded = RunTokenUsage {
                input_tokens: 31,
                output_tokens: 6,
                total_tokens: 37,
            };
            if runtime
                .record_provider_usage(
                    &lease,
                    0,
                    ProviderUsage {
                        input_tokens: 10,
                        output_tokens: 1,
                        total_tokens: 11,
                    },
                    Some(5),
                    Some(&rate_card),
                    None,
                )
                .await
                != Err(RunRuntimeError::Conflict)
            {
                return Err("同 index 异值 usage 必须 conflict".to_owned());
            }
            if runtime
                .record_provider_usage(&lease, 2, first_usage, Some(5), Some(&rate_card), None)
                .await
                != Err(RunRuntimeError::Conflict)
            {
                return Err("跳号 sampling usage 必须 conflict".to_owned());
            }
            let second = RunTokenUsage {
                input_tokens: 30,
                output_tokens: 5,
                total_tokens: 35,
            };
            if runtime
                .record_provider_usage(
                    &lease,
                    1,
                    ProviderUsage {
                        input_tokens: 20,
                        output_tokens: 3,
                        total_tokens: 23,
                    },
                    Some(5),
                    Some(&rate_card),
                    None,
                )
                .await
                .map_err(|error| error.to_string())?
                != RunTokenUsageReceipt::Recorded(second)
            {
                return Err("第二个 sampling 未累加到 run aggregate".to_owned());
            }
            if runtime
                .record_provider_usage(
                    &lease,
                    2,
                    ProviderUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        total_tokens: 2,
                    },
                    Some(5),
                    Some(&rate_card),
                    None,
                )
                .await
                .map_err(|error| error.to_string())?
                != RunTokenUsageReceipt::BudgetExceeded(exceeded)
            {
                return Err("跨 sampling output ceiling 未 fail closed".to_owned());
            }
            if runtime
                .record_provider_usage(
                    &lease,
                    2,
                    ProviderUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        total_tokens: 2,
                    },
                    Some(5),
                    Some(&rate_card),
                    None,
                )
                .await
                .map_err(|error| error.to_string())?
                != RunTokenUsageReceipt::BudgetExceeded(exceeded)
            {
                return Err("超预算 sampling 未精确回放同一结论".to_owned());
            }
            if runtime
                .record_provider_usage(
                    &lease,
                    3,
                    ProviderUsage {
                        input_tokens: 1,
                        output_tokens: 0,
                        total_tokens: 1,
                    },
                    Some(6),
                    Some(&rate_card),
                    None,
                )
                .await
                != Err(RunRuntimeError::Conflict)
            {
                return Err("已固定 run ceiling 不得漂移".to_owned());
            }
            let changed_rate = ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::OpenAiCompatible,
                model: "model-priced".to_owned(),
                currency: "USD".to_owned(),
                max_input_micro_units_per_million_tokens: 1_500_001,
                max_output_micro_units_per_million_tokens: 2_000_000,
                source_url: "https://prices.example.test/archive/2026-08-30".to_owned(),
                source_sha256: "b".repeat(64),
                observed_at: datetime!(2026-08-30 12:00 UTC),
            })
            .map_err(|error| error.to_string())?;
            if runtime
                .record_provider_usage(
                    &lease,
                    3,
                    ProviderUsage {
                        input_tokens: 1,
                        output_tokens: 0,
                        total_tokens: 1,
                    },
                    Some(5),
                    Some(&changed_rate),
                    None,
                )
                .await
                != Err(RunRuntimeError::Conflict)
            {
                return Err("已固定 provider rate snapshot 不得漂移".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT budget_max_output_tokens,usage_input_tokens,usage_output_tokens, \
                            usage_total_tokens,usage_next_sampling,usage_last_sampling \
                     FROM public.runs WHERE run_id='run-usage'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let facts: (Option<i64>, i64, i64, i64, i32, Option<i32>) = (
                row.try_get(0).map_err(|error| error.to_string())?,
                row.try_get(1).map_err(|error| error.to_string())?,
                row.try_get(2).map_err(|error| error.to_string())?,
                row.try_get(3).map_err(|error| error.to_string())?,
                row.try_get(4).map_err(|error| error.to_string())?,
                row.try_get(5).map_err(|error| error.to_string())?,
            );
            if facts != (Some(5), 31, 6, 37, 3, Some(2)) {
                return Err(format!("durable run usage 漂移：{facts:?}"));
            }
            let cost_row = client
                .query_one(
                    "SELECT cost_currency,cost_provider,cost_model, \
                            cost_max_input_micro_units_per_million_tokens, \
                            cost_max_output_micro_units_per_million_tokens,cost_source_sha256, \
                            cost_observed_at,usage_cost_upper_bound_micro_units, \
                            usage_cost_upper_bound_remainder_millionths \
                     FROM public.runs WHERE run_id='run-usage'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let cost: (
                String,
                String,
                String,
                i64,
                i64,
                String,
                time::OffsetDateTime,
                i64,
                i32,
            ) = (
                cost_row.try_get(0).map_err(|error| error.to_string())?,
                cost_row.try_get(1).map_err(|error| error.to_string())?,
                cost_row.try_get(2).map_err(|error| error.to_string())?,
                cost_row.try_get(3).map_err(|error| error.to_string())?,
                cost_row.try_get(4).map_err(|error| error.to_string())?,
                cost_row.try_get(5).map_err(|error| error.to_string())?,
                cost_row.try_get(6).map_err(|error| error.to_string())?,
                cost_row.try_get(7).map_err(|error| error.to_string())?,
                cost_row.try_get(8).map_err(|error| error.to_string())?,
            );
            if cost
                != (
                    "USD".to_owned(),
                    "openai_compatible".to_owned(),
                    "model-priced".to_owned(),
                    1_500_000,
                    2_000_000,
                    "a".repeat(64),
                    datetime!(2026-08-30 12:00 UTC),
                    58,
                    500_000,
                )
            {
                return Err(format!("durable run provider cost 漂移：{cost:?}"));
            }
            runtime
                .finish_run(
                    &lease,
                    1,
                    RunTerminal::Failed(RunFailureCode::RunTokenBudgetExceeded),
                )
                .await
                .map_err(|error| error.to_string())?;
            let terminal: (String, Option<String>) = client
                .query_one(
                    "SELECT status,error_code FROM public.runs WHERE run_id='run-usage'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())
                .and_then(|row| {
                    Ok((
                        row.try_get(0).map_err(|error| error.to_string())?,
                        row.try_get(1).map_err(|error| error.to_string())?,
                    ))
                })?;
            if terminal
                != (
                    "failed".to_owned(),
                    Some("run_token_budget_exceeded".to_owned()),
                )
            {
                return Err(format!("run budget terminal code 漂移：{terminal:?}"));
            }
            if runtime
                .record_provider_usage(&lease, 3, first_usage, Some(5), Some(&rate_card), None)
                .await
                != Err(RunRuntimeError::StaleLease)
            {
                return Err("terminal run 必须拒绝后续 usage".to_owned());
            }
            directory
                .begin_thread_run(request(&deployment, 92, "run-unpriced"))
                .await
                .map_err(|error| error.to_string())?;
            let claim = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("unpriced dispatch 未被 claim")?;
            let unpriced_lease = runtime
                .acknowledge_dispatch(&claim)
                .await
                .map_err(|error| error.to_string())?;
            runtime
                .record_provider_usage(&unpriced_lease, 0, first_usage, Some(5), None, None)
                .await
                .map_err(|error| error.to_string())?;
            let unpriced_is_null: bool = client
                .query_one(
                    "SELECT cost_currency IS NULL AND cost_provider IS NULL \
                            AND cost_model IS NULL AND usage_cost_upper_bound_micro_units IS NULL \
                            AND usage_cost_upper_bound_remainder_millionths IS NULL \
                     FROM public.runs WHERE run_id='run-unpriced'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if !unpriced_is_null {
                return Err("缺 rate card 必须保持 unpriced/null，不能静默记零".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn claim_chunk_terminal_are_exact_and_materialize_one_assistant_message() {
    let admin =
        admin_config("claim_chunk_terminal_are_exact_and_materialize_one_assistant_message");
    with_temp_database(&admin, "runruntime", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-a".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let request = request(&deployment, 1, "run-1");
            directory
                .begin_thread_run(request.clone())
                .await
                .map_err(|error| error.to_string())?;

            let runtime = runtime(&pool, "runtime-a")?;
            let first = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("dispatch 未被 claim")?;
            let replayed_claim = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("owned claim 未被精确恢复")?;
            if first != replayed_claim || first.attempt() != 1 {
                return Err(format!(
                    "claim commit reconciliation 漂移：{first:?}/{replayed_claim:?}"
                ));
            }
            let lease = runtime
                .acknowledge_dispatch(&first)
                .await
                .map_err(|error| error.to_string())?;
            let ack_replay = runtime
                .acknowledge_dispatch(&first)
                .await
                .map_err(|error| error.to_string())?;
            if lease != ack_replay || lease.next_event_sequence() != 1 {
                return Err(format!(
                    "dispatch ack replay 漂移：{lease:?}/{ack_replay:?}"
                ));
            }

            let one = runtime
                .append_semantic_chunk(&lease, 1, RunSemanticChannel::Text, "hello ")
                .await
                .map_err(|error| error.to_string())?;
            let one_replay = runtime
                .append_semantic_chunk(&lease, 1, RunSemanticChannel::Text, "hello ")
                .await
                .map_err(|error| error.to_string())?;
            if one.replayed || !one_replay.replayed || one.thread_event_sequence != 1 {
                return Err(format!("chunk exact replay 漂移：{one:?}/{one_replay:?}"));
            }
            if runtime
                .append_semantic_chunk(&lease, 1, RunSemanticChannel::Text, "tampered")
                .await
                != Err(RunRuntimeError::Conflict)
            {
                return Err("相同 sequence 不同 chunk 必须 conflict".to_owned());
            }
            runtime
                .renew_lease(&lease)
                .await
                .map_err(|error| error.to_string())?;
            runtime
                .append_semantic_chunk(
                    &lease,
                    2,
                    RunSemanticChannel::Reasoning,
                    "REASONING_RETENTION_CANARY",
                )
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let active_reasoning: Value = client
                .query_one(
                    "SELECT payload FROM public.run_events WHERE run_id='run-1' AND seq=2",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if active_reasoning
                != json!({
                    "channel":"reasoning",
                    "delta":"REASONING_RETENTION_CANARY"
                })
            {
                return Err(format!(
                    "active run reasoning must remain replayable: {active_reasoning}"
                ));
            }
            drop(client);
            let projection = ProviderRemoteProjection::new(
                ProviderRemoteProjectionKind::Raw,
                Some("remote".to_owned()),
                None,
                json!({"permission":"forged-admin","canary":"REMOTE_PROJECTION_CANARY"}),
            )
            .map_err(|error| error.to_string())?;
            let projection_write = runtime
                .append_remote_projection(&lease, 3, &projection)
                .await
                .map_err(|error| error.to_string())?;
            let projection_replay = runtime
                .append_remote_projection(&lease, 3, &projection)
                .await
                .map_err(|error| error.to_string())?;
            if projection_write.replayed || !projection_replay.replayed {
                return Err(format!(
                    "remote projection exact replay drifted: {projection_write:?}/{projection_replay:?}"
                ));
            }
            let tampered_projection = ProviderRemoteProjection::new(
                ProviderRemoteProjectionKind::Raw,
                Some("remote".to_owned()),
                None,
                json!({"permission":"forged-admin","canary":"tampered"}),
            )
            .map_err(|error| error.to_string())?;
            if runtime
                .append_remote_projection(&lease, 3, &tampered_projection)
                .await
                != Err(RunRuntimeError::Conflict)
            {
                return Err("same sequence with different remote projection must conflict".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let active_projection: Value = client
                .query_one(
                    "SELECT payload FROM public.run_events WHERE run_id='run-1' AND seq=3",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if &active_projection != projection.journal_payload() {
                return Err(format!(
                    "active remote projection must remain replayable: {active_projection}"
                ));
            }
            drop(client);
            runtime
                .append_semantic_chunk(&lease, 4, RunSemanticChannel::Text, "world")
                .await
                .map_err(|error| error.to_string())?;
            let terminal = runtime
                .finish_run(&lease, 5, RunTerminal::Completed)
                .await
                .map_err(|error| error.to_string())?;
            let terminal_replay = runtime
                .finish_run(&lease, 5, RunTerminal::Completed)
                .await
                .map_err(|error| error.to_string())?;
            if terminal.replayed
                || !terminal_replay.replayed
                || terminal.message_sequence != Some(1)
                || terminal.thread_event_sequence != 5
            {
                return Err(format!(
                    "terminal receipt 漂移：{terminal:?}/{terminal_replay:?}"
                ));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let shape = client
                .query_one(
                    "SELECT r.status,r.next_event_seq,r.terminal_event_seq,r.error_code,
                            t.next_message_seq,t.next_event_seq,o.status,
                            (SELECT count(*)::bigint FROM public.run_events WHERE run_id=r.run_id),
                            (SELECT count(*)::bigint FROM public.messages
                             WHERE run_id=r.run_id AND role='assistant'),
                            (SELECT content->>'text' FROM public.messages
                             WHERE run_id=r.run_id AND role='assistant')
                     FROM public.runs r
                     JOIN public.threads t ON t.thread_id=r.thread_id
                     JOIN public.outbox o ON o.outbox_id=r.run_id || ':agent_run_dispatch'
                     WHERE r.run_id='run-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let actual = (
                shape
                    .try_get::<_, String>(0)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, i64>(1)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, Option<i64>>(2)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, Option<String>>(3)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, i64>(4)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, i64>(5)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, String>(6)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, i64>(7)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, i64>(8)
                    .map_err(|error| error.to_string())?,
                shape
                    .try_get::<_, String>(9)
                    .map_err(|error| error.to_string())?,
            );
            if actual
                != (
                    "completed".to_owned(),
                    6,
                    Some(5),
                    None,
                    2,
                    6,
                    "delivered".to_owned(),
                    6,
                    1,
                    "hello world".to_owned(),
                )
            {
                return Err(format!("run terminal durable shape 漂移：{actual:?}"));
            }
            let reasoning = client
                .query_one(
                    "SELECT payload,payload::text LIKE '%REASONING_RETENTION_CANARY%' \
                     FROM public.run_events \
                     WHERE run_id='run-1' AND event_type='semantic_chunk' \
                       AND payload->>'channel'='reasoning'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let scrubbed: Value = reasoning.try_get(0).map_err(|error| error.to_string())?;
            let leaked: bool = reasoning.try_get(1).map_err(|error| error.to_string())?;
            if scrubbed != json!({"channel":"reasoning","delta":"","retained":false}) || leaked {
                return Err(format!(
                    "terminal reasoning retention boundary drifted: {scrubbed}/{leaked}"
                ));
            }
            let remote_projection = client
                .query_one(
                    "SELECT payload,payload::text LIKE '%REMOTE_PROJECTION_CANARY%' \
                     FROM public.run_events \
                     WHERE run_id='run-1' AND event_type='checkpoint' \
                       AND payload->>'kind'='remote_agui_projection'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let projection_marker: Value = remote_projection
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let projection_leaked: bool = remote_projection
                .try_get(1)
                .map_err(|error| error.to_string())?;
            if projection_marker
                != json!({
                    "kind":"remote_agui_projection",
                    "source":"remote_ag_ui",
                    "retained":false,
                    "untrusted":true
                })
                || projection_leaked
            {
                return Err(format!(
                    "terminal remote projection retention drifted: {projection_marker}/{projection_leaked}"
                ));
            }
            if runtime
                .append_semantic_chunk(&lease, 6, RunSemanticChannel::Text, "late")
                .await
                != Err(RunRuntimeError::Conflict)
            {
                return Err("terminal 后旧 writer 不得追加".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "DELETE FROM public.messages WHERE run_id='run-1' AND role='assistant'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if runtime.finish_run(&lease, 5, RunTerminal::Completed).await
                != Err(RunRuntimeError::Corrupt {
                    field: "terminal_assistant_message",
                })
            {
                return Err("terminal replay 不得隐藏丢失的 assistant materialization".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn expired_unaccepted_dispatch_rebinds_but_delivered_stale_run_reconciles() {
    let admin =
        admin_config("expired_unaccepted_dispatch_rebinds_but_delivered_stale_run_reconciles");
    with_temp_database(&admin, "runrecovery", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-a".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let request = request(&deployment, 2, "run-2");
            directory
                .begin_thread_run(request.clone())
                .await
                .map_err(|error| error.to_string())?;
            let old_lease = RunExecutionLease::new(
                RunId::new("run-2"),
                request.command.thread_id.clone(),
                BotId::new("bot-1"),
                ActorId::new("actor-a"),
                FencingToken::new(1).unwrap(),
                1,
            )
            .map_err(|error| error.to_string())?;

            expire_lease(&pool, request.command.thread_id.as_str()).await?;
            let runtime_b = runtime(&pool, "runtime-b")?;
            let claim = runtime_b
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("过期未受理 dispatch 没有被接管")?;
            if claim.lease().fencing().get() != 2 {
                return Err(format!("安全接管必须 fencing 1→2：{claim:?}"));
            }
            let runtime_a = runtime(&pool, "runtime-a")?;
            if runtime_a
                .append_semantic_chunk(&old_lease, 1, RunSemanticChannel::Text, "stale")
                .await
                != Err(RunRuntimeError::StaleLease)
            {
                return Err("旧 fencing writer 必须拒绝".to_owned());
            }
            let lease_b = runtime_b
                .acknowledge_dispatch(&claim)
                .await
                .map_err(|error| error.to_string())?;
            expire_lease(&pool, request.command.thread_id.as_str()).await?;
            let runtime_c = runtime(&pool, "runtime-c")?;
            let recovered = runtime_c
                .recover_one_stale_run()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("delivered stale run 未进入 recovery")?;
            if recovered.run_event_sequence != 1 || recovered.thread_event_sequence != 1 {
                return Err(format!("recovery sequence 漂移：{recovered:?}"));
            }
            if runtime_b
                .append_semantic_chunk(&lease_b, 1, RunSemanticChannel::Text, "late")
                .await
                != Err(RunRuntimeError::StaleLease)
            {
                return Err("recovery 后旧 runtime 必须 fencing 失效".to_owned());
            }
            if runtime_c
                .recover_one_stale_run()
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("同一 stale run 不得生成第二 terminal".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT status,error_code,terminal_event_seq,fencing_token FROM public.runs
                     WHERE run_id='run-2'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let actual: (String, Option<String>, Option<i64>, i64) = (
                row.try_get(0).map_err(|error| error.to_string())?,
                row.try_get(1).map_err(|error| error.to_string())?,
                row.try_get(2).map_err(|error| error.to_string())?,
                row.try_get(3).map_err(|error| error.to_string())?,
            );
            if actual
                != (
                    "reconciliation_required".to_owned(),
                    Some("runtime_lease_expired".to_owned()),
                    Some(1),
                    3,
                )
            {
                return Err(format!("stale recovery durable shape 漂移：{actual:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn rejected_dispatch_terminal_and_outbox_ack_share_one_transaction() {
    let admin = admin_config("rejected_dispatch_terminal_and_outbox_ack_share_one_transaction");
    with_temp_database(&admin, "runreject", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-a".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            directory
                .begin_thread_run(request(&deployment, 3, "run-3"))
                .await
                .map_err(|error| error.to_string())?;
            let runtime = runtime(&pool, "runtime-a")?;
            let claim = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("dispatch 未 claim")?;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "CREATE FUNCTION fail_dispatch_delivery() RETURNS trigger LANGUAGE plpgsql AS $$
                       BEGIN
                         IF NEW.status='delivered' THEN RAISE EXCEPTION 'forced outbox failure'; END IF;
                         RETURN NEW;
                       END $$;
                     CREATE TRIGGER fail_dispatch_delivery_trigger BEFORE UPDATE ON public.outbox
                       FOR EACH ROW EXECUTE FUNCTION fail_dispatch_delivery();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if runtime
                .reject_dispatch(&claim, RunFailureCode::AgentRuntimeUnavailable)
                .await
                != Err(RunRuntimeError::Unavailable)
            {
                return Err("末段 outbox 失败必须显式返回且不能伪装 terminal success".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let rolled_back = client
                .query_one(
                    "SELECT r.status,(SELECT count(*)::bigint FROM public.run_events
                                      WHERE run_id=r.run_id),o.status
                     FROM public.runs r JOIN public.outbox o
                       ON o.outbox_id=r.run_id || ':agent_run_dispatch'
                     WHERE r.run_id='run-3'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let actual: (String, i64, String) = (
                rolled_back.try_get(0).map_err(|error| error.to_string())?,
                rolled_back.try_get(1).map_err(|error| error.to_string())?,
                rolled_back.try_get(2).map_err(|error| error.to_string())?,
            );
            if actual != ("running".to_owned(), 1, "delivering".to_owned()) {
                return Err(format!("reject rollback 不完整：{actual:?}"));
            }
            client
                .batch_execute(
                    "DROP TRIGGER fail_dispatch_delivery_trigger ON public.outbox;
                     DROP FUNCTION fail_dispatch_delivery();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let receipt = runtime
                .reject_dispatch(&claim, RunFailureCode::AgentRuntimeUnavailable)
                .await
                .map_err(|error| error.to_string())?;
            if receipt.run_event_sequence != 1 || receipt.message_sequence.is_some() {
                return Err(format!("确定拒绝 terminal receipt 漂移：{receipt:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let final_row = client
                .query_one(
                    "SELECT r.status,r.error_code,o.status,o.last_error_code
                     FROM public.runs r JOIN public.outbox o
                       ON o.outbox_id=r.run_id || ':agent_run_dispatch'
                     WHERE r.run_id='run-3'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let final_shape: (String, Option<String>, String, Option<String>) = (
                final_row.try_get(0).map_err(|error| error.to_string())?,
                final_row.try_get(1).map_err(|error| error.to_string())?,
                final_row.try_get(2).map_err(|error| error.to_string())?,
                final_row.try_get(3).map_err(|error| error.to_string())?,
            );
            if final_shape
                != (
                    "failed".to_owned(),
                    Some("agent_runtime_unavailable".to_owned()),
                    "delivered".to_owned(),
                    Some("agent_runtime_unavailable".to_owned()),
                )
            {
                return Err(format!("reject final shape 漂移：{final_shape:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn production_relay_fail_closed_consumer_never_leaves_a_fake_running_run() {
    let admin =
        admin_config("production_relay_fail_closed_consumer_never_leaves_a_fake_running_run");
    with_temp_database(&admin, "runrelay", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-a".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            directory
                .begin_thread_run(request(&deployment, 4, "run-4"))
                .await
                .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(runtime(&pool, "runtime-a")?);
            let relay = RunRelay::start(runtime, Arc::new(NoRunDispatchConsumer));

            let mut observed = None;
            for _ in 0..80 {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                let row = client
                    .query_one(
                        "SELECT r.status,r.error_code,o.status FROM public.runs r
                         JOIN public.outbox o ON o.outbox_id=r.run_id || ':agent_run_dispatch'
                         WHERE r.run_id='run-4'",
                        &[],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let shape: (String, Option<String>, String) = (
                    row.try_get(0).map_err(|error| error.to_string())?,
                    row.try_get(1).map_err(|error| error.to_string())?,
                    row.try_get(2).map_err(|error| error.to_string())?,
                );
                if shape.0 != "running" {
                    observed = Some(shape);
                    break;
                }
                tokio::time::sleep(core::time::Duration::from_millis(25)).await;
            }
            relay.stop().await;
            if observed
                != Some((
                    "failed".to_owned(),
                    Some("agent_runtime_unavailable".to_owned()),
                    "delivered".to_owned(),
                ))
            {
                return Err(format!(
                    "fail-closed relay durable shape 漂移：{observed:?}"
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

async fn expire_lease(
    pool: &openbot_infra::db::pool::DatabasePool,
    thread_id: &str,
) -> Result<(), String> {
    let client = pool.get().await.map_err(|error| error.to_string())?;
    client
        .execute(
            "UPDATE public.thread_leases SET acquired_at=now()-interval '10 seconds',
             expires_at=now()-interval '1 second',updated_at=now()-interval '1 second'
             WHERE thread_id=$1",
            &[&thread_id],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}
