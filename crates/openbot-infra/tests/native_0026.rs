//! Native 0026 actor-scoped per-run cost-cap PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    BeginThreadRunRequest, ProviderBillingFamily, ProviderRateCard, ProviderRateCardInput,
    ProviderUsage, RunCostBudgetAdministration, RunCostCap, RunRuntime, RunRuntimeError,
    RunTokenUsage, RunTokenUsageReceipt, ThreadDirectory,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::{baseline, pool, schema_facts};
use openbot_infra::run_cost_budget::PostgresRunCostBudgetAdministration;
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use time::macros::datetime;

const POST_0025: &str = include_str!("../../../fixtures/db/schema-0025.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture must be valid")
}

fn post_0026_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/db/schema-0026.json")
}

fn auth(deployment: &str, tenant: &str) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(deployment),
        TenantId::new(tenant),
        ActorId::new("budget-owner"),
        AuthGeneration::new(1),
        false,
    )
    .with_role(Role::User)
    .build()
}

fn request(deployment: &DeploymentId, entropy_tail: u64, run_id: &str) -> BeginThreadRunRequest {
    let mut entropy = [0_u8; 16];
    entropy[8..].copy_from_slice(&entropy_tail.to_be_bytes());
    BeginThreadRunRequest {
        auth_generation: openbot_contracts::auth::AuthGeneration::new(1),
        deployment: deployment.clone(),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new("budget-owner"),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            thread_id: ThreadIdentity::new(deployment).mint_from_entropy(entropy),
            run_id: RunId::new(run_id),
            bot_id: BotId::new("bot-budget"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "hello budget".to_owned(),
        },
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0026_is_exact_expand_only_user_run_cost_budget_schema() {
    let admin = admin_config("post_0026_is_exact_expand_only_user_run_cost_budget_schema");
    with_temp_database(&admin, "native0026facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0025_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0025) {
                return Err("0026 prerequisite fixture drift".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0026_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("0026 should apply exactly once".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0026").is_some() {
                let mut encoded =
                    serde_json::to_string_pretty(&after).map_err(|error| error.to_string())?;
                encoded.push('\n');
                std::fs::write(post_0026_path(), encoded).map_err(|error| error.to_string())?;
                return Ok(());
            }
            let expected = std::fs::read_to_string(post_0026_path())
                .map_err(|error| format!("schema-0026 fixture missing: {error}"))?;
            if after != facts(&expected) {
                return Err("0026 live schema differs from fixture".to_owned());
            }
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0026 dropped table {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!(
                            "0026 rewrote old column {}.{}",
                            old.name, column.name
                        ));
                    }
                }
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
            if ledger != 14 {
                return Err(format!("native ledger expected 14, got {ledger}"));
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
async fn actor_budget_is_scoped_frozen_per_run_and_fences_cost_upper_bound() {
    let admin = admin_config("actor_budget_is_scoped_frozen_per_run_and_fences_cost_upper_bound");
    with_temp_database(&admin, "native0026runtime", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,auth_generation)
                       VALUES('budget-owner','budget-owner@example.test',1);
                     INSERT INTO public.user_roles(user_id,role) VALUES('budget-owner','user');
                     INSERT INTO public.agents(id,name,type,configuration)
                       VALUES('bot-budget','Budget Bot','built_in','{}'::jsonb);
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                     ) VALUES(
                       'bot-budget',NULL,'Budget Bot','test role','seed','public',NULL
                     );",
                )
                .await
                .map_err(|error| error.to_string())?;

            let store = PostgresRunCostBudgetAdministration::new(pool.clone());
            let owner = auth("dep-budget", "tenant-a");
            let usd_cap = RunCostCap::new("USD".to_owned(), 10)
                .map_err(|error| error.to_string())?;
            if store.get(&owner).await.map_err(|error| error.to_string())?.is_some() {
                return Err("unset actor budget must be absent".to_owned());
            }
            if store
                .replace(&owner, Some(usd_cap.clone()))
                .await
                .map_err(|error| error.to_string())?
                != Some(usd_cap.clone())
            {
                return Err("budget replacement did not return committed value".to_owned());
            }
            for other in [auth("dep-other", "tenant-a"), auth("dep-budget", "tenant-b")] {
                if store.get(&other).await.map_err(|error| error.to_string())?.is_some() {
                    return Err("cross-scope budget became visible".to_owned());
                }
            }

            let deployment = DeploymentId::new("dep-budget");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                "runtime-budget".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            directory
                .begin_thread_run(request(&deployment, 1, "run-budget"))
                .await
                .map_err(|error| error.to_string())?;
            let snapshot: (Option<String>, Option<i64>) = client
                .query_one(
                    "SELECT budget_cost_currency,budget_max_cost_micro_units \
                     FROM public.runs WHERE run_id='run-budget'",
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
            if snapshot != (Some("USD".to_owned()), Some(10)) {
                return Err(format!("run did not freeze actor budget: {snapshot:?}"));
            }
            let eur_cap = RunCostCap::new("EUR".to_owned(), 999)
                .map_err(|error| error.to_string())?;
            store
                .replace(&owner, Some(eur_cap))
                .await
                .map_err(|error| error.to_string())?;
            let unchanged: (Option<String>, Option<i64>) = client
                .query_one(
                    "SELECT budget_cost_currency,budget_max_cost_micro_units \
                     FROM public.runs WHERE run_id='run-budget'",
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
            if unchanged != snapshot {
                return Err("preference update drifted an existing run".to_owned());
            }

            let runtime = PostgresRunRuntime::new(
                pool.clone(),
                "runtime-budget".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
                DEFAULT_DISPATCH_CLAIM_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let claim = runtime
                .claim_dispatch()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("budget dispatch not claimed")?;
            let lease = runtime
                .acknowledge_dispatch(&claim)
                .await
                .map_err(|error| error.to_string())?;
            let usd_rate = ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::OpenAiCompatible,
                model: "model-budget".to_owned(),
                currency: "USD".to_owned(),
                max_input_micro_units_per_million_tokens: 2_000_000,
                max_output_micro_units_per_million_tokens: 0,
                source_url: "https://prices.example.test/archive/2026-08-30".to_owned(),
                source_sha256: "d".repeat(64),
                observed_at: datetime!(2026-08-30 12:00 UTC),
            })
            .map_err(|error| error.to_string())?;
            let usage = ProviderUsage {
                input_tokens: 6,
                output_tokens: 0,
                total_tokens: 6,
            };
            let aggregate = RunTokenUsage {
                input_tokens: 6,
                output_tokens: 0,
                total_tokens: 6,
            };
            if runtime
                .record_provider_usage(
                    &lease,
                    0,
                    usage,
                    Some(9),
                    Some(&usd_rate),
                    Some(&RunCostCap::new("EUR".to_owned(), 10).unwrap()),
                )
                .await
                != Err(RunRuntimeError::InvalidInput {
                    field: "run_cost_budget",
                })
            {
                return Err("wrong-currency cap must fail before a usage write".to_owned());
            }
            if runtime
                .record_provider_usage(
                    &lease,
                    0,
                    usage,
                    Some(9),
                    Some(&usd_rate),
                    Some(&RunCostCap::new("USD".to_owned(), 11).unwrap()),
                )
                .await
                != Err(RunRuntimeError::Conflict)
            {
                return Err("caller cap drift must conflict with the frozen run".to_owned());
            }
            if runtime
                .record_provider_usage(
                    &lease,
                    0,
                    usage,
                    Some(9),
                    Some(&usd_rate),
                    Some(&usd_cap),
                )
                .await
                .map_err(|error| error.to_string())?
                != RunTokenUsageReceipt::CostBudgetExceeded(aggregate)
            {
                return Err("cost upper bound did not stop at the frozen cap".to_owned());
            }
            if runtime
                .record_provider_usage(
                    &lease,
                    0,
                    usage,
                    Some(9),
                    Some(&usd_rate),
                    Some(&usd_cap),
                )
                .await
                .map_err(|error| error.to_string())?
                != RunTokenUsageReceipt::CostBudgetExceeded(aggregate)
            {
                return Err("cost-cap overage did not exact-replay".to_owned());
            }
            let cost: (i64, i32) = client
                .query_one(
                    "SELECT usage_cost_upper_bound_micro_units, \
                            usage_cost_upper_bound_remainder_millionths \
                     FROM public.runs WHERE run_id='run-budget'",
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
            if cost != (12, 0) {
                return Err(format!("durable cost upper bound drifted: {cost:?}"));
            }

            store
                .replace(&owner, None)
                .await
                .map_err(|error| error.to_string())?;
            if store.get(&owner).await.map_err(|error| error.to_string())?.is_some() {
                return Err("cap null did not delete the preference".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
