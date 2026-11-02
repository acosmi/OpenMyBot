//! Native 0021 actor-scoped UI preference PostgreSQL 17 evidence.

#![cfg(feature = "server-runtime")]

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::UiPreferenceAdministration;
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::{baseline, pool, schema_facts};
use openbot_infra::ui_preferences::PostgresUiPreferenceAdministration;

const POST_0020: &str = include_str!("../../../fixtures/db/schema-0020.json");
const POST_0021: &str = include_str!("../../../fixtures/db/schema-0021.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture must be valid")
}

fn auth(deployment: &str, tenant: &str) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(deployment),
        TenantId::new(tenant),
        ActorId::new("preference-owner"),
        AuthGeneration::new(1),
        false,
    )
    .with_role(Role::User)
    .build()
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0021_is_exact_expand_only_ui_preference_schema() {
    let admin = admin_config("post_0021_is_exact_expand_only_ui_preference_schema");
    with_temp_database(&admin, "native0021facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0020_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0020) {
                return Err("0021 prerequisite fixture drift".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0021_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("0021 should apply exactly once".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0021").is_some() {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/db/schema-0021.json");
                let mut encoded =
                    serde_json::to_string_pretty(&after).map_err(|error| error.to_string())?;
                encoded.push('\n');
                std::fs::write(path, encoded).map_err(|error| error.to_string())?;
                return Ok(());
            }
            if after != facts(POST_0021) {
                return Err("0021 live schema differs from fixture".to_owned());
            }
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0021 dropped table {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!(
                            "0021 rewrote old column {}.{}",
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
            if ledger != 9 {
                return Err(format!("native ledger expected 9, got {ledger}"));
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
async fn partial_updates_merge_atomically_and_scope_by_actor_tenant_deployment() {
    let admin =
        admin_config("partial_updates_merge_atomically_and_scope_by_actor_tenant_deployment");
    with_temp_database(&admin, "native0021runtime", |config| async move {
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
                       VALUES('preference-owner','preference-owner@example.test',1);
                     INSERT INTO public.user_roles(user_id,role)
                       VALUES('preference-owner','user');",
                )
                .await
                .map_err(|error| error.to_string())?;

            let store = PostgresUiPreferenceAdministration::new(pool.clone(),DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),openbot_domain::vault::SecretBytes::new(vec![0x21;32]))
                .map_err(|error|error.to_string())?;
            let owner = auth("deployment-a", "tenant-a");
            if store.get(&owner).await.map_err(|error| error.to_string())?
                != UiPreferences::default()
            {
                return Err("unset preferences must preserve host fallback".to_owned());
            }
            // The original partial-field semantics survive only after an exact CAS.
            // Historical concurrent upsert evidence is retained under its original identity.
            let theme=store.update(&owner,UpdateUiPreferences {
                theme:Some(UiTheme::Dark),locale:None,expected_revision:None,
            }).await.map_err(|error|error.to_string())?;
            let locale=store.update(&owner,UpdateUiPreferences {
                theme:None,locale:Some(UiLocale::ZhCn),expected_revision:theme.revision,
            }).await.map_err(|error|error.to_string())?;
            let stored=store.get(&owner).await.map_err(|error|error.to_string())?;
            if stored.theme!=Some(UiTheme::Dark) || stored.locale!=Some(UiLocale::ZhCn)
                || stored.revision!=Some(2) || stored!=locale {
                return Err(format!("authorized partial updates did not preserve values: {stored:?}"));
            }
            for other in [auth("deployment-b","tenant-a"),auth("deployment-a","tenant-b")] {
                if store.get(&other).await != Err(openbot_application::UiPreferenceAdministrationError::NotVisible) {
                    return Err("host scope mismatch must not expose preferences".to_owned());
                }
                let scoped=PostgresUiPreferenceAdministration::new(pool.clone(),other.deployment().clone(),
                    other.tenant().clone(),openbot_domain::vault::SecretBytes::new(vec![0x21;32]))
                    .map_err(|error|error.to_string())?;
                if scoped.get(&other).await.map_err(|error|error.to_string())?!=UiPreferences::default() {
                    return Err("cross-scope preference became visible".to_owned());
                }
            }

            for invalid in [
                "INSERT INTO public.user_ui_preferences(deployment_id,tenant_id,actor_user_id)
                   VALUES('bad-empty','tenant','preference-owner')",
                "INSERT INTO public.user_ui_preferences(deployment_id,tenant_id,actor_user_id,theme)
                   VALUES('bad-theme','tenant','preference-owner','sepia')",
                "INSERT INTO public.user_ui_preferences(deployment_id,tenant_id,actor_user_id,locale)
                   VALUES('bad-locale','tenant','preference-owner','zh')",
            ] {
                client
                    .execute(invalid, &[])
                    .await
                    .expect_err("invalid UI preference row must be rejected");
            }

            client
                .execute("DELETE FROM public.users WHERE id='preference-owner'", &[])
                .await
                .map_err(|error| error.to_string())?;
            let remaining: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.user_ui_preferences",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if remaining != 0 {
                return Err("actor deletion did not cascade UI preferences".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
