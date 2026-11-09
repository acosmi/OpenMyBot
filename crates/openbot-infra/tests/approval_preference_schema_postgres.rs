//! Internal preference schema checks against caller-owned disposable PostgreSQL.
//!
//! Raw fixture INSERT/UPDATE statements exercise storage constraints and immutable identity.
//! They are not a repository, a caller expected-revision CAS, a permission observation, a
//! same-transaction audit producer, or evidence of an operation's commit/deadline/physical close.

mod harness;

use openbot_contracts::approval_preferences::RememberPreferenceKey;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_infra::db::approval_preference_schema::{self, ApprovalPreferenceSchemaError};
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, fresh, native, pool, schema_facts};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tokio_postgres::Client;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

const TABLE: &str = "openbot_internal.approval_preferences";
const INSERT: &str = "INSERT INTO openbot_internal.approval_preferences (
    preference_id,deployment_id,tenant_id,actor_id,bot_id,target_kind,target_id,
    tool_name,effect,preference,revision,created_at,updated_at
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)";
const IDENTITY_PARTS: [usize; 5] = [0, 1, 2, 3, 5];

#[derive(Clone)]
struct FixtureRow {
    id: Uuid,
    // Ordered six-key coordinates: deployment, tenant, actor, Bot, kind, target.
    key: [String; 6],
    tool: String,
    effect: String,
    preference: String,
    revision: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl FixtureRow {
    fn new() -> Self {
        let at = OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap();
        Self {
            id: Uuid::now_v7(),
            key: [
                "fixture-deployment".to_owned(),
                "fixture-tenant".to_owned(),
                "fixture-actor".to_owned(),
                "fixture-bot".to_owned(),
                "memory_thread".to_owned(),
                "fixture-thread".to_owned(),
            ],
            tool: "remember".to_owned(),
            effect: "write".to_owned(),
            preference: "ask".to_owned(),
            revision: 1,
            created_at: at,
            updated_at: at,
        }
    }

    fn pure_key(&self) -> Result<RememberPreferenceKey, String> {
        RememberPreferenceKey::from_stored(
            DeploymentId::new(self.key[0].clone()),
            TenantId::new(self.key[1].clone()),
            ActorId::new(self.key[2].clone()),
            BotId::new(self.key[3].clone()),
            &self.key[4],
            self.key[5].clone(),
        )
        .map_err(|error| error.to_string())
    }
}

async fn insert(client: &Client, row: &FixtureRow) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            INSERT,
            &[
                &row.id,
                &row.key[0],
                &row.key[1],
                &row.key[2],
                &row.key[3],
                &row.key[4],
                &row.key[5],
                &row.tool,
                &row.effect,
                &row.preference,
                &row.revision,
                &row.created_at,
                &row.updated_at,
            ],
        )
        .await
}

async fn fresh_pool(config: &DatabaseConfig) -> openbot_infra::db::pool::DatabasePool {
    let pool = pool::connect(config).await.unwrap();
    let mut client = pool.get().await.unwrap();
    fresh::apply(&mut client).await.unwrap();
    drop(client);
    pool
}

async fn read_key(client: &Client, id: Uuid) -> [String; 6] {
    let row = client
        .query_one(
            "SELECT deployment_id,tenant_id,actor_id,bot_id,target_kind,target_id
             FROM openbot_internal.approval_preferences WHERE preference_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    std::array::from_fn(|index| row.get(index))
}

type LedgerRow = (i32, String, String, String);

async fn ledger(client: &Client) -> Vec<LedgerRow> {
    client
        .query(
            "SELECT version,name,checksum,applied_at::text
             FROM openbot_internal.schema_migrations ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect()
}

/// Full row values, not just a count: read-only verification must not modify existing data.
async fn business_rows(client: &Client) -> Value {
    let raw: String = client
        .query_one(
            "SELECT jsonb_build_object(
               'preferences', (SELECT coalesce(jsonb_agg(to_jsonb(p)
                 ORDER BY p.preference_id),'[]'::jsonb)
                 FROM openbot_internal.approval_preferences p),
               'audit', (SELECT coalesce(jsonb_agg(to_jsonb(a)
                 ORDER BY to_jsonb(a)::text),'[]'::jsonb) FROM public.audit_events a)
             )::text",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    serde_json::from_str(&raw).unwrap()
}

async fn seed_read_only_observation_rows(client: &Client) {
    insert(client, &FixtureRow::new()).await.unwrap();
    // A raw historical-shaped fixture checks preservation only; this is not an audit producer.
    client
        .execute(
            "INSERT INTO public.audit_events(id,event_type,target_type,target_id,payload,created_at)
             VALUES($1,'fixture.observation','schema_fixture','fixture-only',
                    '{\"fixture\":true}'::jsonb,'2020-01-01T00:00:00Z')",
            &[&Uuid::now_v7()],
        )
        .await
        .unwrap();
    let rows = business_rows(client).await;
    assert_eq!(rows["preferences"].as_array().unwrap().len(), 1);
    assert_eq!(rows["audit"].as_array().unwrap().len(), 1);
}

async fn assert_constraint_refusal(client: &Client, row: &FixtureRow) {
    let before = business_rows(client).await;
    let error = insert(client, row).await.unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    assert_eq!(business_rows(client).await, before);
}

/// Each temporary DDL change is rolled back; only the verifier's observations are under test.
async fn assert_catalog_drift_refused(client: &Client, ddl: &str) {
    let original = approval_preference_schema::capture(client).await.unwrap();
    let original_rows = business_rows(client).await;
    let original_ledger = ledger(client).await;
    client.batch_execute("BEGIN").await.unwrap();
    client.batch_execute(ddl).await.unwrap();
    let changed = approval_preference_schema::capture(client).await.unwrap();
    let outcome = approval_preference_schema::verify(client).await;
    let observed_rows = business_rows(client).await;
    let observed_ledger = ledger(client).await;
    client.batch_execute("ROLLBACK").await.unwrap();
    assert_ne!(changed, original);
    assert_eq!(
        outcome,
        Err(ApprovalPreferenceSchemaError::Corrupt {
            field: "internal_schema",
        })
    );
    assert_eq!(observed_rows, original_rows);
    assert_eq!(observed_ledger, original_ledger);
    assert_eq!(
        approval_preference_schema::capture(client).await.unwrap(),
        original
    );
    approval_preference_schema::verify(client).await.unwrap();
}

async fn assert_ledger_drift_refused(client: &Client, mutation: &str) {
    let original_schema = approval_preference_schema::capture(client).await.unwrap();
    let original_ledger = ledger(client).await;
    client.batch_execute("BEGIN").await.unwrap();
    client.batch_execute(mutation).await.unwrap();
    let changed_ledger = ledger(client).await;
    let before_rows = business_rows(client).await;
    let outcome = approval_preference_schema::verify(client).await;
    let observed_schema = approval_preference_schema::capture(client).await.unwrap();
    let observed_rows = business_rows(client).await;
    let observed_ledger = ledger(client).await;
    client.batch_execute("ROLLBACK").await.unwrap();
    assert_ne!(changed_ledger, original_ledger);
    assert_eq!(
        outcome,
        Err(ApprovalPreferenceSchemaError::Corrupt {
            field: "native_prefix",
        })
    );
    assert_eq!(observed_schema, original_schema);
    assert_eq!(observed_rows, before_rows);
    assert_eq!(observed_ledger, changed_ledger);
    assert_eq!(ledger(client).await, original_ledger);
    approval_preference_schema::verify(client).await.unwrap();
}

/// Independent high-entropy ASCII blocks avoid relying on compression to fit a complete key.
fn incompressible_identity(tag: &str) -> String {
    (0..8)
        .map(|counter| {
            format!(
                "{:x}",
                Sha256::digest(format!("preference-key/{tag}/{counter}").as_bytes())
            )
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn native43_fresh_keeps_public_and_artifact_oracles_and_is_idempotent() {
    harness::with_temp_database(
        &harness::admin_config("prefs43fresh"),
        "prefs43fresh",
        |config| async move {
            let pool = pool::connect(&config).await.unwrap();
            let mut client = pool.get().await.unwrap();
            // Pin native 43 for its public-schema preservation assertion;
            // later migrations intentionally change those public objects.
            baseline::apply(&client).await.unwrap();
            native::apply_through(&mut client, native::NATIVE_0043_VERSION)
                .await
                .unwrap();
            approval_preference_schema::verify_storage_prerequisites(&client)
                .await
                .unwrap();
            approval_preference_schema::verify(&client).await.unwrap();
            let expected: Value = serde_json::from_str(include_str!(
                "../../../fixtures/db/approval-preferences-0043.json"
            ))
            .unwrap();
            assert_eq!(
                approval_preference_schema::capture(&client).await.unwrap(),
                expected
            );
            let public: schema_facts::SchemaFacts =
                serde_json::from_str(include_str!("../../../fixtures/db/schema-0040.json"))
                    .unwrap();
            assert_eq!(schema_facts::fetch(&client).await.unwrap(), public);
            let before = ledger(&client).await;
            // This original prefix and native 43's evidence remain exact.
            let latest = native::validate_known_prefix(&client, native::NATIVE_0043_VERSION)
                .await
                .unwrap()
                .latest_version();
            assert_eq!(latest, native::NATIVE_0043_VERSION);
            assert_eq!(
                before.iter().map(|row| row.0).collect::<Vec<_>>(),
                (13..=latest).collect::<Vec<_>>()
            );
            let native43 = &before[(native::NATIVE_0043_VERSION - 13) as usize];
            assert_eq!(native43.1, native::NATIVE_0043_NAME);
            assert_eq!(
                native43.2,
                format!("{:x}", Sha256::digest(native::NATIVE_0043_SQL.as_bytes()))
            );
            let empty = business_rows(&client).await;
            assert_eq!(empty["preferences"], serde_json::json!([]));
            assert_eq!(empty["audit"], serde_json::json!([]));
            assert_eq!(
                native::apply_through(&mut client, native::NATIVE_0043_VERSION)
                    .await
                    .unwrap(),
                native::ApplyOutcome::AlreadyApplied
            );
            approval_preference_schema::verify(&client).await.unwrap();
            assert_eq!(ledger(&client).await, before);
            assert_eq!(business_rows(&client).await, empty);
            // Current-schema compatibility does not assert that later public
            // migrations are no-ops. The original approval oracle and prefix stay fixed.
            native::apply(&mut client).await.unwrap();
            approval_preference_schema::verify(&client).await.unwrap();
            assert_eq!(approval_preference_schema::capture(&client).await.unwrap(), expected);
            let current = ledger(&client).await;
            assert_eq!(&current[..before.len()], before.as_slice());
            assert_eq!(
                current.iter().map(|row| row.0).collect::<Vec<_>>(),
                (13..=native::NATIVE_LATEST_VERSION).collect::<Vec<_>>()
            );
            assert_eq!(native::apply(&mut client).await.unwrap(), native::ApplyOutcome::AlreadyApplied);
            assert_eq!(ledger(&client).await, current);
            assert_eq!(business_rows(&client).await, empty);
            drop(client);
            // These older internal oracles remain byte-identical and independently accepted.
            #[cfg(feature = "server-runtime")]
            {
                openbot_infra::artifact_registry::verify_artifact_registry_schema(&pool)
                    .await
                    .unwrap();
                openbot_infra::artifact_administration::verify_artifact_registration_schema(&pool)
                    .await
                    .unwrap();
            }
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn native42_upgrade_preserves_existing_rows_and_migration_evidence() {
    harness::with_temp_database(&harness::admin_config("prefs43upgrade"), "prefs43upgrade", |config| async move {
        let pool = pool::connect(&config).await.unwrap();
        let mut client = pool.get().await.unwrap();
        baseline::apply(&client).await.unwrap();
        native::apply_through(&mut client, native::NATIVE_0042_VERSION).await.unwrap();
        client.batch_execute("INSERT INTO public.users(id,email) VALUES('prefs43-owner','prefs43@example.test');
          INSERT INTO public.user_ui_preferences(deployment_id,tenant_id,actor_user_id,theme,locale,revision,updated_at)
            VALUES('old-deployment','old-tenant','prefs43-owner','dark','zh-CN',17,'2020-01-01T00:00:00Z');
          INSERT INTO openbot_internal.artifact_dataset_bindings(deployment_id,tenant_id,dataset_id,binding_schema,initial_origin,created_at)
            VALUES('old-deployment','old-tenant','old-dataset',1,'server_first_adoption','2020-01-01T00:00:00Z')").await.unwrap();
        let old_ledger = ledger(&client).await;
        let old_public = schema_facts::fetch(&client).await.unwrap();
        let sql = "SELECT jsonb_build_object(
          'user',(SELECT to_jsonb(u) FROM public.users u WHERE id='prefs43-owner'),
          'ui',(SELECT to_jsonb(p) FROM public.user_ui_preferences p WHERE actor_user_id='prefs43-owner'),
          'dataset',(SELECT to_jsonb(b) FROM openbot_internal.artifact_dataset_bindings b WHERE deployment_id='old-deployment')
        )::text";
        let before: String = client.query_one(sql, &[]).await.unwrap().get(0);
        assert!(client.query_one("SELECT to_regclass($1)::text", &[&TABLE]).await.unwrap().get::<_,Option<String>>(0).is_none());
        assert!(approval_preference_schema::verify(&client).await.is_err());
        assert_eq!(ledger(&client).await, old_ledger);
        // Only native 43 is responsible for preserving this native 42 public schema.
        native::apply_through(&mut client, native::NATIVE_0043_VERSION).await.unwrap();
        approval_preference_schema::verify(&client).await.unwrap();
        let current = ledger(&client).await;
        assert_eq!(&current[..old_ledger.len()], old_ledger.as_slice());
        // The known prefix ends at the migration this test is exercising.
        let latest = native::validate_known_prefix(&client, native::NATIVE_0043_VERSION).await.unwrap().latest_version();
        assert_eq!(latest, native::NATIVE_0043_VERSION);
        assert_eq!(current.iter().map(|row| row.0).collect::<Vec<_>>(), (13..=latest).collect::<Vec<_>>());
        assert_eq!(current[old_ledger.len()].0, native::NATIVE_0043_VERSION);
        assert_eq!(client.query_one(sql, &[]).await.unwrap().get::<_,String>(0), before);
        assert_eq!(schema_facts::fetch(&client).await.unwrap(), old_public);
        assert_eq!(business_rows(&client).await["preferences"], serde_json::json!([]));
        assert_eq!(business_rows(&client).await["audit"], serde_json::json!([]));
        drop(client);
        pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn storage_prerequisites_use_actual_server_and_reject_non_utf8() {
    let admin = harness::admin_config("prefs43storage");
    harness::with_temp_database(&admin, "prefs43storage", |config| async move {
        let pool = fresh_pool(&config).await;
        let client = pool.get().await.unwrap();
        let actual = client.query_one("SELECT current_setting('server_encoding'),current_setting('block_size')::integer,current_setting('server_version_num')::integer", &[]).await.unwrap();
        assert_eq!(actual.get::<_,String>(0), "UTF8");
        assert_eq!(actual.get::<_,i32>(1), 8192);
        assert!((170_000..180_000).contains(&actual.get::<_,i32>(2)));
        let before = business_rows(&client).await;
        client.batch_execute("SET client_encoding = 'LATIN1'").await.unwrap();
        assert_eq!(client.query_one("SHOW client_encoding", &[]).await.unwrap().get::<_,String>(0), "LATIN1");
        approval_preference_schema::verify_storage_prerequisites(&client).await.unwrap();
        client.batch_execute("SET client_encoding = 'UTF8'").await.unwrap();
        assert_eq!(business_rows(&client).await, before);
        drop(client);
        pool.close();
        Ok(())
    }).await;

    // A genuinely different owned database encoding, not a changed client setting or label.
    let name = harness::unique_database_name("prefs43nonutf8");
    harness::run_utility(&admin, &format!("CREATE DATABASE \"{name}\" TEMPLATE template0 ENCODING 'LATIN1' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C'")).await.unwrap();
    let outcome: Result<(), String> = async {
        let pool = pool::connect(&admin.clone().with_dbname(&name))
            .await
            .map_err(|error| error.to_string())?;
        let client = pool.get().await.map_err(|error| error.to_string())?;
        let encoding: String = client
            .query_one("SHOW server_encoding", &[])
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        let prerequisite = approval_preference_schema::verify_storage_prerequisites(&client).await;
        let migration = client.batch_execute(native::NATIVE_0043_SQL).await;
        let absent = client
            .query_one("SELECT to_regclass($1)::text", &[&TABLE])
            .await
            .map_err(|error| error.to_string())?
            .get::<_, Option<String>>(0)
            .is_none();
        drop(client);
        pool.close();
        if encoding != "LATIN1"
            || prerequisite != Err(ApprovalPreferenceSchemaError::IncompatibleStorage)
            || migration
                .as_ref()
                .err()
                .and_then(tokio_postgres::Error::code)
                != Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE)
            || !absent
        {
            return Err("owned non-UTF8 storage was not rejected before DDL".to_owned());
        }
        Ok(())
    }
    .await;
    let dropped =
        harness::run_utility(&admin, &format!("DROP DATABASE \"{name}\" WITH (FORCE)")).await;
    outcome.unwrap();
    dropped.unwrap();
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn unicode_controls_are_rejected_by_all_five_pg_identities_like_the_pure_key() {
    harness::with_temp_database(
        &harness::admin_config("prefs43controls"),
        "prefs43controls",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            let before = business_rows(&client).await;
            let controls: Vec<char> = (0..=0x1f)
                .chain(0x7f..=0x9f)
                .map(|value| char::from_u32(value).unwrap())
                .collect();
            assert_eq!(controls.len(), 65);
            for control in controls {
                assert!(control.is_control());
                for part in IDENTITY_PARTS {
                    let mut row = FixtureRow::new();
                    row.key[part] = format!("before{control}after");
                    assert!(
                        row.pure_key().is_err(),
                        "pure identity part={part} control={:x}",
                        u32::from(control)
                    );
                    let error = insert(&client, &row).await.unwrap_err();
                    if control == '\0' {
                        assert_eq!(error.code(), Some(&SqlState::CHARACTER_NOT_IN_REPERTOIRE));
                    } else {
                        assert_eq!(
                            error.code(),
                            Some(&SqlState::CHECK_VIOLATION),
                            "PG identity part={part} control={:x}",
                            u32::from(control)
                        );
                    }
                }
            }
            assert_eq!(business_rows(&client).await, before);
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn identity_boundaries_are_utf8_bytes_and_preserve_allowed_unicode_exactly() {
    harness::with_temp_database(
        &harness::admin_config("prefs43utf8"),
        "prefs43utf8",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            let exact = format!("{}ab", "中".repeat(170));
            assert_eq!(exact.len(), 512);
            assert_eq!(exact.chars().count(), 172);
            for part in IDENTITY_PARTS {
                let mut row = FixtureRow::new();
                row.key[part] = exact.clone();
                assert!(row.pure_key().is_ok());
                assert_eq!(insert(&client, &row).await.unwrap(), 1);
                assert_eq!(read_key(&client, row.id).await, row.key);
                for invalid in [String::new(), format!("{exact}c")] {
                    let mut bad = FixtureRow::new();
                    bad.key[part] = invalid;
                    assert!(bad.pure_key().is_err());
                    assert_constraint_refusal(&client, &bad).await;
                }
            }
            for allowed in [
                ' ', '~', '\u{a0}', '\u{ad}', '\u{200b}', '\u{200d}', '中', '🦀',
            ] {
                assert!(!allowed.is_control());
                for part in IDENTITY_PARTS {
                    let mut row = FixtureRow::new();
                    row.key[part] = format!("  opaque/{allowed}/value  ");
                    assert!(row.pure_key().is_ok());
                    assert_eq!(insert(&client, &row).await.unwrap(), 1);
                    assert_eq!(read_key(&client, row.id).await, row.key);
                }
            }
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn maximum_incompressible_complete_key_fits_and_each_coordinate_separates() {
    harness::with_temp_database(&harness::admin_config("prefs43maxkey"), "prefs43maxkey", |config| async move {
        let pool = fresh_pool(&config).await;
        let client = pool.get().await.unwrap();
        let mut largest = FixtureRow::new();
        for part in IDENTITY_PARTS {
            largest.key[part] = incompressible_identity(&format!("coordinate-{part}"));
            assert_eq!(largest.key[part].len(), 512);
        }
        assert!(largest.pure_key().is_ok());
        assert_eq!(insert(&client, &largest).await.unwrap(), 1);
        assert_eq!(read_key(&client, largest.id).await, largest.key);
        let sizes = client.query_one("SELECT pg_column_size(deployment_id),pg_column_size(tenant_id),pg_column_size(actor_id),pg_column_size(bot_id),pg_column_size(target_id) FROM openbot_internal.approval_preferences WHERE preference_id=$1", &[&largest.id]).await.unwrap();
        for part in 0..5 {
            assert!(sizes.get::<_,i32>(part) >= 512, "identity {part} relied on compression");
        }
        let mut duplicate = largest.clone();
        duplicate.id = Uuid::now_v7();
        let conflict = insert(&client, &duplicate).await.unwrap_err();
        assert_eq!(conflict.code(), Some(&SqlState::UNIQUE_VIOLATION));
        assert_eq!(conflict.as_db_error().unwrap().constraint(), Some("approval_preferences_complete_key"));
        for part in IDENTITY_PARTS {
            let mut separate = largest.clone();
            separate.id = Uuid::now_v7();
            separate.key[part] = incompressible_identity(&format!("different-coordinate-{part}"));
            assert_eq!(insert(&client, &separate).await.unwrap(), 1);
            assert_eq!(read_key(&client, separate.id).await, separate.key);
        }
        // Change kind alone while satisfying both derived-target constraints.
        let mut same_target = largest.clone();
        same_target.key[0] = incompressible_identity("kind-isolation-deployment");
        same_target.key[3] = same_target.key[2].clone();
        same_target.key[5] = same_target.key[2].clone();
        for kind in ["memory_thread", "memory_user", "memory_bot"] {
            same_target.id = Uuid::now_v7();
            same_target.key[4] = kind.to_owned();
            assert!(same_target.pure_key().is_ok());
            assert_eq!(insert(&client, &same_target).await.unwrap(), 1);
            assert_eq!(read_key(&client, same_target.id).await, same_target.key);
        }
        assert_eq!(client.query_one("SELECT count(*) FROM openbot_internal.approval_preferences", &[]).await.unwrap().get::<_,i64>(0), 9);
        approval_preference_schema::verify(&client).await.unwrap();
        drop(client);
        pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn stored_row_constraints_accept_all_targets_and_closed_preferences_only() {
    harness::with_temp_database(
        &harness::admin_config("prefs43closed"),
        "prefs43closed",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            for (kind, target_part) in [("memory_user", 2), ("memory_bot", 3), ("memory_thread", 5)]
            {
                for preference in ["never", "ask", "allow_if_policy"] {
                    let mut row = FixtureRow::new();
                    row.key[0] = format!("{kind}-{preference}");
                    row.key[4] = kind.to_owned();
                    row.key[5] = row.key[target_part].clone();
                    row.preference = preference.to_owned();
                    assert!(row.pure_key().is_ok());
                    assert_eq!(insert(&client, &row).await.unwrap(), 1);
                }
            }
            for kind in [
                "memory_user",
                "memory_bot",
                "workspace",
                "",
                "memory_Thread",
            ] {
                let mut row = FixtureRow::new();
                row.key[4] = kind.to_owned();
                assert!(row.pure_key().is_err());
                assert_constraint_refusal(&client, &row).await;
            }
            for tool in ["Remember", "other", "remember.*", ""] {
                let mut row = FixtureRow::new();
                row.tool = tool.to_owned();
                assert_constraint_refusal(&client, &row).await;
            }
            for effect in ["read", "Write", "external", ""] {
                let mut row = FixtureRow::new();
                row.effect = effect.to_owned();
                assert_constraint_refusal(&client, &row).await;
            }
            for preference in ["allow", "Ask", "ask ", ""] {
                let mut row = FixtureRow::new();
                row.preference = preference.to_owned();
                assert_constraint_refusal(&client, &row).await;
            }
            for revision in [0, -1, i64::MIN] {
                let mut row = FixtureRow::new();
                row.revision = revision;
                assert_constraint_refusal(&client, &row).await;
            }
            for id in [
                Uuid::nil(),
                Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
                Uuid::parse_str("00000000-0000-7000-0000-000000000001").unwrap(),
            ] {
                let mut row = FixtureRow::new();
                row.id = id;
                assert_constraint_refusal(&client, &row).await;
            }
            let mut row = FixtureRow::new();
            assert_eq!(insert(&client, &row).await.unwrap(), 1);
            row.key[0] = "different-key-same-id".to_owned();
            let duplicate_id = insert(&client, &row).await.unwrap_err();
            assert_eq!(duplicate_id.code(), Some(&SqlState::UNIQUE_VIOLATION));
            assert_eq!(
                duplicate_id.as_db_error().unwrap().constraint(),
                Some("approval_preferences_pkey")
            );
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn mutations_preserve_identity_and_advance_once_without_delete_or_overflow() {
    harness::with_temp_database(&harness::admin_config("prefs43guard"), "prefs43guard", |config| async move {
        let pool = fresh_pool(&config).await;
        let client = pool.get().await.unwrap();
        let row = FixtureRow::new();
        insert(&client, &row).await.unwrap();
        let original = business_rows(&client).await;
        for assignment in [
            "preference_id='00000000-0000-7000-8000-000000000001'::uuid",
            "deployment_id='other-deployment'", "tenant_id='other-tenant'",
            "actor_id='other-actor'", "bot_id='other-bot'",
            "target_kind='memory_user'", "target_id='other-target'",
            "created_at=created_at+interval '1 second'",
        ] {
            let error = client.execute(&format!("UPDATE {TABLE} SET {assignment},revision=2 WHERE preference_id=$1"), &[&row.id]).await.unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE));
            assert_eq!(business_rows(&client).await, original);
        }
        for revision in [0_i64, -1, 1, 3, i64::MAX] {
            let error = client.execute("UPDATE openbot_internal.approval_preferences SET revision=$2 WHERE preference_id=$1", &[&row.id, &revision]).await.unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE));
            assert_eq!(business_rows(&client).await, original);
        }
        // Same value still advances; updated_at has no invented monotonicity constraint.
        assert_eq!(client.execute("UPDATE openbot_internal.approval_preferences SET preference='ask',revision=2 WHERE preference_id=$1", &[&row.id]).await.unwrap(), 1);
        assert_eq!(client.execute("UPDATE openbot_internal.approval_preferences SET preference='never',revision=3,updated_at=created_at-interval '1 day' WHERE preference_id=$1", &[&row.id]).await.unwrap(), 1);
        let current = client.query_one("SELECT revision,preference,created_at,updated_at FROM openbot_internal.approval_preferences WHERE preference_id=$1", &[&row.id]).await.unwrap();
        assert_eq!(current.get::<_,i64>(0), 3);
        assert_eq!(current.get::<_,String>(1), "never");
        assert_eq!(current.get::<_,OffsetDateTime>(2), row.created_at);
        assert!(current.get::<_,OffsetDateTime>(3) < row.created_at);
        assert_eq!(read_key(&client, row.id).await, row.key);
        let mut exhausted = FixtureRow::new();
        exhausted.key[0] = "exhausted-fixture-deployment".to_owned();
        exhausted.revision = i64::MAX;
        insert(&client, &exhausted).await.unwrap();
        let before_refusals = business_rows(&client).await;
        for revision in [0_i64, 1, i64::MAX] {
            let error = client.execute("UPDATE openbot_internal.approval_preferences SET revision=$2,preference='ask' WHERE preference_id=$1", &[&exhausted.id, &revision]).await.unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE));
            assert_eq!(business_rows(&client).await, before_refusals);
        }
        for sql in ["DELETE FROM openbot_internal.approval_preferences", "TRUNCATE openbot_internal.approval_preferences"] {
            let error = client.batch_execute(sql).await.unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE));
            assert_eq!(business_rows(&client).await, before_refusals);
        }
        assert_eq!(before_refusals["audit"], serde_json::json!([]));
        drop(client);
        pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn schema_verification_rejects_guard_trigger_key_collation_and_column_drift_read_only() {
    harness::with_temp_database(&harness::admin_config("prefs43drift"), "prefs43drift", |config| async move {
        let pool = fresh_pool(&config).await;
        let client = pool.get().await.unwrap();
        seed_read_only_observation_rows(&client).await;
        approval_preference_schema::verify(&client).await.unwrap();
        for ddl in [
            "ALTER TABLE openbot_internal.approval_preferences DISABLE TRIGGER approval_preferences_mutation_guard",
            "ALTER TABLE openbot_internal.approval_preferences DISABLE TRIGGER approval_preferences_no_truncate",
            "CREATE OR REPLACE FUNCTION openbot_internal.prevent_approval_preference_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
            "ALTER TABLE openbot_internal.approval_preferences DROP CONSTRAINT approval_preferences_complete_key; CREATE UNIQUE INDEX approval_preferences_incomplete_key ON openbot_internal.approval_preferences(deployment_id,tenant_id,actor_id,bot_id,target_kind)",
            "ALTER TABLE openbot_internal.approval_preferences ALTER COLUMN deployment_id TYPE text COLLATE \"default\"",
            "ALTER TABLE openbot_internal.approval_preferences ALTER COLUMN preference DROP NOT NULL",
            "ALTER TABLE openbot_internal.approval_preferences ALTER COLUMN revision SET DEFAULT 1",
            "ALTER TABLE openbot_internal.approval_preferences DROP CONSTRAINT approval_preferences_effect; ALTER TABLE openbot_internal.approval_preferences ADD CONSTRAINT approval_preferences_effect CHECK(effect='write') NOT VALID",
            "CREATE INDEX approval_preferences_unexpected_index ON openbot_internal.approval_preferences(preference)",
        ] {
            assert_catalog_drift_refused(&client, ddl).await;
        }
        drop(client);
        pool.close();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn schema_verification_rejects_known_prefix_drift_read_only() {
    harness::with_temp_database(&harness::admin_config("prefs43ledger"), "prefs43ledger", |config| async move {
        let pool = fresh_pool(&config).await;
        let client = pool.get().await.unwrap();
        seed_read_only_observation_rows(&client).await;
        approval_preference_schema::verify(&client).await.unwrap();
        for mutation in [
            "DELETE FROM openbot_internal.schema_migrations WHERE version=43",
            "DELETE FROM openbot_internal.schema_migrations WHERE version=20",
            "UPDATE openbot_internal.schema_migrations SET name='drifted-native43' WHERE version=43",
            "UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=43",
            "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(9999,'unknown-native9999',repeat('4',64))",
        ] {
            assert_ledger_drift_refused(&client, mutation).await;
        }
        drop(client);
        pool.close();
        Ok(())
    }).await;
}
