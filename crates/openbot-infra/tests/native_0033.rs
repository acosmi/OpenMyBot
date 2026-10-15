//! Native 0033 SDK Gateway authority schema, typed rows and exact PostgreSQL facts.

mod harness;

use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::tables::{
    NATIVE_0033_TABLES, TableRow, sdk_gateway_connections, sdk_gateway_operations,
    sdk_gateway_secrets,
};
use openbot_infra::db::{baseline, fresh, pool, schema_facts};
use time::OffsetDateTime;
use tokio_postgres::{Transaction, error::SqlState};
use uuid::Uuid;

const POST_0032: &str = include_str!("../../../fixtures/db/schema-0031.json");

fn post_0033_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/db/schema-0033.json")
}

fn read_post_0033() -> SchemaFacts {
    serde_json::from_str(
        &std::fs::read_to_string(post_0033_path()).expect("schema-0033 fixture missing"),
    )
    .expect("schema-0033 fixture must be exported from owned PostgreSQL")
}

async fn insert_row<R: TableRow>(transaction: &Transaction<'_>, row: &R) {
    let placeholders = (1..=R::COLUMNS.len())
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(",");
    transaction
        .execute(
            &format!(
                "INSERT INTO public.{} ({}) VALUES ({placeholders})",
                R::TABLE_NAME,
                R::COLUMNS.join(",")
            ),
            &row.as_sql_params(),
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn post_0033_preserves_0032_applies_once_and_fresh_matches_owned_fixture() {
    let admin = harness::admin_config("native0033_schema");
    harness::with_temp_database(&admin, "sdk33upgrade", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        baseline::apply(&client)
            .await
            .map_err(|error| error.to_string())?;
        native::apply_through(&mut client, native::NATIVE_0032_VERSION)
            .await
            .map_err(|error| error.to_string())?;
        let before = schema_facts::fetch(&client)
            .await
            .map_err(|error| error.to_string())?;
        let expected_before: SchemaFacts =
            serde_json::from_str(POST_0032).map_err(|error| error.to_string())?;
        assert_eq!(before, expected_before);

        assert_eq!(
            native::apply_through(&mut client, native::NATIVE_0033_VERSION)
                .await
                .map_err(|error| error.to_string())?,
            ApplyOutcome::Applied
        );
        let after = schema_facts::fetch(&client)
            .await
            .map_err(|error| error.to_string())?;
        assert_eq!(after.enums, before.enums);
        assert_eq!(after.extensions, before.extensions);
        assert_eq!(after.functions, before.functions);
        assert_eq!(after.tables.len(), before.tables.len() + 3);
        for old in &before.tables {
            assert_eq!(after.table(&old.name), Some(old), "{}", old.name);
        }
        assert_eq!(NATIVE_0033_TABLES.len(), 3);
        assert_eq!(
            NATIVE_0033_TABLES
                .iter()
                .map(|table| table.columns.len())
                .sum::<usize>(),
            45
        );
        for spec in NATIVE_0033_TABLES {
            let table = after.table(spec.name).expect("native0033 table exists");
            assert_eq!(table.columns.len(), spec.columns.len());
            let (constraints, indexes) = match spec.name {
                sdk_gateway_connections::TABLE_NAME => (17, 3),
                sdk_gateway_operations::TABLE_NAME => (10, 2),
                sdk_gateway_secrets::TABLE_NAME => (5, 2),
                _ => unreachable!("closed native0033 registry"),
            };
            assert_eq!(table.constraints.len(), constraints);
            assert_eq!(table.indexes.len(), indexes);
            assert!(table.triggers.is_empty());
            for (position, (actual, declared)) in table
                .columns
                .iter()
                .zip(spec.column_specs.iter())
                .enumerate()
            {
                assert_eq!(actual.name, spec.columns[position]);
                assert_eq!(actual.name, declared.name);
                assert_eq!(actual.sql_type, declared.sql_type);
                assert_eq!(actual.notnull, declared.not_null);
                assert_eq!(actual.default, None);
                assert_eq!(usize::try_from(actual.ordinal).unwrap(), position + 1);
            }
        }
        if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0033").is_some() {
            let mut encoded = serde_json::to_string_pretty(&after).map_err(|e| e.to_string())?;
            encoded.push('\n');
            std::fs::write(post_0033_path(), encoded).map_err(|error| error.to_string())?;
        } else {
            assert_eq!(after, read_post_0033());
        }
        let ledger: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM openbot_internal.schema_migrations",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(ledger, 21);
        let checksum: String = client
            .query_one(
                "SELECT checksum FROM openbot_internal.schema_migrations WHERE version=33",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(checksum, native::native_0033_checksum());
        assert_eq!(
            native::apply_through(&mut client, native::NATIVE_0033_VERSION)
                .await
                .unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        drop(client);
        pool.close();
        Ok(())
    })
    .await;

    harness::with_temp_database(&admin, "sdk33fresh", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        fresh::apply(&mut client)
            .await
            .map_err(|error| error.to_string())?;
        let current = schema_facts::fetch(&client).await.unwrap();
        let expected_current: SchemaFacts =
            serde_json::from_str(include_str!("../../../fixtures/db/schema-0052.json"))
                .expect("current schema-0052 fixture must be frozen");
        assert_eq!(current, expected_current);
        let original = read_post_0033();
        for spec in NATIVE_0033_TABLES {
            let old = original
                .table(spec.name)
                .expect("native0033 frozen table exists");
            assert_eq!(current.table(spec.name), Some(old), "{}", spec.name);
        }
        drop(client);
        pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn post_0033_typed_rows_and_scope_state_constraints_are_exact() {
    let admin = harness::admin_config("native0033_rows");
    harness::with_temp_database(&admin, "sdk33rows", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        fresh::apply(&mut client)
            .await
            .map_err(|error| error.to_string())?;
        client
            .batch_execute(
                "INSERT INTO public.users(id,email) VALUES('sdk-owner','sdk-owner@example.test')",
            )
            .await
            .unwrap();
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(33);
        let connection_id = Uuid::from_u128(1);
        let secret_id = Uuid::from_u128(2);
        let operation_id = Uuid::from_u128(3);
        let connection = sdk_gateway_connections::Row {
            id: connection_id,
            deployment_id: "deployment-a".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            owner_user_id: "sdk-owner".to_owned(),
            name: "SDK Gateway".to_owned(),
            issuer: "https://gateway.example.test".to_owned(),
            client_id: "client-a".to_owned(),
            account_id: "account-a".to_owned(),
            organization_id: None,
            auth_contract_version: 2,
            error_contract_version: 1,
            enabled: true,
            revision: 1,
            credential_generation: 1,
            auth_generation: 0,
            state: "ready".to_owned(),
            current_secret_id: Some(secret_id),
            pending_operation_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let secret = sdk_gateway_secrets::Row {
            id: secret_id,
            connection_id,
            deployment_id: "deployment-a".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            owner_user_id: "sdk-owner".to_owned(),
            credential_generation: 1,
            encrypted_value: "SDK-CIPHERTEXT-SENTINEL".to_owned(),
            created_at: now,
            retired_at: None,
        };
        let operation = sdk_gateway_operations::Row {
            id: operation_id,
            connection_id,
            deployment_id: "deployment-a".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            owner_user_id: "sdk-owner".to_owned(),
            expected_revision: 1,
            auth_generation: 0,
            from_generation: 1,
            to_generation: 2,
            state: "pending".to_owned(),
            candidate_secret_id: None,
            token_admitted_at: Some(now),
            created_at: now,
            updated_at: now,
            completed_at: None,
        };
        let transaction = client.transaction().await.unwrap();
        insert_row(&transaction, &connection).await;
        insert_row(&transaction, &secret).await;
        insert_row(&transaction, &operation).await;
        transaction.commit().await.unwrap();

        for (table, id) in [
            (sdk_gateway_connections::TABLE_NAME, connection_id),
            (sdk_gateway_secrets::TABLE_NAME, secret_id),
            (sdk_gateway_operations::TABLE_NAME, operation_id),
        ] {
            let row = client
                .query_one(&format!("SELECT * FROM public.{table} WHERE id=$1"), &[&id])
                .await
                .unwrap();
            match table {
                sdk_gateway_connections::TABLE_NAME => {
                    assert_eq!(sdk_gateway_connections::Row::try_from(&row).unwrap(), connection)
                }
                sdk_gateway_secrets::TABLE_NAME => {
                    assert_eq!(sdk_gateway_secrets::Row::try_from(&row).unwrap(), secret)
                }
                _ => assert_eq!(sdk_gateway_operations::Row::try_from(&row).unwrap(), operation),
            }
        }
        assert!(!format!("{secret:?}").contains("SDK-CIPHERTEXT-SENTINEL"));

        for statement in [
            "UPDATE public.sdk_gateway_connections SET state='ready',current_secret_id=NULL WHERE id='00000000-0000-0000-0000-000000000001'",
            "UPDATE public.sdk_gateway_connections SET auth_contract_version=3 WHERE id='00000000-0000-0000-0000-000000000001'",
            "UPDATE public.sdk_gateway_operations SET to_generation=from_generation+2 WHERE id='00000000-0000-0000-0000-000000000003'",
            "UPDATE public.sdk_gateway_operations SET state='staged',candidate_secret_id=NULL WHERE id='00000000-0000-0000-0000-000000000003'",
        ] {
            let error = client.batch_execute(statement).await.unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        }

        let transaction = client.transaction().await.unwrap();
        transaction
            .execute(
                "UPDATE public.sdk_gateway_secrets SET owner_user_id='other-owner' WHERE id=$1",
                &[&secret_id],
            )
            .await
            .unwrap();
        assert_eq!(
            transaction.commit().await.unwrap_err().code(),
            Some(&SqlState::FOREIGN_KEY_VIOLATION)
        );
        drop(client);
        pool.close();
        Ok(())
    })
    .await;
}
