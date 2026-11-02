//! Durable cleanup-fence storage checks against caller-owned disposable PostgreSQL.
//!
//! Terminal rows below are raw database fixtures, not a physical deletion, permission check,
//! reader drain, directory sync, quota refund, or a product cleanup consumer. The tests only
//! establish the finite seven-column schema and its retained-receipt/phase guards.
#![cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]

mod harness;

use std::time::Duration;

use openbot_infra::artifact_administration;
use openbot_infra::artifact_registry;
use openbot_infra::db::artifact_cleanup_schema::{self, ArtifactCleanupSchemaError};
use openbot_infra::db::pool::{DatabaseConfig, DatabasePool};
use openbot_infra::db::{approval_preference_schema, baseline, fresh, native, pool, schema_facts};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tokio_postgres::Client;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

const TABLE: &str = "openbot_internal.artifact_cleanup_fences";
const INSERT_FENCE: &str = "INSERT INTO openbot_internal.artifact_cleanup_fences
    (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase)
    VALUES($1,$2,$3,$4,$5,$6,$7)";

#[derive(Clone, Debug)]
struct Receipt {
    namespace: [String; 3],
    operation: String,
    artifact: String,
    request: String,
    owner: String,
    thread: String,
    run: String,
    message: String,
    call: Option<i64>,
    attempt: Option<i64>,
}

impl Receipt {
    fn new() -> Self {
        Self {
            namespace: [
                "cleanup-fixture-deployment".to_owned(),
                "cleanup-fixture-tenant".to_owned(),
                "cleanup-fixture-dataset".to_owned(),
            ],
            operation: Uuid::now_v7().to_string(),
            artifact: Uuid::now_v7().to_string(),
            request: Uuid::now_v7().to_string(),
            owner: "cleanup-fixture-owner".to_owned(),
            thread: "cleanup-fixture-thread".to_owned(),
            run: "cleanup-fixture-run".to_owned(),
            message: "cleanup-fixture-message".to_owned(),
            call: Some(7),
            attempt: Some(11),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fence {
    key: [String; 5],
    terminal: String,
    phase: String,
}

impl Fence {
    fn armed(receipt: &Receipt, terminal: &str) -> Self {
        Self {
            key: [
                receipt.namespace[0].clone(),
                receipt.namespace[1].clone(),
                receipt.namespace[2].clone(),
                receipt.operation.clone(),
                receipt.artifact.clone(),
            ],
            terminal: terminal.to_owned(),
            phase: "armed".to_owned(),
        }
    }
}

async fn fresh_pool(config: &DatabaseConfig) -> DatabasePool {
    let pool = pool::connect(config).await.unwrap();
    let mut client = pool.get().await.unwrap();
    fresh::apply(&mut client).await.unwrap();
    drop(client);
    pool
}

/// All fields satisfy the existing 0042 checks; there are no user/source-row fixtures or FKs.
async fn insert_operation(client: &Client, receipt: &Receipt, state: &str) {
    let identity: [&(dyn tokio_postgres::types::ToSql + Sync); 13] = [
        &receipt.namespace[0],
        &receipt.namespace[1],
        &receipt.namespace[2],
        &receipt.request,
        &receipt.operation,
        &receipt.artifact,
        &receipt.owner,
        &receipt.thread,
        &receipt.run,
        &receipt.message,
        &receipt.call,
        &receipt.attempt,
        &state,
    ];
    if matches!(state, "deleted" | "expired") {
        client
            .execute(
                "INSERT INTO openbot_internal.artifact_save_operations
                 (deployment_id,tenant_id,dataset_id,request_id,operation_id,artifact_id,
                  owner_actor_id,source_thread_id,source_run_id,source_message_id,
                  source_call_seq,source_attempt_seq,state)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                &identity,
            )
            .await
            .unwrap();
    } else {
        let inserted = client
            .query_opt(
                "INSERT INTO openbot_internal.artifact_store_bindings
                 (deployment_id,tenant_id,dataset_id,store_id,root_device,root_inode,root_uid)
                 VALUES($1,$2,$3,$4,'1','2','3') ON CONFLICT DO NOTHING RETURNING store_id",
                &[
                    &receipt.namespace[0],
                    &receipt.namespace[1],
                    &receipt.namespace[2],
                    &Uuid::now_v7().to_string(),
                ],
            )
            .await
            .unwrap();
        let store: String = if let Some(row) = inserted {
            row.get(0)
        } else {
            client
                .query_one(
                    "SELECT store_id FROM openbot_internal.artifact_store_bindings
                     WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3",
                    &[
                        &receipt.namespace[0],
                        &receipt.namespace[1],
                        &receipt.namespace[2],
                    ],
                )
                .await
                .unwrap()
                .get::<_, String>(0)
        };
        let mut parameters = identity.to_vec();
        parameters.push(&store);
        client
            .execute(
                "INSERT INTO openbot_internal.artifact_save_operations
                 (deployment_id,tenant_id,dataset_id,request_id,operation_id,artifact_id,
                  owner_actor_id,source_thread_id,source_run_id,source_message_id,
                  source_call_seq,source_attempt_seq,state,store_id,workspace_kind,
                  workspace_id,expected_sha256,expected_bytes,charged_bytes,created_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'thread',
                        'fixture-workspace',repeat('a',64),1,1,'2020-01-01T00:00:00Z')",
                &parameters,
            )
            .await
            .unwrap();
    }
}

async fn insert_record(client: &Client, receipt: &Receipt, status: &str) {
    let parameters: [&(dyn tokio_postgres::types::ToSql + Sync); 13] = [
        &receipt.namespace[0],
        &receipt.namespace[1],
        &receipt.namespace[2],
        &receipt.artifact,
        &receipt.operation,
        &receipt.request,
        &receipt.owner,
        &receipt.thread,
        &receipt.run,
        &receipt.message,
        &receipt.call,
        &receipt.attempt,
        &status,
    ];
    let sql = if matches!(status, "deleted" | "expired") {
        "INSERT INTO openbot_internal.artifact_records
         (deployment_id,tenant_id,dataset_id,artifact_id,operation_id,request_id,
          owner_actor_id,source_thread_id,source_run_id,source_message_id,
          source_call_seq,source_attempt_seq,status)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)"
    } else {
        "INSERT INTO openbot_internal.artifact_records
         (deployment_id,tenant_id,dataset_id,artifact_id,operation_id,request_id,
          owner_actor_id,source_thread_id,source_run_id,source_message_id,
          source_call_seq,source_attempt_seq,status,workspace_kind,workspace_id,
          media_type,byte_length,sha256,retention_class,saved_by,saved_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'thread',
                'fixture-workspace','text/plain; charset=utf-8',1,repeat('a',64),
                'explicit_saved',$7,'2020-01-01T00:00:00Z')"
    };
    client.execute(sql, &parameters).await.unwrap();
}

async fn insert_pair(client: &Client, receipt: &Receipt, state: &str, status: &str) {
    insert_operation(client, receipt, state).await;
    insert_record(client, receipt, status).await;
}

async fn insert_fence(client: &Client, fence: &Fence) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            INSERT_FENCE,
            &[
                &fence.key[0],
                &fence.key[1],
                &fence.key[2],
                &fence.key[3],
                &fence.key[4],
                &fence.terminal,
                &fence.phase,
            ],
        )
        .await
}

async fn read_fence(client: &Client, fence: &Fence) -> Fence {
    let row = client
        .query_one(
            "SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,
                    terminal_status,phase FROM openbot_internal.artifact_cleanup_fences
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4",
            &[&fence.key[0], &fence.key[1], &fence.key[2], &fence.key[4]],
        )
        .await
        .unwrap();
    Fence {
        key: std::array::from_fn(|index| row.get(index)),
        terminal: row.get(5),
        phase: row.get(6),
    }
}

async fn complete(client: &Client, fence: &Fence) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            "UPDATE openbot_internal.artifact_cleanup_fences SET phase='completed'
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4",
            &[&fence.key[0], &fence.key[1], &fence.key[2], &fence.key[4]],
        )
        .await
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

async fn legacy_rows(client: &Client) -> Value {
    let raw: String = client
        .query_one(
            "SELECT jsonb_build_object(
               'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),
                 '[]'::jsonb) FROM openbot_internal.artifact_save_operations o),
               'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),
                 '[]'::jsonb) FROM openbot_internal.artifact_records r),
               'stores',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),
                 '[]'::jsonb) FROM openbot_internal.artifact_store_bindings s),
               'preferences',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY to_jsonb(p)::text),
                 '[]'::jsonb) FROM openbot_internal.approval_preferences p),
               'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text),
                 '[]'::jsonb) FROM public.audit_events a))::text",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    serde_json::from_str(&raw).unwrap()
}

async fn business_rows(client: &Client) -> Value {
    let mut rows = legacy_rows(client).await;
    let raw: String = client
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),
                    '[]'::jsonb)::text FROM openbot_internal.artifact_cleanup_fences f",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    rows["fences"] = serde_json::from_str(&raw).unwrap();
    rows
}

async fn assert_insert_refused(client: &Client, fence: &Fence, state: &SqlState) {
    let before = business_rows(client).await;
    let error = insert_fence(client, fence).await.unwrap_err();
    assert_eq!(error.code(), Some(state));
    assert_eq!(business_rows(client).await, before);
}

async fn assert_completion_refused(client: &Client, fence: &Fence) {
    let before = business_rows(client).await;
    let error = complete(client, fence).await.unwrap_err();
    assert_eq!(
        error.code(),
        Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE)
    );
    assert_eq!(business_rows(client).await, before);
    assert_eq!(read_fence(client, fence).await, *fence);
}

fn incompressible_identity(tag: &str) -> String {
    (0..8)
        .map(|counter| {
            format!(
                "{:x}",
                Sha256::digest(format!("cleanup-fence/{tag}/{counter}").as_bytes())
            )
        })
        .collect()
}

async fn assert_old_oracles(pool: &DatabasePool, public_fixture: &'static str) {
    let client = pool.get().await.unwrap();
    let public: schema_facts::SchemaFacts = serde_json::from_str(public_fixture).unwrap();
    assert_eq!(schema_facts::fetch(&client).await.unwrap(), public);
    let preferences: Value = serde_json::from_str(include_str!(
        "../../../fixtures/db/approval-preferences-0043.json"
    ))
    .unwrap();
    assert_eq!(
        approval_preference_schema::capture(&client).await.unwrap(),
        preferences
    );
    approval_preference_schema::verify(&client).await.unwrap();
    drop(client);
    let registration: Value = serde_json::from_str(include_str!(
        "../../../fixtures/db/artifact-registration-0042.json"
    ))
    .unwrap();
    assert_eq!(
        artifact_administration::capture_artifact_registration_schema(pool)
            .await
            .unwrap(),
        registration
    );
    let dataset: Value = serde_json::from_str(include_str!(
        "../../../fixtures/db/artifact-dataset-bindings-0041.json"
    ))
    .unwrap();
    assert_eq!(
        artifact_registry::capture_artifact_registry_schema(pool)
            .await
            .unwrap(),
        dataset
    );
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn native_0045_desktop_canary_preflight_accepts_fresh_and_upgrade_read_only() {
    for upgrade in [false, true] {
        harness::with_temp_database(
            &harness::admin_config("canary45layout"),
            "canary45layout",
            |config| async move {
                let pool = pool::connect(&config).await.unwrap();
                let mut client = pool.get().await.unwrap();
                if upgrade {
                    baseline::apply(&client).await.unwrap();
                    native::apply_through(&mut client, native::NATIVE_0044_VERSION)
                        .await
                        .unwrap();
                    drop(client);
                    assert_eq!(
                        openbot_infra::db::desktop_vault_canary::verify_pre_upgrade_layout(&pool)
                            .await
                            .unwrap()
                            .native_version(),
                        native::NATIVE_0044_VERSION
                    );
                    client = pool.get().await.unwrap();
                    native::apply(&mut client).await.unwrap();
                } else {
                    fresh::apply(&mut client).await.unwrap();
                }
                let before_ledger = ledger(&client).await;
                let before_rows = business_rows(&client).await;
                drop(client);
                let layout =
                    openbot_infra::db::desktop_vault_canary::verify_pre_upgrade_layout(&pool)
                        .await
                        .expect(
                            "current canary preflight must accept its registered public layout",
                        );
                assert_eq!(layout.native_version(), native::NATIVE_0053_VERSION);
                openbot_infra::db::desktop_vault_canary::verify_current_layout(&pool)
                    .await
                    .unwrap();
                assert_old_oracles(&pool, include_str!("../../../fixtures/db/schema-0052.json"))
                    .await;
                let client = pool.get().await.unwrap();
                assert_eq!(ledger(&client).await, before_ledger);
                assert_eq!(business_rows(&client).await, before_rows);
                drop(client);
                pool.close();
                Ok(())
            },
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn fresh_and_upgrade_catalogs_match_frozen_cleanup_oracle() {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../fixtures/db/artifact-cleanup-fences-0045.json"
    ))
    .unwrap();
    assert_eq!(native::NATIVE_LATEST_VERSION, native::NATIVE_0053_VERSION);
    for upgrade in [false, true] {
        let expected = expected.clone();
        harness::with_temp_database(
            &harness::admin_config("cleanup44catalog"),
            "cleanup44catalog",
            |config| async move {
                let pool = pool::connect(&config).await.unwrap();
                let mut client = pool.get().await.unwrap();
                let old_ledger;
                let old_rows;
                if upgrade {
                    baseline::apply(&client).await.unwrap();
                    native::apply_through(&mut client, native::NATIVE_0044_VERSION)
                        .await
                        .unwrap();
                    let receipt = Receipt::new();
                    insert_pair(&client, &receipt, "deleted", "deleted").await;
                    client
                        .execute(
                            "INSERT INTO public.audit_events
                             (id,event_type,target_type,target_id,payload,created_at)
                             VALUES($1,'fixture.cleanup_observation','schema_fixture',
                                    'fixture-only','{\"fixture\":true}'::jsonb,
                                    '2020-01-01T00:00:00Z')",
                            &[&Uuid::now_v7()],
                        )
                        .await
                        .unwrap();
                    old_ledger = ledger(&client).await;
                    old_rows = legacy_rows(&client).await;
                    let raw: String = client
                        .query_one(
                            artifact_cleanup_schema::ARTIFACT_CLEANUP_SCHEMA_0044_SQL,
                            &[],
                        )
                        .await
                        .unwrap()
                        .get(0);
                    let original: Value = serde_json::from_str(&raw).unwrap();
                    let old: Value = serde_json::from_str(include_str!(
                        "../../../fixtures/db/artifact-cleanup-fences-0044.json"
                    ))
                    .unwrap();
                    assert_eq!(original, old);
                    assert!(artifact_cleanup_schema::verify(&client).await.is_err());
                    assert_eq!(ledger(&client).await, old_ledger);
                    assert_eq!(legacy_rows(&client).await, old_rows);
                    drop(client);
                    assert_old_oracles(
                        &pool,
                        include_str!("../../../fixtures/db/schema-0040.json"),
                    )
                    .await;
                    client = pool.get().await.unwrap();
                    native::apply(&mut client).await.unwrap();
                } else {
                    old_ledger = Vec::new();
                    old_rows = Value::Null;
                    fresh::apply(&mut client).await.unwrap();
                }
                artifact_cleanup_schema::verify(&client).await.unwrap();
                assert_eq!(
                    artifact_cleanup_schema::capture(&client).await.unwrap(),
                    expected
                );
                let current = ledger(&client).await;
                assert_eq!(
                    current.iter().map(|row| row.0).collect::<Vec<_>>(),
                    (13..=native::NATIVE_0053_VERSION).collect::<Vec<_>>()
                );
                assert_eq!(current.last().unwrap().1, native::NATIVE_0053_NAME);
                assert_eq!(
                    current.last().unwrap().2,
                    format!("{:x}", Sha256::digest(native::NATIVE_0053_SQL.as_bytes()))
                );
                if upgrade {
                    assert_eq!(&current[..old_ledger.len()], old_ledger.as_slice());
                    assert_eq!(current.len(), old_ledger.len() + 9);
                    assert_eq!(
                        current[old_ledger.len()..]
                            .iter()
                            .map(|row| row.0)
                            .collect::<Vec<_>>(),
                        [
                            native::NATIVE_0045_VERSION,
                            native::NATIVE_0046_VERSION,
                            native::NATIVE_0047_VERSION,
                            native::NATIVE_0048_VERSION,
                            native::NATIVE_0049_VERSION,
                            native::NATIVE_0050_VERSION,
                            native::NATIVE_0051_VERSION,
                            native::NATIVE_0052_VERSION,
                            native::NATIVE_0053_VERSION,
                        ]
                    );
                    assert_eq!(legacy_rows(&client).await, old_rows);
                }
                let before = business_rows(&client).await;
                assert_eq!(before["fences"], serde_json::json!([]));
                assert_eq!(
                    native::apply(&mut client).await.unwrap(),
                    native::ApplyOutcome::AlreadyApplied
                );
                assert_eq!(ledger(&client).await, current);
                assert_eq!(business_rows(&client).await, before);
                client.batch_execute("BEGIN READ ONLY").await.unwrap();
                artifact_cleanup_schema::verify(&client).await.unwrap();
                assert_eq!(
                    artifact_cleanup_schema::capture(&client).await.unwrap(),
                    expected
                );
                client.batch_execute("ROLLBACK").await.unwrap();
                assert_eq!(ledger(&client).await, current);
                assert_eq!(business_rows(&client).await, before);
                drop(client);
                assert_old_oracles(&pool, include_str!("../../../fixtures/db/schema-0052.json"))
                    .await;
                artifact_administration::verify_artifact_registration_schema(&pool)
                    .await
                    .unwrap();
                pool.close();
                Ok(())
            },
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn identity_bytes_cc_and_maximum_incompressible_key_are_enforced() {
    harness::with_temp_database(
        &harness::admin_config("cleanup44identity"),
        "cleanup44identity",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            let controls: Vec<char> = (0..=0x1f)
                .chain(0x7f..=0x9f)
                .map(|code| char::from_u32(code).unwrap())
                .collect();
            assert_eq!(controls.len(), 65);
            for control in controls {
                assert!(control.is_control());
                for coordinate in 0..3 {
                    let mut fence = Fence::armed(&Receipt::new(), "deleted");
                    fence.key[coordinate] = format!("before{control}after");
                    let state = if control == '\0' {
                        SqlState::CHARACTER_NOT_IN_REPERTOIRE
                    } else {
                        SqlState::CHECK_VIOLATION
                    };
                    assert_insert_refused(&client, &fence, &state).await;
                }
            }
            let exact = format!("{}ab", "中".repeat(170));
            assert_eq!(exact.len(), 512);
            assert_eq!(exact.chars().count(), 172);
            for coordinate in 0..3 {
                let mut receipt = Receipt::new();
                receipt.namespace[coordinate] = exact.clone();
                insert_pair(&client, &receipt, "deleted", "deleted").await;
                let fence = Fence::armed(&receipt, "deleted");
                insert_fence(&client, &fence).await.unwrap();
                assert_eq!(read_fence(&client, &fence).await, fence);
                for invalid in [String::new(), format!("{exact}c")] {
                    let mut bad = Fence::armed(&Receipt::new(), "deleted");
                    bad.key[coordinate] = invalid;
                    assert_insert_refused(&client, &bad, &SqlState::CHECK_VIOLATION).await;
                }
                for allowed in [
                    ' ', '~', '\u{a0}', '\u{ad}', '\u{200b}', '\u{200d}', '中', '🦀',
                ] {
                    assert!(!allowed.is_control());
                    let mut receipt = Receipt::new();
                    receipt.namespace[coordinate] = format!("  opaque/{allowed}/value  ");
                    insert_pair(&client, &receipt, "deleted", "deleted").await;
                    let fence = Fence::armed(&receipt, "deleted");
                    insert_fence(&client, &fence).await.unwrap();
                    assert_eq!(read_fence(&client, &fence).await, fence);
                }
            }
            for coordinate in 3..5 {
                for invalid in [
                    "018F0AB1-7C2D-7E3F-8A4B-5C6D7E8F9012".to_owned(),
                    "12345678-1234-4123-8123-123456789abc".to_owned(),
                    "12345678-1234-7123-0123-123456789abc".to_owned(),
                    "12345678123471238123123456789abc".to_owned(),
                    "018f0ab1-7c2d-7e3f-8a4b-5c6d7e8f9012\n".to_owned(),
                ] {
                    let mut fence = Fence::armed(&Receipt::new(), "deleted");
                    fence.key[coordinate] = invalid;
                    assert_insert_refused(&client, &fence, &SqlState::CHECK_VIOLATION).await;
                }
            }
            let mut receipt = Receipt::new();
            for coordinate in 0..3 {
                receipt.namespace[coordinate] =
                    incompressible_identity(&format!("largest/{coordinate}"));
                assert_eq!(receipt.namespace[coordinate].len(), 512);
            }
            insert_pair(&client, &receipt, "deleted", "deleted").await;
            let largest = Fence::armed(&receipt, "deleted");
            insert_fence(&client, &largest).await.unwrap();
            assert_eq!(read_fence(&client, &largest).await, largest);
            let sizes = client
                .query_one(
                    "SELECT pg_column_size(deployment_id),pg_column_size(tenant_id),
                            pg_column_size(dataset_id)
                     FROM openbot_internal.artifact_cleanup_fences WHERE operation_id=$1",
                    &[&receipt.operation],
                )
                .await
                .unwrap();
            for coordinate in 0..3 {
                assert!(sizes.get::<_, i32>(coordinate) >= 512);
                let mut separate = Receipt::new();
                separate.namespace = receipt.namespace.clone();
                separate.namespace[coordinate] =
                    incompressible_identity(&format!("separate/{coordinate}"));
                insert_pair(&client, &separate, "deleted", "deleted").await;
                let fence = Fence::armed(&separate, "deleted");
                insert_fence(&client, &fence).await.unwrap();
                assert_eq!(read_fence(&client, &fence).await, fence);
            }
            assert_insert_refused(&client, &largest, &SqlState::UNIQUE_VIOLATION).await;
            artifact_cleanup_schema::verify(&client).await.unwrap();
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn record_five_key_pair_is_required() {
    harness::with_temp_database(
        &harness::admin_config("cleanup44pair"),
        "cleanup44pair",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            let receipt = Receipt::new();
            insert_pair(&client, &receipt, "deleted", "deleted").await;
            let valid = Fence::armed(&receipt, "deleted");
            for coordinate in 0..5 {
                let mut bad = valid.clone();
                bad.key[coordinate] = if coordinate < 3 {
                    format!("different-{coordinate}")
                } else {
                    Uuid::now_v7().to_string()
                };
                let before = business_rows(&client).await;
                let error = insert_fence(&client, &bad).await.unwrap_err();
                assert_eq!(error.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));
                assert_eq!(
                    error.as_db_error().unwrap().constraint(),
                    Some("artifact_cleanup_fences_record_pair_fkey")
                );
                assert_eq!(business_rows(&client).await, before);
            }
            let no_record = Receipt::new();
            insert_operation(&client, &no_record, "deleted").await;
            assert_insert_refused(
                &client,
                &Fence::armed(&no_record, "deleted"),
                &SqlState::FOREIGN_KEY_VIOLATION,
            )
            .await;
            assert_eq!(insert_fence(&client, &valid).await.unwrap(), 1);
            assert_eq!(read_fence(&client, &valid).await, valid);
            let orphan = Fence::armed(&Receipt::new(), "deleted");
            assert_insert_refused(&client, &orphan, &SqlState::FOREIGN_KEY_VIOLATION).await;
            artifact_cleanup_schema::verify(&client).await.unwrap();
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn concurrent_arms_preserve_one_original_fence() {
    harness::with_temp_database(
        &harness::admin_config("cleanup44concurrent"),
        "cleanup44concurrent",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let first = pool.get().await.unwrap();
            let second = pool.get().await.unwrap();
            let first_pid: i32 = first.query_one("SELECT pg_backend_pid()", &[]).await.unwrap().get(0);
            let second_pid: i32 = second.query_one("SELECT pg_backend_pid()", &[]).await.unwrap().get(0);
            assert_ne!(first_pid, second_pid);
            let receipt = Receipt::new();
            insert_pair(&first, &receipt, "deleted", "deleted").await;
            let original = Fence::armed(&receipt, "deleted");
            let mut competing = original.clone();
            competing.terminal = "expired".to_owned();
            first.batch_execute("BEGIN").await.unwrap();
            insert_fence(&first, &original).await.unwrap();
            second
                .batch_execute("BEGIN; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='5s'")
                .await
                .unwrap();
            let error = {
                let attempt = insert_fence(&second, &competing);
                let wait_parameters: [&(dyn tokio_postgres::types::ToSql + Sync); 1] = [&second_pid];
                tokio::pin!(attempt);
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        tokio::select! {
                            biased;
                            outcome = &mut attempt => panic!("second INSERT did not wait: {outcome:?}"),
                            row = first.query_one("SELECT pg_blocking_pids($1)", &wait_parameters) => {
                                let blockers: Vec<i32> = row.unwrap().get(0);
                                if blockers.contains(&first_pid) {
                                    break;
                                }
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("actual PostgreSQL unique-key wait must be observed");
                first.batch_execute("COMMIT").await.unwrap();
                attempt.await.unwrap_err()
            };
            assert_eq!(error.code(), Some(&SqlState::UNIQUE_VIOLATION));
            assert_eq!(
                error.as_db_error().unwrap().constraint(),
                Some("artifact_cleanup_fences_pkey")
            );
            second.batch_execute("ROLLBACK").await.unwrap();
            assert_eq!(read_fence(&first, &original).await, original);
            assert_eq!(read_fence(&second, &original).await, original);
            assert_eq!(
                first.query_one("SELECT count(*) FROM openbot_internal.artifact_cleanup_fences", &[])
                    .await.unwrap().get::<_, i64>(0),
                1
            );
            artifact_cleanup_schema::verify(&first).await.unwrap();
            drop(first);
            drop(second);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn insert_completed_and_rebind_of_six_immutable_fields_are_rejected() {
    harness::with_temp_database(
        &harness::admin_config("cleanup44immutable"),
        "cleanup44immutable",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            let receipt = Receipt::new();
            insert_pair(&client, &receipt, "deleted", "deleted").await;
            let fence = Fence::armed(&receipt, "deleted");
            let mut direct = fence.clone();
            direct.phase = "completed".to_owned();
            assert_insert_refused(&client, &direct, &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE)
                .await;
            let mut invalid_status = fence.clone();
            invalid_status.terminal = "available".to_owned();
            assert_insert_refused(&client, &invalid_status, &SqlState::CHECK_VIOLATION).await;
            let mut invalid_phase = fence.clone();
            invalid_phase.phase = "unknown".to_owned();
            assert_insert_refused(&client, &invalid_phase, &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE)
                .await;
            insert_fence(&client, &fence).await.unwrap();
            let columns = [
                "deployment_id", "tenant_id", "dataset_id", "operation_id", "artifact_id",
                "terminal_status",
            ];
            for (coordinate, column) in columns.into_iter().enumerate() {
                let replacement = match coordinate {
                    0..=2 => format!("replacement-{coordinate}"),
                    3..=4 => Uuid::now_v7().to_string(),
                    _ => "expired".to_owned(),
                };
                let before = business_rows(&client).await;
                let error = client
                    .execute(
                        &format!("UPDATE {TABLE} SET {column}=$1 WHERE operation_id=$2"),
                        &[&replacement, &receipt.operation],
                    )
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE));
                assert_eq!(business_rows(&client).await, before);
                assert_eq!(read_fence(&client, &fence).await, fence);
            }
            let before = business_rows(&client).await;
            assert_eq!(
                client.execute("UPDATE openbot_internal.artifact_cleanup_fences SET phase=phase,
                    deployment_id=deployment_id,terminal_status=terminal_status WHERE operation_id=$1",
                    &[&receipt.operation]).await.unwrap(),
                1
            );
            assert_eq!(business_rows(&client).await, before);
            artifact_cleanup_schema::verify(&client).await.unwrap();
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn delete_truncate_and_completed_rearm_are_rejected() {
    harness::with_temp_database(
        &harness::admin_config("cleanup44final"),
        "cleanup44final",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            let receipt = Receipt::new();
            insert_pair(&client, &receipt, "deleted", "deleted").await;
            let fence = Fence::armed(&receipt, "deleted");
            insert_fence(&client, &fence).await.unwrap();
            for sql in [
                "DELETE FROM openbot_internal.artifact_cleanup_fences",
                "TRUNCATE openbot_internal.artifact_cleanup_fences",
            ] {
                let before = business_rows(&client).await;
                let error = client.batch_execute(sql).await.unwrap_err();
                assert_eq!(
                    error.code(),
                    Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE)
                );
                assert_eq!(business_rows(&client).await, before);
                assert_eq!(read_fence(&client, &fence).await, fence);
            }
            assert_eq!(complete(&client, &fence).await.unwrap(), 1);
            let mut completed = fence.clone();
            completed.phase = "completed".to_owned();
            assert_eq!(read_fence(&client, &fence).await, completed);
            for sql in [
                "DELETE FROM openbot_internal.artifact_cleanup_fences",
                "TRUNCATE openbot_internal.artifact_cleanup_fences",
                "UPDATE openbot_internal.artifact_cleanup_fences SET phase='armed'",
                "UPDATE openbot_internal.artifact_cleanup_fences SET terminal_status='expired'",
            ] {
                let before = business_rows(&client).await;
                let error = client.batch_execute(sql).await.unwrap_err();
                assert_eq!(
                    error.code(),
                    Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE)
                );
                assert_eq!(business_rows(&client).await, before);
                assert_eq!(read_fence(&client, &fence).await, completed);
            }
            let before = business_rows(&client).await;
            assert_eq!(complete(&client, &fence).await.unwrap(), 1);
            assert_eq!(business_rows(&client).await, before);
            artifact_cleanup_schema::verify(&client).await.unwrap();
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn completion_requires_both_terminal_rows_and_exact_target() {
    harness::with_temp_database(
        &harness::admin_config("cleanup44terminal"),
        "cleanup44terminal",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            for (state, status, target, accepted) in [
                ("deleted", "deleted", "deleted", true),
                ("expired", "expired", "expired", true),
                ("deleted", "deleted", "expired", false),
                ("expired", "expired", "deleted", false),
                ("deleted", "expired", "deleted", false),
                ("expired", "deleted", "deleted", false),
                ("available", "deleted", "deleted", false),
                ("deleted", "available", "deleted", false),
                ("available", "available", "deleted", false),
            ] {
                let receipt = Receipt::new();
                insert_pair(&client, &receipt, state, status).await;
                let fence = Fence::armed(&receipt, target);
                insert_fence(&client, &fence).await.unwrap();
                if accepted {
                    assert_eq!(complete(&client, &fence).await.unwrap(), 1);
                    let mut expected = fence.clone();
                    expected.phase = "completed".to_owned();
                    assert_eq!(read_fence(&client, &fence).await, expected);
                } else {
                    assert_completion_refused(&client, &fence).await;
                }
            }
            // 0042's operation FK lacks artifact_id. This legal DB fixture isolates that gap.
            let operation = Receipt::new();
            let mut record = operation.clone();
            record.artifact = Uuid::now_v7().to_string();
            insert_operation(&client, &operation, "deleted").await;
            insert_record(&client, &record, "deleted").await;
            let fence = Fence::armed(&record, "deleted");
            insert_fence(&client, &fence).await.unwrap();
            assert_completion_refused(&client, &fence).await;
            let before = business_rows(&client).await;
            let receipt = Receipt::new();
            let error = client
                .execute(
                    "INSERT INTO openbot_internal.artifact_records
                     (deployment_id,tenant_id,dataset_id,artifact_id,operation_id,request_id,
                      owner_actor_id,source_thread_id,source_run_id,source_message_id,status,
                      byte_length)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'deleted',1)",
                    &[
                        &receipt.namespace[0],
                        &receipt.namespace[1],
                        &receipt.namespace[2],
                        &receipt.artifact,
                        &receipt.operation,
                        &receipt.request,
                        &receipt.owner,
                        &receipt.thread,
                        &receipt.run,
                        &receipt.message,
                    ],
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
            assert_eq!(
                error.as_db_error().unwrap().constraint(),
                Some("artifact_records_payload")
            );
            assert_eq!(business_rows(&client).await, before);
            artifact_cleanup_schema::verify(&client).await.unwrap();
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn completion_requires_null_safe_retained_receipt_identity() {
    harness::with_temp_database(
        &harness::admin_config("cleanup44receipt"),
        "cleanup44receipt",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            for coordinate in 0..7 {
                let operation = Receipt::new();
                let mut record = operation.clone();
                match coordinate {
                    0 => record.request = Uuid::now_v7().to_string(),
                    1 => record.owner = "different-owner".to_owned(),
                    2 => record.thread = "different-thread".to_owned(),
                    3 => record.run = "different-run".to_owned(),
                    4 => record.message = "different-message".to_owned(),
                    5 => record.call = Some(8),
                    _ => record.attempt = Some(12),
                }
                insert_operation(&client, &operation, "deleted").await;
                insert_record(&client, &record, "deleted").await;
                let fence = Fence::armed(&record, "deleted");
                insert_fence(&client, &fence).await.unwrap();
                assert_completion_refused(&client, &fence).await;
            }
            for operation_null in [false, true] {
                let mut operation = Receipt::new();
                let mut record = operation.clone();
                let null_receipt = if operation_null {
                    &mut operation
                } else {
                    &mut record
                };
                null_receipt.call = None;
                null_receipt.attempt = None;
                insert_operation(&client, &operation, "deleted").await;
                insert_record(&client, &record, "deleted").await;
                let fence = Fence::armed(&record, "deleted");
                insert_fence(&client, &fence).await.unwrap();
                assert_completion_refused(&client, &fence).await;
            }
            for terminal in ["deleted", "expired"] {
                let mut receipt = Receipt::new();
                receipt.call = None;
                receipt.attempt = None;
                insert_pair(&client, &receipt, terminal, terminal).await;
                let fence = Fence::armed(&receipt, terminal);
                insert_fence(&client, &fence).await.unwrap();
                assert_eq!(complete(&client, &fence).await.unwrap(), 1);
                assert_eq!(read_fence(&client, &fence).await.phase, "completed");
            }
            artifact_cleanup_schema::verify(&client).await.unwrap();
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn completion_checks_existing_saved_receipt_including_null_sequences() {
    harness::with_temp_database(
        &harness::admin_config("cleanup45receipt"),
        "cleanup45receipt",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            // All seven mismatches are legal under the original FK/checks; completion must refuse.
            for coordinate in 0..9 {
                let mut original = Receipt::new();
                if coordinate == 8 {
                    original.call = None;
                    original.attempt = None;
                }
                insert_pair(&client, &original, "deleted", "deleted").await;
                let mut saved = original.clone();
                match coordinate {
                    0 => saved.request = Uuid::now_v7().to_string(),
                    1 => saved.owner = "other-saved-owner".to_owned(),
                    2 => saved.thread = "other-saved-thread".to_owned(),
                    3 => saved.run = "other-saved-run".to_owned(),
                    4 => saved.message = "other-saved-message".to_owned(),
                    5 => saved.call = Some(8),
                    6 => saved.attempt = Some(12),
                    7 => {
                        saved.call = None;
                        saved.attempt = None;
                    }
                    _ => {
                        saved.call = Some(7);
                        saved.attempt = Some(11);
                    }
                }
                insert_saved_receipt(&client, &saved).await;
                let fence = Fence::armed(&original, "deleted");
                insert_fence(&client, &fence).await.unwrap();
                assert_completion_refused(&client, &fence).await;
            }
            for terminal in ["deleted", "expired"] {
                for has_receipt in [false, true] {
                    for null_sequences in [false, true] {
                        let mut original = Receipt::new();
                        if null_sequences {
                            original.call = None;
                            original.attempt = None;
                        }
                        insert_pair(&client, &original, terminal, terminal).await;
                        if has_receipt {
                            insert_saved_receipt(&client, &original).await;
                        }
                        let fence = Fence::armed(&original, terminal);
                        insert_fence(&client, &fence).await.unwrap();
                        assert_eq!(complete(&client, &fence).await.unwrap(), 1);
                    }
                }
            }
            artifact_cleanup_schema::verify(&client).await.unwrap();
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

async fn insert_saved_receipt(client: &Client, receipt: &Receipt) {
    client
        .execute(
            "INSERT INTO openbot_internal.artifact_saved_receipts
         (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,request_id,
          owner_actor_id,source_thread_id,source_run_id,source_message_id,
          source_call_seq,source_attempt_seq) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
            &[
                &receipt.namespace[0],
                &receipt.namespace[1],
                &receipt.namespace[2],
                &receipt.operation,
                &receipt.artifact,
                &receipt.request,
                &receipt.owner,
                &receipt.thread,
                &receipt.run,
                &receipt.message,
                &receipt.call,
                &receipt.attempt,
            ],
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn missing_disabled_and_replaced_parent_terminal_guards_are_refused_read_only() {
    harness::with_temp_database(&harness::admin_config("cleanup45parents"), "cleanup45parents", |config| async move {
        let pool = fresh_pool(&config).await;
        let client = pool.get().await.unwrap();
        let receipt = Receipt::new();
        insert_pair(&client, &receipt, "deleted", "deleted").await;
        insert_fence(&client, &Fence::armed(&receipt, "deleted")).await.unwrap();
        for ddl in [
            "ALTER TABLE openbot_internal.artifact_records DISABLE TRIGGER artifact_records_identity_guard",
            "DROP TRIGGER artifact_records_identity_guard ON openbot_internal.artifact_records",
            "ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard",
            "DROP TRIGGER artifact_save_operations_identity_guard ON openbot_internal.artifact_save_operations",
            "CREATE OR REPLACE FUNCTION openbot_internal.prevent_artifact_record_misuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
            "CREATE OR REPLACE FUNCTION openbot_internal.prevent_artifact_operation_misuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
            "ALTER FUNCTION openbot_internal.prevent_artifact_record_misuse() SECURITY DEFINER",
            "ALTER FUNCTION openbot_internal.prevent_artifact_operation_misuse() SET search_path TO public",
        ] {
            let before = business_rows(&client).await;
            let migration_before = ledger(&client).await;
            client.batch_execute("BEGIN").await.unwrap();
            client.batch_execute(ddl).await.unwrap();
            // The cleanup relation alone is unchanged; its parent dependencies must still fail.
            let catalog = artifact_cleanup_schema::capture(&client).await.unwrap();
            assert!(matches!(artifact_cleanup_schema::verify(&client).await,
                Err(ArtifactCleanupSchemaError::Corrupt { field: "parent_triggers" | "parent_guards" })));
            assert_eq!(artifact_cleanup_schema::capture(&client).await.unwrap(), catalog);
            assert_eq!(business_rows(&client).await, before);
            assert_eq!(ledger(&client).await, migration_before);
            client.batch_execute("ROLLBACK").await.unwrap();
            artifact_cleanup_schema::verify(&client).await.unwrap();
        }
        drop(client);
        pool.close();
        Ok(())
    }).await;
}

async fn assert_catalog_drift_refused(client: &Client, ddl: &str) {
    let original = artifact_cleanup_schema::capture(client).await.unwrap();
    let rows = business_rows(client).await;
    let migrations = ledger(client).await;
    client.batch_execute("BEGIN").await.unwrap();
    client.batch_execute(ddl).await.unwrap();
    let changed = artifact_cleanup_schema::capture(client).await.unwrap();
    // Adding a column changes to_jsonb(row) even without changing any stored business value.
    // Observe that actual post-DDL shape before verify, then require verify to preserve it.
    let changed_rows = business_rows(client).await;
    let outcome = artifact_cleanup_schema::verify(client).await;
    let observed = artifact_cleanup_schema::capture(client).await.unwrap();
    let observed_rows = business_rows(client).await;
    let observed_ledger = ledger(client).await;
    client.batch_execute("ROLLBACK").await.unwrap();
    assert_ne!(changed, original);
    assert_eq!(
        outcome,
        Err(ArtifactCleanupSchemaError::Corrupt {
            field: "internal_schema"
        })
    );
    assert_eq!(observed, changed);
    assert_eq!(observed_rows, changed_rows);
    assert_eq!(observed_ledger, migrations);
    assert_eq!(
        artifact_cleanup_schema::capture(client).await.unwrap(),
        original
    );
    assert_eq!(business_rows(client).await, rows);
    assert_eq!(ledger(client).await, migrations);
    artifact_cleanup_schema::verify(client).await.unwrap();
}

async fn assert_ledger_drift_refused(client: &Client, mutation: &str) {
    let original = artifact_cleanup_schema::capture(client).await.unwrap();
    let rows = business_rows(client).await;
    let migrations = ledger(client).await;
    client.batch_execute("BEGIN").await.unwrap();
    client.batch_execute(mutation).await.unwrap();
    let changed = ledger(client).await;
    let changed_schema = artifact_cleanup_schema::capture(client).await.unwrap();
    let outcome = artifact_cleanup_schema::verify(client).await;
    let observed = artifact_cleanup_schema::capture(client).await.unwrap();
    let observed_rows = business_rows(client).await;
    let observed_ledger = ledger(client).await;
    client.batch_execute("ROLLBACK").await.unwrap();
    assert_ne!(changed, migrations);
    assert_eq!(
        outcome,
        Err(ArtifactCleanupSchemaError::Corrupt {
            field: "native_prefix"
        })
    );
    // Capture intentionally includes the <=0045 ledger; compare the same mutated snapshot.
    assert_eq!(observed, changed_schema);
    assert_eq!(observed_rows, rows);
    assert_eq!(observed_ledger, changed);
    assert_eq!(ledger(client).await, migrations);
    assert_eq!(business_rows(client).await, rows);
    assert_eq!(
        artifact_cleanup_schema::capture(client).await.unwrap(),
        original
    );
    artifact_cleanup_schema::verify(client).await.unwrap();
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17; explicit include-ignored only"]
async fn catalog_guard_and_migration_drift_are_rejected_read_only() {
    harness::with_temp_database(
        &harness::admin_config("cleanup44drift"),
        "cleanup44drift",
        |config| async move {
            let pool = fresh_pool(&config).await;
            let client = pool.get().await.unwrap();
            let receipt = Receipt::new();
            insert_pair(&client, &receipt, "deleted", "deleted").await;
            insert_fence(&client, &Fence::armed(&receipt, "deleted")).await.unwrap();
            client.execute("INSERT INTO public.audit_events
                (id,event_type,target_type,target_id,payload,created_at)
                VALUES($1,'fixture.cleanup_observation','schema_fixture','fixture-only',
                       '{\"fixture\":true}'::jsonb,'2020-01-01T00:00:00Z')",
                &[&Uuid::now_v7()]).await.unwrap();
            for ddl in [
                "ALTER TABLE openbot_internal.artifact_cleanup_fences ALTER COLUMN phase SET DEFAULT 'armed'",
                "ALTER TABLE openbot_internal.artifact_cleanup_fences ALTER COLUMN terminal_status DROP NOT NULL",
                "ALTER TABLE openbot_internal.artifact_cleanup_fences ADD COLUMN fixture_extra text",
                "ALTER TABLE openbot_internal.artifact_cleanup_fences ALTER COLUMN deployment_id TYPE text COLLATE \"default\"",
                "ALTER TABLE openbot_internal.artifact_cleanup_fences DROP CONSTRAINT artifact_cleanup_fences_identity_shape",
                "ALTER TABLE openbot_internal.artifact_cleanup_fences DROP CONSTRAINT artifact_cleanup_fences_record_pair_fkey;
                 ALTER TABLE openbot_internal.artifact_cleanup_fences ADD CONSTRAINT artifact_cleanup_fences_record_pair_fkey
                 FOREIGN KEY(deployment_id,tenant_id,dataset_id,operation_id,artifact_id)
                 REFERENCES openbot_internal.artifact_records(deployment_id,tenant_id,dataset_id,operation_id,artifact_id)
                 ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED",
                "CREATE INDEX cleanup_fixture_extra_idx ON openbot_internal.artifact_cleanup_fences(phase)",
                "ALTER TABLE openbot_internal.artifact_cleanup_fences DISABLE TRIGGER artifact_cleanup_fences_identity_guard",
                "ALTER TABLE openbot_internal.artifact_cleanup_fences DISABLE TRIGGER artifact_cleanup_fences_no_truncate",
                "ALTER TABLE openbot_internal.artifact_cleanup_fences DISABLE TRIGGER ALL",
                "CREATE TRIGGER cleanup_fixture_extra_guard BEFORE UPDATE ON openbot_internal.artifact_cleanup_fences
                 FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_artifact_cleanup_fence_mutation()",
                "CREATE RULE cleanup_fixture_extra_rule AS ON DELETE TO openbot_internal.artifact_cleanup_fences DO INSTEAD NOTHING",
                "CREATE OR REPLACE FUNCTION openbot_internal.prevent_artifact_cleanup_fence_mutation()
                 RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
                "ALTER FUNCTION openbot_internal.prevent_artifact_cleanup_fence_mutation() SECURITY DEFINER",
                "ALTER FUNCTION openbot_internal.prevent_artifact_cleanup_fence_mutation() SET search_path TO public",
                "ALTER TABLE openbot_internal.artifact_records DROP CONSTRAINT artifact_records_payload",
                "ALTER TABLE openbot_internal.artifact_save_operations DROP CONSTRAINT artifact_save_operations_payload",
            ] {
                assert_catalog_drift_refused(&client, ddl).await;
            }
            let unknown_migration = format!(
                "INSERT INTO openbot_internal.schema_migrations(version,name,checksum)
                 VALUES({},'fixture_unknown_migration',repeat('0',64))",
                native::NATIVE_LATEST_VERSION + 1
            );
            for mutation in [
                "UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=44",
                "UPDATE openbot_internal.schema_migrations SET name='fixture_wrong_migration' WHERE version=44",
                "DELETE FROM openbot_internal.schema_migrations WHERE version=44",
                "DELETE FROM openbot_internal.schema_migrations WHERE version=43",
                unknown_migration.as_str(),
            ] {
                assert_ledger_drift_refused(&client, mutation).await;
            }
            let rows = business_rows(&client).await;
            let migrations = ledger(&client).await;
            client.batch_execute("BEGIN READ ONLY").await.unwrap();
            artifact_cleanup_schema::verify(&client).await.unwrap();
            client.batch_execute("ROLLBACK").await.unwrap();
            assert_eq!(business_rows(&client).await, rows);
            assert_eq!(ledger(&client).await, migrations);
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}
