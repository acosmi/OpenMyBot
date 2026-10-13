//! Artifact dataset 的真实临时库迁移、注册与失效回归；不把 SQL 字符串当执行证据。
mod harness;

use std::collections::BTreeSet;

use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_infra::artifact_registry::{
    ArtifactDatasetRegistry, ArtifactRegistryError, capture_artifact_registry_schema,
    verify_artifact_registry_schema,
};
use openbot_infra::db::{baseline, fresh, native, pool, schema_facts};
use tokio_postgres::error::SqlState;

const REGISTRY: &str = "openbot_internal.artifact_dataset_bindings";

fn internal_fixture() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/db/artifact-dataset-bindings-0041.json");
    serde_json::from_str(
        &std::fs::read_to_string(path).expect("须先从真实测试自建 PG 冻结内部 schema oracle"),
    )
    .unwrap()
}

async fn fresh_pool(config: &pool::DatabaseConfig) -> Result<pool::DatabasePool, String> {
    let p = pool::connect(config).await.map_err(|e| e.to_string())?;
    let mut c = p.get().await.map_err(|e| e.to_string())?;
    fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
    drop(c);
    Ok(p)
}

async fn registry_count(p: &pool::DatabasePool) -> i64 {
    let c = p.get().await.unwrap();
    c.query_one(&format!("SELECT count(*)::bigint FROM {REGISTRY}"), &[])
        .await
        .unwrap()
        .get(0)
}

async fn register(
    p: &pool::DatabasePool,
    deployment: &str,
    tenant: &str,
) -> ArtifactDatasetRegistry {
    ArtifactDatasetRegistry::from_server(
        p.clone(),
        &DeploymentId::new(deployment),
        &TenantId::new(tenant),
    )
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn fresh_current_native_preserves_exact_0041_registry_and_public_0040() {
    harness::with_temp_database(
        &harness::admin_config("artifact41fresh"),
        "artifact41fresh",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            let facts = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
            // 0041 is internal-only; PUBLIC has since moved past 0040, so fresh current must
            // equal the current PUBLIC oracle while the 0041 registry stays exact below.
            let expected: schema_facts::SchemaFacts =
                serde_json::from_str(include_str!("../../../fixtures/db/schema-0052.json"))
                    .unwrap();
            assert_eq!(facts, expected);
            assert_eq!(
                native::apply(&mut c).await.map_err(|e| e.to_string())?,
                native::ApplyOutcome::AlreadyApplied
            );
            let latest: i32 = c
                .query_one(
                    "SELECT max(version) FROM openbot_internal.schema_migrations",
                    &[],
                )
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            assert_eq!(latest, native::NATIVE_LATEST_VERSION);
            drop(c);
            assert_eq!(
                capture_artifact_registry_schema(&p).await.unwrap(),
                internal_fixture()
            );
            verify_artifact_registry_schema(&p).await.unwrap();
            assert_eq!(registry_count(&p).await, 0);
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn actual_0040_upgrades_once_without_rewriting_older_ledger_or_public_schema() {
    harness::with_temp_database(
        &harness::admin_config("artifact41upgrade"),
        "artifact41upgrade",
        |config| async move {
            let p = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply_through(&mut c, 40).await.map_err(|e| e.to_string())?;
            let before = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
            let historical: schema_facts::SchemaFacts =
                serde_json::from_str(include_str!("../../../fixtures/db/schema-0040.json"))
                    .unwrap();
            assert_eq!(before, historical);
            let ledger_sql = "SELECT version,name,checksum,applied_at::text FROM openbot_internal.schema_migrations WHERE version <= 40 ORDER BY version";
            let ledger_before: Vec<(i32, String, String, String)> = c
                .query(ledger_sql, &[]).await.map_err(|e| e.to_string())?
                .into_iter().map(|r| (r.get(0),r.get(1),r.get(2),r.get(3))).collect();
            assert_eq!(native::apply(&mut c).await.map_err(|e| e.to_string())?, native::ApplyOutcome::Applied);
            let ledger_after: Vec<(i32, String, String, String)> = c
                .query(ledger_sql, &[]).await.map_err(|e| e.to_string())?
                .into_iter().map(|r| (r.get(0),r.get(1),r.get(2),r.get(3))).collect();
            assert_eq!(ledger_after, ledger_before);
            // The current migration adds its registered table and model connection trigger.
            let current: schema_facts::SchemaFacts =
                serde_json::from_str(include_str!("../../../fixtures/db/schema-0052.json"))
                    .unwrap();
            assert_eq!(schema_facts::fetch(&c).await.map_err(|e| e.to_string())?, current);
            assert_eq!(native::apply(&mut c).await.map_err(|e| e.to_string())?, native::ApplyOutcome::AlreadyApplied);
            drop(c);
            assert_eq!(capture_artifact_registry_schema(&p).await.unwrap(), internal_fixture());
            assert_eq!(registry_count(&p).await, 0);
            register(&p, "upgrade-deployment", "upgrade-tenant").await.validate_current().await.unwrap();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn eight_concurrent_server_adoptions_converge_on_one_persisted_random_id() {
    harness::with_temp_database(
        &harness::admin_config("artifact41race"),
        "artifact41race",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let mut tasks = Vec::new();
            for _ in 0..8 {
                let p = p.clone();
                tasks.push(tokio::spawn(async move {
                    register(&p, "shared-deployment", "shared-tenant").await
                }));
            }
            let mut ids = BTreeSet::new();
            for task in tasks {
                let registry = task.await.map_err(|e| e.to_string())?;
                registry.validate_current().await.unwrap();
                assert_eq!(registry.binding().initial_origin(), "server_first_adoption");
                assert_eq!(registry.binding().deployment_id(), "shared-deployment");
                assert_eq!(registry.binding().tenant_id(), "shared-tenant");
                let id = registry.binding().dataset_id();
                assert_eq!(id.len(), 32);
                assert!(
                    id.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                );
                ids.insert(id.to_owned());
            }
            assert_eq!(ids.len(), 1);
            assert_eq!(registry_count(&p).await, 1);
            let c = p.get().await.map_err(|e| e.to_string())?;
            let persisted: String = c
                .query_one(&format!("SELECT dataset_id FROM {REGISTRY}"), &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            assert!(ids.contains(&persisted));
            drop(c);
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn namespace_is_exact_and_new_pool_rebuilds_proof_without_changing_dataset() {
    harness::with_temp_database(
        &harness::admin_config("artifact41scope"),
        "artifact41scope",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let cases = [
                ("Dep", "租户"),
                ("dep", "租户"),
                ("Dep", "租户 "),
                ("Dep ", "租户"),
            ];
            let mut ids = BTreeSet::new();
            for (deployment, tenant) in cases {
                let registry = register(&p, deployment, tenant).await;
                assert_eq!(registry.binding().deployment_id(), deployment);
                assert_eq!(registry.binding().tenant_id(), tenant);
                ids.insert(registry.binding().dataset_id().to_owned());
            }
            assert_eq!(ids.len(), cases.len());
            let first = register(&p, "Dep", "租户").await;
            let deployment = DeploymentId::new("Dep");
            let tenant = TenantId::new("租户");
            assert!(first.matches_pool_scope(&p.clone(), &deployment, &tenant));
            assert!(!first.matches_pool_scope(&p, &DeploymentId::new("dep"), &tenant));
            assert!(!first.matches_pool_scope(&p, &deployment, &TenantId::new("租户 ")));
            let reopened = pool::connect(&config).await.map_err(|e| e.to_string())?;
            assert!(!first.matches_pool_scope(&reopened, &deployment, &tenant));
            let rebuilt = register(&reopened, "Dep", "租户").await;
            assert_eq!(rebuilt.binding().dataset_id(), first.binding().dataset_id());
            assert!(rebuilt.matches_pool_scope(&reopened, &deployment, &tenant));
            rebuilt.validate_current().await.unwrap();
            assert_eq!(registry_count(&p).await, cases.len() as i64);
            reopened.close();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn bounded_restored_dataset_is_preserved_without_imposing_new_hex_format() {
    harness::with_temp_database(
        &harness::admin_config("artifact41restore"),
        "artifact41restore",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let dataset = "历史 Dataset:é/保留 ";
            let c = p.get().await.map_err(|e| e.to_string())?;
            c.execute(&format!("INSERT INTO {REGISTRY}(deployment_id,tenant_id,dataset_id,binding_schema,initial_origin) VALUES($1,$2,$3,1,'server_first_adoption')"), &[&"restored-deployment", &"restored-tenant", &dataset])
                .await.map_err(|e| e.to_string())?;
            drop(c);
            let first = register(&p, "restored-deployment", "restored-tenant").await;
            assert_eq!(first.binding().dataset_id(), dataset);
            let reopened = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let rebuilt = register(&reopened, "restored-deployment", "restored-tenant").await;
            assert_eq!(rebuilt.binding().dataset_id(), dataset);
            rebuilt.validate_current().await.unwrap();
            assert_eq!(registry_count(&p).await, 1);
            reopened.close();
            p.close();
            Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn invalid_namespace_is_rejected_without_writing_and_512_utf8_bytes_are_accepted() {
    harness::with_temp_database(
        &harness::admin_config("artifact41shape"),
        "artifact41shape",
        |config| async move {
            let p = fresh_pool(&config).await?;
            for invalid in [
                String::new(),
                "a".repeat(513),
                "é".repeat(257),
                "x\ny".to_owned(),
                "x\u{7f}y".to_owned(),
                "x\u{85}y".to_owned(),
            ] {
                assert!(
                    ArtifactDatasetRegistry::from_server(
                        p.clone(),
                        &DeploymentId::new(&invalid),
                        &TenantId::new("valid")
                    )
                    .await
                    .is_err()
                );
                assert!(
                    ArtifactDatasetRegistry::from_server(
                        p.clone(),
                        &DeploymentId::new("valid"),
                        &TenantId::new(&invalid)
                    )
                    .await
                    .is_err()
                );
                assert_eq!(registry_count(&p).await, 0);
            }
            let boundary = "é".repeat(256);
            let registry = register(&p, &boundary, &"t".repeat(512)).await;
            assert_eq!(registry.binding().deployment_id(), boundary);
            assert_eq!(registry.binding().tenant_id().len(), 512);
            registry.validate_current().await.unwrap();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn registry_refuses_update_delete_and_truncate_without_changing_binding() {
    harness::with_temp_database(
        &harness::admin_config("artifact41immutable"),
        "artifact41immutable",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let registry = register(&p, "immutable-deployment", "immutable-tenant").await;
            let c = p.get().await.map_err(|e| e.to_string())?;
            for sql in [
                format!("UPDATE {REGISTRY} SET dataset_id='replacement'"),
                format!("UPDATE {REGISTRY} SET initial_origin='desktop_canary'"),
                format!("DELETE FROM {REGISTRY}"),
                format!("TRUNCATE {REGISTRY}"),
            ] {
                let error = c
                    .batch_execute(&sql)
                    .await
                    .expect_err("append-only mutation must fail");
                assert_eq!(error.code(), Some(&SqlState::RAISE_EXCEPTION));
            }
            drop(c);
            registry.validate_current().await.unwrap();
            assert_eq!(registry_count(&p).await, 1);
            let observed = register(&p, "immutable-deployment", "immutable-tenant").await;
            assert_eq!(
                observed.binding().dataset_id(),
                registry.binding().dataset_id()
            );
            assert_eq!(observed.binding().initial_origin(), "server_first_adoption");
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn actual_registry_constraints_reject_unknown_shapes_and_keep_full_512_byte_ids() {
    harness::with_temp_database(
        &harness::admin_config("artifact41sqlshape"),
        "artifact41sqlshape",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let c = p.get().await.map_err(|e| e.to_string())?;
            let insert = format!("INSERT INTO {REGISTRY}(deployment_id,tenant_id,dataset_id,binding_schema,initial_origin) VALUES($1,$2,$3,$4,$5)");
            for invalid in [String::new(), "a".repeat(513), "é".repeat(257), "control\n".to_owned(), "control\u{7f}".to_owned(), "control\u{85}".to_owned()] {
                for field in 0..3 {
                    let mut values = ["valid-deployment".to_owned(), "valid-tenant".to_owned(), "historical-valid-dataset".to_owned()];
                    values[field] = invalid.clone();
                    let error = c.execute(&insert, &[&values[0], &values[1], &values[2], &1_i16, &"server_first_adoption"])
                        .await.expect_err("实际 SQL CHECK 必须拒绝无效 identity");
                    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
                }
            }
            for (schema, origin) in [(0_i16,"server_first_adoption"), (2_i16,"server_first_adoption"), (1_i16,"unknown_origin")] {
                let error = c.execute(&insert, &[&"valid-deployment", &"valid-tenant", &"valid-dataset", &schema, &origin])
                    .await.expect_err("SQL 只能保存已知 schema 与 origin");
                assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
            }
            let deployment = "é".repeat(256);
            let tenant = "t".repeat(512);
            let dataset = "界".repeat(170) + "é";
            assert_eq!(dataset.len(), 512);
            c.execute(&insert, &[&deployment, &tenant, &dataset, &1_i16, &"server_first_adoption"])
                .await.map_err(|e| e.to_string())?;
            drop(c);
            let registry = register(&p, &deployment, &tenant).await;
            assert_eq!(registry.binding().dataset_id(), dataset);
            assert_eq!(registry_count(&p).await, 1);
            p.close();
            Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn existing_proof_rereads_tuple_and_fails_after_privileged_row_replacement() {
    harness::with_temp_database(
        &harness::admin_config("artifact41tuple"),
        "artifact41tuple",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let registry = register(&p, "tuple-deployment", "tuple-tenant").await;
            let c = p.get().await.map_err(|e| e.to_string())?;
            // 只在测试自建库模拟恢复/受损状态；重新启用后 schema 必须仍与 oracle 相同。
            c.batch_execute(&format!("ALTER TABLE {REGISTRY} DISABLE TRIGGER artifact_dataset_bindings_append_only; UPDATE {REGISTRY} SET dataset_id='restored-replacement'; ALTER TABLE {REGISTRY} ENABLE TRIGGER artifact_dataset_bindings_append_only;"))
                .await.map_err(|e| e.to_string())?;
            drop(c);
            verify_artifact_registry_schema(&p).await.unwrap();
            assert!(registry.validate_current().await.is_err());
            assert!(registry.validate_current().await.is_err(), "旧 proof 不得在失败后自行重新认领");
            assert_eq!(registry_count(&p).await, 1);
            p.close();
            Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn internal_schema_drift_refuses_both_existing_proof_and_new_adoption() {
    for (tag, drift) in [
        ("artifact41trig", format!("ALTER TABLE {REGISTRY} DISABLE TRIGGER artifact_dataset_bindings_append_only")),
        ("artifact41trunc", format!("DROP TRIGGER artifact_dataset_bindings_no_truncate ON {REGISTRY}")),
        ("artifact41column", format!("ALTER TABLE {REGISTRY} ADD COLUMN unexpected_column text")),
        ("artifact41coll", format!("ALTER TABLE {REGISTRY} ALTER COLUMN deployment_id TYPE text COLLATE \"default\"")),
        ("artifact41pk", format!("ALTER TABLE {REGISTRY} DROP CONSTRAINT artifact_dataset_bindings_pkey")),
        ("artifact41guard", "CREATE OR REPLACE FUNCTION openbot_internal.prevent_append_only_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$".to_owned()),
    ] {
        harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
            let p = fresh_pool(&config).await?;
            let registry = register(&p, "schema-deployment", "schema-tenant").await;
            let c = p.get().await.map_err(|e| e.to_string())?;
            c.batch_execute(&drift).await.map_err(|e| e.to_string())?;
            drop(c);
            assert!(verify_artifact_registry_schema(&p).await.is_err());
            assert!(registry.validate_current().await.is_err());
            assert!(ArtifactDatasetRegistry::from_server(p.clone(), &DeploymentId::new("new-deployment"), &TenantId::new("new-tenant")).await.is_err());
            assert_eq!(registry_count(&p).await, 1, "schema 异常时不得预先写新 namespace");
            p.close();
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn unverified_desktop_canary_cannot_be_adopted_or_replaced_by_server_minting() {
    harness::with_temp_database(
        &harness::admin_config("artifact41fakecanary"),
        "artifact41fakecanary",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let c = p.get().await.map_err(|e| e.to_string())?;
            c.execute("INSERT INTO openbot_internal.desktop_vault_canaries(dataset_id,deployment_id,tenant_id,key_id,key_version,canary_schema,encrypted_canary) VALUES($1,$2,$3,$4,1,1,'not-a-verified-envelope')", &[&"d".repeat(32), &"canary-deployment", &"canary-tenant", &"e".repeat(32)])
                .await.map_err(|e| e.to_string())?;
            drop(c);
            for _ in 0..2 {
                assert!(ArtifactDatasetRegistry::from_server(p.clone(), &DeploymentId::new("canary-deployment"), &TenantId::new("canary-tenant")).await.is_err());
                assert_eq!(registry_count(&p).await, 0);
            }
            p.close();
            Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and frozen artifact dataset oracle"]
async fn registry_adoption_does_not_run_missing_migration() {
    harness::with_temp_database(
        &harness::admin_config("artifact41nomigrate"),
        "artifact41nomigrate",
        |config| async move {
            let p = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply_through(&mut c, 40).await.map_err(|e| e.to_string())?;
            drop(c);
            assert!(ArtifactDatasetRegistry::from_server(p.clone(), &DeploymentId::new("missing-deployment"), &TenantId::new("missing-tenant")).await.is_err());
            let c = p.get().await.map_err(|e| e.to_string())?;
            let row = c.query_one("SELECT max(version),to_regclass('openbot_internal.artifact_dataset_bindings')::text FROM openbot_internal.schema_migrations", &[]).await.map_err(|e| e.to_string())?;
            assert_eq!(row.get::<_,i32>(0), 40);
            assert!(row.get::<_,Option<String>>(1).is_none());
            drop(c);
            p.close();
            Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL with test-only role creation"]
async fn ordinary_server_role_without_pg_control_system_permission_can_adopt_registry() {
    harness::with_temp_database(
        &harness::admin_config("artifact41ordinary"), "artifact41ordinary", |config| async move {
            let p = fresh_pool(&config).await?;
            let role = format!("artifact_it_{}", uuid::Uuid::now_v7().simple());
            let password = format!("{}{}", uuid::Uuid::now_v7().simple(), uuid::Uuid::now_v7().simple());
            let c = p.get().await.map_err(|e| e.to_string())?;
            // 显式控制本测试临时库 ACL，不声称这是部署默认。pg_catalog function ACL 是
            // database-local；不修改生产权限，也不把普通 Server 路径扩成管理员路径。
            c.batch_execute("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC")
                .await.map_err(|_| "设置 owned test-only pg_control_system ACL 失败".to_owned())?;
            // 仅授予本测试临时库的业务表权限；口令不进入日志或断言输出。
            c.batch_execute(&format!(
                "CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '{password}'; \
                 GRANT USAGE ON SCHEMA public,openbot_internal TO {role}; \
                 GRANT SELECT ON ALL TABLES IN SCHEMA public,openbot_internal TO {role}; \
                 GRANT INSERT ON openbot_internal.artifact_dataset_bindings TO {role}; \
                 GRANT UPDATE ON openbot_internal.desktop_vault_canaries TO {role};"
            )).await.map_err(|_| "创建 owned test-only Server 角色失败".to_owned())?;
            drop(c);
            let mut ordinary_config = config.clone().with_password(&password);
            ordinary_config.user = role.clone();
            let ordinary = pool::connect(&ordinary_config).await.map_err(|_| "连接 owned 普通角色失败".to_owned())?;
            let result = async {
                let c = ordinary.get().await.map_err(|_| "获取普通角色连接失败".to_owned())?;
                let row = c.query_one(
                    "SELECT r.rolsuper,has_function_privilege(current_user,'pg_catalog.pg_control_system()','EXECUTE') FROM pg_catalog.pg_roles r WHERE r.rolname=current_user", &[],
                ).await.map_err(|_| "普通角色事实取证失败".to_owned())?;
                if row.get::<_,bool>(0) || row.get::<_,bool>(1) {
                    return Err("普通角色须非超级用户且无 pg_control_system EXECUTE".to_owned());
                }
                let denied = c.query_one("SELECT system_identifier FROM pg_catalog.pg_control_system()", &[])
                    .await.err().ok_or_else(|| "普通角色不应能读取 pg_control_system".to_owned())?;
                if denied.code() != Some(&SqlState::INSUFFICIENT_PRIVILEGE) {
                    return Err("pg_control_system 应由真实权限检查拒绝".to_owned());
                }
                drop(c);
                let registry = ArtifactDatasetRegistry::from_server(
                    ordinary.clone(), &DeploymentId::new("ordinary-server"), &TenantId::new("ordinary-tenant"),
                ).await.map_err(|e| format!("普通角色 registry 初始化失败：{e}"))?;
                registry.validate_current().await.map_err(|e| e.to_string())?;
                if registry.binding().initial_origin() != "server_first_adoption" || registry_count(&ordinary).await != 1 {
                    return Err("普通角色应持有真实唯一 Server 注册事实".to_owned());
                }
                Ok(())
            }.await;
            ordinary.close();
            let c = p.get().await.map_err(|e| e.to_string())?;
            c.batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role};"))
                .await.map_err(|_| "清理 owned test-only 角色失败".to_owned())?;
            drop(c);
            p.close();
            if result.is_ok() {
                println!("artifact_server_role_receipt test=ordinary_server_role_without_pg_control_system_permission_can_adopt_registry acl_source=test_controlled_owned_database rolsuper=false pg_control_system_execute=false pg_control_system_select_sqlstate=42501 registry_valid=true role_cleanup=true");
            }
            result
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; verifies real bounded lock wait"]
async fn server_adoption_times_out_at_five_seconds_without_minting_or_retrying() {
    harness::with_temp_database(
        &harness::admin_config("artifact41locktimeout"),
        "artifact41locktimeout",
        |config| async move {
            let p = fresh_pool(&config).await?;
            let blocker = p.get().await.map_err(|e| e.to_string())?;
            blocker.batch_execute("BEGIN; LOCK TABLE openbot_internal.desktop_vault_canaries IN ACCESS EXCLUSIVE MODE")
                .await.map_err(|e| e.to_string())?;
            let start = std::time::Instant::now();
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(12),
                ArtifactDatasetRegistry::from_server(
                    p.clone(), &DeploymentId::new("blocked-deployment"), &TenantId::new("blocked-tenant"),
                ),
            ).await;
            let elapsed = start.elapsed();
            blocker.batch_execute("ROLLBACK").await.map_err(|e| e.to_string())?;
            drop(blocker);
            assert!(matches!(outcome, Ok(Err(ArtifactRegistryError::Unavailable))), "真实锁等待必须受 5s local timeout 限制");
            assert!(elapsed >= std::time::Duration::from_secs(4));
            assert!(elapsed < std::time::Duration::from_secs(12));
            assert_eq!(registry_count(&p).await, 0, "timeout 不能写入或暗中重试初始化");
            p.close();
            Ok(())
        },
    ).await;
}

#[cfg(unix)]
mod desktop {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::*;
    use openbot_domain::vault::{
        DesktopVaultCanaryBinding, KeyVersion, NONCE_BYTES, Nonce, SecretBytes,
        seal_desktop_vault_canary,
    };
    use openbot_infra::auth::single_user::desktop_local::{
        CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore, DesktopLocalInstallation,
    };
    use openbot_infra::db::desktop_local::{DesktopLocalDatabase, connect_for_attestation};
    use openbot_infra::db::desktop_vault_canary::{self, VerifiedDesktopVaultCanary};

    const TEST_USER: &str = "desktop_admin";
    const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn postgres_binary(name: &str) -> Result<PathBuf, String> {
        let directory = std::env::var_os("OPENBOT_TEST_PG_BIN")
            .map(PathBuf::from)
            .ok_or_else(|| "owned runner must set OPENBOT_TEST_PG_BIN".to_owned())?;
        if !directory.is_absolute() {
            return Err(
                "OPENBOT_TEST_PG_BIN must be an absolute owned test binary directory".to_owned(),
            );
        }
        let binary = directory.join(name);
        if !binary.is_file() {
            return Err(format!("owned PostgreSQL binary missing: {name}"));
        }
        Ok(binary)
    }

    fn run(command: &mut Command, phase: &'static str) -> Result<(), String> {
        let output = command
            .output()
            .map_err(|_| format!("{phase}: process unavailable"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("{phase}: exit={:?}", output.status.code()))
        }
    }

    /// 只清理本测试 create_new 的路径，先停自己的 PG；不接触用户目录。
    struct OwnedSidecar {
        pg_ctl: PathBuf,
        app_root: PathBuf,
        data_dir: PathBuf,
        socket_dir: PathBuf,
        socket_created: bool,
        started: bool,
        postmaster_pid: Option<u32>,
    }

    impl OwnedSidecar {
        fn read_owned_postmaster_pid(&self) -> Result<u32, String> {
            let content = fs::read_to_string(self.data_dir.join("postmaster.pid"))
                .map_err(|_| "read owned postmaster.pid failed".to_owned())?;
            content
                .lines()
                .next()
                .and_then(|line| line.parse::<u32>().ok())
                .filter(|pid| *pid > 1 && *pid <= i32::MAX as u32)
                .ok_or_else(|| "owned postmaster PID is not a positive process identity".to_owned())
        }

        fn stop_verified(&mut self) -> Result<u32, String> {
            let pid = self
                .postmaster_pid
                .map_or_else(|| self.read_owned_postmaster_pid(), Ok)?;
            if self.read_owned_postmaster_pid()? != pid {
                return Err("owned postmaster.pid changed before stop".to_owned());
            }
            // success() means actual exit 0; no Drop result stands in for this acceptance.
            run(
                Command::new(&self.pg_ctl)
                    .arg("-D")
                    .arg(&self.data_dir)
                    .args(["-t", "15", "-m", "fast", "-w", "stop"]),
                "owned pg_ctl stop",
            )?;
            match fs::symlink_metadata(self.data_dir.join("postmaster.pid")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(
                        "owned postmaster.pid remains or cannot be observed after stop".to_owned(),
                    );
                }
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                // Signal 0 only queries the PID captured from this test's own PG data directory.
                // Require ESRCH text in a fixed locale; EPERM or a missing tool proves nothing.
                let probe = Command::new("/bin/kill")
                    .env("LC_ALL", "C")
                    .args(["-0", &pid.to_string()])
                    .output()
                    .map_err(|_| "query owned stopped PID failed".to_owned())?;
                if probe.status.code() == Some(1)
                    && String::from_utf8_lossy(&probe.stderr).contains("No such process")
                {
                    break;
                }
                if !probe.status.success() || std::time::Instant::now() >= deadline {
                    return Err(
                        "owned old postmaster PID is still present or absence was not proved"
                            .to_owned(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            self.started = false;
            Ok(pid)
        }

        fn cleanup_owned_paths(&mut self) -> Result<(), String> {
            match fs::remove_dir_all(&self.app_root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("remove owned stopped app root failed".to_owned()),
            }
            if self.socket_created {
                match fs::remove_dir_all(&self.socket_dir) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err("remove owned stopped socket root failed".to_owned()),
                }
                self.socket_created = false;
            }
            Ok(())
        }

        fn finish(&mut self, test: &'static str) -> Result<(), String> {
            if !self.started {
                return Err(
                    "owned successful fixture must explicitly stop its started PG".to_owned(),
                );
            }
            let pid = self.stop_verified()?;
            self.cleanup_owned_paths()?;
            println!(
                "artifact_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
            );
            Ok(())
        }
    }

    impl Drop for OwnedSidecar {
        fn drop(&mut self) {
            // Failed tests/startups retain this best-effort fallback. A successful test must use
            // explicit finish, and only that path emits its acceptance receipt.
            let stopped = !self.started || self.stop_verified().is_ok();
            if stopped {
                let _ = self.cleanup_owned_paths();
            }
        }
    }

    struct OwnedDesktop {
        database: DesktopLocalDatabase,
        installation: DesktopLocalInstallation,
        port: u16,
        _sidecar: OwnedSidecar,
    }

    impl OwnedDesktop {
        fn finish(mut self, test: &'static str) -> Result<(), String> {
            self.database.close();
            self._sidecar.finish(test)
        }
    }

    fn append_postgres_config(data_dir: &Path, socket_dir: &Path, port: u16) -> Result<(), String> {
        let socket = socket_dir
            .to_str()
            .filter(|s| !s.contains('\''))
            .ok_or_else(|| "owned socket path is not a safe setting".to_owned())?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(data_dir.join("postgresql.conf"))
            .map_err(|_| "open owned postgresql.conf failed".to_owned())?;
        writeln!(file, "\nlisten_addresses = '127.0.0.1'\nport = {port}\npassword_encryption = 'scram-sha-256'\ndynamic_shared_memory_type = 'posix'\nunix_socket_directories = '{socket}'\nunix_socket_permissions = 0700")
            .map_err(|_| "write owned postgresql.conf failed".to_owned())?;
        file.sync_all()
            .map_err(|_| "sync owned postgresql.conf failed".to_owned())
    }

    async fn start_owned_desktop() -> Result<OwnedDesktop, String> {
        let pg_ctl = postgres_binary("pg_ctl")?;
        let initdb = postgres_binary("initdb")?;
        let id = uuid::Uuid::now_v7().simple().to_string();
        let app_root = std::env::temp_dir().join(format!("openbot-artifact-desktop-{id}"));
        // PG Unix socket 路径长度有限，仍只使用 create_new 的测试自有路径。
        let socket_dir = PathBuf::from("/tmp").join(format!("obart-{id}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&app_root)
            .map_err(|_| "create owned app root failed".to_owned())?;
        let mut sidecar = OwnedSidecar {
            pg_ctl,
            data_dir: app_root.join("not-started"),
            app_root,
            socket_dir,
            socket_created: false,
            started: false,
            postmaster_pid: None,
        };
        let store = DesktopLocalAuthorityStore::new(
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(&sidecar.app_root)
                .map_err(|e| e.to_string())?,
        );
        let installation = store
            .load_or_create_installation()
            .map_err(|e| e.to_string())?;
        sidecar.data_dir = installation.sidecar_data_dir().to_owned();
        let password_file = sidecar.app_root.join(".test-postgres-password");
        let mut password = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&password_file)
            .map_err(|_| "create owned initdb credential failed".to_owned())?;
        writeln!(password, "{TEST_PASSWORD}")
            .map_err(|_| "write owned initdb credential failed".to_owned())?;
        password
            .sync_all()
            .map_err(|_| "sync owned initdb credential failed".to_owned())?;
        drop(password);
        run(
            Command::new(initdb)
                .arg("--pgdata")
                .arg(&sidecar.data_dir)
                .arg(format!("--username={TEST_USER}"))
                .arg("--pwfile")
                .arg(&password_file)
                .args([
                    "--auth-host=scram-sha-256",
                    "--auth-local=trust",
                    "--encoding=UTF8",
                    "--no-locale",
                ]),
            "initdb",
        )?;
        fs::remove_file(password_file)
            .map_err(|_| "remove owned initdb credential failed".to_owned())?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&sidecar.socket_dir)
            .map_err(|_| "create owned socket root failed".to_owned())?;
        sidecar.socket_created = true;
        let probe = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|_| "allocate owned loopback port failed".to_owned())?;
        let port = probe
            .local_addr()
            .map_err(|_| "read owned loopback port failed".to_owned())?
            .port();
        drop(probe);
        append_postgres_config(&sidecar.data_dir, &sidecar.socket_dir, port)?;
        sidecar.started = true;
        run(
            Command::new(&sidecar.pg_ctl)
                .arg("-D")
                .arg(&sidecar.data_dir)
                .arg("-l")
                .arg(sidecar.app_root.join("postgres.log"))
                .args(["-w", "start"]),
            "pg_ctl start",
        )?;
        sidecar.postmaster_pid = Some(sidecar.read_owned_postmaster_pid()?);
        let admin =
            connect_for_attestation(port, SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()))
                .await
                .map_err(|e| e.to_string())?;
        let admin = installation
            .attest_postgres_admin(admin)
            .await
            .map_err(|e| e.to_string())?;
        let database = admin
            .connect_application(true)
            .await
            .map_err(|e| e.to_string())?;
        let mut c = database.pool().get().await.map_err(|e| e.to_string())?;
        fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
        drop(c);
        Ok(OwnedDesktop {
            database,
            installation,
            port,
            _sidecar: sidecar,
        })
    }

    async fn reopen(fixture: &OwnedDesktop) -> Result<DesktopLocalDatabase, String> {
        let admin = connect_for_attestation(
            fixture.port,
            SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()),
        )
        .await
        .map_err(|e| e.to_string())?;
        let admin = fixture
            .installation
            .attest_postgres_admin(admin)
            .await
            .map_err(|e| e.to_string())?;
        admin
            .connect_application(false)
            .await
            .map_err(|e| e.to_string())
    }

    async fn verified_canary(fixture: &OwnedDesktop, dataset: &str) -> VerifiedDesktopVaultCanary {
        let auth = fixture.installation.authority().auth_context();
        let key_id = "b".repeat(32);
        let master = SecretBytes::new(vec![0x5a; 32]);
        let binding = DesktopVaultCanaryBinding::new(
            dataset,
            auth.deployment().as_str(),
            auth.tenant().as_str(),
            &key_id,
            KeyVersion::new(1),
        )
        .unwrap();
        let envelope =
            seal_desktop_vault_canary(&master, &binding, Nonce::from_array([0x33; NONCE_BYTES]))
                .unwrap();
        let row = desktop_vault_canary::DesktopVaultCanaryRow::new(
            dataset,
            auth.deployment().as_str(),
            auth.tenant().as_str(),
            &key_id,
            envelope.to_column_value(),
        )
        .unwrap();
        desktop_vault_canary::insert_once(fixture.database.pool(), &row)
            .await
            .unwrap();
        desktop_vault_canary::verify_persisted(
            &fixture.database,
            &master,
            dataset,
            auth.deployment().as_str(),
            auth.tenant().as_str(),
            &key_id,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL binaries and frozen artifact dataset oracle"]
    async fn current_desktop_crypto_proof_adopts_original_dataset_and_preserves_origin() {
        let fixture = start_owned_desktop().await.unwrap();
        let dataset = "a".repeat(32);
        let proof = verified_canary(&fixture, &dataset).await;
        let registry = ArtifactDatasetRegistry::from_desktop(&fixture.database, &proof)
            .await
            .unwrap();
        assert_eq!(registry.binding().dataset_id(), dataset);
        assert_eq!(registry.binding().initial_origin(), "desktop_canary");
        assert_eq!(registry.binding().deployment_id(), proof.deployment_id());
        assert_eq!(registry.binding().tenant_id(), proof.tenant_id());
        registry.validate_current().await.unwrap();
        let auth = fixture.installation.authority().auth_context();
        assert!(
            ArtifactDatasetRegistry::from_server(
                fixture.database.clone_pool(),
                auth.deployment(),
                auth.tenant()
            )
            .await
            .is_err()
        );
        let reobserved = ArtifactDatasetRegistry::from_desktop(&fixture.database, &proof)
            .await
            .unwrap();
        assert_eq!(reobserved.binding().dataset_id(), dataset);
        assert_eq!(reobserved.binding().initial_origin(), "desktop_canary");
        assert_eq!(registry_count(fixture.database.pool()).await, 1);
        fixture
            .finish("current_desktop_crypto_proof_adopts_original_dataset_and_preserves_origin")
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL binaries and frozen artifact dataset oracle"]
    async fn reopened_same_physical_desktop_database_requires_new_current_owner_proof() {
        let fixture = start_owned_desktop().await.unwrap();
        let dataset = "c".repeat(32);
        let proof = verified_canary(&fixture, &dataset).await;
        let reopened = reopen(&fixture).await.unwrap();
        assert!(
            ArtifactDatasetRegistry::from_desktop(&reopened, &proof)
                .await
                .is_err()
        );
        assert_eq!(registry_count(fixture.database.pool()).await, 0);
        let master = SecretBytes::new(vec![0x5a; 32]);
        let current = desktop_vault_canary::verify_persisted(
            &reopened,
            &master,
            &dataset,
            proof.deployment_id(),
            proof.tenant_id(),
            proof.key_id(),
        )
        .await
        .unwrap();
        let registry = ArtifactDatasetRegistry::from_desktop(&reopened, &current)
            .await
            .unwrap();
        assert_eq!(registry.binding().dataset_id(), dataset);
        registry.validate_current().await.unwrap();
        reopened.close();
        fixture
            .finish("reopened_same_physical_desktop_database_requires_new_current_owner_proof")
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL binaries and frozen artifact dataset oracle"]
    async fn stale_desktop_canary_crypto_observation_cannot_initialize_registry() {
        let fixture = start_owned_desktop().await.unwrap();
        let proof = verified_canary(&fixture, &"d".repeat(32)).await;
        let c = fixture.database.pool().get().await.unwrap();
        c.execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary='changed-after-verification'", &[]).await.unwrap();
        drop(c);
        assert!(
            ArtifactDatasetRegistry::from_desktop(&fixture.database, &proof)
                .await
                .is_err()
        );
        assert_eq!(registry_count(fixture.database.pool()).await, 0);
        fixture
            .finish("stale_desktop_canary_crypto_observation_cannot_initialize_registry")
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL binaries and frozen artifact dataset oracle"]
    async fn desktop_canary_cannot_replace_existing_different_server_dataset() {
        let fixture = start_owned_desktop().await.unwrap();
        let auth = fixture.installation.authority().auth_context();
        let initial = ArtifactDatasetRegistry::from_server(
            fixture.database.clone_pool(),
            auth.deployment(),
            auth.tenant(),
        )
        .await
        .unwrap();
        let before = initial.binding().dataset_id().to_owned();
        let distinct = if before == "e".repeat(32) {
            "f".repeat(32)
        } else {
            "e".repeat(32)
        };
        let proof = verified_canary(&fixture, &distinct).await;
        assert!(
            ArtifactDatasetRegistry::from_desktop(&fixture.database, &proof)
                .await
                .is_err()
        );
        initial.validate_current().await.unwrap();
        assert_eq!(registry_count(fixture.database.pool()).await, 1);
        let c = fixture.database.pool().get().await.unwrap();
        let persisted: String = c
            .query_one(&format!("SELECT dataset_id FROM {REGISTRY}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(persisted, before);
        drop(c);
        fixture
            .finish("desktop_canary_cannot_replace_existing_different_server_dataset")
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL binaries and frozen artifact dataset oracle"]
    async fn current_desktop_proof_for_existing_server_tuple_keeps_initial_server_origin() {
        let fixture = start_owned_desktop().await.unwrap();
        let auth = fixture.installation.authority().auth_context();
        let initial = ArtifactDatasetRegistry::from_server(
            fixture.database.clone_pool(),
            auth.deployment(),
            auth.tenant(),
        )
        .await
        .unwrap();
        let proof = verified_canary(&fixture, initial.binding().dataset_id()).await;
        let registry = ArtifactDatasetRegistry::from_desktop(&fixture.database, &proof)
            .await
            .unwrap();
        assert_eq!(
            registry.binding().dataset_id(),
            initial.binding().dataset_id()
        );
        assert_eq!(registry.binding().initial_origin(), "server_first_adoption");
        registry.validate_current().await.unwrap();
        assert_eq!(registry_count(fixture.database.pool()).await, 1);
        fixture
            .finish("current_desktop_proof_for_existing_server_tuple_keeps_initial_server_origin")
            .unwrap();
    }
}
