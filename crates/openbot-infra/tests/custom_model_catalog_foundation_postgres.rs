//! Owned PostgreSQL/Vault regressions for the persistent custom-model catalogue.
//!
//! The two new registered oracles are independently captured fixtures. These tests do not
//! generate, repair, or normalize an expected schema. The wire relay and event trigger are
//! private controls in a newly created test database, never application extension points.

mod harness;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use openbot_application::model_connections::{
    ModelConnectionAdministration, ModelConnectionError as ModelError,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    ids::{ActorId, DeploymentId, TenantId},
    model_connections::{
        CreateModelConnection, CustomModelProtocol, DeleteModelConnection, ModelApiKey,
        ModelConnection, ModelConnectionPageRequest, UpdateModelConnection,
    },
};
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::{
    artifact_administration::{
        capture_artifact_registration_schema, verify_artifact_registration_schema,
    },
    artifact_registry::{
        ArtifactDatasetRegistry, ArtifactRegistryError, capture_artifact_registry_schema,
        verify_artifact_registry_schema,
    },
    db::{
        InfraError, baseline, custom_model_catalog_schema, desktop_vault_canary, fresh,
        initialization, native, pool, schema_facts, tables,
    },
    model_connections::PostgresModelConnections,
    vault::CredentialRecordVault,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, String>;

const DEPLOYMENT: &str = "catalog-foundation-deployment";
const TENANT: &str = "catalog-foundation-tenant";
const AUDIT_KEY: &[u8] = b"catalog-foundation-owned-audit-key-32-bytes";
// Fixture observation budgets, not changes to an application/native deadline.
const OBSERVE_BUDGET: Duration = Duration::from_secs(15);
const CLOSE_BUDGET: Duration = Duration::from_secs(10);
const DDL_GATE_KEY: i64 = 0x4341_5441_4c4f_4736;

fn require(condition: bool, message: &'static str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn actor(user: &str) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        ActorId::new(user),
        AuthGeneration::new(7),
        false,
    )
    .with_roles([Role::User])
    .build()
}

fn create_input() -> CreateModelConnection {
    CreateModelConnection {
        name: "Owned catalogue model".to_owned(),
        protocol: CustomModelProtocol::OpenaiChatCompletions,
        endpoint: "https://catalog.example.test/v1".to_owned(),
        model: "catalog-model-one".to_owned(),
        enabled: true,
        api_key: key("OWNED_CATALOGUE_CANARY_ONE"),
    }
}

fn key(value: &str) -> ModelApiKey {
    ModelApiKey::new(Zeroizing::new(value.to_owned())).expect("bounded synthetic key")
}

fn edit(row: &ModelConnection) -> UpdateModelConnection {
    UpdateModelConnection {
        expected_revision: row.revision,
        name: row.name.clone(),
        protocol: row.protocol,
        endpoint: row.endpoint.clone(),
        model: row.model.clone(),
        enabled: row.enabled,
        api_key: None,
    }
}

fn port(p: &pool::DatabasePool) -> TestResult<PostgresModelConnections> {
    PostgresModelConnections::new(
        p.clone(),
        CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x36; 32]).map_err(|e| e.to_string())?,
        ),
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        SecretBytes::new(AUDIT_KEY.to_vec()),
    )
    .map_err(|e| e.to_string())
}

async fn close_pool(p: pool::DatabasePool) -> TestResult {
    let observations = p.connection_observations();
    p.close();
    let deadline = Instant::now() + CLOSE_BUDGET;
    for observation in observations {
        require(
            observation
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|e| e.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "original pool connection was not actually destroyed",
        )?;
    }
    Ok(())
}

async fn owned_fixture<F, Fut>(name: &str, body: F)
where
    F: FnOnce(pool::DatabaseConfig, pool::DatabasePool) -> Fut,
    Fut: Future<Output = TestResult>,
{
    let admin = harness::admin_config(name);
    require(
        matches!(admin.host.as_str(), "127.0.0.1" | "::1"),
        "catalogue tests require an explicitly owned literal loopback PostgreSQL",
    )
    .expect("owned PostgreSQL invocation prerequisite");
    harness::with_temp_database(&admin, name, |config| async move {
        require(
            config.dbname.starts_with("openbot_it_"),
            "test database ownership missing",
        )?;
        let p = pool::connect(&config.clone().with_max_pool_size(4))
            .await
            .map_err(|e| e.to_string())?;
        let result = body(config, p.clone()).await;
        let closed = close_pool(p).await;
        result.and(closed)
    })
    .await;
}

async fn initialize(p: &pool::DatabasePool, version: i32) -> TestResult {
    let mut c = p.get().await.map_err(|e| e.to_string())?;
    if version == 46 {
        require(
            matches!(
                fresh::apply(&mut c).await.map_err(|e| e.to_string())?,
                fresh::FreshApplyOutcome::Applied(native::ApplyOutcome::Applied)
            ),
            "genuine fresh bootstrap did not apply",
        )?;
    } else {
        require(version == 45, "only genuine45 or fresh46 is registered")?;
        baseline::apply(&c).await.map_err(|e| e.to_string())?;
        require(
            native::apply_through(&mut c, 45)
                .await
                .map_err(|e| e.to_string())?
                == native::ApplyOutcome::Applied,
            "genuine45 native path did not apply",
        )?;
    }
    c.batch_execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES
        ('alice','catalog-alice@example.test',7),('bob','catalog-bob@example.test',7);
        INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','user')",
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

async fn state(c: &Client) -> TestResult<Value> {
    // All rows were generated by this fixture. Ciphertext stays in memory and is never printed.
    let text: String = c.query_one("SELECT jsonb_build_object(
        'connections',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM public.model_connections c),
        'secrets',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.model_connection_secrets s),
        'catalogues',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY connection_id),'[]') FROM public.custom_model_catalogs m),
        'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a),
        'checkpoints',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY sequence),'[]') FROM public.audit_checkpoints a),
        'ledger',(SELECT jsonb_agg(to_jsonb(l) ORDER BY version) FROM openbot_internal.schema_migrations l)
        )::text", &[]).await.map_err(|e| e.to_string())?.get(0);
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

async fn legacy_state(c: &Client) -> TestResult<Value> {
    let text: String = c.query_one("SELECT jsonb_build_object(
        'connections',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM public.model_connections c),
        'secrets',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.model_connection_secrets s),
        'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a),
        'checkpoints',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY sequence),'[]') FROM public.audit_checkpoints a),
        'ledger',(SELECT jsonb_agg(to_jsonb(l) ORDER BY version) FROM openbot_internal.schema_migrations l WHERE version<=45)
        )::text", &[]).await.map_err(|e| e.to_string())?.get(0);
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

async fn namespace_rows(c: &Client) -> TestResult<Value> {
    let text: String = c
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY deployment_id,tenant_id),'[]')::text
        FROM openbot_internal.artifact_dataset_bindings b",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

async fn registered_legacy_identity(p: &pool::DatabasePool) -> TestResult {
    let registry: Value = serde_json::from_str(include_str!(
        "../../../fixtures/db/artifact-dataset-bindings-0041.json"
    ))
    .map_err(|e| e.to_string())?;
    let registration: Value = serde_json::from_str(include_str!(
        "../../../fixtures/db/artifact-registration-0042.json"
    ))
    .map_err(|e| e.to_string())?;
    require(
        capture_artifact_registry_schema(p)
            .await
            .map_err(|e| e.to_string())?
            == registry,
        "0041 original internal identity changed",
    )?;
    require(
        capture_artifact_registration_schema(p)
            .await
            .map_err(|e| e.to_string())?
            == registration,
        "0042 original internal identity changed",
    )
}

async fn assert_current(p: &pool::DatabasePool) -> TestResult {
    let mut c = p.get().await.map_err(|e| e.to_string())?;
    let expected: schema_facts::SchemaFacts =
        serde_json::from_str(include_str!("../../../fixtures/db/schema-0051.json"))
            .map_err(|e| e.to_string())?;
    let actual_public = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
    require(
        actual_public == expected,
        "actual full public catalogue differs from independent current0051 oracle",
    )?;
    custom_model_catalog_schema::verify(&c)
        .await
        .map_err(|e| e.to_string())?;
    let captured = custom_model_catalog_schema::capture(&c)
        .await
        .map_err(|e| e.to_string())?;
    let registered_specialized: Value = serde_json::from_str(include_str!(
        "../../../fixtures/db/custom-model-catalogs-0046.json"
    ))
    .map_err(|e| e.to_string())?;
    require(
        captured.is_object() && captured == registered_specialized,
        "actual specialized capture differs from independent0046 fixture",
    )?;
    let before = state(&c).await?;
    require(
        native::apply(&mut c).await.map_err(|e| e.to_string())?
            == native::ApplyOutcome::AlreadyApplied,
        "current replay was not AlreadyApplied",
    )?;
    require(
        state(&c).await? == before,
        "AlreadyApplied rewrote business state or ledger",
    )?;
    let table = actual_public
        .table("custom_model_catalogs")
        .ok_or("captured0046 fixture lacks the new table")?;
    let descriptor = tables::current_table_specs()
        .find(|t| t.name == "custom_model_catalogs")
        .ok_or("typed current registry does not include catalogue")?;
    require(
        descriptor.column_specs.len() == 11 && table.columns.len() == 11,
        "typed/captured catalogue is not eleven columns",
    )?;
    for (column, actual) in descriptor.column_specs.iter().zip(&table.columns) {
        require(
            column.name == actual.name
                && column.sql_type == actual.sql_type
                && column.not_null == actual.notnull,
            "typed descriptor differs from real catalogue",
        )?;
    }
    for actual in c
        .query(
            "SELECT connection_id,deployment_id,tenant_id,owner_user_id,model_id,
        catalog_revision,protocol,endpoint,model,enabled,retired
        FROM public.custom_model_catalogs ORDER BY connection_id",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?
    {
        let typed =
            tables::custom_model_catalogs::Row::try_from(&actual).map_err(|e| e.to_string())?;
        require(
            typed.connection_id == actual.get::<_, Uuid>("connection_id")
                && typed.deployment_id == actual.get::<_, String>("deployment_id")
                && typed.tenant_id == actual.get::<_, String>("tenant_id")
                && typed.owner_user_id == actual.get::<_, String>("owner_user_id")
                && typed.model_id == actual.get::<_, String>("model_id")
                && typed.catalog_revision == actual.get::<_, i64>("catalog_revision")
                && typed.protocol == actual.get::<_, String>("protocol")
                && typed.endpoint == actual.get::<_, String>("endpoint")
                && typed.model == actual.get::<_, String>("model")
                && typed.enabled == actual.get::<_, bool>("enabled")
                && typed.retired == actual.get::<_, bool>("retired"),
            "typed eleven-field Row did not decode genuine catalogue data",
        )?;
    }
    drop(c);
    registered_legacy_identity(p).await?;
    verify_artifact_registry_schema(p)
        .await
        .map_err(|e| e.to_string())?;
    verify_artifact_registration_schema(p)
        .await
        .map_err(|e| e.to_string())?;
    let adopted = ArtifactDatasetRegistry::from_server(
        p.clone(),
        &DeploymentId::new(DEPLOYMENT),
        &TenantId::new(TENANT),
    )
    .await
    .map_err(|e| e.to_string())?;
    let dataset = adopted.binding().dataset_id().to_owned();
    require(
        !dataset.is_empty(),
        "original namespace adoption returned no dataset",
    )?;
    require(
        adopted.matches_pool_scope(p, &DeploymentId::new(DEPLOYMENT), &TenantId::new(TENANT)),
        "original registry lost pool/namespace binding",
    )?;
    let again = ArtifactDatasetRegistry::from_server(
        p.clone(),
        &DeploymentId::new(DEPLOYMENT),
        &TenantId::new(TENANT),
    )
    .await
    .map_err(|e| e.to_string())?;
    require(
        again.binding().dataset_id() == dataset,
        "current adoption reminted namespace",
    )?;
    drop(again);
    drop(adopted);
    require(
        initialization::initialize(p)
            .await
            .map_err(|e| e.to_string())?
            == initialization::DatabaseOrigin::RustManaged,
        "startup lost native provenance",
    )?;
    desktop_vault_canary::verify_current_layout(p)
        .await
        .map_err(|e| e.to_string())
}

#[derive(Debug, PartialEq, Eq)]
struct CatalogRow {
    model_id: String,
    revision: i64,
    protocol: String,
    endpoint: String,
    model: String,
    enabled: bool,
    retired: bool,
    xmin: String,
}

async fn catalogue(c: &Client, id: &str) -> TestResult<CatalogRow> {
    let id = Uuid::parse_str(id).map_err(|e| e.to_string())?;
    let r = c
        .query_one(
            "SELECT model_id,catalog_revision,protocol,endpoint,model,enabled,retired,xmin::text
        FROM public.custom_model_catalogs WHERE connection_id=$1",
            &[&id],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(CatalogRow {
        model_id: r.get(0),
        revision: r.get(1),
        protocol: r.get(2),
        endpoint: r.get(3),
        model: r.get(4),
        enabled: r.get(5),
        retired: r.get(6),
        xmin: r.get(7),
    })
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PG17 and independently captured0046 fixtures"]
async fn foundation_fresh_and_original45_upgrade_capture_exact_shape_and_backfill() {
    for version in [46, 45] {
        owned_fixture(if version == 46 { "catalog46fresh" } else { "catalog45upgrade" },
            move |_, p| async move {
                initialize(&p, version).await?;
                if version == 45 {
                    let administration = port(&p)?;
                    let first = administration.create(&actor("alice"), &create_input())
                        .await.map_err(|e| e.to_string())?;
                    let mut disabled = create_input();
                    disabled.enabled = false;
                    disabled.protocol = CustomModelProtocol::OpenaiResponses;
                    let second = administration.create(&actor("alice"), &disabled)
                        .await.map_err(|e| e.to_string())?;
                    let mut retired = create_input();
                    retired.protocol = CustomModelProtocol::AnthropicMessages;
                    let third = administration.create(&actor("alice"), &retired)
                        .await.map_err(|e| e.to_string())?;
                    administration.delete(&actor("alice"), &third.id,
                        &DeleteModelConnection { expected_revision: third.revision })
                        .await.map_err(|e| e.to_string())?;
                    let c = p.get().await.map_err(|e| e.to_string())?;
                    // SQL-legal old definitions which the Rust normalizer would reject remain raw.
                    c.execute("UPDATE public.model_connections SET endpoint=' legacy RAW endpoint ',
                        model=' legacy RAW model ',revision=42 WHERE id=$1",
                        &[&Uuid::parse_str(&second.id).map_err(|e| e.to_string())?])
                        .await.map_err(|e| e.to_string())?;
                    let old = legacy_state(&c).await?;
                    let public45 = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
                    require(public45 == serde_json::from_str(include_str!(
                        "../../../fixtures/db/schema-0040.json")).map_err(|e| e.to_string())?,
                        "genuine45 public shape was not the original0040")?;
                    let namespaces = namespace_rows(&c).await?;
                    require(native::validate_known_prefix(&c, 45).await.map_err(|e| e.to_string())?
                        .latest_version() == 45, "old prefix was not genuinely45")?;
                    drop(c);
                    require(matches!(verify_artifact_registry_schema(&p).await,
                        Err(ArtifactRegistryError::Corrupt { field: "native_schema" })),
                        "current artifact guard accepted old45")?;
                    require(matches!(ArtifactDatasetRegistry::from_server(p.clone(),
                        &DeploymentId::new(DEPLOYMENT), &TenantId::new(TENANT)).await,
                        Err(ArtifactRegistryError::Corrupt { field: "native_schema" })),
                        "old45 namespace adoption accepted")?;
                    let mut c = p.get().await.map_err(|e| e.to_string())?;
                    require(legacy_state(&c).await? == old
                        && namespace_rows(&c).await? == namespaces
                        && schema_facts::fetch(&c).await.map_err(|e| e.to_string())? == public45,
                        "old45 rejection ran DDL, minted namespace, or changed old state")?;
                    require(native::apply(&mut c).await.map_err(|e| e.to_string())?
                        == native::ApplyOutcome::Applied, "original45 native upgrade did not apply")?;
                    require(legacy_state(&c).await? == old, "upgrade rewrote old rows/ledger/Vault/audit")?;
                    let exact: bool = c.query_one("SELECT
                        (SELECT count(*)=3 FROM public.custom_model_catalogs)
                        AND NOT EXISTS(SELECT 1 FROM public.model_connections c FULL OUTER JOIN
                            public.custom_model_catalogs m ON c.id=m.connection_id
                            WHERE c.id IS NULL OR m.connection_id IS NULL
                            OR (m.deployment_id,m.tenant_id,m.owner_user_id,m.protocol,m.endpoint,m.model,m.enabled,m.retired)
                               IS DISTINCT FROM (c.deployment_id,c.tenant_id,c.owner_user_id,c.protocol,c.endpoint,c.model,c.enabled,c.deleted_at IS NOT NULL)
                            OR m.catalog_revision<>1 OR m.model_id<>'custom:'||c.id::text)", &[])
                        .await.map_err(|e| e.to_string())?.get(0);
                    require(exact, "backfill failed complete original-byte mapping")?;
                    require(catalogue(&c, &first.id).await?.revision == 1
                        && catalogue(&c, &second.id).await?.endpoint == " legacy RAW endpoint "
                        && catalogue(&c, &third.id).await?.retired,
                        "backfill normalized or omitted disabled/retired data")?;
                    drop(c);
                    drop(administration);
                }
                assert_current(&p).await
            }).await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PG17 and independently captured0046 fixtures"]
async fn foundation_original_crud_preserves_model_id_and_independent_revisions() {
    owned_fixture("catalog46crud", |_, p| async move {
        initialize(&p, 46).await?;
        let administration = port(&p)?;
        let auth = actor("alice");
        let mut row = administration.create(&auth, &create_input()).await.map_err(|e| e.to_string())?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        let initial = catalogue(&c, &row.id).await?;
        require(initial.model_id == format!("custom:{}", Uuid::parse_str(&row.id).map_err(|e| e.to_string())?)
            && initial.revision == 1 && row.revision == 1, "initial identity/revisions wrong")?;
        let stable_id = initial.model_id.clone();
        drop(c);
        for change in ["name", "key", "noop"] {
            let mut input = edit(&row);
            match change {
                "name" => input.name = "Renamed only".to_owned(),
                "key" => input.api_key = Some(key("OWNED_CATALOGUE_KEY_ROTATION")),
                _ => {},
            }
            let previous_revision = row.revision;
            row = administration.update(&auth, &row.id, &input).await.map_err(|e| e.to_string())?;
            require(row.revision == previous_revision + 1, "old CRUD did not advance its own revision")?;
            let c = p.get().await.map_err(|e| e.to_string())?;
            require(catalogue(&c, &row.id).await? == initial,
                "name/key/noop rewrote catalogue tuple or advanced catalogue xmin/revision")?;
        }
        let c = p.get().await.map_err(|e| e.to_string())?;
        c.execute("UPDATE public.model_connections SET updated_at=updated_at+interval '1 second' WHERE id=$1",
            &[&Uuid::parse_str(&row.id).map_err(|e| e.to_string())?])
            .await.map_err(|e| e.to_string())?;
        require(catalogue(&c, &row.id).await? == initial, "time-only change rewrote catalogue xmin")?;
        drop(c);
        row = administration.get(&auth, &row.id).await.map_err(|e| e.to_string())?;
        for change in ["protocol", "endpoint", "model", "enabled"] {
            let c = p.get().await.map_err(|e| e.to_string())?;
            let before = catalogue(&c, &row.id).await?;
            drop(c);
            let mut input = edit(&row);
            match change {
                "protocol" => { input.protocol = CustomModelProtocol::OpenaiResponses;
                    input.endpoint = "https://catalog.example.test/v1".to_owned();
                    input.api_key = Some(key("OWNED_CATALOGUE_PROTOCOL_KEY")); },
                "endpoint" => { input.endpoint = "https://second.example.test/v1/responses".to_owned();
                    input.api_key = Some(key("OWNED_CATALOGUE_ENDPOINT_KEY")); },
                "model" => input.model = "catalog-model-two".to_owned(),
                _ => input.enabled = false,
            }
            row = administration.update(&auth, &row.id, &input).await.map_err(|e| e.to_string())?;
            let c = p.get().await.map_err(|e| e.to_string())?;
            let after = catalogue(&c, &row.id).await?;
            require(after.model_id == stable_id && after.revision == before.revision + 1
                && after.xmin != before.xmin && after.protocol == row.protocol.as_str()
                && after.endpoint == row.endpoint && after.model == row.model
                && after.enabled == row.enabled && !after.retired,
                "real definition change did not advance independent catalogue state once")?;
        }
        require(administration.get(&actor("bob"), &row.id).await == Err(ModelError::NotVisible),
            "foreign owner read a connection")?;
        require(administration.update(&actor("bob"), &row.id, &edit(&row)).await
            == Err(ModelError::NotVisible), "foreign owner updated a connection")?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        let before = catalogue(&c, &row.id).await?;
        drop(c);
        let deleted = administration.delete(&auth, &row.id,
            &DeleteModelConnection { expected_revision: row.revision }).await.map_err(|e| e.to_string())?;
        require(deleted.revision == row.revision + 1, "softdelete lost original connection revision")?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        let after = catalogue(&c, &row.id).await?;
        require(after.model_id == stable_id && after.revision == before.revision + 1 && after.retired,
            "retirement did not independently advance catalogue revision")?;
        custom_model_catalog_schema::verify(&c).await.map_err(|e| e.to_string())?;
        c.execute("DELETE FROM public.model_connections WHERE id=$1",
            &[&Uuid::parse_str(&row.id).map_err(|e| e.to_string())?])
            .await.map_err(|e| e.to_string())?;
        let remaining: i64 = c.query_one("SELECT count(*) FROM public.custom_model_catalogs", &[])
            .await.map_err(|e| e.to_string())?.get(0);
        require(remaining == 0, "harddelete did not use registered FK cascade")?;
        drop(c);
        drop(administration);
        Ok(())
    }).await;
}

// A single accepted, explicitly owned loopback connection. There is no unbounded accept loop,
// and finish() joins the original relay task rather than treating abort as destruction proof.
#[derive(Default)]
struct WireFacts {
    pid: AtomicI32,
    frontend_commits: AtomicUsize,
    commit_cz: AtomicUsize,
    rollback_cz: AtomicUsize,
    dropped_commit_cz: AtomicUsize,
    hold_row_result: AtomicBool,
    saw_row_parse: AtomicBool,
    row_result_cz: AtomicUsize,
    frontend_terminated: AtomicBool,
    drop_commit: AtomicBool,
    row_result_seen: Notify,
    row_result_release: Notify,
}

struct WireRelay {
    port: u16,
    facts: Arc<WireFacts>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<TestResult>>,
}

impl Drop for WireRelay {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        // Only a failed/unwound test takes this path. It does not report successful retirement.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let tag = r.read_u8().await?;
    let length = r.read_u32().await?;
    if !(4..=16 * 1024 * 1024).contains(&length) {
        return Err(std::io::Error::other("owned relay invalid frame length"));
    }
    let mut payload = vec![0; (length - 4) as usize];
    r.read_exact(&mut payload).await?;
    Ok((tag, payload))
}

async fn send_frame<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    tag: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    w.write_u8(tag).await?;
    w.write_u32((payload.len() + 4) as u32).await?;
    w.write_all(payload).await
}

fn sql_in_frame(tag: u8, payload: &[u8]) -> Option<&str> {
    let bytes = match tag {
        b'Q' => payload,
        b'P' => {
            let end = payload.iter().position(|b| *b == 0)?;
            payload.get(end + 1..)?
        }
        _ => return None,
    };
    let end = bytes.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&bytes[..end]).ok()
}

impl WireRelay {
    async fn start(config: &pool::DatabaseConfig) -> TestResult<Self> {
        require(
            matches!(config.host.as_str(), "127.0.0.1" | "::1")
                && config.dbname.starts_with("openbot_it_"),
            "relay target is not an owned loopback database",
        )?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let host = config.host.clone();
        let upstream_port = config.port;
        let facts = Arc::new(WireFacts::default());
        let observed = facts.clone();
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let operation = async {
                let (mut downstream, _) = listener.accept().await.map_err(|e| e.to_string())?;
                let mut upstream = TcpStream::connect((host.as_str(), upstream_port))
                    .await
                    .map_err(|e| e.to_string())?;
                // NoTls startup is length-prefixed, without a frame tag. No SSL downgrade exists.
                let length = downstream.read_u32().await.map_err(|e| e.to_string())?;
                require(
                    (8..=64 * 1024).contains(&length),
                    "owned relay invalid startup",
                )?;
                let mut startup = vec![0; (length - 4) as usize];
                downstream
                    .read_exact(&mut startup)
                    .await
                    .map_err(|e| e.to_string())?;
                require(
                    startup.get(..4) == Some(&196_608_u32.to_be_bytes()),
                    "owned relay received a non-v3 startup",
                )?;
                upstream
                    .write_u32(length)
                    .await
                    .map_err(|e| e.to_string())?;
                upstream
                    .write_all(&startup)
                    .await
                    .map_err(|e| e.to_string())?;
                let (mut down_read, mut down_write) = downstream.into_split();
                let (mut up_read, mut up_write) = upstream.into_split();
                let frontend_facts = observed.clone();
                let frontend = async {
                    loop {
                        let (tag, payload) = frame(&mut down_read).await?;
                        if let Some(sql) = sql_in_frame(tag, &payload) {
                            if sql.trim().eq_ignore_ascii_case("COMMIT") {
                                frontend_facts
                                    .frontend_commits
                                    .fetch_add(1, Ordering::SeqCst);
                            }
                            if sql.contains("public.model_connections c")
                                && sql.ends_with(" FOR UPDATE OF c")
                            {
                                frontend_facts.saw_row_parse.store(true, Ordering::SeqCst);
                            }
                        }
                        send_frame(&mut up_write, tag, &payload).await?;
                        if tag == b'X' {
                            frontend_facts
                                .frontend_terminated
                                .store(true, Ordering::SeqCst);
                            return Ok::<(), std::io::Error>(());
                        }
                    }
                };
                let backend = async {
                    loop {
                        let (tag, payload) = frame(&mut up_read).await?;
                        if tag == b'K' {
                            if payload.len() != 8 {
                                return Err(std::io::Error::other("bad BackendKeyData"));
                            }
                            observed.pid.store(
                                i32::from_be_bytes(
                                    payload[..4]
                                        .try_into()
                                        .map_err(|_| std::io::Error::other("bad backend PID"))?,
                                ),
                                Ordering::SeqCst,
                            );
                        }
                        let disposition =
                            tag == b'C' && (payload == b"COMMIT\0" || payload == b"ROLLBACK\0");
                        let row_gate = tag == b'C'
                            && payload == b"SELECT 1\0"
                            && observed.saw_row_parse.swap(false, Ordering::SeqCst)
                            && observed.hold_row_result.swap(false, Ordering::SeqCst);
                        if disposition || row_gate {
                            // The exact response completes at ReadyForQuery. Capture both real
                            // frames before suppression/holding; neither is manufactured.
                            let (ready_tag, ready) = frame(&mut up_read).await?;
                            if ready_tag != b'Z'
                                || ready.as_slice() != if row_gate { b"T" } else { b"I" }
                            {
                                return Err(std::io::Error::other(
                                    "owned relay unexpected disposition sequence",
                                ));
                            }
                            if row_gate {
                                observed.row_result_cz.fetch_add(1, Ordering::SeqCst);
                                observed.row_result_seen.notify_one();
                                observed.row_result_release.notified().await;
                            } else if payload == b"COMMIT\0" {
                                observed.commit_cz.fetch_add(1, Ordering::SeqCst);
                                if observed.drop_commit.swap(false, Ordering::SeqCst) {
                                    observed.dropped_commit_cz.fetch_add(1, Ordering::SeqCst);
                                    return Ok(());
                                }
                            } else {
                                observed.rollback_cz.fetch_add(1, Ordering::SeqCst);
                            }
                            send_frame(&mut down_write, tag, &payload).await?;
                            send_frame(&mut down_write, ready_tag, &ready).await?;
                        } else {
                            send_frame(&mut down_write, tag, &payload).await?;
                        }
                    }
                };
                tokio::select! {
                    value = frontend => match value {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
                        Err(e) => Err(e.to_string()),
                    },
                    value = backend => match value {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
                            && observed.frontend_terminated.load(Ordering::SeqCst) => Ok(()),
                        Err(e) => Err(e.to_string()),
                    },
                }
            };
            tokio::select! {
                value = operation => value,
                _ = stopped => Err("owned relay explicitly stopped before natural closure".to_owned()),
            }
        });
        Ok(Self {
            port,
            facts,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    fn config(&self, original: &pool::DatabaseConfig, name: &str) -> pool::DatabaseConfig {
        let mut config = original
            .clone()
            .with_application_name(name)
            .with_max_pool_size(1);
        config.host = "127.0.0.1".to_owned();
        config.port = self.port;
        config
    }

    async fn finish(mut self) -> TestResult {
        let task = self.task.take().ok_or("owned relay task missing")?;
        let joined = tokio::time::timeout(CLOSE_BUDGET, task)
            .await
            .map_err(|_| "original relay did not naturally retire".to_owned())?
            .map_err(|e| e.to_string())?;
        self.shutdown.take();
        joined
    }
}

struct OwnedClient {
    client: Client,
    driver: JoinHandle<Result<(), tokio_postgres::Error>>,
    pid: i32,
}

impl OwnedClient {
    async fn connect(config: &pool::DatabaseConfig, name: &str) -> TestResult<Self> {
        require(
            config.dbname.starts_with("openbot_it_")
                && matches!(config.host.as_str(), "127.0.0.1" | "::1"),
            "direct owner target is not owned",
        )?;
        let (client, connection) = config
            .clone()
            .with_application_name(name)
            .to_pg_config()
            .connect(NoTls)
            .await
            .map_err(|e| e.to_string())?;
        let driver = tokio::spawn(connection);
        let pid = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        Ok(Self {
            client,
            driver,
            pid,
        })
    }

    async fn close(self, observer: &Client) -> TestResult {
        let Self {
            client,
            driver,
            pid,
        } = self;
        drop(client);
        tokio::time::timeout(CLOSE_BUDGET, driver)
            .await
            .map_err(|_| "original direct driver did not retire".to_owned())?
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        wait_for(
            observer,
            "original direct PG backend did not disappear",
            |c| {
                Box::pin(async move {
                    let absent: bool = c
                        .query_one(
                            "SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                            &[&pid],
                        )
                        .await
                        .map_err(|e| e.to_string())?
                        .get(0);
                    Ok(absent)
                })
            },
        )
        .await
    }
}

async fn wait_for<F>(c: &Client, failure: &'static str, mut predicate: F) -> TestResult
where
    F: for<'a> FnMut(
        &'a Client,
    ) -> std::pin::Pin<Box<dyn Future<Output = TestResult<bool>> + Send + 'a>>,
{
    tokio::time::timeout(OBSERVE_BUDGET, async {
        loop {
            if predicate(c).await? {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| failure.to_owned())?
}

async fn pool_barrier(p: &pool::DatabasePool) -> TestResult {
    // A one-client pool means this original connection consumes its queued real ROLLBACK
    // before this subsequent SELECT result. The relay separately records ROLLBACK C/Z(I).
    let c = p.get().await.map_err(|e| e.to_string())?;
    c.simple_query("SELECT 1")
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PG17, Vault and observed original rollback wire"]
async fn foundation_original_failures_roll_back_catalog_vault_and_audit() {
    owned_fixture("catalog46rollback", |config, p| async move {
        initialize(&p, 46).await?;
        let relay = WireRelay::start(&config).await?;
        let original_pool = pool::connect(&relay.config(&config, "catalog-original-failure-crud"))
            .await.map_err(|e| e.to_string())?;
        let administration = port(&original_pool)?;
        let original = administration.create(&actor("alice"), &create_input())
            .await.map_err(|e| e.to_string())?;
        let id = Uuid::parse_str(&original.id).map_err(|e| e.to_string())?;
        let mut c = p.get().await.map_err(|e| e.to_string())?;
        let clean = state(&c).await?;
        // Each reached failure is compared against its own committed pre-fault state.
        c.batch_execute("CREATE FUNCTION openbot_internal.qa_catalog_audit_fault() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN IF NEW.target_type='model_connection' THEN
            RAISE EXCEPTION 'owned catalogue audit fault'; END IF; RETURN NEW; END $$;
            CREATE TRIGGER qa_catalog_audit_fault BEFORE INSERT ON public.audit_events
            FOR EACH ROW EXECUTE FUNCTION openbot_internal.qa_catalog_audit_fault()")
            .await.map_err(|e| e.to_string())?;
        for operation in ["create", "update", "delete"] {
            let before = state(&c).await?;
            let rollbacks = relay.facts.rollback_cz.load(Ordering::SeqCst);
            let failed = match operation {
                "create" => administration.create(&actor("alice"), &create_input()).await.map(|_| ()),
                "update" => {
                    let mut input = edit(&original);
                    input.model = "change-before-audit-fault".to_owned();
                    input.api_key = Some(key("OWNED_CATALOGUE_AUDIT_ROTATION"));
                    administration.update(&actor("alice"), &original.id, &input).await.map(|_| ())
                },
                _ => administration.delete(&actor("alice"), &original.id,
                    &DeleteModelConnection { expected_revision: original.revision }).await.map(|_| ()),
            };
            require(failed == Err(ModelError::Unavailable), "original audit failure classification changed")?;
            pool_barrier(&original_pool).await?;
            require(relay.facts.rollback_cz.load(Ordering::SeqCst) == rollbacks + 1,
                "original audit failure had no real ROLLBACK C/Z(I)")?;
            require(state(&c).await? == before, "audit failure committed connection/catalogue/Vault/audit delta")?;
        }
        c.batch_execute("DROP TRIGGER qa_catalog_audit_fault ON public.audit_events;
            DROP FUNCTION openbot_internal.qa_catalog_audit_fault();
            CREATE FUNCTION openbot_internal.qa_catalog_ciphertext_fault() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN NEW.encrypted_value='invalid-owned-envelope'; RETURN NEW; END $$;
            CREATE TRIGGER qa_catalog_ciphertext_fault BEFORE INSERT ON public.model_connection_secrets
            FOR EACH ROW EXECUTE FUNCTION openbot_internal.qa_catalog_ciphertext_fault()")
            .await.map_err(|e| e.to_string())?;
        for creating in [true, false] {
            let before = state(&c).await?;
            let rollbacks = relay.facts.rollback_cz.load(Ordering::SeqCst);
            let failed = if creating {
                administration.create(&actor("alice"), &create_input()).await.map(|_| ())
            } else {
                let mut input = edit(&original);
                input.model = "change-before-vault-fault".to_owned();
                input.api_key = Some(key("OWNED_CATALOGUE_VAULT_ROTATION"));
                administration.update(&actor("alice"), &original.id, &input).await.map(|_| ())
            };
            require(failed == Err(ModelError::Corrupt), "actual stored Vault ciphertext failure was not Corrupt")?;
            pool_barrier(&original_pool).await?;
            require(relay.facts.rollback_cz.load(Ordering::SeqCst) == rollbacks + 1,
                "original Vault failure had no real rollback")?;
            require(state(&c).await? == before, "Vault failure committed any original transaction row")?;
        }
        c.batch_execute("DROP TRIGGER qa_catalog_ciphertext_fault ON public.model_connection_secrets;
            DROP FUNCTION openbot_internal.qa_catalog_ciphertext_fault()")
            .await.map_err(|e| e.to_string())?;
        require(state(&c).await? == clean, "fault setup/teardown changed business rows")?;
        for fault in ["overflow", "missing", "drift"] {
            match fault {
                "overflow" => { c.execute("UPDATE public.custom_model_catalogs SET catalog_revision=9223372036854775807 WHERE connection_id=$1", &[&id])
                    .await.map_err(|e| e.to_string())?; },
                "missing" => { c.execute("DELETE FROM public.custom_model_catalogs WHERE connection_id=$1", &[&id])
                    .await.map_err(|e| e.to_string())?; },
                _ => { c.execute("UPDATE public.custom_model_catalogs SET model='owned-drift' WHERE connection_id=$1", &[&id])
                    .await.map_err(|e| e.to_string())?; },
            }
            let before = state(&c).await?;
            let rollbacks = relay.facts.rollback_cz.load(Ordering::SeqCst);
            let mut input = edit(&original);
            input.model = "definition-trigger-fault".to_owned();
            input.api_key = Some(key("OWNED_CATALOGUE_TRIGGER_ROTATION"));
            require(administration.update(&actor("alice"), &original.id, &input).await
                == Err(ModelError::Unavailable), "trigger/mapping/overflow did not fail original CRUD")?;
            pool_barrier(&original_pool).await?;
            require(relay.facts.rollback_cz.load(Ordering::SeqCst) == rollbacks + 1,
                "trigger failure had no real original rollback")?;
            require(state(&c).await? == before, "trigger failure wrote or repaired catalogue/Vault/audit")?;
            // Explicit QA teardown restores the deliberately damaged fixture, never product repair.
            if fault == "missing" {
                c.execute("INSERT INTO public.custom_model_catalogs
                    SELECT id,deployment_id,tenant_id,owner_user_id,'custom:'||id::text,1,protocol,endpoint,model,enabled,deleted_at IS NOT NULL
                    FROM public.model_connections WHERE id=$1", &[&id])
                    .await.map_err(|e| e.to_string())?;
            } else {
                c.execute("UPDATE public.custom_model_catalogs SET catalog_revision=1,model=$2 WHERE connection_id=$1",
                    &[&id, &original.model]).await.map_err(|e| e.to_string())?;
            }
        }
        // The original API has no rebinding operation; exercise real SQL constraints/trigger,
        // recording their actual classification rather than promising every branch reaches55000.
        let before = state(&c).await?;
        let tx = c.transaction().await.map_err(|e| e.to_string())?;
        let rejected = match tx.execute("UPDATE public.model_connections SET tenant_id='foreign-owned-tenant' WHERE id=$1", &[&id]).await {
            Ok(_) => return Err("namespace rebinding was accepted".to_owned()),
            Err(error) => error,
        };
        let code = rejected.code().ok_or("rebinding lacked SQLSTATE")?.code();
        require(matches!(code, "55000" | "23503" | "23514"), "unexpected actual rebind classification")?;
        tx.rollback().await.map_err(|e| e.to_string())?;
        require(state(&c).await? == before, "rebind changed original namespace/catalogue")?;
        custom_model_catalog_schema::verify(&c).await.map_err(|e| e.to_string())?;
        let original_pid = relay.facts.pid.load(Ordering::SeqCst);
        require(relay.facts.rollback_cz.load(Ordering::SeqCst) == 8
            && relay.facts.commit_cz.load(Ordering::SeqCst) == 1
            && relay.facts.dropped_commit_cz.load(Ordering::SeqCst) == 0,
            "original failure matrix had an unexpected commit/rollback disposition")?;
        println!("catalogue_original_failure_dispositions_actual {}", serde_json::json!({
            "originalBackendPid": original_pid,
            "actualRollbackCZIdle": relay.facts.rollback_cz.load(Ordering::SeqCst),
            "actualInitialCreateCommitCZIdle": relay.facts.commit_cz.load(Ordering::SeqCst),
            "actualRebindSQLSTATE": code,
            "directRebindRollbackAcknowledged": true
        }));
        drop(administration);
        close_pool(original_pool).await?;
        relay.finish().await?;
        wait_for(&c, "original CRUD backend survived driver closure", |observer| Box::pin(async move {
            Ok(observer.query_one("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)", &[&original_pid])
                .await.map_err(|e| e.to_string())?.get(0))
        })).await?;
        Ok(())
    }).await;
}

async fn install_ddl_gate(c: &Client, fail: bool) -> TestResult {
    let superuser: bool = c
        .query_one(
            "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(
        superuser,
        "owned ddl_command_start capability unavailable; test cannot silently skip",
    )?;
    let tail = if fail {
        "RAISE EXCEPTION 'owned pre-backfill fault' USING ERRCODE='P0001';"
    } else {
        ""
    };
    c.batch_execute(&format!("CREATE FUNCTION openbot_internal.qa_catalog_ddl_gate() RETURNS event_trigger
        LANGUAGE plpgsql AS $$ BEGIN
        IF TG_TAG='CREATE TABLE' AND position('CREATE TABLE public.custom_model_catalogs' in current_query())>0 THEN
            PERFORM pg_catalog.pg_advisory_xact_lock({DDL_GATE_KEY}); {tail}
        END IF; END $$;
        CREATE EVENT TRIGGER qa_catalog_ddl_gate ON ddl_command_start
        EXECUTE FUNCTION openbot_internal.qa_catalog_ddl_gate()"))
        .await.map_err(|e| e.to_string())?;
    c.query_one("SELECT pg_advisory_lock($1)", &[&DDL_GATE_KEY])
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn remove_ddl_gate(c: &Client) -> TestResult {
    c.batch_execute(
        "DROP EVENT TRIGGER qa_catalog_ddl_gate;
        DROP FUNCTION openbot_internal.qa_catalog_ddl_gate()",
    )
    .await
    .map_err(|e| e.to_string())
}

async fn wait_early_exclusive(c: &Client, migration_pid: i32, control_pid: i32) -> TestResult {
    wait_for(c, "migration never reached genuine pre-DDL exclusive control point", |observer| Box::pin(async move {
        Ok(observer.query_one("SELECT
            EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.model_connections'::regclass AND mode='ExclusiveLock' AND granted)
            AND NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.model_connections'::regclass AND mode='ShareRowExclusiveLock')
            AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)
            AND $2=ANY(pg_blocking_pids($1))
            AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND query LIKE '%CREATE TABLE public.custom_model_catalogs%')
            AND to_regclass('public.custom_model_catalogs') IS NULL", &[&migration_pid, &control_pid])
            .await.map_err(|e| e.to_string())?.get(0))
    })).await
}

async fn wait_crud_behind_migration(c: &Client, crud_pid: i32, migration_pid: i32) -> TestResult {
    wait_for(c, "original CRUD did not actually wait behind migration ExclusiveLock", |observer| Box::pin(async move {
        Ok(observer.query_one("SELECT
            EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.model_connections'::regclass AND mode='RowShareLock' AND NOT granted)
            AND $2=ANY(pg_blocking_pids($1))
            AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND query LIKE '%FOR UPDATE OF c')",
            &[&crud_pid, &migration_pid]).await.map_err(|e| e.to_string())?.get(0))
    })).await
}

async fn early_lock_leg(fail: bool) {
    owned_fixture(if fail { "catalog45earlyfail" } else { "catalog45earlylock" },
        move |config, p| async move {
            initialize(&p, 45).await?;
            let administration = port(&p)?;
            let original = administration.create(&actor("alice"), &create_input())
                .await.map_err(|e| e.to_string())?;
            drop(administration);
            let control = p.get().await.map_err(|e| e.to_string())?;
            let control_pid: i32 = control.query_one("SELECT pg_backend_pid()", &[])
                .await.map_err(|e| e.to_string())?.get(0);
            let old_ledger: String = control.query_one("SELECT jsonb_agg(to_jsonb(l) ORDER BY version)::text FROM openbot_internal.schema_migrations l", &[])
                .await.map_err(|e| e.to_string())?.get(0);
            install_ddl_gate(&control, fail).await?;
            let migration_relay = WireRelay::start(&config).await?;
            let mut migrating = OwnedClient::connect(&migration_relay.config(&config, "catalog-original-native"),
                "catalog-original-native").await?;
            let migration_pid = migrating.pid;
            let migration_task = tokio::spawn(async move {
                let result = native::apply(&mut migrating.client).await;
                // Transaction drop queues rollback. This same original connection's next result
                // consumes it; the relay additionally requires actual ROLLBACK C/Z(I).
                let barrier = migrating.client.simple_query("SELECT 1").await;
                (migrating, result, barrier)
            });
            wait_early_exclusive(&control, migration_pid, control_pid).await?;
            let crud_relay = WireRelay::start(&config).await?;
            let original_pool = pool::connect(&crud_relay.config(&config, "catalog-original-waiting-crud"))
                .await.map_err(|e| e.to_string())?;
            let reader = port(&original_pool)?;
            require(reader.get(&actor("alice"), &original.id).await.map_err(|e| e.to_string())? == original,
                "ordinary original get was blocked or changed by ExclusiveLock")?;
            require(reader.list(&actor("alice"), &ModelConnectionPageRequest::default())
                .await.map_err(|e| e.to_string())?.connections.len() == 1,
                "ordinary original list was blocked by ExclusiveLock")?;
            let crud_pid = crud_relay.facts.pid.load(Ordering::SeqCst);
            let mut input = edit(&original);
            input.model = "original-crud-after-lock".to_owned();
            let id = original.id.clone();
            let crud_task = tokio::spawn(async move {
                let result = reader.update(&actor("alice"), &id, &input).await;
                (reader, result)
            });
            wait_crud_behind_migration(&control, crud_pid, migration_pid).await?;
            let released: bool = control.query_one("SELECT pg_advisory_unlock($1)", &[&DDL_GATE_KEY])
                .await.map_err(|e| e.to_string())?.get(0);
            require(released, "original DDL control lock was not owned")?;
            let (migrating, migration_result, barrier) = tokio::time::timeout(OBSERVE_BUDGET, migration_task)
                .await.map_err(|_| "original native outcome was not observed".to_owned())?
                .map_err(|e| e.to_string())?;
            barrier.map_err(|e| e.to_string())?;
            let (reader, crud_result) = tokio::time::timeout(OBSERVE_BUDGET, crud_task)
                .await.map_err(|_| "original CRUD outcome was not observed".to_owned())?
                .map_err(|e| e.to_string())?;
            let changed = crud_result.map_err(|e| e.to_string())?;
            require(changed.revision == original.revision + 1 && changed.model == "original-crud-after-lock",
                "later original CRUD did not independently commit its own change")?;
            remove_ddl_gate(&control).await?;
            if fail {
                require(migration_result.as_ref().err().is_some_and(|e| e.sqlstate() == Some("P0001")),
                    "pre-backfill exception lacked actual expected SQLSTATE P0001")?;
                require(migration_relay.facts.rollback_cz.load(Ordering::SeqCst) == 1
                    && migration_relay.facts.commit_cz.load(Ordering::SeqCst) == 0,
                    "failed native did not produce original rollback-only disposition")?;
                let absent: bool = control.query_one("SELECT
                    to_regclass('public.custom_model_catalogs') IS NULL
                    AND to_regprocedure('openbot_internal.sync_custom_model_catalog()') IS NULL
                    AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.model_connections'::regclass AND tgname='model_connections_custom_catalog_sync')
                    AND NOT EXISTS(SELECT 1 FROM openbot_internal.schema_migrations WHERE version=46)", &[])
                    .await.map_err(|e| e.to_string())?.get(0);
                require(absent, "failed pre-backfill native left catalogue/function/trigger/ledger")?;
                let actual: String = control.query_one("SELECT jsonb_agg(to_jsonb(l) ORDER BY version)::text FROM openbot_internal.schema_migrations l", &[])
                    .await.map_err(|e| e.to_string())?.get(0);
                require(actual == old_ledger, "failed native rewrote original45 ledger")?;
                require(crud_relay.facts.commit_cz.load(Ordering::SeqCst) == 3,
                    "get/list/later CRUD real commit dispositions were not all observed")?;
            } else {
                require(migration_result.map_err(|e| e.to_string())? == native::ApplyOutcome::Applied,
                    "early-lock native did not normally commit")?;
                require(migration_relay.facts.commit_cz.load(Ordering::SeqCst) == 1
                    && migration_relay.facts.rollback_cz.load(Ordering::SeqCst) == 0,
                    "normal native disposition was not actual COMMIT C/Z(I)")?;
                let actual = catalogue(&control, &original.id).await?;
                require(actual.revision == 2 && actual.model == changed.model,
                    "post-migration original CRUD did not advance catalogue exactly once")?;
                custom_model_catalog_schema::verify(&control).await.map_err(|e| e.to_string())?;
            }
            println!("catalogue_early_lock_actual {}", serde_json::json!({
                "migrationPid": migration_pid, "crudPid": crud_pid, "controlPid": control_pid,
                "preCreateExclusiveAndActualWaitObserved": true,
                "migrationCommitCZ": migration_relay.facts.commit_cz.load(Ordering::SeqCst),
                "migrationRollbackCZ": migration_relay.facts.rollback_cz.load(Ordering::SeqCst),
                "laterOriginalCrudCommitCZ": crud_relay.facts.commit_cz.load(Ordering::SeqCst),
                "failedLeg": fail
            }));
            migrating.close(&control).await?;
            migration_relay.finish().await?;
            drop(reader);
            close_pool(original_pool).await?;
            crud_relay.finish().await?;
            Ok(())
        }).await;
}

async fn reverse_lock_leg() {
    owned_fixture("catalog45reverselock", |config, p| async move {
        initialize(&p, 45).await?;
        let setup = port(&p)?;
        let original = setup.create(&actor("alice"), &create_input()).await.map_err(|e| e.to_string())?;
        drop(setup);
        let observer = p.get().await.map_err(|e| e.to_string())?;
        let relay = WireRelay::start(&config).await?;
        let original_pool = pool::connect(&relay.config(&config, "catalog-original-row-first-crud"))
            .await.map_err(|e| e.to_string())?;
        let administration = port(&original_pool)?;
        relay.facts.hold_row_result.store(true, Ordering::SeqCst);
        let facts = relay.facts.clone();
        let mut input = edit(&original);
        input.model = "original-crud-won-before-backfill".to_owned();
        let id = original.id.clone();
        let crud_task = tokio::spawn(async move {
            let result = administration.update(&actor("alice"), &id, &input).await;
            (administration, result)
        });
        tokio::time::timeout(OBSERVE_BUDGET, facts.row_result_seen.notified()).await
            .map_err(|_| "original FOR UPDATE real C/Z(T) was not observed".to_owned())?;
        let crud_pid = facts.pid.load(Ordering::SeqCst);
        require(facts.row_result_cz.load(Ordering::SeqCst) == 1,
            "original FOR UPDATE did not produce exactly one real C/Z(T) gate")?;
        let held: bool = observer.query_one("SELECT
            EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.model_connections'::regclass AND mode='RowShareLock' AND granted)
            AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND state='idle in transaction' AND query LIKE '%FOR UPDATE OF c')",
            &[&crud_pid]).await.map_err(|e| e.to_string())?.get(0);
        require(held, "original CRUD had not truly obtained table/row lock before migration")?;
        let mut migrating = OwnedClient::connect(&config, "catalog-native-after-original-row-lock").await?;
        let migration_pid = migrating.pid;
        let migration_task = tokio::spawn(async move {
            let result = native::apply(&mut migrating.client).await;
            (migrating, result)
        });
        wait_for(&observer, "migration did not wait on actual original CRUD RowShareLock", |c| Box::pin(async move {
            Ok(c.query_one("SELECT
                EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.model_connections'::regclass AND mode='ExclusiveLock' AND NOT granted)
                AND $2=ANY(pg_blocking_pids($1))
                AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND query LIKE '%LOCK TABLE public.model_connections IN EXCLUSIVE MODE%')
                AND to_regclass('public.custom_model_catalogs') IS NULL", &[&migration_pid, &crud_pid])
                .await.map_err(|e| e.to_string())?.get(0))
        })).await?;
        facts.row_result_release.notify_one();
        let (administration, result) = tokio::time::timeout(OBSERVE_BUDGET, crud_task).await
            .map_err(|_| "original row-first CRUD outcome unobserved".to_owned())?
            .map_err(|e| e.to_string())?;
        let changed = result.map_err(|e| e.to_string())?;
        let (migrating, result) = tokio::time::timeout(OBSERVE_BUDGET, migration_task).await
            .map_err(|_| "native after row-first CRUD outcome unobserved".to_owned())?
            .map_err(|e| e.to_string())?;
        require(result.map_err(|e| e.to_string())? == native::ApplyOutcome::Applied,
            "native after original row-first CRUD did not apply")?;
        let actual = catalogue(&observer, &original.id).await?;
        require(changed.revision == 2 && actual.revision == 1
            && actual.model == "original-crud-won-before-backfill",
            "backfill did not preserve original CRUD winner with independent version1")?;
        require(facts.commit_cz.load(Ordering::SeqCst) == 1,
            "original row-first CRUD did not actually COMMIT")?;
        custom_model_catalog_schema::verify(&observer).await.map_err(|e| e.to_string())?;
        println!("catalogue_reverse_lock_actual {}", serde_json::json!({
            "crudPid": crud_pid, "migrationPid": migration_pid,
            "originalForUpdateCZTransactionState": "T",
            "originalForUpdateCZCount": facts.row_result_cz.load(Ordering::SeqCst),
            "actualRowShareBeforeExclusiveWaitObserved": true,
            "originalCrudCommitCZ": facts.commit_cz.load(Ordering::SeqCst)
        }));
        migrating.close(&observer).await?;
        drop(administration);
        close_pool(original_pool).await?;
        relay.finish().await?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned loopback PG17 superuser ddl event capability and real wire controls"]
async fn foundation_native_pre_backfill_lock_blocks_original_crud_until_commit() {
    early_lock_leg(false).await;
    reverse_lock_leg().await;
}

#[tokio::test]
#[ignore = "requires owned loopback PG17 superuser ddl event capability and real rollback wire"]
async fn foundation_native_pre_backfill_failure_installs_no_catalog() {
    early_lock_leg(true).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PG17 and independently captured0046 fixtures"]
async fn foundation_tamper_is_refused_at_native_replay_start_and_schema_verify() {
    // Separate newly owned databases avoid restoring a tampered schema through product code.
    // The unknown row must stay strictly after the binary's pinned latest, not a real migration.
    let unknown_future = format!(
        "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES({},'owned_unknown_native','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')",
        native::NATIVE_LATEST_VERSION + 1
    );
    let mutations = [
        ("missingmapping", "DELETE FROM public.custom_model_catalogs"),
        (
            "definitiondrift",
            "UPDATE public.custom_model_catalogs SET model='owned-definition-drift'",
        ),
        (
            "disabledsync",
            "ALTER TABLE public.model_connections DISABLE TRIGGER model_connections_custom_catalog_sync",
        ),
        (
            "extracolumn",
            "ALTER TABLE public.custom_model_catalogs ADD COLUMN owned_extra text",
        ),
        (
            "extraindex",
            "CREATE INDEX owned_extra_catalog_index ON public.custom_model_catalogs(model)",
        ),
        (
            "tablegrant",
            "GRANT SELECT ON public.custom_model_catalogs TO PUBLIC",
        ),
        (
            "columngrant",
            "GRANT SELECT(model) ON public.custom_model_catalogs TO PUBLIC",
        ),
        (
            "functiongrant",
            "GRANT EXECUTE ON FUNCTION openbot_internal.sync_custom_model_catalog() TO PUBLIC",
        ),
        (
            "functionbody",
            "CREATE OR REPLACE FUNCTION openbot_internal.sync_custom_model_catalog() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN RETURN NEW; END$$",
        ),
        (
            "functionoverload",
            "CREATE FUNCTION openbot_internal.sync_custom_model_catalog(integer) RETURNS integer LANGUAGE sql AS $$SELECT $1$$",
        ),
        (
            "catalogpolicy",
            "CREATE POLICY owned_extra_policy ON public.custom_model_catalogs USING(true)",
        ),
        (
            "connectionpolicy",
            "CREATE POLICY owned_extra_policy ON public.model_connections USING(true)",
        ),
        (
            "secretpolicy",
            "CREATE POLICY owned_extra_policy ON public.model_connection_secrets USING(true)",
        ),
        ("unknownprefix", unknown_future.as_str()),
    ];
    for (tag, sql) in mutations {
        owned_fixture(tag, move |_, p| async move {
            initialize(&p, 46).await?;
            let administration = port(&p)?;
            let original = administration
                .create(&actor("alice"), &create_input())
                .await
                .map_err(|e| e.to_string())?;
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            c.batch_execute(sql).await.map_err(|e| e.to_string())?;
            let before = state(&c).await?;
            let shape = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
            let captured = custom_model_catalog_schema::capture(&c).await;
            require(matches!(&captured, Ok(_) |
                Err(custom_model_catalog_schema::CustomModelCatalogSchemaError::Corrupt { .. })),
                "tamper capture failed because storage or infrastructure was unavailable")?;
            let verification = custom_model_catalog_schema::verify(&c).await;
            require(
                matches!(verification,
                    Err(custom_model_catalog_schema::CustomModelCatalogSchemaError::Corrupt { field })
                    if if tag == "unknownprefix" { field == "native_prefix" }
                    else if matches!(tag, "missingmapping" | "definitiondrift") { field == "catalog_mapping" }
                    else { matches!(field, "catalog_schema" | "catalog_facts") }),
                "specialized verify did not return the explicit actual tamper classification",
            )?;
            require(
                matches!(native::apply(&mut c).await,
                    Err(InfraError::RepositoryInvariant { code: "custom_model_catalog_schema_invalid" })),
                "native AlreadyApplied did not return the explicit catalogue invariant",
            )?;
            c.simple_query("SELECT 1")
                .await
                .map_err(|e| e.to_string())?;
            drop(c);
            require(
                matches!(initialization::initialize(&p).await,
                    Err(initialization::DatabaseInitializationError::Infra(
                        InfraError::RepositoryInvariant { code: "custom_model_catalog_schema_invalid" }))),
                "original startup did not return the explicit catalogue invariant",
            )?;
            require(
                matches!(desktop_vault_canary::verify_pre_upgrade_layout(&p).await,
                    Err(desktop_vault_canary::DesktopVaultCanaryError::Infra(
                        InfraError::RepositoryInvariant { code:
                            "custom_model_catalog_schema_invalid" | "desktop_vault_public_schema_invalid"
                            | "native_migration_ledger_unknown_row" }))),
                "original canary preflight did not return an explicit schema/prefix refusal",
            )?;
            let c = p.get().await.map_err(|e| e.to_string())?;
            require(
                state(&c).await? == before
                    && schema_facts::fetch(&c).await.map_err(|e| e.to_string())? == shape
                    && custom_model_catalog_schema::capture(&c).await == captured,
                "schema refusal repaired or changed tampered database",
            )?;
            drop(c);
            if tag == "disabledsync" {
                // Legacy CRUD has no every-call schema gate. Prove its limited behavior rather
                // than claiming disabling a privileged trigger magically denies legacy CRUD.
                let c = p.get().await.map_err(|e| e.to_string())?;
                let old_catalogue = catalogue(&c, &original.id).await?;
                drop(c);
                let mut input = edit(&original);
                input.model = "legacy-update-with-privileged-sync-disabled".to_owned();
                let changed = administration
                    .update(&actor("alice"), &original.id, &input)
                    .await
                    .map_err(|e| e.to_string())?;
                let c = p.get().await.map_err(|e| e.to_string())?;
                require(changed.model == input.model && changed.revision == original.revision + 1
                    && catalogue(&c, &original.id).await? == old_catalogue,
                    "legacy CRUD schema-gate boundary was misrepresented")?;
                require(matches!(custom_model_catalog_schema::verify(&c).await,
                    Err(custom_model_catalog_schema::CustomModelCatalogSchemaError::Corrupt { .. })),
                    "explicit schema verify accepted privileged disabled-sync corruption")?;
            }
            drop(administration);
            Ok(())
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires owned loopback PG17 and suppression of original actual COMMIT C/Z(I)"]
async fn foundation_original_commit_ack_loss_keeps_unknown_outcome_without_replay() {
    owned_fixture("catalog46commitloss", |config, p| async move {
        initialize(&p, 46).await?;
        let setup = port(&p)?;
        let original = setup.create(&actor("alice"), &create_input()).await.map_err(|e| e.to_string())?;
        drop(setup);
        let c = p.get().await.map_err(|e| e.to_string())?;
        let before = state(&c).await?;
        let first = catalogue(&c, &original.id).await?;
        let relay = WireRelay::start(&config).await?;
        let original_pool = pool::connect(&relay.config(&config, "catalog-original-commit-loss-crud"))
            .await.map_err(|e| e.to_string())?;
        let administration = port(&original_pool)?;
        // Preserve the same original owner before connection loss can retire/remove it from the
        // supervisor's live inventory. An empty later inventory is not destruction evidence.
        let original_observations = original_pool.connection_observations();
        require(original_observations.len() == 1,
            "commit-loss fixture did not retain exactly one original pool owner")?;
        let before_commits = relay.facts.frontend_commits.load(Ordering::SeqCst);
        relay.facts.drop_commit.store(true, Ordering::SeqCst);
        let mut input = edit(&original);
        input.model = "committed-before-original-ack-loss".to_owned();
        input.api_key = Some(key("OWNED_CATALOGUE_COMMIT_LOSS_ROTATION"));
        require(administration.update(&actor("alice"), &original.id, &input).await
            == Err(ModelError::CommitUnknown), "original commit ACK loss was not CommitUnknown")?;
        require(relay.facts.frontend_commits.load(Ordering::SeqCst) == before_commits + 1
            && relay.facts.commit_cz.load(Ordering::SeqCst) == 1
            && relay.facts.dropped_commit_cz.load(Ordering::SeqCst) == 1
            && relay.facts.rollback_cz.load(Ordering::SeqCst) == 0,
            "original committed ACK loss was replayed or fabricated as rollback")?;
        let after = state(&c).await?;
        let actual = catalogue(&c, &original.id).await?;
        require(actual.model_id == first.model_id && actual.revision == first.revision + 1
            && actual.model == input.model, "actual committed catalogue outcome was not exactly once")?;
        let row = c.query_one("SELECT c.revision,c.model,
            (SELECT count(*) FROM public.model_connection_secrets),
            (SELECT count(*) FROM public.model_connection_secrets WHERE retired_at IS NOT NULL),
            (SELECT count(*) FROM public.audit_events WHERE target_type='model_connection')
            FROM public.model_connections c WHERE c.id=$1", &[&Uuid::parse_str(&original.id).map_err(|e| e.to_string())?])
            .await.map_err(|e| e.to_string())?;
        require(row.get::<_, i64>(0) == original.revision + 1
            && row.get::<_, String>(1) == input.model && row.get::<_, i64>(2) == 2
            && row.get::<_, i64>(3) == 1 && row.get::<_, i64>(4) == 2,
            "committed unknown outcome duplicated connection/Vault/retirement/audit")?;
        require(after != before, "actual committed outcome was wrongly treated as unchanged")?;
        custom_model_catalog_schema::verify(&c).await.map_err(|e| e.to_string())?;
        let original_pid = relay.facts.pid.load(Ordering::SeqCst);
        println!("catalogue_original_commit_loss_actual {}", serde_json::json!({
            "originalBackendPid": original_pid,
            "frontendCommitCount": relay.facts.frontend_commits.load(Ordering::SeqCst),
            "actualSuppressedCommitCZIdle": relay.facts.dropped_commit_cz.load(Ordering::SeqCst),
            "actualRollbackCZ": relay.facts.rollback_cz.load(Ordering::SeqCst),
            "originalReturnedCommitUnknown": true
        }));
        drop(administration);
        close_pool(original_pool).await?;
        let original_close_deadline = Instant::now() + CLOSE_BUDGET;
        for observation in original_observations {
            require(observation.wait_for_destruction_before(original_close_deadline).await
                .map_err(|e| e.to_string())? == pool::ConnectionDestruction::ConnectionDestroyed,
                "original commit-loss driver had no actual retained destruction observation")?;
        }
        relay.finish().await?;
        wait_for(&c, "original commit-loss PG backend did not disappear", |observer| Box::pin(async move {
            Ok(observer.query_one("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)", &[&original_pid])
                .await.map_err(|e| e.to_string())?.get(0))
        })).await?;
        // Independent read-only verification after closure; no call retries the failed update.
        require(state(&c).await? == after, "closure or verification replayed original CRUD")?;
        Ok(())
    }).await;
}
