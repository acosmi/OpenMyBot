//! Actual Axum framing → PostgreSQL session resolver → shared production assembly → model Vault.
//! ServiceExt avoids opening an HTTP socket; PostgreSQL is a separately owned synthetic instance.

#[path = "support/transport_fixture.rs"]
mod transport_fixture;

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
    assemble_postgres_application,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::policy::PolicyStore;
use openbot_infra::ui_preferences::PostgresUiPreferenceAdministration;
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::{PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const DEPLOYMENT: &str = "model-http-deployment";
const TENANT: &str = "model-http-tenant";
const ORIGIN: &str = "https://wrok-ui.example.test";
const SESSION_KEY: &[u8] = b"synthetic-model-http-session-hash-key";
const ALICE_COOKIE: &str = "synthetic-model-http-alice-session-token-001";
const ALICE_OLD_COOKIE: &str = "synthetic-model-http-alice-old-session-token-002";
const BOB_COOKIE: &str = "synthetic-model-http-bob-session-token-003";
const KEY_ONE: &str = "MODEL_HTTP_PRIVATE_CANARY_ONE";
const KEY_TWO: &str = "MODEL_HTTP_PRIVATE_CANARY_TWO";
const KEY_THREE: &str = "MODEL_HTTP_PRIVATE_CANARY_THREE";
const KEY_REJECTED: &str = "MODEL_HTTP_PRIVATE_CANARY_REJECTED";
const BASE: &str = "/api/me/model-connections";

struct UnusedRemote;

#[async_trait]
impl RemoteAguiTransport for UnusedRemote {
    async fn start(
        &self,
        _endpoint: &str,
        _authorization: Option<&openbot_application::RemoteAguiAuthorization>,
        _body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        panic!("personal model CRUD must not invoke the unrelated remote Agent port")
    }
}

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn no_secret(text: &str) -> Result<(), String> {
    require(
        !text.contains("MODEL_HTTP_PRIVATE_CANARY")
            && ![ALICE_COOKIE, ALICE_OLD_COOKIE, BOB_COOKIE]
                .iter()
                .any(|cookie| text.contains(cookie)),
        "HTTP/audit/ciphertext leaked a key canary",
    )
}

async fn seed_identity(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    baseline::apply(&client).await.map_err(|e| e.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|e| e.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.users(id,email,auth_generation) VALUES
         ('alice','alice@example.test',7),('bob','bob@example.test',3);
         INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');",
        )
        .await
        .map_err(|e| e.to_string())?;
    let now = OffsetDateTime::now_utc();
    for (id, actor, token, generation, age) in [
        (
            "alice-session",
            "alice",
            ALICE_COOKIE,
            7_i64,
            Duration::minutes(1),
        ),
        (
            "alice-old-session",
            "alice",
            ALICE_OLD_COOKIE,
            7,
            Duration::hours(1),
        ),
        ("bob-session", "bob", BOB_COOKIE, 3, Duration::minutes(1)),
    ] {
        let token = SessionTokenHash::compute(
            SessionToken::new(token.as_bytes()),
            SessionHashKey::new(SESSION_KEY),
        )
        .to_column_value();
        client.execute(
            "INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation)
             VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[&id,&actor,&token,&(now+Duration::hours(1)),&(now-age),&now,&generation],
        ).await.map_err(|e|e.to_string())?;
    }
    Ok(())
}

async fn assemble(
    pool: &openbot_infra::db::pool::DatabasePool,
    config: &DatabaseConfig,
) -> Result<
    (
        PostgresApplicationAssembly,
        CredentialRecordVault,
        axum::Router,
    ),
    String,
> {
    let tenant = TenantId::new(TENANT);
    let vault = CredentialRecordVault::single_key(
        tenant.clone(),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x71; 32]).map_err(|e| e.to_string())?,
    );
    let policies = PolicyStore::postgres(pool.clone(), None);
    policies.load().await.map_err(|e| e.to_string())?;
    // This is the same production entry used by Server and Desktop. The test does not manually
    // inject PostgresModelConnections: a missing production assembly edge must make it fail.
    let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
        pool: pool.clone(),
        listener_database: config.clone().into(),
        deployment: DeploymentId::new(DEPLOYMENT),
        tenant: tenant.clone(),
        single_user: false,
        admin_floor: None,
        model: "unused-routing-model".to_owned(),
        credential_key_id: "unused-routing-key".to_owned(),
        credential_vault: vault.clone(),
        audit_key: SecretBytes::new(vec![0x72; 32]),
        remote_assertions: Arc::new(
            RemoteRunAssertionSigner::new(vec![0x73; 32]).map_err(|e| e.to_string())?,
        ),
        mcp_oauth_state_key: SecretBytes::new(vec![0x74; 32]),
        policy_store: policies,
        ui_preferences: Arc::new(
            PostgresUiPreferenceAdministration::new(
                pool.clone(),
                DeploymentId::new(DEPLOYMENT),
                tenant.clone(),
                SecretBytes::new(vec![0x72; 32]),
            )
            .map_err(|e| e.to_string())?,
        ),
        screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
        artifacts: None,
        runtime_capabilities: None,
        remote_agent_probe: Arc::new(UnusedRemote),
        managed_slot_available: false,
        channel_routing_provider: ChannelRoutingProviderInput {
            endpoint: Url::parse("http://127.0.0.1:9/v1/chat/completions")
                .map_err(|e| e.to_string())?,
            environment_api_key: None,
            egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
            allow_http: true,
        },
        stall_timeout: Some(std::time::Duration::from_secs(2)),
        oauth_public_url: None,
        app_url: None,
        extra_provider_adapters: Vec::new(),
        run_event_subscriber: None,
        delegation_authority: None,
    })
    .await
    .map_err(|e| e.to_string())?;
    let resolver = PostgresSessionAuthResolver::new(
        pool.clone(),
        SESSION_KEY,
        default_session_lifetime(),
        DeploymentId::new(DEPLOYMENT),
        tenant,
    )
    .map_err(|e| e.to_string())?;
    let security = SensitiveWriteSecurity::new(
        default_session_lifetime(),
        TrustedOrigins::from_configured([ORIGIN]).map_err(|e| e.to_string())?,
    );
    let router = transport_fixture::loopback_router(
        ServerBuilder::new(assembly.application.clone(), Arc::new(resolver))
            .with_transport_policy(transport_fixture::loopback_policy())
            .with_sensitive_write_security(security)
            .build(),
    );
    Ok((assembly, vault, router))
}

async fn send(
    router: &axum::Router,
    method: Method,
    path: &str,
    cookie: &str,
    origin: Option<&str>,
    body: Option<String>,
    expected: StatusCode,
) -> Result<Value, String> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::COOKIE, format!("openbot_session={cookie}"));
    if let Some(origin) = origin {
        request = request.header(http::header::ORIGIN, origin);
    }
    if body.is_some() {
        request = request.header(http::header::CONTENT_TYPE, "application/json");
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, Body::from))
                .map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    for value in response.headers().values() {
        if let Ok(value) = value.to_str() {
            no_secret(value)?;
        }
    }
    if status.is_success() || status == StatusCode::CONFLICT {
        require(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .is_some_and(|v| v == "no-store"),
            "model response missing no-store",
        )?;
    }
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "HTTP response is not UTF-8".to_owned())?;
    no_secret(text)?;
    require(
        status == expected,
        "unexpected model HTTP status (body intentionally omitted)",
    )?;
    serde_json::from_str(text).map_err(|_| "HTTP response is not JSON".to_owned())
}

fn create_body() -> Value {
    json!({"name":"Personal model","protocol":"openai_chat_completions",
        "endpoint":"https://one-provider.example.test/v1","model":"model-one","enabled":true,"apiKey":KEY_ONE})
}

fn update_body(row: &Value) -> Value {
    json!({"expectedRevision":row["revision"],"name":row["name"],"protocol":row["protocol"],
        "endpoint":row["endpoint"],"model":row["model"],"enabled":row["enabled"]})
}

fn read_shape(row: &Value) -> Result<(), String> {
    const KEYS: [&str; 11] = [
        "id",
        "source",
        "name",
        "protocol",
        "endpoint",
        "model",
        "enabled",
        "revision",
        "hasCredential",
        "createdAt",
        "updatedAt",
    ];
    let object = row
        .as_object()
        .ok_or_else(|| "model response is not an object".to_owned())?;
    require(
        object.len() == KEYS.len() && object.keys().all(|key| KEYS.contains(&key.as_str())),
        "model read exposed undeclared fields",
    )
}

async fn current_secret(
    pool: &openbot_infra::db::pool::DatabasePool,
    vault: &CredentialRecordVault,
    id: &str,
    expected: &str,
) -> Result<Uuid, String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let id_uuid = Uuid::parse_str(id).map_err(|e| e.to_string())?;
    let row=client.query_one(
        "SELECT c.deployment_id,c.tenant_id,c.owner_user_id,s.id,s.encrypted_value,s.retired_at IS NULL AS active
         FROM public.model_connections c JOIN public.model_connection_secrets s ON s.id=c.current_secret_id WHERE c.id=$1",
        &[&id_uuid],
    ).await.map_err(|e|e.to_string())?;
    let (deployment, tenant, actor): (String, String, String) =
        (row.get(0), row.get(1), row.get(2));
    require(
        deployment == DEPLOYMENT && tenant == TENANT && actor == "alice",
        "HTTP stored scope did not come from the session",
    )?;
    require(
        row.get::<_, bool>("active"),
        "current model key is already retired",
    )?;
    let secret_id: Uuid = row.get("id");
    let ciphertext: String = row.get("encrypted_value");
    no_secret(&ciphertext)?;
    let owner = SecretPrincipal::Actor(ActorId::new("alice"));
    let consumer = SecretPrincipal::Service(ServiceId::new(id));
    let opened = vault
        .open(
            &secret_id,
            SecretKind::Model,
            owner,
            consumer.clone(),
            &ciphertext,
        )
        .map_err(|_| "stored model key failed production Vault authentication".to_owned())?
        .into_secret();
    require(
        opened.expose() == expected.as_bytes(),
        "Vault key roundtrip mismatch",
    )?;
    require(
        vault
            .open(
                &secret_id,
                SecretKind::Model,
                SecretPrincipal::Actor(ActorId::new("bob")),
                consumer,
                &ciphertext,
            )
            .is_err(),
        "another administrator authenticated the owner key envelope",
    )?;
    Ok(secret_id)
}

async fn snapshot(pool: &openbot_infra::db::pool::DatabasePool) -> Result<Value, String> {
    pool.get().await.map_err(|e|e.to_string())?.query_one(
        "SELECT jsonb_build_object(
           'connections',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM public.model_connections c),
           'secrets',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.model_connection_secrets s),
           'audit',(SELECT count(*) FROM public.audit_events WHERE target_type='model_connection'))",
        &[],
    ).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())
}

async fn guard_matrix(
    router: &axum::Router,
    pool: &openbot_infra::db::pool::DatabasePool,
    path: &str,
) -> Result<(), String> {
    let before = snapshot(pool).await?;
    for (method, route) in [
        (Method::POST, BASE),
        (Method::PUT, path),
        (Method::DELETE, path),
    ] {
        for origin in [None, Some("https://other-origin.example.test")] {
            let response = send(
                router,
                method.clone(),
                route,
                ALICE_COOKIE,
                origin,
                Some("{malformed".to_owned()),
                StatusCode::FORBIDDEN,
            )
            .await?;
            require(
                response["code"]
                    .as_str()
                    .is_some_and(|code| code.starts_with("identity_sensitive_write_origin_")),
                "Origin guard did not precede JSON parsing",
            )?;
        }
        let response = send(
            router,
            method,
            route,
            ALICE_OLD_COOKIE,
            Some(ORIGIN),
            Some("{malformed".to_owned()),
            StatusCode::UNAUTHORIZED,
        )
        .await?;
        require(
            response["code"] == "identity_sensitive_write_session_not_fresh",
            "freshness guard did not precede body parsing",
        )?;
    }
    // The old session remains authenticated for reads; it only lacks fresh write assurance.
    send(
        router,
        Method::GET,
        path,
        ALICE_OLD_COOKIE,
        None,
        None,
        StatusCode::OK,
    )
    .await?;
    require(
        snapshot(pool).await? == before,
        "rejected HTTP guard changed model data/key/audit",
    )
}

async fn journey(
    router: &axum::Router,
    pool: &openbot_infra::db::pool::DatabasePool,
    vault: &CredentialRecordVault,
) -> Result<(), String> {
    let created = send(
        router,
        Method::POST,
        BASE,
        ALICE_COOKIE,
        Some(ORIGIN),
        Some(create_body().to_string()),
        StatusCode::CREATED,
    )
    .await?;
    read_shape(&created)?;
    require(
        created["source"] == "custom"
            && created["revision"] == 1
            && created["hasCredential"] == true,
        "created custom model metadata is invalid",
    )?;
    require(
        created["endpoint"] == "https://one-provider.example.test/v1/chat/completions",
        "shared normalization was bypassed",
    )?;
    let id = created["id"]
        .as_str()
        .ok_or_else(|| "missing server model ID".to_owned())?;
    require(
        Uuid::parse_str(id)
            .map_err(|e| e.to_string())?
            .get_version_num()
            == 7,
        "connection ID was not server-minted UUIDv7",
    )?;
    let path = format!("{BASE}/{id}");
    let first = current_secret(pool, vault, id, KEY_ONE).await?;
    let loaded = send(
        router,
        Method::GET,
        &path,
        ALICE_COOKIE,
        None,
        None,
        StatusCode::OK,
    )
    .await?;
    require(
        loaded == created,
        "HTTP GET did not read durable model metadata",
    )?;
    let list = send(
        router,
        Method::GET,
        BASE,
        ALICE_COOKIE,
        None,
        None,
        StatusCode::OK,
    )
    .await?;
    require(
        list["connections"] == json!([created.clone()]),
        "owner HTTP inventory missed the durable row",
    )?;
    guard_matrix(router, pool, &path).await?;

    let before = snapshot(pool).await?;
    send(
        router,
        Method::GET,
        &path,
        BOB_COOKIE,
        None,
        None,
        StatusCode::NOT_FOUND,
    )
    .await?;
    send(
        router,
        Method::PUT,
        &path,
        BOB_COOKIE,
        Some(ORIGIN),
        Some(update_body(&created).to_string()),
        StatusCode::NOT_FOUND,
    )
    .await?;
    send(
        router,
        Method::DELETE,
        &path,
        BOB_COOKIE,
        Some(ORIGIN),
        Some(json!({"expectedRevision":1}).to_string()),
        StatusCode::NOT_FOUND,
    )
    .await?;
    let admin_list = send(
        router,
        Method::GET,
        BASE,
        BOB_COOKIE,
        None,
        None,
        StatusCode::OK,
    )
    .await?;
    require(
        admin_list["connections"] == json!([]),
        "administrator enumerated another actor's private model",
    )?;
    require(
        snapshot(pool).await? == before,
        "administrator mutated another actor's connection",
    )?;

    let mut metadata = update_body(&created);
    metadata["model"] = json!("model-two");
    metadata["enabled"] = json!(false);
    let changed = send(
        router,
        Method::PUT,
        &path,
        ALICE_COOKIE,
        Some(ORIGIN),
        Some(metadata.to_string()),
        StatusCode::OK,
    )
    .await?;
    read_shape(&changed)?;
    require(
        changed["revision"] == 2 && changed["enabled"] == false,
        "metadata update failed",
    )?;
    require(
        current_secret(pool, vault, id, KEY_ONE).await? == first,
        "metadata-only update replaced the key",
    )?;
    let mut endpoint = update_body(&changed);
    endpoint["endpoint"] = json!("https://two-provider.example.test/v1");
    let before = snapshot(pool).await?;
    send(
        router,
        Method::PUT,
        &path,
        ALICE_COOKIE,
        Some(ORIGIN),
        Some(endpoint.to_string()),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    require(
        snapshot(pool).await? == before,
        "endpoint change without a new key changed persistence",
    )?;
    endpoint["apiKey"] = json!(KEY_TWO);
    endpoint["enabled"] = json!(true);
    let rotated = send(
        router,
        Method::PUT,
        &path,
        ALICE_COOKIE,
        Some(ORIGIN),
        Some(endpoint.to_string()),
        StatusCode::OK,
    )
    .await?;
    read_shape(&rotated)?;
    require(
        rotated["revision"] == 3,
        "endpoint and key revision did not advance",
    )?;
    let second = current_secret(pool, vault, id, KEY_TWO).await?;
    require(
        second != first,
        "endpoint/key update reused old envelope ID",
    )?;
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let retired: bool = client
        .query_one(
            "SELECT retired_at IS NOT NULL FROM public.model_connection_secrets WHERE id=$1",
            &[&first],
        )
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(retired, "old key was not atomically retired")?;
    drop(client);

    let mut replacement = update_body(&rotated);
    replacement["apiKey"] = json!(KEY_THREE);
    let key_only = send(
        router,
        Method::PUT,
        &path,
        ALICE_COOKIE,
        Some(ORIGIN),
        Some(replacement.to_string()),
        StatusCode::OK,
    )
    .await?;
    read_shape(&key_only)?;
    require(
        key_only["revision"] == 4,
        "key-only revision did not advance",
    )?;
    let third = current_secret(pool, vault, id, KEY_THREE).await?;
    require(third != second, "key-only rotation reused envelope")?;
    replacement["apiKey"] = json!(KEY_REJECTED);
    let before = snapshot(pool).await?;
    for method in [Method::PUT, Method::DELETE] {
        let body = if method == Method::PUT {
            update_body(&created)
        } else {
            json!({"expectedRevision":1})
        };
        let denied = send(
            router,
            method,
            &path,
            BOB_COOKIE,
            Some(ORIGIN),
            Some(body.to_string()),
            StatusCode::NOT_FOUND,
        )
        .await?;
        require(
            denied == json!({"code":"not_visible"}),
            "another actor received current revision metadata",
        )?;
    }
    let stale_update = send(
        router,
        Method::PUT,
        &path,
        ALICE_COOKIE,
        Some(ORIGIN),
        Some(replacement.to_string()),
        StatusCode::CONFLICT,
    )
    .await?;
    let stale_delete = send(
        router,
        Method::DELETE,
        &path,
        ALICE_COOKIE,
        Some(ORIGIN),
        Some(json!({"expectedRevision":3}).to_string()),
        StatusCode::CONFLICT,
    )
    .await?;
    let expected_snapshot = openbot_contracts::revision::RevisionSnapshot::from_public(
        4,
        serde_json::from_value::<openbot_contracts::model_connections::ModelConnection>(
            key_only.clone(),
        )
        .map_err(|e| e.to_string())?
        .updated_at,
        &key_only,
    )
    .map_err(|e| e.to_string())?;
    require(
        stale_update == serde_json::to_value(expected_snapshot).map_err(|e| e.to_string())?,
        "stale update did not return the exact closed current snapshot",
    )?;
    require(
        stale_delete == stale_update,
        "stale delete returned a different current snapshot",
    )?;
    require(
        snapshot(pool).await? == before,
        "stale CAS left a metadata/key/audit effect",
    )?;
    require(
        current_secret(pool, vault, id, KEY_THREE).await? == third,
        "stale CAS changed the current key",
    )?;

    let deleted = send(
        router,
        Method::DELETE,
        &path,
        ALICE_COOKIE,
        Some(ORIGIN),
        Some(json!({"expectedRevision":4}).to_string()),
        StatusCode::OK,
    )
    .await?;
    require(
        deleted["id"] == id && deleted["revision"] == 5,
        "delete receipt is inconsistent",
    )?;
    send(
        router,
        Method::GET,
        &path,
        ALICE_COOKIE,
        None,
        None,
        StatusCode::NOT_FOUND,
    )
    .await?;
    let list = send(
        router,
        Method::GET,
        BASE,
        ALICE_COOKIE,
        None,
        None,
        StatusCode::OK,
    )
    .await?;
    require(
        list["connections"] == json!([]),
        "deleted model remained in active inventory",
    )?;
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let row=client.query_one("SELECT count(*)::bigint,count(*) FILTER(WHERE retired_at IS NULL)::bigint FROM public.model_connection_secrets",&[])
        .await.map_err(|e|e.to_string())?;
    require(
        row.get::<_, i64>(0) == 3 && row.get::<_, i64>(1) == 0,
        "deleted connection did not retain only three retired envelopes",
    )?;
    let audit:String=client.query_one("SELECT coalesce(string_agg(payload::text,' '),'') FROM public.audit_events WHERE target_type='model_connection'",&[])
        .await.map_err(|e|e.to_string())?.get(0);
    no_secret(&audit)?;
    require(
        !audit.contains("provider.example") && !audit.contains("apiKey"),
        "closed audit leaked endpoint/key field",
    )?;
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM public.audit_events WHERE target_type='model_connection'",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(
        count == 5,
        "successful CRUD writes did not each commit one closed audit",
    )
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn actual_http_sessions_shared_assembly_and_vault_enforce_personal_model_crud() {
    let config = harness::admin_config("model HTTP production assembly");
    harness::with_temp_database(&config, "modelhttp", |config| async move {
        let config = config.with_max_pool_size(6);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let result = async {
            seed_identity(&pool).await?;
            let (assembly, vault, router) = assemble(&pool, &config).await?;
            let result = journey(&router, &pool, &vault).await;
            drop(router);
            assembly.shutdown().await;
            result
        }
        .await;
        pool.close();
        result
    })
    .await;
}
