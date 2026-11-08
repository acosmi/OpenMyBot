use super::*;
use crate::auth::{
    AuthResolver, PostgresSessionAuthResolver, SensitiveWriteSecurity, SingleUserAuthResolver,
};
use crate::http::ServerBuilder;
use async_trait::async_trait;
use futures_util::StreamExt;
use openbot_application::custom_model_catalog::{
    CurrentCustomModelCatalogPage, CustomModelCatalogError, CustomModelCatalogInventory,
};
use openbot_application::{ApplicationService, OpenBotApplication};
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::single_user::{
    SINGLE_USER_ACTOR_ID, initialize_single_user, load_single_user_principal,
};
use openbot_infra::custom_model_catalog::PostgresCustomModelCatalogInventory;
use openbot_infra::db::{baseline, native, pool, pool::DatabaseConfig};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;
use time::OffsetDateTime;
use tower::ServiceExt;

mod harness {
    use std::future::Future;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}

const KEY: &[u8] = b"owned-custom-catalog-session-key";
const COOKIE_A: &str = "owned-catalog-session-token-a-0001";
const COOKIE_B: &str = "owned-catalog-session-token-b-0002";
const CONNECTION: &str = "00000000-0000-7000-8000-000000000001";
const ORIGIN: &str = "https://catalog.example.test";

#[test]
fn raw_cursor_is_literal_closed_and_bounded() {
    assert_eq!(parse_raw_query(None).unwrap().cursor, None);
    assert_eq!(parse_raw_query(Some("")).unwrap().cursor, None);
    assert_eq!(
        parse_raw_query(Some(&format!("cursor={CONNECTION}")))
            .unwrap()
            .cursor
            .as_deref(),
        Some(CONNECTION)
    );
    for query in [
        "cursor=",
        "owner=owner",
        "cursor=%30",
        "Cursor=00000000-0000-7000-8000-000000000001",
        "cursor=00000000-0000-7000-8000-000000000001&cursor=00000000-0000-7000-8000-000000000001",
        "cursor=00000000-0000-7000-8000-000000000001&",
        "cursor=00000000-0000-7000-8000-00000000000A",
    ] {
        assert!(matches!(
            parse_raw_query(Some(query)),
            Err(AppError::MalformedPayload { field: "query" })
        ));
    }
}

#[test]
fn bounded_writer_refuses_the_overflow_before_appending() {
    let mut bytes = vec![0; MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES - 1];
    assert!(BoundedWriter(&mut bytes).write_all(b"xy").is_err());
    assert_eq!(bytes.len(), MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES - 1);
    BoundedWriter(&mut bytes).write_all(b"x").unwrap();
    assert!(BoundedWriter(&mut bytes).write_all(b"y").is_err());
    assert_eq!(bytes.len(), MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES);
}

struct CountedInventory {
    actual: Arc<PostgresCustomModelCatalogInventory>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl CustomModelCatalogInventory for CountedInventory {
    async fn list_current(
        &self,
        auth: &AuthContext,
        request: &CustomModelCatalogPageRequest,
        deadline: Instant,
    ) -> Result<CurrentCustomModelCatalogPage, CustomModelCatalogError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.actual.list_current(auth, request, deadline).await
    }
}

struct Fixture {
    pool: pool::DatabasePool,
    resolver: Arc<PostgresSessionAuthResolver>,
    application: Arc<dyn ApplicationService>,
    state: ServerState,
    calls: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new(config: DatabaseConfig) -> Result<Self, String> {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&client).await.map_err(|e| e.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|e| e.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('catalog-owner','catalog-owner@example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('catalog-owner','user');
                BEGIN;
                INSERT INTO public.model_connections(id,deployment_id,tenant_id,owner_user_id,name,protocol,endpoint,model,enabled,revision,current_secret_id,created_at,updated_at)
                VALUES('00000000-0000-7000-8000-000000000001','catalog-deployment','catalog-tenant','catalog-owner','Current definition','openai_responses','https://model.example.test/v1/responses','owned-model',false,7,'00000000-0000-7000-8000-000000000002',clock_timestamp(),clock_timestamp());
                INSERT INTO public.model_connection_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at)
                VALUES('00000000-0000-7000-8000-000000000002','00000000-0000-7000-8000-000000000001','catalog-deployment','catalog-tenant','catalog-owner','opaque-owned-test-secret',clock_timestamp());
                COMMIT;").await.map_err(|e| e.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, cookie) in [
                ("catalog-session-a", COOKIE_A),
                ("catalog-session-b", COOKIE_B),
            ] {
                let column = SessionTokenHash::compute(
                    SessionToken::new(cookie.as_bytes()),
                    SessionHashKey::new(KEY),
                )
                .to_column_value();
                client.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,'catalog-owner',$2,$3,$4,$4,0)",
                    &[&id,&column,&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))]).await.map_err(|e| e.to_string())?;
            }
        }
        let deployment = DeploymentId::new("catalog-deployment");
        let tenant = TenantId::new("catalog-tenant");
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                KEY,
                default_session_lifetime(),
                deployment.clone(),
                tenant.clone(),
            )
            .map_err(|e| e.to_string())?,
        );
        let actual = Arc::new(
            PostgresCustomModelCatalogInventory::new(pool.clone(), deployment, tenant)
                .map_err(|e| format!("{e:?}"))?,
        );
        resolver
            .install_custom_model_catalog_inventory(&actual)
            .map_err(|e| format!("{e:?}"))?;
        let calls = Arc::new(AtomicUsize::new(0));
        let inventory = Arc::new(CountedInventory {
            actual,
            calls: calls.clone(),
        });
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(openbot_infra::repo::channels::ChannelRepo::new(
                pool.clone(),
            ))
            .with_custom_model_catalog_inventory(inventory),
        );
        let state = ServerBuilder::new(application.clone(), resolver.clone())
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured([ORIGIN]).map_err(|e| e.to_string())?,
            ))
            .build();
        Ok(Self {
            pool,
            resolver,
            application,
            state,
            calls,
        })
    }

    async fn auth(&self, cookie: &str) -> Result<AuthContext, String> {
        let parts = http::Request::builder()
            .uri(PATH)
            .header("cookie", format!("openbot_session={cookie}"))
            .body(())
            .map_err(|e| e.to_string())?
            .into_parts()
            .0;
        self.resolver
            .resolve(&parts)
            .await
            .map_err(|e| e.to_string())
    }

    async fn response(&self, auth: AuthContext) -> Result<Response, HttpError> {
        list(
            State(self.state.clone()),
            OriginAuthenticated(auth),
            http::Request::builder()
                .uri(PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.resolver.close_request_bindings();
        self.pool.close();
    }
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL and actual Session/schema/rollback chain"]
async fn actual_session_catalog_http_framing_and_no_store() {
    harness::with_temp_database(&harness::admin_config("catalog_http"), "catalog_http", |config| async move {
        let fixture = Fixture::new(config).await?;
        let router = crate::router(fixture.state.clone());
        let idle_before: serde_json::Value = fixture.pool.get().await.map_err(|e| e.to_string())?.query_one("SELECT jsonb_build_object('updated_at',updated_at,'expires_at',expires_at,'created_at',created_at) FROM public.sessions WHERE id='catalog-session-a'",&[]).await.map_err(|e| e.to_string())?.get(0);
        for (method,path,cookie,body,status) in [
            (Method::HEAD, PATH.to_owned(), Some(COOKIE_A), Vec::new(), StatusCode::METHOD_NOT_ALLOWED),
            (Method::POST, PATH.to_owned(), Some(COOKIE_A), Vec::new(), StatusCode::METHOD_NOT_ALLOWED),
            (Method::GET, PATH.to_owned(), None, Vec::new(), StatusCode::UNAUTHORIZED),
            (Method::GET, format!("{PATH}?owner=other"), Some(COOKIE_A), Vec::new(), StatusCode::BAD_REQUEST),
            (Method::GET, format!("{PATH}?cursor="), Some(COOKIE_A), Vec::new(), StatusCode::BAD_REQUEST),
            (Method::GET, format!("{PATH}?cursor=%30{CONNECTION}"), Some(COOKIE_A), Vec::new(), StatusCode::BAD_REQUEST),
            (Method::GET, PATH.to_owned(), Some(COOKIE_A), b"x".to_vec(), StatusCode::BAD_REQUEST),
            (Method::GET, format!("{PATH}/unknown"), Some(COOKIE_A), Vec::new(), StatusCode::NOT_FOUND),
        ] {
            let calls = fixture.calls.load(Ordering::SeqCst);
            let mut request = http::Request::builder().method(method).uri(path).header("origin", ORIGIN);
            if let Some(cookie)=cookie { request=request.header("cookie",format!("openbot_session={cookie}")); }
            let response=router.clone().oneshot(request.body(Body::from(body)).map_err(|e| e.to_string())?).await.map_err(|e|e.to_string())?;
            assert_eq!(response.status(),status);
            assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
            assert_eq!(fixture.calls.load(Ordering::SeqCst),calls);
            drop(response);
        }
        for (method, origin, status, reads) in [
            (Method::GET, None, StatusCode::OK, 1),
            (Method::GET, Some("https://untrusted.example.test"), StatusCode::FORBIDDEN, 0),
            (Method::HEAD, None, StatusCode::METHOD_NOT_ALLOWED, 0),
        ] {
            let calls = fixture.calls.load(Ordering::SeqCst);
            let mut request = http::Request::builder().method(method).uri(PATH)
                .header("cookie", format!("openbot_session={COOKIE_A}"));
            if let Some(origin) = origin { request = request.header("origin", origin); }
            let response = router.clone().oneshot(request.body(Body::empty()).unwrap()).await
                .map_err(|e| e.to_string())?;
            assert_eq!(response.status(), status);
            assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
            assert_eq!(fixture.calls.load(Ordering::SeqCst), calls + reads);
            if status == StatusCode::OK {
                let bytes = to_bytes(response.into_body(), MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES)
                    .await.map_err(|e| e.to_string())?;
                let page: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                assert_eq!(page["models"][0]["connectionId"], CONNECTION);
            }
        }
        let response=router.oneshot(http::Request::builder().uri(format!("{PATH}?")).header("origin",ORIGIN).header("cookie",format!("openbot_session={COOKIE_A}")).body(Body::empty()).unwrap()).await.map_err(|e|e.to_string())?;
        assert_eq!(response.status(),StatusCode::OK);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(),"no-store");
        let bytes=to_bytes(response.into_body(),MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES).await.map_err(|e|e.to_string())?;
        let page:serde_json::Value=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
        assert_eq!(page["models"][0]["connectionRevision"],7);
        assert_eq!(page["models"][0]["catalogRevision"],1);
        assert_eq!(page["models"][0]["enabled"],false);
        assert_eq!(page["models"][0].as_object().unwrap().len(),9);
        assert!(page["models"][0].get("endpoint").is_none());
        let idle_after:serde_json::Value=fixture.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT jsonb_build_object('updated_at',updated_at,'expires_at',expires_at,'created_at',created_at) FROM public.sessions WHERE id='catalog-session-a'",&[]).await.map_err(|e|e.to_string())?.get(0);
        assert_eq!(idle_before,idle_after,"catalog read must preserve the persisted touch/idle and lifetime facts");
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL; explicit old rejection must not poison fresh session"]
async fn actual_revoked_session_catalog_does_not_poison_new_session() {
    harness::with_temp_database(&harness::admin_config("catalog_revoke"), "catalog_revoke", |config| async move {
        let fixture=Fixture::new(config).await?;
        let old=fixture.auth(COOKIE_A).await?;
        fixture.pool.get().await.map_err(|e|e.to_string())?.execute("DELETE FROM public.sessions WHERE id='catalog-session-a'",&[]).await.map_err(|e|e.to_string())?;
        let refused=fixture.application.execute(old,AppCommand::ListCustomModelCatalog(CustomModelCatalogPageRequest{cursor:None})).await;
        assert!(matches!(refused,Err(AppError::NotVisible)));
        let response=fixture.response(fixture.auth(COOKIE_B).await?).await.map_err(|e|e.inner().to_string())?;
        assert_eq!(response.status(),StatusCode::OK);
        let bytes=to_bytes(response.into_body(),MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES).await.map_err(|e|e.to_string())?;
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e|e.to_string())?["models"].as_array().unwrap().len(),1);
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires actual PG Session replies, independent keys and real first-poll Bytes ownership"]
async fn actual_catalog_same_body_deliveries_and_bytes_keep_original_allocation() {
    harness::with_temp_database(
        &harness::admin_config("catalog_bytes"),
        "catalog_bytes",
        |config| async move {
            let fixture = Fixture::new(config).await?;
            let auth = fixture.auth(COOKIE_A).await?;
            let input = CustomModelCatalogPageRequest { cursor: None };
            let (one, two) = tokio::join!(
                fixture.application.execute(
                    auth.clone(),
                    AppCommand::ListCustomModelCatalog(input.clone())
                ),
                fixture
                    .application
                    .execute(auth.clone(), AppCommand::ListCustomModelCatalog(input))
            );
            let one = one.map_err(|e| e.to_string())?;
            let two = two.map_err(|e| e.to_string())?;
            let serialized = serde_json::to_vec(&one).map_err(|e| e.to_string())?;
            assert_eq!(
                serialized,
                serde_json::to_vec(&two).map_err(|e| e.to_string())?
            );
            let forged: AppReply =
                serde_json::from_slice(&serialized).map_err(|e| e.to_string())?;
            assert!(matches!(
                fixture
                    .application
                    .take_custom_model_catalog_delivery(auth.clone(), forged),
                Err(AppError::NotVisible)
            ));
            let mut first = fixture
                .application
                .take_custom_model_catalog_delivery(auth.clone(), one)
                .map_err(|e| e.to_string())?;
            let mut second = fixture
                .application
                .take_custom_model_catalog_delivery(auth.clone(), two)
                .map_err(|e| e.to_string())?;
            first
                .verify_current_tail_once(&auth)
                .map_err(|e| e.to_string())?;
            second
                .verify_current_tail_once(&auth)
                .map_err(|e| e.to_string())?;
            drop(first);
            drop(second);
            let mut held = Vec::new();
            for _ in 0..8 {
                let response = fixture
                    .response(auth.clone())
                    .await
                    .map_err(|e| e.inner().to_string())?;
                let mut stream = response.into_body().into_data_stream();
                let bytes = stream
                    .next()
                    .await
                    .ok_or("first JSON frame absent")?
                    .map_err(|e| e.to_string())?;
                assert!(stream.next().await.is_none());
                held.push(bytes);
            }
            assert!(fixture.response(auth.clone()).await.is_err());
            let retained_clone = held[0].clone();
            drop(held.remove(0));
            assert!(
                fixture.response(auth.clone()).await.is_err(),
                "Bytes clone still owns eighth permit"
            );
            drop(retained_clone);
            let unpolled = fixture
                .response(auth.clone())
                .await
                .map_err(|e| e.inner().to_string())?;
            drop(unpolled);
            let mut response = fixture
                .response(auth.clone())
                .await
                .map_err(|e| e.inner().to_string())?
                .into_body()
                .into_data_stream();
            fixture.resolver.close_request_bindings();
            assert!(
                response
                    .next()
                    .await
                    .ok_or("closed body must report its first-poll error")?
                    .is_err()
            );
            assert!(
                response.next().await.is_none(),
                "failed poll emitted a later JSON frame"
            );
            drop(held);
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires genuine canonical ServerSingleUser principal and exact-Pool inventory enrollment"]
async fn actual_single_user_catalog_enrollment_keeps_original_pool_and_once_slot() {
    harness::with_temp_database(&harness::admin_config("catalog_single"), "catalog_single", |config| async move {
        let fixture = Fixture::new(config.clone()).await?;
        let foreign_pool = pool::DatabasePool::build_unprobed(&config).map_err(|e| e.to_string())?;
        let outcome = async {
            initialize_single_user(&fixture.pool, true).await.map_err(|e| e.to_string())?;
            let deployment = DeploymentId::new("catalog-deployment");
            let tenant = TenantId::new("catalog-tenant");
            let principal = load_single_user_principal(&fixture.pool, deployment.clone(), tenant.clone())
                .await.map_err(|e| e.to_string())?;
            assert!(principal.matches_pool_scope(&fixture.pool));
            assert!(!principal.matches_pool_scope(&foreign_pool));
            let parts = http::Request::builder().uri(PATH).body(()).unwrap().into_parts().0;
            struct RejectOtherTarget(AtomicUsize);
            impl openbot_contracts::request_binding::CustomModelCatalogHostTarget for RejectOtherTarget {
                fn matches_authority(&self, _: &Arc<()>) -> bool { self.0.fetch_add(1, Ordering::SeqCst); false }
                fn matches_auth(&self, _: &AuthContext) -> bool { true }
            }
            // Each failed startup uses a distinct genuine resolver/repository and ends here.
            // It must not retry installation or begin serving after the failed assembly step.
            for mismatch in ["principal_pool", "both_pools", "repository_pool", "tenant", "deployment"] {
                let failed = SingleUserAuthResolver::from_verified_principal(principal.clone(), default_session_lifetime());
                let (repository_pool, actual_pool, repository_deployment, repository_tenant) = match mismatch {
                    "principal_pool" => (&fixture.pool, &foreign_pool, deployment.clone(), tenant.clone()),
                    "both_pools" => (&foreign_pool, &foreign_pool, deployment.clone(), tenant.clone()),
                    "repository_pool" => (&foreign_pool, &fixture.pool, deployment.clone(), tenant.clone()),
                    "tenant" => (&fixture.pool, &fixture.pool, deployment.clone(), TenantId::new("foreign-tenant")),
                    "deployment" => (&fixture.pool, &fixture.pool, DeploymentId::new("foreign-deployment"), tenant.clone()),
                    _ => unreachable!("closed test mismatch"),
                };
                let repository = Arc::new(PostgresCustomModelCatalogInventory::new(repository_pool.clone(), repository_deployment, repository_tenant).map_err(|e| format!("{e:?}"))?);
                let rejected = failed.install_custom_model_catalog_inventory(&repository, actual_pool).is_err();
                let failed_auth = failed.resolve(&parts).await.map_err(|e| e.to_string())?;
                let target = RejectOtherTarget(AtomicUsize::new(0));
                let has_no_catalog_grant = failed_auth.request_binding().ok_or("failed branch original binding missing")?
                    .borrow_custom_model_catalog_host_before(&failed_auth, &target, Instant::now() + std::time::Duration::from_secs(5)).is_err();
                failed.close_request_bindings();
                assert!(rejected && has_no_catalog_grant, "wrong startup scope granted inventory: {mismatch}");
                drop(failed_auth);drop(repository);drop(failed);
            }
            // A new normal startup has its own original issuer, repository and once slot.
            let resolver = Arc::new(SingleUserAuthResolver::from_verified_principal(principal, default_session_lifetime()));
            let original = Arc::new(PostgresCustomModelCatalogInventory::new(fixture.pool.clone(), deployment, tenant).map_err(|e| format!("{e:?}"))?);
            resolver.install_custom_model_catalog_inventory(&original, &fixture.pool).map_err(|e| format!("{e:?}"))?;
            let application: Arc<dyn ApplicationService> = Arc::new(OpenBotApplication::new(openbot_infra::repo::channels::ChannelRepo::new(fixture.pool.clone())).with_custom_model_catalog_inventory(original.clone()));
            let state = ServerBuilder::new(application.clone(), resolver.clone())
                .with_sensitive_write_security(SensitiveWriteSecurity::new(default_session_lifetime(), TrustedOrigins::from_configured([ORIGIN]).map_err(|e| e.to_string())?)).build();
            let router = crate::router(state);
            let client = fixture.pool.get().await.map_err(|e| e.to_string())?;
            client.batch_execute("BEGIN;
                INSERT INTO public.model_connections(id,deployment_id,tenant_id,owner_user_id,name,protocol,endpoint,model,enabled,revision,current_secret_id,created_at,updated_at)
                VALUES('00000000-0000-7000-8000-000000000003','catalog-deployment','catalog-tenant','dev-local-user','Canonical definition','openai_responses','https://model.example.test/v1/responses','canonical-model',true,13,'00000000-0000-7000-8000-000000000004',clock_timestamp(),clock_timestamp());
                INSERT INTO public.model_connection_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at)
                VALUES('00000000-0000-7000-8000-000000000004','00000000-0000-7000-8000-000000000003','catalog-deployment','catalog-tenant','dev-local-user','opaque-canonical-test-secret',clock_timestamp());
                COMMIT;").await.map_err(|e| e.to_string())?;
            drop(client);

            async fn own_page(router: axum::Router) -> Result<(), String> {
                let response = router.oneshot(http::Request::builder().uri(PATH).header("origin", ORIGIN).body(Body::empty()).unwrap()).await.map_err(|e| e.to_string())?;
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
                let bytes = to_bytes(response.into_body(), MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES).await.map_err(|e| e.to_string())?;
                let page: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                assert_eq!(page["models"].as_array().unwrap().len(), 1);
                assert_eq!(page["models"][0]["connectionId"], "00000000-0000-7000-8000-000000000003");
                assert_eq!(page["models"][0]["connectionRevision"], 13);
                assert_eq!(page["models"][0]["catalogRevision"], 1);
                assert_eq!(page["models"][0].as_object().unwrap().len(), 9);
                Ok(())
            }
            own_page(router.clone()).await?;
            let auth = resolver.resolve(&parts).await.map_err(|e| e.to_string())?;
            let target = RejectOtherTarget(AtomicUsize::new(0));
            assert!(matches!(auth.request_binding().ok_or("normal original binding missing")?
                .borrow_custom_model_catalog_host_before(&auth, &target, Instant::now() + std::time::Duration::from_secs(5)),
                Err(openbot_contracts::HostRequestBindingError::Unavailable)));
            assert_eq!(target.0.load(Ordering::SeqCst), 1, "original per-call probe did not reach enrolled target comparison");
            own_page(router.clone()).await?;
            fixture.pool.get().await.map_err(|e| e.to_string())?.execute("DELETE FROM public.user_roles WHERE user_id=$1 AND role='admin'", &[&SINGLE_USER_ACTOR_ID]).await.map_err(|e| e.to_string())?;
            assert!(matches!(application.execute(auth, AppCommand::ListCustomModelCatalog(CustomModelCatalogPageRequest { cursor: None })).await, Err(AppError::NotVisible)));
            fixture.pool.get().await.map_err(|e| e.to_string())?.execute("INSERT INTO public.user_roles(user_id,role) VALUES($1,'admin')", &[&SINGLE_USER_ACTOR_ID]).await.map_err(|e| e.to_string())?;
            own_page(router).await?;
            // Duplicate installation is refused at the end; no serving follows that failure.
            let duplicate_refused = resolver.install_custom_model_catalog_inventory(&original, &fixture.pool).is_err();
            resolver.close_request_bindings();
            assert!(duplicate_refused);
            Ok::<(), String>(())
        }.await;
        foreign_pool.close();
        outcome
    }).await;
}
