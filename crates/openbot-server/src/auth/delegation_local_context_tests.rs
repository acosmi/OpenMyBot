use super::*;
mod harness {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}
use harness::{admin_config, with_temp_database};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::single_user::{initialize_single_user, load_single_user_principal};
use openbot_infra::db::{baseline, native, pool};

async fn check(closed: bool) {
    let admin = admin_config("delegation_local_context");
    with_temp_database(
        &admin,
        if closed {
            "delegationlocalclosed"
        } else {
            "delegationlocalequal"
        },
        |config| async move {
            let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let result = async {
                let mut client = pool.get().await.map_err(|e| e.to_string())?;
                baseline::apply(&client).await.map_err(|e| e.to_string())?;
                native::apply(&mut client)
                    .await
                    .map_err(|e| e.to_string())?;
                drop(client);
                initialize_single_user(&pool, true)
                    .await
                    .map_err(|e| e.to_string())?;
                let principal = load_single_user_principal(
                    &pool,
                    DeploymentId::new("local-context-deployment"),
                    TenantId::new("local-context-tenant"),
                )
                .await
                .map_err(|e| e.to_string())?;
                let resolver = SingleUserAuthResolver::from_verified_principal(
                    principal,
                    default_session_lifetime(),
                );
                let local = resolver.local_context().map_err(|e| e.to_string())?;
                assert!(local.request_binding().is_some());
                assert!(local.delegation().is_none());
                let (parts, _) = http::Request::new(()).into_parts();
                let resolved = resolver.resolve(&parts).await.map_err(|e| e.to_string())?;
                assert_eq!(local, resolved);
                assert_eq!(local.roles(), resolved.roles());
                assert_eq!(local.auth_generation(), resolved.auth_generation());
                assert!(resolved.request_binding().is_some());
                if closed {
                    resolver.close_request_bindings();
                    assert!(matches!(
                        resolver.local_context(),
                        Err(AppError::Unauthenticated)
                    ));
                    assert!(matches!(
                        resolver.resolve(&parts).await,
                        Err(AppError::Unauthenticated)
                    ));
                }
                Ok(())
            }
            .await;
            pool.close();
            result
        },
    )
    .await;
}
#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn local_context_matches_resolve_and_keeps_binding() {
    check(false).await;
}
#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn closed_binding_refuses_local_context() {
    check(true).await;
}
