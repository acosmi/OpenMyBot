//! Actual disposable PG composition checks. These are provenance checks, not live host acceptance.
#![cfg(all(unix, feature = "server-runtime"))]

mod harness;

use std::fs::{self, File};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::sync::Arc;

use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::db::{baseline, native, pool};
use uuid::Uuid;

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "openbot-current-read-composition-{}",
            Uuid::now_v7()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        Ok(Self(path))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = fs::remove_dir_all(&self.0).is_ok();
        let absent = !self.0.exists();
        eprintln!("ARTIFACT_CURRENT_COMPOSITION_ROOT_CLEANUP removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(removed && absent, "owned composition root cleanup failed");
        }
    }
}
async fn actual_pool(config: &pool::DatabaseConfig) -> Result<pool::DatabasePool, String> {
    let pool = pool::connect(config)
        .await
        .map_err(|error| error.to_string())?;
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    drop(client);
    Ok(pool)
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pool_enrollment_rejects_foreign_manager_and_scope() {
    harness::with_temp_database(
        &harness::admin_config("arc_enrollment"),
        "arc_enrollment",
        |config| async move {
            let pool = actual_pool(&config).await?;
            let deployment = DeploymentId::new("current-read-enrollment-deployment");
            let tenant = TenantId::new("current-read-enrollment-tenant");
            let registry = Arc::new(
                ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                    .await
                    .map_err(|error| error.to_string())?,
            );
            let root = OwnedRoot::new()?;
            let policy = ArtifactQuotaPolicy::default();
            let store = Arc::new(
                DatasetBoundArtifactStore::bind_host_root(
                    File::open(&root.0).map_err(|error| error.to_string())?,
                    registry.clone(),
                    policy,
                )
                .await
                .map_err(|error| error.to_string())?,
            );
            let administration = Arc::new(
                PostgresArtifactAdministration::new(
                    registry,
                    store,
                    policy,
                    SecretBytes::new(vec![0x81; 32]),
                    openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                        &pool,
                        &deployment,
                        &tenant,
                    ),
                )
                .map_err(|error| error.to_string())?,
            );
            let authority = administration.read_authority();
            assert!(Arc::ptr_eq(&authority, &administration.read_authority()));
            assert!(authority.matches_pool_scope(&pool.clone(), &deployment, &tenant));
            let foreign = pool::connect(&config)
                .await
                .map_err(|error| error.to_string())?;
            assert!(!authority.matches_pool_scope(&foreign, &deployment, &tenant));
            assert!(!authority.matches_pool_scope(&pool, &DeploymentId::new("foreign"), &tenant));
            assert!(!authority.matches_pool_scope(&pool, &deployment, &TenantId::new("foreign")));
            drop(administration);
            assert!(!authority.matches_pool_scope(&pool, &deployment, &tenant));
            foreign.close();
            pool.close();
            drop(root);
            Ok(())
        },
    )
    .await;
}
