//! Current Desktop installation authority for Local OS confirmation; no provisioning or repair.

use async_trait::async_trait;
use openbot_contracts::{auth::AuthContext, error::AppError};

/// Host-owned read capability. A renderer cannot choose the installation or the database pool.
#[async_trait]
pub(crate) trait LocalConfirmationAuthority: Send + Sync {
    async fn verify_current(&self, expected: &AuthContext) -> Result<AuthContext, AppError>;
}

#[cfg(feature = "desktop-local-runtime")]
pub(crate) struct PostgresLocalConfirmationAuthority {
    installation: openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
    pool: openbot_infra::db::pool::DatabasePool,
    artifact_read_authority: std::sync::OnceLock<
        std::sync::Weak<openbot_infra::artifact_read_authority::PostgresArtifactReadAuthority>,
    >,
    custom_model_catalog_inventory: std::sync::OnceLock<
        std::sync::Weak<openbot_infra::custom_model_catalog::PostgresCustomModelCatalogInventory>,
    >,
    remember_preferences: std::sync::OnceLock<
        std::sync::Weak<openbot_infra::approval_preferences::PostgresRememberPreferenceRepository>,
    >,
    thread_history_authority: std::sync::OnceLock<
        std::sync::Weak<openbot_infra::thread_history_authority::PostgresThreadHistoryAuthority>,
    >,
}

#[cfg(feature = "desktop-local-runtime")]
impl PostgresLocalConfirmationAuthority {
    pub(crate) fn matches_runtime_scope(
        &self,
        pool: &openbot_infra::db::pool::DatabasePool,
        installation: &openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
    ) -> bool {
        std::ptr::eq(self.pool.manager(), pool.manager()) && &self.installation == installation
    }
    pub(crate) fn new(
        installation: openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
        pool: openbot_infra::db::pool::DatabasePool,
    ) -> Self {
        Self {
            installation,
            pool,
            artifact_read_authority: std::sync::OnceLock::new(),
            remember_preferences: std::sync::OnceLock::new(),
            thread_history_authority: std::sync::OnceLock::new(),
            custom_model_catalog_inventory: std::sync::OnceLock::new(),
        }
    }

    pub(crate) fn install_artifact_read_authority(
        &self,
        authority: &std::sync::Arc<
            openbot_infra::artifact_read_authority::PostgresArtifactReadAuthority,
        >,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        use openbot_contracts::HostRequestBindingError;
        let original = self.installation.auth_context();
        if !authority.matches_pool_scope(&self.pool, original.deployment(), original.tenant()) {
            return Err(HostRequestBindingError::Unavailable);
        }
        self.artifact_read_authority
            .set(std::sync::Arc::downgrade(authority))
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    pub(crate) fn install_custom_model_catalog_inventory(
        &self,
        repository: &std::sync::Arc<
            openbot_infra::custom_model_catalog::PostgresCustomModelCatalogInventory,
        >,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        let original = self.installation.auth_context();
        if self.custom_model_catalog_inventory.get().is_some()
            || !repository.matches_pool_scope(&self.pool, original.deployment(), original.tenant())
        {
            return Err(openbot_contracts::HostRequestBindingError::Unavailable);
        }
        self.custom_model_catalog_inventory
            .set(std::sync::Arc::downgrade(repository))
            .map_err(|_| openbot_contracts::HostRequestBindingError::Unavailable)
    }

    pub(crate) fn install_remember_preference_repository(
        &self,
        repository: &std::sync::Arc<
            openbot_infra::approval_preferences::PostgresRememberPreferenceRepository,
        >,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        let original = self.installation.auth_context();
        if !repository.matches_pool_scope(&self.pool, original.deployment(), original.tenant()) {
            return Err(openbot_contracts::HostRequestBindingError::Unavailable);
        }
        self.remember_preferences
            .set(std::sync::Arc::downgrade(repository))
            .map_err(|_| openbot_contracts::HostRequestBindingError::Unavailable)
    }
    pub(crate) fn install_thread_history_authority(
        &self,
        authority: &std::sync::Arc<
            openbot_infra::thread_history_authority::PostgresThreadHistoryAuthority,
        >,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        let original = self.installation.auth_context();
        if self.thread_history_authority.get().is_some()
            || !authority.matches_pool_scope(&self.pool, original.deployment(), original.tenant())
        {
            return Err(openbot_contracts::HostRequestBindingError::Unavailable);
        }
        self.thread_history_authority
            .set(std::sync::Arc::downgrade(authority))
            .map_err(|_| openbot_contracts::HostRequestBindingError::Unavailable)
    }

    pub(crate) fn enroll_custom_model_catalog_window_issuer(
        &self,
        issuer: &openbot_contracts::RequestBindingIssuer,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        let repository = self
            .custom_model_catalog_inventory
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(openbot_contracts::HostRequestBindingError::Unavailable)?;
        let original = self.installation.auth_context();
        if !repository.matches_pool_scope(&self.pool, original.deployment(), original.tenant())
            || !issuer.observation().is_current()
        {
            return Err(openbot_contracts::HostRequestBindingError::Unavailable);
        }
        repository.enroll_host_issuer(issuer)
    }

    pub(crate) fn enroll_remember_preference_window_issuer(
        &self,
        issuer: &openbot_contracts::RequestBindingIssuer,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        let repository = self
            .remember_preferences
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(openbot_contracts::HostRequestBindingError::Unavailable)?;
        let original = self.installation.auth_context();
        if !repository.matches_pool_scope(&self.pool, original.deployment(), original.tenant())
            || !issuer.observation().is_current()
        {
            return Err(openbot_contracts::HostRequestBindingError::Unavailable);
        }
        repository.enroll_host_issuer(issuer)
    }
    pub(crate) fn enroll_thread_history_window_issuer(
        &self,
        issuer: &openbot_contracts::RequestBindingIssuer,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        let authority = self
            .thread_history_authority
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(openbot_contracts::HostRequestBindingError::Unavailable)?;
        let original = self.installation.auth_context();
        if !authority.matches_pool_scope(&self.pool, original.deployment(), original.tenant())
            || !issuer.observation().is_current()
        {
            return Err(openbot_contracts::HostRequestBindingError::Unavailable);
        }
        authority.enroll_host_issuer(issuer)
    }

    pub(crate) fn artifact_read_lifecycle(
        &self,
    ) -> Option<std::sync::Arc<openbot_infra::artifact_read_lifecycle::ArtifactReadLifecycle>> {
        self.artifact_read_authority
            .get()
            .and_then(std::sync::Weak::upgrade)
            .map(|authority| authority.read_lifecycle())
    }

    // Request-binding observations have a stricter current-only contract than the established
    // OS-confirmation reader. Do not call its compatibility loader: NULL is not generation zero.
    async fn verify_binding_current(
        &self,
        expected: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        use openbot_contracts::HostRequestBindingError;
        use openbot_infra::auth::single_user::desktop_local::{
            DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL,
        };

        let installation = self.installation.auth_context();
        if !expected.is_single_user()
            || expected.deployment() != installation.deployment()
            || expected.tenant() != installation.tenant()
            || expected.actor().as_str() != DESKTOP_LOCAL_ACTOR_ID
            || expected.actor() != installation.actor()
            || expected.roles() != installation.roles()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .read_only(true)
            .start()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let observation = async {
            let remaining = deadline.checked_duration_since(std::time::Instant::now()).ok_or(HostRequestBindingError::Unavailable)?;
            let milliseconds = remaining.as_millis().min(5_000);
            if milliseconds == 0 { return Err(HostRequestBindingError::Unavailable); }
            transaction
                .batch_execute(&format!("SET LOCAL statement_timeout='{milliseconds}ms'; SET LOCAL lock_timeout='{milliseconds}ms'"))
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let row = transaction
                .query_opt(
                    LOCAL_BINDING_CURRENT_SQL,
                    &[&DESKTOP_LOCAL_ACTOR_ID, &DESKTOP_LOCAL_EMAIL],
                )
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            decode_binding_generation(row)
        }
        .await;
        // Both successful and failed observations wait for explicit rollback. Rollback failure
        // cannot certify current authority; an outer timeout likewise supplies no cleanup proof.
        transaction
            .rollback()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let generation = observation?;
        if generation != expected.auth_generation() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(())
    }
}

#[cfg(feature = "desktop-local-runtime")]
const LOCAL_BINDING_CURRENT_SQL: &str = "SELECT u.auth_generation AS generation,u.email=$2 AS canonical_email, \
    EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied, \
    ARRAY(SELECT ur.role::text FROM public.user_roles ur \
    WHERE ur.user_id=u.id ORDER BY ur.role::text) AS roles \
    FROM public.users u WHERE u.id=$1";

#[cfg(feature = "desktop-local-runtime")]
fn decode_binding_generation(
    row: Option<tokio_postgres::Row>,
) -> Result<openbot_contracts::auth::AuthGeneration, openbot_contracts::HostRequestBindingError> {
    use openbot_contracts::HostRequestBindingError;
    let row = row.ok_or(HostRequestBindingError::NotCurrent)?;
    let generation: Option<i64> = row
        .try_get("generation")
        .map_err(|_| HostRequestBindingError::Unavailable)?;
    let generation = generation
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(HostRequestBindingError::NotCurrent)?;
    let canonical_email: bool = row
        .try_get("canonical_email")
        .map_err(|_| HostRequestBindingError::Unavailable)?;
    let denied: bool = row
        .try_get("denied")
        .map_err(|_| HostRequestBindingError::Unavailable)?;
    let roles: Vec<String> = row
        .try_get("roles")
        .map_err(|_| HostRequestBindingError::Unavailable)?;
    if !canonical_email || denied || roles != ["admin"] {
        return Err(HostRequestBindingError::NotCurrent);
    }
    Ok(openbot_contracts::auth::AuthGeneration::new(generation))
}

#[cfg(feature = "desktop-local-runtime")]
#[async_trait]
impl LocalConfirmationAuthority for PostgresLocalConfirmationAuthority {
    async fn verify_current(&self, expected: &AuthContext) -> Result<AuthContext, AppError> {
        // This established resolver reads canonical user/generation/deny/sole-admin in one SQL
        // snapshot. It never initializes, repairs or advances authority in response to a request.
        let current = self
            .installation
            .load_runtime_auth_context(&self.pool)
            .await
            .map_err(|error| match error {
                openbot_infra::db::InfraError::RepositoryInvariant {
                    code: "canonical_principal_missing" | "canonical_principal_refused",
                } => AppError::Unauthenticated,
                _ => AppError::DependencyUnavailable {
                    dependency: "desktop_local_confirmation_authority",
                },
            })?;
        if !expected.is_single_user()
            || !current.is_single_user()
            || current.deployment() != expected.deployment()
            || current.tenant() != expected.tenant()
            || current.actor() != expected.actor()
            || current.auth_generation() != expected.auth_generation()
            || current.roles() != expected.roles()
        {
            return Err(AppError::Unauthenticated);
        }
        Ok(current)
    }
}

#[cfg(all(test, feature = "desktop-local-runtime"))]
#[path = "local_confirmation_authority_tests.rs"]
mod tests;

#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::HostRequestBindingGuard for PostgresLocalConfirmationAuthority {
    fn borrow_artifact_cleanup_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::ArtifactCleanupHostTarget,
        deadline: std::time::Instant,
    ) -> Result<
        openbot_contracts::request_binding::ArtifactCleanupHostObservation<'a>,
        openbot_contracts::HostRequestBindingError,
    > {
        use openbot_contracts::request_binding::{
            ArtifactCleanupHostObservation, HostRequestBindingError, HostRequestBindingKind,
        };
        let installation = self.installation.auth_context();
        if !auth.is_single_user()
            || auth.deployment() != installation.deployment()
            || auth.tenant() != installation.tenant()
            || auth.actor() != installation.actor()
            || auth.roles() != installation.roles()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let authority = self
            .artifact_read_authority
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !authority.matches_pool_scope(
            &self.pool,
            installation.deployment(),
            installation.tenant(),
        ) || !authority.matches_cleanup_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if binding.kind() != HostRequestBindingKind::DesktopWindow {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let factory = LocalArtifactCleanupTail {
            authority: std::sync::Arc::downgrade(&authority),
            pool: self.pool.clone(),
            installation: self.installation.clone(),
            original: auth.clone(),
        };
        openbot_contracts::request_binding::ArtifactCleanupHostTailWitness::verify_current(
            &factory, auth, deadline,
        )?;
        ArtifactCleanupHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(factory),
        )
    }
    fn borrow_custom_model_catalog_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::CustomModelCatalogHostTarget,
        deadline: std::time::Instant,
    ) -> Result<
        openbot_contracts::request_binding::CustomModelCatalogHostObservation<'a>,
        openbot_contracts::HostRequestBindingError,
    > {
        use openbot_contracts::request_binding::{
            CustomModelCatalogHostObservation, HostRequestBindingError, HostRequestBindingKind,
        };
        let installation = self.installation.auth_context();
        if !auth.is_single_user()
            || auth.deployment() != installation.deployment()
            || auth.tenant() != installation.tenant()
            || auth.actor() != installation.actor()
            || auth.roles() != installation.roles()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let repository = self
            .custom_model_catalog_inventory
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !repository.matches_pool_scope(
            &self.pool,
            installation.deployment(),
            installation.tenant(),
        ) || !repository.matches_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if binding.kind() != HostRequestBindingKind::DesktopWindow {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let factory = LocalCustomModelCatalogTail {
            repository: std::sync::Arc::downgrade(&repository),
            original: auth.clone(),
            observed_wall: std::time::SystemTime::now(),
            observed_monotonic: std::time::Instant::now(),
        };
        openbot_contracts::request_binding::CustomModelCatalogHostTailWitness::verify_current(
            &factory, auth, deadline,
        )?;
        CustomModelCatalogHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(factory),
        )
    }
    fn borrow_remember_preference_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::RememberPreferenceHostTarget,
        deadline: std::time::Instant,
    ) -> Result<
        openbot_contracts::request_binding::RememberPreferenceHostObservation<'a>,
        openbot_contracts::HostRequestBindingError,
    > {
        use openbot_contracts::request_binding::{
            HostRequestBindingError, HostRequestBindingKind, RememberPreferenceHostObservation,
        };
        let installation = self.installation.auth_context();
        if !auth.is_single_user()
            || auth.deployment() != installation.deployment()
            || auth.tenant() != installation.tenant()
            || auth.actor() != installation.actor()
            || auth.roles() != installation.roles()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let repository = self
            .remember_preferences
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !repository.matches_pool_scope(
            &self.pool,
            installation.deployment(),
            installation.tenant(),
        ) || !repository.matches_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if binding.kind() != HostRequestBindingKind::DesktopWindow {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let factory = LocalRememberPreferenceTail {
            repository: std::sync::Arc::downgrade(&repository),
            pool: self.pool.clone(),
            installation: self.installation.clone(),
            original: auth.clone(),
        };
        openbot_contracts::request_binding::RememberPreferenceHostTailWitness::verify_current(
            &factory, auth, deadline,
        )?;
        RememberPreferenceHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(factory),
        )
    }
    fn borrow_thread_history_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::ThreadHistoryHostTarget,
        deadline: std::time::Instant,
    ) -> Result<
        openbot_contracts::request_binding::ThreadHistoryHostObservation<'a>,
        openbot_contracts::HostRequestBindingError,
    > {
        use openbot_contracts::request_binding::{
            HostRequestBindingError, HostRequestBindingKind, ThreadHistoryHostObservation,
        };
        let installation = self.installation.auth_context();
        if !auth.is_single_user()
            || auth.deployment() != installation.deployment()
            || auth.tenant() != installation.tenant()
            || auth.actor() != installation.actor()
            || auth.roles() != installation.roles()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let authority = self
            .thread_history_authority
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !authority.matches_pool_scope(
            &self.pool,
            installation.deployment(),
            installation.tenant(),
        ) || !authority.matches_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if binding.kind() != HostRequestBindingKind::DesktopWindow {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let factory = LocalThreadHistoryTail {
            authority: std::sync::Arc::downgrade(&authority),
            pool: self.pool.clone(),
            installation: self.installation.clone(),
            original: auth.clone(),
        };
        openbot_contracts::request_binding::ThreadHistoryHostTailWitness::verify_current(
            &factory, auth, deadline,
        )?;
        ThreadHistoryHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(factory),
        )
    }
    fn verify_source_run_artifact_ids_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::SourceRunArtifactIdsCurrentTarget,
        deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::SourceRunArtifactIdsCurrentCheck<'a> {
        Box::pin(async move {
            use openbot_contracts::request_binding::{
                ArtifactReadCurrentError, HostRequestBindingError,
            };
            let authority = self
                .artifact_read_authority
                .get()
                .and_then(std::sync::Weak::upgrade)
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ))?;
            if deadline <= std::time::Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                authority.observe_source_run_ids_desktop_local(
                    auth,
                    target,
                    &self.installation,
                    deadline,
                ),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable))?
        })
    }

    fn verify_artifact_save_receipt_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::ArtifactSaveReceiptCurrentTarget,
        deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::ArtifactSaveReceiptCurrentCheck<'a> {
        Box::pin(async move {
            use openbot_contracts::request_binding::{
                ArtifactReadCurrentError, HostRequestBindingError,
            };
            let authority = self
                .artifact_read_authority
                .get()
                .and_then(std::sync::Weak::upgrade)
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ))?;
            if deadline <= std::time::Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                authority.observe_artifact_save_receipt_desktop_local(
                    auth,
                    target,
                    &self.installation,
                    deadline,
                ),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable))?
        })
    }

    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::ArtifactReadCurrentTarget,
        deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::ArtifactReadCurrentCheck<'a> {
        Box::pin(async move {
            use openbot_contracts::request_binding::{
                ArtifactReadCurrentError, HostRequestBindingError,
            };
            let authority = self
                .artifact_read_authority
                .get()
                .and_then(std::sync::Weak::upgrade)
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ))?;
            if deadline <= std::time::Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                authority.observe_desktop_local(auth, target, &self.installation, deadline),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable))?
        })
    }

    fn verify_current<'a>(
        &'a self,
        expected: &'a AuthContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), openbot_contracts::HostRequestBindingError>>
                + Send
                + 'a,
        >,
    > {
        self.verify_current_before(
            expected,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
    }

    fn verify_current_before<'a>(
        &'a self,
        expected: &'a AuthContext,
        deadline: std::time::Instant,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), openbot_contracts::HostRequestBindingError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if deadline <= std::time::Instant::now() {
                return Err(openbot_contracts::HostRequestBindingError::Unavailable);
            }
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.verify_binding_current(expected, deadline),
            )
            .await
            .unwrap_or(Err(openbot_contracts::HostRequestBindingError::Unavailable))
        })
    }
}

#[cfg(feature = "desktop-local-runtime")]
#[derive(Clone)]
struct LocalCustomModelCatalogTail {
    repository:
        std::sync::Weak<openbot_infra::custom_model_catalog::PostgresCustomModelCatalogInventory>,
    original: AuthContext,
    observed_wall: std::time::SystemTime,
    observed_monotonic: std::time::Instant,
}
#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::request_binding::CustomModelCatalogHostTailFactory
    for LocalCustomModelCatalogTail
{
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<openbot_contracts::request_binding::CustomModelCatalogSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<
        Box<dyn openbot_contracts::request_binding::CustomModelCatalogHostTailWitness>,
        openbot_contracts::HostRequestBindingError,
    > {
        if session.is_some() {
            return Err(openbot_contracts::HostRequestBindingError::NotCurrent);
        }
        openbot_contracts::request_binding::CustomModelCatalogHostTailWitness::verify_current(
            self, auth, deadline,
        )?;
        Ok(Box::new(self.clone()))
    }
}
#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::request_binding::CustomModelCatalogHostTailWitness
    for LocalCustomModelCatalogTail
{
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        use openbot_contracts::request_binding::{HostRequestBindingError, HostRequestBindingKind};
        if std::time::SystemTime::now() < self.observed_wall
            || std::time::Instant::now() < self.observed_monotonic
            || auth != &self.original
            || !self
                .original
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(a, b)| {
                    a.identity().same_binding(b.identity())
                        && b.kind() == HostRequestBindingKind::DesktopWindow
                })
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        // The actual immutable source Pool/scope and original repository attachment were
        // checked when borrowing. This tail does not acquire another Pool or source lease.
        if self.repository.upgrade().is_none() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(())
    }
}

#[cfg(feature = "desktop-local-runtime")]
#[derive(Clone)]
struct LocalRememberPreferenceTail {
    repository:
        std::sync::Weak<openbot_infra::approval_preferences::PostgresRememberPreferenceRepository>,
    pool: openbot_infra::db::pool::DatabasePool,
    installation: openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
    original: AuthContext,
}

#[cfg(feature = "desktop-local-runtime")]
#[derive(Clone)]
struct LocalThreadHistoryTail {
    authority:
        std::sync::Weak<openbot_infra::thread_history_authority::PostgresThreadHistoryAuthority>,
    pool: openbot_infra::db::pool::DatabasePool,
    installation: openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
    original: AuthContext,
}
#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::request_binding::RememberPreferenceHostTailFactory
    for LocalRememberPreferenceTail
{
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<openbot_contracts::request_binding::RememberPreferenceSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<
        Box<dyn openbot_contracts::request_binding::RememberPreferenceHostTailWitness>,
        openbot_contracts::HostRequestBindingError,
    > {
        if session.is_some() {
            return Err(openbot_contracts::HostRequestBindingError::NotCurrent);
        }
        openbot_contracts::request_binding::RememberPreferenceHostTailWitness::verify_current(
            self, auth, deadline,
        )?;
        Ok(Box::new(self.clone()))
    }
}

#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::request_binding::ThreadHistoryHostTailFactory for LocalThreadHistoryTail {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<openbot_contracts::request_binding::ThreadHistorySessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<
        Box<dyn openbot_contracts::request_binding::ThreadHistoryHostTailWitness>,
        openbot_contracts::HostRequestBindingError,
    > {
        if session.is_some() {
            return Err(openbot_contracts::HostRequestBindingError::NotCurrent);
        }
        openbot_contracts::request_binding::ThreadHistoryHostTailWitness::verify_current(
            self, auth, deadline,
        )?;
        Ok(Box::new(self.clone()))
    }
}
#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::request_binding::RememberPreferenceHostTailWitness
    for LocalRememberPreferenceTail
{
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        use openbot_contracts::request_binding::{HostRequestBindingError, HostRequestBindingKind};
        if auth != &self.original
            || !self
                .original
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(a, b)| {
                    a.identity().same_binding(b.identity())
                        && b.kind() == HostRequestBindingKind::DesktopWindow
                })
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        let repository = self
            .repository
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let installation = self.installation.auth_context();
        if !repository.matches_pool_scope(
            &self.pool,
            installation.deployment(),
            installation.tenant(),
        ) {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(())
    }
}

#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::request_binding::ThreadHistoryHostTailWitness for LocalThreadHistoryTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        use openbot_contracts::request_binding::{HostRequestBindingError, HostRequestBindingKind};
        if auth != &self.original
            || !self
                .original
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(a, b)| {
                    a.identity().same_binding(b.identity())
                        && b.kind() == HostRequestBindingKind::DesktopWindow
                })
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        let authority = self
            .authority
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let installation = self.installation.auth_context();
        if !authority.matches_pool_scope(
            &self.pool,
            installation.deployment(),
            installation.tenant(),
        ) {
            return Err(HostRequestBindingError::Unavailable);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(())
    }
}

#[cfg(feature = "desktop-local-runtime")]
#[derive(Clone)]
struct LocalArtifactCleanupTail {
    authority:
        std::sync::Weak<openbot_infra::artifact_read_authority::PostgresArtifactReadAuthority>,
    pool: openbot_infra::db::pool::DatabasePool,
    installation: openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
    original: AuthContext,
}
#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::request_binding::ArtifactCleanupHostTailFactory
    for LocalArtifactCleanupTail
{
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<openbot_contracts::request_binding::ArtifactCleanupSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<
        Box<dyn openbot_contracts::request_binding::ArtifactCleanupHostTailWitness>,
        openbot_contracts::HostRequestBindingError,
    > {
        if session.is_some() {
            return Err(openbot_contracts::HostRequestBindingError::NotCurrent);
        }
        openbot_contracts::request_binding::ArtifactCleanupHostTailWitness::verify_current(
            self, auth, deadline,
        )?;
        Ok(Box::new(self.clone()))
    }
}
#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::request_binding::ArtifactCleanupHostTailWitness
    for LocalArtifactCleanupTail
{
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        use openbot_contracts::request_binding::{HostRequestBindingError, HostRequestBindingKind};
        if auth != &self.original
            || !self
                .original
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(a, b)| {
                    a.identity().same_binding(b.identity())
                        && b.kind() == HostRequestBindingKind::DesktopWindow
                })
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        let authority = self
            .authority
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let installation = self.installation.auth_context();
        if !authority.matches_pool_scope(
            &self.pool,
            installation.deployment(),
            installation.tenant(),
        ) {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(())
    }
}
