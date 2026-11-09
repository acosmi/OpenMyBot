use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use acosmi::{
    AuthorityResult, AuthorityState, HttpTransport, StrictTokenAuthority, TokenAuthorityError,
};
use async_trait::async_trait;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::vault::SecretBytes;
use tokio::time::Instant;
use uuid::Uuid;

use crate::gateway_account::{GatewayAccountClient, GatewayAccountError};

use super::store::{self, DetachedSession};
use super::{GatewayAuthorityError, Scope};

pub(super) struct ActiveSession {
    pub(super) session: Arc<DetachedSession>,
    pub(super) operation_id: Option<Uuid>,
}

struct ActiveState {
    token: Uuid,
    session: Arc<DetachedSession>,
    operation_id: Option<Uuid>,
    token_admitted: bool,
}

pub(super) struct AuthorityInner {
    pub(super) pool: crate::db::pool::DatabasePool,
    pub(super) vault: crate::vault::CredentialRecordVault,
    pub(super) audit_key: SecretBytes,
    pub(super) scope: Scope,
    acquiring: AtomicBool,
    active: Mutex<Option<ActiveState>>,
    transport: OnceLock<Weak<dyn HttpTransport>>,
    self_ref: OnceLock<Weak<AuthorityInner>>,
    pub(super) recovery_gate: crate::recovery_control::RecoveryReadGate,
}

impl AuthorityInner {
    pub(super) fn new(
        pool: crate::db::pool::DatabasePool,
        vault: crate::vault::CredentialRecordVault,
        audit_key: SecretBytes,
        scope: Scope,
        recovery_gate: crate::recovery_control::RecoveryReadGate,
    ) -> Arc<Self> {
        let inner = Arc::new(Self {
            pool,
            vault,
            audit_key,
            scope,
            acquiring: AtomicBool::new(false),
            active: Mutex::new(None),
            transport: OnceLock::new(),
            self_ref: OnceLock::new(),
            recovery_gate,
        });
        let _ = inner.self_ref.set(Arc::downgrade(&inner));
        inner
    }

    pub(super) fn set_transport(
        &self,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<(), GatewayAuthorityError> {
        self.transport
            .set(Arc::downgrade(&transport))
            .map_err(|_| GatewayAuthorityError::Conflict)
    }

    pub(super) fn active_session(&self) -> Option<ActiveSession> {
        self.active.lock().ok().and_then(|state| {
            state.as_ref().map(|active| ActiveSession {
                session: Arc::clone(&active.session),
                operation_id: active.operation_id,
            })
        })
    }

    pub(super) fn mark_token_admitted(
        &self,
        operation_id: Uuid,
    ) -> Result<(), GatewayAuthorityError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| GatewayAuthorityError::Unavailable)?;
        let state = active
            .as_mut()
            .ok_or(GatewayAuthorityError::ReconciliationRequired)?;
        if state.operation_id != Some(operation_id) || state.token_admitted {
            return Err(GatewayAuthorityError::ReconciliationRequired);
        }
        state.token_admitted = true;
        Ok(())
    }

    fn active(&self) -> Result<ActiveSession, GatewayAuthorityError> {
        self.active_session()
            .ok_or(GatewayAuthorityError::ReconciliationRequired)
    }

    fn set_operation(&self, operation_id: Uuid) -> Result<(), GatewayAuthorityError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| GatewayAuthorityError::Unavailable)?;
        let state = active
            .as_mut()
            .ok_or(GatewayAuthorityError::ReconciliationRequired)?;
        if state.operation_id.is_some() && state.operation_id != Some(operation_id) {
            return Err(GatewayAuthorityError::Conflict);
        }
        state.operation_id = Some(operation_id);
        Ok(())
    }

    fn admitted(&self, operation_id: Uuid) -> Result<(), GatewayAuthorityError> {
        let active = self
            .active
            .lock()
            .map_err(|_| GatewayAuthorityError::Unavailable)?;
        let state = active
            .as_ref()
            .ok_or(GatewayAuthorityError::ReconciliationRequired)?;
        if state.operation_id != Some(operation_id) || !state.token_admitted {
            return Err(GatewayAuthorityError::ReconciliationRequired);
        }
        Ok(())
    }

    /// One worker admission under this operation's original deadline, held by
    /// the caller through its Vault-open or write (the borrow verifies it once).
    pub(super) async fn admission(
        &self,
    ) -> Result<crate::recovery_control::RecoveryWorkerLease<'static>, GatewayAuthorityError> {
        self.recovery_gate
            .borrow_worker_before(self.scope.deadline.into_std())
            .await
            .map_err(|_| GatewayAuthorityError::Unavailable)
    }

    async fn load_inner(&self) -> Result<AuthorityState, GatewayAuthorityError> {
        enum LoadedState {
            Ready(store::SensitiveTokens),
            Public(AuthorityState),
        }

        let active = self.active()?;
        let admission = self.admission().await?;
        active
            .session
            .begin(&self.scope.cancel, self.scope.deadline)
            .await?;
        let result = async {
            let connection = store::load_connection(&active.session, &self.scope, false).await?;
            match connection.state.as_str() {
                "ready" => {
                    let secret_id = connection
                        .current_secret_id
                        .ok_or(GatewayAuthorityError::Corrupt)?;
                    if connection.pending_operation_id.is_some() {
                        return Err(GatewayAuthorityError::Corrupt);
                    }
                    {
                        let client = active
                            .session
                            .lock_client(&self.scope.cancel, self.scope.deadline)
                            .await?;
                        let client = client.as_ref().ok_or(GatewayAuthorityError::Unavailable)?;
                        let source_ref = self.scope.connection_id.to_string();
                        tokio::select! {
                            biased;
                            () = self.scope.cancel.cancelled() => {
                                return Err(GatewayAuthorityError::Cancelled);
                            }
                            result = crate::restore_reconfirmation::require_confirmed_before(
                                &**client,
                                crate::restore_reconfirmation::RequirementSource {
                                    cohort: admission.restore_cohort(),
                                    kind: crate::restore_reconfirmation::RequirementKind::SdkSecret,
                                    source_ref: &source_ref,
                                },
                                self.scope.deadline.into_std(),
                            ) => result.map_err(|error| match error {
                                crate::restore_reconfirmation::RestoreReconfirmationError::NotConfirmed => {
                                    GatewayAuthorityError::ReconciliationRequired
                                }
                                _ => GatewayAuthorityError::Unavailable,
                            })?,
                        }
                    }
                    let encrypted = store::load_secret(
                        &active.session,
                        &self.scope,
                        secret_id,
                        connection.credential_generation,
                    )
                    .await?;
                    admission
                        .verify_current_before(self.scope.deadline.into_std())
                        .map_err(|_| GatewayAuthorityError::Unavailable)?;
                    let tokens = store::open_tokens(
                        &self.vault,
                        secret_id,
                        &encrypted,
                        &self.scope,
                        connection.credential_generation,
                    )?;
                    Ok(LoadedState::Ready(tokens))
                }
                "missing" => {
                    if connection.current_secret_id.is_some()
                        || connection.pending_operation_id.is_some()
                    {
                        return Err(GatewayAuthorityError::Corrupt);
                    }
                    Ok(LoadedState::Public(AuthorityState::Missing))
                }
                "rotation_pending" => {
                    let operation_id = connection
                        .pending_operation_id
                        .ok_or(GatewayAuthorityError::Corrupt)?;
                    let operation =
                        store::load_operation(&active.session, &self.scope, operation_id, false)
                            .await?;
                    if !matches!(operation.state.as_str(), "pending" | "staged") {
                        return Err(GatewayAuthorityError::Corrupt);
                    }
                    self.set_operation(operation_id)?;
                    Ok(LoadedState::Public(AuthorityState::RotationPending))
                }
                "auth_required" => Err(GatewayAuthorityError::ReconciliationRequired),
                _ => Err(GatewayAuthorityError::Corrupt),
            }
        }
        .await;
        let rollback = active
            .session
            .rollback(&self.scope.cancel, self.scope.deadline)
            .await;
        match (result, rollback) {
            (Ok(LoadedState::Ready(tokens)), Ok(())) => {
                Ok(AuthorityState::Ready(tokens.clone_plain()))
            }
            (Ok(LoadedState::Public(value)), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            _ => Err(GatewayAuthorityError::ReconciliationRequired),
        }
    }

    async fn commit_inner(&self, tokens: &acosmi::TokenSet) -> Result<(), GatewayAuthorityError> {
        let active = self.active()?;
        let operation_id = active
            .operation_id
            .ok_or(GatewayAuthorityError::ReconciliationRequired)?;
        self.admitted(operation_id)?;
        store::validate_token(tokens, &self.scope, 1)?;
        let transport = self
            .transport
            .get()
            .and_then(Weak::upgrade)
            .ok_or(GatewayAuthorityError::Unavailable)?;
        let account =
            GatewayAccountClient::new(&self.scope.issuer, transport).map_err(map_account)?;
        let metadata = account
            .fetch_metadata(self.scope.cancel.clone())
            .await
            .map_err(map_account)?;
        let identity = account
            .fetch_profile(
                &metadata,
                &SecretBytes::new(tokens.access_token.as_bytes().to_vec()),
                self.scope.cancel.clone(),
            )
            .await
            .map_err(map_account)?;
        if identity.issuer() != self.scope.issuer
            || identity.account_id() != self.scope.account_id
            || identity.organization_id() != self.scope.organization_id.as_deref()
            || tokens.client_id != self.scope.client_id
        {
            return Err(GatewayAuthorityError::Conflict);
        }
        let (secret_id, generation) = store::stage_rotation(
            &active.session,
            &self.vault,
            &self.scope,
            operation_id,
            tokens,
            self.audit_key.expose(),
        )
        .await?;
        store::finalize_rotation(
            &active.session,
            &self.scope,
            operation_id,
            secret_id,
            generation,
            self.audit_key.expose(),
        )
        .await?;
        let state = self.load_inner().await?;
        match state {
            AuthorityState::Ready(confirmed) => {
                let confirmed = store::SensitiveTokens::new(confirmed);
                if store::token_bytes_equal(&confirmed, tokens) {
                    Ok(())
                } else {
                    Err(GatewayAuthorityError::ReconciliationRequired)
                }
            }
            _ => Err(GatewayAuthorityError::ReconciliationRequired),
        }
    }
}

struct StrictGuard {
    inner: Arc<AuthorityInner>,
    token: Uuid,
    session: Arc<DetachedSession>,
}

struct LockClaim<'a>(&'a AtomicBool);

impl Drop for LockClaim<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Drop for StrictGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.inner.active.lock()
            && active
                .as_ref()
                .is_some_and(|state| state.token == self.token)
        {
            active.take();
        }
        self.session.schedule_close();
    }
}

fn advisory_key(connection: Uuid) -> i64 {
    let mut bytes = b"wrokbot-sdk-token-lock-v1".to_vec();
    bytes.extend_from_slice(connection.as_bytes());
    let digest = Sha256Digest::of(&bytes);
    i64::from_be_bytes(
        digest.as_bytes()[..8]
            .try_into()
            .expect("eight digest bytes"),
    )
}

fn map(error: GatewayAuthorityError) -> TokenAuthorityError {
    match error {
        GatewayAuthorityError::ReconciliationRequired
        | GatewayAuthorityError::CommitUnknown
        | GatewayAuthorityError::Conflict
        | GatewayAuthorityError::AccountProtocol
        | GatewayAuthorityError::NotVisible => TokenAuthorityError::ReconciliationRequired,
        GatewayAuthorityError::Corrupt => TokenAuthorityError::CommitUnverified,
        _ => TokenAuthorityError::Unavailable,
    }
}

fn map_account(error: GatewayAccountError) -> GatewayAuthorityError {
    match error {
        GatewayAccountError::Cancelled => GatewayAuthorityError::Cancelled,
        GatewayAccountError::Timeout => GatewayAuthorityError::Timeout,
        _ => GatewayAuthorityError::AccountProtocol,
    }
}

#[async_trait]
impl StrictTokenAuthority for AuthorityInner {
    async fn lock(&self) -> AuthorityResult<Box<dyn Send>> {
        if self.scope.cancel.is_cancelled() || Instant::now() >= self.scope.deadline {
            return Err(TokenAuthorityError::Unavailable);
        }
        self.acquiring
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| TokenAuthorityError::Unavailable)?;
        let _claim = LockClaim(&self.acquiring);
        if self
            .active
            .lock()
            .map_err(|_| TokenAuthorityError::Unavailable)?
            .is_some()
        {
            return Err(TokenAuthorityError::Unavailable);
        }
        let inner = self
            .self_ref
            .get()
            .and_then(Weak::upgrade)
            .ok_or(TokenAuthorityError::Unavailable)?;
        let session = DetachedSession::acquire(&self.pool, &self.scope.cancel, self.scope.deadline)
            .await
            .map_err(map)?;
        session
            .advisory_lock(
                advisory_key(self.scope.connection_id),
                &self.scope.cancel,
                self.scope.deadline,
            )
            .await
            .map_err(map)?;
        session
            .begin(&self.scope.cancel, self.scope.deadline)
            .await
            .map_err(map)?;
        store::load_connection(&session, &self.scope, false)
            .await
            .map_err(map)?;
        session
            .rollback(&self.scope.cancel, self.scope.deadline)
            .await
            .map_err(map)?;
        let token = Uuid::now_v7();
        *self
            .active
            .lock()
            .map_err(|_| TokenAuthorityError::Unavailable)? = Some(ActiveState {
            token,
            session: Arc::clone(&session),
            operation_id: None,
            token_admitted: false,
        });
        Ok(Box::new(StrictGuard {
            inner,
            token,
            session,
        }))
    }

    async fn load(&self) -> AuthorityResult<AuthorityState> {
        self.load_inner().await.map_err(map)
    }

    async fn begin_rotation(&self) -> AuthorityResult<()> {
        let active = self.active().map_err(map)?;
        if active.operation_id.is_some() {
            return Err(TokenAuthorityError::RotationPending);
        }
        let _admission = self.admission().await.map_err(map)?;
        let operation =
            store::begin_rotation(&active.session, &self.scope, self.audit_key.expose())
                .await
                .map_err(map)?;
        self.set_operation(operation.id).map_err(map)
    }

    async fn commit_rotation(&self, tokens: &acosmi::TokenSet) -> AuthorityResult<()> {
        let _admission = self.admission().await.map_err(map)?;
        self.commit_inner(tokens).await.map_err(map)
    }

    async fn clear(&self) -> AuthorityResult<()> {
        let active = self.active().map_err(map)?;
        let _admission = self.admission().await.map_err(map)?;
        store::clear_credentials(&active.session, &self.scope, self.audit_key.expose())
            .await
            .map_err(map)
    }
}

#[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
mod tests {
    use super::*;
    use crate::recovery_control::tests::restore_current::RestoreCurrentFixture;
    use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_domain::vault::{KeyVersion, WrappingKey};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    /// T046-32 on a published RestoreCurrent: the strict authority's worker
    /// lease carries the restored cohort, so a READY connection whose
    /// `sdk_secret` requirement has no receipt is not loaded or opened.
    #[tokio::test]
    #[ignore = "requires OPENBOT_TEST_PG_BIN PostgreSQL 17.11 for an owned candidate"]
    async fn t046_32_unconfirmed_sdk_secret_is_not_loaded() {
        let restored = RestoreCurrentFixture::publish("").await;
        let (dep, ten) = (DeploymentId::new("dep"), TenantId::new("ten"));
        let scope = Scope {
            auth: AuthContextBuilder::from_verified_session(dep.clone(), ten.clone(), ActorId::new("alice"), AuthGeneration::new(7), false)
                .with_role(Role::User)
                .build(),
            deployment: dep,
            tenant: ten.clone(),
            connection_id: Uuid::now_v7(),
            expected_revision: 1,
            auth_generation: 7,
            issuer: "https://restored.example.test".into(),
            client_id: "restored-client".into(),
            account_id: "restored-account".into(),
            organization_id: None,
            cancel: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(60),
        };
        let vault = crate::vault::CredentialRecordVault::single_key(ten, KeyVersion::new(1), WrappingKey::from_bytes(vec![0x46; 32]).unwrap());
        let secret = Uuid::now_v7();
        let tokens = acosmi::TokenSet {
            access_token: "restored-access-token".into(),
            refresh_token: "restored-refresh-token".into(),
            expires_at: "2035-01-01T00:00:00Z".into(),
            scope: "ai account".into(),
            client_id: "restored-client".into(),
            server_url: "https://restored.example.test".into(),
        };
        let sealed = super::super::store::seal_tokens(&vault, secret, &scope, 1, &tokens).unwrap();
        let mut client = restored.pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        tx.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','restored-alice@example.test',7);
            INSERT INTO public.user_roles(user_id,role) VALUES('alice','user');").await.unwrap();
        tx.execute("INSERT INTO public.sdk_gateway_connections(id,deployment_id,tenant_id,owner_user_id,name,issuer,client_id,account_id,organization_id,
              auth_contract_version,error_contract_version,enabled,revision,credential_generation,auth_generation,state,current_secret_id,pending_operation_id,created_at,updated_at)
            VALUES($1,'dep','ten','alice','Restored SDK',$2,$3,$4,NULL,2,1,true,1,1,7,'ready',$5,NULL,clock_timestamp(),clock_timestamp())",
            &[&scope.connection_id, &scope.issuer, &scope.client_id, &scope.account_id, &secret]).await.unwrap();
        tx.execute("INSERT INTO public.sdk_gateway_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation,encrypted_value,created_at)
            VALUES($1,$2,'dep','ten','alice',1,$3,clock_timestamp())", &[&secret, &scope.connection_id, &sealed]).await.unwrap();
        tx.commit().await.unwrap();
        drop(client);
        let requirement = crate::restore_reconfirmation::tests::bound_requirement(&restored, "sdk_secret", &scope.connection_id.to_string()).await;
        let inner = AuthorityInner::new(restored.pool.clone(), vault.clone(), SecretBytes::new(vec![0x55; 32]), scope, restored.read_gate());
        let _guard = inner.lock().await.unwrap();

        assert!(matches!(inner.load_inner().await, Err(GatewayAuthorityError::ReconciliationRequired)), "unconfirmed sdk secret");
        assert_eq!(vault.open_calls(), 0, "Vault-open before the receipt");

        // Positive control: one receipt for the same requirement loads READY.
        restored.confirm(requirement, "alice", "fresh_actor").await;
        assert!(matches!(inner.load_inner().await, Ok(AuthorityState::Ready(_))));
        assert_eq!(vault.open_calls(), 1);
    }
}
