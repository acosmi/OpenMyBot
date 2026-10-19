//! PostgreSQL/Vault authority for one actor-owned SDK Gateway connection.
//!
//! This module is an Infra-only assembly boundary. Its values are not renderer DTOs and neither
//! enrollment nor an SDK token grants Wrok authorization by itself.

mod enrollment;
pub(crate) use enrollment::EnrollmentAdoption;
mod fence;
mod store;
mod strict;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use acosmi::{HttpTransport, StrictTokenAuthority};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::vault::SecretBytes;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::gateway_account::{GatewayAccountClient, GatewayAccountError};
use crate::gateway_transport::{
    GatewayHttpOutcomes, GatewayModelWire, GatewayOAuthEndpoints, GatewayOAuthProfile,
    GatewayTransportFactory, GatewayTransportLimits, VerifiedGatewayEndpoints,
};
use crate::net::safe_http::SafeDialer;
use crate::vault::CredentialRecordVault;

use fence::EnrollmentFence;
pub(crate) use fence::{
    EnrollmentFenceControl, EnrollmentFenceEnd, EnrollmentPermitControl, EnrollmentRequestKind,
    enrollment_headers_channel,
};
use store::DetachedSession;
use strict::AuthorityInner;

const OPERATION_MAX: Duration = Duration::from_secs(60);

/// Closed, payload-free failures for the SDK Gateway authority boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GatewayAuthorityError {
    #[error("gateway_authority_invalid_input")]
    InvalidInput,
    #[error("gateway_authority_not_visible")]
    NotVisible,
    #[error("gateway_authority_conflict")]
    Conflict,
    #[error("gateway_authority_unavailable")]
    Unavailable,
    #[error("gateway_authority_cancelled")]
    Cancelled,
    #[error("gateway_authority_timeout")]
    Timeout,
    #[error("gateway_authority_commit_unknown")]
    CommitUnknown,
    #[error("gateway_authority_reconciliation_required")]
    ReconciliationRequired,
    #[error("gateway_authority_corrupt")]
    Corrupt,
    #[error("gateway_authority_account_protocol")]
    AccountProtocol,
}

#[derive(Clone)]
pub(super) struct Scope {
    auth: AuthContext,
    deployment: DeploymentId,
    tenant: TenantId,
    connection_id: Uuid,
    expected_revision: i64,
    auth_generation: i64,
    issuer: String,
    client_id: String,
    account_id: String,
    organization_id: Option<String>,
    cancel: CancellationToken,
    deadline: Instant,
}

/// Host-minted enrollment identity. It is neither Clone nor serializable.
pub struct GatewayEnrollment {
    auth: AuthContext,
    id: Uuid,
    name: String,
    issuer: String,
    client_id: String,
}

impl GatewayEnrollment {
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }
}

impl fmt::Debug for GatewayEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayEnrollment([redacted])")
    }
}

/// Confirmed connection creation receipt without credential material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayConnectionReceipt {
    id: Uuid,
    revision: i64,
    credential_generation: i64,
}

impl GatewayConnectionReceipt {
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }
    #[must_use]
    pub const fn revision(&self) -> i64 {
        self.revision
    }
    #[must_use]
    pub const fn credential_generation(&self) -> i64 {
        self.credential_generation
    }
}

/// One operation-private SDK authority and its sole reviewed transport.
pub struct GatewayOperation {
    authority: Arc<dyn StrictTokenAuthority>,
    transport: Arc<dyn HttpTransport>,
}

impl GatewayOperation {
    #[must_use]
    pub fn authority(&self) -> Arc<dyn StrictTokenAuthority> {
        Arc::clone(&self.authority)
    }
    #[must_use]
    pub fn transport(&self) -> Arc<dyn HttpTransport> {
        Arc::clone(&self.transport)
    }
}

impl fmt::Debug for GatewayOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayOperation([redacted])")
    }
}

/// Trusted host composition for SDK Gateway account persistence.
pub struct PostgresGatewayAccounts {
    pool: crate::db::pool::DatabasePool,
    vault: CredentialRecordVault,
    deployment: DeploymentId,
    tenant: TenantId,
    audit_key: SecretBytes,
    dialer: SafeDialer,
    origin: String,
}

impl PostgresGatewayAccounts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        vault: CredentialRecordVault,
        deployment: DeploymentId,
        tenant: TenantId,
        audit_key: SecretBytes,
        dialer: SafeDialer,
        origin: &str,
    ) -> Result<Self, GatewayAuthorityError> {
        let origin = normalize_origin(origin)?;
        if deployment.as_str().is_empty()
            || tenant.as_str().is_empty()
            || audit_key.expose().len() < 32
        {
            return Err(GatewayAuthorityError::InvalidInput);
        }
        Ok(Self {
            pool,
            vault,
            deployment,
            tenant,
            audit_key,
            dialer,
            origin,
        })
    }

    pub fn prepare_enrollment(
        &self,
        auth: AuthContext,
        name: &str,
        registered_client_id: &str,
    ) -> Result<GatewayEnrollment, GatewayAuthorityError> {
        self.check_auth(&auth)?;
        if !bounded(name, 100) || !bounded(registered_client_id, 256) {
            return Err(GatewayAuthorityError::InvalidInput);
        }
        Ok(GatewayEnrollment {
            auth,
            id: Uuid::now_v7(),
            name: name.to_owned(),
            issuer: self.origin.clone(),
            client_id: registered_client_id.to_owned(),
        })
    }

    pub async fn enroll(
        &self,
        enrollment: &GatewayEnrollment,
        tokens: &acosmi::TokenSet,
        cancel: CancellationToken,
        outcomes: Arc<dyn GatewayHttpOutcomes>,
    ) -> Result<GatewayConnectionReceipt, GatewayAuthorityError> {
        self.check_auth(&enrollment.auth)?;
        if enrollment.issuer != self.origin
            || tokens.client_id != enrollment.client_id
            || tokens.server_url != self.origin
        {
            return Err(GatewayAuthorityError::InvalidInput);
        }
        store::validate_token_shape(tokens, &enrollment.issuer, &enrollment.client_id)?;
        let deadline = Instant::now() + OPERATION_MAX;
        let fence = Arc::new(EnrollmentFence::new(
            self.pool.clone(),
            enrollment.auth.clone(),
            self.deployment.clone(),
            self.tenant.clone(),
            deadline,
        ));
        let transport = self.transport(fence, outcomes, deadline)?;
        let account = GatewayAccountClient::new(&self.origin, transport).map_err(map_account)?;
        let metadata = account
            .fetch_metadata(cancel.clone())
            .await
            .map_err(map_account)?;
        let identity = account
            .fetch_profile(
                &metadata,
                &SecretBytes::new(tokens.access_token.as_bytes().to_vec()),
                cancel.clone(),
            )
            .await
            .map_err(map_account)?;
        let auth_generation = i64::try_from(enrollment.auth.auth_generation().get())
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        let scope = Scope {
            auth: enrollment.auth.clone(),
            deployment: self.deployment.clone(),
            tenant: self.tenant.clone(),
            connection_id: enrollment.id,
            expected_revision: 1,
            auth_generation,
            issuer: identity.issuer().to_owned(),
            client_id: enrollment.client_id.clone(),
            account_id: identity.account_id().to_owned(),
            organization_id: identity.organization_id().map(str::to_owned),
            cancel: cancel.clone(),
            deadline,
        };
        store::validate_token(tokens, &scope, 1)?;
        let session = DetachedSession::acquire(&self.pool, &cancel, deadline).await?;
        store::insert_enrollment(
            &session,
            &self.vault,
            self.audit_key.expose(),
            &scope,
            &enrollment.name,
            tokens,
        )
        .await?;
        session.schedule_close();
        let verify = DetachedSession::acquire(&self.pool, &cancel, deadline).await?;
        verify.begin(&cancel, deadline).await?;
        let readback = async {
            let connection = store::load_connection(&verify, &scope, false).await?;
            let secret = connection
                .current_secret_id
                .ok_or(GatewayAuthorityError::Corrupt)?;
            let encrypted = store::load_secret(&verify, &scope, secret, 1).await?;
            Ok::<_, GatewayAuthorityError>((connection, secret, encrypted))
        }
        .await;
        let rollback = verify.rollback(&cancel, deadline).await;
        verify.schedule_close();
        let (connection, secret, encrypted) = match (readback, rollback) {
            (Ok(value), Ok(())) => value,
            _ => return Err(GatewayAuthorityError::CommitUnknown),
        };
        let confirmed = store::open_tokens(&self.vault, secret, &encrypted, &scope, 1)?;
        if connection.state != "ready"
            || connection.credential_generation != 1
            || !store::token_bytes_equal(&confirmed, tokens)
        {
            return Err(GatewayAuthorityError::CommitUnknown);
        }
        Ok(GatewayConnectionReceipt {
            id: enrollment.id,
            revision: 1,
            credential_generation: 1,
        })
    }

    pub async fn operation(
        &self,
        auth: AuthContext,
        id: Uuid,
        expected_revision: i64,
        cancel: CancellationToken,
        deadline: Instant,
        outcomes: Arc<dyn GatewayHttpOutcomes>,
    ) -> Result<GatewayOperation, GatewayAuthorityError> {
        self.check_auth(&auth)?;
        let now = Instant::now();
        if expected_revision <= 0 || deadline <= now {
            return Err(GatewayAuthorityError::InvalidInput);
        }
        let deadline = deadline.min(now + OPERATION_MAX);
        let auth_generation = i64::try_from(auth.auth_generation().get())
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        let seed_scope = Scope {
            auth: auth.clone(),
            deployment: self.deployment.clone(),
            tenant: self.tenant.clone(),
            connection_id: id,
            expected_revision,
            auth_generation,
            issuer: self.origin.clone(),
            client_id: String::new(),
            account_id: String::new(),
            organization_id: None,
            cancel: cancel.clone(),
            deadline,
        };
        let session = DetachedSession::acquire(&self.pool, &cancel, deadline).await?;
        session.begin(&cancel, deadline).await?;
        session.verify_actor(&auth, &cancel, deadline, true).await?;
        let row=session.query_opt("SELECT issuer,client_id,account_id,organization_id,revision,auth_generation FROM public.sdk_gateway_connections WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND enabled AND deleted_at IS NULL FOR SHARE",
            &[&id,&self.deployment.as_str(),&self.tenant.as_str(),&auth.actor().as_str()],&cancel,deadline).await?.ok_or(GatewayAuthorityError::NotVisible)?;
        let scope = Scope {
            issuer: row
                .try_get("issuer")
                .map_err(|_| GatewayAuthorityError::Corrupt)?,
            client_id: row
                .try_get("client_id")
                .map_err(|_| GatewayAuthorityError::Corrupt)?,
            account_id: row
                .try_get("account_id")
                .map_err(|_| GatewayAuthorityError::Corrupt)?,
            organization_id: row
                .try_get("organization_id")
                .map_err(|_| GatewayAuthorityError::Corrupt)?,
            ..seed_scope
        };
        let rev: i64 = row
            .try_get("revision")
            .map_err(|_| GatewayAuthorityError::Corrupt)?;
        let ag: i64 = row
            .try_get("auth_generation")
            .map_err(|_| GatewayAuthorityError::Corrupt)?;
        session.rollback(&cancel, deadline).await?;
        session.schedule_close();
        if rev != expected_revision || ag != auth_generation {
            return Err(GatewayAuthorityError::Conflict);
        }
        if scope.issuer != self.origin
            || !bounded(&scope.client_id, 256)
            || !bounded(&scope.account_id, 256)
            || scope
                .organization_id
                .as_deref()
                .is_some_and(|value| !bounded(value, 256))
        {
            return Err(GatewayAuthorityError::Corrupt);
        }
        let inner = AuthorityInner::new(
            self.pool.clone(),
            self.vault.clone(),
            SecretBytes::new(self.audit_key.expose().to_vec()),
            scope,
        );
        let http_authority: Arc<dyn crate::gateway_transport::GatewayHttpAuthority> = inner.clone();
        let transport = self.transport(http_authority, outcomes, deadline)?;
        inner.set_transport(transport.clone())?;
        let authority: Arc<dyn StrictTokenAuthority> = inner;
        Ok(GatewayOperation {
            authority,
            transport,
        })
    }

    fn check_auth(&self, auth: &AuthContext) -> Result<(), GatewayAuthorityError> {
        if auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !(auth.has_role(Role::User) || auth.has_role(Role::Admin))
        {
            return Err(GatewayAuthorityError::NotVisible);
        }
        Ok(())
    }

    fn transport(
        &self,
        authority: Arc<dyn crate::gateway_transport::GatewayHttpAuthority>,
        outcomes: Arc<dyn GatewayHttpOutcomes>,
        deadline: Instant,
    ) -> Result<Arc<dyn HttpTransport>, GatewayAuthorityError> {
        let oauth = GatewayOAuthEndpoints::new(
            GatewayOAuthProfile::Desktop,
            &format!("{}/oauth/desktop/register", self.origin),
            &format!("{}/oauth/desktop/token", self.origin),
            Some(&format!("{}/oauth/desktop/revoke", self.origin)),
        )
        .map_err(|_| GatewayAuthorityError::InvalidInput)?;
        let endpoints = VerifiedGatewayEndpoints::new(
            &self.origin,
            None::<(&str, GatewayModelWire)>,
            Some(oauth),
        )
        .map_err(|_| GatewayAuthorityError::InvalidInput)?
        .with_account_profile()
        .map_err(|_| GatewayAuthorityError::InvalidInput)?;
        GatewayTransportFactory::new(
            self.dialer.clone(),
            endpoints,
            GatewayTransportLimits::new(Duration::from_secs(30), 64 * 1024 * 1024)
                .map_err(|_| GatewayAuthorityError::InvalidInput)?,
        )
        .for_operation(authority, outcomes, deadline, Duration::from_secs(10))
        .map_err(|_| GatewayAuthorityError::InvalidInput)
    }
}

fn normalize_origin(raw: &str) -> Result<String, GatewayAuthorityError> {
    if raw.is_empty() || raw.trim() != raw || raw.len() > 2048 {
        return Err(GatewayAuthorityError::InvalidInput);
    }
    let url = Url::parse(raw).map_err(|_| GatewayAuthorityError::InvalidInput)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GatewayAuthorityError::InvalidInput);
    }
    let path = url.path().trim_end_matches('/');
    if !matches!(path, "" | "/api/v4") {
        return Err(GatewayAuthorityError::InvalidInput);
    }
    Ok(url.origin().ascii_serialization())
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn map_account(error: GatewayAccountError) -> GatewayAuthorityError {
    match error {
        GatewayAccountError::Cancelled => GatewayAuthorityError::Cancelled,
        GatewayAccountError::Timeout => GatewayAuthorityError::Timeout,
        _ => GatewayAuthorityError::AccountProtocol,
    }
}
