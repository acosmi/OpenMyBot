//! Fresh PostgreSQL/Vault credential selection for one MCP operation.
//!
//! Deployment bearer, generic MCP actor OAuth and curated Drive actor OAuth all resolve here.
//! Generic OAuth refresh uses the current server's canonical egress authority selected with the
//! credential snapshot; no caller can receive an empty bearer or a token from another actor.

use openbot_contracts::ids::ActorId;
use openbot_domain::vault::{SecretKind, SecretPrincipal, ServiceId};
use uuid::Uuid;

use crate::db::types::CredentialKind;
use crate::google_drive_oauth::GoogleDriveOAuthClient;
use crate::mcp::McpBearerToken;
use crate::mcp_catalog::VendorTransportKind;
use crate::mcp_oauth::McpOAuthClient;
use crate::net::safe_http::{SafeDialer, SchemePolicy};
use crate::recovery_control::RecoveryWorkerLease;
use crate::store::plugin_user_credential::{
    OAuthTokenExchangeError, PluginUserCredentialStore, RotatingOAuthTokenExchanger,
    UserCredentialSelectionError, UserOAuthAccessError,
};
use crate::vault::CredentialRecordVault;

/// Stable credential resolution failure. No database value or secret crosses this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum McpCredentialError {
    /// Server/credential row is unavailable.
    #[error("mcp_credential_unavailable")]
    Unavailable,
    /// The current actor must connect/reconnect or the deployment credential was revoked.
    #[error("mcp_auth_required")]
    AuthRequired,
    /// Existing grant lacks a scope that requires interactive step-up authorization.
    #[error("mcp_insufficient_scope")]
    InsufficientScope,
    /// Refresh rotation commit result is unknown; no access token is released.
    #[error("mcp_credential_commit_unknown")]
    CommitUnknown,
    /// Stored binding or ciphertext violates the closed credential schema.
    #[error("mcp_credential_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
}

/// Per-operation broker. It never caches cleartext or access tokens.
#[derive(Clone)]
pub struct PostgresMcpCredentialBroker {
    pool: crate::db::pool::DatabasePool,
    vault: CredentialRecordVault,
    user_oauth: Option<UserOAuthRuntime>,
    drive_oauth: Option<GoogleDriveOAuthClient>,
    recovery_gate: crate::recovery_control::RecoveryReadGate,
}

#[derive(Clone)]
struct UserOAuthRuntime {
    store: PluginUserCredentialStore,
    exchanger: McpOAuthClient,
}

impl PostgresMcpCredentialBroker {
    /// Bind the same tenant vault and PostgreSQL pool used by production credentials.
    #[must_use]
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        vault: CredentialRecordVault,
        recovery_gate: crate::recovery_control::RecoveryReadGate,
    ) -> Self {
        Self {
            pool,
            vault,
            user_oauth: None,
            drive_oauth: None,
            recovery_gate,
        }
    }

    /// Attach the production actor-OAuth runtime and the audit key needed for atomic refresh-token
    /// rotation. The base dialer contributes resolver/TLS; each operation replaces its destination
    /// policy with the current server's PostgreSQL-bound exact CIDR set. Production passes
    /// `HttpsOnly`; local conformance servers may use `HttpOrHttps`.
    pub fn with_user_oauth(
        mut self,
        dialer: SafeDialer,
        scheme_policy: SchemePolicy,
        audit_checkpoint_key: Vec<u8>,
    ) -> Result<Self, McpCredentialError> {
        let store = PluginUserCredentialStore::new(
            self.pool.clone(),
            self.vault.clone(),
            self.recovery_gate.clone(),
        )
        .with_rotation_audit_key(audit_checkpoint_key)
        .map_err(map_selection_error)?;
        self.user_oauth = Some(UserOAuthRuntime {
            store,
            exchanger: McpOAuthClient::new(dialer, scheme_policy),
        });
        Ok(self)
    }

    /// Attach the curated Drive refresh adapter to the same actor credential store. Google may
    /// retain the existing refresh token, so its exchanger uses the store's explicit non-rotation
    /// contract while MCP continues to require rotation.
    #[must_use]
    pub fn with_google_drive_oauth(mut self, exchanger: GoogleDriveOAuthClient) -> Self {
        self.drive_oauth = Some(exchanger);
        self
    }

    /// Resolve anonymous, deployment-bearer, MCP actor-OAuth or Drive actor-OAuth authentication
    /// immediately before one vendor operation. No cleartext/access token is cached.
    pub async fn bearer_for(
        &self,
        server_id: &str,
        actor: &ActorId,
    ) -> Result<Option<McpBearerToken>, McpCredentialError> {
        // A standalone resolution: the 5 s SQL precedent plus one OAuth round
        // for a refresh.
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(5)
            + crate::mcp_oauth::MCP_OAUTH_ROUND_BUDGET;
        let admission = self
            .recovery_gate
            .borrow_worker_before(deadline)
            .await
            .map_err(|_| McpCredentialError::Unavailable)?;
        self.bearer_for_admitted(server_id, actor, &admission).await
    }

    /// Same resolution under the caller's held worker admission, which this
    /// rechecks before the Vault-open and the refresh.
    pub(crate) async fn bearer_for_admitted(
        &self,
        server_id: &str,
        actor: &ActorId,
        admission: &RecoveryWorkerLease<'_>,
    ) -> Result<Option<McpBearerToken>, McpCredentialError> {
        if server_id.is_empty() || server_id.len() > 64 || server_id.as_bytes().contains(&0) {
            return Err(McpCredentialError::Corrupt { field: "server_id" });
        }
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "MCP credential 获取 PostgreSQL 连接失败");
            McpCredentialError::Unavailable
        })?;
        let row = client
            .query_opt(
                "SELECT coalesce(s.transport,'mcp') AS transport,
                        s.credential_id,c.kind,c.provider,c.encrypted_value,c.revoked_at
                   FROM public.mcp_servers s
                   LEFT JOIN public.credentials c ON c.id=s.credential_id
                  WHERE s.id=$1",
                &[&server_id],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "MCP credential 权威选择失败");
                McpCredentialError::Unavailable
            })?
            .ok_or(McpCredentialError::Unavailable)?;
        let transport = VendorTransportKind::parse(
            &row.try_get::<_, String>("transport")
                .map_err(|_| McpCredentialError::Corrupt { field: "transport" })?,
        )
        .map_err(|_| McpCredentialError::Corrupt { field: "transport" })?;
        let pointer: Option<Uuid> =
            row.try_get("credential_id")
                .map_err(|_| McpCredentialError::Corrupt {
                    field: "credential_id",
                })?;
        let Some(pointer) = pointer else {
            return match transport {
                VendorTransportKind::Mcp => Ok(None),
                VendorTransportKind::GoogleDriveRest => Err(McpCredentialError::AuthRequired),
            };
        };
        let kind: Option<CredentialKind> =
            row.try_get("kind")
                .map_err(|_| McpCredentialError::Corrupt {
                    field: "credential_kind",
                })?;
        let provider: Option<String> = row
            .try_get("provider")
            .map_err(|_| McpCredentialError::Corrupt { field: "provider" })?;
        let encrypted: Option<String> =
            row.try_get("encrypted_value")
                .map_err(|_| McpCredentialError::Corrupt {
                    field: "encrypted_value",
                })?;
        let revoked: Option<time::OffsetDateTime> =
            row.try_get("revoked_at")
                .map_err(|_| McpCredentialError::Corrupt {
                    field: "revoked_at",
                })?;
        if revoked.is_some() {
            return Err(McpCredentialError::AuthRequired);
        }
        let kind = kind.ok_or(McpCredentialError::Corrupt {
            field: "credential_kind",
        })?;
        if provider.as_deref() != Some(server_id) {
            return Err(McpCredentialError::Corrupt { field: "provider" });
        }
        if kind == CredentialKind::Mcp {
            // The deployment bearer is opened below; the user-OAuth path gates its own opens.
            crate::restore_reconfirmation::require_confirmed_before(
                &**client,
                crate::restore_reconfirmation::RequirementSource {
                    cohort: admission.restore_cohort(),
                    kind: crate::restore_reconfirmation::RequirementKind::Credential,
                    source_ref: &pointer.to_string(),
                },
                admission.deadline(),
            )
            .await
            .map_err(|error| match error {
                crate::restore_reconfirmation::RestoreReconfirmationError::NotConfirmed => {
                    McpCredentialError::AuthRequired
                }
                crate::restore_reconfirmation::RestoreReconfirmationError::Unavailable => {
                    McpCredentialError::Unavailable
                }
            })?;
        }
        drop(client);
        admission
            .verify_current_before(admission.deadline())
            .map_err(|_| McpCredentialError::Unavailable)?;
        match kind {
            CredentialKind::Mcp => {
                if transport != VendorTransportKind::Mcp {
                    return Err(McpCredentialError::Corrupt { field: "transport" });
                }
                let secret = self
                    .vault
                    .open(
                        &pointer,
                        SecretKind::Mcp,
                        SecretPrincipal::Deployment,
                        SecretPrincipal::Service(ServiceId::new(server_id)),
                        encrypted.as_deref().ok_or(McpCredentialError::Corrupt {
                            field: "encrypted_value",
                        })?,
                    )
                    .map_err(|error| {
                        tracing::error!(code = %error, "deployment MCP credential 密文被拒");
                        McpCredentialError::Corrupt {
                            field: "encrypted_value",
                        }
                    })?
                    .into_secret();
                McpBearerToken::from_secret(secret).map(Some).map_err(|_| {
                    McpCredentialError::Corrupt {
                        field: "encrypted_value",
                    }
                })
            }
            CredentialKind::McpOauthClient => self
                .user_oauth_bearer(server_id, actor, transport, admission)
                .await
                .map(Some),
            CredentialKind::McpUserToken => Err(McpCredentialError::Corrupt {
                field: "credential_kind",
            }),
            CredentialKind::Model | CredentialKind::Connector | CredentialKind::Agent => {
                Err(McpCredentialError::Corrupt {
                    field: "credential_kind",
                })
            }
        }
    }

    async fn user_oauth_bearer(
        &self,
        server_id: &str,
        actor: &ActorId,
        transport: VendorTransportKind,
        admission: &RecoveryWorkerLease<'_>,
    ) -> Result<McpBearerToken, McpCredentialError> {
        let runtime = self
            .user_oauth
            .as_ref()
            .ok_or(McpCredentialError::AuthRequired)?;
        match transport {
            VendorTransportKind::Mcp => {
                refresh_actor_bearer(
                    &runtime.store,
                    &runtime.exchanger,
                    server_id,
                    actor,
                    admission,
                )
                .await
            }
            VendorTransportKind::GoogleDriveRest => {
                let exchanger = self
                    .drive_oauth
                    .as_ref()
                    .ok_or(McpCredentialError::AuthRequired)?;
                refresh_actor_bearer(&runtime.store, exchanger, server_id, actor, admission).await
            }
        }
    }
}

async fn refresh_actor_bearer<E: RotatingOAuthTokenExchanger + ?Sized>(
    store: &PluginUserCredentialStore,
    exchanger: &E,
    server_id: &str,
    actor: &ActorId,
    admission: &RecoveryWorkerLease<'_>,
) -> Result<McpBearerToken, McpCredentialError> {
    let token = store
        .fresh_user_access_token_admitted(server_id, actor, exchanger, admission)
        .await
        .map_err(map_user_oauth_error)?;
    McpBearerToken::from_secret(token.into_secret()).map_err(|_| McpCredentialError::Corrupt {
        field: "access_token",
    })
}

impl core::fmt::Debug for PostgresMcpCredentialBroker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresMcpCredentialBroker")
            .field("vault", &self.vault)
            .field("user_oauth", &self.user_oauth.is_some())
            .field("drive_oauth", &self.drive_oauth.is_some())
            .finish_non_exhaustive()
    }
}

fn map_selection_error(error: UserCredentialSelectionError) -> McpCredentialError {
    match error {
        UserCredentialSelectionError::Refused(_) => McpCredentialError::AuthRequired,
        UserCredentialSelectionError::Unavailable | UserCredentialSelectionError::Conflict => {
            McpCredentialError::Unavailable
        }
        UserCredentialSelectionError::CommitUnknown
        | UserCredentialSelectionError::RotationPending => McpCredentialError::CommitUnknown,
        UserCredentialSelectionError::Corrupt { field } => McpCredentialError::Corrupt { field },
    }
}

fn map_user_oauth_error(error: UserOAuthAccessError) -> McpCredentialError {
    match error {
        UserOAuthAccessError::Selection(error) => map_selection_error(error),
        UserOAuthAccessError::Exchange(OAuthTokenExchangeError::AuthRequired) => {
            McpCredentialError::AuthRequired
        }
        UserOAuthAccessError::Exchange(OAuthTokenExchangeError::InsufficientScope) => {
            McpCredentialError::InsufficientScope
        }
        UserOAuthAccessError::Exchange(OAuthTokenExchangeError::Unavailable) => {
            McpCredentialError::Unavailable
        }
        UserOAuthAccessError::Exchange(
            OAuthTokenExchangeError::InvalidResponse
            | OAuthTokenExchangeError::RefreshTokenPassthrough,
        ) => McpCredentialError::Corrupt {
            field: "oauth_response",
        },
    }
}
