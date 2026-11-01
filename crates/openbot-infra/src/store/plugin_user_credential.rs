//! per-user MCP/OAuth credential 的选择、交换边界与退役（v3 §6.4 / §9.2）。
//!
//! 本模块在 vendor 网络前回答“这次调用应当用谁的 refresh token、哪个部署 OAuth client、
//! 哪组 current private-egress authority”，并把 refresh-token exchange 与 vendor access token
//! 做成两个不同类型。真实 RMCP/Drive executor 只能取得完成选择与 rotation commit 后的 access token。

mod refresh_operation;

use refresh_operation::{OperationSendFence, RefreshSendFence};
use std::sync::Arc;

use crate::db::pool::DatabasePool as Pool;
use async_trait::async_trait;
use openbot_application::{OwnedCredentialRetirementError, OwnedCredentialRetirer};
use openbot_contracts::ids::ActorId;
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use postgres_types::FromSqlOwned;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::InfraError;
use crate::db::types::CredentialKind;
use crate::mcp_egress::parse_stored_mcp_egress;
use crate::net::safe_http::CidrAllowlist;
use crate::recovery_control::RecoveryWorkerLease;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::vault::CredentialRecordVault;

/// `prepare_user_oauth_call` 在任何 token/vendor 网络之前给出的封闭拒绝原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UserCredentialRefusal {
    /// 调用没有可归责 actor；空 actor 永不查询“第一条可用连接”。
    #[error("mcp_user_actor_required")]
    ActorRequired,
    /// 该 actor 没有为这个 server 建立连接。
    #[error("mcp_user_connection_required")]
    ConnectionRequired,
    /// join 存在，但个人 credential 已撤销。
    #[error("mcp_user_reconnect_required")]
    ReconnectRequired,
    /// 人已连接，但部署没有登记 OAuth client。
    #[error("mcp_oauth_client_required")]
    DeploymentClientRequired,
    /// 部署 OAuth client 已撤销，必须由管理员重新登记。
    #[error("mcp_oauth_client_unusable")]
    DeploymentClientUnusable,
    /// catalog/server 行不存在；不能猜一个 transport 或 fallback。
    #[error("mcp_server_unknown")]
    ServerUnknown,
}

impl UserCredentialRefusal {
    /// 稳定 code；用户文案由 transport/GUI 本地化。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ActorRequired => "mcp_user_actor_required",
            Self::ConnectionRequired => "mcp_user_connection_required",
            Self::ReconnectRequired => "mcp_user_reconnect_required",
            Self::DeploymentClientRequired => "mcp_oauth_client_required",
            Self::DeploymentClientUnusable => "mcp_oauth_client_unusable",
            Self::ServerUnknown => "mcp_server_unknown",
        }
    }
}

/// per-user credential 选择失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UserCredentialSelectionError {
    /// 正常、可操作的产品拒绝。
    #[error("{0}")]
    Refused(UserCredentialRefusal),
    /// PostgreSQL 当前不可用。
    #[error("plugin_user_credential_unavailable")]
    Unavailable,
    /// 行存在但违反持久化不变量；只报告静态字段名，不报告值。
    #[error("plugin_user_credential_corrupt field={field}")]
    Corrupt {
        /// 损坏的字段类别。
        field: &'static str,
    },
    /// Another request rotated/reconnected the same credential first.
    #[error("plugin_user_credential_conflict")]
    Conflict,
    /// An existing operation owns this credential; inspection never grants another send.
    #[error("plugin_user_credential_rotation_pending")]
    RotationPending,
    /// Rotation transaction may have committed; caller must not use the access token automatically.
    #[error("plugin_user_credential_commit_unknown")]
    CommitUnknown,
}

impl From<UserCredentialRefusal> for UserCredentialSelectionError {
    fn from(value: UserCredentialRefusal) -> Self {
        Self::Refused(value)
    }
}

/// token endpoint 的窄输入；只有 token exchanger 能接触 refresh token。
#[derive(Clone, Copy)]
pub struct OAuthRefreshExchange<'a> {
    server_id: &'a str,
    endpoint: &'a str,
    transport: &'a str,
    granted_scope: &'a str,
    oauth_client: &'a SecretBytes,
    refresh_token: &'a SecretBytes,
    egress_allowlist: &'a CidrAllowlist,
    send_fence: &'a dyn RefreshSendFence,
}

impl OAuthRefreshExchange<'_> {
    /// Admit this exact token POST once, immediately before the adapter calls SafeDialer.
    /// Discovery is not admission; a second call always fails without another token send.
    pub async fn admit_token_send(&self) -> Result<(), OAuthTokenExchangeError> {
        self.send_fence.admit().await
    }

    /// 目标 server 的稳定 catalog id。
    #[must_use]
    pub const fn server_id(&self) -> &str {
        self.server_id
    }

    /// Exact MCP protected-resource identifier selected from PostgreSQL.
    #[must_use]
    pub const fn endpoint(&self) -> &str {
        self.endpoint
    }

    /// Closed vendor transport selected with the credential and egress snapshot.
    #[must_use]
    pub const fn transport(&self) -> &str {
        self.transport
    }

    /// Previously granted scope to preserve during refresh.
    #[must_use]
    pub const fn granted_scope(&self) -> &str {
        self.granted_scope
    }

    /// 显式暴露部署 OAuth client 的 JSON 字节，仅供 token endpoint 请求构造。
    #[must_use]
    pub fn expose_oauth_client(&self) -> &[u8] {
        self.oauth_client.expose()
    }

    /// 显式暴露个人 refresh token，仅供 token endpoint 请求构造。
    #[must_use]
    pub fn expose_refresh_token(&self) -> &[u8] {
        self.refresh_token.expose()
    }

    /// Current administrator-authorized numeric destinations for this exact server operation.
    #[must_use]
    pub const fn egress_allowlist(&self) -> &CidrAllowlist {
        self.egress_allowlist
    }
}

impl core::fmt::Debug for OAuthRefreshExchange<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OAuthRefreshExchange")
            .field("server_id", &self.server_id)
            .field("endpoint", &"<redacted-origin>")
            .field("transport", &self.transport)
            .field("scope_bytes", &self.granted_scope.len())
            .field("oauth_client", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("egress_allowlist_entries", &self.egress_allowlist.len())
            .finish()
    }
}

/// token endpoint exchange 失败；不保留远端 body 或 token 值。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OAuthTokenExchangeError {
    /// 网络/endpoint 当前不可用。
    #[error("oauth_token_exchange_unavailable")]
    Unavailable,
    /// endpoint 响应结构无效。
    #[error("oauth_token_exchange_invalid_response")]
    InvalidResponse,
    /// endpoint adapter 试图把 refresh token 原样当 access token 返回。
    #[error("oauth_refresh_token_passthrough_refused")]
    RefreshTokenPassthrough,
    /// Authorization server rejected the refresh grant/client and the person must reconnect.
    #[error("oauth_auth_required")]
    AuthRequired,
    /// The current grant cannot satisfy the resource server's required scope.
    #[error("oauth_insufficient_scope")]
    InsufficientScope,
}

/// OAuth token response whose optional refresh token still has to be durably rotated before the
/// access token may leave the broker.
pub struct RotatingOAuthGrant {
    access_token: SecretBytes,
    refresh_token: Option<SecretBytes>,
    scope: Option<String>,
}

impl RotatingOAuthGrant {
    /// Construct from a validated token-endpoint response.
    #[must_use]
    pub fn new(
        access_token: SecretBytes,
        refresh_token: Option<SecretBytes>,
        scope: Option<String>,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            scope,
        }
    }
}

impl core::fmt::Debug for RotatingOAuthGrant {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RotatingOAuthGrant")
            .field("access_token", &"<redacted>")
            .field("has_refresh_token", &self.refresh_token.is_some())
            .field("scope_bytes", &self.scope.as_ref().map_or(0, String::len))
            .finish()
    }
}

/// Rotation-aware token endpoint port used by the production MCP broker.
#[async_trait]
pub trait RotatingOAuthTokenExchanger: Send + Sync {
    /// Whether a successful token response without a replacement refresh token is invalid.
    /// MCP OAuth requires rotation; Google web-server OAuth normally reuses the stored refresh.
    fn requires_refresh_rotation(&self) -> bool {
        true
    }

    /// Exchange one refresh token. Returned secrets are never serializable/debuggable.
    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError>;
}

/// 唯一允许交给 vendor transport 的短寿命 access token。
pub struct VendorAccessToken(SecretBytes);

impl VendorAccessToken {
    /// 显式暴露给 vendor transport；refresh token 没有这个类型。
    #[must_use]
    pub fn expose_for_vendor(&self) -> &[u8] {
        self.0.expose()
    }

    /// Transfer the zeroizing access-token allocation to the protocol-specific bearer wrapper.
    #[must_use]
    pub(crate) fn into_secret(self) -> SecretBytes {
        self.0
    }
}

impl core::fmt::Debug for VendorAccessToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VendorAccessToken(<redacted>)")
    }
}

/// 已完成 PostgreSQL 精确选择与 v1/v2 vault 解封、尚未发生网络的 exchange 计划。
pub struct PreparedUserOAuthCredential {
    server_id: String,
    endpoint: String,
    transport: String,
    actor: ActorId,
    scope: String,
    user_credential_id: Uuid,
    deployment_credential_id: Uuid,
    refresh_token: SecretBytes,
    oauth_client: SecretBytes,
    user_encrypted_value: String,
    client_encrypted_value: String,
    auth_generation: i64,
    server_generation: i64,
    server_updated_at: OffsetDateTime,
    client_updated_at: OffsetDateTime,
    egress_allowlist: CidrAllowlist,
    egress_allow_cidrs: Vec<String>,
}

impl PreparedUserOAuthCredential {
    /// 实际绑定的 actor；来自权威调用上下文。
    #[must_use]
    pub const fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// Canonical protected-resource endpoint read in the same credential-selection snapshot.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// vendor 实际授予并持久化的 scope 原串。
    #[must_use]
    pub fn granted_scope(&self) -> &str {
        &self.scope
    }

    /// 被选择的个人 credential id；不是秘密，可用于受控 audit。
    #[must_use]
    pub const fn user_credential_id(&self) -> Uuid {
        self.user_credential_id
    }

    /// 被选择的 deployment OAuth client credential id。
    #[must_use]
    pub const fn deployment_credential_id(&self) -> Uuid {
        self.deployment_credential_id
    }

    async fn exchange_rotating<E: RotatingOAuthTokenExchanger + ?Sized>(
        &self,
        exchanger: &E,
        send_fence: &dyn RefreshSendFence,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        let grant = exchanger
            .exchange_rotating(OAuthRefreshExchange {
                server_id: &self.server_id,
                endpoint: &self.endpoint,
                transport: &self.transport,
                granted_scope: &self.scope,
                oauth_client: &self.oauth_client,
                refresh_token: &self.refresh_token,
                egress_allowlist: &self.egress_allowlist,
                send_fence,
            })
            .await?;
        if grant.access_token.is_empty() {
            return Err(OAuthTokenExchangeError::InvalidResponse);
        }
        if grant.access_token.ct_eq(&self.refresh_token)
            || grant.refresh_token.as_ref().is_some_and(|refresh| {
                refresh.is_empty()
                    || (exchanger.requires_refresh_rotation() && refresh.ct_eq(&self.refresh_token))
                    || refresh.ct_eq(&grant.access_token)
            })
        {
            return Err(OAuthTokenExchangeError::RefreshTokenPassthrough);
        }
        if grant
            .scope
            .as_ref()
            .is_some_and(|scope| scope.len() > 16 * 1024 || scope.as_bytes().contains(&0))
        {
            return Err(OAuthTokenExchangeError::InvalidResponse);
        }
        Ok(grant)
    }
}

impl core::fmt::Debug for PreparedUserOAuthCredential {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedUserOAuthCredential")
            .field("server_id", &self.server_id)
            .field("endpoint", &"<redacted-origin>")
            .field("transport", &self.transport)
            .field("actor", &self.actor)
            .field("scope", &self.scope)
            .field("user_credential_id", &self.user_credential_id)
            .field("deployment_credential_id", &self.deployment_credential_id)
            .field("refresh_token", &"<redacted>")
            .field("oauth_client", &"<redacted>")
            .field("egress_allowlist_entries", &self.egress_allowlist.len())
            .finish()
    }
}

/// 设置页的一条个人连接投影；不含 credential id 或秘密。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserOAuthConnection {
    /// MCP/vendor server id。
    pub server_id: String,
    /// vendor 实际授予的 scope。
    pub scope: String,
    /// 首次连接时刻。
    pub connected_at: OffsetDateTime,
}

/// PostgreSQL + credential vault 的 per-user 选择 store。
#[derive(Clone)]
pub struct PluginUserCredentialStore {
    pool: Pool,
    vault: CredentialRecordVault,
    rotation_checkpoint_key: Option<Arc<SecretBytes>>,
    recovery_gate: crate::recovery_control::RecoveryReadGate,
}

impl PluginUserCredentialStore {
    /// 用共享池与显式 credential vault 构造。
    #[must_use]
    pub fn new(
        pool: Pool,
        vault: CredentialRecordVault,
        recovery_gate: crate::recovery_control::RecoveryReadGate,
    ) -> Self {
        Self {
            pool,
            vault,
            rotation_checkpoint_key: None,
            recovery_gate,
        }
    }

    /// One worker admission for a standalone call: SQL steps take the 5 s
    /// precedent and a refresh adds one OAuth round.
    async fn admission(
        &self,
        budget: std::time::Duration,
    ) -> Result<RecoveryWorkerLease<'_>, UserCredentialSelectionError> {
        self.recovery_gate
            .borrow_worker_before(std::time::Instant::now() + budget)
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)
    }

    /// Attach the audit key required before a refresh-token rotation can commit.
    pub fn with_rotation_audit_key(
        mut self,
        checkpoint_key: Vec<u8>,
    ) -> Result<Self, UserCredentialSelectionError> {
        if checkpoint_key.is_empty() {
            return Err(UserCredentialSelectionError::Corrupt {
                field: "audit_checkpoint_key",
            });
        }
        self.rotation_checkpoint_key = Some(Arc::new(SecretBytes::new(checkpoint_key)));
        Ok(self)
    }

    /// 在任何 token endpoint/vendor 网络之前，按 `(server_id, actor_id)` 精确选择两份凭据。
    ///
    /// # Errors
    ///
    /// 缺 actor/连接、撤销、缺 deployment client 是稳定产品拒绝；数据库不可用或持久化绑定
    /// 损坏则分别返回 `Unavailable` / `Corrupt`。任何失败都拿不到明文计划。
    pub async fn prepare_user_oauth_call(
        &self,
        server_id: &str,
        actor: &ActorId,
    ) -> Result<PreparedUserOAuthCredential, UserCredentialSelectionError> {
        let admission = self.admission(SQL_STEPS_BUDGET).await?;
        self.prepare_admitted(server_id, actor, &admission).await
    }

    /// The caller holds `admission` through every later send and write.
    async fn prepare_admitted(
        &self,
        server_id: &str,
        actor: &ActorId,
        admission: &RecoveryWorkerLease<'_>,
    ) -> Result<PreparedUserOAuthCredential, UserCredentialSelectionError> {
        if actor.as_str().is_empty() {
            return Err(UserCredentialRefusal::ActorRequired.into());
        }
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "选择 per-user credential 获取连接失败");
            UserCredentialSelectionError::Unavailable
        })?;
        let row = client
            .query_opt(SELECTION_SQL, &[&server_id, &actor.as_str()])
            .await
            .map_err(|error| {
                let safe = InfraError::query("选择 per-user credential", error);
                tracing::error!(error = %safe, "选择 per-user credential 查询失败");
                UserCredentialSelectionError::Unavailable
            })?
            .ok_or(UserCredentialRefusal::ServerUnknown)?;

        let endpoint = required_column::<String>(&row, "server_endpoint")?;
        if endpoint.is_empty() || endpoint.len() > 8 * 1024 || endpoint.as_bytes().contains(&0) {
            return Err(UserCredentialSelectionError::Corrupt {
                field: "server_endpoint",
            });
        }
        let transport = required_column::<String>(&row, "server_transport")?;
        if !matches!(transport.as_str(), "mcp" | "google_drive_rest") {
            return Err(UserCredentialSelectionError::Corrupt {
                field: "server_transport",
            });
        }
        let egress_allow_cidrs = required_column::<Vec<String>>(&row, "egress_allow_cidrs")?;
        let egress_allowlist = parse_stored_mcp_egress(&egress_allow_cidrs).map_err(|_| {
            UserCredentialSelectionError::Corrupt {
                field: "egress_allow_cidrs",
            }
        })?;
        let user_pointer = optional_column::<Uuid>(&row, "user_pointer")?
            .ok_or(UserCredentialRefusal::ConnectionRequired)?;
        if !required_column::<bool>(&row, "actor_current")? {
            return Err(UserCredentialRefusal::ReconnectRequired.into());
        }
        let user_id = required_joined::<Uuid>(&row, "user_credential_id")?;
        if user_id != user_pointer {
            return Err(UserCredentialSelectionError::Corrupt {
                field: "user_credential_id",
            });
        }
        let user_kind = required_joined::<CredentialKind>(&row, "user_kind")?;
        let user_provider = required_joined::<String>(&row, "user_provider")?;
        let user_key_id = required_joined::<String>(&row, "user_key_id")?;
        let user_encrypted = required_joined::<String>(&row, "user_encrypted_value")?;
        let user_revoked = optional_column::<OffsetDateTime>(&row, "user_revoked_at")?;
        if user_revoked.is_some() {
            return Err(UserCredentialRefusal::ReconnectRequired.into());
        }
        if user_kind != CredentialKind::McpUserToken
            || user_provider != server_id
            || user_key_id != actor.as_str()
        {
            return Err(UserCredentialSelectionError::Corrupt {
                field: "user_credential_binding",
            });
        }
        let granted_scope = required_joined::<String>(&row, "granted_scope")?;
        let deployment_pointer = optional_column::<Uuid>(&row, "deployment_pointer")?
            .ok_or(UserCredentialRefusal::DeploymentClientRequired)?;
        let deployment_id = optional_column::<Uuid>(&row, "deployment_credential_id")?
            .ok_or(UserCredentialRefusal::DeploymentClientUnusable)?;
        if deployment_id != deployment_pointer {
            return Err(UserCredentialSelectionError::Corrupt {
                field: "deployment_credential_id",
            });
        }
        let deployment_kind = required_joined::<CredentialKind>(&row, "deployment_kind")?;
        let deployment_provider = required_joined::<String>(&row, "deployment_provider")?;
        let deployment_encrypted = required_joined::<String>(&row, "deployment_encrypted_value")?;
        let deployment_revoked = optional_column::<OffsetDateTime>(&row, "deployment_revoked_at")?;
        if deployment_revoked.is_some() {
            return Err(UserCredentialRefusal::DeploymentClientUnusable.into());
        }
        if deployment_kind != CredentialKind::McpOauthClient || deployment_provider != server_id {
            return Err(UserCredentialSelectionError::Corrupt {
                field: "deployment_credential_binding",
            });
        }
        // No Vault-open of either restored credential before its receipt.
        for credential in [user_id, deployment_id] {
            crate::restore_reconfirmation::require_confirmed_before(
                &**client,
                crate::restore_reconfirmation::RequirementSource {
                    cohort: admission.restore_cohort(),
                    kind: crate::restore_reconfirmation::RequirementKind::Credential,
                    source_ref: &credential.to_string(),
                },
                admission.deadline(),
            )
            .await
            .map_err(|error| match error {
                crate::restore_reconfirmation::RestoreReconfirmationError::NotConfirmed => {
                    UserCredentialSelectionError::Refused(UserCredentialRefusal::ReconnectRequired)
                }
                crate::restore_reconfirmation::RestoreReconfirmationError::Unavailable => {
                    UserCredentialSelectionError::Unavailable
                }
            })?;
        }
        current(admission)?;
        let service = SecretPrincipal::Service(ServiceId::new(server_id));
        let refresh_token = self
            .vault
            .open(
                &user_id,
                SecretKind::McpUserToken,
                SecretPrincipal::Actor(actor.clone()),
                service.clone(),
                &user_encrypted,
            )
            .map_err(|error| {
                tracing::error!(code = %error, "个人 credential 密文被拒");
                UserCredentialSelectionError::Corrupt {
                    field: "user_encrypted_value",
                }
            })?
            .into_secret();
        if refresh_token.is_empty() {
            return Err(UserCredentialRefusal::ReconnectRequired.into());
        }
        let oauth_client = self
            .vault
            .open(
                &deployment_id,
                SecretKind::McpOauthClient,
                SecretPrincipal::Deployment,
                service,
                &deployment_encrypted,
            )
            .map_err(|error| {
                tracing::error!(code = %error, "deployment OAuth client 密文被拒");
                UserCredentialSelectionError::Corrupt {
                    field: "deployment_encrypted_value",
                }
            })?
            .into_secret();
        if oauth_client.is_empty() {
            return Err(UserCredentialRefusal::DeploymentClientUnusable.into());
        }

        Ok(PreparedUserOAuthCredential {
            server_id: server_id.to_owned(),
            endpoint,
            transport,
            actor: actor.clone(),
            scope: granted_scope,
            user_credential_id: user_id,
            deployment_credential_id: deployment_id,
            refresh_token,
            oauth_client,
            user_encrypted_value: user_encrypted,
            client_encrypted_value: deployment_encrypted,
            auth_generation: required_column(&row, "auth_generation")?,
            server_generation: required_column(&row, "server_generation")?,
            server_updated_at: required_column(&row, "server_updated_at")?,
            client_updated_at: required_column(&row, "client_updated_at")?,
            egress_allowlist,
            egress_allow_cidrs,
        })
    }

    /// Exchange one actor's refresh credential before releasing an access token. Providers whose
    /// adapter requires rotation must durably commit the replacement first; a reviewed adapter may
    /// explicitly retain the existing refresh token when the vendor omits a replacement.
    pub async fn fresh_user_access_token<E: RotatingOAuthTokenExchanger + ?Sized>(
        &self,
        server_id: &str,
        actor: &ActorId,
        exchanger: &E,
    ) -> Result<VendorAccessToken, UserOAuthAccessError> {
        let admission = self
            .admission(SQL_STEPS_BUDGET + crate::mcp_oauth::MCP_OAUTH_ROUND_BUDGET)
            .await
            .map_err(UserOAuthAccessError::Selection)?;
        self.fresh_user_access_token_admitted(server_id, actor, exchanger, &admission)
            .await
    }

    /// Same refresh under the caller's held worker admission: rechecked before
    /// the Vault-opens, the claim, the token send (in the send fence) and the
    /// rotation commit.
    pub(crate) async fn fresh_user_access_token_admitted<
        E: RotatingOAuthTokenExchanger + ?Sized,
    >(
        &self,
        server_id: &str,
        actor: &ActorId,
        exchanger: &E,
        admission: &RecoveryWorkerLease<'_>,
    ) -> Result<VendorAccessToken, UserOAuthAccessError> {
        let prepared = self
            .prepare_admitted(server_id, actor, admission)
            .await
            .map_err(UserOAuthAccessError::Selection)?;
        current(admission).map_err(UserOAuthAccessError::Selection)?;
        let operation = self
            .claim_refresh(&prepared)
            .await
            .map_err(UserOAuthAccessError::Selection)?;
        let fence = OperationSendFence::new(self, &prepared, &operation, admission);
        let mut grant = match prepared.exchange_rotating(exchanger, &fence).await {
            Ok(grant) if fence.admitted() => grant,
            Ok(_) => {
                return Err(UserOAuthAccessError::Exchange(
                    OAuthTokenExchangeError::InvalidResponse,
                ));
            }
            Err(error) => {
                self.fail_refresh(
                    &operation,
                    matches!(
                        error,
                        OAuthTokenExchangeError::AuthRequired
                            | OAuthTokenExchangeError::InsufficientScope
                    ),
                )
                .await;
                return Err(UserOAuthAccessError::Exchange(error));
            }
        };
        if grant.refresh_token.is_none() && exchanger.requires_refresh_rotation() {
            self.fail_refresh(&operation, false).await;
            return Err(UserOAuthAccessError::Exchange(
                OAuthTokenExchangeError::InvalidResponse,
            ));
        }
        // A reusable provider may echo its current refresh token; that is not a rotation.
        if !exchanger.requires_refresh_rotation()
            && grant
                .refresh_token
                .as_ref()
                .is_some_and(|token| token.ct_eq(&prepared.refresh_token))
        {
            grant.refresh_token = None;
        }
        if let Err(error) = current(admission) {
            self.fail_refresh(&operation, false).await;
            return Err(UserOAuthAccessError::Selection(error));
        }
        if let Err(error) = self
            .finish_refresh(
                &prepared,
                &operation,
                grant.refresh_token.take(),
                grant.scope.take(),
            )
            .await
        {
            self.fail_refresh(&operation, false).await;
            return Err(UserOAuthAccessError::Selection(error));
        }
        Ok(VendorAccessToken(grant.access_token))
    }

    /// 列出一个 actor 的连接投影；空 actor 构造性拥有零连接。
    ///
    /// # Errors
    ///
    /// PostgreSQL 不可用或行解码失败时返回稳定错误。
    pub async fn connections_for(
        &self,
        actor: &ActorId,
    ) -> Result<Vec<UserOAuthConnection>, UserCredentialSelectionError> {
        if actor.as_str().is_empty() {
            return Ok(Vec::new());
        }
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "列出 per-user connections 获取连接失败");
            UserCredentialSelectionError::Unavailable
        })?;
        let rows = client
            .query(
                "SELECT server_id,scope,connected_at FROM public.mcp_user_credentials \
                 WHERE user_id=$1 ORDER BY server_id",
                &[&actor.as_str()],
            )
            .await
            .map_err(|error| {
                let safe = InfraError::query("列出 per-user connections", error);
                tracing::error!(error = %safe, "列出 per-user connections 查询失败");
                UserCredentialSelectionError::Unavailable
            })?;
        rows.iter()
            .map(|row| {
                Ok(UserOAuthConnection {
                    server_id: required_column(row, "server_id")?,
                    scope: required_column(row, "scope")?,
                    connected_at: required_column(row, "connected_at")?,
                })
            })
            .collect()
    }
}

/// End-to-end actor OAuth access failure. Secrets and remote response text never cross this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UserOAuthAccessError {
    /// PostgreSQL/Vault selection or rotation persistence failed.
    #[error("{0}")]
    Selection(UserCredentialSelectionError),
    /// Protected-resource discovery or token exchange failed.
    #[error("{0}")]
    Exchange(OAuthTokenExchangeError),
}

impl core::fmt::Debug for PluginUserCredentialStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PluginUserCredentialStore")
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

/// 人员移除后的 PostgreSQL credential 退役器。
///
/// 它按 `credentials(kind='mcp_user_token', key_id=owner)` 直接查 vault，因而能找到
/// `mcp_user_credentials` 已被 user FK cascade 删除后留下的孤儿。revoked_at、连接清理与每条
/// `mcp.account_disconnected` audit 在同一个事务提交。
#[derive(Clone)]
pub struct PostgresOwnedCredentialRetirer {
    pool: Pool,
    checkpoint_key: Arc<SecretBytes>,
    recovery_gate: crate::recovery_control::RecoveryReadGate,
}

impl PostgresOwnedCredentialRetirer {
    /// 构造；空 audit checkpoint key 立即拒绝。
    ///
    /// # Errors
    ///
    /// `checkpoint_key` 为空时返回 repository invariant。
    pub fn new(
        pool: Pool,
        checkpoint_key: impl Into<Vec<u8>>,
        recovery_gate: crate::recovery_control::RecoveryReadGate,
    ) -> Result<Self, InfraError> {
        let checkpoint_key = checkpoint_key.into();
        if checkpoint_key.is_empty() {
            return Err(InfraError::repository_invariant(
                "audit_checkpoint_key_empty",
            ));
        }
        Ok(Self {
            pool,
            checkpoint_key: Arc::new(SecretBytes::new(checkpoint_key)),
            recovery_gate,
        })
    }

    /// 退役 owner 的所有仍 active 的个人 token；重复调用与空 owner 返回 0。
    ///
    /// # Errors
    ///
    /// 任一 vault update、join delete 或 audit append 失败时整个本次退役事务回滚。
    pub async fn retire_connections_for(
        &self,
        owner: &ActorId,
        retired_by: &ActorId,
    ) -> Result<u64, InfraError> {
        if owner.as_str().is_empty() {
            return Ok(0);
        }
        if retired_by.as_str().is_empty() {
            return Err(InfraError::repository_invariant(
                "credential_retired_by_empty",
            ));
        }
        let owner_fact = AuditIdentifier::new(owner.as_str())
            .map_err(|_| InfraError::repository_invariant("credential_owner_not_audit_id"))?;
        // No caller binding reaches this port: a worker admission held through
        // the COMMIT (5 s precedent).
        let deadline = std::time::Instant::now() + SQL_STEPS_BUDGET;
        let admission = self
            .recovery_gate
            .borrow_worker_before(deadline)
            .await
            .map_err(|error| {
                InfraError::connect("recovery admission for credential retirement", error)
            })?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|error| InfraError::connect("为个人 credential 退役获取连接", error))?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| InfraError::query("开始个人 credential 退役事务", error))?;
        let rows = transaction
            .query(
                "UPDATE public.credentials SET revoked_at=clock_timestamp(),updated_at=clock_timestamp(),
                   metadata=coalesce(metadata,'{}'::jsonb)||
                            jsonb_build_object('revocation_status','pending',
                                               'revocation_reason','person_removed') \
                 WHERE kind='mcp_user_token' AND key_id=$1 AND revoked_at IS NULL \
                 RETURNING id,provider",
                &[&owner.as_str()],
            )
            .await
            .map_err(|error| InfraError::query("退役个人 credential", error))?;
        let mut retired = rows
            .iter()
            .map(|row| {
                Ok((
                    row.try_get::<_, Uuid>("id").map_err(|error| {
                        crate::db::RowDecodeError::column("credentials", "id", error)
                    })?,
                    row.try_get::<_, String>("provider").map_err(|error| {
                        crate::db::RowDecodeError::column("credentials", "provider", error)
                    })?,
                ))
            })
            .collect::<Result<Vec<_>, InfraError>>()?;
        retired.sort_by_key(|row| row.0);

        for (_, provider) in &retired {
            let target_id = AuditIdentifier::new(provider.as_str()).map_err(|_| {
                InfraError::repository_invariant("credential_provider_not_audit_id")
            })?;
            let payload = AuditPayload::from_facts([
                AuditFact::CredentialOwner(owner_fact.clone()),
                AuditFact::RevocationReason(AuditLabel::new("person_removed")),
                AuditFact::VendorRevoked(false),
            ])
            .map_err(|_| InfraError::repository_invariant("credential_audit_payload_invalid"))?;
            let (id, created_at) = next_event_coordinates(&transaction).await?;
            let event = AuditEvent {
                id,
                actor: Some(retired_by.clone()),
                event_type: AuditEventType::parse("mcp.account_disconnected")
                    .expect("catalog 含 account disconnected"),
                target_kind: AuditLabel::new("mcp_server"),
                target_id: Some(target_id),
                payload,
                created_at,
            };
            append_event_in_transaction(&transaction, &event, self.checkpoint_key.expose()).await?;
        }

        transaction
            .execute(
                "DELETE FROM public.mcp_user_credentials WHERE user_id=$1",
                &[&owner.as_str()],
            )
            .await
            .map_err(|error| InfraError::query("删除已退役个人 connection", error))?;
        admission.verify_current_before(deadline).map_err(|error| {
            InfraError::connect("recovery admission for credential retirement", error)
        })?;
        transaction
            .commit()
            .await
            .map_err(|error| InfraError::query("提交个人 credential 退役事务", error))?;
        u64::try_from(retired.len())
            .map_err(|_| InfraError::repository_invariant("credential_retired_count_overflow"))
    }
}

impl core::fmt::Debug for PostgresOwnedCredentialRetirer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresOwnedCredentialRetirer")
            .field("checkpoint_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl OwnedCredentialRetirer for PostgresOwnedCredentialRetirer {
    async fn retire_owned_credentials(
        &self,
        owner: &ActorId,
        retired_by: &ActorId,
    ) -> Result<u64, OwnedCredentialRetirementError> {
        self.retire_connections_for(owner, retired_by)
            .await
            .map_err(|error| {
                let mapped = match error {
                    InfraError::RowDecode(_) | InfraError::RepositoryInvariant { .. } => {
                        OwnedCredentialRetirementError::Corrupt {
                            field: "credential",
                        }
                    }
                    _ => OwnedCredentialRetirementError::Unavailable,
                };
                tracing::error!(error = %error, "个人 credential 退役失败");
                mapped
            })
    }
}

/// SQL-only steps without a per-step bound: the 5 s precedent.
const SQL_STEPS_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

fn current(admission: &RecoveryWorkerLease<'_>) -> Result<(), UserCredentialSelectionError> {
    admission
        .verify_current_before(admission.deadline())
        .map_err(|_| UserCredentialSelectionError::Unavailable)
}

const SELECTION_SQL: &str = "SELECT s.url AS server_endpoint, \
            coalesce(owner.auth_generation,0) AS auth_generation, \
            (owner.id IS NOT NULL AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=owner.id) \
             AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(owner.email))) AS actor_current, \
            coalesce(s.credential_generation,0) AS server_generation, \
            s.updated_at AS server_updated_at,d.updated_at AS client_updated_at, \
            coalesce(s.transport,'mcp') AS server_transport, \
            coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs, \
            uc.credential_id AS user_pointer,uc.scope AS granted_scope, \
            u.id AS user_credential_id,u.kind AS user_kind,u.provider AS user_provider, \
            u.encrypted_value AS user_encrypted_value,u.key_id AS user_key_id, \
            u.revoked_at AS user_revoked_at, \
            s.credential_id AS deployment_pointer, \
            d.id AS deployment_credential_id,d.kind AS deployment_kind, \
            d.provider AS deployment_provider,d.encrypted_value AS deployment_encrypted_value, \
            d.revoked_at AS deployment_revoked_at \
     FROM public.mcp_servers s \
     LEFT JOIN public.mcp_user_credentials uc ON uc.server_id=s.id AND uc.user_id=$2 \
     LEFT JOIN public.credentials u ON u.id=uc.credential_id \
     LEFT JOIN public.credentials d ON d.id=s.credential_id \
     LEFT JOIN public.users owner ON owner.id=$2 \
     WHERE s.id=$1";

fn optional_column<T: FromSqlOwned>(
    row: &tokio_postgres::Row,
    column: &'static str,
) -> Result<Option<T>, UserCredentialSelectionError> {
    row.try_get(column).map_err(|error| {
        tracing::error!(column, error = %error, "per-user credential 行解码失败");
        UserCredentialSelectionError::Corrupt { field: column }
    })
}

fn required_joined<T: FromSqlOwned>(
    row: &tokio_postgres::Row,
    column: &'static str,
) -> Result<T, UserCredentialSelectionError> {
    optional_column(row, column)?.ok_or(UserCredentialSelectionError::Corrupt { field: column })
}

fn required_column<T: FromSqlOwned>(
    row: &tokio_postgres::Row,
    column: &'static str,
) -> Result<T, UserCredentialSelectionError> {
    row.try_get(column).map_err(|error| {
        tracing::error!(column, error = %error, "per-user connection 行解码失败");
        UserCredentialSelectionError::Corrupt { field: column }
    })
}
