//! PostgreSQL/Vault implementation of MCP OAuth connect, callback and local-first disconnect.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::db::pool::DatabasePool as Pool;
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use deadpool_postgres::GenericClient;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use openbot_application::{
    McpConnectionAdministration, McpConnectionError, McpOAuthCallback, McpOAuthCallbackInput,
    McpOAuthCallbackOutcome,
};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::mcp::{
    GrantedPluginSkill, GrantedPluginTool, GrantedPlugins, MAX_SKILL_INSTRUCTIONS_BYTES,
    McpAdminAuthentication, McpAdminCatalogueEntry, McpAdminPage, McpAdminServer, McpAdminSkill,
    McpAdminTool, McpAdminToolEffect, McpConnection, McpConnectionDisconnected, McpConnections,
    McpCustomServerRegistration, McpOAuthAuthorization, McpOAuthClientAuthMethod,
    McpOAuthClientRegistered, McpOAuthClientRegistration, McpOAuthReturnTo, McpServerMutation,
    McpServerRemoved, McpVendorRevocationStatus, PluginGrantKind, PluginGrantMutation,
    PluginMutationAcknowledged, PluginSkillMutation, PluginSkills,
};
use openbot_domain::agent::profile_policy::{AgentActor, AgentProfileFacts, can_access_agent};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_postgres::IsolationLevel;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::db::types::CredentialKind;
use crate::google_drive::{
    GOOGLE_DRIVE_API_BASE, GOOGLE_DRIVE_PROVENANCE, GOOGLE_DRIVE_READONLY_SCOPE,
    GOOGLE_DRIVE_SERVER_ID, GOOGLE_DRIVE_TRANSPORT, GOOGLE_DRIVE_VENDOR,
};
use crate::google_drive_oauth::{GoogleDriveOAuthClient, GoogleDriveOAuthError};
use crate::mcp::McpBearerToken;
use crate::mcp_catalog::{
    McpCatalogError, McpCatalogRefresh, PostgresMcpCatalog, VendorTransportKind,
};
use crate::mcp_credentials::{McpCredentialError, PostgresMcpCredentialBroker};
use crate::mcp_egress::{MAX_MCP_EGRESS_CIDR_BYTES, MAX_MCP_EGRESS_CIDRS, parse_stored_mcp_egress};
use crate::mcp_oauth::{McpOAuthClient, McpOAuthError};
use crate::net::safe_http::{CidrAllowlist, SchemePolicy};
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::vault::CredentialRecordVault;

mod skill_editing;

type HmacSha256 = Hmac<Sha256>;

const CALLBACK_PATH: &str = "/api/plugins/oauth/callback";
const ATTEMPT_TTL: Duration = Duration::minutes(10);
const ATTEMPT_LOCK_KEY: i64 = 0x4f50_4d43_504f_4131; // `OPMCPOA1`
// v3 binds the reviewed vendor transport and exact private-egress authority into the sealed
// one-time attempt. Older attempts fail closed after an upgrade instead of being reinterpreted.
const ATTEMPT_VERSION: u8 = 3;
const MAX_ATTEMPT_VALUE_BYTES: usize = 32 * 1024;
const DEFAULT_ATTEMPT_CAPACITY: usize = 4096;
const REVOCATION_BATCH: i64 = 32;
const REVOCATION_RETRY_INTERVAL: StdDuration = StdDuration::from_secs(30);
const MAX_CUSTOM_SERVER_ID_BYTES: usize = 40;
const MAX_CUSTOM_SERVER_TITLE_BYTES: usize = 256;
const MAX_CUSTOM_SERVER_URL_BYTES: usize = 8 * 1024;
const MAX_SKILL_TITLE_BYTES: usize = 256;
const MAX_SKILL_SUMMARY_BYTES: usize = 4 * 1024;
const PLUGIN_ADMIN_LOCK_SEED: i64 = 0x504c_5547_494e_4131; // `PLUGINA1`

/// Production MCP OAuth connection coordinator.
#[derive(Clone)]
pub struct PostgresMcpConnections {
    pool: Pool,
    vault: CredentialRecordVault,
    oauth: McpOAuthClient,
    drive_oauth: Option<GoogleDriveOAuthClient>,
    credentials: Option<Arc<PostgresMcpCredentialBroker>>,
    catalog: Arc<PostgresMcpCatalog>,
    deployment: DeploymentId,
    tenant: TenantId,
    state_key: Arc<SecretBytes>,
    checkpoint_key: Arc<SecretBytes>,
    tenant_scope: String,
    callback_uri: Option<String>,
    app_origin: Option<String>,
    capacity: usize,
}

/// One pending-revocation sweep summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct McpRevocationSweep {
    /// Tombstones claimed for this sweep.
    pub attempted: usize,
    /// Vendor revocations confirmed and durably audited.
    pub revoked: usize,
    /// Claims returned to pending for a later retry.
    pub pending: usize,
    /// Claims whose retained local material cannot safely drive another automatic attempt.
    pub operator_required: usize,
}

/// Lifecycle handle for periodic pending vendor-revocation reconciliation.
pub struct McpRevocationReconciler {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    capture_stop_requested: bool,
    capture_stop: Option<Result<(), McpReconcilerStopFailure>>,
}

/// Actual original reconciler join, without SQL, endpoint or vendor diagnostic text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpReconcilerStopFailure {
    /// The original reconciler was cancelled.
    Cancelled,
    /// The original reconciler panicked.
    Panicked,
}

impl McpRevocationReconciler {
    /// Start an immediate sweep followed by bounded 30-second retry intervals.
    #[must_use]
    pub fn start(connections: Arc<PostgresMcpConnections>) -> Self {
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(supervise_revocations(connections, stop_rx));
        Self {
            stop,
            task: Some(task),
            capture_stop_requested: false,
            capture_stop: None,
        }
    }

    /// Stop claiming new tombstones and wait for the current bounded sweep.
    pub async fn stop(mut self) {
        let _ = self.stop_for_capture().await;
    }

    /// Borrow the original handle; interrupted waits retain it and cached results send no
    /// additional stop request. Failure is permanent for this exact original task.
    pub async fn stop_for_capture(&mut self) -> Result<(), McpReconcilerStopFailure> {
        if let Some(result) = self.capture_stop {
            return result;
        }
        if !self.capture_stop_requested {
            self.stop.send_replace(true);
            self.capture_stop_requested = true;
        }
        let result = match self.task.as_mut() {
            Some(task) => match task.await {
                Ok(()) => Ok(()),
                Err(error) if error.is_cancelled() => Err(McpReconcilerStopFailure::Cancelled),
                Err(_) => Err(McpReconcilerStopFailure::Panicked),
            },
            None => Err(McpReconcilerStopFailure::Cancelled),
        };
        self.task = None;
        self.capture_stop = Some(result);
        result
    }
}

impl core::fmt::Debug for McpRevocationReconciler {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("McpRevocationReconciler")
            .finish_non_exhaustive()
    }
}

impl PostgresMcpConnections {
    /// Construct from production network, vault, catalog and deployment-owned addresses/keys.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: Pool,
        vault: CredentialRecordVault,
        oauth: McpOAuthClient,
        catalog: Arc<PostgresMcpCatalog>,
        deployment: DeploymentId,
        tenant: TenantId,
        state_key: Vec<u8>,
        checkpoint_key: Vec<u8>,
        public_url: Option<&str>,
        app_url: Option<&str>,
        callback_scheme_policy: SchemePolicy,
    ) -> Result<Self, McpConnectionError> {
        if state_key.len() < 32 || checkpoint_key.is_empty() {
            return Err(McpConnectionError::Corrupt { field: "oauth_key" });
        }
        let callback_uri = public_url
            .map(|value| callback_uri(value, callback_scheme_policy))
            .transpose()?;
        let app_origin = app_url
            .map(validate_app_origin)
            .transpose()?
            .map(|value| value.trim_end_matches('/').to_owned());
        let tenant_scope = hex(&Sha256::digest(
            [
                b"openbot-mcp-oauth-attempt-tenant-v1\0".as_slice(),
                deployment.as_str().as_bytes(),
                b"\0",
                tenant.as_str().as_bytes(),
            ]
            .concat(),
        ));
        Ok(Self {
            pool,
            vault,
            oauth,
            drive_oauth: None,
            credentials: None,
            catalog,
            deployment,
            tenant,
            state_key: Arc::new(SecretBytes::new(state_key)),
            checkpoint_key: Arc::new(SecretBytes::new(checkpoint_key)),
            tenant_scope,
            callback_uri,
            app_origin,
            capacity: DEFAULT_ATTEMPT_CAPACITY,
        })
    }

    /// Attach the curated Google Drive web-server OAuth adapter. Without it, Drive connect,
    /// callback and vendor-revocation operations fail closed while remote MCP remains available.
    #[must_use]
    pub fn with_google_drive_oauth(mut self, oauth: GoogleDriveOAuthClient) -> Self {
        self.drive_oauth = Some(oauth);
        self
    }

    /// Attach the same fresh per-operation credential broker used by the Agent tool runtime.
    #[must_use]
    pub fn with_mcp_credentials(mut self, credentials: Arc<PostgresMcpCredentialBroker>) -> Self {
        self.credentials = Some(credentials);
        self
    }

    async fn admin_page_projection(
        &self,
        auth: &AuthContext,
    ) -> Result<McpAdminPage, McpConnectionError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(query_unavailable)?;
        ensure_transaction_actor(&transaction, auth, auth.has_role(Role::Admin)).await?;
        let is_admin = auth.has_role(Role::Admin);
        let active_grants = transaction
            .query(
                "SELECT g.ref,g.agent_id
                   FROM public.plugin_grants g
                   JOIN public.mcp_tools t
                     ON g.kind='mcp' AND g.ref=t.server_id||'/'||t.name
                   JOIN public.mcp_servers s ON s.id=t.server_id
                   JOIN public.agents a ON a.id=g.agent_id
                   JOIN public.agent_profiles p ON p.agent_id=a.id
                   LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
                  WHERE g.state='active' AND t.available=true
                    AND s.catalog_generation IS NOT NULL
                    AND g.catalog_generation=s.catalog_generation
                    AND t.catalog_generation=s.catalog_generation
                    AND g.schema_hash=t.schema_hash AND g.effect=t.effect
                    AND g.transport_fingerprint=s.catalog_transport_fingerprint
                    AND g.credential_generation=coalesce(s.credential_generation,0)
                    AND p.deleted_at IS NULL
                    AND (a.package_id IS NULL OR dp.tenant_id=$3)
                    AND ($2::boolean OR p.visibility='public' OR p.owner_user_id=$1)
                  ORDER BY g.ref,g.agent_id",
                &[&auth.actor().as_str(), &is_admin, &self.tenant.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        let mut grants = BTreeMap::<String, Vec<String>>::new();
        for row in active_grants {
            let reference: String = row.try_get("ref").map_err(|_| corrupt("grant_ref"))?;
            let agent_id: String = row
                .try_get("agent_id")
                .map_err(|_| corrupt("grant_agent_id"))?;
            grants.entry(reference).or_default().push(agent_id);
        }

        let tool_rows = transaction
            .query(
                "SELECT t.server_id,t.name,t.description,t.input_schema,t.effect
                   FROM public.mcp_tools t
                   JOIN public.mcp_servers s ON s.id=t.server_id
                  WHERE t.available=true AND s.catalog_generation IS NOT NULL
                    AND t.catalog_generation=s.catalog_generation
                  ORDER BY t.server_id,t.name",
                &[],
            )
            .await
            .map_err(query_unavailable)?;
        let mut tools_by_server = BTreeMap::<String, Vec<McpAdminTool>>::new();
        for row in tool_rows {
            let server_id: String = row.try_get("server_id").map_err(|_| corrupt("server_id"))?;
            let name: String = row.try_get("name").map_err(|_| corrupt("tool_name"))?;
            validate_server_id(&server_id)?;
            validate_tool_component(&name)?;
            let reference = format!("{server_id}/{name}");
            let description: String = row
                .try_get("description")
                .map_err(|_| corrupt("description"))?;
            if description.len() > crate::mcp::MAX_MCP_TOOL_DESCRIPTION_BYTES
                || description.as_bytes().contains(&0)
            {
                return Err(corrupt("description"));
            }
            let input_schema: serde_json::Value = row
                .try_get("input_schema")
                .map_err(|_| corrupt("input_schema"))?;
            let effect: String = row.try_get("effect").map_err(|_| corrupt("effect"))?;
            tools_by_server
                .entry(server_id.clone())
                .or_default()
                .push(McpAdminTool {
                    server_id,
                    name,
                    description,
                    input_schema,
                    reference: reference.clone(),
                    effect: admin_effect(&effect)?,
                    granted_to: grants.remove(&reference).unwrap_or_default(),
                });
        }
        if !grants.is_empty() {
            return Err(corrupt("active_grant_projection"));
        }

        let server_rows = transaction
            .query(
                "SELECT s.id,s.title,s.vendor,s.url,s.provenance,s.credential_id,s.tools_refreshed_at,
                        s.last_error,s.added_by,c.kind AS credential_kind,
                        coalesce(s.transport,'mcp') AS transport,
                        coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs
                   FROM public.mcp_servers s
                   LEFT JOIN public.credentials c ON c.id=s.credential_id ORDER BY s.title,s.id",
                &[],
            )
            .await
            .map_err(query_unavailable)?;
        let mut servers = Vec::with_capacity(server_rows.len());
        for row in server_rows {
            let id: String = row.try_get("id").map_err(|_| corrupt("server_id"))?;
            validate_server_id(&id)?;
            let title: String = row.try_get("title").map_err(|_| corrupt("title"))?;
            let vendor: String = row.try_get("vendor").map_err(|_| corrupt("vendor"))?;
            let url: String = row.try_get("url").map_err(|_| corrupt("server_endpoint"))?;
            let provenance: String = row
                .try_get("provenance")
                .map_err(|_| corrupt("provenance"))?;
            let transport = VendorTransportKind::parse(
                &row.try_get::<_, String>("transport")
                    .map_err(|_| corrupt("transport"))?,
            )
            .map_err(|_| corrupt("transport"))?;
            let egress_allow_cidrs: Vec<String> = row
                .try_get("egress_allow_cidrs")
                .map_err(|_| corrupt("egress_allow_cidrs"))?;
            validate_stored_egress(&egress_allow_cidrs)?;
            validate_public_server_projection(
                &id,
                &title,
                &vendor,
                &url,
                &provenance,
                transport,
                &egress_allow_cidrs,
            )?;
            let (summary, docs_url) = if id == GOOGLE_DRIVE_SERVER_ID {
                (
                    "Files in the Drive of whoever is asking.".to_owned(),
                    "https://developers.google.com/workspace/guides/configure-mcp-servers"
                        .to_owned(),
                )
            } else {
                (String::new(), String::new())
            };
            let raw_error: Option<String> = row
                .try_get("last_error")
                .map_err(|_| corrupt("last_error"))?;
            servers.push(McpAdminServer {
                id: id.clone(),
                title,
                vendor,
                url,
                summary,
                docs_url,
                provenance,
                authentication: match (
                    transport,
                    row.try_get::<_, Option<CredentialKind>>("credential_kind")
                        .map_err(|_| corrupt("credential_kind"))?,
                ) {
                    (VendorTransportKind::GoogleDriveRest, _)
                    | (_, Some(CredentialKind::McpOauthClient)) => {
                        McpAdminAuthentication::UserOAuth
                    }
                    (VendorTransportKind::Mcp, Some(CredentialKind::Mcp)) => {
                        McpAdminAuthentication::DeploymentBearer
                    }
                    (VendorTransportKind::Mcp, None) => McpAdminAuthentication::None,
                    _ => return Err(corrupt("credential_kind")),
                },
                has_credential: row
                    .try_get::<_, Option<Uuid>>("credential_id")
                    .map_err(|_| corrupt("credential_id"))?
                    .is_some(),
                tools_refreshed_at: row
                    .try_get("tools_refreshed_at")
                    .map_err(|_| corrupt("tools_refreshed_at"))?,
                last_error: raw_error.map(|_| "mcp_catalog_unavailable".to_owned()),
                added_by: row.try_get("added_by").map_err(|_| corrupt("added_by"))?,
                egress_allow_cidrs,
                tools: tools_by_server.remove(&id).unwrap_or_default(),
            });
        }
        if !tools_by_server.is_empty() {
            return Err(corrupt("tool_server_projection"));
        }

        let skills = visible_skills(&transaction, auth, &self.tenant).await?;
        let page = McpAdminPage {
            catalogue: vec![McpAdminCatalogueEntry {
                key: GOOGLE_DRIVE_SERVER_ID.to_owned(),
                title: "Google Drive".to_owned(),
                vendor: GOOGLE_DRIVE_VENDOR.to_owned(),
                summary: "Files in the Drive of whoever is asking.".to_owned(),
                docs_url: "https://developers.google.com/workspace/guides/configure-mcp-servers"
                    .to_owned(),
                auth: McpAdminAuthentication::UserOAuth,
                per_instance: false,
            }],
            bots_may_call_back: false,
            servers,
            skills,
            redirect_uri: self.callback_uri.clone(),
        };
        transaction.commit().await.map_err(query_unavailable)?;
        Ok(page)
    }

    async fn refresh_configured_catalog(
        &self,
        auth: &AuthContext,
        server_id: &str,
    ) -> Result<McpServerMutation, McpConnectionError> {
        validate_server_id(server_id)?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                "SELECT title,url,vendor,provenance,coalesce(transport,'mcp') AS transport,
                        credential_id,
                        coalesce(egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs
                   FROM public.mcp_servers WHERE id=$1",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpConnectionError::NotVisible)?;
        let title: String = row.try_get("title").map_err(|_| corrupt("title"))?;
        let endpoint: String = row.try_get("url").map_err(|_| corrupt("server_endpoint"))?;
        let vendor: String = row.try_get("vendor").map_err(|_| corrupt("vendor"))?;
        let provenance: String = row
            .try_get("provenance")
            .map_err(|_| corrupt("provenance"))?;
        let transport = VendorTransportKind::parse(
            &row.try_get::<_, String>("transport")
                .map_err(|_| corrupt("transport"))?,
        )
        .map_err(|_| corrupt("transport"))?;
        let credential_id: Option<Uuid> = row
            .try_get("credential_id")
            .map_err(|_| corrupt("credential_id"))?;
        let egress_allow_cidrs: Vec<String> = row
            .try_get("egress_allow_cidrs")
            .map_err(|_| corrupt("egress_allow_cidrs"))?;
        validate_stored_egress(&egress_allow_cidrs)?;
        validate_public_server_projection(
            server_id,
            &title,
            &vendor,
            &endpoint,
            &provenance,
            transport,
            &egress_allow_cidrs,
        )?;
        let bearer = match (provenance.as_str(), transport, credential_id) {
            (GOOGLE_DRIVE_PROVENANCE, VendorTransportKind::GoogleDriveRest, _)
                if server_id == GOOGLE_DRIVE_SERVER_ID =>
            {
                None
            }
            ("custom", VendorTransportKind::Mcp, None) => None,
            ("custom", VendorTransportKind::Mcp, Some(_)) => self
                .credentials
                .as_ref()
                .ok_or(McpConnectionError::Unavailable)?
                .bearer_for(server_id, auth.actor())
                .await
                .map_err(map_credential_failure)?,
            _ => return Err(corrupt("server_authentication")),
        };
        drop(client);
        let refresh = match self.catalog.refresh(server_id, bearer).await {
            Ok(refresh) => refresh,
            Err(error) => {
                if let Ok(client) = self.pool.get().await {
                    let _ = client
                        .execute(
                            "UPDATE public.mcp_servers SET last_error='mcp_catalog_unavailable',
                               updated_at=clock_timestamp() WHERE id=$1",
                            &[&server_id],
                        )
                        .await;
                }
                return Err(map_catalog_failure(error));
            }
        };
        mutation_receipt(server_id, &refresh)
    }

    async fn load_server_client(
        &self,
        server_id: &str,
    ) -> Result<ServerClientMaterial, McpConnectionError> {
        validate_server_id(server_id)?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                "SELECT s.url,s.vendor,s.provenance,coalesce(s.transport,'mcp') AS transport,
                        coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs,
                        s.credential_id,c.kind,c.provider,c.encrypted_value,c.revoked_at
                   FROM public.mcp_servers s
                   LEFT JOIN public.credentials c ON c.id=s.credential_id
                  WHERE s.id=$1",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpConnectionError::NotVisible)?;
        let endpoint: String = row.try_get("url").map_err(|_| corrupt("server_endpoint"))?;
        let vendor: String = row.try_get("vendor").map_err(|_| corrupt("vendor"))?;
        let provenance: String = row
            .try_get("provenance")
            .map_err(|_| corrupt("provenance"))?;
        let transport = VendorTransportKind::parse(
            &row.try_get::<_, String>("transport")
                .map_err(|_| corrupt("transport"))?,
        )
        .map_err(|_| corrupt("transport"))?;
        let egress_allow_cidrs: Vec<String> = row
            .try_get("egress_allow_cidrs")
            .map_err(|_| corrupt("egress_allow_cidrs"))?;
        let egress_allowlist = parse_stored_mcp_egress(&egress_allow_cidrs)
            .map_err(|_| corrupt("egress_allow_cidrs"))?;
        if transport == VendorTransportKind::GoogleDriveRest
            && (server_id != GOOGLE_DRIVE_SERVER_ID
                || endpoint != GOOGLE_DRIVE_API_BASE
                || vendor != GOOGLE_DRIVE_VENDOR
                || provenance != GOOGLE_DRIVE_PROVENANCE
                || !egress_allowlist.is_empty())
        {
            return Err(corrupt("transport_identity"));
        }
        let credential_id: Option<Uuid> = row
            .try_get("credential_id")
            .map_err(|_| corrupt("oauth_client_id"))?;
        let kind: Option<crate::db::types::CredentialKind> = row
            .try_get("kind")
            .map_err(|_| corrupt("oauth_client_kind"))?;
        let provider: Option<String> = row
            .try_get("provider")
            .map_err(|_| corrupt("oauth_client_provider"))?;
        let encrypted: Option<String> = row
            .try_get("encrypted_value")
            .map_err(|_| corrupt("oauth_client_value"))?;
        let revoked: Option<OffsetDateTime> = row
            .try_get("revoked_at")
            .map_err(|_| corrupt("oauth_client_revoked_at"))?;
        let credential_id = credential_id.ok_or(McpConnectionError::Conflict {
            resource: "mcp_oauth_client",
        })?;
        if kind != Some(crate::db::types::CredentialKind::McpOauthClient)
            || provider.as_deref() != Some(server_id)
            || revoked.is_some()
        {
            return Err(McpConnectionError::Conflict {
                resource: "mcp_oauth_client",
            });
        }
        let secret = self
            .vault
            .open(
                &credential_id,
                SecretKind::McpOauthClient,
                SecretPrincipal::Deployment,
                SecretPrincipal::Service(ServiceId::new(server_id)),
                encrypted
                    .as_deref()
                    .ok_or_else(|| corrupt("oauth_client_value"))?,
            )
            .map_err(|error| {
                tracing::error!(code = %error, "MCP OAuth client 密文被拒");
                corrupt("oauth_client_value")
            })?
            .into_secret();
        Ok(ServerClientMaterial {
            credential_id,
            endpoint,
            client: secret,
            transport,
            egress_allow_cidrs,
            egress_allowlist,
        })
    }

    async fn ensure_auth_current(&self, auth: &AuthContext) -> Result<(), McpConnectionError> {
        if auth.deployment() != &self.deployment || auth.tenant() != &self.tenant {
            return Err(McpConnectionError::NotVisible);
        }
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let current: bool = client
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM public.users u
                     WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                       AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                       AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                       WHERE ra.email=lower(u.email)))",
                &[&auth.actor().as_str(), &generation],
            )
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("actor_scope"))?;
        if current {
            Ok(())
        } else {
            Err(McpConnectionError::NotVisible)
        }
    }

    async fn insert_attempt(
        &self,
        state: &str,
        attempt: &StoredAttempt,
    ) -> Result<(), McpConnectionError> {
        let identifier = self.state_identifier(state)?;
        let value = self.seal_attempt(attempt)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(attempt.expires_at_unix_seconds)
            .map_err(|_| corrupt("attempt_expiry"))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&ATTEMPT_LOCK_KEY])
            .await
            .map_err(query_unavailable)?;
        let now: OffsetDateTime = transaction
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("clock"))?;
        let prefix = format!("mcp-oauth-attempt:{}:%", self.tenant_scope);
        transaction
            .execute(
                "DELETE FROM public.verifications WHERE identifier LIKE $1 AND expires_at<=$2",
                &[&prefix, &now],
            )
            .await
            .map_err(query_unavailable)?;
        let count: i64 = transaction
            .query_one(
                "SELECT count(*)::bigint FROM public.verifications WHERE identifier LIKE $1",
                &[&prefix],
            )
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("attempt_count"))?;
        if usize::try_from(count).map_err(|_| corrupt("attempt_count"))? >= self.capacity {
            return Err(McpConnectionError::Conflict {
                resource: "mcp_oauth_attempt_capacity",
            });
        }
        let current = transaction
            .query_opt(
                "SELECT u.id FROM public.users u
                   JOIN public.mcp_servers s ON s.id=$3
                  WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                    AND s.url=$4 AND s.credential_id=$5
                    AND coalesce(s.transport,'mcp')=$6
                    AND coalesce(s.egress_allow_cidrs,ARRAY[]::text[])=$7
                    AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                    WHERE ra.email=lower(u.email))
                  FOR SHARE OF u,s",
                &[
                    &attempt.actor_id,
                    &attempt.auth_generation,
                    &attempt.server_id,
                    &attempt.resource,
                    &attempt.client_credential_id,
                    &attempt.transport,
                    &attempt.egress_allow_cidrs,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if current.is_none() {
            return Err(McpConnectionError::NotVisible);
        }
        let id = Uuid::now_v7().to_string();
        transaction
            .execute(
                "INSERT INTO public.verifications(id,identifier,value,expires_at,created_at,updated_at)
                 VALUES($1,$2,$3,$4,$5,$5)",
                &[&id, &identifier, &value, &expires_at, &now],
            )
            .await
            .map_err(query_unavailable)?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "MCP OAuth attempt commit 结果未知");
            McpConnectionError::CommitUnknown
        })
    }

    async fn consume_attempt(&self, state: &[u8]) -> Result<StoredAttempt, McpConnectionError> {
        let state = core::str::from_utf8(state).map_err(|_| McpConnectionError::NotVisible)?;
        let identifier = self.state_identifier(state)?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let rows = transaction
            .query(
                "DELETE FROM public.verifications WHERE identifier=$1
                 RETURNING value,expires_at,clock_timestamp() AS consumed_at",
                &[&identifier],
            )
            .await
            .map_err(query_unavailable)?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "MCP OAuth state consume commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        if rows.len() != 1 {
            return Err(McpConnectionError::NotVisible);
        }
        let value: String = rows[0]
            .try_get("value")
            .map_err(|_| corrupt("attempt_value"))?;
        let column_expiry: OffsetDateTime = rows[0]
            .try_get("expires_at")
            .map_err(|_| corrupt("attempt_expiry"))?;
        let consumed_at: OffsetDateTime = rows[0]
            .try_get("consumed_at")
            .map_err(|_| corrupt("clock"))?;
        let attempt = self.open_attempt(&value)?;
        if attempt.version != ATTEMPT_VERSION
            || attempt.deployment_id != self.deployment.as_str()
            || attempt.tenant_id != self.tenant.as_str()
            || self.callback_uri.as_deref() != Some(attempt.redirect_uri.as_str())
            || attempt.expires_at_unix_seconds != column_expiry.unix_timestamp()
            || attempt_is_expired(attempt.expires_at_unix_seconds, consumed_at)
            || !valid_server_id(&attempt.server_id)
            || !valid_pkce(&attempt.code_verifier)
            || parse_stored_mcp_egress(&attempt.egress_allow_cidrs).is_err()
        {
            return Err(corrupt("attempt"));
        }
        Ok(attempt)
    }

    fn state_identifier(&self, state: &str) -> Result<String, McpConnectionError> {
        if state.is_empty()
            || state.len() > 512
            || !state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(McpConnectionError::NotVisible);
        }
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.state_key.expose())
            .map_err(|_| corrupt("state_key"))?;
        mac.update(b"openbot-mcp-oauth-state-v1\0");
        mac.update(self.tenant_scope.as_bytes());
        mac.update(b"\0");
        mac.update(state.as_bytes());
        Ok(format!(
            "mcp-oauth-attempt:{}:{}",
            self.tenant_scope,
            hex(&mac.finalize().into_bytes())
        ))
    }

    fn seal_attempt(&self, attempt: &StoredAttempt) -> Result<String, McpConnectionError> {
        let key = self.attempt_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| corrupt("state_key"))?;
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| McpConnectionError::Unavailable)?;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(attempt).map_err(|_| corrupt("attempt_value"))?);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: self.tenant_scope.as_bytes(),
                },
            )
            .map_err(|_| corrupt("attempt_value"))?;
        let mut encoded = Vec::with_capacity(nonce.len() + ciphertext.len());
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(encoded))
    }

    fn open_attempt(&self, value: &str) -> Result<StoredAttempt, McpConnectionError> {
        if value.is_empty() || value.len() > MAX_ATTEMPT_VALUE_BYTES {
            return Err(corrupt("attempt_value"));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| corrupt("attempt_value"))?;
        if decoded.len() <= 12 {
            return Err(corrupt("attempt_value"));
        }
        let key = self.attempt_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| corrupt("state_key"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&decoded[..12]),
                    Payload {
                        msg: &decoded[12..],
                        aad: self.tenant_scope.as_bytes(),
                    },
                )
                .map_err(|_| corrupt("attempt_value"))?,
        );
        serde_json::from_slice(&plaintext).map_err(|_| corrupt("attempt_value"))
    }

    fn attempt_encryption_key(&self) -> Result<Zeroizing<[u8; 32]>, McpConnectionError> {
        let mut key = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(
            Some(b"openbot-mcp-oauth-attempt-aead-v1"),
            self.state_key.expose(),
        )
        .expand(self.tenant_scope.as_bytes(), &mut *key)
        .map_err(|_| corrupt("state_key"))?;
        Ok(key)
    }

    async fn complete_inner(
        &self,
        input: &McpOAuthCallbackInput,
    ) -> Result<String, McpConnectionError> {
        // State is burned before code/issuer validation or any vendor request.
        let attempt = self.consume_attempt(input.state()).await?;
        if input.code().is_empty() {
            return Err(McpConnectionError::VendorFailure);
        }
        match input.issuer() {
            Some(issuer) if issuer == attempt.issuer => {}
            Some(_) => return Err(McpConnectionError::VendorFailure),
            None if attempt.issuer_required => return Err(McpConnectionError::VendorFailure),
            None => {}
        }
        self.ensure_stored_actor_current(&attempt).await?;
        let material = self.load_server_client(&attempt.server_id).await?;
        if material.credential_id != attempt.client_credential_id
            || material.endpoint != attempt.resource
            || material.transport.as_str() != attempt.transport
            || material.egress_allow_cidrs != attempt.egress_allow_cidrs
        {
            return Err(McpConnectionError::NotVisible);
        }
        let (access, refresh, scope) = match material.transport {
            VendorTransportKind::Mcp => self
                .oauth
                .with_egress_allowlist(material.egress_allowlist.clone())
                .exchange_authorization_code(
                    &material.endpoint,
                    material.client.expose(),
                    input.code(),
                    &attempt.redirect_uri,
                    attempt.code_verifier.as_bytes(),
                    &attempt.requested_scope,
                )
                .await
                .map_err(map_oauth_vendor)?
                .into_parts(),
            VendorTransportKind::GoogleDriveRest => self
                .drive_oauth
                .as_ref()
                .ok_or(McpConnectionError::Conflict {
                    resource: "google_drive_oauth_runtime",
                })?
                .exchange_authorization_code(
                    material.client.expose(),
                    input.code(),
                    &attempt.redirect_uri,
                    attempt.code_verifier.as_bytes(),
                )
                .await
                .map_err(map_drive_oauth_vendor)?
                .into_parts(),
        };
        let old = self
            .persist_connection(&attempt, &material, &refresh, &scope)
            .await?;

        // Catalog failure does not roll back a valid connection; it remains invisible until a later
        // refresh rather than lying that consent failed after the credential transaction committed.
        let catalog_bearer = match material.transport {
            VendorTransportKind::Mcp => McpBearerToken::from_secret(access).map(Some).ok(),
            VendorTransportKind::GoogleDriveRest => Some(None),
        };
        if let Some(bearer) = catalog_bearer
            && let Err(error) = self.catalog.refresh(&attempt.server_id, bearer).await
        {
            tracing::warn!(code = %error, "MCP OAuth callback 后 catalog refresh 失败");
        }
        if let Some(old) = old {
            self.try_vendor_revoke(&attempt.actor_id, &attempt.server_id, &material, old)
                .await;
        }
        Ok(self.success_redirect(&attempt.server_id, attempt.return_to))
    }

    async fn ensure_stored_actor_current(
        &self,
        attempt: &StoredAttempt,
    ) -> Result<(), McpConnectionError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        let current: bool = client
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM public.users u
                     WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                       AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                       AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                       WHERE ra.email=lower(u.email)))",
                &[&attempt.actor_id, &attempt.auth_generation],
            )
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("actor_scope"))?;
        if current {
            Ok(())
        } else {
            Err(McpConnectionError::NotVisible)
        }
    }

    async fn persist_connection(
        &self,
        attempt: &StoredAttempt,
        material: &ServerClientMaterial,
        refresh: &SecretBytes,
        scope: &str,
    ) -> Result<Option<OldRefresh>, McpConnectionError> {
        if scope.len() > 16 * 1024 || scope.as_bytes().contains(&0) {
            return Err(corrupt("scope"));
        }
        if material.transport == VendorTransportKind::GoogleDriveRest
            && scope != GOOGLE_DRIVE_READONLY_SCOPE
        {
            return Err(corrupt("scope"));
        }
        let credential_id = Uuid::now_v7();
        let actor = ActorId::new(&attempt.actor_id);
        let encrypted = self
            .vault
            .seal(
                &credential_id,
                SecretKind::McpUserToken,
                SecretPrincipal::Actor(actor.clone()),
                SecretPrincipal::Service(ServiceId::new(&attempt.server_id)),
                refresh,
            )
            .map_err(|_| corrupt("refresh_token"))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let now: OffsetDateTime = transaction
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("clock"))?;
        let current = transaction
            .query_opt(
                "SELECT u.id FROM public.users u JOIN public.mcp_servers s ON s.id=$3
                  WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                    AND s.url=$4 AND s.credential_id=$5
                    AND coalesce(s.transport,'mcp')=$6
                    AND coalesce(s.egress_allow_cidrs,ARRAY[]::text[])=$7
                    AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                    WHERE ra.email=lower(u.email))
                  FOR SHARE OF u,s",
                &[
                    &attempt.actor_id,
                    &attempt.auth_generation,
                    &attempt.server_id,
                    &attempt.resource,
                    &attempt.client_credential_id,
                    &attempt.transport,
                    &attempt.egress_allow_cidrs,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if current.is_none() {
            return Err(McpConnectionError::NotVisible);
        }
        let old_row = transaction
            .query_opt(
                "SELECT uc.credential_id,c.kind,c.provider,c.key_id,
                        c.encrypted_value,c.revoked_at
                   FROM public.mcp_user_credentials uc
                   JOIN public.credentials c ON c.id=uc.credential_id
                  WHERE uc.server_id=$1 AND uc.user_id=$2 FOR UPDATE OF uc,c",
                &[&attempt.server_id, &attempt.actor_id],
            )
            .await
            .map_err(query_unavailable)?;
        let old = if let Some(row) = old_row {
            let old_id: Uuid = row
                .try_get("credential_id")
                .map_err(|_| corrupt("old_credential_id"))?;
            let old_encrypted: String = row
                .try_get("encrypted_value")
                .map_err(|_| corrupt("old_credential_value"))?;
            let old_kind: crate::db::types::CredentialKind = row
                .try_get("kind")
                .map_err(|_| corrupt("old_credential_kind"))?;
            let old_provider: String = row
                .try_get("provider")
                .map_err(|_| corrupt("old_credential_provider"))?;
            let old_owner: String = row
                .try_get("key_id")
                .map_err(|_| corrupt("old_credential_owner"))?;
            let old_revoked: Option<OffsetDateTime> = row
                .try_get("revoked_at")
                .map_err(|_| corrupt("old_credential_revoked_at"))?;
            if old_revoked.is_some()
                || old_kind != crate::db::types::CredentialKind::McpUserToken
                || old_provider != attempt.server_id
                || old_owner != attempt.actor_id
            {
                return Err(corrupt("old_credential_binding"));
            }
            let old_refresh = self
                .vault
                .open(
                    &old_id,
                    SecretKind::McpUserToken,
                    SecretPrincipal::Actor(actor.clone()),
                    SecretPrincipal::Service(ServiceId::new(&attempt.server_id)),
                    &old_encrypted,
                )
                .map_err(|_| corrupt("old_credential_value"))?
                .into_secret();
            Some(OldRefresh {
                credential_id: old_id,
                refresh: old_refresh,
            })
        } else {
            None
        };
        let metadata = serde_json::json!({
            "server":attempt.server_id,
            "scope":scope,
            "resource":attempt.resource,
            "issuer":attempt.issuer,
            "transport":attempt.transport,
            "credential_generation":1,
            "revocation_status":"active"
        });
        transaction
            .execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata,created_at,updated_at
                 ) VALUES($1,'mcp_user_token',$2,$3,$4,$5,$6,$6)",
                &[
                    &credential_id,
                    &attempt.server_id,
                    &encrypted,
                    &attempt.actor_id,
                    &metadata,
                    &now,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .execute(
                "INSERT INTO public.mcp_user_credentials(
                   server_id,user_id,credential_id,scope,connected_at,updated_at
                 ) VALUES($1,$2,$3,$4,$5,$5)
                 ON CONFLICT(server_id,user_id) DO UPDATE SET
                   credential_id=excluded.credential_id,scope=excluded.scope,
                   connected_at=excluded.connected_at,updated_at=excluded.updated_at",
                &[
                    &attempt.server_id,
                    &attempt.actor_id,
                    &credential_id,
                    &scope,
                    &now,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if let Some(old) = &old {
            transaction
                .execute(
                    "UPDATE public.credentials SET revoked_at=$2,updated_at=$2,
                       metadata=coalesce(metadata,'{}'::jsonb)||
                                jsonb_build_object('revocation_status','pending',
                                                   'revocation_reason','reconnected')
                     WHERE id=$1 AND revoked_at IS NULL",
                    &[&old.credential_id, &now],
                )
                .await
                .map_err(query_unavailable)?;
        }
        self.append_connection_audit(
            &transaction,
            &actor,
            &attempt.server_id,
            "mcp.account_connected",
            None,
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "MCP OAuth connection commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        Ok(old)
    }

    async fn append_connection_audit(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
        actor: &ActorId,
        server_id: &str,
        event_type: &'static str,
        revocation: Option<(AuditLabel, bool)>,
    ) -> Result<(), McpConnectionError> {
        let mut facts = vec![AuditFact::CredentialOwner(
            AuditIdentifier::new(actor.as_str()).map_err(|_| corrupt("actor_id"))?,
        )];
        if let Some((reason, vendor_revoked)) = revocation {
            facts.push(AuditFact::RevocationReason(reason));
            facts.push(AuditFact::VendorRevoked(vendor_revoked));
        }
        let payload = AuditPayload::from_facts(facts).map_err(|_| corrupt("audit_payload"))?;
        let (id, created_at) = next_event_coordinates(transaction)
            .await
            .map_err(query_unavailable)?;
        let event = AuditEvent {
            id,
            actor: Some(actor.clone()),
            event_type: AuditEventType::parse(event_type).ok_or_else(|| corrupt("audit_event"))?,
            target_kind: AuditLabel::new("mcp_server"),
            target_id: Some(AuditIdentifier::new(server_id).map_err(|_| corrupt("server_id"))?),
            payload,
            created_at,
        };
        append_event_in_transaction(transaction, &event, self.checkpoint_key.expose())
            .await
            .map(|_| ())
            .map_err(query_unavailable)
    }

    async fn try_vendor_revoke(
        &self,
        actor_id: &str,
        server_id: &str,
        material: &ServerClientMaterial,
        old: OldRefresh,
    ) -> bool {
        let revoked = match material.transport {
            VendorTransportKind::Mcp => self
                .oauth
                .with_egress_allowlist(material.egress_allowlist.clone())
                .revoke_refresh_token(
                    &material.endpoint,
                    material.client.expose(),
                    old.refresh.expose(),
                )
                .await
                .is_ok(),
            VendorTransportKind::GoogleDriveRest => match &self.drive_oauth {
                Some(oauth) => oauth
                    .revoke_refresh_token(old.refresh.expose())
                    .await
                    .is_ok(),
                None => false,
            },
        };
        if !revoked {
            return false;
        }
        self.mark_vendor_revoked(actor_id, server_id, old.credential_id)
            .await
            .is_ok()
    }

    async fn mark_vendor_revoked(
        &self,
        actor_id: &str,
        server_id: &str,
        credential_id: Uuid,
    ) -> Result<(), McpConnectionError> {
        let actor = ActorId::new(actor_id);
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let updated = transaction
            .query_opt(
                "UPDATE public.credentials SET
                   metadata=coalesce(metadata,'{}'::jsonb)||
                            jsonb_build_object('revocation_status','revoked',
                                               'vendor_revoked_at',clock_timestamp()),
                   updated_at=clock_timestamp()
                 WHERE id=$1 AND revoked_at IS NOT NULL
                   AND metadata->>'revocation_status' IN ('pending','revoking')
                 RETURNING metadata",
                &[&credential_id],
            )
            .await
            .map_err(query_unavailable)?;
        let Some(updated) = updated else {
            return Err(McpConnectionError::NotVisible);
        };
        let metadata: serde_json::Value = updated
            .try_get("metadata")
            .map_err(|_| corrupt("credential_metadata"))?;
        if metadata
            .get("revocation_reason")
            .and_then(serde_json::Value::as_str)
            == Some("mcp_server_removed")
        {
            let context: RemovedServerRevocationContext = serde_json::from_value(
                metadata
                    .get("server_removal_revocation")
                    .cloned()
                    .ok_or_else(|| corrupt("server_removal_revocation"))?,
            )
            .map_err(|_| corrupt("server_removal_revocation"))?;
            if context.version != REMOVED_SERVER_REVOCATION_VERSION {
                return Err(corrupt("server_removal_revocation"));
            }
            if let Some(client_credential_id) = context.client_credential_id {
                let pending: bool = transaction
                    .query_one(
                        "SELECT EXISTS(
                           SELECT 1 FROM public.credentials c
                            WHERE c.kind='mcp_user_token'
                              AND c.provider=$1
                              AND c.metadata->>'revocation_status' IN ('pending','revoking')
                              AND c.metadata#>>'{server_removal_revocation,client_credential_id}'=$2)",
                        &[&server_id, &client_credential_id.to_string()],
                    )
                    .await
                    .map_err(query_unavailable)?
                    .try_get(0)
                    .map_err(|_| corrupt("revocation_context"))?;
                if !pending {
                    let client_updated = transaction
                        .execute(
                            "UPDATE public.credentials SET
                               metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object(
                                 'revocation_status','operator_required',
                                 'operator_required_at',clock_timestamp(),
                                 'user_token_revocations_completed_at',clock_timestamp()),
                               updated_at=clock_timestamp()
                             WHERE id=$1 AND kind='mcp_oauth_client' AND provider=$2
                               AND revoked_at IS NOT NULL
                               AND metadata->>'revocation_reason'='mcp_server_removed'",
                            &[&client_credential_id, &server_id],
                        )
                        .await
                        .map_err(query_unavailable)?;
                    if client_updated != 1 {
                        return Err(corrupt("server_removal_client"));
                    }
                }
            }
        }
        let scrubbed = transaction
            .execute(
                "UPDATE public.credentials SET
                   metadata=metadata-'server_removal_revocation'-'credential_revocation',updated_at=clock_timestamp()
                 WHERE id=$1 AND metadata->>'revocation_status'='revoked'",
                &[&credential_id],
            )
            .await
            .map_err(query_unavailable)?;
        if scrubbed != 1 {
            return Err(McpConnectionError::NotVisible);
        }
        self.append_connection_audit(
            &transaction,
            &actor,
            server_id,
            "mcp.account_disconnected",
            Some((AuditLabel::new("vendor_revoke_confirmed"), true)),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "vendor revoke confirmation commit 结果未知");
            McpConnectionError::CommitUnknown
        })
    }

    fn success_redirect(&self, server_id: &str, return_to: McpOAuthReturnTo) -> String {
        let origin = self.app_origin.as_deref().unwrap_or_default();
        match return_to {
            McpOAuthReturnTo::Admin => format!("{origin}/admin/plugins/{server_id}"),
            McpOAuthReturnTo::Settings => {
                format!("{origin}/settings/connected-accounts/{server_id}")
            }
        }
    }

    fn failure_redirect(&self) -> String {
        let origin = self.app_origin.as_deref().unwrap_or_default();
        format!("{origin}/settings/connected-accounts?connected=failed")
    }

    /// Prepare local admin retirement under the caller's existing credential transaction. The
    /// returned metadata is Rust-owned and never accepted from an administration request body.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prepare_admin_credential_retirement(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        auth: &AuthContext,
        credential_id: Uuid,
        kind: CredentialKind,
        server_id: &str,
        owner_key: &str,
        now: OffsetDateTime,
    ) -> Result<serde_json::Value, McpConnectionError> {
        if auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !auth.has_role(Role::Admin)
        {
            return Err(McpConnectionError::NotVisible);
        }
        let stamp = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| corrupt("clock"))?;
        let operator = || serde_json::json!({"revocation_status":"operator_required", "revocation_reason":"credential_revoked", "operator_required_at":stamp});
        if !matches!(
            kind,
            CredentialKind::McpUserToken | CredentialKind::McpOauthClient
        ) {
            return Ok(operator());
        }
        let server = tx.query_opt("SELECT url,coalesce(transport,'mcp') AS transport,credential_id,coalesce(egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs FROM public.mcp_servers WHERE id=$1 FOR UPDATE", &[&server_id]).await.map_err(query_unavailable)?;
        let mut frozen = None;
        let mut attached_client = false;
        if let Some(server) = server {
            let pointer: Option<Uuid> = server
                .try_get("credential_id")
                .map_err(|_| corrupt("credential_id"))?;
            attached_client = pointer == Some(credential_id);
            let resource: String = server
                .try_get("url")
                .map_err(|_| corrupt("server_endpoint"))?;
            let transport: String = server
                .try_get("transport")
                .map_err(|_| corrupt("transport"))?;
            let egress_allow_cidrs: Vec<String> = server
                .try_get("egress_allow_cidrs")
                .map_err(|_| corrupt("egress_allow_cidrs"))?;
            let transport_kind =
                VendorTransportKind::parse(&transport).map_err(|_| corrupt("transport"))?;
            let context_valid = valid_server_removal_resource(&resource)
                && parse_stored_mcp_egress(&egress_allow_cidrs).is_ok()
                && (transport_kind != VendorTransportKind::GoogleDriveRest
                    || (server_id == GOOGLE_DRIVE_SERVER_ID
                        && resource == GOOGLE_DRIVE_API_BASE
                        && egress_allow_cidrs.is_empty()));
            if let Some(pointer) = pointer
                && context_valid
                && (kind == CredentialKind::McpUserToken || attached_client)
            {
                let client = tx.query_opt("SELECT kind,provider,encrypted_value,revoked_at FROM public.credentials WHERE id=$1 FOR SHARE", &[&pointer]).await.map_err(query_unavailable)?;
                if let Some(client) = client {
                    let client_kind: CredentialKind = client
                        .try_get("kind")
                        .map_err(|_| corrupt("credential_kind"))?;
                    let provider: String = client
                        .try_get("provider")
                        .map_err(|_| corrupt("credential_provider"))?;
                    let revoked: Option<OffsetDateTime> = client
                        .try_get("revoked_at")
                        .map_err(|_| corrupt("credential_revoked_at"))?;
                    let encrypted: String = client
                        .try_get("encrypted_value")
                        .map_err(|_| corrupt("credential_value"))?;
                    let usable = client_kind == CredentialKind::McpOauthClient
                        && provider == server_id
                        && revoked.is_none()
                        && self
                            .vault
                            .open(
                                &pointer,
                                SecretKind::McpOauthClient,
                                SecretPrincipal::Deployment,
                                SecretPrincipal::Service(ServiceId::new(server_id)),
                                &encrypted,
                            )
                            .is_ok_and(|opened| {
                                self.oauth
                                    .validate_stored_client(opened.into_secret().expose())
                                    .is_ok()
                            });
                    if usable {
                        frozen = Some(
                            serde_json::to_value(RemovedServerRevocationContext {
                                version: REMOVED_SERVER_REVOCATION_VERSION,
                                resource,
                                transport,
                                client_credential_id: Some(pointer),
                                egress_allow_cidrs,
                            })
                            .map_err(|_| corrupt("credential_revocation"))?,
                        );
                    }
                }
            }
        }
        let token_metadata = match frozen {
            Some(context) => {
                serde_json::json!({"revocation_status":"pending", "revocation_reason":"credential_revoked", "credential_revocation":context})
            }
            None => operator(),
        };
        let owners = if kind == CredentialKind::McpUserToken {
            // The row's key_id is the token's authoritative owner. A mismatched join is corruption,
            // not permission to disconnect a different person's current credential.
            let bad: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM public.mcp_user_credentials WHERE credential_id=$1 AND (server_id<>$2 OR user_id<>$3))", &[&credential_id,&server_id,&owner_key]).await.map_err(query_unavailable)?.try_get(0).map_err(|_| corrupt("user_credential_binding"))?;
            if bad {
                return Err(corrupt("user_credential_binding"));
            }
            tx.execute(
                "DELETE FROM public.mcp_user_credentials WHERE credential_id=$1",
                &[&credential_id],
            )
            .await
            .map_err(query_unavailable)?;
            vec![owner_key.to_owned()]
        } else if attached_client {
            let rows = tx.query("UPDATE public.credentials SET revoked_at=$2,updated_at=$2,metadata=metadata || $3::jsonb WHERE kind='mcp_user_token' AND provider=$1 AND revoked_at IS NULL RETURNING key_id", &[&server_id,&now,&token_metadata]).await.map_err(query_unavailable)?;
            tx.execute(
                "DELETE FROM public.mcp_user_credentials WHERE server_id=$1",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?;
            rows.into_iter()
                .map(|row| {
                    row.try_get::<_, String>("key_id")
                        .map_err(|_| corrupt("credential_owner"))
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        for owner in owners {
            let (id, created_at) = next_event_coordinates(tx)
                .await
                .map_err(|_| McpConnectionError::Unavailable)?;
            let event = AuditEvent {
                id,
                actor: Some(auth.actor().clone()),
                event_type: AuditEventType::parse("mcp.account_disconnected").expect("known event"),
                target_kind: AuditLabel::new("mcp_server"),
                target_id: Some(AuditIdentifier::new(server_id).map_err(|_| corrupt("server_id"))?),
                payload: AuditPayload::from_facts([
                    AuditFact::CredentialOwner(
                        AuditIdentifier::new(owner).map_err(|_| corrupt("credential_owner"))?,
                    ),
                    AuditFact::RevocationReason(AuditLabel::new("credential_revoked")),
                    AuditFact::VendorRevoked(false),
                ])
                .map_err(|_| corrupt("audit_payload"))?,
                created_at,
            };
            append_event_in_transaction(tx, &event, self.checkpoint_key.expose())
                .await
                .map_err(|_| McpConnectionError::Unavailable)?;
        }
        Ok(if kind == CredentialKind::McpUserToken {
            token_metadata
        } else {
            operator()
        })
    }

    async fn removed_server_client_material(
        &self,
        claim: &PendingRevocation,
        admin_retirement: bool,
    ) -> Result<ServerClientMaterial, McpConnectionError> {
        let raw = claim
            .metadata
            .get(if admin_retirement {
                "credential_revocation"
            } else {
                "server_removal_revocation"
            })
            .cloned()
            .ok_or_else(|| corrupt("server_removal_revocation"))?;
        let context: RemovedServerRevocationContext =
            serde_json::from_value(raw).map_err(|_| corrupt("server_removal_revocation"))?;
        if context.version != REMOVED_SERVER_REVOCATION_VERSION
            || context.resource.is_empty()
            || context.resource.len() > MAX_CUSTOM_SERVER_URL_BYTES
            || context.resource.as_bytes().contains(&0)
        {
            return Err(corrupt("server_removal_revocation"));
        }
        if !valid_server_removal_resource(&context.resource) {
            return Err(corrupt("server_removal_revocation"));
        }
        let transport = VendorTransportKind::parse(&context.transport)
            .map_err(|_| corrupt("server_removal_transport"))?;
        let egress_allowlist = parse_stored_mcp_egress(&context.egress_allow_cidrs)
            .map_err(|_| corrupt("server_removal_egress"))?;
        if transport == VendorTransportKind::GoogleDriveRest
            && (claim.server_id != GOOGLE_DRIVE_SERVER_ID
                || context.resource != GOOGLE_DRIVE_API_BASE
                || !egress_allowlist.is_empty())
        {
            return Err(corrupt("server_removal_identity"));
        }
        let credential_id = context
            .client_credential_id
            .ok_or_else(|| corrupt("server_removal_client"))?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                "SELECT kind,provider,encrypted_value,revoked_at,metadata
                   FROM public.credentials WHERE id=$1",
                &[&credential_id],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or_else(|| corrupt("server_removal_client"))?;
        let kind: crate::db::types::CredentialKind = row
            .try_get("kind")
            .map_err(|_| corrupt("server_removal_client"))?;
        let provider: String = row
            .try_get("provider")
            .map_err(|_| corrupt("server_removal_client"))?;
        let revoked_at: Option<OffsetDateTime> = row
            .try_get("revoked_at")
            .map_err(|_| corrupt("server_removal_client"))?;
        let metadata: serde_json::Value = row
            .try_get("metadata")
            .map_err(|_| corrupt("server_removal_client"))?;
        if kind != crate::db::types::CredentialKind::McpOauthClient
            || provider != claim.server_id
            || (!admin_retirement
                && (revoked_at.is_none()
                    || metadata
                        .get("revocation_reason")
                        .and_then(serde_json::Value::as_str)
                        != Some("mcp_server_removed")))
        {
            return Err(corrupt("server_removal_client"));
        }
        let encrypted: String = row
            .try_get("encrypted_value")
            .map_err(|_| corrupt("server_removal_client"))?;
        let secret = self
            .vault
            .open(
                &credential_id,
                SecretKind::McpOauthClient,
                SecretPrincipal::Deployment,
                SecretPrincipal::Service(ServiceId::new(&claim.server_id)),
                &encrypted,
            )
            .map_err(|_| corrupt("server_removal_client"))?
            .into_secret();
        self.oauth
            .validate_stored_client(secret.expose())
            .map_err(|_| corrupt("server_removal_client"))?;
        Ok(ServerClientMaterial {
            credential_id,
            endpoint: context.resource,
            client: secret,
            transport,
            egress_allow_cidrs: context.egress_allow_cidrs,
            egress_allowlist,
        })
    }

    /// Claim and reconcile a bounded batch of local tombstones. Vendor revocation is idempotent;
    /// local access is already absent regardless of this method's outcome.
    pub async fn reconcile_pending_revocations(
        &self,
    ) -> Result<McpRevocationSweep, McpConnectionError> {
        let claims = self.claim_pending_revocations().await?;
        let mut sweep = McpRevocationSweep {
            attempted: claims.len(),
            ..McpRevocationSweep::default()
        };
        for claim in claims {
            let actor = ActorId::new(&claim.actor_id);
            let refresh = self
                .vault
                .open(
                    &claim.credential_id,
                    SecretKind::McpUserToken,
                    SecretPrincipal::Actor(actor),
                    SecretPrincipal::Service(ServiceId::new(&claim.server_id)),
                    &claim.encrypted_value,
                )
                .map(|value| value.into_secret());
            let removed_server = claim
                .metadata
                .get("revocation_reason")
                .and_then(serde_json::Value::as_str)
                == Some("mcp_server_removed");
            let admin_retirement = claim
                .metadata
                .get("revocation_reason")
                .and_then(serde_json::Value::as_str)
                == Some("credential_revoked");
            let (refresh, material) = if removed_server || admin_retirement {
                let refresh = match refresh {
                    Ok(refresh) => refresh,
                    Err(_) => {
                        self.mark_revocation_operator_required(&claim).await?;
                        sweep.operator_required = sweep.operator_required.saturating_add(1);
                        continue;
                    }
                };
                let material = match self
                    .removed_server_client_material(&claim, admin_retirement)
                    .await
                {
                    Ok(material) => material,
                    Err(error) if removed_server_material_error_is_permanent(error) => {
                        self.mark_revocation_operator_required(&claim).await?;
                        sweep.operator_required = sweep.operator_required.saturating_add(1);
                        continue;
                    }
                    Err(_) => {
                        self.return_revocation_pending(claim.credential_id).await?;
                        sweep.pending = sweep.pending.saturating_add(1);
                        continue;
                    }
                };
                (Some(refresh), Some(material))
            } else {
                (
                    refresh.ok(),
                    self.load_server_client(&claim.server_id).await.ok(),
                )
            };
            let revoked = match (refresh, material) {
                (Some(refresh), Some(material)) => {
                    self.try_vendor_revoke(
                        &claim.actor_id,
                        &claim.server_id,
                        &material,
                        OldRefresh {
                            credential_id: claim.credential_id,
                            refresh,
                        },
                    )
                    .await
                }
                _ => false,
            };
            if revoked {
                sweep.revoked = sweep.revoked.saturating_add(1);
            } else {
                self.return_revocation_pending(claim.credential_id).await?;
                sweep.pending = sweep.pending.saturating_add(1);
            }
        }
        Ok(sweep)
    }

    async fn mark_revocation_operator_required(
        &self,
        claim: &PendingRevocation,
    ) -> Result<(), McpConnectionError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let updated = transaction
            .execute(
                "UPDATE public.credentials SET
                   metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object(
                     'revocation_status','operator_required',
                     'operator_required_at',clock_timestamp()),
                   updated_at=clock_timestamp()
                 WHERE id=$1 AND kind='mcp_user_token' AND provider=$2
                   AND revoked_at IS NOT NULL
                   AND metadata->>'revocation_reason' IN ('mcp_server_removed','credential_revoked')
                   AND metadata->>'revocation_status'='revoking'",
                &[&claim.credential_id, &claim.server_id],
            )
            .await
            .map_err(query_unavailable)?;
        if updated != 1 {
            return Err(McpConnectionError::NotVisible);
        }
        if claim
            .metadata
            .get("revocation_reason")
            .and_then(serde_json::Value::as_str)
            == Some("mcp_server_removed")
        {
            transaction
                .execute(
                    "UPDATE public.credentials SET
                   metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object(
                     'revocation_status','operator_required',
                     'operator_required_at',clock_timestamp(),
                     'automatic_user_token_revocation_failed_at',clock_timestamp()),
                   updated_at=clock_timestamp()
                 WHERE kind='mcp_oauth_client' AND provider=$1
                   AND revoked_at IS NOT NULL
                   AND metadata->>'revocation_reason'='mcp_server_removed'
                   AND metadata->>'revocation_status' IN (
                     'retained_for_user_token_revocation','operator_required')",
                    &[&claim.server_id],
                )
                .await
                .map_err(query_unavailable)?;
        }
        self.append_connection_audit(
            &transaction,
            &ActorId::new(&claim.actor_id),
            &claim.server_id,
            "mcp.account_disconnected",
            Some((AuditLabel::new("vendor_revoke_operator_required"), false)),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "operator-required vendor revoke commit 结果未知");
            McpConnectionError::CommitUnknown
        })
    }

    async fn claim_pending_revocations(
        &self,
    ) -> Result<Vec<PendingRevocation>, McpConnectionError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let rows = transaction
            .query(
                "WITH candidates AS (
                    SELECT id FROM public.credentials
                     WHERE kind='mcp_user_token' AND revoked_at IS NOT NULL
                       AND ((metadata->>'revocation_status'='pending' AND
                             updated_at<clock_timestamp()-interval '30 seconds') OR
                            (metadata->>'revocation_status'='revoking' AND
                             updated_at<clock_timestamp()-interval '2 minutes'))
                     ORDER BY updated_at,id
                     LIMIT $1 FOR UPDATE SKIP LOCKED
                 )
                 UPDATE public.credentials c SET
                   metadata=coalesce(c.metadata,'{}'::jsonb)||
                            jsonb_build_object(
                              'revocation_status','revoking',
                              'revocation_attempts',
                                CASE WHEN coalesce(c.metadata->>'revocation_attempts','')
                                               ~ '^[0-9]{1,17}$'
                                     THEN (c.metadata->>'revocation_attempts')::bigint+1
                                     ELSE 1 END),
                   updated_at=clock_timestamp()
                  FROM candidates WHERE c.id=candidates.id
                 RETURNING c.id,c.provider,c.key_id,c.encrypted_value,c.metadata",
                &[&REVOCATION_BATCH],
            )
            .await
            .map_err(query_unavailable)?;
        let claims = rows
            .iter()
            .map(|row| {
                Ok(PendingRevocation {
                    credential_id: row.try_get("id").map_err(|_| corrupt("credential_id"))?,
                    server_id: row
                        .try_get("provider")
                        .map_err(|_| corrupt("credential_provider"))?,
                    actor_id: row
                        .try_get("key_id")
                        .map_err(|_| corrupt("credential_owner"))?,
                    encrypted_value: row
                        .try_get("encrypted_value")
                        .map_err(|_| corrupt("credential_value"))?,
                    metadata: row
                        .try_get("metadata")
                        .map_err(|_| corrupt("credential_metadata"))?,
                })
            })
            .collect::<Result<Vec<_>, McpConnectionError>>()?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "pending vendor revoke claim commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        Ok(claims)
    }

    async fn return_revocation_pending(
        &self,
        credential_id: Uuid,
    ) -> Result<(), McpConnectionError> {
        self.pool
            .get()
            .await
            .map_err(unavailable)?
            .execute(
                "UPDATE public.credentials SET
                   metadata=coalesce(metadata,'{}'::jsonb)||
                            jsonb_build_object('revocation_status','pending'),
                   updated_at=clock_timestamp()
                 WHERE id=$1 AND revoked_at IS NOT NULL
                   AND metadata->>'revocation_status'='revoking'",
                &[&credential_id],
            )
            .await
            .map(|_| ())
            .map_err(query_unavailable)
    }
}

#[async_trait]
impl McpConnectionAdministration for PostgresMcpConnections {
    async fn list_connections(
        &self,
        auth: &AuthContext,
    ) -> Result<McpConnections, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let rows = client
            .query(
                "SELECT uc.server_id,uc.scope,uc.connected_at
                   FROM public.mcp_user_credentials uc
                   JOIN public.credentials c ON c.id=uc.credential_id
                  WHERE uc.user_id=$1 AND c.kind='mcp_user_token'
                    AND c.provider=uc.server_id AND c.key_id=$1 AND c.revoked_at IS NULL
                  ORDER BY uc.server_id",
                &[&auth.actor().as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        let connections = rows
            .iter()
            .map(|row| {
                Ok(McpConnection {
                    server_id: row.try_get("server_id").map_err(|_| corrupt("server_id"))?,
                    scope: row.try_get("scope").map_err(|_| corrupt("scope"))?,
                    connected_at: row
                        .try_get("connected_at")
                        .map_err(|_| corrupt("connected_at"))?,
                })
            })
            .collect::<Result<Vec<_>, McpConnectionError>>()?;
        let reviewed = client
            .query_opt(
                "SELECT url,vendor,provenance,transport
                   FROM public.mcp_servers WHERE id=$1",
                &[&GOOGLE_DRIVE_SERVER_ID],
            )
            .await
            .map_err(query_unavailable)?;
        let available_server_ids = if let Some(row) = reviewed {
            let endpoint: String = row.try_get("url").map_err(|_| corrupt("server_endpoint"))?;
            let vendor: String = row.try_get("vendor").map_err(|_| corrupt("vendor"))?;
            let provenance: String = row
                .try_get("provenance")
                .map_err(|_| corrupt("provenance"))?;
            let transport: Option<String> =
                row.try_get("transport").map_err(|_| corrupt("transport"))?;
            if endpoint != GOOGLE_DRIVE_API_BASE
                || vendor != GOOGLE_DRIVE_VENDOR
                || provenance != GOOGLE_DRIVE_PROVENANCE
                || transport.as_deref() != Some(GOOGLE_DRIVE_TRANSPORT)
            {
                return Err(corrupt("reviewed_server_identity"));
            }
            vec![GOOGLE_DRIVE_SERVER_ID.to_owned()]
        } else {
            Vec::new()
        };
        Ok(McpConnections {
            available_server_ids,
            connections,
            redirect_uri: self.callback_uri.clone(),
        })
    }

    async fn list_admin_page(
        &self,
        auth: &AuthContext,
    ) -> Result<McpAdminPage, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        self.admin_page_projection(auth).await
    }

    async fn begin_oauth(
        &self,
        auth: &AuthContext,
        server_id: &str,
        return_to: McpOAuthReturnTo,
    ) -> Result<McpOAuthAuthorization, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        let callback_uri = self
            .callback_uri
            .as_deref()
            .ok_or(McpConnectionError::Conflict {
                resource: "mcp_oauth_public_callback",
            })?;
        let material = self.load_server_client(server_id).await?;
        let state = random_base64::<32>()?;
        let verifier = random_base64::<48>()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let (authorization_url, issuer, issuer_required, requested_scope) = match material.transport
        {
            VendorTransportKind::Mcp => {
                let plan = self
                    .oauth
                    .with_egress_allowlist(material.egress_allowlist.clone())
                    .authorization_plan(
                        &material.endpoint,
                        material.client.expose(),
                        callback_uri,
                        &state,
                        &challenge,
                    )
                    .await
                    .map_err(map_oauth_vendor)?;
                (
                    plan.authorization_url().to_string(),
                    plan.issuer().to_owned(),
                    plan.requires_callback_issuer(),
                    plan.requested_scope().to_owned(),
                )
            }
            VendorTransportKind::GoogleDriveRest => {
                let plan = self
                    .drive_oauth
                    .as_ref()
                    .ok_or(McpConnectionError::Conflict {
                        resource: "google_drive_oauth_runtime",
                    })?
                    .authorization_plan(material.client.expose(), callback_uri, &state, &challenge)
                    .map_err(map_drive_oauth_vendor)?;
                (
                    plan.authorization_url().to_string(),
                    plan.issuer().to_owned(),
                    false,
                    GOOGLE_DRIVE_READONLY_SCOPE.to_owned(),
                )
            }
        };
        let now = database_now(&self.pool).await?;
        let auth_generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let attempt = StoredAttempt {
            version: ATTEMPT_VERSION,
            deployment_id: self.deployment.as_str().to_owned(),
            tenant_id: self.tenant.as_str().to_owned(),
            actor_id: auth.actor().as_str().to_owned(),
            auth_generation,
            server_id: server_id.to_owned(),
            client_credential_id: material.credential_id,
            resource: material.endpoint,
            transport: material.transport.as_str().to_owned(),
            egress_allow_cidrs: material.egress_allow_cidrs,
            code_verifier: verifier,
            redirect_uri: callback_uri.to_owned(),
            issuer,
            issuer_required,
            requested_scope,
            return_to,
            expires_at_unix_seconds: (now + ATTEMPT_TTL).unix_timestamp(),
        };
        self.insert_attempt(&state, &attempt).await?;
        Ok(McpOAuthAuthorization { authorization_url })
    }

    async fn disconnect(
        &self,
        auth: &AuthContext,
        server_id: &str,
    ) -> Result<McpConnectionDisconnected, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        validate_server_id(server_id)?;
        let candidate = self.disconnect_candidate(auth.actor(), server_id).await?;
        self.tombstone_connection(auth, server_id, candidate.credential_id)
            .await?;
        let material = self.load_server_client(server_id).await.ok();
        let vendor_revocation = match (material, candidate.refresh) {
            (Some(material), Some(refresh)) => {
                if self
                    .try_vendor_revoke(
                        auth.actor().as_str(),
                        server_id,
                        &material,
                        OldRefresh {
                            credential_id: candidate.credential_id,
                            refresh,
                        },
                    )
                    .await
                {
                    McpVendorRevocationStatus::Revoked
                } else {
                    McpVendorRevocationStatus::Pending
                }
            }
            _ => McpVendorRevocationStatus::Pending,
        };
        Ok(McpConnectionDisconnected {
            server_id: server_id.to_owned(),
            vendor_revocation,
        })
    }

    async fn register_oauth_client(
        &self,
        auth: &AuthContext,
        server_id: &str,
        registration: &McpOAuthClientRegistration,
    ) -> Result<McpOAuthClientRegistered, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        if !auth.has_role(Role::Admin) {
            return Err(McpConnectionError::NotVisible);
        }
        validate_server_id(server_id)?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let server = client
            .query_opt(
                "SELECT url,vendor,provenance,coalesce(transport,'mcp') AS transport,
                        coalesce(egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs
                   FROM public.mcp_servers WHERE id=$1",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpConnectionError::NotVisible)?;
        let endpoint: String = server
            .try_get("url")
            .map_err(|_| corrupt("server_endpoint"))?;
        let vendor: String = server.try_get("vendor").map_err(|_| corrupt("vendor"))?;
        let provenance: String = server
            .try_get("provenance")
            .map_err(|_| corrupt("provenance"))?;
        let transport = VendorTransportKind::parse(
            &server
                .try_get::<_, String>("transport")
                .map_err(|_| corrupt("transport"))?,
        )
        .map_err(|_| corrupt("transport"))?;
        let egress_allow_cidrs: Vec<String> = server
            .try_get("egress_allow_cidrs")
            .map_err(|_| corrupt("egress_allow_cidrs"))?;
        let egress_allowlist = parse_stored_mcp_egress(&egress_allow_cidrs)
            .map_err(|_| corrupt("egress_allow_cidrs"))?;
        drop(client);
        let encoded = encoded_registration(registration)?;
        match transport {
            VendorTransportKind::Mcp => {
                self.oauth
                    .with_egress_allowlist(egress_allowlist.clone())
                    .discover(&endpoint, &encoded)
                    .await
                    .map_err(map_oauth_vendor)?;
            }
            VendorTransportKind::GoogleDriveRest => {
                if server_id != GOOGLE_DRIVE_SERVER_ID
                    || endpoint != GOOGLE_DRIVE_API_BASE
                    || vendor != GOOGLE_DRIVE_VENDOR
                    || provenance != GOOGLE_DRIVE_PROVENANCE
                    || !egress_allowlist.is_empty()
                {
                    return Err(corrupt("transport_identity"));
                }
                self.drive_oauth
                    .as_ref()
                    .ok_or(McpConnectionError::Conflict {
                        resource: "google_drive_oauth_runtime",
                    })?
                    .validate_registration(registration)
                    .map_err(map_drive_oauth_vendor)?;
            }
        }
        let credential_id = Uuid::now_v7();
        let secret = SecretBytes::new(encoded.to_vec());
        let encrypted = self
            .vault
            .seal(
                &credential_id,
                SecretKind::McpOauthClient,
                SecretPrincipal::Deployment,
                SecretPrincipal::Service(ServiceId::new(server_id)),
                &secret,
            )
            .map_err(|_| corrupt("oauth_client"))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        ensure_transaction_actor(&transaction, auth, true).await?;
        let server = transaction
            .query_opt(
                "SELECT s.url,s.vendor,s.provenance,coalesce(s.transport,'mcp') AS transport,
                        coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs,
                        s.credential_id,coalesce(s.credential_generation,0)
                        AS credential_generation,s.catalog_generation,
                        c.kind AS old_client_kind,c.provider AS old_client_provider,
                        c.revoked_at AS old_client_revoked_at
                   FROM public.mcp_servers s
                   LEFT JOIN public.credentials c ON c.id=s.credential_id
                  WHERE s.id=$1 FOR UPDATE OF s",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpConnectionError::NotVisible)?;
        let locked_endpoint: String = server
            .try_get("url")
            .map_err(|_| corrupt("server_endpoint"))?;
        if locked_endpoint != endpoint {
            return Err(McpConnectionError::Conflict {
                resource: "mcp_server",
            });
        }
        let locked_transport = VendorTransportKind::parse(
            &server
                .try_get::<_, String>("transport")
                .map_err(|_| corrupt("transport"))?,
        )
        .map_err(|_| corrupt("transport"))?;
        let locked_vendor: String = server.try_get("vendor").map_err(|_| corrupt("vendor"))?;
        let locked_provenance: String = server
            .try_get("provenance")
            .map_err(|_| corrupt("provenance"))?;
        let locked_egress_allow_cidrs: Vec<String> = server
            .try_get("egress_allow_cidrs")
            .map_err(|_| corrupt("egress_allow_cidrs"))?;
        parse_stored_mcp_egress(&locked_egress_allow_cidrs)
            .map_err(|_| corrupt("egress_allow_cidrs"))?;
        if locked_transport != transport
            || locked_vendor != vendor
            || locked_provenance != provenance
            || locked_egress_allow_cidrs != egress_allow_cidrs
        {
            return Err(McpConnectionError::Conflict {
                resource: "mcp_server",
            });
        }
        let old_client_id: Option<Uuid> = server
            .try_get("credential_id")
            .map_err(|_| corrupt("oauth_client_id"))?;
        if old_client_id.is_some() {
            let old_kind: Option<crate::db::types::CredentialKind> = server
                .try_get("old_client_kind")
                .map_err(|_| corrupt("old_oauth_client_kind"))?;
            let old_provider: Option<String> = server
                .try_get("old_client_provider")
                .map_err(|_| corrupt("old_oauth_client_provider"))?;
            let _: Option<OffsetDateTime> = server
                .try_get("old_client_revoked_at")
                .map_err(|_| corrupt("old_oauth_client_revoked_at"))?;
            if !matches!(
                old_kind,
                Some(
                    crate::db::types::CredentialKind::Mcp
                        | crate::db::types::CredentialKind::McpOauthClient
                )
            ) || old_provider.as_deref() != Some(server_id)
            {
                return Err(corrupt("old_oauth_client_binding"));
            }
        }
        let old_generation: i64 = server
            .try_get("credential_generation")
            .map_err(|_| corrupt("credential_generation"))?;
        let catalog_generation: Option<i64> = server
            .try_get("catalog_generation")
            .map_err(|_| corrupt("catalog_generation"))?;
        if catalog_generation == Some(i64::MAX) {
            return Err(corrupt("catalog_generation"));
        }
        let new_generation = old_generation
            .checked_add(1)
            .ok_or_else(|| corrupt("credential_generation"))?;
        let now: OffsetDateTime = transaction
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("clock"))?;
        let metadata = serde_json::json!({
            "clientId":registration.client_id(),
            "issuer":registration.issuer(),
            "tokenEndpointAuthMethod":match registration.auth_method() {
                McpOAuthClientAuthMethod::ClientSecretBasic => "client_secret_basic",
                McpOAuthClientAuthMethod::ClientSecretPost => "client_secret_post",
            },
            "resourceMetadataUrl":registration.resource_metadata_url(),
            "credentialGeneration":new_generation
        });
        transaction
            .execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata,created_at,updated_at
                 ) VALUES($1,'mcp_oauth_client',$2,$3,'oauth-client',$4,$5,$5)",
                &[&credential_id, &server_id, &encrypted, &metadata, &now],
            )
            .await
            .map_err(query_unavailable)?;

        // Tag every pre-existing grant with the old generation before advancing the server. It is
        // therefore invisible immediately and refresh can only suspend, never auto-revive, it.
        transaction
            .execute(
                "UPDATE public.plugin_grants SET
                   credential_generation=coalesce(credential_generation,$2),updated_at=$3
                  WHERE kind='mcp' AND split_part(ref,'/',1)=$1",
                &[&server_id, &old_generation, &now],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .execute(
                "UPDATE public.mcp_servers SET credential_id=$2,credential_generation=$3,
                   catalog_generation=CASE WHEN catalog_generation IS NULL THEN NULL
                                           ELSE catalog_generation+1 END,
                   last_error='credential_changed_requires_regrant',updated_at=$4
                  WHERE id=$1",
                &[&server_id, &credential_id, &new_generation, &now],
            )
            .await
            .map_err(query_unavailable)?;
        if let Some(old_client_id) = old_client_id {
            transaction
                .execute(
                    "UPDATE public.credentials SET revoked_at=$2,updated_at=$2,
                       metadata=coalesce(metadata,'{}'::jsonb)||
                                jsonb_build_object('revocation_reason','oauth_client_rotated')
                     WHERE id=$1 AND revoked_at IS NULL",
                    &[&old_client_id, &now],
                )
                .await
                .map_err(query_unavailable)?;
        }

        let corrupt_connection: bool = transaction
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM public.mcp_user_credentials uc
                    LEFT JOIN public.credentials c ON c.id=uc.credential_id
                     WHERE uc.server_id=$1 AND
                       (c.id IS NULL OR c.kind<>'mcp_user_token' OR c.provider<>uc.server_id
                        OR c.key_id<>uc.user_id OR c.revoked_at IS NOT NULL))",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("user_credential_binding"))?;
        if corrupt_connection {
            return Err(corrupt("user_credential_binding"));
        }
        let disconnected = transaction
            .query(
                "UPDATE public.credentials c SET revoked_at=$2,updated_at=$2,
                   metadata=coalesce(c.metadata,'{}'::jsonb)||
                            jsonb_build_object('revocation_status','pending',
                                               'revocation_reason','oauth_client_rotated')
                  FROM public.mcp_user_credentials uc
                 WHERE uc.server_id=$1 AND uc.credential_id=c.id
                   AND c.kind='mcp_user_token' AND c.provider=uc.server_id
                   AND c.key_id=uc.user_id AND c.revoked_at IS NULL
                 RETURNING c.key_id",
                &[&server_id, &now],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .execute(
                "DELETE FROM public.mcp_user_credentials WHERE server_id=$1",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?;
        for row in disconnected {
            let owner: String = row
                .try_get("key_id")
                .map_err(|_| corrupt("credential_owner"))?;
            self.append_connection_audit(
                &transaction,
                &ActorId::new(owner),
                server_id,
                "mcp.account_disconnected",
                Some((AuditLabel::new("oauth_client_rotated"), false)),
            )
            .await?;
        }
        let (id, created_at) = next_event_coordinates(&transaction)
            .await
            .map_err(query_unavailable)?;
        let event = AuditEvent {
            id,
            actor: Some(auth.actor().clone()),
            event_type: AuditEventType::parse("mcp.oauth_client_registered")
                .ok_or_else(|| corrupt("audit_event"))?,
            target_kind: AuditLabel::new("mcp_server"),
            target_id: Some(AuditIdentifier::new(server_id).map_err(|_| corrupt("server_id"))?),
            payload: AuditPayload::empty(),
            created_at,
        };
        append_event_in_transaction(&transaction, &event, self.checkpoint_key.expose())
            .await
            .map_err(query_unavailable)?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "MCP OAuth client registration commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        Ok(McpOAuthClientRegistered::success())
    }

    async fn add_curated_server(
        &self,
        auth: &AuthContext,
        key: &str,
    ) -> Result<McpServerMutation, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        if !auth.has_role(Role::Admin) {
            return Err(McpConnectionError::NotVisible);
        }
        if key != GOOGLE_DRIVE_SERVER_ID {
            return Err(McpConnectionError::InvalidInput {
                field: "catalogue_key",
            });
        }
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let current: bool = transaction
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM public.users u
                     WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                       AND EXISTS(SELECT 1 FROM public.user_roles ur
                                   WHERE ur.user_id=u.id AND ur.role='admin')
                       AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                       WHERE ra.email=lower(u.email)))",
                &[&auth.actor().as_str(), &generation],
            )
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("admin_scope"))?;
        if !current {
            return Err(McpConnectionError::NotVisible);
        }
        let existing = transaction
            .query_opt(
                "SELECT url,vendor,provenance,transport
                   FROM public.mcp_servers WHERE id=$1 FOR UPDATE",
                &[&key],
            )
            .await
            .map_err(query_unavailable)?;
        if let Some(row) = existing {
            let endpoint: String = row.try_get("url").map_err(|_| corrupt("server_endpoint"))?;
            let vendor: String = row.try_get("vendor").map_err(|_| corrupt("vendor"))?;
            let provenance: String = row
                .try_get("provenance")
                .map_err(|_| corrupt("provenance"))?;
            let transport: Option<String> =
                row.try_get("transport").map_err(|_| corrupt("transport"))?;
            if endpoint != GOOGLE_DRIVE_API_BASE
                || vendor != GOOGLE_DRIVE_VENDOR
                || provenance != GOOGLE_DRIVE_PROVENANCE
                || transport
                    .as_deref()
                    .is_some_and(|value| value != GOOGLE_DRIVE_TRANSPORT)
            {
                return Err(McpConnectionError::Conflict {
                    resource: "mcp_server_identity",
                });
            }
            transaction
                .execute(
                    "UPDATE public.mcp_servers SET title='Google Drive',vendor='Google',
                       url=$2,provenance='first-party',transport='google_drive_rest',
                       added_by=$3,updated_at=clock_timestamp() WHERE id=$1",
                    &[&key, &GOOGLE_DRIVE_API_BASE, &auth.actor().as_str()],
                )
                .await
                .map_err(query_unavailable)?;
        } else {
            transaction
                .execute(
                    "INSERT INTO public.mcp_servers(
                       id,title,vendor,url,provenance,credential_id,tools_refreshed_at,last_error,
                       added_by,created_at,updated_at,catalog_generation,catalog_hash,
                       catalog_transport_fingerprint,credential_generation,transport
                     ) VALUES($1,'Google Drive','Google',$2,'first-party',NULL,NULL,NULL,$3,
                              clock_timestamp(),clock_timestamp(),NULL,NULL,NULL,0,
                              'google_drive_rest')",
                    &[&key, &GOOGLE_DRIVE_API_BASE, &auth.actor().as_str()],
                )
                .await
                .map_err(query_unavailable)?;
        }
        append_configuration_audit(
            &transaction,
            auth.actor(),
            key,
            "mcp_server_saved",
            self.checkpoint_key.expose(),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "curated MCP server commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        drop(client);
        let refresh = self
            .catalog
            .refresh(GOOGLE_DRIVE_SERVER_ID, None)
            .await
            .map_err(map_catalog_failure)?;
        mutation_receipt(GOOGLE_DRIVE_SERVER_ID, &refresh)
    }

    async fn add_custom_server(
        &self,
        auth: &AuthContext,
        registration: &McpCustomServerRegistration,
    ) -> Result<McpServerMutation, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        if !auth.has_role(Role::Admin) {
            return Err(McpConnectionError::NotVisible);
        }
        let prepared = prepare_custom_server(registration)?;
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let current: bool = transaction
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM public.users u
                     WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                       AND EXISTS(SELECT 1 FROM public.user_roles ur
                                   WHERE ur.user_id=u.id AND ur.role='admin')
                       AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                       WHERE ra.email=lower(u.email)))",
                &[&auth.actor().as_str(), &generation],
            )
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("admin_scope"))?;
        if !current {
            return Err(McpConnectionError::NotVisible);
        }
        let mut old_credential_id = None;
        if let Some(row) = transaction
            .query_opt(
                "SELECT provenance,credential_id FROM public.mcp_servers WHERE id=$1 FOR UPDATE",
                &[&prepared.id],
            )
            .await
            .map_err(query_unavailable)?
        {
            let provenance: String = row
                .try_get("provenance")
                .map_err(|_| corrupt("provenance"))?;
            if provenance != "custom" {
                return Err(McpConnectionError::Conflict {
                    resource: "mcp_server_identity",
                });
            }
            old_credential_id = row
                .try_get("credential_id")
                .map_err(|_| corrupt("credential_id"))?;
        }
        if let Some(credential_id) = prepared.credential_id {
            let credential = transaction
                .query_opt(
                    "SELECT kind,provider,revoked_at FROM public.credentials WHERE id=$1 FOR SHARE",
                    &[&credential_id],
                )
                .await
                .map_err(query_unavailable)?
                .ok_or(McpConnectionError::InvalidInput {
                    field: "credential_id",
                })?;
            let kind: crate::db::types::CredentialKind = credential
                .try_get("kind")
                .map_err(|_| corrupt("credential_kind"))?;
            let provider: String = credential
                .try_get("provider")
                .map_err(|_| corrupt("credential_provider"))?;
            let revoked_at: Option<OffsetDateTime> = credential
                .try_get("revoked_at")
                .map_err(|_| corrupt("credential_revoked_at"))?;
            if kind != crate::db::types::CredentialKind::Mcp
                || provider != prepared.id
                || revoked_at.is_some()
            {
                return Err(McpConnectionError::InvalidInput {
                    field: "credential_id",
                });
            }
        }
        transaction
            .execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,credential_id,tools_refreshed_at,last_error,
                   added_by,created_at,updated_at,catalog_generation,catalog_hash,
                   catalog_transport_fingerprint,credential_generation,transport,
                   egress_allow_cidrs
                 ) VALUES($1,$2,$3,$4,'custom',$5,NULL,NULL,$6,clock_timestamp(),
                          clock_timestamp(),NULL,NULL,NULL,0,'mcp',$7)
                 ON CONFLICT (id) DO UPDATE SET
                   title=EXCLUDED.title,vendor=EXCLUDED.vendor,url=EXCLUDED.url,
                   credential_generation=coalesce(public.mcp_servers.credential_generation,0)
                     + CASE WHEN public.mcp_servers.credential_id IS DISTINCT FROM EXCLUDED.credential_id
                            THEN 1 ELSE 0 END,
                   credential_id=EXCLUDED.credential_id,added_by=EXCLUDED.added_by,
                   egress_allow_cidrs=EXCLUDED.egress_allow_cidrs,last_error=NULL,
                   updated_at=clock_timestamp()",
                &[
                    &prepared.id,
                    &prepared.title,
                    &prepared.vendor,
                    &prepared.url,
                    &prepared.credential_id,
                    &auth.actor().as_str(),
                    &prepared.egress_allow_cidrs,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if let Some(old_credential_id) = old_credential_id
            && Some(old_credential_id) != prepared.credential_id
        {
            transaction
                .execute(
                    "UPDATE public.credentials SET
                       revoked_at=coalesce(revoked_at,clock_timestamp()),
                       updated_at=clock_timestamp(),
                       metadata=coalesce(metadata,'{}'::jsonb)
                         || jsonb_build_object('revocation_reason','mcp_server_credential_replaced')
                     WHERE id=$1",
                    &[&old_credential_id],
                )
                .await
                .map_err(query_unavailable)?;
        }
        append_configuration_audit(
            &transaction,
            auth.actor(),
            &prepared.id,
            "mcp_server_saved",
            self.checkpoint_key.expose(),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "custom MCP server commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        drop(client);
        self.refresh_configured_catalog(auth, &prepared.id).await
    }

    async fn remove_server(
        &self,
        auth: &AuthContext,
        server_id: &str,
    ) -> Result<McpServerRemoved, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        if !auth.has_role(Role::Admin) {
            return Err(McpConnectionError::NotVisible);
        }
        validate_server_id(server_id)?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        ensure_transaction_actor(&transaction, auth, true).await?;
        let row = transaction
            .query_opt(
                "SELECT s.url,coalesce(s.transport,'mcp') AS transport,
                        coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs,
                        s.credential_id
                   FROM public.mcp_servers s WHERE s.id=$1 FOR UPDATE OF s",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpConnectionError::NotVisible)?;
        let resource: String = row.try_get("url").map_err(|_| corrupt("server_endpoint"))?;
        let resource_valid = valid_server_removal_resource(&resource);
        let transport_text: String = row.try_get("transport").map_err(|_| corrupt("transport"))?;
        let transport = VendorTransportKind::parse(&transport_text).ok();
        let egress_allow_cidrs: Vec<String> = row
            .try_get("egress_allow_cidrs")
            .map_err(|_| corrupt("egress_allow_cidrs"))?;
        let egress_valid = parse_stored_mcp_egress(&egress_allow_cidrs).is_ok();
        let transport_valid = match transport {
            Some(VendorTransportKind::Mcp) => true,
            Some(VendorTransportKind::GoogleDriveRest) => {
                server_id == GOOGLE_DRIVE_SERVER_ID
                    && resource == GOOGLE_DRIVE_API_BASE
                    && egress_allow_cidrs.is_empty()
                    && self.drive_oauth.is_some()
            }
            None => false,
        };
        let automatic_context_valid = resource_valid && egress_valid && transport_valid;
        let server_credential: Option<Uuid> = row
            .try_get("credential_id")
            .map_err(|_| corrupt("credential_id"))?;
        let mut owned_server_credential = None;
        let mut revocation_client = None;
        if let Some(credential_id) = server_credential {
            let credential = transaction
                .query_opt(
                    "SELECT kind,provider,encrypted_value,revoked_at
                       FROM public.credentials WHERE id=$1 FOR UPDATE",
                    &[&credential_id],
                )
                .await
                .map_err(query_unavailable)?;
            if let Some(credential) = credential {
                let kind: crate::db::types::CredentialKind = credential
                    .try_get("kind")
                    .map_err(|_| corrupt("credential_kind"))?;
                let provider: String = credential
                    .try_get("provider")
                    .map_err(|_| corrupt("credential_provider"))?;
                if provider == server_id
                    && matches!(
                        kind,
                        crate::db::types::CredentialKind::Mcp
                            | crate::db::types::CredentialKind::McpOauthClient
                    )
                {
                    owned_server_credential = Some((credential_id, kind));
                    let revoked_at: Option<OffsetDateTime> = credential
                        .try_get("revoked_at")
                        .map_err(|_| corrupt("credential_revoked_at"))?;
                    if kind == crate::db::types::CredentialKind::McpOauthClient
                        && revoked_at.is_none()
                        && automatic_context_valid
                    {
                        let encrypted: String = credential
                            .try_get("encrypted_value")
                            .map_err(|_| corrupt("credential_value"))?;
                        let usable = self
                            .vault
                            .open(
                                &credential_id,
                                SecretKind::McpOauthClient,
                                SecretPrincipal::Deployment,
                                SecretPrincipal::Service(ServiceId::new(server_id)),
                                &encrypted,
                            )
                            .ok()
                            .map(|opened| opened.into_secret())
                            .is_some_and(|secret| {
                                self.oauth.validate_stored_client(secret.expose()).is_ok()
                            });
                        if usable {
                            revocation_client = Some(credential_id);
                        }
                    }
                }
            }
        }
        let revocation_context = serde_json::to_value(RemovedServerRevocationContext {
            version: REMOVED_SERVER_REVOCATION_VERSION,
            resource,
            transport: transport_text,
            client_credential_id: revocation_client,
            egress_allow_cidrs,
        })
        .map_err(|_| corrupt("server_removal_revocation"))?;
        let user_revocation_status = if revocation_client.is_some() {
            "pending"
        } else {
            "operator_required"
        };
        let disconnected = transaction
            .query(
                "WITH candidates AS MATERIALIZED (
                    SELECT id,key_id,(revoked_at IS NULL) AS was_active
                      FROM public.credentials
                     WHERE kind='mcp_user_token' AND provider=$1
                       AND (revoked_at IS NULL OR
                            (metadata->>'revocation_status' IN ('pending','revoking')
                             AND NOT (coalesce(metadata->>'revocation_reason'='credential_revoked',false)
                                      AND metadata ? 'credential_revocation')))
                     FOR UPDATE
                 )
                 UPDATE public.credentials c SET
                   revoked_at=coalesce(c.revoked_at,clock_timestamp()),
                   updated_at=clock_timestamp(),
                   metadata=coalesce(c.metadata,'{}'::jsonb)
                     || jsonb_build_object(
                          'revocation_reason','mcp_server_removed',
                          'revocation_status',$2::text,
                          'server_removal_revocation',$3::jsonb)
                     || CASE WHEN $4::boolean
                             THEN jsonb_build_object('operator_required_at',clock_timestamp())
                             ELSE '{}'::jsonb END
                  FROM candidates WHERE c.id=candidates.id
                 RETURNING c.key_id,candidates.was_active",
                &[
                    &server_id,
                    &user_revocation_status,
                    &revocation_context,
                    &revocation_client.is_none(),
                ],
            )
            .await
            .map_err(query_unavailable)?;
        let mut disconnected_actors = BTreeSet::new();
        for row in &disconnected {
            let was_active: bool = row
                .try_get("was_active")
                .map_err(|_| corrupt("credential_revocation_state"))?;
            if was_active {
                disconnected_actors.insert(
                    row.try_get::<_, String>("key_id")
                        .map_err(|_| corrupt("credential_owner"))?,
                );
            }
        }
        if let Some((server_credential, credential_kind)) = owned_server_credential {
            let automatic_user_tokens = revocation_client.is_some() && !disconnected.is_empty();
            let client_status = if automatic_user_tokens {
                "retained_for_user_token_revocation"
            } else {
                "operator_required"
            };
            let user_token_revocations_completed =
                revocation_client.is_some() && disconnected.is_empty();
            let operator_required = !automatic_user_tokens;
            let updated = transaction
                .execute(
                    "UPDATE public.credentials SET
                       revoked_at=coalesce(revoked_at,clock_timestamp()),
                       updated_at=clock_timestamp(),
                       metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object(
                         'revocation_reason','mcp_server_removed',
                         'revocation_status',$2::text,
                         'server_removal_revocation',$3::jsonb)
                         || CASE WHEN $6::boolean
                                 THEN jsonb_build_object(
                                   'user_token_revocations_completed_at',clock_timestamp())
                                 ELSE '{}'::jsonb END
                         || CASE WHEN $7::boolean
                                 THEN jsonb_build_object('operator_required_at',clock_timestamp())
                                 ELSE '{}'::jsonb END
                     WHERE id=$1 AND provider=$4 AND kind=$5",
                    &[
                        &server_credential,
                        &client_status,
                        &revocation_context,
                        &server_id,
                        &credential_kind,
                        &user_token_revocations_completed,
                        &operator_required,
                    ],
                )
                .await
                .map_err(query_unavailable)?;
            if updated != 1 {
                return Err(corrupt("server_credential_binding"));
            }
        }
        transaction
            .execute(
                "DELETE FROM public.plugin_grants g
                  WHERE g.kind='mcp' AND split_part(g.ref,'/',1)=$1",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .execute("DELETE FROM public.mcp_servers WHERE id=$1", &[&server_id])
            .await
            .map_err(query_unavailable)?;
        for actor_id in disconnected_actors {
            self.append_connection_audit(
                &transaction,
                &ActorId::new(actor_id),
                server_id,
                "mcp.account_disconnected",
                Some((AuditLabel::new("mcp_server_removed"), false)),
            )
            .await?;
        }
        append_configuration_audit(
            &transaction,
            auth.actor(),
            server_id,
            "mcp_server_removed",
            self.checkpoint_key.expose(),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "MCP server removal commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        Ok(McpServerRemoved::success())
    }

    async fn refresh_server(
        &self,
        auth: &AuthContext,
        server_id: &str,
    ) -> Result<McpServerMutation, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        if !auth.has_role(Role::Admin) {
            return Err(McpConnectionError::NotVisible);
        }
        self.refresh_configured_catalog(auth, server_id).await
    }

    async fn save_skill(
        &self,
        auth: &AuthContext,
        mutation: &PluginSkillMutation,
    ) -> Result<PluginSkills, McpConnectionError> {
        self.save_skill_revision(auth, mutation).await
    }

    async fn remove_skill(
        &self,
        auth: &AuthContext,
        slug: &str,
        expected_revision: i64,
    ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
        self.remove_skill_revision(auth, slug, expected_revision)
            .await
    }

    async fn set_grant(
        &self,
        auth: &AuthContext,
        mutation: &PluginGrantMutation,
        enabled: bool,
    ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        validate_plugin_grant(mutation)?;
        let mcp_requires_admin = mutation.kind == PluginGrantKind::Mcp;
        if mcp_requires_admin && !auth.has_role(Role::Admin) {
            return Err(McpConnectionError::NotVisible);
        }
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        ensure_transaction_actor(
            &transaction,
            auth,
            mcp_requires_admin || auth.has_role(Role::Admin),
        )
        .await?;
        let agent = load_agent_facts(&transaction, &self.tenant, &mutation.agent_id).await?;
        let actor = AgentActor {
            id: auth.actor().as_str(),
            admin: auth.has_role(Role::Admin),
        };
        if !can_access_agent(&actor, &agent.as_borrowed())
            && (enabled || !auth.has_role(Role::Admin))
        {
            return Err(McpConnectionError::NotVisible);
        }
        match mutation.kind {
            PluginGrantKind::Mcp => {
                let (server_id, tool_name) = parse_mcp_reference(&mutation.reference)?;
                if enabled {
                    let row = transaction
                        .query_opt(
                            "SELECT s.catalog_generation,t.schema_hash,t.effect,
                                    s.catalog_transport_fingerprint,
                                    coalesce(s.credential_generation,0) AS credential_generation
                               FROM public.mcp_tools t
                               JOIN public.mcp_servers s ON s.id=t.server_id
                              WHERE t.server_id=$1 AND t.name=$2 AND t.available=true
                                AND s.catalog_generation IS NOT NULL
                                AND t.catalog_generation=s.catalog_generation
                                AND s.catalog_transport_fingerprint IS NOT NULL
                              FOR SHARE OF s,t",
                            &[&server_id, &tool_name],
                        )
                        .await
                        .map_err(query_unavailable)?
                        .ok_or(McpConnectionError::NotVisible)?;
                    let catalog_generation: i64 = row
                        .try_get("catalog_generation")
                        .map_err(|_| corrupt("catalog_generation"))?;
                    let schema_hash: String = row
                        .try_get("schema_hash")
                        .map_err(|_| corrupt("schema_hash"))?;
                    let effect: String = row.try_get("effect").map_err(|_| corrupt("effect"))?;
                    let transport_fingerprint: String = row
                        .try_get("catalog_transport_fingerprint")
                        .map_err(|_| corrupt("transport_fingerprint"))?;
                    let credential_generation: i64 = row
                        .try_get("credential_generation")
                        .map_err(|_| corrupt("credential_generation"))?;
                    transaction
                        .execute(
                            "INSERT INTO public.plugin_grants(
                               kind,ref,agent_id,granted_by,created_at,updated_at,state,
                               catalog_generation,schema_hash,effect,transport_fingerprint,
                               credential_generation)
                             VALUES('mcp',$1,$2,$3,clock_timestamp(),clock_timestamp(),'active',
                                    $4,$5,$6,$7,$8)
                             ON CONFLICT(kind,ref,agent_id) DO UPDATE SET
                               granted_by=EXCLUDED.granted_by,updated_at=clock_timestamp(),
                               state='active',catalog_generation=EXCLUDED.catalog_generation,
                               schema_hash=EXCLUDED.schema_hash,effect=EXCLUDED.effect,
                               transport_fingerprint=EXCLUDED.transport_fingerprint,
                               credential_generation=EXCLUDED.credential_generation",
                            &[
                                &mutation.reference,
                                &mutation.agent_id,
                                &auth.actor().as_str(),
                                &catalog_generation,
                                &schema_hash,
                                &effect,
                                &transport_fingerprint,
                                &credential_generation,
                            ],
                        )
                        .await
                        .map_err(query_unavailable)?;
                } else {
                    transaction
                        .execute(
                            "DELETE FROM public.plugin_grants
                              WHERE kind='mcp' AND ref=$1 AND agent_id=$2",
                            &[&mutation.reference, &mutation.agent_id],
                        )
                        .await
                        .map_err(query_unavailable)?;
                }
            }
            PluginGrantKind::Skill => {
                if enabled || !auth.has_role(Role::Admin) {
                    let row = transaction
                        .query_opt(
                            "SELECT owner_user_id FROM public.skills WHERE slug=$1 FOR SHARE",
                            &[&mutation.reference],
                        )
                        .await
                        .map_err(query_unavailable)?
                        .ok_or(McpConnectionError::NotVisible)?;
                    let skill_owner: Option<String> = row
                        .try_get("owner_user_id")
                        .map_err(|_| corrupt("skill_owner"))?;
                    if !auth.has_role(Role::Admin)
                        && (skill_owner.as_deref() != Some(auth.actor().as_str())
                            || agent.owner_user_id.as_deref() != Some(auth.actor().as_str()))
                    {
                        return Err(McpConnectionError::NotVisible);
                    }
                }
                if enabled {
                    transaction
                        .execute(
                            "INSERT INTO public.plugin_grants(
                               kind,ref,agent_id,granted_by,created_at,updated_at,state,
                               catalog_generation,schema_hash,effect,transport_fingerprint,
                               credential_generation)
                             VALUES('skill',$1,$2,$3,clock_timestamp(),clock_timestamp(),
                                    NULL,NULL,NULL,NULL,NULL,NULL)
                             ON CONFLICT(kind,ref,agent_id) DO UPDATE SET
                               granted_by=EXCLUDED.granted_by,updated_at=clock_timestamp(),
                               state=NULL,catalog_generation=NULL,schema_hash=NULL,effect=NULL,
                               transport_fingerprint=NULL,credential_generation=NULL",
                            &[
                                &mutation.reference,
                                &mutation.agent_id,
                                &auth.actor().as_str(),
                            ],
                        )
                        .await
                        .map_err(query_unavailable)?;
                } else {
                    transaction
                        .execute(
                            "DELETE FROM public.plugin_grants
                              WHERE kind='skill' AND ref=$1 AND agent_id=$2",
                            &[&mutation.reference, &mutation.agent_id],
                        )
                        .await
                        .map_err(query_unavailable)?;
                }
            }
        }
        append_plugin_audit(
            &transaction,
            auth.actor(),
            match mutation.kind {
                PluginGrantKind::Mcp => "mcp_tool",
                PluginGrantKind::Skill => "skill",
            },
            &mutation.reference,
            if enabled {
                "plugin_granted"
            } else {
                "plugin_revoked"
            },
            Some(&mutation.agent_id),
            self.checkpoint_key.expose(),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "plugin grant mutation commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        Ok(PluginMutationAcknowledged::success())
    }

    async fn list_for_agent(
        &self,
        auth: &AuthContext,
        agent_id: &openbot_contracts::ids::BotId,
    ) -> Result<GrantedPlugins, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        validate_agent_id(agent_id.as_str())?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(query_unavailable)?;
        ensure_transaction_actor(&transaction, auth, auth.has_role(Role::Admin)).await?;
        let agent = load_agent_facts(&transaction, &self.tenant, agent_id.as_str()).await?;
        let actor = AgentActor {
            id: auth.actor().as_str(),
            admin: auth.has_role(Role::Admin),
        };
        if !can_access_agent(&actor, &agent.as_borrowed()) {
            return Err(McpConnectionError::NotVisible);
        }
        let tools = self
            .catalog
            .granted_tools_in_transaction(&transaction, agent_id, auth.actor())
            .await
            .map_err(map_catalog_failure)?
            .into_iter()
            .map(|tool| GrantedPluginTool {
                reference: format!("{}/{}", tool.server_id, tool.raw_name),
                tool_name: tool.model_name,
                description: tool.description,
                input_schema: tool.input_schema,
            })
            .collect();
        let rows = transaction
            .query(
                "SELECT s.slug,s.title,s.summary,s.instructions
                   FROM public.plugin_grants g
                   JOIN public.skills s ON g.kind='skill' AND g.ref=s.slug
                  WHERE g.agent_id=$1 ORDER BY s.slug",
                &[&agent_id.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        let skills = rows
            .iter()
            .map(decode_granted_skill)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await.map_err(query_unavailable)?;
        Ok(GrantedPlugins { tools, skills })
    }
}

#[async_trait]
impl McpOAuthCallback for PostgresMcpConnections {
    async fn complete(&self, input: McpOAuthCallbackInput) -> McpOAuthCallbackOutcome {
        let redirect_to = match self.complete_inner(&input).await {
            Ok(success) => success,
            Err(error) => {
                tracing::warn!(code = %error, "MCP OAuth callback 被拒");
                self.failure_redirect()
            }
        };
        McpOAuthCallbackOutcome { redirect_to }
    }
}

impl PostgresMcpConnections {
    async fn disconnect_candidate(
        &self,
        actor: &ActorId,
        server_id: &str,
    ) -> Result<DisconnectCandidate, McpConnectionError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                "SELECT uc.credential_id,c.kind,c.provider,c.key_id,c.encrypted_value,c.revoked_at
                   FROM public.mcp_user_credentials uc
                   JOIN public.mcp_servers s ON s.id=uc.server_id
                   JOIN public.credentials c ON c.id=uc.credential_id
                  WHERE uc.server_id=$1 AND uc.user_id=$2",
                &[&server_id, &actor.as_str()],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpConnectionError::NotVisible)?;
        let credential_id: Uuid = row
            .try_get("credential_id")
            .map_err(|_| corrupt("credential_id"))?;
        let kind: crate::db::types::CredentialKind = row
            .try_get("kind")
            .map_err(|_| corrupt("credential_kind"))?;
        let provider: String = row
            .try_get("provider")
            .map_err(|_| corrupt("credential_provider"))?;
        let key_id: String = row
            .try_get("key_id")
            .map_err(|_| corrupt("credential_owner"))?;
        let encrypted: String = row
            .try_get("encrypted_value")
            .map_err(|_| corrupt("credential_value"))?;
        let revoked: Option<OffsetDateTime> = row
            .try_get("revoked_at")
            .map_err(|_| corrupt("credential_revoked_at"))?;
        if kind != crate::db::types::CredentialKind::McpUserToken
            || provider != server_id
            || key_id != actor.as_str()
            || revoked.is_some()
        {
            return Err(McpConnectionError::NotVisible);
        }
        let refresh = self
            .vault
            .open(
                &credential_id,
                SecretKind::McpUserToken,
                SecretPrincipal::Actor(actor.clone()),
                SecretPrincipal::Service(ServiceId::new(server_id)),
                &encrypted,
            )
            .ok()
            .map(|value| value.into_secret());
        Ok(DisconnectCandidate {
            credential_id,
            refresh,
        })
    }

    async fn tombstone_connection(
        &self,
        auth: &AuthContext,
        server_id: &str,
        credential_id: Uuid,
    ) -> Result<(), McpConnectionError> {
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let now: OffsetDateTime = transaction
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("clock"))?;
        let updated = transaction
            .execute(
                "UPDATE public.credentials c SET revoked_at=$5,updated_at=$5,
                   metadata=coalesce(c.metadata,'{}'::jsonb)||
                            jsonb_build_object('revocation_status','pending',
                                               'revocation_reason','user_disconnect')
                 WHERE c.id=$1 AND c.kind='mcp_user_token' AND c.provider=$2
                   AND c.key_id=$3 AND c.revoked_at IS NULL
                   AND EXISTS(SELECT 1 FROM public.users u WHERE u.id=$3
                               AND coalesce(u.auth_generation,0)=$4
                               AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                               AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                               WHERE ra.email=lower(u.email)))",
                &[
                    &credential_id,
                    &server_id,
                    &auth.actor().as_str(),
                    &generation,
                    &now,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if updated != 1 {
            return Err(McpConnectionError::NotVisible);
        }
        let deleted = transaction
            .execute(
                "DELETE FROM public.mcp_user_credentials
                  WHERE server_id=$1 AND user_id=$2 AND credential_id=$3",
                &[&server_id, &auth.actor().as_str(), &credential_id],
            )
            .await
            .map_err(query_unavailable)?;
        if deleted != 1 {
            return Err(McpConnectionError::NotVisible);
        }
        self.append_connection_audit(
            &transaction,
            auth.actor(),
            server_id,
            "mcp.account_disconnected",
            Some((AuditLabel::new("user_disconnect"), false)),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "MCP disconnect local tombstone commit 结果未知");
            McpConnectionError::CommitUnknown
        })
    }
}

impl core::fmt::Debug for PostgresMcpConnections {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresMcpConnections")
            .field("deployment", &self.deployment)
            .field("tenant", &self.tenant)
            .field("state_key", &"<redacted>")
            .field("checkpoint_key", &"<redacted>")
            .field("callback_uri", &"<configured>")
            .finish_non_exhaustive()
    }
}

struct ServerClientMaterial {
    credential_id: Uuid,
    endpoint: String,
    client: SecretBytes,
    transport: VendorTransportKind,
    egress_allow_cidrs: Vec<String>,
    egress_allowlist: CidrAllowlist,
}

struct OldRefresh {
    credential_id: Uuid,
    refresh: SecretBytes,
}

struct DisconnectCandidate {
    credential_id: Uuid,
    refresh: Option<SecretBytes>,
}

struct PendingRevocation {
    credential_id: Uuid,
    server_id: String,
    actor_id: String,
    encrypted_value: String,
    metadata: serde_json::Value,
}

const REMOVED_SERVER_REVOCATION_VERSION: u8 = 1;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovedServerRevocationContext {
    version: u8,
    resource: String,
    transport: String,
    client_credential_id: Option<Uuid>,
    egress_allow_cidrs: Vec<String>,
}

impl core::fmt::Debug for RemovedServerRevocationContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RemovedServerRevocationContext")
            .field("version", &self.version)
            .field("resource", &"<redacted-origin>")
            .field("transport", &self.transport)
            .field("has_client", &self.client_credential_id.is_some())
            .field("egress_allowlist_entries", &self.egress_allow_cidrs.len())
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAttempt {
    version: u8,
    deployment_id: String,
    tenant_id: String,
    actor_id: String,
    auth_generation: i64,
    server_id: String,
    client_credential_id: Uuid,
    resource: String,
    transport: String,
    egress_allow_cidrs: Vec<String>,
    code_verifier: String,
    redirect_uri: String,
    issuer: String,
    issuer_required: bool,
    requested_scope: String,
    return_to: McpOAuthReturnTo,
    expires_at_unix_seconds: i64,
}

impl Drop for StoredAttempt {
    fn drop(&mut self) {
        self.code_verifier.zeroize();
    }
}

fn callback_uri(
    public_url: &str,
    scheme_policy: SchemePolicy,
) -> Result<String, McpConnectionError> {
    let url = Url::parse(public_url).map_err(|_| McpConnectionError::InvalidInput {
        field: "public_url",
    })?;
    let allowed = match scheme_policy {
        SchemePolicy::HttpsOnly => url.scheme() == "https",
        SchemePolicy::HttpOrHttps => {
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && match url.host() {
                        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
                        Some(url::Host::Ipv4(address)) => address.is_loopback(),
                        Some(url::Host::Ipv6(address)) => address.is_loopback(),
                        None => false,
                    })
        }
    };
    if !allowed
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(McpConnectionError::InvalidInput {
            field: "public_url",
        });
    }
    Ok(format!(
        "{}{}",
        public_url.trim_end_matches('/'),
        CALLBACK_PATH
    ))
}

fn validate_app_origin(value: &str) -> Result<String, McpConnectionError> {
    let url =
        Url::parse(value).map_err(|_| McpConnectionError::InvalidInput { field: "app_url" })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(McpConnectionError::InvalidInput { field: "app_url" });
    }
    Ok(value.to_owned())
}

fn random_base64<const N: usize>() -> Result<String, McpConnectionError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| McpConnectionError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn encoded_registration(
    registration: &McpOAuthClientRegistration,
) -> Result<Zeroizing<Vec<u8>>, McpConnectionError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Wire<'a> {
        client_id: &'a str,
        client_secret: &'a str,
        issuer: &'a str,
        token_endpoint_auth_method: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_metadata_url: Option<&'a str>,
    }
    let auth_method = match registration.auth_method() {
        McpOAuthClientAuthMethod::ClientSecretBasic => "client_secret_basic",
        McpOAuthClientAuthMethod::ClientSecretPost => "client_secret_post",
    };
    serde_json::to_vec(&Wire {
        client_id: registration.client_id(),
        client_secret: registration.expose_client_secret(),
        issuer: registration.issuer(),
        token_endpoint_auth_method: auth_method,
        resource_metadata_url: registration.resource_metadata_url(),
    })
    .map(Zeroizing::new)
    .map_err(|_| corrupt("oauth_client"))
}

fn valid_server_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.contains("__")
        && !value.contains('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

struct PreparedCustomServer {
    id: String,
    title: String,
    vendor: String,
    url: String,
    credential_id: Option<Uuid>,
    egress_allow_cidrs: Option<Vec<String>>,
}

struct PreparedSkillMutation {
    slug: String,
    title: String,
    summary: String,
    instructions: String,
    deployment_wide: bool,
}

fn prepare_skill_mutation(
    mutation: &PluginSkillMutation,
) -> Result<PreparedSkillMutation, McpConnectionError> {
    validate_skill_slug(&mutation.slug)?;
    if mutation.title.is_empty()
        || mutation.title.len() > MAX_SKILL_TITLE_BYTES
        || mutation.title.chars().any(char::is_control)
    {
        return Err(McpConnectionError::InvalidInput { field: "title" });
    }
    if mutation.summary.len() > MAX_SKILL_SUMMARY_BYTES
        || mutation.summary.chars().any(char::is_control)
    {
        return Err(McpConnectionError::InvalidInput { field: "summary" });
    }
    if mutation.instructions.is_empty()
        || mutation.instructions.len() > MAX_SKILL_INSTRUCTIONS_BYTES
        || mutation.instructions.as_bytes().contains(&0)
    {
        return Err(McpConnectionError::InvalidInput {
            field: "instructions",
        });
    }
    Ok(PreparedSkillMutation {
        slug: mutation.slug.clone(),
        title: mutation.title.clone(),
        summary: mutation.summary.clone(),
        instructions: mutation.instructions.clone(),
        deployment_wide: mutation.deployment_wide,
    })
}

fn validate_skill_slug(slug: &str) -> Result<(), McpConnectionError> {
    if !openbot_contracts::mcp::valid_skill_slug(slug) {
        return Err(McpConnectionError::InvalidInput { field: "slug" });
    }
    Ok(())
}

fn validate_agent_id(agent_id: &str) -> Result<(), McpConnectionError> {
    if !valid_server_id(agent_id) {
        return Err(McpConnectionError::InvalidInput { field: "agent_id" });
    }
    Ok(())
}

fn validate_plugin_grant(mutation: &PluginGrantMutation) -> Result<(), McpConnectionError> {
    validate_agent_id(&mutation.agent_id)?;
    match mutation.kind {
        PluginGrantKind::Mcp => parse_mcp_reference(&mutation.reference).map(|_| ()),
        PluginGrantKind::Skill => validate_skill_slug(&mutation.reference),
    }
}

fn parse_mcp_reference(reference: &str) -> Result<(&str, &str), McpConnectionError> {
    let (server_id, tool_name) = reference
        .split_once('/')
        .ok_or(McpConnectionError::InvalidInput { field: "ref" })?;
    if tool_name.contains('/') {
        return Err(McpConnectionError::InvalidInput { field: "ref" });
    }
    validate_server_id(server_id)?;
    validate_tool_component(tool_name)?;
    Ok((server_id, tool_name))
}

struct StoredAgentFacts {
    owner_user_id: Option<String>,
    visibility: openbot_contracts::agent::AgentVisibility,
    system_owned: bool,
    deleted: bool,
}

impl StoredAgentFacts {
    fn as_borrowed(&self) -> AgentProfileFacts<'_> {
        AgentProfileFacts {
            owner_user_id: self.owner_user_id.as_deref(),
            visibility: self.visibility,
            system_owned: self.system_owned,
            deleted: self.deleted,
        }
    }
}

const PLUGIN_AGENT_FACTS_SQL: &str =
    "SELECT p.owner_user_id,p.visibility::text AS visibility,p.deleted_at,a.package_id,
            (a.package_id IS NULL OR dp.tenant_id=$2) AS tenant_visible
       FROM public.agents a JOIN public.agent_profiles p ON p.agent_id=a.id
       LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
      WHERE a.id=$1";

async fn load_agent_facts(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
    agent_id: &str,
) -> Result<StoredAgentFacts, McpConnectionError> {
    let sql = format!("{PLUGIN_AGENT_FACTS_SQL} FOR SHARE OF a,p");
    let row = transaction
        .query_opt(&sql, &[&agent_id, &tenant.as_str()])
        .await
        .map_err(query_unavailable)?
        .ok_or(McpConnectionError::NotVisible)?;
    decode_agent_facts(&row)
}

fn decode_agent_facts(row: &tokio_postgres::Row) -> Result<StoredAgentFacts, McpConnectionError> {
    let tenant_visible: bool = row
        .try_get("tenant_visible")
        .map_err(|_| corrupt("agent_tenant"))?;
    if !tenant_visible {
        return Err(McpConnectionError::NotVisible);
    }
    let visibility = match row
        .try_get::<_, String>("visibility")
        .map_err(|_| corrupt("agent_visibility"))?
        .as_str()
    {
        "public" => openbot_contracts::agent::AgentVisibility::Public,
        "private" => openbot_contracts::agent::AgentVisibility::Private,
        _ => return Err(corrupt("agent_visibility")),
    };
    Ok(StoredAgentFacts {
        owner_user_id: row
            .try_get("owner_user_id")
            .map_err(|_| corrupt("agent_owner"))?,
        visibility,
        system_owned: row
            .try_get::<_, Option<Uuid>>("package_id")
            .map_err(|_| corrupt("agent_package"))?
            .is_some(),
        deleted: row
            .try_get::<_, Option<OffsetDateTime>>("deleted_at")
            .map_err(|_| corrupt("agent_deleted"))?
            .is_some(),
    })
}

async fn ensure_transaction_actor(
    transaction: &tokio_postgres::Transaction<'_>,
    auth: &AuthContext,
    require_admin: bool,
) -> Result<(), McpConnectionError> {
    let generation =
        i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
    let current = transaction
        .query_opt(
            "SELECT u.id FROM public.users u
              WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                AND (NOT $3::boolean OR EXISTS(
                      SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role='admin'))
                AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                WHERE ra.email=lower(u.email))
              FOR SHARE OF u",
            &[&auth.actor().as_str(), &generation, &require_admin],
        )
        .await
        .map_err(query_unavailable)?;
    if current.is_some() {
        Ok(())
    } else {
        Err(McpConnectionError::NotVisible)
    }
}

async fn visible_skills<C: GenericClient + Sync>(
    client: &C,
    auth: &AuthContext,
    tenant: &TenantId,
) -> Result<Vec<McpAdminSkill>, McpConnectionError> {
    let is_admin = auth.has_role(Role::Admin);
    let skill_rows = client
        .query(
            "SELECT id,slug,owner_user_id,title,summary,instructions,origin,installed_by,
                      coalesce(revision,1)::bigint AS revision,updated_at
               FROM public.skills
              WHERE $2::boolean OR owner_user_id IS NULL OR owner_user_id=$1
              ORDER BY title,id",
            &[&auth.actor().as_str(), &is_admin],
        )
        .await
        .map_err(query_unavailable)?;
    let skill_grant_rows = client
        .query(
            "SELECT g.ref,g.agent_id
               FROM public.plugin_grants g
               JOIN public.skills s ON g.kind='skill' AND g.ref=s.slug
               JOIN public.agents a ON a.id=g.agent_id
               JOIN public.agent_profiles p ON p.agent_id=a.id
               LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
              WHERE ($2::boolean OR s.owner_user_id IS NULL OR s.owner_user_id=$1)
                AND p.deleted_at IS NULL
                AND (a.package_id IS NULL OR dp.tenant_id=$3)
                AND ($2::boolean OR p.visibility='public' OR p.owner_user_id=$1)
              ORDER BY g.ref,g.agent_id",
            &[&auth.actor().as_str(), &is_admin, &tenant.as_str()],
        )
        .await
        .map_err(query_unavailable)?;
    let mut skill_grants = BTreeMap::<String, Vec<String>>::new();
    for row in skill_grant_rows {
        let reference: String = row.try_get("ref").map_err(|_| corrupt("skill_ref"))?;
        validate_skill_slug(&reference).map_err(|_| corrupt("skill_ref"))?;
        let agent_id: String = row
            .try_get("agent_id")
            .map_err(|_| corrupt("grant_agent_id"))?;
        validate_agent_id(&agent_id).map_err(|_| corrupt("grant_agent_id"))?;
        skill_grants.entry(reference).or_default().push(agent_id);
    }
    let mut skills = Vec::with_capacity(skill_rows.len());
    for row in skill_rows {
        let slug: String = row.try_get("slug").map_err(|_| corrupt("skill_slug"))?;
        skills.push(decode_admin_skill(
            &row,
            skill_grants.remove(&slug).unwrap_or_default(),
        )?);
    }
    Ok(skills)
}

fn decode_admin_skill(
    row: &tokio_postgres::Row,
    granted_to: Vec<String>,
) -> Result<McpAdminSkill, McpConnectionError> {
    let id: String = row.try_get("id").map_err(|_| corrupt("skill_id"))?;
    if id.is_empty() || id.len() > 256 || id.as_bytes().contains(&0) {
        return Err(corrupt("skill_id"));
    }
    let slug: String = row.try_get("slug").map_err(|_| corrupt("skill_slug"))?;
    let owner_user_id: Option<String> = row
        .try_get("owner_user_id")
        .map_err(|_| corrupt("skill_owner"))?;
    let title: String = row.try_get("title").map_err(|_| corrupt("skill_title"))?;
    let summary: String = row
        .try_get("summary")
        .map_err(|_| corrupt("skill_summary"))?;
    let instructions: String = row
        .try_get("instructions")
        .map_err(|_| corrupt("skill_instructions"))?;
    prepare_skill_mutation(&PluginSkillMutation {
        slug: slug.clone(),
        title: title.clone(),
        summary: summary.clone(),
        instructions: instructions.clone(),
        deployment_wide: owner_user_id.is_none(),
        expected_revision: None,
    })
    .map_err(|_| corrupt("skill_projection"))?;
    let origin: String = row.try_get("origin").map_err(|_| corrupt("skill_origin"))?;
    if origin.is_empty() || origin.len() > 256 || origin.chars().any(char::is_control) {
        return Err(corrupt("skill_origin"));
    }
    let installed_by: Option<String> = row
        .try_get("installed_by")
        .map_err(|_| corrupt("skill_installed_by"))?;
    for identity in [owner_user_id.as_deref(), installed_by.as_deref()]
        .into_iter()
        .flatten()
    {
        if identity.is_empty() || identity.len() > 4_096 || identity.as_bytes().contains(&0) {
            return Err(corrupt("skill_actor"));
        }
    }
    let revision: i64 = row
        .try_get("revision")
        .map_err(|_| corrupt("skill_revision"))?;
    if revision <= 0 {
        return Err(corrupt("skill_revision"));
    }
    let updated_at = row
        .try_get("updated_at")
        .map_err(|_| corrupt("skill_updated_at"))?;
    let skill = McpAdminSkill {
        id,
        slug,
        owner_user_id,
        title,
        summary,
        instructions,
        origin,
        installed_by,
        revision,
        updated_at,
        granted_to,
    };
    skill
        .revision_snapshot()
        .map_err(|_| corrupt("skill_snapshot"))?;
    Ok(skill)
}

fn decode_granted_skill(
    row: &tokio_postgres::Row,
) -> Result<GrantedPluginSkill, McpConnectionError> {
    let slug: String = row.try_get("slug").map_err(|_| corrupt("skill_slug"))?;
    validate_skill_slug(&slug).map_err(|_| corrupt("skill_slug"))?;
    let title: String = row.try_get("title").map_err(|_| corrupt("skill_title"))?;
    let summary: String = row
        .try_get("summary")
        .map_err(|_| corrupt("skill_summary"))?;
    let instructions: String = row
        .try_get("instructions")
        .map_err(|_| corrupt("skill_instructions"))?;
    prepare_skill_mutation(&PluginSkillMutation {
        slug: slug.clone(),
        title: title.clone(),
        summary: summary.clone(),
        instructions: instructions.clone(),
        deployment_wide: false,
        expected_revision: None,
    })
    .map_err(|_| corrupt("skill_projection"))?;
    Ok(GrantedPluginSkill {
        slug,
        title,
        summary,
        instructions,
    })
}

async fn append_plugin_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorId,
    target_kind: &'static str,
    target_id: &str,
    change: &'static str,
    agent_id: Option<&str>,
    checkpoint_key: &[u8],
) -> Result<(), McpConnectionError> {
    let mut facts = vec![AuditFact::ConfigurationChange(AuditLabel::new(change))];
    if let Some(agent_id) = agent_id {
        facts.push(AuditFact::Bot(
            AuditIdentifier::new(agent_id).map_err(|_| corrupt("agent_id"))?,
        ));
    }
    let payload = AuditPayload::from_facts(facts).map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(query_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(actor.clone()),
        event_type: AuditEventType::parse("configuration.changed")
            .ok_or_else(|| corrupt("audit_event"))?,
        target_kind: AuditLabel::new(target_kind),
        target_id: Some(AuditIdentifier::new(target_id).map_err(|_| corrupt("target_id"))?),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(query_unavailable)
}

fn prepare_custom_server(
    registration: &McpCustomServerRegistration,
) -> Result<PreparedCustomServer, McpConnectionError> {
    if registration.id == GOOGLE_DRIVE_SERVER_ID
        || registration.id.len() < 2
        || registration.id.len() > MAX_CUSTOM_SERVER_ID_BYTES
        || !registration
            .id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || registration.id.starts_with('-')
        || registration.id.ends_with('-')
    {
        return Err(McpConnectionError::InvalidInput { field: "server_id" });
    }
    if registration.title.is_empty()
        || registration.title.trim() != registration.title
        || registration.title.len() > MAX_CUSTOM_SERVER_TITLE_BYTES
        || registration.title.as_bytes().contains(&0)
    {
        return Err(McpConnectionError::InvalidInput { field: "title" });
    }
    if registration.url.is_empty()
        || registration.url.len() > MAX_CUSTOM_SERVER_URL_BYTES
        || registration.url.as_bytes().contains(&0)
    {
        return Err(McpConnectionError::InvalidInput { field: "url" });
    }
    let parsed = Url::parse(&registration.url)
        .map_err(|_| McpConnectionError::InvalidInput { field: "url" })?;
    if parsed.scheme() != "https"
        || parsed.cannot_be_a_base()
        || parsed.host_str().is_none()
        || parsed.port_or_known_default().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(McpConnectionError::InvalidInput { field: "url" });
    }
    let cidr_bytes = registration
        .egress_allow_cidrs
        .iter()
        .map(String::len)
        .sum::<usize>();
    if registration.egress_allow_cidrs.len() > MAX_MCP_EGRESS_CIDRS
        || cidr_bytes > MAX_MCP_EGRESS_CIDR_BYTES
    {
        return Err(McpConnectionError::InvalidInput {
            field: "egress_allow_cidrs",
        });
    }
    CidrAllowlist::parse_exact(registration.egress_allow_cidrs.iter().map(String::as_str))
        .map_err(|_| McpConnectionError::InvalidInput {
            field: "egress_allow_cidrs",
        })?;
    let cidrs = registration
        .egress_allow_cidrs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let vendor = parsed
        .host_str()
        .ok_or(McpConnectionError::InvalidInput { field: "url" })?
        .to_ascii_lowercase();
    Ok(PreparedCustomServer {
        id: registration.id.clone(),
        title: registration.title.clone(),
        vendor,
        url: parsed.to_string(),
        credential_id: registration
            .credential_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| McpConnectionError::InvalidInput {
                field: "credential_id",
            })?,
        egress_allow_cidrs: (!cidrs.is_empty()).then_some(cidrs),
    })
}

fn validate_stored_egress(entries: &[String]) -> Result<(), McpConnectionError> {
    parse_stored_mcp_egress(entries)
        .map(|_| ())
        .map_err(|_| corrupt("egress_allow_cidrs"))
}

fn valid_server_removal_resource(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_CUSTOM_SERVER_URL_BYTES
        || value.as_bytes().contains(&0)
    {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && !url.cannot_be_a_base()
        && url.host_str().is_some()
        && url.port_or_known_default().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

const fn removed_server_material_error_is_permanent(error: McpConnectionError) -> bool {
    matches!(
        error,
        McpConnectionError::NotVisible
            | McpConnectionError::InvalidInput { .. }
            | McpConnectionError::Conflict { .. }
            | McpConnectionError::Corrupt { .. }
    )
}

fn validate_public_server_projection(
    id: &str,
    title: &str,
    vendor: &str,
    endpoint: &str,
    provenance: &str,
    transport: VendorTransportKind,
    egress_allow_cidrs: &[String],
) -> Result<(), McpConnectionError> {
    if title.is_empty()
        || title.len() > MAX_CUSTOM_SERVER_TITLE_BYTES
        || title.as_bytes().contains(&0)
        || vendor.is_empty()
        || vendor.len() > 256
        || vendor.as_bytes().contains(&0)
    {
        return Err(corrupt("server_presentation"));
    }
    let parsed = Url::parse(endpoint).map_err(|_| corrupt("server_endpoint"))?;
    if parsed.scheme() != "https"
        || parsed.cannot_be_a_base()
        || parsed.host_str().is_none()
        || parsed.port_or_known_default().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(corrupt("server_endpoint"));
    }
    match provenance {
        GOOGLE_DRIVE_PROVENANCE
            if id == GOOGLE_DRIVE_SERVER_ID
                && title == "Google Drive"
                && vendor == GOOGLE_DRIVE_VENDOR
                && endpoint == GOOGLE_DRIVE_API_BASE
                && transport == VendorTransportKind::GoogleDriveRest
                && egress_allow_cidrs.is_empty() =>
        {
            Ok(())
        }
        "custom"
            if id != GOOGLE_DRIVE_SERVER_ID
                && transport == VendorTransportKind::Mcp
                && vendor
                    == parsed
                        .host_str()
                        .ok_or_else(|| corrupt("server_endpoint"))?
                        .to_ascii_lowercase() =>
        {
            Ok(())
        }
        _ => Err(corrupt("server_identity")),
    }
}

fn validate_tool_component(value: &str) -> Result<(), McpConnectionError> {
    if value.is_empty()
        || value.len() > 64
        || value.contains("__")
        || value.contains('/')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(corrupt("tool_name"));
    }
    Ok(())
}

fn admin_effect(value: &str) -> Result<McpAdminToolEffect, McpConnectionError> {
    match value {
        "read" => Ok(McpAdminToolEffect::Read),
        "write" => Ok(McpAdminToolEffect::Write),
        "execute" => Ok(McpAdminToolEffect::Execute),
        "network" => Ok(McpAdminToolEffect::Network),
        "credential" => Ok(McpAdminToolEffect::Credential),
        _ => Err(corrupt("effect")),
    }
}

fn map_credential_failure(error: McpCredentialError) -> McpConnectionError {
    match error {
        McpCredentialError::Unavailable => McpConnectionError::Unavailable,
        McpCredentialError::AuthRequired | McpCredentialError::InsufficientScope => {
            McpConnectionError::Conflict {
                resource: "actor_catalog_credential",
            }
        }
        McpCredentialError::CommitUnknown => McpConnectionError::CommitUnknown,
        McpCredentialError::Corrupt { field } => McpConnectionError::Corrupt { field },
    }
}

async fn append_configuration_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorId,
    server_id: &str,
    change: &'static str,
    checkpoint_key: &[u8],
) -> Result<(), McpConnectionError> {
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(query_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(actor.clone()),
        event_type: AuditEventType::parse("configuration.changed")
            .ok_or_else(|| corrupt("audit_event"))?,
        target_kind: AuditLabel::new("mcp_server"),
        target_id: Some(AuditIdentifier::new(server_id).map_err(|_| corrupt("server_id"))?),
        payload: AuditPayload::from_facts([AuditFact::ConfigurationChange(AuditLabel::new(
            change,
        ))])
        .map_err(|_| corrupt("audit_payload"))?,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(query_unavailable)
}

fn validate_server_id(value: &str) -> Result<(), McpConnectionError> {
    if valid_server_id(value) {
        Ok(())
    } else {
        Err(McpConnectionError::InvalidInput { field: "server_id" })
    }
}

fn valid_pkce(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn attempt_is_expired(expires_at_unix_seconds: i64, now: OffsetDateTime) -> bool {
    now.unix_timestamp() >= expires_at_unix_seconds
}

async fn database_now(pool: &Pool) -> Result<OffsetDateTime, McpConnectionError> {
    pool.get()
        .await
        .map_err(unavailable)?
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(query_unavailable)?
        .try_get(0)
        .map_err(|_| corrupt("clock"))
}

fn map_oauth_vendor(error: McpOAuthError) -> McpConnectionError {
    match error {
        McpOAuthError::Unavailable
        | McpOAuthError::AuthRequired
        | McpOAuthError::InsufficientScope
        | McpOAuthError::InvalidMetadata
        | McpOAuthError::InvalidTokenResponse => McpConnectionError::VendorFailure,
        McpOAuthError::InvalidClient => corrupt("oauth_client"),
    }
}

fn map_drive_oauth_vendor(error: GoogleDriveOAuthError) -> McpConnectionError {
    match error {
        GoogleDriveOAuthError::Unavailable
        | GoogleDriveOAuthError::AuthRequired
        | GoogleDriveOAuthError::InvalidResponse => McpConnectionError::VendorFailure,
        GoogleDriveOAuthError::InvalidClient => corrupt("oauth_client"),
    }
}

fn map_catalog_failure(error: McpCatalogError) -> McpConnectionError {
    match error {
        McpCatalogError::NotVisible => McpConnectionError::NotVisible,
        McpCatalogError::Unavailable => McpConnectionError::Unavailable,
        McpCatalogError::Corrupt { field } => McpConnectionError::Corrupt { field },
    }
}

fn mutation_receipt(
    server_id: &str,
    refresh: &McpCatalogRefresh,
) -> Result<McpServerMutation, McpConnectionError> {
    Ok(McpServerMutation {
        server_id: server_id.to_owned(),
        catalog_generation: refresh.generation.get(),
        tool_count: u32::try_from(refresh.tools.len()).map_err(|_| corrupt("tool_count"))?,
        suspended_grants: u32::try_from(refresh.suspended_grants)
            .map_err(|_| corrupt("suspended_grants"))?,
    })
}

fn unavailable(error: crate::db::pool::PoolError) -> McpConnectionError {
    tracing::error!(error = %error, "MCP connections 获取 PostgreSQL 连接失败");
    McpConnectionError::Unavailable
}

fn query_unavailable(error: impl core::fmt::Display) -> McpConnectionError {
    tracing::error!(error = %error, "MCP connections PostgreSQL 操作失败");
    McpConnectionError::Unavailable
}

const fn corrupt(field: &'static str) -> McpConnectionError {
    McpConnectionError::Corrupt { field }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

async fn supervise_revocations(
    connections: Arc<PostgresMcpConnections>,
    mut stop: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(REVOCATION_RETRY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                match connections.reconcile_pending_revocations().await {
                    Ok(sweep) if sweep.attempted > 0 => tracing::info!(
                        attempted = sweep.attempted,
                        revoked = sweep.revoked,
                        pending = sweep.pending,
                        operator_required = sweep.operator_required,
                        "MCP vendor revocation reconciliation sweep 完成"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(code = %error,
                        "MCP vendor revocation reconciliation sweep 失败"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_uri_is_exact_configured_path_and_never_comes_from_a_host_header() {
        assert_eq!(
            callback_uri("https://api.example.test///", SchemePolicy::HttpsOnly).unwrap(),
            "https://api.example.test/api/plugins/oauth/callback"
        );
        assert!(callback_uri("http://api.example.test", SchemePolicy::HttpsOnly).is_err());
        assert_eq!(
            callback_uri("http://127.0.0.1:43123", SchemePolicy::HttpOrHttps).unwrap(),
            "http://127.0.0.1:43123/api/plugins/oauth/callback"
        );
        assert!(
            callback_uri("http://public.example", SchemePolicy::HttpOrHttps).is_err(),
            "HTTP exception is loopback-only"
        );
    }

    #[test]
    fn app_redirect_origin_rejects_query_fragment_and_userinfo() {
        assert_eq!(
            validate_app_origin("https://app.example.test/").unwrap(),
            "https://app.example.test/"
        );
        for invalid in [
            "https://user@app.example.test",
            "https://app.example.test?returnTo=https://evil.test",
            "https://app.example.test/#fragment",
        ] {
            assert!(validate_app_origin(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn oauth_attempt_expiry_is_inclusive_at_the_database_clock_boundary() {
        let before = OffsetDateTime::from_unix_timestamp(99).unwrap();
        let exact = OffsetDateTime::from_unix_timestamp(100).unwrap();
        assert!(!attempt_is_expired(100, before));
        assert!(attempt_is_expired(100, exact));
    }

    #[test]
    fn custom_server_registration_canonicalizes_exact_cidrs_and_rejects_ambiguous_urls() {
        let prepared = prepare_custom_server(&McpCustomServerRegistration {
            id: "internal-search".to_owned(),
            title: "Internal search".to_owned(),
            url: "https://search.internal.example/mcp".to_owned(),
            credential_id: None,
            egress_allow_cidrs: vec![
                "10.40.0.0/16".to_owned(),
                "10.40.0.0/16".to_owned(),
                "fd00:40::/48".to_owned(),
            ],
        })
        .unwrap();
        assert_eq!(
            prepared.egress_allow_cidrs.unwrap(),
            ["10.40.0.0/16", "fd00:40::/48"]
        );
        for url in [
            "http://search.example/mcp",
            "https://user@search.example/mcp",
            "https://search.example/mcp?target=internal",
            "https://search.example/mcp#fragment",
        ] {
            assert!(
                prepare_custom_server(&McpCustomServerRegistration {
                    id: "internal-search".to_owned(),
                    title: "Internal search".to_owned(),
                    url: url.to_owned(),
                    credential_id: None,
                    egress_allow_cidrs: Vec::new(),
                })
                .is_err(),
                "{url}"
            );
        }
        assert!(
            prepare_custom_server(&McpCustomServerRegistration {
                id: "internal-search".to_owned(),
                title: "Internal search".to_owned(),
                url: "https://search.example/mcp".to_owned(),
                credential_id: None,
                egress_allow_cidrs: vec!["10.40.1.1/16".to_owned()],
            })
            .is_err(),
            "host bits must not be silently canonicalized"
        );
    }
}
