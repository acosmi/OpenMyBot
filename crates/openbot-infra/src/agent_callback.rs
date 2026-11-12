//! PostgreSQL per-Agent callback-token administration.

use std::str::FromStr as _;
use std::sync::Arc;

use async_trait::async_trait;
use openbot_application::{
    AgentCallbackTokenAdministration, AgentCallbackTokenError, RemoteCallbackAuthError,
    RemoteCallbackAuthenticator, RemoteCallbackAuthorization,
};
use openbot_contracts::agent::{CallbackTokenIssued, CallbackTokenRevoked};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{BotId, DeploymentId, TenantId, ThreadId};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::identity::roles::resolve_effective_role;
use openbot_domain::remote_callback::{
    CALLBACK_TOKEN_BYTES, RemoteRunAssertionSigner, RemoteToolSet, callback_token_from_entropy,
    callback_token_hash, same_callback_token_hash,
};
use openbot_domain::vault::SecretBytes;

use crate::mcp_catalog::{McpCatalogError, PostgresMcpCatalog};
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::repo::people_admin::lock_people;

/// Production token store. Hash update and lifecycle audit share one transaction.
#[derive(Clone)]
pub struct PostgresAgentCallbackTokens {
    pool: crate::db::pool::DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    checkpoint_key: Arc<SecretBytes>,
}

impl PostgresAgentCallbackTokens {
    /// Construct for one authoritative deployment/tenant.
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
        checkpoint_key: Vec<u8>,
    ) -> Result<Self, AgentCallbackTokenError> {
        if checkpoint_key.is_empty() {
            return Err(AgentCallbackTokenError::Corrupt {
                field: "audit_checkpoint_key",
            });
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            checkpoint_key: Arc::new(SecretBytes::new(checkpoint_key)),
        })
    }

    async fn authorize<'a>(
        &self,
        transaction: &tokio_postgres::Transaction<'a>,
        auth: &AuthContext,
        agent: &BotId,
    ) -> Result<(), AgentCallbackTokenError> {
        if auth.deployment() != &self.deployment || auth.tenant() != &self.tenant {
            return Err(AgentCallbackTokenError::NotVisible);
        }
        // Serialize with role/access/generation mutations, then recheck inside this transaction.
        lock_people(transaction)
            .await
            .map_err(|error| unavailable("callback token people lock", error))?;
        let actor = transaction
            .query_opt(
                "SELECT coalesce(u.auth_generation,0) AS auth_generation, \
                        EXISTS(SELECT 1 FROM public.revoked_access ra \
                               WHERE ra.email=lower(u.email)) AS revoked, \
                        ARRAY(SELECT DISTINCT ur.role::text FROM public.user_roles ur \
                               WHERE ur.user_id=u.id ORDER BY ur.role::text) AS roles \
                   FROM public.users u WHERE u.id=$1 FOR UPDATE OF u",
                &[&auth.actor().as_str()],
            )
            .await
            .map_err(|error| unavailable("callback token actor query", error))?
            .ok_or(AgentCallbackTokenError::NotVisible)?;
        let generation: i64 =
            actor
                .try_get("auth_generation")
                .map_err(|_| AgentCallbackTokenError::Corrupt {
                    field: "auth_generation",
                })?;
        let generation =
            u64::try_from(generation).map_err(|_| AgentCallbackTokenError::Corrupt {
                field: "auth_generation",
            })?;
        let revoked: bool = actor
            .try_get("revoked")
            .map_err(|_| AgentCallbackTokenError::Corrupt { field: "revoked" })?;
        let raw_roles: Vec<String> = actor
            .try_get("roles")
            .map_err(|_| AgentCallbackTokenError::Corrupt { field: "roles" })?;
        let roles = raw_roles
            .iter()
            .map(|value| Role::from_str(value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AgentCallbackTokenError::Corrupt { field: "roles" })?;
        let role =
            resolve_effective_role(roles).map_err(|_| AgentCallbackTokenError::NotVisible)?;
        if revoked || generation != auth.auth_generation().get() {
            return Err(AgentCallbackTokenError::NotVisible);
        }

        let profile = transaction
            .query_opt(
                "SELECT a.type::text AS agent_type,p.owner_user_id,p.deleted_at, \
                        (a.package_id IS NULL OR dp.tenant_id=$2) AS tenant_visible \
                   FROM public.agents a \
                   JOIN public.agent_profiles p ON p.agent_id=a.id \
                   LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id \
                  WHERE a.id=$1 FOR UPDATE OF a,p",
                &[&agent.as_str(), &self.tenant.as_str()],
            )
            .await
            .map_err(|error| unavailable("callback token profile query", error))?
            .ok_or(AgentCallbackTokenError::NotVisible)?;
        let agent_type: String =
            profile
                .try_get("agent_type")
                .map_err(|_| AgentCallbackTokenError::Corrupt {
                    field: "agent_type",
                })?;
        let owner: Option<String> =
            profile
                .try_get("owner_user_id")
                .map_err(|_| AgentCallbackTokenError::Corrupt {
                    field: "owner_user_id",
                })?;
        let deleted: Option<time::OffsetDateTime> =
            profile
                .try_get("deleted_at")
                .map_err(|_| AgentCallbackTokenError::Corrupt {
                    field: "deleted_at",
                })?;
        let tenant_visible: bool =
            profile
                .try_get("tenant_visible")
                .map_err(|_| AgentCallbackTokenError::Corrupt {
                    field: "tenant_visible",
                })?;
        let manageable = role == Role::Admin || owner.as_deref() == Some(auth.actor().as_str());
        if agent_type != "remote_ag_ui" || deleted.is_some() || !tenant_visible || !manageable {
            return Err(AgentCallbackTokenError::NotVisible);
        }
        Ok(())
    }

    async fn append_audit(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
        auth: &AuthContext,
        agent: &BotId,
        event_type: &'static str,
    ) -> Result<(), AgentCallbackTokenError> {
        let (id, created_at) = next_event_coordinates(transaction)
            .await
            .map_err(|error| unavailable("callback token audit coordinates", error))?;
        let event = AuditEvent {
            id,
            actor: Some(auth.actor().clone()),
            event_type: AuditEventType::parse(event_type).ok_or(
                AgentCallbackTokenError::Corrupt {
                    field: "audit_event_type",
                },
            )?,
            target_kind: AuditLabel::new("bot"),
            target_id: Some(
                AuditIdentifier::new(agent.as_str())
                    .map_err(|_| AgentCallbackTokenError::Corrupt { field: "agent_id" })?,
            ),
            payload: AuditPayload::empty(),
            created_at,
        };
        append_event_in_transaction(transaction, &event, self.checkpoint_key.expose())
            .await
            .map(|_| ())
            .map_err(|error| unavailable("callback token audit append", error))
    }
}

impl core::fmt::Debug for PostgresAgentCallbackTokens {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresAgentCallbackTokens")
            .field("deployment", &self.deployment)
            .field("tenant", &self.tenant)
            .field("checkpoint_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AgentCallbackTokenAdministration for PostgresAgentCallbackTokens {
    async fn issue(
        &self,
        auth: &AuthContext,
        agent: &BotId,
    ) -> Result<CallbackTokenIssued, AgentCallbackTokenError> {
        // No step here has its own bound, so the 5 s precedent.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let binding = auth
            .request_binding()
            .ok_or(AgentCallbackTokenError::Unavailable)?;
        let admission = binding
            .borrow_recovery_admission_before(auth, deadline)
            .await
            .map_err(|_| AgentCallbackTokenError::Unavailable)?;
        let mut client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "callback token 获取连接失败");
            AgentCallbackTokenError::Unavailable
        })?;
        let transaction = client.transaction().await.map_err(|error| {
            tracing::error!(error = %error, "callback token 开始事务失败");
            AgentCallbackTokenError::Unavailable
        })?;
        self.authorize(&transaction, auth, agent).await?;
        let mut entropy = [0_u8; CALLBACK_TOKEN_BYTES];
        getrandom::fill(&mut entropy).map_err(|error| {
            tracing::error!(error = %error, "callback token OS CSPRNG 失败");
            AgentCallbackTokenError::Unavailable
        })?;
        let token = callback_token_from_entropy(entropy);
        let hash = callback_token_hash(&token)
            .map_err(|_| AgentCallbackTokenError::Corrupt { field: "token" })?
            .to_hex();
        transaction
            .execute(
                "UPDATE public.agent_profiles \
                    SET callback_token_hash=$2,callback_token_issued_at=clock_timestamp(), \
                        updated_at=clock_timestamp() WHERE agent_id=$1",
                &[&agent.as_str(), &hash],
            )
            .await
            .map_err(|error| unavailable("callback token hash update", error))?;
        self.append_audit(&transaction, auth, agent, "bot.callback_token_issued")
            .await?;
        admission
            .verify_current_before(binding, auth, deadline)
            .map_err(|_| AgentCallbackTokenError::Unavailable)?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "callback token issue commit 结果未知");
            AgentCallbackTokenError::CommitUnknown
        })?;
        CallbackTokenIssued::new(token).map_err(|_| AgentCallbackTokenError::Corrupt {
            field: "token_response",
        })
    }

    async fn revoke(
        &self,
        auth: &AuthContext,
        agent: &BotId,
    ) -> Result<CallbackTokenRevoked, AgentCallbackTokenError> {
        let mut client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "callback token revoke 获取连接失败");
            AgentCallbackTokenError::Unavailable
        })?;
        let transaction = client.transaction().await.map_err(|error| {
            tracing::error!(error = %error, "callback token revoke 开始事务失败");
            AgentCallbackTokenError::Unavailable
        })?;
        self.authorize(&transaction, auth, agent).await?;
        transaction
            .execute(
                "UPDATE public.agent_profiles \
                    SET callback_token_hash=NULL,callback_token_issued_at=NULL, \
                        updated_at=clock_timestamp() WHERE agent_id=$1",
                &[&agent.as_str()],
            )
            .await
            .map_err(|error| unavailable("callback token revoke update", error))?;
        self.append_audit(&transaction, auth, agent, "bot.callback_token_revoked")
            .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "callback token revoke commit 结果未知");
            AgentCallbackTokenError::CommitUnknown
        })?;
        Ok(CallbackTokenRevoked)
    }
}

fn unavailable(operation: &'static str, error: impl core::fmt::Display) -> AgentCallbackTokenError {
    tracing::error!(operation, error = %error, "callback token PostgreSQL 操作失败");
    AgentCallbackTokenError::Unavailable
}

/// Production token + assertion + active-run verifier. The current production tool set is empty
/// until RMCP/Drive executors land, so valid callers reach an honest 404 rather than a fake tool.
pub struct PostgresRemoteCallbackAuthenticator {
    pool: crate::db::pool::DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    single_user: bool,
    signer: Arc<RemoteRunAssertionSigner>,
    checkpoint_key: Arc<SecretBytes>,
    mcp_catalog: Option<Arc<PostgresMcpCatalog>>,
    delegation: Option<Arc<openbot_application::DelegationRuntime>>,
    run_runtime: Option<Arc<crate::run_runtime::PostgresRunRuntime>>,
    recovery_gate: crate::recovery_control::RecoveryReadGate,
}

impl PostgresRemoteCallbackAuthenticator {
    /// Construct with the same run signer and audit checkpoint key used by production assembly.
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
        single_user: bool,
        signer: Arc<RemoteRunAssertionSigner>,
        checkpoint_key: Vec<u8>,
        recovery_gate: crate::recovery_control::RecoveryReadGate,
    ) -> Result<Self, RemoteCallbackAuthError> {
        if checkpoint_key.is_empty() {
            return Err(RemoteCallbackAuthError::Corrupt {
                field: "audit_checkpoint_key",
            });
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            single_user,
            signer,
            checkpoint_key: Arc::new(SecretBytes::new(checkpoint_key)),
            mcp_catalog: None,
            delegation: None,
            run_runtime: None,
            recovery_gate,
        })
    }

    /// Attach the same authoritative catalog used to construct remote RunAgentInput.
    #[must_use]
    pub fn with_mcp_catalog(mut self, catalog: Arc<PostgresMcpCatalog>) -> Self {
        self.mcp_catalog = Some(catalog);
        self
    }

    pub(crate) fn with_delegation_runtime(
        mut self,
        delegation: Option<Arc<openbot_application::DelegationRuntime>>,
        runtime: Arc<crate::run_runtime::PostgresRunRuntime>,
    ) -> Self {
        self.delegation = delegation;
        self.run_runtime = Some(runtime);
        self
    }

    async fn refuse(
        &self,
        transaction: deadpool_postgres::Transaction<'_>,
        code: &'static str,
        error: RemoteCallbackAuthError,
    ) -> Result<RemoteCallbackAuthorization, RemoteCallbackAuthError> {
        let (id, created_at) = next_event_coordinates(&transaction)
            .await
            .map_err(|source| callback_unavailable("callback refusal coordinates", source))?;
        let event = AuditEvent {
            id,
            // No actor/Bot: the credential pair failed to establish those facts.
            actor: None,
            event_type: AuditEventType::parse("mcp.callback_refused").ok_or(
                RemoteCallbackAuthError::Corrupt {
                    field: "audit_event_type",
                },
            )?,
            target_kind: AuditLabel::new("mcp_tool"),
            target_id: None,
            payload: AuditPayload::from_facts([AuditFact::ErrorCode(AuditLabel::new(code))])
                .map_err(|_| RemoteCallbackAuthError::Corrupt {
                    field: "audit_payload",
                })?,
            created_at,
        };
        append_event_in_transaction(&transaction, &event, self.checkpoint_key.expose())
            .await
            .map_err(|source| callback_unavailable("callback refusal audit", source))?;
        transaction.commit().await.map_err(|source| {
            tracing::error!(error = %source, "callback refusal audit commit 结果未知");
            RemoteCallbackAuthError::Unavailable
        })?;
        Err(error)
    }
}

impl core::fmt::Debug for PostgresRemoteCallbackAuthenticator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresRemoteCallbackAuthenticator")
            .field("deployment", &self.deployment)
            .field("tenant", &self.tenant)
            .field("single_user", &self.single_user)
            .field("signer", &"[redacted]")
            .field("checkpoint_key", &"[redacted]")
            .field("mcp_catalog", &self.mcp_catalog.is_some())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RemoteCallbackAuthenticator for PostgresRemoteCallbackAuthenticator {
    async fn authorize(
        &self,
        presented_token: &str,
        run: &serde_json::Value,
        requested_tool: &str,
    ) -> Result<RemoteCallbackAuthorization, RemoteCallbackAuthError> {
        // No step here has its own bound, so the 5 s precedent. The worker
        // admission is held through the refusal audit or the returned grant.
        let admitted_until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let admission = self
            .recovery_gate
            .borrow_worker_before(admitted_until)
            .await
            .map_err(|_| RemoteCallbackAuthError::Unavailable)?;
        let mut client = self.pool.get().await.map_err(|source| {
            tracing::error!(error = %source, "remote callback 获取连接失败");
            RemoteCallbackAuthError::Unavailable
        })?;
        let transaction = client.transaction().await.map_err(|source| {
            tracing::error!(error = %source, "remote callback 开始事务失败");
            RemoteCallbackAuthError::Unavailable
        })?;
        let now_millis: i64 = transaction
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .map_err(|source| callback_unavailable("callback database clock", source))?
            .try_get(0)
            .map_err(|_| RemoteCallbackAuthError::Corrupt {
                field: "database_clock",
            })?;
        let Some(run) = run.as_str() else {
            return self
                .refuse(
                    transaction,
                    "callback_credential_invalid",
                    RemoteCallbackAuthError::Unauthenticated,
                )
                .await;
        };
        let assertion = match self.signer.verify(run, now_millis) {
            Ok(assertion)
                if assertion.scope().deployment == self.deployment
                    && assertion.scope().tenant == self.tenant =>
            {
                assertion
            }
            Ok(_) | Err(_) => {
                return self
                    .refuse(
                        transaction,
                        "callback_credential_invalid",
                        RemoteCallbackAuthError::Unauthenticated,
                    )
                    .await;
            }
        };
        let presented_hash = match callback_token_hash(presented_token) {
            Ok(hash) => hash,
            Err(_) => {
                return self
                    .refuse(
                        transaction,
                        "callback_credential_invalid",
                        RemoteCallbackAuthError::Unauthenticated,
                    )
                    .await;
            }
        };
        let rows = transaction
            .query(
                "SELECT p.agent_id,p.callback_token_hash \
                   FROM public.agent_profiles p \
                   JOIN public.agents a ON a.id=p.agent_id \
                   LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id \
                  WHERE p.callback_token_hash=$1 AND p.deleted_at IS NULL \
                    AND a.type='remote_ag_ui' \
                    AND (a.package_id IS NULL OR dp.tenant_id=$2) LIMIT 2",
                &[&presented_hash.to_hex(), &self.tenant.as_str()],
            )
            .await
            .map_err(|source| callback_unavailable("callback token lookup", source))?;
        let Some(row) = rows.first().filter(|_| rows.len() == 1) else {
            return self
                .refuse(
                    transaction,
                    "callback_credential_invalid",
                    RemoteCallbackAuthError::Unauthenticated,
                )
                .await;
        };
        let token_owner: String =
            row.try_get("agent_id")
                .map_err(|_| RemoteCallbackAuthError::Corrupt {
                    field: "token_owner",
                })?;
        let stored_hash: String =
            row.try_get("callback_token_hash")
                .map_err(|_| RemoteCallbackAuthError::Corrupt {
                    field: "callback_token_hash",
                })?;
        let stored_hash = openbot_domain::audit::hash::Sha256Digest::parse_hex(&stored_hash)
            .map_err(|_| RemoteCallbackAuthError::Corrupt {
                field: "callback_token_hash",
            })?;
        if !same_callback_token_hash(&stored_hash, &presented_hash) {
            return self
                .refuse(
                    transaction,
                    "callback_credential_invalid",
                    RemoteCallbackAuthError::Unauthenticated,
                )
                .await;
        }
        if token_owner != assertion.scope().bot.as_str() {
            return self
                .refuse(
                    transaction,
                    "callback_token_bot_mismatch",
                    RemoteCallbackAuthError::BotMismatch,
                )
                .await;
        }

        let scope = transaction
            .query_opt(
                "SELECT r.thread_id,r.fencing_token,r.next_event_seq,(m.content ? 'delegation' OR m.content ? 'delegationSnapshot') AS delegation_present,m.content->'delegationSnapshot' AS delegation_snapshot,coalesce(u.auth_generation,0) AS auth_generation, \
                        EXISTS(SELECT 1 FROM public.revoked_access ra \
                               WHERE ra.email=lower(u.email)) AS revoked, \
                        ARRAY(SELECT DISTINCT ur.role::text FROM public.user_roles ur \
                               WHERE ur.user_id=u.id ORDER BY ur.role::text) AS roles \
                   FROM public.runs r \
                   JOIN public.threads t ON t.thread_id=r.thread_id \
                   JOIN public.thread_memberships tm ON tm.thread_id=t.thread_id \
                   JOIN public.thread_leases l ON l.thread_id=t.thread_id \
                   JOIN public.users u ON u.id=r.actor_id \
                   LEFT JOIN public.messages m ON m.message_id=r.run_id||':input' AND m.run_id=r.run_id \
                  WHERE r.run_id=$1 AND r.bot_id=$2 AND r.actor_id=$3 \
                    AND r.status='running' AND t.status='active' \
                    AND t.deployment_id=$4 AND t.tenant_id=$5 AND tm.user_id=$3 \
                    AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp()",
                &[
                    &assertion.scope().run.as_str(),
                    &assertion.scope().bot.as_str(),
                    &assertion.scope().actor.as_str(),
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                ],
            )
            .await
            .map_err(|source| callback_unavailable("callback active run scope", source))?;
        let Some(scope) = scope else {
            return self
                .refuse(
                    transaction,
                    "callback_run_not_active",
                    RemoteCallbackAuthError::Unauthenticated,
                )
                .await;
        };
        let snapshot: Option<serde_json::Value> =
            scope
                .try_get("delegation_snapshot")
                .map_err(|_| RemoteCallbackAuthError::Corrupt {
                    field: "delegation_input",
                })?;
        let delegated: bool = scope
            .try_get::<_, Option<bool>>("delegation_present")
            .map_err(|_| RemoteCallbackAuthError::Corrupt {
                field: "delegation_input",
            })?
            .unwrap_or(false);
        let revoked: bool = scope
            .try_get("revoked")
            .map_err(|_| RemoteCallbackAuthError::Corrupt { field: "revoked" })?;
        let generation: i64 =
            scope
                .try_get("auth_generation")
                .map_err(|_| RemoteCallbackAuthError::Corrupt {
                    field: "auth_generation",
                })?;
        let generation =
            u64::try_from(generation).map_err(|_| RemoteCallbackAuthError::Corrupt {
                field: "auth_generation",
            })?;
        let raw_roles: Vec<String> = scope
            .try_get("roles")
            .map_err(|_| RemoteCallbackAuthError::Corrupt { field: "roles" })?;
        let roles = raw_roles
            .iter()
            .map(|value| Role::from_str(value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RemoteCallbackAuthError::Corrupt { field: "roles" })?;
        let role = resolve_effective_role(roles);
        if role.is_err() && !delegated {
            return Err(RemoteCallbackAuthError::Unauthenticated);
        }
        if revoked && !delegated {
            return self
                .refuse(
                    transaction,
                    "callback_actor_revoked",
                    RemoteCallbackAuthError::Unauthenticated,
                )
                .await;
        }
        let thread_id: String = scope
            .try_get("thread_id")
            .map_err(|_| RemoteCallbackAuthError::Corrupt { field: "thread_id" })?;
        if requested_tool.is_empty()
            || requested_tool.len() > openbot_domain::remote_callback::MAX_REMOTE_TOOL_NAME_BYTES
            || requested_tool.as_bytes().contains(&0)
        {
            return Err(RemoteCallbackAuthError::InvalidInput { field: "name" });
        }
        let current_tools = match &self.mcp_catalog {
            Some(catalog) => RemoteToolSet::new(
                catalog
                    .granted_tools_in_transaction(
                        &transaction,
                        &assertion.scope().bot,
                        &assertion.scope().actor,
                    )
                    .await
                    .map_err(map_callback_catalog_error)?
                    .into_iter()
                    .map(|tool| tool.model_name),
            )
            .map_err(|_| RemoteCallbackAuthError::Corrupt {
                field: "remote_tool_set",
            })?,
            None => RemoteToolSet::empty(),
        };
        if assertion.tool_set_digest() != current_tools.digest()
            || !current_tools.contains(requested_tool)
        {
            return self
                .refuse(
                    transaction,
                    "callback_tool_not_granted",
                    RemoteCallbackAuthError::ToolNotVisible,
                )
                .await;
        }
        let auth = AuthContextBuilder::from_verified_session(
            self.deployment.clone(),
            self.tenant.clone(),
            assertion.scope().actor.clone(),
            AuthGeneration::new(generation),
            self.single_user,
        )
        .with_roles(role.ok())
        .build();
        let original = RemoteCallbackAuthorization::new(
            auth,
            assertion.scope().run.clone(),
            ThreadId::new(thread_id.clone()),
            assertion.scope().bot.clone(),
        );
        if delegated {
            let fencing: i64 =
                scope
                    .try_get("fencing_token")
                    .map_err(|_| RemoteCallbackAuthError::Corrupt {
                        field: "fencing_token",
                    })?;
            let sequence: i64 =
                scope
                    .try_get("next_event_seq")
                    .map_err(|_| RemoteCallbackAuthError::Corrupt {
                        field: "next_event_seq",
                    })?;
            let deadline = snapshot
                .as_ref()
                .and_then(|v| v.get("absoluteDeadline"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| {
                    std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_millis(v))
                })
                .unwrap_or(std::time::UNIX_EPOCH);
            let lease = openbot_application::RunExecutionLease::new(
                assertion.scope().run.clone(),
                ThreadId::new(thread_id),
                assertion.scope().bot.clone(),
                assertion.scope().actor.clone(),
                openbot_domain::thread::FencingToken::new(fencing)
                    .map_err(|_| RemoteCallbackAuthError::Unauthenticated)?,
                u64::try_from(sequence).map_err(|_| RemoteCallbackAuthError::Unauthenticated)?,
            )
            .map_err(|_| RemoteCallbackAuthError::Unauthenticated)?
            .with_delegated_run_binding(self.delegation.clone(), deadline);
            transaction
                .rollback()
                .await
                .map_err(|_| RemoteCallbackAuthError::Unavailable)?;
            admission
                .verify_current_before(admitted_until)
                .map_err(|_| RemoteCallbackAuthError::Unavailable)?;
            let result = match &self.delegation {
                Some(runtime) => runtime.remint_callback(&original, &lease).await,
                None => Err(openbot_contracts::error::AppError::PolicyRefused {
                    rule: "delegation_not_current".into(),
                    decision: None,
                }),
            };
            match result {
                Ok(auth) => Ok(RemoteCallbackAuthorization::new(
                    auth,
                    original.run().clone(),
                    original.thread().clone(),
                    original.bot().clone(),
                )),
                Err(_) => match &self.run_runtime {
                    Some(runtime) => match runtime
                        .fail_confirmed_delegated_callback(&lease, None)
                        .await
                    {
                        Ok(_) => Err(RemoteCallbackAuthError::Unauthenticated),
                        Err(
                            openbot_application::RunRuntimeError::StaleLease
                            | openbot_application::RunRuntimeError::Conflict,
                        ) => Err(RemoteCallbackAuthError::Unauthenticated),
                        Err(_) => Err(RemoteCallbackAuthError::Unavailable),
                    },
                    None => Err(RemoteCallbackAuthError::Unavailable),
                },
            }
        } else {
            admission
                .verify_current_before(admitted_until)
                .map_err(|_| RemoteCallbackAuthError::Unavailable)?;
            Ok(original)
        }
    }
}

fn callback_unavailable(
    operation: &'static str,
    error: impl core::fmt::Display,
) -> RemoteCallbackAuthError {
    tracing::error!(operation, error = %error, "remote callback PostgreSQL 操作失败");
    RemoteCallbackAuthError::Unavailable
}

fn map_callback_catalog_error(error: McpCatalogError) -> RemoteCallbackAuthError {
    match error {
        McpCatalogError::Unavailable => RemoteCallbackAuthError::Unavailable,
        McpCatalogError::NotVisible => RemoteCallbackAuthError::ToolNotVisible,
        McpCatalogError::Corrupt { field } => RemoteCallbackAuthError::Corrupt { field },
    }
}
