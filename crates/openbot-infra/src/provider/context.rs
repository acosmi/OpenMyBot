//! PostgreSQL run/thread history → provider-neutral bounded context。

use std::collections::BTreeMap;

use async_trait::async_trait;
use openbot_application::{
    AgentContextError, AgentContextSource, ComponentAdministration, ComponentRuntimeScope,
    ProviderMessage, ProviderMessageRole, ProviderRateCard, ProviderRequest, ProviderRoute,
    ProviderToolCall, ProviderToolDefinition, RemoteAguiAuthorization, RemoteAguiRoute, RunCostCap,
    RunExecutionLease, SandboxedComponentAdministration,
};
use openbot_contracts::components::{
    compiled_component_manifest, compiled_component_parameter_schema,
};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_domain::remote_callback::{RemoteRunAssertionSigner, RemoteRunScope, RemoteToolSet};
use openbot_domain::vault::{SecretKind, SecretPrincipal, ServiceId};
use serde_json::Value;

use crate::component_catalogue::PostgresComponentAdministration;
use crate::mcp_catalog::{GrantedMcpTool, McpCatalogError, PostgresMcpCatalog};
use crate::sandboxed_components::PostgresSandboxedComponentAdministration;
use crate::vault::CredentialRecordVault;

// SPDX-License-Identifier: MIT
// Source: CopilotKit/openbot@891df72f1827454d8b353d108fe5dd2313b7e30d
// File: shared/bot-prompt.ts::PROVENANCE_GUIDANCE; modified into a Rust static string.
const PROVENANCE_GUIDANCE: &str = concat!(
    "Say where an answer came from. When you read it with one of your tools, cite what you read. ",
    "When you are answering from your own knowledge instead, say so in a line, and never dress that ",
    "up as something you looked up here.",
    "\n\n",
    "This matters most for the answers people act on: a threshold, a deadline, a filing obligation, a ",
    "figure, a rule you are presenting as this organisation's. Never state one of those as established ",
    "here without having read it somewhere you can name. Saying 'I have not checked this against your ",
    "own policy or the current regulation' costs you a sentence. Being confidently wrong about a ",
    "number somebody acts on costs them a great deal more.",
    "\n\n",
    "This is not an instruction to go looking. If nothing you can reach covers the question, answer as ",
    "well as you can and mark it plainly as unverified. Do not go hunting the open web for something ",
    "to cite, and do not keep retrying a page that is not giving you one: an unsourced answer that ",
    "says it is unsourced is honest, and a search that never ends is a Bot that never answers."
);

/// First provider slice refuses oversized history until provenance-aware compression lands。
pub const MAX_AGENT_CONTEXT_MESSAGES: i64 = 4096;
/// Bounded plaintext context bytes；JSON framing/tool schema still faces safe HTTP 8MiB cap。
pub const MAX_AGENT_CONTEXT_BYTES: usize = 6 * 1024 * 1024;
const CUSTOM_MODEL_V2_CONTEXT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Production PostgreSQL context source。
#[derive(Clone, Debug)]
pub struct PostgresAgentContextSource {
    pool: crate::db::pool::DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    extensions: openbot_application::ProviderExtensions,
    max_output_tokens: Option<u32>,
    package_rate_card: Option<ProviderRateCard>,
    managed_rate_card: Option<ProviderRateCard>,
    tools: Vec<ProviderToolDefinition>,
    remote_assertions: Option<std::sync::Arc<RemoteRunAssertionSigner>>,
    mcp_catalog: Option<std::sync::Arc<PostgresMcpCatalog>>,
    components: Option<std::sync::Arc<PostgresComponentAdministration>>,
    sandboxed_components: Option<std::sync::Arc<PostgresSandboxedComponentAdministration>>,
    agent_credential_vault: Option<CredentialRecordVault>,
    model_dataset_binding:
        Option<std::sync::Arc<crate::model_dataset::PostgresModelDatasetBinding>>,
}

impl PostgresAgentContextSource {
    /// Construct a bounded context source; first-party tools may be attached with [`Self::with_tools`].
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
        max_output_tokens: Option<u32>,
    ) -> Result<Self, AgentContextError> {
        if max_output_tokens == Some(0) {
            return Err(AgentContextError::Corrupt {
                field: "max_output_tokens",
            });
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            extensions: Default::default(),
            max_output_tokens,
            package_rate_card: None,
            managed_rate_card: None,
            tools: Vec::new(),
            remote_assertions: None,
            mcp_catalog: None,
            components: None,
            sandboxed_components: None,
            agent_credential_vault: None,
            model_dataset_binding: None,
        })
    }

    /// Use the immutable registration shared with this assembly's provider router.
    #[must_use]
    pub fn with_extensions(mut self, extensions: openbot_application::ProviderExtensions) -> Self {
        self.extensions = extensions;
        self
    }

    /// Attach host-validated package and managed provider rate snapshots.
    #[must_use]
    pub fn with_rate_cards(
        mut self,
        package: Option<ProviderRateCard>,
        managed: Option<ProviderRateCard>,
    ) -> Self {
        self.package_rate_card = package;
        self.managed_rate_card = managed;
        self
    }

    /// Attach the first-party catalog projected to model-visible JSON Schema.
    #[must_use]
    pub fn with_tools(mut self, tools: Vec<ProviderToolDefinition>) -> Self {
        self.tools = tools;
        self
    }

    /// Attach the deployment run-assertion signer. A remote route without it fails closed.
    #[must_use]
    pub fn with_remote_assertions(
        mut self,
        signer: std::sync::Arc<RemoteRunAssertionSigner>,
    ) -> Self {
        self.remote_assertions = Some(signer);
        self
    }

    /// Attach the authoritative per-Bot MCP grant/catalog projection.
    #[must_use]
    pub fn with_mcp_catalog(mut self, catalog: std::sync::Arc<PostgresMcpCatalog>) -> Self {
        self.mcp_catalog = Some(catalog);
        self
    }

    /// Attach the same compiled-component authority used by HTTP/Tauri call-time checks.
    #[must_use]
    pub fn with_components(
        mut self,
        components: std::sync::Arc<PostgresComponentAdministration>,
    ) -> Self {
        self.components = Some(components);
        self
    }

    /// Attach published sandbox source/grants used for dynamic provider definitions.
    #[must_use]
    pub fn with_sandboxed_components(
        mut self,
        components: std::sync::Arc<PostgresSandboxedComponentAdministration>,
    ) -> Self {
        self.sandboxed_components = Some(components);
        self
    }

    /// Attach the same tenant Vault used by Agent lifecycle credential writes.
    #[must_use]
    pub fn with_agent_credential_vault(mut self, vault: CredentialRecordVault) -> Self {
        self.agent_credential_vault = Some(vault);
        self
    }

    /// Configure the same original-Pool dataset producer once; enrollment is a host step.
    pub fn with_model_dataset_binding(
        mut self,
        binding: std::sync::Arc<crate::model_dataset::PostgresModelDatasetBinding>,
    ) -> Result<Self, AgentContextError> {
        if self.model_dataset_binding.is_some()
            || !binding.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            return Err(AgentContextError::Corrupt {
                field: "model_dataset_binding",
            });
        }
        self.model_dataset_binding = Some(binding);
        Ok(self)
    }
}

impl PostgresAgentContextSource {
    // The unconfigured constructor retains its full legacy load and its old budget behavior.
    async fn load_configured(
        &self,
        lease: &RunExecutionLease,
    ) -> Result<ProviderRequest, AgentContextError> {
        let deadline = std::time::Instant::now() + CUSTOM_MODEL_V2_CONTEXT_TIMEOUT;
        let binding = self
            .model_dataset_binding
            .as_ref()
            .ok_or(AgentContextError::Unavailable)?;
        if !binding.matches_pool_scope(&self.pool, &self.deployment, &self.tenant) {
            return Err(AgentContextError::Corrupt {
                field: "model_dataset_binding",
            });
        }
        let kind = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.classify_on_original_read_only(lease, deadline),
        )
        .await
        .map_err(|_| AgentContextError::Unavailable)??;
        match kind {
            crate::model_runtime::StoredSelectionKind::None
            | crate::model_runtime::StoredSelectionKind::Legacy => {
                // This new preliminary stage affects configured hosts only. The complete
                // legacy load follows and is not truncated to the v2 five-second budget.
                self.load_legacy(lease).await
            }
            crate::model_runtime::StoredSelectionKind::V2 => tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.load_v2(lease, binding, deadline),
            )
            .await
            .map_err(|_| AgentContextError::Unavailable)?,
        }
    }

    async fn classify_on_original_read_only(
        &self,
        lease: &RunExecutionLease,
        deadline: std::time::Instant,
    ) -> Result<crate::model_runtime::StoredSelectionKind, AgentContextError> {
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| AgentContextError::Unavailable)?;
        let transaction = client
            .begin_read_committed_read_only()
            .await
            .map_err(map_context_transaction)?;
        let remaining = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .max(1)
            .to_string();
        let result=async {
            transaction.as_transaction().query_one(
                "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",&[&remaining])
                .await.map_err(|_|AgentContextError::Unavailable)?;
            crate::model_runtime::classify_selection_storage(transaction.as_transaction(),
                &self.deployment,&self.tenant,lease).await
        }.await;
        let ended = transaction.rollback().await;
        // The first checkout must be physically released before selecting a second one.
        drop(client);
        match result {
            Err(error) => {
                if let Err(end) = ended {
                    tracing::warn!(state=?end,"custom model classification rejected with unproved closure");
                }
                Err(error)
            }
            Ok(kind) => {
                ended.map_err(map_context_transaction)?;
                if std::time::Instant::now() >= deadline {
                    return Err(AgentContextError::Unavailable);
                }
                Ok(kind)
            }
        }
    }

    async fn load_v2(
        &self,
        lease: &RunExecutionLease,
        binding: &crate::model_dataset::PostgresModelDatasetBinding,
        deadline: std::time::Instant,
    ) -> Result<ProviderRequest, AgentContextError> {
        let selection = {
            let mut checkout = binding
                .checkout(deadline)
                .await
                .map_err(map_context_dataset)?;
            let transaction = checkout
                .begin_read_committed()
                .await
                .map_err(map_context_transaction)?;
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .max(1)
                .to_string();
            let result=async {
                // This authoritative projection performs no business writes. D03 retains
                // the original RW guard so dataset/canary SHARE locks remain legitimate.
                transaction.as_transaction().query_one(
                    "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",&[&remaining])
                    .await.map_err(|_|AgentContextError::Unavailable)?;
                crate::model_runtime::load_v2_for_context(&transaction,&self.deployment,&self.tenant,lease).await
            }.await;
            let ended = transaction.rollback().await;
            drop(checkout);
            match result {
                Err(error) => {
                    if let Err(end) = ended {
                        tracing::warn!(state=?end,"custom model projection rejected with unproved closure");
                    }
                    return Err(error);
                }
                Ok(value) => {
                    ended.map_err(map_context_transaction)?;
                    if std::time::Instant::now() >= deadline {
                        return Err(AgentContextError::Unavailable);
                    }
                    value
                }
            }
        };
        // Neither earlier checkout is retained. Common metadata/history is nonauthorizing
        // and has only the remainder of the same original deadline.
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| AgentContextError::Unavailable)?;
        let mut connection = V2ContextProjectionConnection {
            client: Some(client),
            clean: false,
            deadline,
        };
        let result = self
            .load_common(
                lease,
                connection
                    .client
                    .as_ref()
                    .expect("owned context projection"),
                Some(selection),
            )
            .await;
        connection.clean = true;
        if std::time::Instant::now() >= deadline {
            return Err(AgentContextError::Unavailable);
        }
        result
    }

    async fn load_legacy(
        &self,
        lease: &RunExecutionLease,
    ) -> Result<ProviderRequest, AgentContextError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| AgentContextError::Unavailable)?;
        // This check projects a binding only. It takes no authority row locks; the real
        // custom start rechecks in its own bounded, cancellation-safe transaction.
        let selection = crate::model_runtime::load_selection_for_context(
            &client,
            &self.deployment,
            &self.tenant,
            lease,
        )
        .await?;
        self.load_common(lease, &client, selection).await
    }

    async fn load_common(
        &self,
        lease: &RunExecutionLease,
        client: &tokio_postgres::Client,
        selection: Option<openbot_application::RunModelBinding>,
    ) -> Result<ProviderRequest, AgentContextError> {
        let has_custom_selection = selection.is_some();
        let visible = client
            .query_opt(
                "SELECT a.type::text AS agent_type,a.name,a.configuration,p.title,p.role_description, \
                        p.owner_user_id,r.budget_cost_currency,r.budget_max_cost_micro_units, \
                        EXISTS(SELECT 1 FROM public.user_roles ur \
                                WHERE ur.user_id=$4 AND ur.role='admin') AS actor_admin, \
                        floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
                          AS assertion_issued_at_millis \
                   FROM public.runs r \
                   JOIN public.threads t ON t.thread_id=r.thread_id \
                   JOIN public.agents a ON a.id=r.bot_id \
                   LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id \
                   JOIN public.agent_profiles p ON p.agent_id=a.id \
                   WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4 \
                     AND r.fencing_token=$5 AND r.status='running' \
                     AND t.deployment_id=$6 AND t.tenant_id=$7 \
                     AND NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads h \
                                     WHERE h.deployment_id=t.deployment_id \
                                       AND h.tenant_id=t.tenant_id \
                                       AND h.thread_id=t.thread_id AND h.phase='closed') \
                     AND (a.package_id IS NULL OR dp.tenant_id=$7) \
                     AND t.status='active' AND ($8::boolean OR EXISTS( \
                       SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$4)) \
                     AND (NOT $8::boolean OR a.type='built_in') \
                     AND a.type IN ('built_in','remote_ag_ui') \
                     AND p.deleted_at IS NULL \
                     AND (p.visibility='public' OR p.owner_user_id=$4 OR EXISTS( \
                           SELECT 1 FROM public.user_roles access_role \
                            WHERE access_role.user_id=$4 AND access_role.role='admin'))",
                &[
                    &lease.run_id().as_str(),
                    &lease.thread_id().as_str(),
                    &lease.bot_id().as_str(),
                    &lease.actor_id().as_str(),
                    &lease.fencing().get(),
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                    &has_custom_selection,
                ],
            )
            .await
            .map_err(|_| AgentContextError::Unavailable)?
            .ok_or(AgentContextError::Stale)?;
        let configuration: Value =
            visible
                .try_get("configuration")
                .map_err(|_| AgentContextError::Corrupt {
                    field: "agent_configuration",
                })?;
        let agent_type: String =
            visible
                .try_get("agent_type")
                .map_err(|_| AgentContextError::Corrupt {
                    field: "agent_type",
                })?;
        let granted_mcp = match &self.mcp_catalog {
            Some(catalog) => catalog
                .granted_tools_on_client(client, lease.bot_id(), lease.actor_id())
                .await
                .map_err(map_mcp_catalog_error)?,
            None => Vec::new(),
        };
        let actor_admin: bool =
            visible
                .try_get("actor_admin")
                .map_err(|_| AgentContextError::Corrupt {
                    field: "actor_admin",
                })?;
        let component_tools = match &self.components {
            Some(components) => {
                let renderer_names = compiled_component_manifest()
                    .into_iter()
                    .map(|entry| entry.name)
                    .collect::<Vec<_>>();
                let granted = components
                    .list_components_for_agent(
                        &ComponentRuntimeScope {
                            tenant: self.tenant.clone(),
                            actor: lease.actor_id().clone(),
                            admin: actor_admin,
                            agent_id: lease.bot_id().clone(),
                        },
                        &renderer_names,
                    )
                    .await
                    .map_err(map_component_error)?;
                granted
                    .components
                    .into_iter()
                    .map(|component| {
                        let input_schema = compiled_component_parameter_schema(&component.name)
                            .ok_or(AgentContextError::Corrupt {
                                field: "component_schema",
                            })?;
                        Ok(ProviderToolDefinition {
                            name: component.name,
                            description: component.description,
                            input_schema,
                        })
                    })
                    .collect::<Result<Vec<_>, AgentContextError>>()?
            }
            None => Vec::new(),
        };
        let sandboxed_component_tools = match &self.sandboxed_components {
            Some(components) => components
                .list_sandboxed_components_for_agent(&ComponentRuntimeScope {
                    tenant: self.tenant.clone(),
                    actor: lease.actor_id().clone(),
                    admin: actor_admin,
                    agent_id: lease.bot_id().clone(),
                })
                .await
                .map_err(map_sandboxed_component_error)?
                .components
                .into_iter()
                .map(|component| ProviderToolDefinition {
                    name: component.name,
                    description: component.description,
                    input_schema: component.argument_schema,
                })
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };
        let database_now_millis: i64 =
            visible.try_get("assertion_issued_at_millis").map_err(|_| {
                AgentContextError::Corrupt {
                    field: "database_now_millis",
                }
            })?;
        let cost_cap = match (
            visible
                .try_get::<_, Option<String>>("budget_cost_currency")
                .map_err(|_| AgentContextError::Corrupt {
                    field: "budget_cost_currency",
                })?,
            visible
                .try_get::<_, Option<i64>>("budget_max_cost_micro_units")
                .map_err(|_| AgentContextError::Corrupt {
                    field: "budget_max_cost_micro_units",
                })?,
        ) {
            (None, None) => None,
            (Some(currency), Some(amount)) => Some(
                RunCostCap::new(
                    currency,
                    u64::try_from(amount).map_err(|_| AgentContextError::Corrupt {
                        field: "budget_max_cost_micro_units",
                    })?,
                )
                .map_err(|_| AgentContextError::Corrupt {
                    field: "run_cost_budget",
                })?,
            ),
            _ => {
                return Err(AgentContextError::Corrupt {
                    field: "run_cost_budget_shape",
                });
            }
        };
        let (route, standing_prompt, tools, max_output_tokens, rate_card) = match agent_type
            .as_str()
        {
            "built_in" => {
                let mut tools = self.tools.clone();
                tools.extend(component_tools.clone());
                tools.extend(sandboxed_component_tools.clone());
                tools.extend(granted_mcp.iter().map(|tool| tool.provider_definition()));
                let route = match &selection {
                    Some(binding) => ProviderRoute::CustomModel(binding.clone()),
                    None => {
                        let route = provider_route(&configuration)?;
                        if let ProviderRoute::Extension(key) = &route {
                            if self.extensions.get(key).is_none() {
                                return Err(AgentContextError::Unavailable);
                            }
                        }
                        route
                    }
                };
                let rate_card = match &route {
                    ProviderRoute::PackageOpenAi => self.package_rate_card.clone(),
                    ProviderRoute::Managed => self.managed_rate_card.clone(),
                    ProviderRoute::RemoteAgUi(_)
                    | ProviderRoute::CustomModel(_)
                    | ProviderRoute::Extension(_) => None,
                };
                (
                    route,
                    append_granted_tool_guidance(standing_prompt(&configuration)?, &granted_mcp),
                    tools,
                    self.max_output_tokens,
                    rate_card,
                )
            }
            "remote_ag_ui" => {
                let endpoint = configuration
                    .as_object()
                    .and_then(|value| value.get("endpoint"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or(AgentContextError::Corrupt {
                        field: "remote_endpoint",
                    })?
                    .trim()
                    .to_owned();
                let name: String =
                    visible
                        .try_get("name")
                        .map_err(|_| AgentContextError::Corrupt {
                            field: "agent_name",
                        })?;
                let title: String =
                    visible
                        .try_get("title")
                        .map_err(|_| AgentContextError::Corrupt {
                            field: "agent_title",
                        })?;
                let role_description: String =
                    visible.try_get("role_description").map_err(|_| {
                        AgentContextError::Corrupt {
                            field: "role_description",
                        }
                    })?;
                let remote_tools =
                    RemoteToolSet::new(granted_mcp.iter().map(|tool| tool.model_name.clone()))
                        .map_err(|_| AgentContextError::Corrupt {
                            field: "remote_tool_set",
                        })?;
                let assertion = self
                    .remote_assertions
                    .as_ref()
                    .ok_or(AgentContextError::Unavailable)?
                    .mint(
                        RemoteRunScope {
                            deployment: self.deployment.clone(),
                            tenant: self.tenant.clone(),
                            bot: lease.bot_id().clone(),
                            actor: lease.actor_id().clone(),
                            run: lease.run_id().clone(),
                        },
                        &remote_tools,
                        database_now_millis,
                    )
                    .map_err(|_| AgentContextError::Corrupt {
                        field: "remote_run_assertion",
                    })?;
                let authorization = load_remote_authorization(
                    client,
                    &configuration,
                    lease.bot_id(),
                    visible
                        .try_get::<_, Option<String>>("owner_user_id")
                        .map_err(|_| AgentContextError::Corrupt {
                            field: "owner_user_id",
                        })?
                        .as_deref(),
                    self.agent_credential_vault.as_ref(),
                )
                .await?;
                let mut route = RemoteAguiRoute::new(
                    endpoint,
                    lease.thread_id().as_str().to_owned(),
                    lease.run_id().as_str().to_owned(),
                    lease.bot_id().as_str().to_owned(),
                    Some(assertion),
                )?;
                if let Some(authorization) = authorization {
                    route = route.with_authorization(authorization);
                }
                (
                    ProviderRoute::RemoteAgUi(route),
                    append_granted_tool_guidance(
                        remote_standing_prompt(&name, &title, &role_description)?,
                        &granted_mcp,
                    ),
                    component_tools
                        .into_iter()
                        .chain(sandboxed_component_tools)
                        .chain(granted_mcp.iter().map(|tool| tool.provider_definition()))
                        .collect(),
                    None,
                    None,
                )
            }
            _ => {
                return Err(AgentContextError::Corrupt {
                    field: "agent_type",
                });
            }
        };
        if rate_card.as_ref().is_some_and(|rate| {
            rate.observed_at().unix_timestamp_nanos()
                >= i128::from(database_now_millis)
                    .saturating_add(1)
                    .saturating_mul(1_000_000)
        }) {
            return Err(AgentContextError::Corrupt {
                field: "provider_rate_observed_at",
            });
        }
        let count: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM public.messages WHERE thread_id=$1",
                &[&lease.thread_id().as_str()],
            )
            .await
            .map_err(|_| AgentContextError::Unavailable)?
            .try_get(0)
            .map_err(|_| AgentContextError::Corrupt {
                field: "message_count",
            })?;
        if count <= 0 || count > MAX_AGENT_CONTEXT_MESSAGES {
            return Err(if count > MAX_AGENT_CONTEXT_MESSAGES {
                AgentContextError::TooLarge
            } else {
                AgentContextError::Corrupt {
                    field: "message_count",
                }
            });
        }
        let rows = client
            .query(
                "SELECT role,content FROM public.messages WHERE thread_id=$1 ORDER BY seq",
                &[&lease.thread_id().as_str()],
            )
            .await
            .map_err(|_| AgentContextError::Unavailable)?;
        // A close that committed after the admission statement above must not hand out a
        // request built from this read. A missing head is open; a failed check is never open.
        // The window after this check, up to the provider send, belongs to the in-flight drain.
        if crate::thread_history_writer::history_closed_for_read(
            client,
            &self.deployment,
            &self.tenant,
            lease.thread_id(),
        )
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "agent context history closure check failed");
            AgentContextError::Unavailable
        })? {
            return Err(AgentContextError::Stale);
        }
        let mut messages = Vec::with_capacity(rows.len() + 1);
        let mut total_bytes = standing_prompt.len();
        if total_bytes > MAX_AGENT_CONTEXT_BYTES {
            return Err(AgentContextError::TooLarge);
        }
        messages.push(ProviderMessage {
            role: ProviderMessageRole::System,
            content: standing_prompt.clone(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        });
        let mut pending_tool_calls = BTreeMap::<String, String>::new();
        for row in rows {
            let role: String = row
                .try_get("role")
                .map_err(|_| AgentContextError::Corrupt { field: "role" })?;
            let content: Value = row
                .try_get("content")
                .map_err(|_| AgentContextError::Corrupt { field: "content" })?;
            let text = text_content(&content).ok_or(AgentContextError::Corrupt {
                field: "message_content",
            })?;
            if role == "system"
                && text == standing_prompt
                && content.get("selectedSkillSlug").is_none()
            {
                continue;
            }
            let tool_calls = if role == "assistant" {
                if !pending_tool_calls.is_empty() {
                    return Err(AgentContextError::Corrupt {
                        field: "unfinished_tool_pair",
                    });
                }
                provider_tool_calls(&content)?
            } else {
                if content.get("toolCalls").is_some() {
                    return Err(AgentContextError::Corrupt {
                        field: "tool_calls_role",
                    });
                }
                Vec::new()
            };
            let tool_call_id = if role == "tool" {
                Some(required_content_string(&content, "toolCallId")?)
            } else {
                None
            };
            let tool_name = if role == "tool" {
                Some(required_content_string(&content, "toolName")?)
            } else {
                None
            };
            if role == "assistant" {
                for call in &tool_calls {
                    if pending_tool_calls
                        .insert(call.call_id.clone(), call.name.clone())
                        .is_some()
                    {
                        return Err(AgentContextError::Corrupt {
                            field: "duplicate_tool_call_id",
                        });
                    }
                }
            } else if role == "tool" {
                let (Some(call_id), Some(name)) = (tool_call_id.as_deref(), tool_name.as_deref())
                else {
                    return Err(AgentContextError::Corrupt {
                        field: "tool_pair_binding",
                    });
                };
                if pending_tool_calls.remove(call_id).as_deref() != Some(name) {
                    return Err(AgentContextError::Corrupt {
                        field: "tool_pair_binding",
                    });
                }
            } else if !pending_tool_calls.is_empty() {
                return Err(AgentContextError::Corrupt {
                    field: "unfinished_tool_pair",
                });
            }
            let tool_bytes = tool_calls.iter().try_fold(0_usize, |total, call| {
                serde_json::to_vec(&call.arguments)
                    .ok()
                    .and_then(|arguments| {
                        total
                            .checked_add(call.call_id.len())?
                            .checked_add(call.name.len())?
                            .checked_add(arguments.len())
                    })
                    .ok_or(AgentContextError::TooLarge)
            })?;
            let result_pair_bytes = tool_call_id
                .as_ref()
                .zip(tool_name.as_ref())
                .map_or(0, |(call_id, name)| {
                    call_id.len().saturating_add(name.len())
                });
            total_bytes = total_bytes
                .checked_add(text.len())
                .and_then(|value| value.checked_add(tool_bytes))
                .and_then(|value| value.checked_add(result_pair_bytes))
                .ok_or(AgentContextError::TooLarge)?;
            if total_bytes > MAX_AGENT_CONTEXT_BYTES {
                return Err(AgentContextError::TooLarge);
            }
            let role = match role.as_str() {
                "user" => ProviderMessageRole::User,
                "assistant" => ProviderMessageRole::Assistant,
                "system" | "summary" => ProviderMessageRole::System,
                "tool" => ProviderMessageRole::Tool,
                _ => return Err(AgentContextError::Corrupt { field: "role" }),
            };
            messages.push(ProviderMessage {
                role,
                content: text,
                tool_call_id,
                tool_name,
                tool_calls,
            });
        }
        if !pending_tool_calls.is_empty() {
            return Err(AgentContextError::ToolHistoryUnsupported);
        }
        Ok(ProviderRequest {
            route,
            messages,
            tools,
            max_output_tokens,
            rate_card,
            cost_cap,
        })
    }
}

fn map_context_dataset(error: crate::model_dataset::ModelDatasetError) -> AgentContextError {
    match error {
        crate::model_dataset::ModelDatasetError::InvalidBinding => AgentContextError::Corrupt {
            field: "model_dataset_binding",
        },
        crate::model_dataset::ModelDatasetError::Unavailable => AgentContextError::Unavailable,
    }
}
fn map_context_transaction(error: crate::db::pool::TransactionOwnerError) -> AgentContextError {
    use crate::db::pool::TransactionOwnerError as E;
    tracing::warn!(state=?error,"custom model original context transaction state");
    match error {
        E::AlreadyStarted => AgentContextError::Corrupt {
            field: "model_dataset_transaction",
        },
        E::DeadlineExceeded
        | E::BeginUnavailable
        | E::CommitUnknown
        | E::RollbackUnproven
        | E::CommitAcknowledgedAfterDeadline
        | E::RollbackAcknowledgedAfterDeadline => AgentContextError::Unavailable,
    }
}

// Common projection uses existing Client-only helper ports. Cancellation retires only this
// separate legacy checkout; it never detaches or cancels either original guarded owner.
struct V2ContextProjectionConnection {
    client: Option<crate::db::pool::PooledClient>,
    clean: bool,
    deadline: std::time::Instant,
}
impl Drop for V2ContextProjectionConnection {
    fn drop(&mut self) {
        if self.clean {
            return;
        }
        let Some(client) = self.client.take() else {
            return;
        };
        let owned = crate::db::pool::PooledClient::take(client);
        let cancel = owned.cancel_token();
        let deadline = self.deadline;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    cancel.cancel_query(tokio_postgres::NoTls),
                )
                .await;
                drop(owned);
            });
        }
    }
}

#[async_trait]
impl AgentContextSource for PostgresAgentContextSource {
    async fn load(&self, lease: &RunExecutionLease) -> Result<ProviderRequest, AgentContextError> {
        lease
            .check_delegated_sampling()
            .await
            .map_err(|_| AgentContextError::DelegationNotCurrent)?;
        if self.model_dataset_binding.is_some() {
            self.load_configured(lease).await
        } else {
            self.load_legacy(lease).await
        }
    }
}

fn map_component_error(
    error: openbot_application::ComponentAdministrationError,
) -> AgentContextError {
    match error {
        openbot_application::ComponentAdministrationError::NotVisible => AgentContextError::Stale,
        openbot_application::ComponentAdministrationError::Corrupt { .. }
        | openbot_application::ComponentAdministrationError::InvalidInput { .. } => {
            AgentContextError::Corrupt {
                field: "component_catalogue",
            }
        }
        openbot_application::ComponentAdministrationError::Unavailable
        | openbot_application::ComponentAdministrationError::CommitUnknown
        | openbot_application::ComponentAdministrationError::Conflict => {
            AgentContextError::Unavailable
        }
    }
}

fn map_sandboxed_component_error(
    error: openbot_application::SandboxedComponentAdministrationError,
) -> AgentContextError {
    match error {
        openbot_application::SandboxedComponentAdministrationError::NotVisible
        | openbot_application::SandboxedComponentAdministrationError::StaleSnapshot(_) => {
            AgentContextError::Stale
        }
        openbot_application::SandboxedComponentAdministrationError::Corrupt { .. }
        | openbot_application::SandboxedComponentAdministrationError::InvalidInput { .. } => {
            AgentContextError::Corrupt {
                field: "sandboxed_component_catalogue",
            }
        }
        openbot_application::SandboxedComponentAdministrationError::Unavailable
        | openbot_application::SandboxedComponentAdministrationError::CommitUnknown
        | openbot_application::SandboxedComponentAdministrationError::Conflict => {
            AgentContextError::Unavailable
        }
    }
}

fn map_mcp_catalog_error(error: McpCatalogError) -> AgentContextError {
    match error {
        McpCatalogError::Unavailable => AgentContextError::Unavailable,
        McpCatalogError::NotVisible => AgentContextError::Stale,
        McpCatalogError::Corrupt { .. } => AgentContextError::Corrupt {
            field: "mcp_catalog",
        },
    }
}

// SPDX-License-Identifier: MIT
// Source: CopilotKit/openbot@891df72f1827454d8b353d108fe5dd2313b7e30d
// File: server/src/plugins/tools.ts::grantedToolGuidance; translated to validated catalog facts.
fn append_granted_tool_guidance(mut prompt: String, tools: &[GrantedMcpTool]) -> String {
    if tools.is_empty() {
        return prompt;
    }
    let mut by_system = BTreeMap::<&str, Vec<&str>>::new();
    for tool in tools {
        by_system
            .entry(tool.server_id.as_str())
            .or_default()
            .push(tool.raw_name.as_str());
    }
    let mut guidance = vec![
        "You can reach these systems directly, as the person asking, with their own access:"
            .to_owned(),
    ];
    for (system, names) in by_system {
        guidance.push(format!("- {system}: {}", names.join(", ")));
    }
    guidance.extend([
        "Use them for anything about those systems. Do NOT browse to one of their websites instead: your".to_owned(),
        "browser is signed in as nobody, so it sees less than these tools do and will meet a sign-in wall".to_owned(),
        "that connecting an account has already solved.".to_owned(),
        "If one of these systems is involved and no tool above covers the part you need, that is a".to_owned(),
        "missing grant and not something to work around. Say so plainly, name the capability you would".to_owned(),
        "need, and say an administrator can grant it on that connector. Do not reach for the browser, do".to_owned(),
        "not ask the person to sign in, and do not ask them to fetch it for you: they already have the".to_owned(),
        "access, and the thing that is missing is yours, not theirs.".to_owned(),
    ]);
    prompt.push_str("\n\n");
    prompt.push_str(&guidance.join("\n"));
    prompt
}

fn provider_tool_calls(content: &Value) -> Result<Vec<ProviderToolCall>, AgentContextError> {
    let Some(calls) = content.get("toolCalls") else {
        return Ok(Vec::new());
    };
    let calls = calls.as_array().ok_or(AgentContextError::Corrupt {
        field: "tool_calls",
    })?;
    if calls.len() > 256 {
        return Err(AgentContextError::TooLarge);
    }
    calls
        .iter()
        .map(|call| {
            let call_id = call
                .get("id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(AgentContextError::Corrupt {
                    field: "tool_call_id",
                })?
                .to_owned();
            let function = call.get("function").and_then(Value::as_object).ok_or(
                AgentContextError::Corrupt {
                    field: "tool_call_function",
                },
            )?;
            let name = function
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(AgentContextError::Corrupt {
                    field: "tool_call_name",
                })?
                .to_owned();
            let arguments = match function.get("arguments") {
                Some(value) if value.is_object() => value.clone(),
                Some(Value::String(value)) => serde_json::from_str(value)
                    .ok()
                    .filter(Value::is_object)
                    .ok_or(AgentContextError::Corrupt {
                        field: "tool_call_arguments",
                    })?,
                _ => {
                    return Err(AgentContextError::Corrupt {
                        field: "tool_call_arguments",
                    });
                }
            };
            Ok(ProviderToolCall {
                call_id,
                name,
                arguments,
            })
        })
        .collect()
}

fn required_content_string(
    content: &Value,
    field: &'static str,
) -> Result<String, AgentContextError> {
    content
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(AgentContextError::Corrupt { field })
}

fn provider_route(configuration: &Value) -> Result<ProviderRoute, AgentContextError> {
    match configuration
        .as_object()
        .and_then(|value| value.get("providerSource"))
    {
        None | Some(Value::Null) => Ok(ProviderRoute::PackageOpenAi),
        Some(Value::String(value)) if value == "package" => Ok(ProviderRoute::PackageOpenAi),
        Some(Value::String(value)) if value == "managed" => Ok(ProviderRoute::Managed),
        Some(Value::String(value)) if value.starts_with("extension:") => {
            openbot_application::ProviderExtensionKey::new(&value[10..])
                .map(ProviderRoute::Extension)
                .map_err(|_| AgentContextError::Corrupt {
                    field: "provider_source",
                })
        }
        _ => Err(AgentContextError::Corrupt {
            field: "provider_source",
        }),
    }
}

fn standing_prompt(configuration: &Value) -> Result<String, AgentContextError> {
    let prompt = configuration
        .as_object()
        .and_then(|value| value.get("systemPrompt"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(AgentContextError::Corrupt {
            field: "system_prompt",
        })?;
    if prompt.as_bytes().contains(&0) {
        return Err(AgentContextError::Corrupt {
            field: "system_prompt",
        });
    }
    Ok(format!("{prompt}\n\n{PROVENANCE_GUIDANCE}"))
}

fn remote_standing_prompt(
    name: &str,
    title: &str,
    role_description: &str,
) -> Result<String, AgentContextError> {
    let name = name.trim();
    let title = title.trim();
    let role_description = role_description.trim();
    if name.is_empty() || title.is_empty() || role_description.is_empty() {
        return Err(AgentContextError::Corrupt {
            field: "remote_standing_role",
        });
    }
    let prompt = format!(
        "You are {name}, {title}.\n\n{role_description}\n\n\
         This standing role applies in every channel. Treat channel messages as task-specific instructions within it.\n\n\
         {PROVENANCE_GUIDANCE}"
    );
    if prompt.len() > MAX_AGENT_CONTEXT_BYTES {
        return Err(AgentContextError::TooLarge);
    }
    Ok(prompt)
}

async fn load_remote_authorization(
    client: &tokio_postgres::Client,
    configuration: &Value,
    bot: &BotId,
    owner: Option<&str>,
    vault: Option<&CredentialRecordVault>,
) -> Result<Option<RemoteAguiAuthorization>, AgentContextError> {
    let Some(auth) = configuration.get("auth") else {
        return Ok(None);
    };
    let auth = auth.as_object().ok_or(AgentContextError::Corrupt {
        field: "remote_authorization",
    })?;
    if auth.len() != 2 || auth.get("header").and_then(Value::as_str) != Some("Authorization") {
        return Err(AgentContextError::Corrupt {
            field: "remote_authorization",
        });
    }
    let credential_id = auth
        .get("credentialId")
        .and_then(Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or(AgentContextError::Corrupt {
            field: "remote_credential_id",
        })?;
    let owner = owner.ok_or(AgentContextError::Corrupt {
        field: "owner_user_id",
    })?;
    let vault = vault.ok_or(AgentContextError::Unavailable)?;
    let row = client
        .query_opt(
            "SELECT encrypted_value,key_id FROM public.credentials
              WHERE id=$1 AND kind='agent' AND provider=$2 AND revoked_at IS NULL",
            &[&credential_id, &bot.as_str()],
        )
        .await
        .map_err(|_| AgentContextError::Unavailable)?
        .ok_or(AgentContextError::Stale)?;
    let key_id: String = row
        .try_get("key_id")
        .map_err(|_| AgentContextError::Corrupt {
            field: "remote_credential_owner",
        })?;
    if key_id != owner {
        return Err(AgentContextError::Corrupt {
            field: "remote_credential_owner",
        });
    }
    let encrypted: String =
        row.try_get("encrypted_value")
            .map_err(|_| AgentContextError::Corrupt {
                field: "remote_credential",
            })?;
    let secret = vault
        .open(
            &credential_id,
            SecretKind::Agent,
            SecretPrincipal::Actor(ActorId::new(owner)),
            SecretPrincipal::Service(ServiceId::new(bot.as_str())),
            &encrypted,
        )
        .map_err(|_| AgentContextError::Corrupt {
            field: "remote_credential",
        })?
        .into_secret();
    RemoteAguiAuthorization::new(secret).map(Some)
}

fn text_content(value: &Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return Some(value.to_owned());
    }
    if let Some(value) = value
        .get("text")
        .or_else(|| value.get("content"))
        .and_then(Value::as_str)
    {
        return Some(value.to_owned());
    }
    value.as_array().map(|parts| {
        parts
            .iter()
            .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_standing_prompt_is_trimmed_and_always_carries_provenance_guidance() {
        let prompt =
            standing_prompt(&serde_json::json!({"systemPrompt":"  Be helpful.  "})).unwrap();
        assert!(prompt.starts_with("Be helpful.\n\nSay where an answer came from."));
        assert!(prompt.ends_with("a search that never ends is a Bot that never answers."));
        assert_eq!(
            standing_prompt(&serde_json::json!({"systemPrompt":"  "})),
            Err(AgentContextError::Corrupt {
                field: "system_prompt"
            })
        );
        assert_eq!(
            provider_route(&serde_json::json!({"systemPrompt":"x","providerSource":"managed"})),
            Ok(ProviderRoute::Managed)
        );
        assert_eq!(
            provider_route(&serde_json::json!({"systemPrompt":"x","providerSource":"unknown"})),
            Err(AgentContextError::Corrupt {
                field: "provider_source"
            })
        );
    }
}
