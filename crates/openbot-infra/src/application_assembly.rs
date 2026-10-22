//! Shared PostgreSQL-backed [`ApplicationService`] assembly for Server and Desktop Local.
//!
//! This is a composition root, not a transport: every input is already parsed/verified, no process
//! environment is read, and no HTTP listener or native window is created. Server and Tauri must
//! both consume the returned *same* typed application boundary instead of reproducing business
//! adapter wiring.

use std::sync::Arc;
use std::time::Duration;

use crate::db::pool::DatabasePool as Pool;
use openbot_application::provider::RemoteAguiTransport;
use openbot_application::{
    ApplicationService, ArtifactAdministration, OpenBotApplication, ProviderAdapter, RunRuntime,
    ScreenSessionAdministration, ToolCancellationRegistry, UiPreferenceAdministration,
};
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::identity::roles::AdminFloor;
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::SecretBytes;
use url::Url;

use crate::agent_callback::{PostgresAgentCallbackTokens, PostgresRemoteCallbackAuthenticator};
use crate::agent_tools::PostgresBuiltInToolControlPlane;
use crate::component_catalogue::PostgresComponentAdministration;
use crate::credential_admin::PostgresCredentialAdministration;
use crate::custom_model_catalog::PostgresCustomModelCatalogInventory;
use crate::google_drive::GoogleDriveRestTransport;
use crate::google_drive_oauth::GoogleDriveOAuthClient;
use crate::mcp::SafeRmcpClient;
use crate::mcp_catalog::PostgresMcpCatalog;
use crate::mcp_connections::{McpRevocationReconciler, PostgresMcpConnections};
use crate::mcp_credentials::PostgresMcpCredentialBroker;
use crate::mcp_oauth::McpOAuthClient;
use crate::memory_admin::PostgresMemoryAdministration;
use crate::model_dataset::PostgresModelDatasetBinding;
use crate::net::safe_http::{
    CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy,
};
use crate::policy::PolicyStore;
use crate::provider::credential::PostgresOpenAiCredentialSource;
use crate::provider::openai::{OpenAiApiKey, OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig};
use crate::remote_interrupt::PostgresRemoteInterruptCoordinator;
use crate::repo::ChannelRepo;
use crate::repo::agents::{PostgresAgentAdministration, PostgresAgentDirectory};
use crate::repo::audit::PostgresAuditReader;
use crate::repo::people_admin::PostgresPeopleAdministration;
use crate::repo::tools::PostgresToolJournal;
use crate::routing::PostgresChannelRouting;
use crate::run_cost_budget::PostgresRunCostBudgetAdministration;
use crate::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use crate::runtime_capability_facts::{
    PostgresRuntimeCapabilityFacts, RuntimeCapabilityAssemblyFactsInput,
    RuntimeCapabilityCollectorFactory,
};
use crate::sandboxed_components::PostgresSandboxedComponentAdministration;
use crate::store::plugin_user_credential::PostgresOwnedCredentialRetirer;
use crate::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use crate::thread_history_authority::PostgresThreadHistoryAuthority;
use crate::thread_id::mint_thread_id;
use crate::thread_listener::ThreadListenerDatabase;
use crate::tool_approval::PostgresToolApprovalCoordinator;
use crate::vault::CredentialRecordVault;

const CHANNEL_ROUTING_PROTOCOL: OpenAiProtocol = OpenAiProtocol::ChatCompletions;

/// Closed OpenAI-compatible route provider input; secrets stay in [`SecretBytes`].
pub struct ChannelRoutingProviderInput {
    /// Exact already-validated Chat Completions endpoint.
    pub endpoint: Url,
    /// Optional environment fallback retained for Server compatibility; Desktop normally passes
    /// `None` and uses its Vault.
    pub environment_api_key: Option<SecretBytes>,
    /// Exact numeric CIDRs already parsed from configuration syntax.
    pub egress_allow_cidrs: Vec<String>,
    /// Explicit local/test HTTP allowance; production defaults false.
    pub allow_http: bool,
}

impl core::fmt::Debug for ChannelRoutingProviderInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ChannelRoutingProviderInput")
            .field("endpoint", &"<redacted>")
            .field(
                "environment_api_key",
                &self.environment_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("egress_allow_cidrs", &self.egress_allow_cidrs.len())
            .field("allow_http", &self.allow_http)
            .finish()
    }
}

/// Explicit inputs shared by Server and the Tauri background setup.
pub struct PostgresApplicationAssemblyInput {
    pub pool: Pool,
    pub listener_database: ThreadListenerDatabase,
    pub deployment: DeploymentId,
    pub tenant: TenantId,
    pub single_user: bool,
    pub admin_floor: Option<AdminFloor>,
    pub model: String,
    pub credential_key_id: String,
    pub credential_vault: CredentialRecordVault,
    pub audit_key: SecretBytes,
    pub remote_assertions: Arc<RemoteRunAssertionSigner>,
    pub mcp_oauth_state_key: SecretBytes,
    pub policy_store: PolicyStore,
    pub ui_preferences: Arc<dyn UiPreferenceAdministration>,
    pub screen_sessions: Arc<dyn ScreenSessionAdministration>,
    /// Actual authoritative artifact dependency, or a truthful unavailable default when absent.
    pub artifacts: Option<Arc<dyn ArtifactAdministration>>,
    /// Only a trusted actual host can build the optional observer from these exact dependencies.
    pub runtime_capabilities: Option<Arc<dyn RuntimeCapabilityCollectorFactory>>,
    pub remote_agent_probe: Arc<dyn RemoteAguiTransport>,
    pub managed_slot_available: bool,
    pub channel_routing_provider: ChannelRoutingProviderInput,
    pub stall_timeout: Option<Duration>,
    pub oauth_public_url: Option<String>,
    pub app_url: Option<String>,
}

/// Sealed by the actual fixed tool/ScreenSession assembly, not a caller inventory.
/// R474 exposes this borrowed DATA getter; only the original assembly constructs it.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub struct CaptureAssemblyMaterialLayout {
    application: std::sync::Weak<dyn ApplicationService>,
    screen: std::sync::Weak<dyn ScreenSessionAdministration>,
}
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl PostgresApplicationAssembly {
    pub fn capture_material_layout(
        &self,
        original_screen: &Arc<dyn ScreenSessionAdministration>,
    ) -> Result<
        &CaptureAssemblyMaterialLayout,
        openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault,
    > {
        if !self
            .capture_material_layout
            .application
            .ptr_eq(&Arc::downgrade(&self.application))
            || !self
                .capture_material_layout
                .screen
                .ptr_eq(&Arc::downgrade(original_screen))
        {
            return Err(
                openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::SourceChanged,
            );
        }
        Ok(&self.capture_material_layout)
    }
}

impl core::fmt::Debug for PostgresApplicationAssemblyInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresApplicationAssemblyInput")
            .field("deployment", &self.deployment)
            .field("tenant", &self.tenant)
            .field("single_user", &self.single_user)
            .field("model", &self.model)
            .field("credential_key_id", &"<redacted-reference>")
            .field("credential_vault", &self.credential_vault)
            .field("audit_key", &"[REDACTED]")
            .field("remote_assertions", &self.remote_assertions)
            .field("mcp_oauth_state_key", &"[REDACTED]")
            .field("ui_preferences", &"Arc<dyn UiPreferenceAdministration>")
            .field("screen_sessions", &"Arc<dyn ScreenSessionAdministration>")
            .field(
                "artifacts",
                &self
                    .artifacts
                    .as_ref()
                    .map(|_| "Arc<dyn ArtifactAdministration>"),
            )
            .field("managed_slot_available", &self.managed_slot_available)
            .field("channel_routing_provider", &self.channel_routing_provider)
            .field("stall_timeout", &self.stall_timeout)
            .field("oauth_public_url", &self.oauth_public_url.is_some())
            .field("app_url", &self.app_url.is_some())
            .finish_non_exhaustive()
    }
}

/// Shared assembly output plus the background/lifecycle adapters its host must retain.
pub struct PostgresApplicationAssembly {
    /// One original current history observer shared with the actual host enrollment.
    pub thread_history_authority: Arc<PostgresThreadHistoryAuthority>,
    /// Same once-enrolled original dataset binding used by every V2 consumer.
    pub model_dataset_binding: Arc<PostgresModelDatasetBinding>,
    pub custom_model_catalog_inventory: Arc<PostgresCustomModelCatalogInventory>,
    pub runtime_capability_facts: Option<Arc<PostgresRuntimeCapabilityFacts>>,
    pub application: Arc<dyn ApplicationService>,
    pub run_runtime: Arc<dyn RunRuntime>,
    pub remote_interrupts: Arc<PostgresRemoteInterruptCoordinator>,
    pub mcp_catalog: Arc<PostgresMcpCatalog>,
    pub components: Arc<PostgresComponentAdministration>,
    pub sandboxed_components: Arc<PostgresSandboxedComponentAdministration>,
    pub mcp_connections: Arc<PostgresMcpConnections>,
    pub remote_callback_auth: Arc<PostgresRemoteCallbackAuthenticator>,
    pub tool_cancellations: Arc<ToolCancellationRegistry>,
    pub mcp_revocation_reconciler: McpRevocationReconciler,
    capture_facts_closed: bool,
    #[cfg(all(feature = "server-runtime", target_os = "macos"))]
    capture_material_layout: CaptureAssemblyMaterialLayout,
}

impl core::fmt::Debug for PostgresApplicationAssembly {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresApplicationAssembly")
            .field("model_dataset_binding", &self.model_dataset_binding)
            .field(
                "custom_model_catalog_inventory",
                &"PostgresCustomModelCatalogInventory",
            )
            .field("application", &"Arc<dyn ApplicationService>")
            .field("run_runtime", &"Arc<dyn RunRuntime>")
            .field("remote_interrupts", &"PostgresRemoteInterruptCoordinator")
            .field("mcp_catalog", &"PostgresMcpCatalog")
            .field("components", &"PostgresComponentAdministration")
            .field(
                "sandboxed_components",
                &"PostgresSandboxedComponentAdministration",
            )
            .field("mcp_connections", &"PostgresMcpConnections")
            .field(
                "remote_callback_auth",
                &"PostgresRemoteCallbackAuthenticator",
            )
            .field("tool_cancellations", &self.tool_cancellations)
            .field("mcp_revocation_reconciler", &"running")
            .finish()
    }
}

/// Actual original reconciler failure; it never grants a closed normal capture source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureAssemblyStopFailure {
    /// The original reconciler was cancelled.
    ReconcilerCancelled,
    /// The original reconciler panicked.
    ReconcilerPanicked,
}

impl PostgresApplicationAssembly {
    /// Stop background reconcilers before dropping database-backed adapter handles.
    pub async fn shutdown(mut self) {
        let _ = self.stop_for_capture().await;
    }

    /// Keep the entire original assembly outside the cancellable waiter. Actual facts drain
    /// and the original reconciler join are both mandatory; a cached join sends no new stop.
    pub async fn stop_for_capture(&mut self) -> Result<(), CaptureAssemblyStopFailure> {
        if let Some(facts) = &self.runtime_capability_facts {
            if !self.capture_facts_closed {
                facts.close();
                self.capture_facts_closed = true;
            }
            facts.drain().await;
        }
        self.mcp_revocation_reconciler
            .stop_for_capture()
            .await
            .map_err(|error| match error {
                crate::mcp_connections::McpReconcilerStopFailure::Cancelled => {
                    CaptureAssemblyStopFailure::ReconcilerCancelled
                }
                crate::mcp_connections::McpReconcilerStopFailure::Panicked => {
                    CaptureAssemblyStopFailure::ReconcilerPanicked
                }
            })
    }
}

/// Stable assembly failure. Detailed dependency errors remain inside their typed adapters and are
/// not carried toward transport/UI errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("postgres_application_assembly_failed")]
pub struct PostgresApplicationAssemblyError;

/// Assemble the one PostgreSQL-backed application boundary shared by Server and Desktop.
pub async fn assemble_postgres_application(
    input: PostgresApplicationAssemblyInput,
) -> Result<PostgresApplicationAssembly, PostgresApplicationAssemblyError> {
    let PostgresApplicationAssemblyInput {
        pool,
        listener_database,
        deployment,
        tenant,
        single_user,
        admin_floor,
        model,
        credential_key_id,
        credential_vault,
        audit_key,
        remote_assertions,
        mcp_oauth_state_key,
        policy_store,
        ui_preferences,
        screen_sessions,
        artifacts,
        runtime_capabilities,
        remote_agent_probe,
        managed_slot_available,
        channel_routing_provider,
        stall_timeout,
        oauth_public_url,
        app_url,
    } = input;
    if audit_key.is_empty() || mcp_oauth_state_key.is_empty() {
        return Err(fail("key_material"));
    }
    let audit_key = audit_key.expose();
    let agent_administration = Arc::new(
        PostgresAgentAdministration::new(
            pool.clone(),
            credential_vault.clone(),
            audit_key.to_vec(),
            remote_agent_probe,
            managed_slot_available,
        )
        .map_err(|_| fail("agent_administration"))?,
    );
    let owned_credentials = Arc::new(
        PostgresOwnedCredentialRetirer::new(pool.clone(), audit_key.to_vec())
            .map_err(|_| fail("owned_credentials"))?,
    );
    let people = PostgresPeopleAdministration::new(pool.clone(), admin_floor, audit_key.to_vec())
        .map_err(|_| fail("people"))?
        .with_owned_credential_retirer(owned_credentials);
    let runtime_owner = format!(
        "runtime:{}",
        mint_thread_id(&deployment).map_err(|_| fail("runtime_owner"))?
    );
    let run_runtime: Arc<dyn RunRuntime> = Arc::new(
        PostgresRunRuntime::new(
            pool.clone(),
            runtime_owner.clone(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|_| fail("run_runtime"))?,
    );
    let remote_interrupts = Arc::new(
        PostgresRemoteInterruptCoordinator::new(
            pool.clone(),
            runtime_owner.clone(),
            audit_key.to_vec(),
        )
        .map_err(|_| fail("remote_interrupts"))?,
    );
    let model_dataset_binding = Arc::new(
        PostgresModelDatasetBinding::unbound(pool.clone(), deployment.clone(), tenant.clone())
            .map_err(|_| fail("model_dataset_binding"))?,
    );
    let thread_directory = PostgresThreadDirectory::with_runtime(
        pool.clone(),
        listener_database
            .clone()
            .with_application_name("openbot-thread-events"),
        runtime_owner,
        DEFAULT_THREAD_LEASE_DURATION,
    )
    .map_err(|_| fail("thread_directory"))?
    .with_model_dataset_binding(model_dataset_binding.clone())
    .map_err(|_| fail("thread_directory_model_dataset"))?;
    let memory = PostgresMemoryAdministration::new(pool.clone())
        .with_effect_audit_key(audit_key.to_vec())
        .map_err(|_| fail("memory_effect_audit"))?;

    let mcp_client = SafeRmcpClient::new(
        SafeDialer::new(EgressPolicy::default()),
        SchemePolicy::HttpsOnly,
        stall_timeout,
    );
    let mcp_catalog = Arc::new(
        PostgresMcpCatalog::new(pool.clone(), mcp_client.clone(), audit_key.to_vec())
            .map_err(|_| fail("mcp_catalog"))?,
    );
    let drive_oauth = GoogleDriveOAuthClient::new(SafeDialer::new(EgressPolicy::default()))
        .map_err(|_| fail("drive_oauth"))?;
    let drive_transport = GoogleDriveRestTransport::new(SafeDialer::new(EgressPolicy::default()))
        .map_err(|_| fail("drive_transport"))?;
    let mcp_credentials = Arc::new(
        PostgresMcpCredentialBroker::new(pool.clone(), credential_vault.clone())
            .with_user_oauth(
                SafeDialer::new(EgressPolicy::default()),
                SchemePolicy::HttpsOnly,
                audit_key.to_vec(),
            )
            .map_err(|_| fail("mcp_user_oauth"))?
            .with_google_drive_oauth(drive_oauth.clone()),
    );
    match tokio::time::timeout(
        Duration::from_secs(30),
        mcp_catalog.refresh_startup_servers(&mcp_credentials),
    )
    .await
    {
        Ok(Ok(report)) => tracing::info!(
            refreshed = report.refreshed,
            failed = report.failed,
            authenticated_deferred = report.authenticated_deferred,
            "MCP startup catalog sweep completed"
        ),
        Ok(Err(_)) => return Err(fail("mcp_startup_sweep")),
        Err(_) => tracing::warn!(
            code = "mcp_startup_sweep_timeout",
            "MCP startup catalog sweep exceeded 30 second aggregate budget"
        ),
    }
    let mcp_connections = Arc::new(
        PostgresMcpConnections::new(
            pool.clone(),
            credential_vault.clone(),
            McpOAuthClient::new(
                SafeDialer::new(EgressPolicy::default()),
                SchemePolicy::HttpsOnly,
            ),
            mcp_catalog.clone(),
            deployment.clone(),
            tenant.clone(),
            mcp_oauth_state_key.expose().to_vec(),
            audit_key.to_vec(),
            oauth_public_url.as_deref(),
            app_url.as_deref(),
            SchemePolicy::HttpsOnly,
        )
        .map_err(|_| fail("mcp_connections"))?
        .with_mcp_credentials(mcp_credentials.clone())
        .with_google_drive_oauth(drive_oauth),
    );
    let tool_approvals = Arc::new(
        PostgresToolApprovalCoordinator::new(
            pool.clone(),
            deployment.clone(),
            tenant.clone(),
            audit_key.to_vec(),
        )
        .map_err(|_| fail("tool_approvals"))?,
    );
    let tool_cancellations = Arc::new(ToolCancellationRegistry::default());
    let tool_control = PostgresBuiltInToolControlPlane::new(
        pool.clone(),
        deployment.clone(),
        tenant.clone(),
        policy_store.clone(),
        Arc::new(memory.clone()),
    )
    .with_mcp(mcp_catalog.clone(), mcp_client)
    .with_google_drive(drive_transport)
    .with_tool_approvals(tool_approvals.clone())
    .with_tool_cancellations(tool_cancellations.clone())
    .with_mcp_credentials(mcp_credentials);
    let tool_journal = PostgresToolJournal::new(pool.clone(), audit_key.to_vec())
        .map_err(|_| fail("tool_journal"))?;
    let callback_tokens = PostgresAgentCallbackTokens::new(
        pool.clone(),
        deployment.clone(),
        tenant.clone(),
        audit_key.to_vec(),
    )
    .map_err(|_| fail("callback_tokens"))?;
    let remote_callback_auth = Arc::new(
        PostgresRemoteCallbackAuthenticator::new(
            pool.clone(),
            deployment.clone(),
            tenant.clone(),
            single_user,
            remote_assertions,
            audit_key.to_vec(),
        )
        .map_err(|_| fail("remote_callback_auth"))?
        .with_mcp_catalog(mcp_catalog.clone()),
    );
    let credentials = Arc::new(
        PostgresCredentialAdministration::new(
            pool.clone(),
            credential_vault.clone(),
            deployment.clone(),
            tenant.clone(),
            SecretBytes::new(audit_key.to_vec()),
            mcp_connections.clone(),
        )
        .map_err(|_| fail("credential_administration"))?
        .with_model_reference("openai".to_owned(), credential_key_id.clone())
        .map_err(|_| fail("credential_model_reference"))?,
    );
    let model_connections = Arc::new(
        crate::model_connections::PostgresModelConnections::new(
            pool.clone(),
            credential_vault.clone(),
            deployment.clone(),
            tenant.clone(),
            SecretBytes::new(audit_key.to_vec()),
        )
        .map_err(|_| fail("model_connections"))?,
    );
    let thread_history_authority = Arc::new(
        PostgresThreadHistoryAuthority::new(pool.clone(), deployment.clone(), tenant.clone())
            .map_err(|_| fail("thread_history_authority"))?,
    );
    thread_history_authority
        .enroll_clear_audit_checkpoint_key(SecretBytes::new(audit_key.to_vec()))
        .map_err(|_| fail("thread_history_authority"))?;
    let custom_model_catalog_inventory = Arc::new(
        PostgresCustomModelCatalogInventory::new(pool.clone(), deployment.clone(), tenant.clone())
            .map_err(|_| fail("custom_model_catalog"))?,
    );
    let channels = ChannelRepo::new(pool.clone());
    let runtime_capability_facts = runtime_capabilities
        .as_ref()
        .map(|_| {
            PostgresRuntimeCapabilityFacts::from_assembly(RuntimeCapabilityAssemblyFactsInput {
                pool: pool.clone(),
                deployment: deployment.clone(),
                tenant: tenant.clone(),
                policy: policy_store.clone(),
                vault: credential_vault.clone(),
                default_key_id: credential_key_id.clone(),
                environment_key: channel_routing_provider
                    .environment_api_key
                    .as_ref()
                    .map(|key| Arc::new(SecretBytes::new(key.expose().to_vec()))),
                channels: channels.clone(),
                people: people.clone(),
                threads: thread_directory.clone(),
                tools: tool_control.clone(),
                models: model_connections.clone(),
            })
            .map(Arc::new)
        })
        .transpose()
        .map_err(|_| fail("runtime_capability_dependencies"))?;
    let runtime_capability_collector = match (&runtime_capabilities, &runtime_capability_facts) {
        (Some(factory), Some(facts)) => Some(
            factory
                .build(Arc::clone(facts))
                .map_err(|_| fail("runtime_capability_host"))?,
        ),
        _ => None,
    };
    let channel_routing = build_channel_routing(
        pool.clone(),
        model,
        credential_key_id,
        credential_vault,
        audit_key.to_vec(),
        stall_timeout,
        channel_routing_provider,
    )?;
    let components = Arc::new(
        PostgresComponentAdministration::new(pool.clone(), audit_key.to_vec())
            .map_err(|_| fail("components"))?
            .with_policy(policy_store.clone()),
    );
    let sandboxed_components = Arc::new(
        PostgresSandboxedComponentAdministration::new(pool.clone(), audit_key.to_vec())
            .map_err(|_| fail("sandboxed_components"))?,
    );
    #[cfg(all(feature = "server-runtime", target_os = "macos"))]
    let capture_screen = Arc::downgrade(&screen_sessions);
    let application = OpenBotApplication::new(channels.clone())
        .with_people(people)
        .with_audit(PostgresAuditReader::new(pool.clone()))
        .with_policy(policy_store)
        .with_tools(tool_control, tool_journal)
        .with_threads(thread_directory)
        .with_memory(memory)
        .with_agent_callback_tokens(callback_tokens)
        .with_channel_administration(Arc::new(channels))
        .with_channel_routing(Arc::new(channel_routing))
        .with_agent_directory(Arc::new(PostgresAgentDirectory::new(pool.clone())))
        .with_agent_administration(agent_administration)
        .with_component_administration(components.clone())
        .with_sandboxed_component_administration(sandboxed_components.clone())
        .with_mcp_connections(mcp_connections.clone())
        .with_credentials(credentials)
        .with_model_connections(model_connections)
        .with_custom_model_catalog_inventory(custom_model_catalog_inventory.clone())
        .with_tool_approvals(tool_approvals)
        .with_ui_preferences(ui_preferences)
        .with_run_cost_budgets(Arc::new(PostgresRunCostBudgetAdministration::new(
            pool.clone(),
        )))
        .with_remote_interrupts(remote_interrupts.clone())
        .with_screen_sessions(screen_sessions);
    let application = match artifacts {
        Some(artifacts) => application.with_artifacts(artifacts),
        None => application,
    };
    let application = match runtime_capability_collector {
        Some(collector) => application.with_runtime_capabilities(collector),
        None => application,
    };
    let application: Arc<dyn ApplicationService> = Arc::new(application);
    #[cfg(all(feature = "server-runtime", target_os = "macos"))]
    let capture_material_layout = CaptureAssemblyMaterialLayout {
        application: Arc::downgrade(&application),
        screen: capture_screen,
    };
    let mcp_revocation_reconciler = McpRevocationReconciler::start(mcp_connections.clone());
    Ok(PostgresApplicationAssembly {
        thread_history_authority,
        model_dataset_binding,
        custom_model_catalog_inventory,
        runtime_capability_facts,
        application,
        run_runtime,
        remote_interrupts,
        mcp_catalog,
        components,
        sandboxed_components,
        mcp_connections,
        remote_callback_auth,
        tool_cancellations,
        mcp_revocation_reconciler,
        capture_facts_closed: false,
        #[cfg(all(feature = "server-runtime", target_os = "macos"))]
        capture_material_layout,
    })
}

fn build_channel_routing(
    pool: Pool,
    model: String,
    credential_key_id: String,
    credential_vault: CredentialRecordVault,
    audit_key: Vec<u8>,
    stall_timeout: Option<Duration>,
    provider: ChannelRoutingProviderInput,
) -> Result<PostgresChannelRouting, PostgresApplicationAssemblyError> {
    let environment_fallback = provider
        .environment_api_key
        .map(|key| OpenAiApiKey::from_bytes(key.expose().to_vec()))
        .transpose()
        .map_err(|_| fail("channel_environment_key"))?;
    let credentials = Arc::new(
        PostgresOpenAiCredentialSource::new(
            pool.clone(),
            credential_vault,
            credential_key_id,
            environment_fallback,
        )
        .map_err(|_| fail("channel_credentials"))?,
    );
    let egress = EgressPolicy::new(
        CidrAllowlist::parse_exact(provider.egress_allow_cidrs.iter().map(String::as_str))
            .map_err(|_| fail("channel_egress"))?,
    );
    let adapter: Arc<dyn ProviderAdapter> = Arc::new(OpenAiProvider::new_with_credential_source(
        OpenAiProviderConfig::new_with_transport_policy(
            provider.endpoint,
            model,
            CHANNEL_ROUTING_PROTOCOL,
            SafeHttpBudget::new(16 * 1024 * 1024, Duration::from_secs(10))
                .map_err(|_| fail("channel_budget"))?,
            stall_timeout,
            if provider.allow_http {
                SchemePolicy::HttpOrHttps
            } else {
                SchemePolicy::HttpsOnly
            },
        )
        .map_err(|_| fail("channel_provider_config"))?,
        credentials,
        SafeDialer::new(egress),
    ));
    PostgresChannelRouting::new(pool, audit_key, adapter).map_err(|_| fail("channel_routing"))
}

fn fail(phase: &'static str) -> PostgresApplicationAssemblyError {
    tracing::error!(phase, "PostgreSQL application assembly failed");
    PostgresApplicationAssemblyError
}
