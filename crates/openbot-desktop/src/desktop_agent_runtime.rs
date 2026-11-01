//! Desktop-owned built-in/remote Agent host assembled before the first native window.

use std::sync::Arc;
use std::time::Duration;

use openbot_agent::{
    AgentToolInvoker, AuthorizedAgentToolGateway, BuiltInAgentConfig, BuiltInAgentRuntime,
    ProviderRouter, RemoteAguiProvider, RetryingProvider, RetryingProviderConfig,
};
use openbot_application::tenant::package::{
    BuiltInProviderSource, LoadedTenantPackage, TenantAgentConfiguration, TenantAgentType,
};
use openbot_application::{
    AgentAudit, ApplicationService, NoRunDispatchConsumer, ProviderAdapter,
    RemoteInterruptCoordinator, RunDispatchConsumer, RunRuntime, ToolCancellationRegistry,
    remember_provider_tool,
};
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_infra::agent_audit::PostgresAgentAudit;
use openbot_infra::agent_tools::{PostgresAgentAuthorizationSource, PostgresAgentToolSequence};
use openbot_infra::component_catalogue::PostgresComponentAdministration;
use openbot_infra::db::pool::DatabasePool;
use openbot_infra::mcp_catalog::PostgresMcpCatalog;
use openbot_infra::net::safe_http::{
    CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy,
};
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::provider::credential::PostgresOpenAiCredentialSource;
use openbot_infra::provider::custom::PostgresCustomModelProvider;
use openbot_infra::provider::openai::{OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig};
use openbot_infra::remote_agui::SafeRemoteAguiTransport;
use openbot_infra::run_runtime::RunRelay;
use openbot_infra::sandboxed_components::PostgresSandboxedComponentAdministration;
use openbot_infra::thread_listener::ThreadListenerDatabase;
use openbot_infra::vault::CredentialRecordVault;
use url::Url;

const PACKAGE_OPENAI_PROTOCOL: OpenAiProtocol = OpenAiProtocol::Responses;
const CHANNEL_OPENAI_PROTOCOL: OpenAiProtocol = OpenAiProtocol::ChatCompletions;
const PROVIDER_RESPONSE_MAX_BYTES: usize = 64 * 1024 * 1024;
const PROVIDER_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Stable Desktop Agent host failures without endpoint, model, credential, or provider prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DesktopAgentRuntimeError {
    /// Provider address, CIDR, or budget input was outside the closed first-release shape.
    #[error("desktop_agent_configuration_invalid")]
    Configuration,
    /// A package requested the Server-only managed provider source.
    #[error("desktop_agent_managed_provider_unsupported")]
    ManagedProviderUnsupported,
    /// Credential, provider, context, audit, or runtime assembly failed.
    #[error("desktop_agent_assembly_failed")]
    Assembly,
}

/// Environment-free OpenAI-compatible provider input used by channel routing and Agent sampling.
#[derive(Clone)]
pub struct DesktopOpenAiProviderInput {
    base_url: Url,
    egress_allow_cidrs: Vec<String>,
    egress: CidrAllowlist,
    #[cfg(test)]
    custom_model_dialer: Option<SafeDialer>,
}

impl DesktopOpenAiProviderInput {
    /// Parse one HTTPS base URL and exact numeric CIDR allowlist; no secret fallback is accepted.
    pub fn new(
        base_url: &str,
        egress_allow_cidrs: Vec<String>,
    ) -> Result<Self, DesktopAgentRuntimeError> {
        let mut base_url =
            Url::parse(base_url).map_err(|_| DesktopAgentRuntimeError::Configuration)?;
        if base_url.scheme() != "https"
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(DesktopAgentRuntimeError::Configuration);
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let egress = CidrAllowlist::parse_exact(egress_allow_cidrs.iter().map(String::as_str))
            .map_err(|_| DesktopAgentRuntimeError::Configuration)?;
        Ok(Self {
            base_url,
            egress_allow_cidrs,
            egress,
            #[cfg(test)]
            custom_model_dialer: None,
        })
    }

    pub(crate) fn channel_endpoint(&self) -> Result<Url, DesktopAgentRuntimeError> {
        self.endpoint(CHANNEL_OPENAI_PROTOCOL)
    }

    fn package_endpoint(&self) -> Result<Url, DesktopAgentRuntimeError> {
        self.endpoint(PACKAGE_OPENAI_PROTOCOL)
    }

    fn endpoint(&self, protocol: OpenAiProtocol) -> Result<Url, DesktopAgentRuntimeError> {
        self.base_url
            .join(match protocol {
                OpenAiProtocol::Responses => "responses",
                OpenAiProtocol::ChatCompletions => "chat/completions",
            })
            .map_err(|_| DesktopAgentRuntimeError::Configuration)
    }

    pub(crate) fn egress_allow_cidrs(&self) -> Vec<String> {
        self.egress_allow_cidrs.clone()
    }

    fn dialer(&self) -> SafeDialer {
        SafeDialer::new(EgressPolicy::new(self.egress.clone()))
    }

    #[cfg(test)]
    pub(crate) fn with_test_custom_model_dialer(mut self, dialer: SafeDialer) -> Self {
        self.custom_model_dialer = Some(dialer);
        self
    }

    fn custom_model_dialer(&self) -> SafeDialer {
        #[cfg(test)]
        if let Some(dialer) = &self.custom_model_dialer {
            return dialer.clone();
        }
        self.dialer()
    }

    pub(crate) fn remote_transport(
        &self,
        stall_timeout: Option<Duration>,
    ) -> Result<Arc<SafeRemoteAguiTransport>, DesktopAgentRuntimeError> {
        SafeRemoteAguiTransport::new(
            self.dialer(),
            SafeHttpBudget::new(PROVIDER_RESPONSE_MAX_BYTES, PROVIDER_CONNECT_TIMEOUT)
                .map_err(|_| DesktopAgentRuntimeError::Configuration)?,
            stall_timeout,
            SchemePolicy::HttpsOnly,
        )
        .map(Arc::new)
        .map_err(|_| DesktopAgentRuntimeError::Configuration)
    }
}

impl core::fmt::Debug for DesktopOpenAiProviderInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DesktopOpenAiProviderInput")
            .field("base_url", &"<reviewed-https>")
            .field("egress_allow_cidrs", &self.egress_allow_cidrs.len())
            .finish()
    }
}

/// Explicit first-release Agent budgets; Desktop never reads Server environment variables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopAgentBudgets {
    pub(crate) stall_timeout: Option<Duration>,
    pub(crate) run_deadline: Option<Duration>,
    pub(crate) max_output_tokens: u32,
}

impl DesktopAgentBudgets {
    /// Validate stall/deadline and the same 1..=1,000,000 output-token range as Server.
    pub fn new(
        stall_timeout: Option<Duration>,
        run_deadline: Option<Duration>,
        max_output_tokens: u32,
    ) -> Result<Self, DesktopAgentRuntimeError> {
        if stall_timeout.is_some_and(|duration| duration.is_zero())
            || run_deadline.is_some_and(|duration| duration.is_zero())
            || !(1..=1_000_000).contains(&max_output_tokens)
        {
            return Err(DesktopAgentRuntimeError::Configuration);
        }
        Ok(Self {
            stall_timeout,
            run_deadline,
            max_output_tokens,
        })
    }
}

pub(crate) struct DesktopAgentHostInput {
    pub(crate) pool: DatabasePool,
    pub(crate) model_dataset_binding:
        Arc<openbot_infra::model_dataset::PostgresModelDatasetBinding>,
    pub(crate) listener_database: ThreadListenerDatabase,
    pub(crate) deployment: DeploymentId,
    pub(crate) tenant: TenantId,
    pub(crate) package: LoadedTenantPackage,
    pub(crate) application: Arc<dyn ApplicationService>,
    pub(crate) tool_cancellations: Arc<ToolCancellationRegistry>,
    pub(crate) runtime: Arc<dyn RunRuntime>,
    pub(crate) remote_interrupts: Arc<dyn RemoteInterruptCoordinator>,
    pub(crate) credential_vault: CredentialRecordVault,
    pub(crate) audit_key: Vec<u8>,
    pub(crate) remote_assertions: Arc<RemoteRunAssertionSigner>,
    pub(crate) mcp_catalog: Arc<PostgresMcpCatalog>,
    pub(crate) components: Arc<PostgresComponentAdministration>,
    pub(crate) sandboxed_components: Arc<PostgresSandboxedComponentAdministration>,
    pub(crate) provider: DesktopOpenAiProviderInput,
    pub(crate) remote_transport: Arc<SafeRemoteAguiTransport>,
    pub(crate) budgets: DesktopAgentBudgets,
}

pub(crate) struct DesktopAgentHost {
    relay: RunRelay,
    agent: Option<BuiltInAgentRuntime>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DesktopAgentStopFailure {
    Relay,
    Agent,
}

impl DesktopAgentHost {
    pub(crate) async fn stop(mut self) {
        let _ = self.stop_for_capture().await;
    }

    /// Both original stop futures are polled. The outer capture owner retains this host and
    /// applies its one original clock; no handle is moved into a disposable timeout future.
    pub(crate) async fn stop_for_capture(&mut self) -> Result<(), DesktopAgentStopFailure> {
        let (relay, agent) = tokio::join!(self.relay.stop_for_capture(), async {
            match self.agent.as_mut() {
                Some(agent) => agent.stop_for_capture().await,
                None => Ok(()),
            }
        });
        relay.map_err(|_| DesktopAgentStopFailure::Relay)?;
        agent.map_err(|_| DesktopAgentStopFailure::Agent)
    }
}

pub(crate) fn start_desktop_agent_host(
    input: DesktopAgentHostInput,
) -> Result<DesktopAgentHost, DesktopAgentRuntimeError> {
    let DesktopAgentHostInput {
        pool,
        model_dataset_binding,
        listener_database,
        deployment,
        tenant,
        package,
        application,
        tool_cancellations,
        runtime,
        remote_interrupts,
        credential_vault,
        audit_key,
        remote_assertions,
        mcp_catalog,
        components,
        sandboxed_components,
        provider,
        remote_transport,
        budgets,
    } = input;
    let required = package.package.agents.iter().any(|agent| {
        matches!(
            agent.agent_type,
            TenantAgentType::BuiltIn | TenantAgentType::RemoteAgUi
        )
    });
    let managed = package.package.agents.iter().any(|agent| {
        matches!(
            agent.configuration,
            TenantAgentConfiguration::BuiltIn {
                provider_source: BuiltInProviderSource::Managed,
                ..
            }
        )
    });
    if managed {
        return Err(DesktopAgentRuntimeError::ManagedProviderUnsupported);
    }

    let (consumer, agent): (Arc<dyn RunDispatchConsumer>, Option<BuiltInAgentRuntime>) = if required
    {
        let tools: Arc<dyn AgentToolInvoker> =
            Arc::new(AuthorizedAgentToolGateway::with_sequence_and_cancellations(
                application,
                Arc::new(PostgresAgentAuthorizationSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    true,
                )),
                Arc::new(PostgresAgentToolSequence::new(pool.clone())),
                tool_cancellations,
            ));
        let audit: Arc<dyn AgentAudit> = Arc::new(
            PostgresAgentAudit::new(pool.clone(), audit_key)
                .map_err(|_| DesktopAgentRuntimeError::Assembly)?,
        );
        let credentials = Arc::new(
            PostgresOpenAiCredentialSource::new(
                pool.clone(),
                credential_vault.clone(),
                package.package.model.credential_secret_ref.clone(),
                None,
            )
            .map_err(|_| DesktopAgentRuntimeError::Assembly)?,
        );
        let package_provider: Arc<dyn ProviderAdapter> =
            Arc::new(OpenAiProvider::new_with_credential_source(
                OpenAiProviderConfig::new_with_transport_policy(
                    provider.package_endpoint()?,
                    package.package.model.default_model.clone(),
                    PACKAGE_OPENAI_PROTOCOL,
                    SafeHttpBudget::new(PROVIDER_RESPONSE_MAX_BYTES, PROVIDER_CONNECT_TIMEOUT)
                        .map_err(|_| DesktopAgentRuntimeError::Configuration)?,
                    budgets.stall_timeout,
                    SchemePolicy::HttpsOnly,
                )
                .map_err(|_| DesktopAgentRuntimeError::Assembly)?,
                credentials,
                provider.dialer(),
            ));
        let remote_provider: Arc<dyn ProviderAdapter> =
            Arc::new(RemoteAguiProvider::new(remote_transport));
        // The same retry wrapper re-enters this factory for every sampling and retry attempt.
        // Personal keys/configuration are resolved there from current PG authority, never from
        // the package provider's environment or a cached adapter.
        let custom_provider: Arc<dyn ProviderAdapter> = Arc::new(
            PostgresCustomModelProvider::new(
                pool.clone(),
                credential_vault.clone(),
                deployment.clone(),
                tenant.clone(),
                provider.custom_model_dialer(),
                SafeHttpBudget::new(PROVIDER_RESPONSE_MAX_BYTES, PROVIDER_CONNECT_TIMEOUT)
                    .map_err(|_| DesktopAgentRuntimeError::Configuration)?,
                budgets.stall_timeout,
            )
            .map_err(|_| DesktopAgentRuntimeError::Assembly)?
            .with_model_dataset_binding(Arc::clone(&model_dataset_binding))
            .map_err(|_| DesktopAgentRuntimeError::Assembly)?,
        );
        let provider = Arc::new(
            RetryingProvider::new(
                Arc::new(
                    ProviderRouter::new(package_provider, None)
                        .with_remote_agui(remote_provider)
                        .with_custom(custom_provider),
                ),
                RetryingProviderConfig::default(),
            )
            .map_err(|_| DesktopAgentRuntimeError::Assembly)?,
        );
        let context = Arc::new(
            PostgresAgentContextSource::new(
                pool,
                deployment,
                tenant,
                Some(budgets.max_output_tokens),
            )
            .map_err(|_| DesktopAgentRuntimeError::Assembly)?
            .with_model_dataset_binding(model_dataset_binding)
            .map_err(|_| DesktopAgentRuntimeError::Assembly)?
            .with_rate_cards(package.package.model.rate_card.clone(), None)
            .with_tools(vec![remember_provider_tool()])
            .with_remote_assertions(remote_assertions)
            .with_mcp_catalog(mcp_catalog)
            .with_components(components)
            .with_sandboxed_components(sandboxed_components)
            .with_agent_credential_vault(credential_vault),
        );
        let agent = BuiltInAgentRuntime::start_with_remote_interrupts(
            Arc::clone(&runtime),
            context,
            provider,
            tools,
            audit,
            remote_interrupts,
            BuiltInAgentConfig {
                run_deadline: budgets.run_deadline,
                ..BuiltInAgentConfig::default()
            },
        )
        .map_err(|_| DesktopAgentRuntimeError::Assembly)?;
        (agent.consumer(), Some(agent))
    } else {
        (Arc::new(NoRunDispatchConsumer), None)
    };
    let relay =
        RunRelay::start_with_database(runtime, consumer, listener_database.for_run_control());
    Ok(DesktopAgentHost { relay, agent })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_and_budget_inputs_are_https_only_and_bounded() {
        assert!(DesktopOpenAiProviderInput::new("https://api.example.test/v1", vec![]).is_ok());
        assert!(DesktopOpenAiProviderInput::new("http://127.0.0.1/v1", vec![]).is_err());
        assert!(
            DesktopOpenAiProviderInput::new("https://api.example.test/v1?secret=x", vec![],)
                .is_err()
        );
        assert!(
            DesktopOpenAiProviderInput::new(
                "https://api.example.test/v1",
                vec!["not-a-cidr".to_owned()],
            )
            .is_err()
        );
        assert!(
            DesktopAgentBudgets::new(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(1_800)),
                16_384,
            )
            .is_ok()
        );
        assert!(DesktopAgentBudgets::new(None, None, 0).is_err());
        assert!(DesktopAgentBudgets::new(None, None, 1_000_001).is_err());
    }
}
