//! Wrok Bot Server 生产二进制组装入口。

use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use openbot_agent::{
    AgentToolInvoker, AuthorizedAgentToolGateway, BuiltInAgentConfig, BuiltInAgentRuntime,
    ProviderRouter, RemoteAgentToolInvoker, RemoteAguiProvider, RetryingProvider,
    RetryingProviderConfig,
};
use openbot_application::tenant::package::{
    BuiltInProviderSource, TenantAgentConfiguration, TenantAgentType, TenantPackageAudienceContext,
    TenantPackageEnvironment, synchronize_tenant_package,
};
use openbot_application::{
    AgentAudit, NoRunDispatchConsumer, ProviderAdapter, ProviderRateCard,
    RemoteInterruptCoordinator, RunDispatchConsumer, RunRuntime, remember_provider_tool,
};
use openbot_computer::screen::{
    DEFAULT_SCREEN_VIEWERS_PER_STREAM, ScreenHub, ScreenSessionService,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::identity::groups::IdentityProviderId;
use openbot_domain::identity::session::TrustedOrigins;
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{
    ApplicationKeyPurpose, KeyVersion, SecretBytes, WrappingKey, derive_application_key,
};
use openbot_infra::agent_audit::PostgresAgentAudit;
use openbot_infra::agent_tools::{PostgresAgentAuthorizationSource, PostgresAgentToolSequence};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssemblyInput, assemble_postgres_application,
};
use openbot_infra::auth::config::{
    AuthConfig, BindingExposure, ExampleKeyPolicy, KeyEncryptionKey, SingleUserAdmission,
    auth_config_with_dynamic_provider, default_session_lifetime, single_user_binding_verdict,
    single_user_enabled,
};
use openbot_infra::auth::oidc::coordinator::{DEFAULT_IDP_TIMEOUT, DEFAULT_METADATA_MAX_BYTES};
use openbot_infra::auth::oidc::{
    FetchBudget, OidcLoginCoordinator, OidcProviderRuntime, PostgresLoginAttemptStore,
    PostgresOidcRateLimiter, PostgresOidcSessionIssuer, PreAuthSurface, ProviderRegistry,
    configured_oidc_providers,
};
use openbot_infra::auth::single_user::{initialize_single_user, load_single_user_principal};
use openbot_infra::auth::sso::DynamicSsoService;
use openbot_infra::component_catalogue::PostgresComponentAdministration;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{native, pool};
use openbot_infra::mcp_catalog::PostgresMcpCatalog;
use openbot_infra::net::safe_http::{
    CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy,
};
use openbot_infra::policy::{PolicyListener, PolicyStore};
use openbot_infra::provider::anthropic::{
    AnthropicApiKey, AnthropicProvider, AnthropicProviderConfig,
};
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::provider::credential::PostgresOpenAiCredentialSource;
use openbot_infra::provider::custom::PostgresCustomModelProvider;
use openbot_infra::provider::google::{GoogleApiKey, GoogleProvider, GoogleProviderConfig};
use openbot_infra::provider::openai::{
    OpenAiApiKey, OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig,
};
use openbot_infra::remote_agui::SafeRemoteAguiTransport;
use openbot_infra::run_runtime::RunRelay;
use openbot_infra::sandboxed_components::PostgresSandboxedComponentAdministration;
use openbot_infra::tenant::{PostgresTenantPackageSynchronizer, load_tenant_package};
use openbot_infra::ui_preferences::PostgresUiPreferenceAdministration;
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::config::{
    AgentBudgets, DEFAULT_TENANT_PACKAGE_DIR, DeploymentEnvironment, ManagedProviderConfig,
    ManagedProviderKind, PackageOpenAiProviderConfig, ServerConfig, env_map_from_process,
};
use openbot_server::readiness::ReadinessVerdict;
use openbot_server::telemetry::{self, LogFormat};
use openbot_server::{
    AuthResolver, FnReadinessProbe, PostgresSessionAuthResolver, SINGLE_USER_ACTOR_ID,
    SensitiveWriteSecurity, ServerBuilder, SingleUserAuthResolver, StaticApp, install_recorder,
};
use url::Url;

const PACKAGE_OPENAI_PROTOCOL: OpenAiProtocol = OpenAiProtocol::Responses;
const CHANNEL_ROUTING_OPENAI_PROTOCOL: OpenAiProtocol = OpenAiProtocol::ChatCompletions;
type OidcLoginAssembly = (
    Arc<OidcLoginCoordinator>,
    Arc<DynamicSsoService>,
    PreAuthSurface,
    TrustedOrigins,
    bool,
);
type AuthAssembly = (
    Arc<dyn AuthResolver>,
    SensitiveWriteSecurity,
    Option<openbot_domain::identity::roles::AdminFloor>,
    Option<OidcLoginAssembly>,
);
type AgentAssembly = (Arc<dyn RunDispatchConsumer>, Option<BuiltInAgentRuntime>);

struct BuiltInAgentAssemblyInput {
    pool: openbot_infra::db::pool::DatabasePool,
    model_dataset_binding: Arc<openbot_infra::model_dataset::PostgresModelDatasetBinding>,
    #[cfg(test)]
    custom_model_dialer: Option<SafeDialer>,
    deployment: DeploymentId,
    tenant: TenantId,
    runtime: Arc<dyn RunRuntime>,
    required: bool,
    requires_managed: bool,
    model: String,
    package_rate_card: Option<ProviderRateCard>,
    credential_key_id: String,
    provider: PackageOpenAiProviderConfig,
    managed_provider: Option<ManagedProviderConfig>,
    credential_vault: CredentialRecordVault,
    tools: Arc<dyn AgentToolInvoker>,
    audit: Arc<dyn AgentAudit>,
    remote_interrupts: Arc<dyn RemoteInterruptCoordinator>,
    remote_assertions: Arc<RemoteRunAssertionSigner>,
    mcp_catalog: Arc<PostgresMcpCatalog>,
    components: Arc<PostgresComponentAdministration>,
    sandboxed_components: Arc<PostgresSandboxedComponentAdministration>,
    budgets: AgentBudgets,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let local = match arguments.as_slice() {
        [] => false,
        [flag] if flag == "--local" => true,
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "Wrok Bot Server\nUsage: wrok-bot-server [--local | --help | --version]\n\n--local selects the first-party local workspace and loopback single-user mode.\nSet WROK_BOT_DATABASE_URL and WROK_BOT_KEY_ENCRYPTION_KEY before starting.\nSet WROK_BOT_APP_DIST_DIR to serve the compiled workbench.\nModel credentials can be added through /admin/credentials after startup.\nExisting deployments may keep their original configuration variable names."
            );
            return Ok(());
        }
        [flag] if flag == "--version" => {
            println!("Wrok Bot Server {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => return Err(startup_error("wrok_bot_arguments_invalid").into()),
    };
    telemetry::init(LogFormat::Json)?;
    let env = openbot_server::config::launch::prepare_environment(env_map_from_process(), local)?;
    let mut server = ServerConfig::from_env_map(&env)?;
    if let Some(warning) = server.public_transport().startup_warning() {
        tracing::warn!(code = server.public_transport().as_str(), "{warning}");
    }
    let package_environment =
        TenantPackageEnvironment::from_allowlist(&env, &["MANAGED_AGENT_AG_UI_URL"]);
    let package_directory = tenant_package_directory_for_startup(&server.tenant_package_directory);
    let tenant_package = load_tenant_package(&package_directory, &package_environment)?;
    let requires_agent_runtime = tenant_package.package.agents.iter().any(|agent| {
        matches!(
            agent.agent_type,
            TenantAgentType::BuiltIn | TenantAgentType::RemoteAgUi
        )
    });
    let requires_managed_agent = tenant_package.package.agents.iter().any(|agent| {
        matches!(
            &agent.configuration,
            TenantAgentConfiguration::BuiltIn {
                provider_source: BuiltInProviderSource::Managed,
                ..
            }
        )
    });

    let database_url = openbot_server::config::env::optional(&env, "DATABASE_URL")
        .ok_or_else(|| startup_error("database_url_missing"))?;
    let database: DatabaseConfig = database_url.parse()?;
    let key_policy = match server.deployment_environment {
        DeploymentEnvironment::Production => ExampleKeyPolicy::Reject,
        DeploymentEnvironment::Development => ExampleKeyPolicy::Allow,
    };
    // Apply the original canonical / strength / example policy once and retain
    // that same original wrapping key. The existing Infra production base64
    // dependency decodes this exact canonical encoding after the publication
    // gate; Server has no new production dependency or raw material accessor.
    let key_encryption = KeyEncryptionKey::from_env_map(&env, key_policy)?;
    let recovery_master_encoding = SecretBytes::new(
        openbot_server::config::env::optional(&env, "KEY_ENCRYPTION_KEY")
            .ok_or_else(|| startup_error("key_encryption_key_missing"))?.as_bytes().to_vec(),
    );
    let deployment = deployment_id_for_startup(server.deployment_id.as_deref(), &tenant_package.package.tenant_id);
    let tenant = TenantId::new(&tenant_package.package.tenant_id);
    let host = server.recovery_host.take().ok_or_else(|| startup_error("recovery_host_missing"))?;
    let limits = host.host_limits().clone();
    let startup_deadline = std::time::Instant::now().checked_add(Duration::from_nanos(limits.admission_ns))
        .ok_or_else(|| startup_error("recovery_startup_bounds_invalid"))?;
    let mut recovery_control = openbot_infra::recovery_control::RecoveryControl::open(
        openbot_infra::recovery_control::RecoveryControlConfig::server(host, limits)?,
    )?;
    let (pool, mut recovery_runtime_owner) = recovery_control.open_existing_server_before(
        &database, recovery_master_encoding, deployment.as_str(), tenant.as_str(), startup_deadline,
    ).await?;
    let recovery_read_gate = recovery_runtime_owner.read_gate();

    let policy_store = PolicyStore::postgres(
        pool.clone(),
        server
            .computer
            .as_ref()
            .and_then(|computer| computer.action_policy.clone()),
    );
    let policy_origin = policy_store.load().await?;
    let compiled_policy = policy_store.compiled();
    tracing::info!(
        origin = ?policy_origin,
        mode = %compiled_policy.mode(),
        version = %compiled_policy.version(),
        configured = compiled_policy.is_configured(),
        "action policy 已从权威来源加载"
    );
    let policy_listener = PolicyListener::start(
        database
            .clone()
            .with_application_name("openbot-action-policy-listener"),
        Arc::new(policy_store.clone()),
    )
    .await?;

    if let Some(code) = key_encryption.advisory_code() {
        tracing::warn!(code, "KEY_ENCRYPTION_KEY 建议轮换到 AES-256");
    }
    let raw_master = openbot_server::config::env::optional(&env, "KEY_ENCRYPTION_KEY")
        .ok_or_else(|| startup_error("key_encryption_key_missing"))?;
    let application_master = SecretBytes::new(raw_master.as_bytes().to_vec());
    let audit_key =
        derive_application_key(&application_master, ApplicationKeyPurpose::AuditCheckpoint)?;
    let mcp_state_parent =
        derive_application_key(&application_master, ApplicationKeyPurpose::McpOauthState)?;
    drop(application_master);
    let has_dynamic_provider = database_has_dynamic_provider(&pool).await?;
    let public_url = server.public_url.as_ref().map(|url| url.as_str());
    let auth_config = auth_config_with_dynamic_provider(
        &env,
        public_url,
        default_session_lifetime(),
        has_dynamic_provider,
    )?;
    let server_authorization_keys = recovery_runtime_owner.derive_server_authorization_keys_before(
        &pool, deployment.as_str(), tenant.as_str(),
        auth_config.as_ref().map(|config| config.session_secret.expose().as_bytes()),
        &mcp_state_parent, raw_master.as_bytes(), startup_deadline,
    )?;
    // Only these five short-lived purposes use the same external epoch.
    // Audit, wrapping/master, stored ciphertext and SCRAM parents stay original.
    drop(mcp_state_parent);
    let remote_assertions = Arc::new(RemoteRunAssertionSigner::new(
        server_authorization_keys.run_assertion_key().to_vec(),
    )?);
    let has_provider = auth_config.is_some();
    let single_user = single_user_enabled(&env, has_provider)?;
    // An existing database can contain dynamic SSO even when the process environment does not.
    // Explicit local mode must never select the multi-user 0.0.0.0 listener in that case.
    if local && !single_user {
        return Err(openbot_server::config::launch::LaunchError::LocalModeConflict.into());
    }
    let environment_provider_ids = auth_config
        .as_ref()
        .map(|config| {
            config
                .configured_providers()
                .into_iter()
                .map(|provider| IdentityProviderId::new(provider.as_str()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let model_credential_vault = CredentialRecordVault::single_key(
        tenant.clone(),
        KeyVersion::new(1),
        KeyEncryptionKey::from_env_map(&env, key_policy)?.into_wrapping_key(),
    );
    let remote_agent_probe = build_remote_agent_transport(
        &server.package_openai_provider.egress_allow_cidrs,
        server.package_openai_provider.allow_http,
        server.agent_budgets,
    )?;
    initialize_single_user(&pool, single_user).await?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let mut artifact_session_resolver: Option<PostgresSessionAuthResolver> = None;
    let mut remember_session_resolver: Option<PostgresSessionAuthResolver> = None;
    let mut remember_single_user_resolver: Option<SingleUserAuthResolver> = None;
    let (auth, sensitive, floor, oidc_login): AuthAssembly = if let Some(config) = auth_config {
        let oidc = build_oidc_login(
            &config,
            &pool,
            &tenant,
            server_authorization_keys.session_key()?,
            server_authorization_keys.oidc_state_key()?,
            server_authorization_keys.sso_state_key()?,
            audit_key.expose(),
            key_encryption.into_wrapping_key(),
            server.public_transport().cookie_secure(),
        )
        .await?;
        let resolver = PostgresSessionAuthResolver::new(
            pool.clone(),
            server_authorization_keys.session_key()?,
            config.session_lifetime,
            deployment.clone(),
            tenant.clone(),
        )?;
        resolver.install_recovery_read_gate(recovery_read_gate.clone())
            .map_err(|_| startup_error("recovery_host_gate_unavailable"))?;
        let sensitive =
            SensitiveWriteSecurity::new(config.session_lifetime, config.trusted_origins.clone());
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            artifact_session_resolver = Some(resolver.clone());
        }
        remember_session_resolver = Some(resolver.clone());
        (
            Arc::new(resolver),
            sensitive,
            Some(config.admin_floor),
            Some(oidc),
        )
    } else {
        if !single_user
            || single_user_binding_verdict(BindingExposure::Loopback) != SingleUserAdmission::Admit
        {
            return Err(startup_error("single_user_binding_refused").into());
        }
        let lifetime = default_session_lifetime();
        let origins = configured_origins(&env)?;
        let principal =
            load_single_user_principal(&pool, deployment.clone(), tenant.clone()).await?;
        let resolver = SingleUserAuthResolver::from_verified_principal(principal, lifetime);
        resolver.install_recovery_read_gate(&pool, recovery_read_gate.clone())
            .map_err(|_| startup_error("recovery_host_gate_unavailable"))?;
        remember_single_user_resolver = Some(resolver.clone());
        (
            Arc::new(resolver),
            SensitiveWriteSecurity::new(lifetime, origins),
            None,
            None,
        )
    };

    // The original optional startup label never comes from a request or a second environment read.
    // The composition root strongly retains this one runtime and journal; request owners retain Weak.
    let gateway_authorization_journal =
        openbot_server::auth::assemble_gateway_authorization_journal(
            &server,
            pool.clone(),
            deployment.clone(),
            tenant.clone(),
            SecretBytes::new(audit_key.expose().to_vec()),
        )
        .map_err(|_| startup_error("gateway_authorization_journal_unavailable"))?;
    if let Some((_, journal)) = &gateway_authorization_journal {
        if let Some(resolver) = &remember_session_resolver {
            resolver
                .install_gateway_authorization_journal(journal)
                .map_err(|_| startup_error("gateway_authorization_host_unavailable"))?;
        } else if let Some(resolver) = &remember_single_user_resolver {
            resolver
                .install_gateway_authorization_journal(journal, &pool)
                .map_err(|_| startup_error("gateway_authorization_host_unavailable"))?;
        } else {
            return Err(startup_error("gateway_authorization_host_unavailable").into());
        }
    }

    // This is the exact supervised application Pool, not a second connection pool
    // assembled from matching labels. Construction validates configuration only;
    // every repository operation proves current storage and authorization itself.
    let remember_preference_repository = Arc::new(
        openbot_infra::approval_preferences::PostgresRememberPreferenceRepository::new(
            pool.clone(),
            deployment.clone(),
            tenant.clone(),
            SecretBytes::new(audit_key.expose().to_vec()),
        )
        .map_err(|_| startup_error("approval_preference_repository_unavailable"))?,
    );
    if let Some(resolver) = &remember_session_resolver {
        resolver
            .install_remember_preference_repository(&remember_preference_repository)
            .map_err(|_| startup_error("approval_preference_host_unavailable"))?;
    } else if let Some(resolver) = &remember_single_user_resolver {
        resolver
            .install_remember_preference_repository(&remember_preference_repository)
            .map_err(|_| startup_error("approval_preference_host_unavailable"))?;
    } else {
        return Err(startup_error("approval_preference_host_unavailable").into());
    }
    // Guards retain only Weak attachments; the composition root retains the actual
    // repository for the complete server runtime lifetime.
    let _remember_preference_repository = remember_preference_repository;

    let audience_context = if single_user {
        TenantPackageAudienceContext::single_user(ActorId::new(SINGLE_USER_ACTOR_ID))?
    } else {
        let mut providers = environment_provider_ids;
        let mut mappings = Vec::new();
        if let Some((_, dynamic_sso, _, _, _)) = &oidc_login {
            let (dynamic_providers, dynamic_mappings) = dynamic_sso.group_audience_inputs().await?;
            providers.extend(dynamic_providers);
            mappings.extend(dynamic_mappings);
        }
        TenantPackageAudienceContext::multi_user(providers, mappings)?
    };
    let package_report = synchronize_tenant_package(
        &PostgresTenantPackageSynchronizer::new(pool.clone()),
        &tenant_package,
        &audience_context,
    )
    .await?;
    tracing::info!(
        tenant = %package_report.tenant_id,
        agents = package_report.agents,
        channels = package_report.channels,
        memberships_granted = package_report.memberships_granted,
        memberships_revoked = package_report.memberships_revoked,
        generations_advanced = package_report.generations_advanced,
        single_user_groups_ignored = package_report.single_user_groups_ignored,
        knowledge_sources_compatibility_only = package_report.knowledge_sources_compatibility_only,
        runtime_theme_ignored = package_report.runtime_theme_ignored,
        "tenant package 已经由 Application use case 同步"
    );

    // Adopt only during trusted startup after database/package verification.
    let artifact_datasets = Arc::new(
        openbot_infra::artifact_registry::ArtifactDatasetRegistry::from_server(
            pool.clone(),
            &deployment,
            &tenant,
        )
        .await?,
    );
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let mut artifact_read_lifecycle = None;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let artifacts: Option<Arc<dyn openbot_application::artifacts::ArtifactAdministration>> =
        if let Some(root_path) = server.artifact_root.clone() {
            let root = tokio::task::spawn_blocking(move || {
                openbot_infra::artifact_store::open_trusted_host_root(&root_path)
            })
            .await
            .map_err(|_| startup_error("artifact_root_unavailable"))??;
            let policy = openbot_domain::artifact::ArtifactQuotaPolicy::default();
            let store = Arc::new(
                openbot_infra::artifact_store::DatasetBoundArtifactStore::bind_host_root(
                    root,
                    Arc::clone(&artifact_datasets),
                    policy,
                )
                .await?,
            );
            let administration = Arc::new(
                openbot_infra::artifact_administration::PostgresArtifactAdministration::new(
                    Arc::clone(&artifact_datasets),
                    store,
                    policy,
                    SecretBytes::new(audit_key.expose().to_vec()),
                )
                .map_err(|_| startup_error("artifact_administration_unavailable"))?,
            );
            if let Some(resolver) = &artifact_session_resolver {
                resolver
                    .install_artifact_read_authority(&administration.read_authority())
                    .map_err(|_| startup_error("artifact_read_authority_unavailable"))?;
            }
            if let Some(resolver) = &remember_single_user_resolver {
                resolver
                    .install_artifact_read_authority(&administration.read_authority())
                    .map_err(|_| startup_error("artifact_read_authority_unavailable"))?;
            }
            artifact_read_lifecycle = Some(administration.read_authority().read_lifecycle());
            Some(administration)
        } else {
            None
        };

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let artifacts: Option<Arc<dyn openbot_application::artifacts::ArtifactAdministration>> = None;

    let PackageOpenAiProviderConfig {
        base_url: channel_base_url,
        environment_api_key: channel_environment_api_key,
        egress_allow_cidrs: channel_egress_allow_cidrs,
        allow_http: channel_allow_http,
    } = server.package_openai_provider.clone();
    let channel_endpoint =
        openai_endpoint(channel_base_url.as_str(), CHANNEL_ROUTING_OPENAI_PROTOCOL)?;
    let oauth_public_url = server
        .public_url
        .as_ref()
        .filter(|url| Url::parse(url.as_str()).is_ok_and(|parsed| parsed.scheme() == "https"));
    if server.public_url.is_some() && oauth_public_url.is_none() {
        tracing::warn!(
            code = "mcp_oauth_https_callback_required",
            "MCP OAuth Server callback 要求 HTTPS public URL；connect 保持不可用"
        );
    }
    let screen_hub = ScreenHub::new(DEFAULT_SCREEN_VIEWERS_PER_STREAM)?;
    let screen_sessions = Arc::new(ScreenSessionService::new(screen_hub.clone()));
    let application_assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
        pool: pool.clone(),
        listener_database: database.clone().into(),
        deployment: deployment.clone(),
        tenant: tenant.clone(),
        single_user,
        admin_floor: floor,
        model: tenant_package.package.model.default_model.clone(),
        credential_key_id: tenant_package.package.model.credential_secret_ref.clone(),
        credential_vault: model_credential_vault.clone(),
        audit_key: SecretBytes::new(audit_key.expose().to_vec()),
        remote_assertions: remote_assertions.clone(),
        mcp_oauth_state_key: SecretBytes::new(server_authorization_keys.mcp_state_key().to_vec()),
        policy_store: policy_store.clone(),
        ui_preferences: Arc::new(PostgresUiPreferenceAdministration::new(
            pool.clone(),
            deployment.clone(),
            tenant.clone(),
            SecretBytes::new(audit_key.expose().to_vec()),
        )?),
        screen_sessions,
        artifacts,
        runtime_capabilities: Some(
            auth.runtime_capability_factory(
                oidc_login
                    .as_ref()
                    .map(|(_, sso, _, _, _)| sso.capability_source()),
            )
            .map_err(|_| startup_error("runtime_capabilities"))?,
        ),
        remote_agent_probe,
        managed_slot_available: managed_provider_for_slot(&server).is_some(),
        channel_routing_provider: ChannelRoutingProviderInput {
            endpoint: channel_endpoint,
            environment_api_key: channel_environment_api_key
                .map(|key| SecretBytes::new(key.expose().as_bytes().to_vec())),
            egress_allow_cidrs: channel_egress_allow_cidrs,
            allow_http: channel_allow_http,
        },
        stall_timeout: server.agent_budgets.stall_timeout,
        oauth_public_url: oauth_public_url.map(|url| url.as_str().to_owned()),
        app_url: server.app_url.clone(),
    })
    .await?;
    if application_assembly
        .model_dataset_binding
        .enroll_original_registry(&artifact_datasets)
        .is_err()
    {
        auth.close_request_bindings();
        let _ = application_assembly
            .application
            .close_public_artifact_reads();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(reads) = &artifact_read_lifecycle {
            reads.close();
            let _ack = reads.drain().await;
        }
        application_assembly.shutdown().await;
        policy_listener.stop().await;
        pool.close();
        return Err(startup_error("model_dataset_binding").into());
    }
    let thread_history_enrollment = application_assembly
        .thread_history_authority
        .enroll_original_registry(&artifact_datasets)
        .and_then(|()| {
            if let Some(resolver) = &remember_session_resolver {
                resolver.install_thread_history_authority(
                    &application_assembly.thread_history_authority,
                )
            } else if let Some(resolver) = &remember_single_user_resolver {
                resolver.install_thread_history_authority(
                    &application_assembly.thread_history_authority,
                    &pool,
                )
            } else {
                Err(openbot_contracts::HostRequestBindingError::Unavailable)
            }
        });
    if thread_history_enrollment.is_err() {
        auth.close_request_bindings();
        let _ = application_assembly
            .application
            .close_public_artifact_reads();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(reads) = &artifact_read_lifecycle {
            reads.close();
            let _ack = reads.drain().await;
        }
        application_assembly.shutdown().await;
        policy_listener.stop().await;
        pool.close();
        return Err(startup_error("thread_history").into());
    }
    if let Some(resolver) = &remember_session_resolver {
        resolver
            .install_custom_model_catalog_inventory(
                &application_assembly.custom_model_catalog_inventory,
            )
            .map_err(|_| startup_error("custom_model_catalog"))?;
    } else if let Some(resolver) = &remember_single_user_resolver {
        resolver
            .install_custom_model_catalog_inventory(
                &application_assembly.custom_model_catalog_inventory,
                &pool,
            )
            .map_err(|_| startup_error("custom_model_catalog"))?;
    } else {
        return Err(startup_error("custom_model_catalog").into());
    }
    let application = application_assembly.application.clone();
    let runtime_capability_facts = application_assembly.runtime_capability_facts.clone();
    let run_runtime = application_assembly.run_runtime.clone();
    let mcp_catalog = application_assembly.mcp_catalog.clone();
    let components = application_assembly.components.clone();
    let sandboxed_components = application_assembly.sandboxed_components.clone();
    let mcp_connections = application_assembly.mcp_connections.clone();
    let remote_callback_auth = application_assembly.remote_callback_auth.clone();
    let remote_interrupts = application_assembly.remote_interrupts.clone();
    let tool_cancellations = application_assembly.tool_cancellations.clone();
    let mcp_revocation_reconciler = application_assembly.mcp_revocation_reconciler;
    let governed_tools = Arc::new(AuthorizedAgentToolGateway::with_sequence_and_cancellations(
        application.clone(),
        Arc::new(PostgresAgentAuthorizationSource::new(
            pool.clone(),
            deployment.clone(),
            tenant.clone(),
            single_user,
        )),
        Arc::new(PostgresAgentToolSequence::new(pool.clone())),
        tool_cancellations,
    ));
    let agent_tools: Arc<dyn AgentToolInvoker> = governed_tools.clone();
    let remote_callback_tools: Arc<dyn RemoteAgentToolInvoker> = governed_tools;
    let managed_provider = managed_provider_for_slot(&server);
    let agent_audit: Arc<dyn AgentAudit> = Arc::new(PostgresAgentAudit::new(
        pool.clone(),
        audit_key.expose().to_vec(),
    )?);
    let (run_consumer, built_in_agent) = build_built_in_agent(BuiltInAgentAssemblyInput {
        pool: pool.clone(),
        model_dataset_binding: Arc::clone(&application_assembly.model_dataset_binding),
        #[cfg(test)]
        custom_model_dialer: None,
        deployment: deployment.clone(),
        tenant: tenant.clone(),
        runtime: run_runtime.clone(),
        required: requires_agent_runtime,
        requires_managed: requires_managed_agent,
        model: tenant_package.package.model.default_model.clone(),
        package_rate_card: tenant_package.package.model.rate_card.clone(),
        credential_key_id: tenant_package.package.model.credential_secret_ref.clone(),
        provider: server.package_openai_provider.clone(),
        managed_provider,
        credential_vault: model_credential_vault,
        tools: agent_tools,
        audit: agent_audit,
        remote_interrupts,
        remote_assertions: remote_assertions.clone(),
        mcp_catalog,
        components,
        sandboxed_components,
        budgets: server.agent_budgets,
    })?;
    let built_in_agent_ready = built_in_agent.is_some() || !requires_agent_runtime;
    let run_relay = RunRelay::start_with_database(
        run_runtime,
        run_consumer,
        database
            .clone()
            .with_application_name("openbot-run-control"),
    );
    let metrics = install_recorder()?;
    let db_probe_pool = pool.clone();
    let db_probe = FnReadinessProbe::new("database_native_schema", move || {
        let pool = db_probe_pool.clone();
        async move {
            let Ok(client) = pool.get().await else {
                return ReadinessVerdict::NotReady;
            };
            match client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM openbot_internal.schema_migrations \
                     WHERE version=$1)",
                    &[&native::NATIVE_LATEST_VERSION],
                )
                .await
                .and_then(|row| row.try_get::<_, bool>(0))
            {
                Ok(true) => ReadinessVerdict::Ready,
                Ok(false) | Err(_) => ReadinessVerdict::NotReady,
            }
        }
    });
    // Retain the actual resolver owner for lifecycle closure, not in a request guard.
    let auth_owner = Arc::clone(&auth);
    let artifact_read_application = Arc::clone(&application);
    let mut builder = ServerBuilder::new(application, auth)
        .with_transport_policy(server.transport_policy(single_user))
        .with_sensitive_write_security(sensitive)
        .with_metrics_handle(metrics)
        .with_insecure_transport(server.public_transport().insecure_transport())
        .with_remote_callback_authenticator(remote_callback_auth)
        .with_remote_callback_tools(remote_callback_tools)
        .with_screen_hub(screen_hub)
        .with_readiness_probe(Arc::new(db_probe));
    if let Some(dist) = server.app_dist_dir.as_deref() {
        builder = builder.with_static_app(StaticApp::open(dist)?);
    }
    builder = builder.with_mcp_oauth_callback(mcp_connections);
    if let Some((coordinator, dynamic_sso, preauth, origins, secure_cookie)) = oidc_login {
        builder = builder.with_login_security(origins, secure_cookie);
        builder = builder.with_oidc_login(coordinator, preauth);
        builder = builder.with_dynamic_sso(dynamic_sso);
    }
    if !single_user {
        builder = builder.with_readiness_probe(Arc::new(FnReadinessProbe::new(
            "computer_isolation",
            || async { ReadinessVerdict::NotReady },
        )));
    }
    if !built_in_agent_ready {
        builder = builder.with_readiness_probe(Arc::new(FnReadinessProbe::new(
            "built_in_agent_provider",
            || async { ReadinessVerdict::NotReady },
        )));
    }

    // R394 supports only a same-machine TLS proxy or the local single-user exception.
    // A public URL and forwarded headers never authorize a public plaintext backend listener.
    let address = format!("127.0.0.1:{}", server.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!(bind = %address, single_user, "Wrok Bot Server 已启动");
    let serve_result = axum::serve(
        listener,
        builder
            .into_router()
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown({
        let shutdown_auth = Arc::clone(&auth_owner);
        let shutdown_gateway_authorization_runtime = gateway_authorization_journal
            .as_ref()
            .map(|(runtime, _)| Arc::clone(runtime));
        let shutdown_application = Arc::clone(&artifact_read_application);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let shutdown_artifact_reads = artifact_read_lifecycle.clone();
        async move {
            shutdown_signal().await;
            // Revoke current observations before axum waits for in-flight requests to drain.
            shutdown_auth.close_request_bindings();
            if let Some(runtime) = &shutdown_gateway_authorization_runtime {
                runtime.close();
            }
            if let Err(error) = shutdown_application.close_public_artifact_reads() {
                tracing::warn!(
                    error.code = error.code().as_str(),
                    "public artifact read closure unavailable"
                );
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if let Some(reads) = shutdown_artifact_reads {
                reads.close();
            }
        }
    })
    .await;
    // A serving error or normal completion also closes the owner before other resources stop.
    auth_owner.close_request_bindings();
    if let Some((runtime, _)) = &gateway_authorization_journal {
        runtime.close();
    }
    if let Err(error) = artifact_read_application.close_public_artifact_reads() {
        tracing::warn!(
            error.code = error.code().as_str(),
            "public artifact read closure unavailable"
        );
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(reads) = &artifact_read_lifecycle {
        reads.close();
        let _ack = reads.drain().await;
    }
    if let Some(facts) = &runtime_capability_facts {
        facts.close();
        facts.drain().await;
    }
    run_relay.stop().await;
    if let Some(agent) = built_in_agent {
        agent.stop().await;
    }
    mcp_revocation_reconciler.stop().await;
    policy_listener.stop().await;
    drop(artifact_datasets);
    drop(gateway_authorization_journal);
    serve_result?;
    pool.close();
    Ok(())
}

fn build_built_in_agent(input: BuiltInAgentAssemblyInput) -> Result<AgentAssembly, Box<dyn Error>> {
    let BuiltInAgentAssemblyInput {
        pool,
        model_dataset_binding,
        #[cfg(test)]
        custom_model_dialer,
        deployment,
        tenant,
        runtime,
        required,
        requires_managed,
        model,
        package_rate_card,
        credential_key_id,
        provider,
        managed_provider,
        credential_vault,
        tools,
        audit,
        remote_interrupts,
        remote_assertions,
        mcp_catalog,
        components,
        sandboxed_components,
        budgets,
    } = input;
    if !required {
        return Ok((Arc::new(NoRunDispatchConsumer), None));
    }
    let PackageOpenAiProviderConfig {
        base_url,
        environment_api_key,
        egress_allow_cidrs,
        allow_http,
    } = provider;
    // Fixed upstream @ai-sdk/openai 3.0.99 `createLanguageModel` delegates to Responses.
    let protocol = PACKAGE_OPENAI_PROTOCOL;
    let endpoint = openai_endpoint(base_url.as_str(), protocol)?;
    let environment_fallback = environment_api_key
        .map(|key| OpenAiApiKey::from_bytes(key.expose().as_bytes().to_vec()))
        .transpose()?;
    let credentials = Arc::new(PostgresOpenAiCredentialSource::new(
        pool.clone(),
        credential_vault.clone(),
        credential_key_id,
        environment_fallback,
    )?);
    let egress = CidrAllowlist::parse_exact(egress_allow_cidrs.iter().map(String::as_str))?;
    let egress_policy = EgressPolicy::new(egress);
    let package_provider: Arc<dyn ProviderAdapter> =
        Arc::new(OpenAiProvider::new_with_credential_source(
            OpenAiProviderConfig::new_with_transport_policy(
                endpoint,
                model,
                protocol,
                SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(30))?,
                budgets.stall_timeout,
                if allow_http {
                    SchemePolicy::HttpOrHttps
                } else {
                    SchemePolicy::HttpsOnly
                },
            )?,
            credentials,
            SafeDialer::new(egress_policy.clone()),
        ));
    let managed = if requires_managed {
        let managed_rate_card = managed_provider
            .as_ref()
            .and_then(|provider| provider.rate_card.clone());
        Some(build_managed_provider(
            managed_provider.ok_or_else(|| startup_error("managed_provider_key_missing"))?,
            budgets,
        )?)
        .map(|provider| (provider, managed_rate_card))
    } else {
        None
    };
    let remote_transport = build_remote_agent_transport(&egress_allow_cidrs, allow_http, budgets)?;
    let remote_provider: Arc<dyn ProviderAdapter> =
        Arc::new(RemoteAguiProvider::new(remote_transport));
    // Personal model starts share the host's current egress policy and budgets, but obtain their
    // own current PG/Vault binding each time the outer retry wrapper invokes the router.
    #[cfg(test)]
    let custom_model_dialer = custom_model_dialer.unwrap_or_else(|| SafeDialer::new(egress_policy));
    #[cfg(not(test))]
    let custom_model_dialer = SafeDialer::new(egress_policy);
    let custom_provider: Arc<dyn ProviderAdapter> = Arc::new(
        PostgresCustomModelProvider::new(
            pool.clone(),
            credential_vault.clone(),
            deployment.clone(),
            tenant.clone(),
            custom_model_dialer,
            SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(30))?,
            budgets.stall_timeout,
        )?
        .with_model_dataset_binding(Arc::clone(&model_dataset_binding))?,
    );
    let provider = Arc::new(RetryingProvider::new(
        Arc::new(
            ProviderRouter::new(
                package_provider,
                managed.as_ref().map(|(provider, _)| Arc::clone(provider)),
            )
            .with_remote_agui(remote_provider)
            .with_custom(custom_provider),
        ),
        RetryingProviderConfig::default(),
    )?);
    let context = Arc::new(
        PostgresAgentContextSource::new(pool, deployment, tenant, Some(budgets.max_output_tokens))?
            .with_model_dataset_binding(model_dataset_binding)?
            .with_rate_cards(
                package_rate_card,
                managed.and_then(|(_, rate_card)| rate_card),
            )
            .with_tools(vec![remember_provider_tool()])
            .with_remote_assertions(remote_assertions)
            .with_mcp_catalog(mcp_catalog)
            .with_components(components)
            .with_sandboxed_components(sandboxed_components)
            .with_agent_credential_vault(credential_vault),
    );
    let agent = BuiltInAgentRuntime::start_with_remote_interrupts(
        runtime,
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
    .map_err(|_| startup_error("agent_runtime_config_invalid"))?;
    let consumer = agent.consumer();
    Ok((consumer, Some(agent)))
}

fn managed_provider_for_slot(server: &ServerConfig) -> Option<ManagedProviderConfig> {
    server.managed_provider.clone().or_else(|| {
        let package = &server.package_openai_provider;
        package
            .environment_api_key
            .clone()
            .map(|api_key| ManagedProviderConfig {
                provider: ManagedProviderKind::OpenAi,
                model: "gpt-5.5".to_owned(),
                api_key,
                base_url: package.base_url.clone(),
                use_responses_api: false,
                egress_allow_cidrs: package.egress_allow_cidrs.clone(),
                allow_http: package.allow_http,
                rate_card: None,
            })
    })
}

fn build_remote_agent_transport(
    egress_allow_cidrs: &[String],
    allow_http: bool,
    budgets: AgentBudgets,
) -> Result<Arc<SafeRemoteAguiTransport>, Box<dyn Error>> {
    let egress = EgressPolicy::new(CidrAllowlist::parse_exact(
        egress_allow_cidrs.iter().map(String::as_str),
    )?);
    Ok(Arc::new(SafeRemoteAguiTransport::new(
        SafeDialer::new(egress),
        SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(30))?,
        budgets.stall_timeout,
        if allow_http {
            SchemePolicy::HttpOrHttps
        } else {
            SchemePolicy::HttpsOnly
        },
    )?))
}

fn build_managed_provider(
    config: ManagedProviderConfig,
    budgets: AgentBudgets,
) -> Result<Arc<dyn ProviderAdapter>, Box<dyn Error>> {
    let ManagedProviderConfig {
        provider,
        model,
        api_key,
        base_url,
        use_responses_api,
        egress_allow_cidrs,
        allow_http,
        rate_card: _,
    } = config;
    let scheme = if allow_http {
        SchemePolicy::HttpOrHttps
    } else {
        SchemePolicy::HttpsOnly
    };
    let dialer = SafeDialer::new(EgressPolicy::new(CidrAllowlist::parse_exact(
        egress_allow_cidrs.iter().map(String::as_str),
    )?));
    let connect_budget = SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(30))?;
    match provider {
        ManagedProviderKind::OpenAi => {
            let protocol = if use_responses_api {
                OpenAiProtocol::Responses
            } else {
                OpenAiProtocol::ChatCompletions
            };
            Ok(Arc::new(OpenAiProvider::new(
                OpenAiProviderConfig::new_with_transport_policy(
                    openai_endpoint(base_url.as_str(), protocol)?,
                    model,
                    protocol,
                    connect_budget,
                    budgets.stall_timeout,
                    scheme,
                )?,
                OpenAiApiKey::from_bytes(api_key.expose().as_bytes().to_vec())?,
                dialer,
            )))
        }
        ManagedProviderKind::Anthropic => Ok(Arc::new(AnthropicProvider::new(
            AnthropicProviderConfig::new_with_transport_policy(
                anthropic_endpoint(base_url.as_str())?,
                model,
                AnthropicApiKey::from_bytes(api_key.expose().as_bytes().to_vec())?,
                connect_budget,
                budgets.stall_timeout,
                scheme,
            )?,
            dialer,
        ))),
        ManagedProviderKind::Google => Ok(Arc::new(GoogleProvider::new(
            GoogleProviderConfig::new_with_transport_policy(
                google_endpoint(base_url.as_str(), &model)?,
                model,
                GoogleApiKey::from_bytes(api_key.expose().as_bytes().to_vec())?,
                connect_budget,
                budgets.stall_timeout,
                scheme,
            )?,
            dialer,
        ))),
    }
}

fn openai_endpoint(base: &str, protocol: OpenAiProtocol) -> Result<Url, std::io::Error> {
    let mut base = Url::parse(base).map_err(|_| startup_error("openai_base_url_invalid"))?;
    if !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(startup_error("openai_base_url_invalid"));
    }
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base.join(match protocol {
        OpenAiProtocol::Responses => "responses",
        OpenAiProtocol::ChatCompletions => "chat/completions",
    })
    .map_err(|_| startup_error("openai_base_url_invalid"))
}

fn anthropic_endpoint(base: &str) -> Result<Url, std::io::Error> {
    provider_base(base, "anthropic_base_url_invalid")?
        .join("v1/messages")
        .map_err(|_| startup_error("anthropic_base_url_invalid"))
}

fn google_endpoint(base: &str, model: &str) -> Result<Url, std::io::Error> {
    let model = model.strip_prefix("models/").unwrap_or(model);
    if model.is_empty()
        || model.starts_with('/')
        || model.ends_with('/')
        || model.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(startup_error("google_model_invalid"));
    }
    let model_path = if model.contains('/') {
        model.to_owned()
    } else {
        format!("models/{model}")
    };
    provider_base(base, "google_base_url_invalid")?
        .join(&format!(
            "v1beta/{model_path}:streamGenerateContent?alt=sse"
        ))
        .map_err(|_| startup_error("google_base_url_invalid"))
}

fn provider_base(base: &str, code: &'static str) -> Result<Url, std::io::Error> {
    let mut base = Url::parse(base).map_err(|_| startup_error(code))?;
    if !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(startup_error(code));
    }
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    Ok(base)
}

async fn build_oidc_login(
    config: &AuthConfig,
    pool: &openbot_infra::db::pool::DatabasePool,
    tenant: &TenantId,
    session_key: &[u8],
    oidc_state_key: &[u8],
    sso_state_key: &[u8],
    audit_key: &[u8],
    wrapping_key: WrappingKey,
    secure_cookie: bool,
) -> Result<OidcLoginAssembly, Box<dyn Error>> {
    let configured = configured_oidc_providers(config)?;
    let registry =
        ProviderRegistry::build(configured.iter().map(|provider| provider.config.clone()))?;
    let preauth = PreAuthSurface::project(&registry);
    let environment_provider_ids: Vec<String> = configured
        .iter()
        .map(|provider| provider.config.id().as_str().to_owned())
        .collect();
    let dialer = SafeDialer::new(EgressPolicy::default());
    let budget = FetchBudget::new(DEFAULT_METADATA_MAX_BYTES, DEFAULT_IDP_TIMEOUT);
    let mut runtimes = Vec::with_capacity(configured.len());
    for provider in configured {
        runtimes.push(
            OidcProviderRuntime::discover(
                provider.config,
                Some(provider.client_secret),
                None,
                &dialer,
                budget,
            )
            .await?,
        );
    }
    let attempts = PostgresLoginAttemptStore::new(
        pool.clone(),
        oidc_state_key,
        tenant,
        4096,
    )?;
    let sessions = PostgresOidcSessionIssuer::new(
        pool.clone(),
        session_key,
        config.session_lifetime,
        config.admin_floor.clone(),
        audit_key,
    )?;
    let rate_limiter = PostgresOidcRateLimiter::new(
        pool.clone(),
        config.session_secret.expose().as_bytes(),
        tenant,
    )?;
    let coordinator =
        OidcLoginCoordinator::new(runtimes, attempts, sessions, rate_limiter, dialer.clone())?;
    let dynamic_sso = DynamicSsoService::new(
        pool.clone(),
        tenant,
        sso_state_key,
        session_key,
        audit_key,
        wrapping_key,
        KeyVersion::new(1),
        config.session_lifetime,
        config.admin_floor.clone(),
        environment_provider_ids,
        dialer,
        config.public_url.clone(),
    )?;
    dynamic_sso
        .preflight_all(time::OffsetDateTime::now_utc())
        .await?;
    Ok((
        Arc::new(coordinator),
        Arc::new(dynamic_sso),
        preauth,
        config.trusted_origins.clone(),
        secure_cookie,
    ))
}

async fn database_has_dynamic_provider(
    pool: &openbot_infra::db::pool::DatabasePool,
) -> Result<bool, Box<dyn Error>> {
    let client = pool.get().await?;
    Ok(client
        .query_one("SELECT EXISTS(SELECT 1 FROM public.sso_providers)", &[])
        .await?
        .try_get(0)?)
}

fn configured_origins(
    env: &openbot_server::config::EnvMap,
) -> Result<TrustedOrigins, Box<dyn Error>> {
    let configured = openbot_server::config::env::comma_separated(env, "TRUSTED_ORIGINS");
    let entries = if configured.is_empty() {
        vec![openbot_infra::auth::config::DEFAULT_TRUSTED_ORIGIN.to_owned()]
    } else {
        configured
    };
    TrustedOrigins::from_configured(entries).map_err(Into::into)
}

fn deployment_id_for_startup(value: Option<&str>, package_tenant_id: &str) -> DeploymentId {
    DeploymentId::new(value.unwrap_or(package_tenant_id))
}

fn tenant_package_directory_for_startup(configured: &str) -> PathBuf {
    let direct = PathBuf::from(configured);
    if direct.is_dir() || configured != DEFAULT_TENANT_PACKAGE_DIR {
        return direct;
    }
    let workspace_default = PathBuf::from("examples/fintech");
    if workspace_default.is_dir() {
        workspace_default
    } else {
        direct
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn startup_error(code: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, code)
}

#[cfg(test)]
#[path = "http/custom_model_v2_tests.rs"]
mod custom_model_v2_tests;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn audit_key_is_domain_separated_and_deterministic() {
        let master = SecretBytes::new(vec![0x42; 32]);
        let other = SecretBytes::new(vec![0x43; 32]);
        let first =
            derive_application_key(&master, ApplicationKeyPurpose::AuditCheckpoint).unwrap();
        let oauth = derive_application_key(&master, ApplicationKeyPurpose::McpOauthState).unwrap();
        assert_eq!(
            first.expose(),
            derive_application_key(&master, ApplicationKeyPurpose::AuditCheckpoint)
                .unwrap()
                .expose()
        );
        assert_ne!(
            first.expose(),
            derive_application_key(&other, ApplicationKeyPurpose::AuditCheckpoint)
                .unwrap()
                .expose()
        );
        assert_ne!(first.expose(), oauth.expose());
        assert_ne!(first.expose(), &[0; 32]);
        assert_ne!(oauth.expose(), &[0; 32]);
    }

    #[test]
    fn deployment_id_uses_explicit_value_or_validated_package_tenant_not_a_directory() {
        assert_eq!(
            deployment_id_for_startup(Some("tenant-id"), "package-id"),
            DeploymentId::new("tenant-id"),
        );
        assert_eq!(
            deployment_id_for_startup(None, "package-id"),
            DeploymentId::new("package-id"),
        );
        assert_ne!(
            deployment_id_for_startup(None, "package-id"),
            DeploymentId::new("../examples/fintech")
        );
    }

    #[test]
    fn default_package_path_resolves_to_the_workspace_fixture_without_rewriting_custom_paths() {
        assert!(
            tenant_package_directory_for_startup(DEFAULT_TENANT_PACKAGE_DIR)
                .ends_with("examples/fintech")
        );
        assert_eq!(
            tenant_package_directory_for_startup("/mounted/customer-package"),
            PathBuf::from("/mounted/customer-package")
        );
    }

    #[test]
    fn openai_base_url_is_sdk_style_base_and_protocol_selects_exact_endpoint() {
        assert_eq!(PACKAGE_OPENAI_PROTOCOL, OpenAiProtocol::Responses);
        assert_eq!(
            CHANNEL_ROUTING_OPENAI_PROTOCOL,
            OpenAiProtocol::ChatCompletions
        );
        assert_eq!(
            openai_endpoint("https://api.openai.com/v1", OpenAiProtocol::Responses)
                .unwrap()
                .as_str(),
            "https://api.openai.com/v1/responses"
        );
        assert_eq!(
            openai_endpoint(
                "https://gateway.example/openai/v1/",
                OpenAiProtocol::ChatCompletions,
            )
            .unwrap()
            .as_str(),
            "https://gateway.example/openai/v1/chat/completions"
        );
        assert!(
            openai_endpoint("https://user@gateway.example/v1", OpenAiProtocol::Responses).is_err()
        );
        assert!(
            openai_endpoint(
                "https://gateway.example/v1?tenant=x",
                OpenAiProtocol::Responses
            )
            .is_err()
        );
    }

    #[test]
    fn managed_provider_defaults_from_openai_environment_only_when_the_slot_needs_it() {
        let server = ServerConfig::from_env_map(&BTreeMap::from([(
            "OPENAI_API_KEY".to_owned(),
            " managed-key ".to_owned(),
        )]))
        .unwrap();
        assert!(server.managed_provider.is_none());
        let managed = managed_provider_for_slot(&server).unwrap();
        assert_eq!(managed.provider, ManagedProviderKind::OpenAi);
        assert_eq!(managed.model, "gpt-5.5");
        assert_eq!(managed.api_key.expose(), "managed-key");
        assert!(!managed.use_responses_api);

        let no_key = ServerConfig::from_env_map(&BTreeMap::new()).unwrap();
        assert!(managed_provider_for_slot(&no_key).is_none());
    }

    #[test]
    fn anthropic_and_google_base_urls_map_to_locked_sdk_endpoints_without_model_injection() {
        assert_eq!(
            anthropic_endpoint("https://api.anthropic.com")
                .unwrap()
                .as_str(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            google_endpoint(
                "https://generativelanguage.googleapis.com",
                "gemini-2.5-flash"
            )
            .unwrap()
            .as_str(),
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        );
        assert_eq!(
            google_endpoint("https://gateway.example/google/", "models/gemini-custom")
                .unwrap()
                .as_str(),
            "https://gateway.example/google/v1beta/models/gemini-custom:streamGenerateContent?alt=sse"
        );
        assert!(google_endpoint("https://gateway.example", "../admin?key=secret").is_err());
    }

    #[test]
    fn production_managed_factory_constructs_all_three_provider_families() {
        let cases = [
            (
                ManagedProviderKind::OpenAi,
                "gpt-5.5",
                "https://api.openai.com/v1",
                false,
            ),
            (
                ManagedProviderKind::Anthropic,
                "claude-sonnet-4-5",
                "https://api.anthropic.com",
                false,
            ),
            (
                ManagedProviderKind::Google,
                "gemini-2.5-flash",
                "https://generativelanguage.googleapis.com",
                false,
            ),
        ];
        let mut constructed = 0;
        for (provider, model, base, use_responses_api) in cases {
            let adapter = build_managed_provider(
                ManagedProviderConfig {
                    provider,
                    model: model.to_owned(),
                    api_key: openbot_server::config::Secret::new("test-key"),
                    base_url: openbot_server::config::DeploymentAddress::parse(base).unwrap(),
                    use_responses_api,
                    egress_allow_cidrs: Vec::new(),
                    allow_http: false,
                    rate_card: None,
                },
                AgentBudgets {
                    stall_timeout: None,
                    run_deadline: Some(Duration::from_secs(1800)),
                    max_output_tokens: 16_384,
                },
            )
            .unwrap();
            constructed += 1;
            drop(adapter);
        }
        assert_eq!(constructed, 3);
    }
}
