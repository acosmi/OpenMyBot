use crate::{DaemonError, config, delegation::OmbDelegationAuthority, pg::Postgres, tenant};
use omb_hostdriver::HostDriver;
use openbot_application::{
    ProviderAdapter, ProviderExtensionKey,
    tenant::package::{
        LoadedTenantPackage, TenantPackageAudienceContext, synchronize_tenant_package,
    },
};
use openbot_computer::screen::{
    DEFAULT_SCREEN_VIEWERS_PER_STREAM, ScreenHub, ScreenSessionService,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::{
    remote_callback::RemoteRunAssertionSigner,
    vault::{ApplicationKeyPurpose, KeyVersion, SecretBytes, WrappingKey, derive_application_key},
};
use openbot_infra::{
    application_assembly::{
        ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
        assemble_postgres_application,
    },
    auth::{
        config::default_session_lifetime,
        single_user::{
            SINGLE_USER_ACTOR_ID, VerifiedSingleUserPrincipal, initialize_single_user,
            load_single_user_principal,
        },
    },
    db::pool::{self, DatabaseConfig, DatabasePool},
    net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy},
    policy::PolicyStore,
    remote_agui::SafeRemoteAguiTransport,
    tenant::PostgresTenantPackageSynchronizer,
    ui_preferences::PostgresUiPreferenceAdministration,
    vault::CredentialRecordVault,
};
use openbot_server::SingleUserAuthResolver;
use std::{path::Path, sync::Arc, time::Duration};

pub(crate) struct Prepared {
    pool: DatabasePool,
    database: DatabaseConfig,
    deployment: DeploymentId,
    tenant: TenantId,
    package: LoadedTenantPackage,
    principal: VerifiedSingleUserPrincipal,
    authority: OmbDelegationAuthority,
}
pub(crate) async fn prepare(
    root: &Path,
    id: &str,
    pg: &mut Postgres,
) -> Result<Prepared, DaemonError> {
    let database = pg.database_config();
    let pool = pool::connect(&database)
        .await
        .map_err(|_| DaemonError::EngineInitializationFailed)?;
    openbot_server::database::initialize(&pool)
        .await
        .map_err(|_| DaemonError::EngineInitializationFailed)?;
    if !initialize_single_user(&pool, true)
        .await
        .map_err(|_| DaemonError::EngineInitializationFailed)?
    {
        return Err(DaemonError::EngineInitializationFailed);
    }
    let deployment = DeploymentId::new(id);
    let tenant = TenantId::new(id);
    let principal = load_single_user_principal(&pool, deployment.clone(), tenant.clone())
        .await
        .map_err(|_| DaemonError::EngineInitializationFailed)?;
    pg.migrate_store().await?;
    let package = tenant::write_and_load(root, id)?;
    let audience = TenantPackageAudienceContext::single_user(ActorId::new(SINGLE_USER_ACTOR_ID))
        .map_err(|_| DaemonError::TenantPackageFailed)?;
    synchronize_tenant_package(
        &PostgresTenantPackageSynchronizer::new(pool.clone()),
        &package,
        &audience,
    )
    .await
    .map_err(|_| DaemonError::TenantPackageFailed)?;
    let authority = OmbDelegationAuthority::open(
        pg,
        deployment.clone(),
        tenant.clone(),
        ActorId::new(SINGLE_USER_ACTOR_ID),
    )
    .await?;
    Ok(Prepared {
        pool,
        database,
        deployment,
        tenant,
        package,
        principal,
        authority,
    })
}
/// The assembled engine, its delegation authority and the single-user owner resolver.
pub struct Engine {
    pub(crate) assembly: PostgresApplicationAssembly,
    pub(crate) authority: Arc<OmbDelegationAuthority>,
    pub(crate) resolver: SingleUserAuthResolver,
    pub(crate) vault: CredentialRecordVault,
    /// The pool, scope and audit checkpoint key the Agent runtime is assembled from.
    pub(crate) pool: DatabasePool,
    pub(crate) deployment: DeploymentId,
    pub(crate) tenant: TenantId,
    pub(crate) agent_audit_key: SecretBytes,
}
impl Engine {
    pub(crate) async fn shutdown(self) {
        self.assembly.shutdown().await;
        self.authority.close().await;
    }
}
pub(crate) async fn assemble(
    root: &Path,
    prepared: Prepared,
    host: &HostDriver,
) -> Result<Engine, DaemonError> {
    let Prepared {
        pool,
        database,
        deployment,
        tenant,
        package,
        principal,
        authority,
    } = prepared;
    let authority = Arc::new(authority);
    let master = SecretBytes::new(config::read_private(&root.join("keys/app-master.key"), 32)?);
    let audit_key = derive_application_key(&master, ApplicationKeyPurpose::AuditCheckpoint)
        .map_err(|_| DaemonError::EngineAssemblyFailed)?;
    let mcp_oauth_state_key = derive_application_key(&master, ApplicationKeyPurpose::McpOauthState)
        .map_err(|_| DaemonError::EngineAssemblyFailed)?;
    let remote_assertions = Arc::new(
        RemoteRunAssertionSigner::new(master.expose().to_vec())
            .map_err(|_| DaemonError::EngineAssemblyFailed)?,
    );
    let wrapping =
        WrappingKey::from_bytes(config::read_private(&root.join("keys/vault-kek.key"), 32)?)
            .map_err(|_| DaemonError::EngineAssemblyFailed)?;
    let credential_vault =
        CredentialRecordVault::single_key(tenant.clone(), KeyVersion::new(1), wrapping);
    let vault = credential_vault.clone();
    let policy_store = PolicyStore::postgres(pool.clone(), None);
    policy_store
        .load()
        .await
        .map_err(|_| DaemonError::EngineAssemblyFailed)?;
    let ui_audit_key = derive_application_key(&master, ApplicationKeyPurpose::AuditCheckpoint)
        .map_err(|_| DaemonError::EngineAssemblyFailed)?;
    let agent_audit_key = SecretBytes::new(audit_key.expose().to_vec());
    let crabcode: Arc<dyn ProviderAdapter> = host.adapter();
    let ui_preferences = Arc::new(
        PostgresUiPreferenceAdministration::new(
            pool.clone(),
            deployment.clone(),
            tenant.clone(),
            ui_audit_key,
        )
        .map_err(|_| DaemonError::EngineAssemblyFailed)?,
    );
    let screen_sessions = Arc::new(ScreenSessionService::new(
        ScreenHub::new(DEFAULT_SCREEN_VIEWERS_PER_STREAM)
            .map_err(|_| DaemonError::EngineAssemblyFailed)?,
    ));
    let remote_agent_probe = Arc::new(
        SafeRemoteAguiTransport::new(
            SafeDialer::new(EgressPolicy::new(
                CidrAllowlist::parse_exact([]).map_err(|_| DaemonError::EngineAssemblyFailed)?,
            )),
            SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(30))
                .map_err(|_| DaemonError::EngineAssemblyFailed)?,
            None,
            SchemePolicy::HttpsOnly,
        )
        .map_err(|_| DaemonError::EngineAssemblyFailed)?,
    );
    let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
        pool: pool.clone(),
        listener_database: database.into(),
        deployment: deployment.clone(),
        tenant: tenant.clone(),
        single_user: true,
        admin_floor: None,
        model: package.package.model.default_model,
        credential_key_id: package.package.model.credential_secret_ref,
        credential_vault,
        audit_key,
        remote_assertions,
        mcp_oauth_state_key,
        policy_store,
        ui_preferences,
        screen_sessions,
        artifacts: None,
        runtime_capabilities: None,
        remote_agent_probe,
        managed_slot_available: false,
        channel_routing_provider: ChannelRoutingProviderInput {
            endpoint: url::Url::parse("https://127.0.0.1/v1/chat/completions")
                .map_err(|_| DaemonError::EngineAssemblyFailed)?,
            environment_api_key: None,
            egress_allow_cidrs: Vec::new(),
            allow_http: false,
        },
        stall_timeout: None,
        oauth_public_url: None,
        app_url: None,
        extra_provider_adapters: vec![(
            ProviderExtensionKey::new("crabcode").map_err(|_| DaemonError::EngineAssemblyFailed)?,
            crabcode,
        )],
        run_event_subscriber: None,
        delegation_authority: Some(authority.clone()),
    })
    .await
    .map_err(|_| DaemonError::EngineAssemblyFailed)?;
    Ok(Engine {
        assembly,
        authority,
        resolver: SingleUserAuthResolver::from_verified_principal(
            principal,
            default_session_lifetime(),
        ),
        vault,
        pool,
        deployment,
        tenant,
        agent_audit_key,
    })
}
