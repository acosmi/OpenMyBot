//! PostgreSQL 17 evidence that the shared Server/Desktop assembly returns one real application.

mod harness;

use std::sync::Arc;

use async_trait::async_trait;
use harness::{admin_config, with_temp_database};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::budget::{RunCostBudgetPreference, RunCostCapInput};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
    assemble_postgres_application,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::policy::PolicyStore;
use openbot_infra::ui_preferences::PostgresUiPreferenceAdministration;
use openbot_infra::vault::CredentialRecordVault;
use url::Url;

#[derive(Default)]
struct ClosedRemoteProbe;

#[async_trait]
impl RemoteAguiTransport for ClosedRemoteProbe {
    async fn start(
        &self,
        _endpoint: &str,
        _authorization: Option<&openbot_application::RemoteAguiAuthorization>,
        _body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn shared_postgres_application_assembly_executes_real_command() {
    let admin = admin_config("shared_postgres_application_assembly_executes_real_command");
    with_temp_database(&admin, "applicationassembly", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,name,auth_generation)
                       VALUES('assembly-user','assembly@example.test','Assembly User',0);
                     INSERT INTO public.user_roles(user_id,role)
                       VALUES('assembly-user','admin');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let deployment = DeploymentId::new("assembly-deployment");
            let tenant = TenantId::new("assembly-tenant");
            let policy_store = PolicyStore::postgres(pool.clone(), None);
            policy_store
                .load()
                .await
                .map_err(|error| error.to_string())?;
            let credential_vault = CredentialRecordVault::single_key(
                tenant.clone(),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x42; 32]).map_err(|error| error.to_string())?,
            );
            let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
                pool: pool.clone(),
                listener_database: config.clone().into(),
                deployment: deployment.clone(),
                tenant: tenant.clone(),
                single_user: true,
                admin_floor: None,
                model: "gpt-4.1".to_owned(),
                credential_key_id: "assembly-model-key".to_owned(),
                credential_vault,
                audit_key: SecretBytes::new(vec![0x51; 32]),
                remote_assertions: Arc::new(
                    RemoteRunAssertionSigner::new(vec![0x52; 32])
                        .map_err(|error| error.to_string())?,
                ),
                mcp_oauth_state_key: SecretBytes::new(vec![0x53; 32]),
                policy_store,
                ui_preferences: Arc::new(
                    PostgresUiPreferenceAdministration::new(
                        pool.clone(),
                        deployment.clone(),
                        tenant.clone(),
                        SecretBytes::new(vec![0x51; 32]),
                    )
                    .map_err(|e| e.to_string())?,
                ),
                screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
                artifacts: None,
                runtime_capabilities: None,
                remote_agent_probe: Arc::new(ClosedRemoteProbe),
                managed_slot_available: false,
                channel_routing_provider: ChannelRoutingProviderInput {
                    endpoint: Url::parse("http://127.0.0.1:9/v1/chat/completions")
                        .map_err(|error| error.to_string())?,
                    environment_api_key: None,
                    egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
                    allow_http: true,
                },
                stall_timeout: Some(std::time::Duration::from_secs(2)),
                oauth_public_url: None,
                app_url: None,
                extra_provider_adapters: Vec::new(),
                run_event_subscriber: None,
                delegation_authority: None,
            })
            .await
            .map_err(|error| error.to_string())?;
            let rendered = format!("{assembly:?}");
            if rendered.contains("assembly-model-key") || rendered.contains("127.0.0.1") {
                return Err("assembly Debug leaked configuration".to_owned());
            }
            let PostgresApplicationAssembly {
                application,
                mcp_revocation_reconciler,
                ..
            } = assembly;
            let auth = AuthContextBuilder::from_verified_session(
                deployment,
                tenant,
                ActorId::new("assembly-user"),
                AuthGeneration::new(0),
                true,
            )
            .with_roles([Role::User, Role::Admin])
            .build();
            let reply = application
                .execute(auth.clone(), AppCommand::GetCurrentUser)
                .await
                .map_err(|error| error.to_string())?;
            if !matches!(reply, AppReply::CurrentUser(_)) {
                return Err(format!("shared application reply drifted: {reply:?}"));
            }
            // The real shared application must use the authoritative PG preference port.
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let before: i64=client.query_one("SELECT count(*) FROM public.user_ui_preferences",&[])
                .await.map_err(|e|e.to_string())?.get(0);
            let empty=application.execute(auth.clone(),AppCommand::GetUiPreferences)
                .await.map_err(|e|e.to_string())?;
            if empty!=AppReply::UiPreferences(openbot_contracts::ui::UiPreferences::default()) {
                return Err("uninitialized PG preferences must remain absent".to_owned());
            }
            if client.query_one("SELECT count(*) FROM public.user_ui_preferences",&[])
                .await.map_err(|e|e.to_string())?.get::<_,i64>(0)!=before {
                return Err("preference GET created a row".to_owned());
            }
            let created=application.execute(auth.clone(),AppCommand::UpdateUiPreferences(
                openbot_contracts::ui::UpdateUiPreferences {theme:Some(openbot_contracts::ui::UiTheme::Light),
                    locale:None,expected_revision:None}))
                .await.map_err(|e|e.to_string())?;
            if !matches!(created,AppReply::UiPreferences(p) if p.revision==Some(1) && p.updated_at.is_some()) {
                return Err("assembled preference create receipt drifted".to_owned());
            }
            let advanced=application.execute(auth.clone(),AppCommand::UpdateUiPreferences(
                openbot_contracts::ui::UpdateUiPreferences {theme:None,
                    locale:Some(openbot_contracts::ui::UiLocale::ZhCn),expected_revision:Some(1)}))
                .await.map_err(|e|e.to_string())?;
            if !matches!(advanced,AppReply::UiPreferences(p) if p.revision==Some(2)
                && p.theme==Some(openbot_contracts::ui::UiTheme::Light)
                && p.locale==Some(openbot_contracts::ui::UiLocale::ZhCn)) {
                return Err("assembled exact-version partial receipt drifted".to_owned());
            }
            let preference = RunCostBudgetPreference {
                cap: Some(RunCostCapInput {
                    currency: "USD".to_owned(),
                    max_cost_micro_units: "250000".to_owned(),
                }),
            };
            let saved = application
                .execute(
                    auth.clone(),
                    AppCommand::ReplaceRunCostBudget(preference.clone()),
                )
                .await
                .map_err(|error| error.to_string())?;
            if saved != AppReply::RunCostBudget(preference.clone()) {
                return Err(format!("shared cost budget write drifted: {saved:?}"));
            }
            let loaded = application
                .execute(auth, AppCommand::GetRunCostBudget)
                .await
                .map_err(|error| error.to_string())?;
            if loaded != AppReply::RunCostBudget(preference) {
                return Err(format!("shared cost budget read drifted: {loaded:?}"));
            }
            mcp_revocation_reconciler.stop().await;
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
