//! Personal custom inference uses the existing PG/Vault, provider decoders and SafeDialer.
//! No connection object, key or static provider survives across sampling or retry attempts.

use super::{
    anthropic::{AnthropicApiKey, AnthropicProvider, AnthropicProviderConfig},
    openai::{OpenAiApiKey, OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig},
};
use crate::{
    model_runtime,
    net::safe_http::{SafeDialer, SafeHttpBudget},
    vault::CredentialRecordVault,
};
use async_trait::async_trait;
use openbot_application::{
    AgentContextError, ProviderAdapter, ProviderPortError, ProviderRequest, ProviderRoute,
    ProviderSession,
};
use openbot_contracts::{
    ids::{DeploymentId, TenantId},
    model_connections::CustomModelProtocol,
};
use openbot_domain::vault::{SecretKind, SecretPrincipal, ServiceId};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use uuid::Uuid;

/// Shared Server/Desktop factory; every start reopens current authority and a short-lived key.
pub struct PostgresCustomModelProvider {
    pool: crate::db::pool::DatabasePool,
    vault: CredentialRecordVault,
    deployment: DeploymentId,
    tenant: TenantId,
    dialer: SafeDialer,
    connect_budget: SafeHttpBudget,
    stall_timeout: Option<Duration>,
    model_dataset_binding: Option<Arc<crate::model_dataset::PostgresModelDatasetBinding>>,
    #[cfg(test)]
    v2_vault_opens: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    v2_expired_last_authority_ready: Arc<std::sync::atomic::AtomicUsize>,
}
impl PostgresCustomModelProvider {
    /// Bind only trusted host infrastructure. URL/model/key are never accepted by this factory.
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        vault: CredentialRecordVault,
        deployment: DeploymentId,
        tenant: TenantId,
        dialer: SafeDialer,
        connect_budget: SafeHttpBudget,
        stall_timeout: Option<Duration>,
    ) -> Result<Self, ProviderPortError> {
        if deployment.as_str().is_empty()
            || tenant.as_str().is_empty()
            || connect_budget.timeout() > Duration::from_secs(30)
            || connect_budget.max_response_bytes() > 64 * 1024 * 1024
            || stall_timeout.is_some_and(|value| value.is_zero())
        {
            return Err(invalid("custom_model_configuration"));
        }
        Ok(Self {
            pool,
            vault,
            deployment,
            tenant,
            dialer,
            connect_budget,
            stall_timeout,
            model_dataset_binding: None,
            #[cfg(test)]
            v2_vault_opens: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            v2_expired_last_authority_ready: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Attach the original dataset producer once. A missing producer never enables v2.
    pub fn with_model_dataset_binding(
        mut self,
        binding: Arc<crate::model_dataset::PostgresModelDatasetBinding>,
    ) -> Result<Self, ProviderPortError> {
        if self.model_dataset_binding.is_some()
            || !binding.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            return Err(invalid("model_dataset_binding"));
        }
        self.model_dataset_binding = Some(binding);
        Ok(self)
    }

    async fn start_v2(
        &self,
        request: ProviderRequest,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let binding = self
            .model_dataset_binding
            .as_ref()
            .ok_or_else(|| invalid("model_dataset_binding"))?;
        if !binding.matches_pool_scope(&self.pool, &self.deployment, &self.tenant) {
            return Err(invalid("model_dataset_binding"));
        }
        let progress = StartProgress::default();
        let result=tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),async{
            let mut checkout=binding.checkout(deadline).await.map_err(map_start_dataset)?;
            let transaction=checkout.begin_read_committed().await.map_err(map_start_transaction)?;
            let result=async {
                let remaining=deadline.saturating_duration_since(std::time::Instant::now()).as_millis().max(1).to_string();
                transaction.as_transaction().query_one(
                    "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",&[&remaining])
                    .await.map_err(|_|ProviderPortError::Unavailable)?;
                let ProviderRoute::CustomModel(expected)=&request.route else{return Err(invalid("custom_model_route"));};
                if expected.v2_snapshot().is_none(){return Err(invalid("custom_model_binding"));}
                let lease=expected.identity_lease().map_err(map_authority)?;
                let loaded=model_runtime::load_v2_for_start(&transaction,&self.deployment,&self.tenant,&lease)
                    .await.map_err(map_authority)?;
                #[cfg(test)]
                if std::time::Instant::now()>=deadline {
                    self.v2_expired_last_authority_ready.fetch_add(1,Ordering::SeqCst);
                }
                if loaded.binding!=*expected{return Err(invalid("custom_model_binding"));}
                if loaded.has_cost_cap{return Err(invalid("custom_model_unpriced"));}
                let secret_id=Uuid::parse_str(loaded.binding.secret_id()).map_err(|_|invalid("custom_model_credential"))?;
                // An outer timeout cannot preempt this synchronous continuation when a
                // Ready SQL future consumes the last budget in the same poll.
                if std::time::Instant::now()>=deadline{return Err(ProviderPortError::Unavailable);}
                #[cfg(test)]
                self.v2_vault_opens.fetch_add(1,Ordering::SeqCst);
                let opened=self.vault.open(&secret_id,SecretKind::Model,
                    SecretPrincipal::Actor(loaded.binding.actor().clone()),
                    SecretPrincipal::Service(ServiceId::new(loaded.binding.connection_id())),&loaded.encrypted_value)
                    .map_err(|_|invalid("custom_model_credential"))?;
                if opened.needs_migration(){return Err(invalid("custom_model_credential"));}
                let key=opened.into_secret();
                let text=core::str::from_utf8(key.expose()).map_err(|_|invalid("custom_model_credential"))?;
                if text.is_empty() || text.len()>16*1024 || text.trim()!=text || text.contains(['\r','\n','\0']){
                    return Err(invalid("custom_model_credential"));
                }
                let endpoint=url::Url::parse(loaded.binding.endpoint()).map_err(|_|invalid("custom_model_configuration"))?;
                let adapter:Box<dyn ProviderAdapter>=match loaded.binding.protocol(){
                    CustomModelProtocol::OpenaiChatCompletions|CustomModelProtocol::OpenaiResponses=>{
                        let protocol=if loaded.binding.protocol()==CustomModelProtocol::OpenaiResponses{
                            OpenAiProtocol::Responses
                        }else{OpenAiProtocol::ChatCompletions};
                        let config=OpenAiProviderConfig::new(endpoint,loaded.binding.model().to_owned(),protocol,
                            self.connect_budget,self.stall_timeout)?;
                        Box::new(OpenAiProvider::new(config,OpenAiApiKey::from_secret(key)?,self.dialer.clone()))
                    }
                    CustomModelProtocol::AnthropicMessages=>{
                        let config=AnthropicProviderConfig::new(endpoint,loaded.binding.model().to_owned(),
                            AnthropicApiKey::from_secret(key)?,self.connect_budget,self.stall_timeout)?;
                        Box::new(AnthropicProvider::new(config,self.dialer.clone()))
                    }
                };
                // Synchronous Vault/configuration work also shares the original budget.
                // Refuse before declaring any possible adapter/network effect.
                if std::time::Instant::now()>=deadline{return Err(ProviderPortError::Unavailable);}
                // This is a conservative may-have-effect fence, not a remote-send or ACK.
                progress.network_started.store(true,Ordering::SeqCst);
                adapter.start(request).await
            }.await;
            if let Err(error)=&result && let Ok(mut failure)=progress.failure.lock(){*failure=Some(*error);}
            let ended=transaction.rollback().await;
            if let Err(end)=ended{tracing::warn!(state=?end,"custom v2 original start rollback state");}
            let after_adapter=progress.network_started.load(Ordering::SeqCst);
            match result {
                Ok(session)=>{
                    if ended.is_err() || std::time::Instant::now()>=deadline {
                        drop(session);
                        return Err(ProviderPortError::CommitUnknown);
                    }
                    // Only a successful adapter plus the original timely rollback ACK may
                    // transfer the live session to the existing decoder/retry machinery.
                    Ok(session)
                }
                Err(_) if after_adapter=>Err(ProviderPortError::CommitUnknown),
                Err(error)=>Err(error),
            }
        }).await;
        match result {
            Ok(result) => result,
            Err(_) => {
                if progress.network_started.load(Ordering::SeqCst) {
                    return Err(ProviderPortError::CommitUnknown);
                }
                Err(progress
                    .failure
                    .lock()
                    .ok()
                    .and_then(|failure| *failure)
                    .unwrap_or(ProviderPortError::Unavailable))
            }
        }
    }

    async fn start_locked(
        &self,
        client: &mut crate::db::pool::PooledClient,
        request: ProviderRequest,
        progress: &StartProgress,
    ) -> Attempt {
        let tx = match client.transaction().await {
            Ok(tx) => tx,
            Err(_) => {
                return Attempt {
                    result: Err(ProviderPortError::Unavailable),
                    clean: false,
                };
            }
        };
        let result = async {
            // Bound a disconnected caller's outstanding SQL too. Values are parameters, not SQL.
            let timeout_ms = self.connect_budget.timeout().as_millis().max(1).to_string();
            tx.query_one(
                "SELECT set_config('statement_timeout',$1,true)",
                &[&timeout_ms],
            )
            .await
            .map_err(|_| ProviderPortError::Unavailable)?;
            let ProviderRoute::CustomModel(expected) = &request.route else {
                return Err(invalid("custom_model_route"));
            };
            let lease = expected.identity_lease().map_err(map_authority)?;
            let loaded =
                model_runtime::load_current_selection(&tx, &self.deployment, &self.tenant, &lease)
                    .await
                    .map_err(map_authority)?
                    .ok_or_else(|| invalid("custom_model_binding"))?;
            if loaded.binding != *expected {
                return Err(invalid("custom_model_binding"));
            }
            if loaded.has_cost_cap {
                return Err(invalid("custom_model_unpriced"));
            }
            let secret_id = Uuid::parse_str(loaded.binding.secret_id())
                .map_err(|_| invalid("custom_model_credential"))?;
            let opened = self
                .vault
                .open(
                    &secret_id,
                    SecretKind::Model,
                    SecretPrincipal::Actor(loaded.binding.actor().clone()),
                    SecretPrincipal::Service(ServiceId::new(loaded.binding.connection_id())),
                    &loaded.encrypted_value,
                )
                .map_err(|_| invalid("custom_model_credential"))?;
            if opened.needs_migration() {
                return Err(invalid("custom_model_credential"));
            }
            let key = opened.into_secret();
            let text = core::str::from_utf8(key.expose())
                .map_err(|_| invalid("custom_model_credential"))?;
            if text.is_empty()
                || text.len() > 16 * 1024
                || text.trim() != text
                || text.contains(['\r', '\n', '\0'])
            {
                return Err(invalid("custom_model_credential"));
            }
            let endpoint = url::Url::parse(loaded.binding.endpoint())
                .map_err(|_| invalid("custom_model_configuration"))?;
            let adapter: Box<dyn ProviderAdapter> = match loaded.binding.protocol() {
                CustomModelProtocol::OpenaiChatCompletions
                | CustomModelProtocol::OpenaiResponses => {
                    let protocol =
                        if loaded.binding.protocol() == CustomModelProtocol::OpenaiResponses {
                            OpenAiProtocol::Responses
                        } else {
                            OpenAiProtocol::ChatCompletions
                        };
                    let config = OpenAiProviderConfig::new(
                        endpoint,
                        loaded.binding.model().to_owned(),
                        protocol,
                        self.connect_budget,
                        self.stall_timeout,
                    )?;
                    Box::new(OpenAiProvider::new(
                        config,
                        OpenAiApiKey::from_secret(key)?,
                        self.dialer.clone(),
                    ))
                }
                CustomModelProtocol::AnthropicMessages => {
                    let config = AnthropicProviderConfig::new(
                        endpoint,
                        loaded.binding.model().to_owned(),
                        AnthropicApiKey::from_secret(key)?,
                        self.connect_budget,
                        self.stall_timeout,
                    )?;
                    Box::new(AnthropicProvider::new(config, self.dialer.clone()))
                }
            };
            progress.network_started.store(true, Ordering::SeqCst);
            // Existing transport errors do not identify the redirect hop. A 303/307 POST may
            // already have happened before a later DNS/connect error, so never retry that error.
            match adapter.start(request).await {
                Err(ProviderPortError::Unavailable) => Err(ProviderPortError::CommitUnknown),
                result => result,
            }
        }
        .await;
        if let Err(error) = &result
            && let Ok(mut failure) = progress.failure.lock()
        {
            *failure = Some(*error);
        }
        let clean = tx.rollback().await.is_ok();
        let result = match result {
            Ok(_) if !clean => Err(ProviderPortError::CommitUnknown),
            other => other,
        };
        Attempt { result, clean }
    }
}
impl core::fmt::Debug for PostgresCustomModelProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PostgresCustomModelProvider([redacted])")
    }
}

#[async_trait]
impl ProviderAdapter for PostgresCustomModelProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let v2_deadline = std::time::Instant::now() + self.connect_budget.timeout();
        super::common::validate_request(&request)?;
        let ProviderRoute::CustomModel(binding) = &request.route else {
            return Err(invalid("custom_model_route"));
        };
        if binding.deployment() != &self.deployment || binding.tenant() != &self.tenant {
            return Err(invalid("custom_model_scope"));
        }
        if request.rate_card.is_some() || request.cost_cap.is_some() {
            return Err(invalid("custom_model_unpriced"));
        }
        if binding.v2_snapshot().is_some() {
            return self.start_v2(request, v2_deadline).await;
        }
        let deadline = tokio::time::Instant::now() + self.connect_budget.timeout();
        let client = tokio::time::timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| ProviderPortError::Unavailable)?
            .map_err(|_| ProviderPortError::Unavailable)?;
        let mut connection = StartConnection {
            client: Some(client),
            clean: false,
            cancel_budget: self.connect_budget.timeout(),
        };
        let progress = StartProgress::default();
        let result = tokio::time::timeout_at(
            deadline,
            self.start_locked(
                connection.client.as_mut().expect("owned start connection"),
                request,
                &progress,
            ),
        )
        .await;
        match result {
            Ok(attempt) => {
                connection.clean = attempt.clean;
                attempt.result
            }
            Err(_) => Err(progress
                .failure
                .lock()
                .ok()
                .and_then(|failure| *failure)
                .unwrap_or_else(|| {
                    if progress.network_started.load(Ordering::SeqCst) {
                        ProviderPortError::CommitUnknown
                    } else {
                        ProviderPortError::Unavailable
                    }
                })),
        }
    }
}

fn invalid(field: &'static str) -> ProviderPortError {
    ProviderPortError::InvalidRequest { field }
}
fn map_start_dataset(error: crate::model_dataset::ModelDatasetError) -> ProviderPortError {
    match error {
        crate::model_dataset::ModelDatasetError::InvalidBinding => invalid("model_dataset_binding"),
        crate::model_dataset::ModelDatasetError::Unavailable => ProviderPortError::Unavailable,
    }
}
fn map_start_transaction(error: crate::db::pool::TransactionOwnerError) -> ProviderPortError {
    use crate::db::pool::TransactionOwnerError as E;
    tracing::warn!(state=?error,"custom v2 original start transaction state");
    match error {
        E::AlreadyStarted => invalid("model_dataset_transaction"),
        E::DeadlineExceeded
        | E::BeginUnavailable
        | E::CommitUnknown
        | E::RollbackUnproven
        | E::CommitAcknowledgedAfterDeadline
        | E::RollbackAcknowledgedAfterDeadline => ProviderPortError::Unavailable,
    }
}
fn map_authority(error: AgentContextError) -> ProviderPortError {
    match error {
        AgentContextError::Unavailable => ProviderPortError::Unavailable,
        _ => invalid("custom_model_authority"),
    }
}
#[derive(Default)]
struct StartProgress {
    network_started: AtomicBool,
    failure: Mutex<Option<ProviderPortError>>,
}
struct Attempt {
    result: Result<Box<dyn ProviderSession>, ProviderPortError>,
    clean: bool,
}

/// A cancelled in-flight SQL request must never be returned to a different pool borrower.
/// Normal completion explicitly confirms rollback. Cancellation detaches the physical connection
/// before sending its private PG cancellation token; no subsequent caller can be cancelled by it.
struct StartConnection {
    client: Option<crate::db::pool::PooledClient>,
    clean: bool,
    cancel_budget: Duration,
}
impl Drop for StartConnection {
    fn drop(&mut self) {
        if self.clean {
            return;
        }
        let Some(client) = self.client.take() else {
            return;
        };
        let owned = crate::db::pool::PooledClient::take(client);
        let cancel = owned.cancel_token();
        let budget = self.cancel_budget;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ =
                    tokio::time::timeout(budget, cancel.cancel_query(tokio_postgres::NoTls)).await;
                // ClientWrapper drop aborts its driver and closes this detached connection.
                drop(owned);
            });
        }
    }
}

#[cfg(test)]
mod v2_test_harness {
    use crate as openbot_infra;
    include!("../../../../test-support/postgres_harness.rs");
}

#[cfg(test)]
mod v2_vault_tests {
    use super::*;
    use crate::{
        artifact_registry::ArtifactDatasetRegistry,
        db::{fresh, pool},
        model_connections::PostgresModelConnections,
        model_dataset::PostgresModelDatasetBinding,
        provider::context::PostgresAgentContextSource,
        thread_directory::PostgresThreadDirectory,
    };
    use async_trait::async_trait;
    use openbot_application::model_connections::ModelConnectionAdministration;
    use openbot_application::{
        AgentContextSource, BeginThreadRunV2Request, RunExecutionLease, ThreadDirectory,
    };
    use openbot_contracts::{
        auth::{AuthContextBuilder, AuthGeneration, Role},
        command::{BeginThreadRunV2, ThreadRunAnchor},
        ids::thread::ThreadIdentity,
        ids::{ActorId, BotId, RunId},
        model_connections::{CreateModelConnection, ModelApiKey},
        versioned_model_selection::{ModelSelectionIntentSource, RunModelSelectionV2},
    };
    use openbot_domain::{
        thread::FencingToken,
        vault::{KeyVersion, SecretBytes, WrappingKey},
    };
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{oneshot, watch};
    use tokio::task::{JoinHandle, JoinSet};
    use zeroize::Zeroizing;

    struct CountedDns(AtomicUsize);
    #[async_trait]
    impl crate::net::safe_http::DnsResolver for CountedDns {
        async fn resolve(
            &self,
            _: &str,
            _: u16,
        ) -> Result<Vec<SocketAddr>, crate::net::safe_http::DnsUnavailable> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(crate::net::safe_http::DnsUnavailable)
        }
    }

    // Owned fixture fault injection only. Always restore the original trigger and observe
    // its actual state before exposing either a successful UPDATE or its PG error.
    async fn owned_dataset_statement(
        client: &pool::PooledClient,
        statement: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<u64, tokio_postgres::Error> {
        client.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings DISABLE TRIGGER artifact_dataset_bindings_append_only")
            .await.unwrap();
        let result = client.execute(statement, params).await;
        client.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings ENABLE TRIGGER artifact_dataset_bindings_append_only")
            .await.unwrap();
        let enabled: String = client
            .query_one(
                "SELECT tgenabled::text FROM pg_catalog.pg_trigger
            WHERE tgrelid='openbot_internal.artifact_dataset_bindings'::regclass
              AND tgname='artifact_dataset_bindings_append_only' AND NOT tgisinternal",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(enabled, "O");
        result
    }
    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; only original provider Vault-call observations"]
    async fn current_predicate_refusals_observe_zero_actual_vault_opens_and_zero_dns_then_positive_control()
     {
        const DEP: &str = "owned-v2-vault-observation-deployment";
        const TENANT: &str = "owned-v2-vault-observation-tenant";
        let admin = super::v2_test_harness::admin_config("v2_vault_real_calls");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(&admin,"v2vaultrealcalls",|config|async move{
            let p=pool::connect(&config.clone().with_max_pool_size(4)).await.unwrap();
            let mut c=p.get().await.unwrap();fresh::apply(&mut c).await.unwrap();
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','owned-vault-alice@example.test',7),('bob','owned-vault-bob@example.test',7);
                INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
                INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
                INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Owned bot','','owned','public');").await.unwrap();drop(c);
            let vault=CredentialRecordVault::single_key(TenantId::new(TENANT),KeyVersion::new(1),WrappingKey::from_bytes(vec![0x76;32]).unwrap());
            let models=PostgresModelConnections::new(p.clone(),vault.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),SecretBytes::new(vec![0x77;32])).unwrap();
            let registry=Arc::new(ArtifactDatasetRegistry::from_server(p.clone(),&DeploymentId::new(DEP),&TenantId::new(TENANT)).await.unwrap());
            let binding=Arc::new(PostgresModelDatasetBinding::unbound(p.clone(),DeploymentId::new(DEP),TenantId::new(TENANT)).unwrap());
            binding.enroll_original_registry(&registry).unwrap();
            let directory=PostgresThreadDirectory::with_runtime(p.clone(),config.clone(),"owned-vault-runtime".into(),time::Duration::seconds(30)).unwrap()
                .with_model_dataset_binding(binding.clone()).unwrap();
            let context=PostgresAgentContextSource::new(p.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),Some(32)).unwrap()
                .with_model_dataset_binding(binding.clone()).unwrap();
            let auth=AuthContextBuilder::from_verified_session(DeploymentId::new(DEP),TenantId::new(TENANT),ActorId::new("alice"),AuthGeneration::new(7),false)
                .with_roles([Role::User]).build();
            let original_dataset:String=p.get().await.unwrap().query_one("SELECT dataset_id FROM openbot_internal.artifact_dataset_bindings WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap().get(0);
            for mode in 0..12u64 {
                let model=models.create(&auth,&CreateModelConnection{name:"Owned no-effect choice".into(),protocol:CustomModelProtocol::OpenaiChatCompletions,
                    endpoint:"https://owned-no-network.example.test/v1".into(),model:"owned-no-effect-model".into(),enabled:true,
                    api_key:ModelApiKey::new(Zeroizing::new("OWNED_V2_VAULT_CALL_CANARY".into())).unwrap()}).await.unwrap();
                let mut entropy=[0u8;16];entropy[8..].copy_from_slice(&(500+mode).to_be_bytes());
                let req=BeginThreadRunV2Request{deployment:DeploymentId::new(DEP),tenant:TenantId::new(TENANT),actor:ActorId::new("alice"),auth_generation:AuthGeneration::new(7),
                    command:BeginThreadRunV2{thread_id:ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),run_id:RunId::new(format!("owned-vault-run-{mode}")),
                        bot_id:BotId::new("bot"),anchor:ThreadRunAnchor::DirectBot,message:"Owned vault observation words".into(),selected_skill_slugs:vec![],
                        model_selection:RunModelSelectionV2::new(ModelSelectionIntentSource::Custom,model.id.clone(),model.revision,format!("custom:{}",model.id),1).unwrap()}};
                directory.begin_thread_run_v2(req.clone()).await.unwrap();
                let lease=RunExecutionLease::new(req.command.run_id.clone(),req.command.thread_id.clone(),req.command.bot_id.clone(),req.actor.clone(),FencingToken::new(1).unwrap(),0).unwrap();
                let request=context.load(&lease).await.unwrap();
                let dns=Arc::new(CountedDns(AtomicUsize::new(0)));
                let dialer=SafeDialer::with_resolver(crate::net::safe_http::EgressPolicy::default(),dns.clone());
                let adapter=PostgresCustomModelProvider::new(p.clone(),vault.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),dialer,
                    SafeHttpBudget::new(64*1024*1024,Duration::from_secs(5)).unwrap(),Some(Duration::from_secs(2))).unwrap()
                    .with_model_dataset_binding(binding.clone()).unwrap();
                assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0);
                let c=p.get().await.unwrap();let id=Uuid::parse_str(&model.id).unwrap();let run=req.command.run_id.as_str();
                match mode{
                    0=>{c.execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'",&[]).await.unwrap();},
                    1=>{c.execute("UPDATE public.model_connections SET enabled=false WHERE id=$1",&[&id]).await.unwrap();},
                    2=>{c.execute("UPDATE public.custom_model_catalogs SET catalog_revision=catalog_revision+1 WHERE connection_id=$1",&[&id]).await.unwrap();},
                    3=>{c.execute("UPDATE public.messages SET content=jsonb_set(content,'{modelSelection,source}','\"sdk_gateway\"'::jsonb) WHERE message_id=$1||':input'",&[&run]).await.unwrap();},
                    4=>{owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id='owned-observed-drift' WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap();},
                    5=>{c.execute("INSERT INTO public.run_model_selections SELECT run_id,deployment_id,tenant_id,owner_user_id,auth_generation,connection_id,connection_revision,secret_id,protocol,endpoint,model,created_at FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&run]).await.unwrap();},
                    6=>{c.execute("DELETE FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&run]).await.unwrap();},
                    7=>{c.execute("UPDATE public.runs SET budget_cost_currency='USD',budget_max_cost_micro_units=1 WHERE run_id=$1",&[&run]).await.unwrap();},
                    8=>{c.execute("UPDATE openbot_internal.run_model_selection_v2_snapshots SET owner_user_id='bob' WHERE run_id=$1",&[&run]).await.unwrap();},
                    9=>{c.batch_execute("GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO PUBLIC").await.unwrap();},
                    10=>{c.execute("UPDATE public.model_connection_secrets SET retired_at=clock_timestamp() WHERE connection_id=$1",&[&id]).await.unwrap();},
                    _=>{},
                }drop(c);
                let result=adapter.start(request).await;
                if mode==11{
                    // A real matching producer reaches exactly the original synchronous Vault
                    // call and the owned DNS control. This proves the counters are connected.
                    assert!(matches!(result,Err(ProviderPortError::CommitUnknown)));
                    assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),1);assert_eq!(dns.0.load(Ordering::SeqCst),1);
                }else{
                    assert!(matches!(result,Err(ProviderPortError::InvalidRequest{..})),"closed current predicate {mode}");
                    assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0,"actual provider Vault call {mode}");
                    assert_eq!(dns.0.load(Ordering::SeqCst),0,"actual DNS before effect {mode}");
                }
                let c=p.get().await.unwrap();
                if mode==0{c.execute("UPDATE public.users SET auth_generation=7 WHERE id='alice'",&[]).await.unwrap();}
                if mode==4{owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id=$3 WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT,&original_dataset]).await.unwrap();}
                if mode==9{c.batch_execute("REVOKE SELECT ON openbot_internal.run_model_selection_v2_snapshots FROM PUBLIC").await.unwrap();}
                drop(c);drop(adapter);
            }
            drop(context);drop(directory);drop(models);drop(binding);drop(registry);drop(vault);
            let observations=p.connection_observations();p.close();let deadline=std::time::Instant::now()+Duration::from_secs(10);
            for o in observations{assert_eq!(o.wait_for_destruction_before(deadline).await.unwrap(),pool::ConnectionDestruction::ConnectionDestroyed);}Ok(())
        }).await;
    }

    // This producer stays inside Infra cfg(test). Its Vault counter must never be
    // presented as a counter in a Server/Desktop dependency build.
    struct ConcurrentAuthorityFixture {
        pool: pool::DatabasePool,
        vault: CredentialRecordVault,
        models: PostgresModelConnections,
        registry: Arc<ArtifactDatasetRegistry>,
        binding: Arc<PostgresModelDatasetBinding>,
        directory: PostgresThreadDirectory,
        context: PostgresAgentContextSource,
        auth: openbot_contracts::auth::AuthContext,
    }
    impl ConcurrentAuthorityFixture {
        async fn new(config: pool::DatabaseConfig) -> Self {
            Self::new_with_pool_size(config, 8).await
        }
        async fn new_with_pool_size(config: pool::DatabaseConfig, size: usize) -> Self {
            const DEP: &str = "owned-v2-concurrent-deployment";
            const TENANT: &str = "owned-v2-concurrent-tenant";
            let p = pool::connect(&config.clone().with_max_pool_size(size))
                .await
                .unwrap();
            let mut c = p.get().await.unwrap();
            fresh::apply(&mut c).await.unwrap();
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation)
                VALUES('alice','owned-concurrent-alice@example.test',7),('bob','owned-concurrent-bob@example.test',7);
                INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
                INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
                INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('bot','alice','Owned bot','','owned','public');
                INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups)
                VALUES('channel','Owned channel','',ARRAY[]::text[],ARRAY[]::text[]);
                INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');
                INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
            drop(c);
            let vault = CredentialRecordVault::single_key(
                TenantId::new(TENANT),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x78; 32]).unwrap(),
            );
            let models = PostgresModelConnections::new(
                p.clone(),
                vault.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                SecretBytes::new(vec![0x79; 32]),
            )
            .unwrap();
            let registry = Arc::new(
                ArtifactDatasetRegistry::from_server(
                    p.clone(),
                    &DeploymentId::new(DEP),
                    &TenantId::new(TENANT),
                )
                .await
                .unwrap(),
            );
            let binding = Arc::new(
                PostgresModelDatasetBinding::unbound(
                    p.clone(),
                    DeploymentId::new(DEP),
                    TenantId::new(TENANT),
                )
                .unwrap(),
            );
            binding.enroll_original_registry(&registry).unwrap();
            let directory = PostgresThreadDirectory::with_runtime(
                p.clone(),
                config,
                "owned-concurrent-runtime".into(),
                time::Duration::seconds(30),
            )
            .unwrap()
            .with_model_dataset_binding(binding.clone())
            .unwrap();
            let context = PostgresAgentContextSource::new(
                p.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                Some(32),
            )
            .unwrap()
            .with_model_dataset_binding(binding.clone())
            .unwrap();
            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                ActorId::new("alice"),
                AuthGeneration::new(7),
                false,
            )
            .with_roles([Role::User])
            .build();
            Self {
                pool: p,
                vault,
                models,
                registry,
                binding,
                directory,
                context,
                auth,
            }
        }
        async fn request(&self, index: u64, channel: bool) -> (Uuid, ProviderRequest) {
            let model = self
                .models
                .create(
                    &self.auth,
                    &CreateModelConnection {
                        name: "Owned concurrent selection".into(),
                        protocol: CustomModelProtocol::OpenaiChatCompletions,
                        endpoint: "https://owned-concurrent-no-network.example.test/v1".into(),
                        model: "owned-concurrent-model".into(),
                        enabled: true,
                        api_key: ModelApiKey::new(Zeroizing::new(
                            "OWNED_V2_CONCURRENT_VAULT_CANARY".into(),
                        ))
                        .unwrap(),
                    },
                )
                .await
                .unwrap();
            let mut entropy = [0u8; 16];
            entropy[8..].copy_from_slice(&index.to_be_bytes());
            let req = BeginThreadRunV2Request {
                deployment: self.auth.deployment().clone(),
                tenant: self.auth.tenant().clone(),
                actor: ActorId::new("alice"),
                auth_generation: AuthGeneration::new(7),
                command: BeginThreadRunV2 {
                    thread_id: ThreadIdentity::new(self.auth.deployment())
                        .mint_from_entropy(entropy),
                    run_id: RunId::new(format!("owned-concurrent-run-{index}")),
                    bot_id: BotId::new("bot"),
                    anchor: if channel {
                        ThreadRunAnchor::Channel {
                            channel_id: openbot_contracts::ids::ChannelId::new("channel"),
                        }
                    } else {
                        ThreadRunAnchor::DirectBot
                    },
                    message: "Owned concurrent selection words".into(),
                    selected_skill_slugs: vec![],
                    model_selection: RunModelSelectionV2::new(
                        ModelSelectionIntentSource::Custom,
                        model.id.clone(),
                        model.revision,
                        format!("custom:{}", model.id),
                        1,
                    )
                    .unwrap(),
                },
            };
            self.directory
                .begin_thread_run_v2(req.clone())
                .await
                .unwrap();
            let lease = RunExecutionLease::new(
                req.command.run_id,
                req.command.thread_id,
                req.command.bot_id,
                req.actor,
                FencingToken::new(1).unwrap(),
                0,
            )
            .unwrap();
            (
                Uuid::parse_str(&model.id).unwrap(),
                self.context.load(&lease).await.unwrap(),
            )
        }
        fn adapter(&self) -> (Arc<PostgresCustomModelProvider>, Arc<CountedDns>) {
            let dns = Arc::new(CountedDns(AtomicUsize::new(0)));
            let dialer = SafeDialer::with_resolver(
                crate::net::safe_http::EgressPolicy::default(),
                dns.clone(),
            );
            let adapter = PostgresCustomModelProvider::new(
                self.pool.clone(),
                self.vault.clone(),
                self.auth.deployment().clone(),
                self.auth.tenant().clone(),
                dialer,
                SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(5)).unwrap(),
                Some(Duration::from_secs(2)),
            )
            .unwrap()
            .with_model_dataset_binding(self.binding.clone())
            .unwrap();
            (Arc::new(adapter), dns)
        }
        async fn finish(self) {
            drop(self.context);
            drop(self.directory);
            drop(self.models);
            drop(self.binding);
            drop(self.registry);
            drop(self.vault);
            drop(self.auth);
            let observations = self.pool.connection_observations();
            self.pool.close();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            for o in observations {
                assert_eq!(
                    o.wait_for_destruction_before(deadline).await.unwrap(),
                    pool::ConnectionDestruction::ConnectionDestroyed
                );
            }
        }
    }

    async fn wait_owned_pg_wait(client: &pool::PooledClient, blocker: i32, needle: &str) -> i32 {
        let pattern = format!("%{needle}%");
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                if let Some(row)=client.query_opt("SELECT pid FROM pg_stat_activity
                    WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE $2
                    ORDER BY pid LIMIT 1",&[&blocker,&pattern]).await.unwrap() { return row.get(0); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("actual owned PG waiter reached the named original lock")
    }

    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; original provider Vault-call observations"]
    async fn final_current_revocation_after_connection_wait_refuses_before_actual_vault_and_dns() {
        let admin = super::v2_test_harness::admin_config("v2_final_current_wait");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(&admin,"v2finalcurrentwait",|config|async move {
            let f=ConcurrentAuthorityFixture::new(config).await;
            for channel in [false,true] {
                let (id,request)=f.request(600+u64::from(channel),channel).await;
                let (adapter,dns)=f.adapter();
                let mut blocker=f.pool.get().await.unwrap();
                let blocker_pid:i32=blocker.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get(0);
                let barrier=blocker.transaction().await.unwrap();
                barrier.query_one("SELECT id FROM public.model_connections WHERE id=$1 FOR UPDATE",&[&id]).await.unwrap();
                let task={let adapter=adapter.clone();tokio::spawn(async move {adapter.start(request).await})};
                let checker=f.pool.get().await.unwrap();
                wait_owned_pg_wait(&checker,blocker_pid,"FROM public.model_connections c").await;
                checker.execute("INSERT INTO public.revoked_access(email,revoked_by)
                    VALUES('owned-concurrent-alice@example.test','bob')",&[]).await.unwrap();
                barrier.commit().await.unwrap();
                let result=tokio::time::timeout(Duration::from_secs(3),task).await.unwrap().unwrap();
                assert!(matches!(result,Err(ProviderPortError::InvalidRequest{..})));
                assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0);
                assert_eq!(dns.0.load(Ordering::SeqCst),0);
                checker.execute("DELETE FROM public.revoked_access WHERE email='owned-concurrent-alice@example.test'",&[]).await.unwrap();
                drop(checker);drop(blocker);drop(adapter);
            }
            f.finish().await;Ok(())
        }).await;
    }

    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; current target row locks and original guard cancellation"]
    async fn target_and_membership_withdrawal_lock_order_cancel_and_successor_refuse_without_vault_or_dns()
     {
        let admin = super::v2_test_harness::admin_config("v2_target_current_wait");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(&admin,"v2targetcurrentwait",|config|async move {
            let f=ConcurrentAuthorityFixture::new(config).await;
            for (index,(channel,withdrawal_first)) in [(false,true),(true,true),(false,false),(true,false)].into_iter().enumerate() {
                let (id,request)=f.request(700+index as u64,channel).await;
                let (adapter,dns)=f.adapter();
                let statement=if channel {"DELETE FROM public.channel_memberships WHERE channel_id='channel' AND user_id='alice'"}
                    else {"UPDATE public.agent_profiles SET deleted_at=clock_timestamp() WHERE agent_id='bot'"};
                let checker=f.pool.get().await.unwrap();
                if withdrawal_first {
                    let mut revoker=f.pool.get().await.unwrap();
                    let revoker_pid:i32=revoker.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get(0);
                    let tx=revoker.transaction().await.unwrap();tx.execute(statement,&[]).await.unwrap();
                    let task={let adapter=adapter.clone();let request=request.clone();tokio::spawn(async move {adapter.start(request).await})};
                    wait_owned_pg_wait(&checker,revoker_pid,if channel {"FROM public.channels c"} else {"JOIN public.agent_profiles p"}).await;
                    tx.commit().await.unwrap();
                    assert!(matches!(tokio::time::timeout(Duration::from_secs(3),task).await.unwrap().unwrap(),Err(ProviderPortError::InvalidRequest{..})));
                    drop(revoker);
                } else {
                    let mut blocker=f.pool.get().await.unwrap();
                    let blocker_pid:i32=blocker.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get(0);
                    let barrier=blocker.transaction().await.unwrap();
                    barrier.query_one("SELECT id FROM public.model_connections WHERE id=$1 FOR UPDATE",&[&id]).await.unwrap();
                    let task={let adapter=adapter.clone();let request=request.clone();tokio::spawn(async move {adapter.start(request).await})};
                    let consumer_pid=wait_owned_pg_wait(&checker,blocker_pid,"FROM public.model_connections c").await;
                    let revoker=f.pool.get().await.unwrap();
                    let change=tokio::spawn(async move {revoker.execute(statement,&[]).await.unwrap()});
                    wait_owned_pg_wait(&checker,consumer_pid,if channel {"DELETE FROM public.channel_memberships"} else {"UPDATE public.agent_profiles"}).await;
                    // The withdrawal is still waiting on positive current authority; it
                    // has not committed. Cancellation drops the original guarded owner.
                    task.abort();assert!(matches!(task.await,Err(error)if error.is_cancelled()));
                    // Release the fixture barrier so the blocked original backend can
                    // observe EOF. Local cancellation is not its rollback ACK.
                    barrier.commit().await.unwrap();drop(blocker);
                    assert_eq!(tokio::time::timeout(Duration::from_secs(3),change).await.unwrap().unwrap(),1);
                    assert!(!f.pool.is_closed());
                    tokio::time::timeout(Duration::from_secs(3),async {
                        loop {
                            let ended:bool=checker.query_one("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid=$1)",&[&consumer_pid]).await.unwrap().get(0);
                            if ended{break;}
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }).await.expect("actual cancelled original backend ended before successor");
                    assert!(!f.pool.is_closed());
                    eprintln!("CUSTOM_V2_WITHDRAWAL_ORIGINAL_ENDED consumer_backend={consumer_pid} actual_backend_absent=true pool_open=true");
                }
                // This actual retry observes the now-committed withdrawal, without
                // treating cancellation/Drop or lock release as a rollback ACK.
                assert!(matches!(adapter.start(request).await,Err(ProviderPortError::InvalidRequest{..})));
                assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0);
                assert_eq!(dns.0.load(Ordering::SeqCst),0);
                if channel {checker.execute("INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice')",&[]).await.unwrap();}
                else {checker.execute("UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='bot'",&[]).await.unwrap();}
                drop(checker);drop(adapter);
            }
            f.finish().await;Ok(())
        }).await;
    }

    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; original start budget and actual Vault/DNS counters"]
    async fn original_connection_lock_budget_exhaustion_refuses_before_actual_vault_and_dns() {
        let admin = super::v2_test_harness::admin_config("v2_original_budget_wait");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(
            &admin,
            "v2originalbudgetwait",
            |config| async move {
                let f = ConcurrentAuthorityFixture::new(config).await;
                for channel in [false, true] {
                    let (id, request) = f.request(800 + u64::from(channel), channel).await;
                    let dns = Arc::new(CountedDns(AtomicUsize::new(0)));
                    let timeout = Duration::from_secs(1);
                    let adapter = Arc::new(
                        PostgresCustomModelProvider::new(
                            f.pool.clone(),
                            f.vault.clone(),
                            f.auth.deployment().clone(),
                            f.auth.tenant().clone(),
                            SafeDialer::with_resolver(
                                crate::net::safe_http::EgressPolicy::default(),
                                dns.clone(),
                            ),
                            SafeHttpBudget::new(64 * 1024 * 1024, timeout).unwrap(),
                            Some(Duration::from_secs(2)),
                        )
                        .unwrap()
                        .with_model_dataset_binding(f.binding.clone())
                        .unwrap(),
                    );
                    let mut blocker = f.pool.get().await.unwrap();
                    let blocker_pid: i32 = blocker
                        .query_one("SELECT pg_backend_pid()", &[])
                        .await
                        .unwrap()
                        .get(0);
                    let barrier = blocker.transaction().await.unwrap();
                    barrier
                        .query_one(
                            "SELECT id FROM public.model_connections WHERE id=$1 FOR UPDATE",
                            &[&id],
                        )
                        .await
                        .unwrap();
                    let started = std::time::Instant::now();
                    let task = {
                        let adapter = adapter.clone();
                        let request = request.clone();
                        tokio::spawn(async move { adapter.start(request).await })
                    };
                    let checker = f.pool.get().await.unwrap();
                    wait_owned_pg_wait(&checker, blocker_pid, "FROM public.model_connections c")
                        .await;
                    // Keep the actual original connection locked through its start budget.
                    // No fake clock, synthetic owner result, or substituted transaction is used.
                    let result = tokio::time::timeout(Duration::from_secs(3), task)
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(matches!(result, Err(ProviderPortError::Unavailable)));
                    assert!(started.elapsed() >= timeout.saturating_sub(Duration::from_millis(50)));
                    assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst), 0);
                    assert_eq!(dns.0.load(Ordering::SeqCst), 0);
                    barrier.commit().await.unwrap();
                    drop(blocker);
                    // The same real producer becomes usable once its owned lock is released.
                    // These actual calls establish that both zero counters are connected.
                    assert!(matches!(
                        adapter.start(request).await,
                        Err(ProviderPortError::CommitUnknown)
                    ));
                    assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst), 1);
                    assert_eq!(dns.0.load(Ordering::SeqCst), 1);
                    drop(checker);
                    drop(adapter);
                }
                // This fixture proves a real PG wait exhausting the original budget. It is
                // not an actual last-Ready-in-the-same-poll producer or any late PG ACK proof.
                f.finish().await;
                Ok(())
            },
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; original unselected context compatibility"]
    async fn configured_and_unconfigured_unselected_context_preserve_nonfixed_input_id_and_close_explicit_half()
     {
        let admin = super::v2_test_harness::admin_config("v2_legacy_unselected_context");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(&admin,"v2legacyunselectedcontext",|config|async move {
            let f=ConcurrentAuthorityFixture::new(config).await;
            let unconfigured=PostgresAgentContextSource::new(f.pool.clone(),f.auth.deployment().clone(),f.auth.tenant().clone(),Some(32)).unwrap();
            for fixed_input in [false,true] {
                let thread=openbot_contracts::ids::ThreadId::new(format!("owned-legacy-thread-{}",u8::from(fixed_input)));
                let run=RunId::new(format!("owned-legacy-run-{}",u8::from(fixed_input)));
                let message_id=if fixed_input {format!("{}:input",run.as_str())} else {"owned-legacy-message-1".into()};
                let c=f.pool.get().await.unwrap();
                c.execute("INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                    next_message_seq,next_event_seq,created_at,updated_at)
                    VALUES($1,$2,$3,'alice','direct_bot','bot','active',1,0,clock_timestamp(),clock_timestamp())",
                    &[&thread.as_str(),&f.auth.tenant().as_str(),&f.auth.deployment().as_str()]).await.unwrap();
                c.execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,'alice')",&[&thread.as_str()]).await.unwrap();
                c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,created_at,started_at)
                    VALUES($1,$2,'bot','alice',true,'running',1,0,clock_timestamp(),clock_timestamp())",&[&run.as_str(),&thread.as_str()]).await.unwrap();
                c.execute("INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at)
                    VALUES($1,$2,0,'user','{\"text\":\"Owned legacy no selection words\"}','Owned legacy no selection words',$3,'alice',clock_timestamp())",
                    &[&message_id,&thread.as_str(),&run.as_str()]).await.unwrap();
                let counts=c.query_one("SELECT
                    (SELECT count(*) FROM public.run_model_selections WHERE run_id=$1) AS v1,
                    (SELECT count(*) FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1) AS v2,
                    (SELECT count(*) FROM public.messages WHERE message_id=$1||':input') AS fixed_input",&[&run.as_str()]).await.unwrap();
                assert_eq!(counts.get::<_,i64>("v1"),0);assert_eq!(counts.get::<_,i64>("v2"),0);
                assert_eq!(counts.get::<_,i64>("fixed_input"),i64::from(fixed_input));drop(c);
                let lease=RunExecutionLease::new(run.clone(),thread.clone(),BotId::new("bot"),ActorId::new("alice"),FencingToken::new(1).unwrap(),0).unwrap();
                let legacy=unconfigured.load(&lease).await.unwrap();
                let configured=f.context.load(&lease).await.unwrap();
                assert!(matches!(&legacy.route,ProviderRoute::Managed));
                assert!(matches!(&configured.route,ProviderRoute::Managed));
                assert_eq!(legacy,configured,"configured classification preserves the complete real legacy projection");
                assert!(legacy.messages.iter().any(|message|
                    message.role==openbot_application::ProviderMessageRole::User && message.content=="Owned legacy no selection words"));

                // The same run becomes an explicit-selection half if an exact marker
                // exists without either snapshot. It must never take the None branch.
                let marker=serde_json::json!({"text":"Owned legacy no selection words","modelSelection":
                    RunModelSelectionV2::new(ModelSelectionIntentSource::Custom,"00000000-0000-4000-8000-000000000001".into(),1,
                        "custom:00000000-0000-4000-8000-000000000001".into(),1).unwrap()});
                let c=f.pool.get().await.unwrap();
                if fixed_input {
                    c.execute("UPDATE public.messages SET content=$2 WHERE message_id=$1",&[&message_id,&marker]).await.unwrap();
                } else {
                    c.execute("INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at)
                        VALUES($1||':input',$2,1,'user',$3,'Owned explicit half',$1,'alice',clock_timestamp())",
                        &[&run.as_str(),&thread.as_str(),&marker]).await.unwrap();
                }
                drop(c);
                assert!(matches!(unconfigured.load(&lease).await,Err(AgentContextError::Corrupt{..})));
                assert!(matches!(f.context.load(&lease).await,Err(AgentContextError::Corrupt{..})));
            }
            drop(unconfigured);f.finish().await;Ok(())
        }).await;
    }

    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; Server lineage and actual Vault/DNS observers"]
    async fn server_tuple_prefix_namespace_and_shape_drift_refuse_before_actual_vault_and_dns() {
        let admin = super::v2_test_harness::admin_config("v2_server_lineage_vault");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(&admin,"v2serverlineagevault",|config|async move {
            let f=ConcurrentAuthorityFixture::new(config).await;
            let c=f.pool.get().await.unwrap();
            let original=c.query_one("SELECT * FROM openbot_internal.artifact_dataset_bindings
                WHERE deployment_id=$1 AND tenant_id=$2",&[&f.auth.deployment().as_str(),&f.auth.tenant().as_str()]).await.unwrap();
            let deployment:String=original.get("deployment_id");let tenant:String=original.get("tenant_id");
            let dataset:String=original.get("dataset_id");let schema:i16=original.get("binding_schema");
            let origin:String=original.get("initial_origin");let created:time::OffsetDateTime=original.get("created_at");
            assert_eq!(schema,1);assert_eq!(origin,"server_first_adoption");
            let original_tuple:serde_json::Value=c.query_one("SELECT to_jsonb(b) FROM openbot_internal.artifact_dataset_bindings b WHERE deployment_id=$1 AND tenant_id=$2",&[&deployment,&tenant]).await.unwrap().get(0);
            let original_ledger:serde_json::Value=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM openbot_internal.schema_migrations m",&[]).await.unwrap().get(0);
            let original_checksum:String=c.query_one("SELECT checksum FROM openbot_internal.schema_migrations WHERE version=47",&[]).await.unwrap().get(0);
            let original_constraint:String=c.query_one("SELECT pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint WHERE conrelid='openbot_internal.artifact_dataset_bindings'::regclass AND conname='artifact_dataset_bindings_schema_known'",&[]).await.unwrap().get(0);
            let original_private=crate::db::custom_model_v2_schema::capture(&c).await.unwrap();drop(c);
            for mode in 0..10u64 {
                let (_,request)=f.request(1000+mode,mode%2==1).await;
                let (adapter,dns)=f.adapter();let c=f.pool.get().await.unwrap();
                match mode {
                    0=>{owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET deployment_id='owned-current-wrong-deployment' WHERE deployment_id=$1 AND tenant_id=$2",&[&deployment,&tenant]).await.unwrap();},
                    1=>{owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET tenant_id='owned-current-wrong-tenant' WHERE deployment_id=$1 AND tenant_id=$2",&[&deployment,&tenant]).await.unwrap();},
                    2=>{owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id='owned-current-wrong-dataset' WHERE deployment_id=$1 AND tenant_id=$2",&[&deployment,&tenant]).await.unwrap();},
                    3=>{owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET initial_origin='desktop_canary' WHERE deployment_id=$1 AND tenant_id=$2",&[&deployment,&tenant]).await.unwrap();},
                    4=>{owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET created_at=created_at+interval '1 second' WHERE deployment_id=$1 AND tenant_id=$2",&[&deployment,&tenant]).await.unwrap();},
                    5=>{c.execute("UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=47",&[]).await.unwrap();},
                    6=>{c.execute("INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(48,'owned_unknown_native_version',repeat('0',64))",&[]).await.unwrap();},
                    7=>{c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings RENAME TO owned_v2_fault_namespace").await.unwrap();},
                    8=>{c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings RENAME CONSTRAINT artifact_dataset_bindings_schema_known TO owned_v2_fault_constraint").await.unwrap();},
                    _=>{c.batch_execute("ALTER TABLE openbot_internal.run_model_selection_v2_snapshots RENAME CONSTRAINT run_model_selection_v2_snapshots_protocol_check TO owned_v2_fault_snapshot_protocol").await.unwrap();},
                }
                let result=adapter.start(request.clone()).await;
                assert!(matches!(result,Err(ProviderPortError::InvalidRequest{..})),"real Server current-lineage fault {mode}");
                assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0,"original Vault call on fault {mode}");
                assert_eq!(dns.0.load(Ordering::SeqCst),0,"actual DNS on fault {mode}");
                match mode {
                    0..=4=>{
                        let current_deployment=if mode==0 {"owned-current-wrong-deployment"} else {deployment.as_str()};
                        let current_tenant=if mode==1 {"owned-current-wrong-tenant"} else {tenant.as_str()};
                        owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings
                            SET deployment_id=$3,tenant_id=$4,dataset_id=$5,binding_schema=$6,initial_origin=$7,created_at=$8
                            WHERE deployment_id=$1 AND tenant_id=$2",
                            &[&current_deployment,&current_tenant,&deployment,&tenant,&dataset,&schema,&origin,&created]).await.unwrap();
                    },
                    5=>{c.execute("UPDATE openbot_internal.schema_migrations SET checksum=$1 WHERE version=47",&[&original_checksum]).await.unwrap();},
                    6=>{c.execute("DELETE FROM openbot_internal.schema_migrations WHERE version=48",&[]).await.unwrap();},
                    7=>{c.batch_execute("ALTER TABLE openbot_internal.owned_v2_fault_namespace RENAME TO artifact_dataset_bindings").await.unwrap();},
                    8=>{c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings RENAME CONSTRAINT owned_v2_fault_constraint TO artifact_dataset_bindings_schema_known").await.unwrap();},
                    _=>{c.batch_execute("ALTER TABLE openbot_internal.run_model_selection_v2_snapshots RENAME CONSTRAINT owned_v2_fault_snapshot_protocol TO run_model_selection_v2_snapshots_protocol_check").await.unwrap();},
                }
                let restored_tuple:serde_json::Value=c.query_one("SELECT to_jsonb(b) FROM openbot_internal.artifact_dataset_bindings b WHERE deployment_id=$1 AND tenant_id=$2",&[&deployment,&tenant]).await.unwrap().get(0);
                assert_eq!(restored_tuple,original_tuple);
                let restored_ledger:serde_json::Value=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM openbot_internal.schema_migrations m",&[]).await.unwrap().get(0);
                assert_eq!(restored_ledger,original_ledger);
                assert_eq!(crate::db::custom_model_v2_schema::capture(&c).await.unwrap(),original_private);
                crate::db::custom_model_v2_schema::verify(&c).await.unwrap();
                assert_eq!(c.query_one("SELECT pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint WHERE conrelid='openbot_internal.artifact_dataset_bindings'::regclass AND conname='artifact_dataset_bindings_schema_known'",&[]).await.unwrap().get::<_,String>(0),original_constraint);drop(c);
                // The original snapshot and producer regain exactly their real current
                // authority after the owned test fault is restored; no remint/repair.
                assert!(matches!(adapter.start(request).await,Err(ProviderPortError::CommitUnknown)));
                assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),1);
                assert_eq!(dns.0.load(Ordering::SeqCst),1);drop(adapter);
            }
            // These are original from_server legs. A changed origin string is a
            // refusal case, never a claim to genuine PreparedLocal/canary adoption.
            f.finish().await;Ok(())
        }).await;
    }

    // The selector identifies the actual last-authority statement from the frozen
    // source. It is not an authority oracle, result replacement or a second query.
    const LAST_AUTHORITY_SQL_SHA256: &str =
        "83f8da58bb0c955b5e185584e6b292c4b1e50593062bcc700921c1c6cc88ccc0";

    #[derive(Default)]
    struct LastReadyRelayCounts {
        accepted: AtomicUsize,
        joined: AtomicUsize,
        parsed: AtomicUsize,
        bound: AtomicUsize,
        executed: AtomicUsize,
        held: AtomicUsize,
        released: AtomicUsize,
        bind_held: AtomicUsize,
        bind_released: AtomicUsize,
        listener_closed: AtomicBool,
    }
    struct LastReadyHeld {
        backend_pid: i32,
        query_bytes: usize,
        parameter_count: u16,
        held_bytes: usize,
        bind_held_bytes: usize,
    }
    #[derive(Default)]
    struct LastReadySelection {
        statement: Option<Vec<u8>>,
        portal: Option<Vec<u8>>,
        query_bytes: usize,
        parameter_count: u16,
    }
    struct LastReadyRelayControl {
        armed: AtomicBool,
        counts: LastReadyRelayCounts,
        held: Mutex<Option<oneshot::Sender<LastReadyHeld>>>,
        release: Mutex<Option<oneshot::Receiver<()>>>,
        bind_release: Mutex<Option<oneshot::Receiver<()>>>,
        bind_forwarded: Mutex<Option<oneshot::Sender<()>>>,
    }
    struct LastAuthorityReadyRelay {
        config: pool::DatabaseConfig,
        control: Arc<LastReadyRelayControl>,
        held: Option<oneshot::Receiver<LastReadyHeld>>,
        release: Option<oneshot::Sender<()>>,
        bind_release: Option<oneshot::Sender<()>>,
        bind_forwarded: Option<oneshot::Receiver<()>>,
        stop: Option<oneshot::Sender<()>>,
        task: Option<JoinHandle<()>>,
    }
    impl LastAuthorityReadyRelay {
        async fn new(config: &pool::DatabaseConfig) -> Self {
            assert_eq!(config.host, "127.0.0.1");
            let upstream = SocketAddr::from(([127, 0, 0, 1], config.port));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut routed = config.clone();
            routed.port = listener.local_addr().unwrap().port();
            assert!(![39025, 39027].contains(&routed.port));
            let (held_tx, held_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let (bind_release_tx, bind_release_rx) = oneshot::channel();
            let (bind_forwarded_tx, bind_forwarded_rx) = oneshot::channel();
            let control = Arc::new(LastReadyRelayControl {
                armed: AtomicBool::new(false),
                counts: LastReadyRelayCounts::default(),
                held: Mutex::new(Some(held_tx)),
                release: Mutex::new(Some(release_rx)),
                bind_release: Mutex::new(Some(bind_release_rx)),
                bind_forwarded: Mutex::new(Some(bind_forwarded_tx)),
            });
            let c = control.clone();
            let (stop, mut stopped) = oneshot::channel();
            let task = tokio::spawn(async move {
                let mut children = JoinSet::new();
                loop {
                    tokio::select! {
                        _=&mut stopped=>break,
                        accepted=listener.accept()=>{
                            let(downstream,_)=accepted.expect("owned D1 listener accept");
                            let accepted=c.counts.accepted.fetch_add(1,Ordering::SeqCst)+1;
                            assert!(accepted<=2,"D1 only original and original-manager successor may connect");
                            let c=c.clone();children.spawn(last_ready_relay_connection(downstream,upstream,c));
                        },
                        Some(joined)=children.join_next(),if !children.is_empty()=>{
                            joined.expect("owned D1 relay child normal join").expect("owned D1 relay protocol");
                            c.counts.joined.fetch_add(1,Ordering::SeqCst);
                        }
                    }
                }
                drop(listener);
                c.counts.listener_closed.store(true, Ordering::SeqCst);
                // Successful cleanup requires actual normal child joins. No abort is
                // counted as EOF, connection retirement or a successful relay join.
                tokio::time::timeout(Duration::from_secs(3), async {
                    while let Some(joined) = children.join_next().await {
                        joined
                            .expect("owned D1 relay child normal join")
                            .expect("owned D1 relay protocol");
                        c.counts.joined.fetch_add(1, Ordering::SeqCst);
                    }
                })
                .await
                .expect("owned D1 relay children naturally ended");
                assert_eq!(
                    c.counts.accepted.load(Ordering::SeqCst),
                    c.counts.joined.load(Ordering::SeqCst)
                );
            });
            Self {
                config: routed,
                control,
                held: Some(held_rx),
                release: Some(release_tx),
                bind_release: Some(bind_release_tx),
                bind_forwarded: Some(bind_forwarded_rx),
                stop: Some(stop),
                task: Some(task),
            }
        }
        async fn stop(mut self) {
            self.stop
                .take()
                .unwrap()
                .send(())
                .expect("owned D1 listener still live");
            self.task
                .take()
                .unwrap()
                .await
                .expect("owned D1 listener normal join");
            assert!(self.control.counts.listener_closed.load(Ordering::SeqCst));
            let accepted = self.control.counts.accepted.load(Ordering::SeqCst);
            assert_eq!(
                accepted, 2,
                "one original backend and one original-manager successor"
            );
            assert_eq!(self.control.counts.joined.load(Ordering::SeqCst), accepted);
            assert_eq!(self.control.counts.bind_held.load(Ordering::SeqCst), 1);
            assert_eq!(self.control.counts.bind_released.load(Ordering::SeqCst), 1);
            eprintln!(
                "CUSTOM_V2_D1_RELAY_CLOSED accepted={accepted} joined={accepted} listener_closed=true all_children_normal=true"
            );
        }
    }
    impl Drop for LastAuthorityReadyRelay {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            // Panic/failure fallback only; stop() must take and normally join this
            // handle before any success marker. Abort never supplies a PASS fact.
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }
    fn last_ready_cstring<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a [u8], &'static str> {
        let end = bytes
            .get(*at..)
            .ok_or("D1 cstring offset")?
            .iter()
            .position(|b| *b == 0)
            .ok_or("D1 cstring termination")?;
        let result = &bytes[*at..*at + end];
        *at += end + 1;
        Ok(result)
    }
    fn last_ready_u16(bytes: &[u8], at: &mut usize) -> Result<u16, &'static str> {
        let value = bytes.get(*at..*at + 2).ok_or("D1 u16 truncation")?;
        *at += 2;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }
    fn last_ready_bind_shape(bytes: &[u8], mut at: usize) -> Result<u16, &'static str> {
        let formats = usize::from(last_ready_u16(bytes, &mut at)?);
        at = at
            .checked_add(formats * 2)
            .ok_or("D1 bind format overflow")?;
        let parameters = last_ready_u16(bytes, &mut at)?;
        for _ in 0..parameters {
            let length = bytes.get(at..at + 4).ok_or("D1 bind length truncation")?;
            at += 4;
            let length = i32::from_be_bytes([length[0], length[1], length[2], length[3]]);
            if length < -1 {
                return Err("D1 bind negative length");
            }
            if length >= 0 {
                at = at
                    .checked_add(length as usize)
                    .ok_or("D1 bind parameter overflow")?;
            }
            if at > bytes.len() {
                return Err("D1 bind parameter truncation");
            }
        }
        if last_ready_u16(bytes, &mut at)? != 1
            || last_ready_u16(bytes, &mut at)? != 1
            || at != bytes.len()
        {
            return Err("D1 original binary result format required");
        }
        if parameters != 22 {
            return Err("D1 original last-authority parameter count");
        }
        Ok(parameters)
    }
    async fn last_ready_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> Result<Option<(u8, Vec<u8>)>, &'static str> {
        let tag = match reader.read_u8().await {
            Ok(tag) => tag,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(_) => return Err("D1 frame tag IO"),
        };
        let length = reader.read_u32().await.map_err(|_| "D1 frame length IO")?;
        if !(4..=8 * 1024 * 1024).contains(&length) {
            return Err("D1 frame length bound");
        }
        let mut bytes = vec![0; length as usize - 4];
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| "D1 frame payload IO")?;
        Ok(Some((tag, bytes)))
    }
    fn last_ready_wire_frame(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(bytes.len() + 5);
        frame.push(tag);
        frame.extend_from_slice(&(bytes.len() as u32 + 4).to_be_bytes());
        frame.extend_from_slice(bytes);
        frame
    }
    async fn last_ready_relay_connection(
        mut downstream: TcpStream,
        upstream: SocketAddr,
        control: Arc<LastReadyRelayControl>,
    ) -> Result<(), &'static str> {
        use sha2::Digest;
        let mut upstream = TcpStream::connect(upstream)
            .await
            .map_err(|_| "D1 upstream connect")?;
        let length = downstream
            .read_u32()
            .await
            .map_err(|_| "D1 startup length")?;
        if !(8..=65536).contains(&length) {
            return Err("D1 startup bound");
        }
        let mut startup = vec![0; length as usize - 4];
        downstream
            .read_exact(&mut startup)
            .await
            .map_err(|_| "D1 startup payload")?;
        // The original NoTls owned connection is forwarded unchanged. Cancel and
        // SSL negotiation are not silently accepted as an inference PG session.
        if startup[..4] != 196608_u32.to_be_bytes() {
            return Err("D1 original protocol startup required");
        }
        upstream
            .write_u32(length)
            .await
            .map_err(|_| "D1 startup forward length")?;
        upstream
            .write_all(&startup)
            .await
            .map_err(|_| "D1 startup forward payload")?;
        let (mut down_read, mut down_write) = downstream.into_split();
        let (mut up_read, mut up_write) = upstream.into_split();
        let selection = Arc::new(Mutex::new(LastReadySelection::default()));
        let executed = Arc::new(AtomicBool::new(false));
        let backend = Arc::new(std::sync::atomic::AtomicI32::new(0));
        let client_control = control.clone();
        let client_selection = selection.clone();
        let client_executed = executed.clone();
        let client = async move {
            while let Some((tag, bytes)) = last_ready_frame(&mut down_read).await? {
                if tag == b'P' {
                    let mut at = 0;
                    let statement = last_ready_cstring(&bytes, &mut at)?;
                    let sql = last_ready_cstring(&bytes, &mut at)?;
                    let hash = format!("{:x}", sha2::Sha256::digest(sql));
                    if hash == LAST_AUTHORITY_SQL_SHA256
                        && client_control.armed.swap(false, Ordering::SeqCst)
                    {
                        let mut selected =
                            client_selection.lock().map_err(|_| "D1 selection lock")?;
                        if selected.statement.is_some() {
                            return Err("D1 duplicate selected Parse");
                        }
                        selected.statement = Some(statement.to_vec());
                        selected.query_bytes = sql.len();
                        client_control.counts.parsed.fetch_add(1, Ordering::SeqCst);
                    }
                } else if tag == b'B' {
                    let mut at = 0;
                    let portal = last_ready_cstring(&bytes, &mut at)?;
                    let statement = last_ready_cstring(&bytes, &mut at)?;
                    let mut selected = client_selection.lock().map_err(|_| "D1 selection lock")?;
                    if selected.statement.as_deref() == Some(statement) {
                        if selected.portal.is_some() {
                            return Err("D1 duplicate selected Bind");
                        }
                        selected.parameter_count = last_ready_bind_shape(&bytes, at)?;
                        selected.portal = Some(portal.to_vec());
                        client_control.counts.bound.fetch_add(1, Ordering::SeqCst);
                    }
                } else if tag == b'E' {
                    let mut at = 0;
                    let portal = last_ready_cstring(&bytes, &mut at)?;
                    let selected = client_selection.lock().map_err(|_| "D1 selection lock")?;
                    if selected.portal.as_deref() == Some(portal) {
                        if bytes.get(at..) != Some(&[0, 0, 0, 0][..])
                            || client_executed.swap(true, Ordering::SeqCst)
                        {
                            return Err("D1 original single unlimited Execute required");
                        }
                        client_control
                            .counts
                            .executed
                            .fetch_add(1, Ordering::SeqCst);
                    }
                }
                up_write
                    .write_all(&last_ready_wire_frame(tag, &bytes))
                    .await
                    .map_err(|_| "D1 client frame forward")?;
            }
            up_write
                .shutdown()
                .await
                .map_err(|_| "D1 upstream write shutdown")?;
            Ok::<(), &'static str>(())
        };
        let server = async move {
            let mut bind_complete = None;
            while let Some((tag, bytes)) = last_ready_frame(&mut up_read).await? {
                if tag == b'K' {
                    if bytes.len() != 8 {
                        return Err("D1 BackendKeyData shape");
                    }
                    backend.store(
                        i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                        Ordering::SeqCst,
                    );
                }
                if tag == b'2'
                    && selection
                        .lock()
                        .map_err(|_| "D1 selection lock")?
                        .portal
                        .is_some()
                {
                    // Keep the selected original BindComplete separate from the original 32B result.
                    if !bytes.is_empty()
                        || bind_complete
                            .replace(last_ready_wire_frame(tag, &bytes))
                            .is_some()
                    {
                        return Err("D1 single original empty BindComplete required");
                    }
                    control.counts.bind_held.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                if executed.load(Ordering::SeqCst) && tag == b'D' {
                    // Original binary bool true; these are actual server bytes,
                    // retained without constructing an ACK or substituting a Row.
                    if bytes != [0, 1, 0, 0, 0, 1, 1] {
                        return Err("D1 last current row must be actual true");
                    }
                    let mut held = last_ready_wire_frame(tag, &bytes);
                    let (command, command_bytes) = last_ready_frame(&mut up_read)
                        .await?
                        .ok_or("D1 actual CommandComplete missing")?;
                    if command != b'C' || command_bytes != b"SELECT 1\0" {
                        return Err("D1 exact actual last CommandComplete required");
                    }
                    held.extend_from_slice(&last_ready_wire_frame(command, &command_bytes));
                    let (ready, ready_bytes) = last_ready_frame(&mut up_read)
                        .await?
                        .ok_or("D1 actual ReadyForQuery missing")?;
                    if ready != b'Z' || ready_bytes != b"T" {
                        return Err("D1 original in-transaction ReadyForQuery required");
                    }
                    held.extend_from_slice(&last_ready_wire_frame(ready, &ready_bytes));
                    let bind = bind_complete
                        .take()
                        .ok_or("D1 actual BindComplete missing")?;
                    if bind.len() != 5 {
                        return Err("D1 original BindComplete must be 5B");
                    }
                    let metadata = {
                        let selected = selection.lock().map_err(|_| "D1 selection lock")?;
                        LastReadyHeld {
                            backend_pid: backend.load(Ordering::SeqCst),
                            query_bytes: selected.query_bytes,
                            parameter_count: selected.parameter_count,
                            held_bytes: held.len(),
                            bind_held_bytes: bind.len(),
                        }
                    };
                    if metadata.backend_pid <= 0 {
                        return Err("D1 original backend identity missing");
                    }
                    let held_sender = control
                        .held
                        .lock()
                        .map_err(|_| "D1 held lock")?
                        .take()
                        .ok_or("D1 duplicate gate capture")?;
                    let release = {
                        control
                            .release
                            .lock()
                            .map_err(|_| "D1 release lock")?
                            .take()
                            .ok_or("D1 duplicate gate release")?
                    };
                    let bind_release = control
                        .bind_release
                        .lock()
                        .map_err(|_| "D1 bind release lock")?
                        .take()
                        .ok_or("D1 duplicate bind release")?;
                    let bind_forwarded = control
                        .bind_forwarded
                        .lock()
                        .map_err(|_| "D1 bind forward lock")?
                        .take()
                        .ok_or("D1 duplicate bind forward observer")?;
                    // One unchanged total 8s gate covers BOTH actual releases, starting before metadata.
                    let gate_deadline = tokio::time::Instant::now() + Duration::from_secs(8);
                    control.counts.held.fetch_add(1, Ordering::SeqCst);
                    held_sender
                        .send(metadata)
                        .map_err(|_| "D1 actual gate observer dropped")?;
                    tokio::time::timeout_at(gate_deadline, bind_release)
                        .await
                        .map_err(|_| "D1 actual bind release budget exhausted")?
                        .map_err(|_| "D1 actual bind release dropped")?;
                    down_write
                        .write_all(&bind)
                        .await
                        .map_err(|_| "D1 original BindComplete forward")?;
                    control.counts.bind_released.fetch_add(1, Ordering::SeqCst);
                    eprintln!(
                        "CUSTOM_V2_D1_TRACE released_original_bind_bytes={}",
                        bind.len()
                    );
                    // This observes the original write only; it is not a SQL/consumer ACK.
                    bind_forwarded
                        .send(())
                        .map_err(|_| "D1 bind write observer dropped")?;
                    tokio::time::timeout_at(gate_deadline, release)
                        .await
                        .map_err(|_| "D1 actual gate release budget exhausted")?
                        .map_err(|_| "D1 actual gate release dropped")?;
                    down_write
                        .write_all(&held)
                        .await
                        .map_err(|_| "D1 held original frames forward")?;
                    eprintln!("CUSTOM_V2_D1_TRACE released_original_bytes={}", held.len());
                    executed.store(false, Ordering::SeqCst);
                    control.counts.released.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                if executed.load(Ordering::SeqCst) && matches!(tag, b'E' | b'C') {
                    return Err("D1 target execution failed or completed without its actual row");
                }
                // Parse/Describe/Sync can yield its earlier Z(T), and preceding
                // Statement Drop can yield CloseComplete. Neither selects this gate.
                down_write
                    .write_all(&last_ready_wire_frame(tag, &bytes))
                    .await
                    .map_err(|_| "D1 server frame forward")?;
            }
            down_write
                .shutdown()
                .await
                .map_err(|_| "D1 downstream write shutdown")?;
            Ok::<(), &'static str>(())
        };
        tokio::try_join!(client, server)?;
        Ok(())
    }
    struct LastReadyWake {
        generation: AtomicUsize,
        changed: watch::Sender<usize>,
    }
    impl std::task::Wake for LastReadyWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
            self.changed.send_replace(generation);
        }
    }
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires explicitly owned PG17; genuine original last SQL Ready after unchanged budget"]
    async fn original_last_authority_ready_in_same_poll_after_budget_refuses_before_vault_and_dns()
    {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        let admin = super::v2_test_harness::admin_config("v2_last_ready_same_poll");
        assert_eq!(admin.host, "127.0.0.1");
        super::v2_test_harness::with_temp_database(&admin,"v2lastreadysamepoll",|config|async move {
            let mut relay=LastAuthorityReadyRelay::new(&config).await;
            let f=ConcurrentAuthorityFixture::new_with_pool_size(relay.config.clone(),1).await;
            assert_eq!(f.pool.status().max_size,1);
            let(_,request)=f.request(1200,false).await;
            let(adapter,dns)=f.adapter();
            assert!(std::ptr::eq(f.pool.manager(),adapter.pool.manager()));
            let c=f.pool.get().await.unwrap();
            let backend:i32=c.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get(0);
            let original=c.observation();drop(c);
            assert_eq!(relay.control.counts.accepted.load(Ordering::SeqCst),1);
            relay.control.armed.store(true,Ordering::SeqCst);
            let(changed,mut changes)=watch::channel(0usize);
            let wake=Arc::new(LastReadyWake{generation:AtomicUsize::new(0),changed});
            let waker=Waker::from(wake.clone());let mut cx=Context::from_waker(&waker);
            let mut started=adapter.start(request.clone());
            let mut original_polls=0usize;
            let mut held=relay.held.take().unwrap();
            let first_poll_before=std::time::Instant::now();
            let metadata=tokio::time::timeout(Duration::from_secs(4),async {
                loop {
                    original_polls+=1;
                    assert!(matches!(Future::poll(started.as_mut(),&mut cx),Poll::Pending),"original start completed before actual last-authority gate");
                    tokio::select! {
                        actual=&mut held=>break actual.expect("original actual last-authority gate"),
                        changed=changes.changed()=>changed.expect("original business waker live"),
                    }
                }
            }).await.expect("original start reached actual last SQL within its original budget");
            assert_eq!(metadata.backend_pid,backend);assert_eq!(metadata.query_bytes,2936);
            assert_eq!(metadata.parameter_count,22);assert_eq!(metadata.held_bytes,32);
            assert_eq!(adapter.v2_expired_last_authority_ready.load(Ordering::SeqCst),0);
            assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0);assert_eq!(dns.0.load(Ordering::SeqCst),0);
            assert!(!original.snapshot().retirement_requested && !original.snapshot().connection_destroyed);
            assert_eq!(metadata.bind_held_bytes,5);
            // A fresh Waker excludes delayed notifications from preceding requests.
            // The same pinned future still waits for the selected original BindComplete.
            let(changed,mut changes)=watch::channel(0usize);
            let wake=Arc::new(LastReadyWake{generation:AtomicUsize::new(0),changed});
            let waker=Waker::from(wake.clone());let mut cx=Context::from_waker(&waker);
            let original_preexpiry_deadline=tokio::time::Instant::from_std(first_poll_before+adapter.connect_budget.timeout());
            assert!(first_poll_before.elapsed()<adapter.connect_budget.timeout());
            original_polls+=1;
            assert!(matches!(Future::poll(started.as_mut(),&mut cx),Poll::Pending),"unforwarded original BindComplete must keep the same future Pending");
            assert!(first_poll_before.elapsed()<adapter.connect_budget.timeout());
            assert_eq!(wake.generation.load(Ordering::SeqCst),0,"fresh receiver waker must not have fired before original BindComplete release");
            relay.bind_release.take().unwrap().send(()).expect("original actual BindComplete gate live");
            let wait_deadline=original_preexpiry_deadline.min(tokio::time::Instant::now()+Duration::from_secs(2));
            tokio::time::timeout_at(wait_deadline,relay.bind_forwarded.take().unwrap()).await.unwrap().unwrap();
            tokio::time::timeout_at(wait_deadline,changes.changed()).await.unwrap().unwrap();
            assert!(first_poll_before.elapsed()<adapter.connect_budget.timeout());
            assert!(wake.generation.load(Ordering::SeqCst)>0);
            original_polls+=1;
            assert!(matches!(Future::poll(started.as_mut(),&mut cx),Poll::Pending),"consumed original BindComplete must reach the held RowStream Pending");
            assert!(first_poll_before.elapsed()<adapter.connect_budget.timeout());
            assert_eq!(adapter.v2_expired_last_authority_ready.load(Ordering::SeqCst),0);
            assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0);assert_eq!(dns.0.load(Ordering::SeqCst),0);
            eprintln!("CUSTOM_V2_D1_TRACE bind_consumed_unexpired_polls={original_polls} fresh_wake={} elapsed_us={} bind_held_bytes={} result_held_bytes={}",wake.generation.load(Ordering::SeqCst),first_poll_before.elapsed().as_micros(),metadata.bind_held_bytes,metadata.held_bytes);
            let polls_at_hold=original_polls;
            let held_at=std::time::Instant::now();
            // No business poll occurs here. This is a conservative natural wall-time
            // wait after the original entry, not a new budget, fake clock or SQLReady.
            tokio::time::sleep(adapter.connect_budget.timeout()+Duration::from_millis(100)).await;
            assert!(held_at.elapsed()>adapter.connect_budget.timeout());
            assert_eq!(original_polls,polls_at_hold,"same business future was not polled during natural expiry");
            changes.borrow_and_update();
            eprintln!("CUSTOM_V2_D1_TRACE before_release_polls={original_polls} wake_generation={} elapsed_us={}",wake.generation.load(Ordering::SeqCst),first_poll_before.elapsed().as_micros());
            relay.release.take().unwrap().send(()).expect("original actual held frames released");
            tokio::time::timeout(Duration::from_secs(2),changes.changed()).await.unwrap().unwrap();
            eprintln!("CUSTOM_V2_D1_TRACE wake_after_release={} elapsed_us={}",wake.generation.load(Ordering::SeqCst),first_poll_before.elapsed().as_micros());
            // A wake/socket write supplies scheduling only. This ONE resumed poll
            // must itself reach the actual load Ok continuation and observe expiry.
            original_polls+=1;
            let result=match Future::poll(started.as_mut(),&mut cx) {
                Poll::Ready(result)=>Some(result),
                Poll::Pending=>None,
            };
            let expired_ready=adapter.v2_expired_last_authority_ready.load(Ordering::SeqCst);
            let vault_opens=adapter.v2_vault_opens.load(Ordering::SeqCst);let dns_calls=dns.0.load(Ordering::SeqCst);
            let proof=if result.is_none(){Err("actual same-poll Ready was not reached; do not retry this proof")}
                else if !matches!(&result,Some(Err(ProviderPortError::Unavailable))){Err("original same-poll result was not pre-effect Unavailable")}
                else if expired_ready!=1{Err("outer timeout with observer0 is not a same-poll regression proof")}
                else if vault_opens!=0 || dns_calls!=0{Err("late original SQLReady reached actual Vault or DNS")}
                else{Ok(())};
            assert_eq!(original_polls,polls_at_hold+1,"exactly one original business poll after release");
            // An unexpectedly delivered session is dropped before original-owner
            // retirement and cannot escape through a failed regression proof.
            drop(result);
            drop(started);
            assert!(!f.pool.is_closed());
            assert_eq!(original.wait_for_destruction_before(std::time::Instant::now()+Duration::from_secs(3)).await.unwrap(),pool::ConnectionDestruction::ConnectionDestroyed);
            let original_state=original.snapshot();assert!(original_state.retirement_requested && original_state.connection_destroyed);
            assert!(!f.pool.is_closed(),"original retirement observed before Pool.close");
            // The successor belongs to the same original manager. Its real PG view
            // separately proves that the original backend has ended; local Drop alone
            // is not relabeled as remote PG termination or a rollback ACK.
            let successor=f.pool.get().await.unwrap();
            let successor_pid:i32=successor.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get(0);
            assert_ne!(successor_pid,backend);
            tokio::time::timeout(Duration::from_secs(2),async {
                loop {
                    let ended:bool=successor.query_one("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid=$1)",&[&backend]).await.unwrap().get(0);
                    if ended{break;}
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("actual original backend ended before Pool.close");drop(successor);
            for count in [&relay.control.counts.parsed,&relay.control.counts.bound,&relay.control.counts.executed,&relay.control.counts.held,&relay.control.counts.released,&relay.control.counts.bind_held,&relay.control.counts.bind_released] {
                assert_eq!(count.load(Ordering::SeqCst),1);
            }
            if let Err(error)=proof {
                eprintln!("CUSTOM_V2_D1_PROOF_FAILED actual_expired_load_ready={expired_ready} vault={vault_opens} dns={dns_calls} resumed_polls=1 reason={error}");
                // The failed same-poll case stays failed even if normal owned
                // cleanup succeeds. No second business poll or fresh positive is
                // used to make observer0 appear accepted.
                drop(adapter);f.finish().await;relay.stop().await;return Err(error.to_owned());
            }
            eprintln!("CUSTOM_V2_D1_LAST_READY query_sha256={LAST_AUTHORITY_SQL_SHA256} original_backend={backend} successor_backend={successor_pid} parsed=1 bound=1 executed=1 actual_binary_true_rows=1 command=SELECT_1 ready=T held_bytes=32 released=1 resumed_polls=1 actual_expired_load_ready=1 vault=0 dns=0 original_retirement_before_pool_close=true original_backend_ended_before_pool_close=true");
            // A separate fresh original start supplies the counter's positive
            // control. The prior original deadline/future is never retried internally.
            assert!(matches!(adapter.start(request).await,Err(ProviderPortError::CommitUnknown)));
            assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),1);assert_eq!(dns.0.load(Ordering::SeqCst),1);
            assert_eq!(adapter.v2_expired_last_authority_ready.load(Ordering::SeqCst),1);
            eprintln!("CUSTOM_V2_D1_FRESH_POSITIVE original_manager=true new_start=true vault=1 dns=1 result=CommitUnknown expired_load_ready_total=1");drop(adapter);
            f.finish().await;relay.stop().await;Ok(())
        }).await;
    }
}
