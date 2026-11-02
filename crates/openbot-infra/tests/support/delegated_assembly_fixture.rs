//! Owned PostgreSQL admission evidence for the delegated Application entry.

use async_trait::async_trait;

use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::*;
use openbot_contracts::auth::{AuthContext, DelegationSource};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::ids::{BotId, DeploymentId, RunId, TenantId};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::application_assembly::*;
use openbot_infra::auth::single_user::{initialize_single_user, load_single_user_principal};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::policy::PolicyStore;
use openbot_infra::ui_preferences::PostgresUiPreferenceAdministration;
use openbot_infra::vault::CredentialRecordVault;
use serde_json::Value;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
struct ClosedRemote;
#[async_trait]
impl RemoteAguiTransport for ClosedRemote {
    async fn start(
        &self,
        _: &str,
        _: Option<&RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}
pub struct Authority {
    pub state: Mutex<Result<DelegationGrant, DelegationAuthorityError>>,
    pub calls: AtomicUsize,
    pub expected_source: Mutex<Option<DelegationSource>>,
}
#[async_trait]
impl DelegationAuthority for Authority {
    async fn verify_current(
        &self,
        _: &DeploymentId,
        _: &TenantId,
        source: &DelegationSource,
        _: u64,
    ) -> Result<DelegationGrant, DelegationAuthorityError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self
            .expected_source
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|expected| expected != source)
        {
            return Err(DelegationAuthorityError::NotCurrent);
        }
        self.state.lock().unwrap().clone()
    }
}
#[derive(Default)]
pub struct Notices(pub Mutex<Vec<RunTerminalNotice>>);
impl RunTerminalSubscriber for Notices {
    fn on_run_terminal(&self, n: RunTerminalNotice) {
        self.0.lock().unwrap().push(n);
    }
}
pub struct Fixture {
    pub pool: pool::DatabasePool,
    pub assembly: PostgresApplicationAssembly,
    pub authority: Arc<Authority>,
    pub auth: AuthContext,
    pub notices: Arc<Notices>,
    pub config: pool::DatabaseConfig,
    pub signer: Arc<RemoteRunAssertionSigner>,
}
pub struct Options {
    pub single_user: bool,
    pub delegated: bool,
    pub subscribe: bool,
    pub extensions: Vec<(ProviderExtensionKey, Arc<dyn ProviderAdapter>)>,
    pub subscriber: Option<Arc<dyn RunTerminalSubscriber>>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            single_user: true,
            delegated: true,
            subscribe: true,
            extensions: Vec::new(),
            subscriber: None,
        }
    }
}
impl Fixture {
    pub async fn new(config: &pool::DatabaseConfig) -> Result<Self, String> {
        Self::with_options(config, Options::default()).await
    }
    pub async fn with_options(
        config: &pool::DatabaseConfig,
        options: Options,
    ) -> Result<Self, String> {
        let pool = pool::connect(config).await.map_err(text)?;
        let mut client = pool.get().await.map_err(text)?;
        baseline::apply(&client).await.map_err(text)?;
        native::apply(&mut client).await.map_err(text)?;
        drop(client);
        initialize_single_user(&pool, true).await.map_err(text)?;
        let client = pool.get().await.map_err(text)?;
        client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('other-owner','other-owner@example.test',0) ON CONFLICT DO NOTHING;INSERT INTO public.agents(id,name,type,configuration) VALUES('delegated-bot','Delegated Bot','built_in','{\"providerSource\":\"extension:fake_host\",\"systemPrompt\":\"Standing instruction\"}') ON CONFLICT DO NOTHING;INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at) VALUES('delegated-bot','dev-local-user','Bot','Fixture role','seed','public',NULL) ON CONFLICT DO NOTHING;").await.map_err(text)?;
        drop(client);
        Self::assemble_existing(config, options, pool).await
    }
    pub async fn reopen(config: &pool::DatabaseConfig) -> Result<Self, String> {
        Self::reopen_with_options(config, Options::default()).await
    }
    pub async fn reopen_with_options(
        config: &pool::DatabaseConfig,
        options: Options,
    ) -> Result<Self, String> {
        let pool = pool::connect(config).await.map_err(text)?;
        Self::assemble_existing(config, options, pool).await
    }
    async fn assemble_existing(
        config: &pool::DatabaseConfig,
        options: Options,
        pool: pool::DatabasePool,
    ) -> Result<Self, String> {
        let deployment = DeploymentId::new("delegated-deployment");
        let tenant = TenantId::new("delegated-tenant");
        let policy = PolicyStore::postgres(pool.clone(), None);
        policy.load().await.map_err(text)?;
        let principal = load_single_user_principal(&pool, deployment.clone(), tenant.clone())
            .await
            .map_err(text)?;
        let auth = principal.auth_context().clone();
        let authority = Arc::new(Authority {
            state: Mutex::new(Ok(DelegationGrant::new(
                auth.actor().clone(),
                BotId::new("delegated-bot"),
                1,
                auth.auth_generation(),
                None,
                None,
                "Frozen owner template".into(),
            ))),
            calls: AtomicUsize::new(0),
            expected_source: Mutex::new(None),
        });
        let notices = Arc::new(Notices::default());
        let signer = Arc::new(RemoteRunAssertionSigner::new(vec![0x52; 32]).map_err(text)?);
        let assembled = assemble_postgres_application(PostgresApplicationAssemblyInput {
            recovery_gate:
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                    &pool,
                    &deployment,
                    &tenant,
                ),
            pool: pool.clone(),
            listener_database: config.clone().into(),
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            single_user: options.single_user,
            admin_floor: None,
            model: "fixture-model".into(),
            credential_key_id: "fixture-credential".into(),
            credential_vault: CredentialRecordVault::single_key(
                tenant.clone(),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x42; 32]).map_err(text)?,
            ),
            audit_key: SecretBytes::new(vec![0x51; 32]),
            remote_assertions: signer.clone(),
            mcp_oauth_state_key: SecretBytes::new(vec![0x53; 32]),
            policy_store: policy,
            ui_preferences: Arc::new(
                PostgresUiPreferenceAdministration::new(
                    pool.clone(),
                    deployment,
                    tenant,
                    SecretBytes::new(vec![0x51; 32]),
                )
                .map_err(text)?,
            ),
            screen_sessions: Arc::new(NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(ClosedRemote),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: url::Url::parse("http://127.0.0.1:9/v1/chat/completions")
                    .map_err(text)?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".into()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
            extra_provider_adapters: options.extensions,
            run_event_subscriber: if options.subscribe {
                Some(options.subscriber.unwrap_or_else(|| notices.clone()))
            } else {
                None
            },
            delegation_authority: options
                .delegated
                .then(|| authority.clone() as Arc<dyn DelegationAuthority>),
        })
        .await;
        let assembly = match assembled {
            Ok(assembly) => assembly,
            Err(error) => {
                pool.close();
                return Err(text(error));
            }
        };
        Ok(Self {
            pool,
            assembly,
            authority,
            auth,
            notices,
            config: config.clone(),
            signer,
        })
    }
    pub async fn request(&self, id: &str) -> Result<BeginDelegatedThreadRun, String> {
        let AppReply::ThreadMinted(minted) = self
            .assembly
            .application
            .execute(self.auth.clone(), AppCommand::MintThreadId)
            .await
            .map_err(text)?
        else {
            return Err("mint reply".into());
        };
        Ok(BeginDelegatedThreadRun {
            source: DelegationSource::ExternalBinding {
                binding_id: "binding".into(),
            },
            revision: 1,
            trigger_id: id.into(),
            thread_id: minted.thread_id,
            run_id: RunId::new(id),
            bot_id: BotId::new("delegated-bot"),
            untrusted_material: None,
        })
    }
    pub async fn image(&self) -> Result<Value, String> {
        let c = self.pool.get().await.map_err(text)?;
        let r=c.query_one("SELECT jsonb_build_object('threads',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY thread_id),'[]') FROM public.threads x),'runs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY run_id),'[]') FROM public.runs x),'messages',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY message_id),'[]') FROM public.messages x),'events',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY run_id,seq),'[]') FROM public.run_events x),'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY outbox_id),'[]') FROM public.outbox x))",&[]).await.map_err(text)?;
        Ok(r.get(0))
    }
    pub fn grant(&self, template: &str, deadline: Option<Duration>) {
        *self.authority.state.lock().unwrap() = Ok(DelegationGrant::new(
            self.auth.actor().clone(),
            BotId::new("delegated-bot"),
            1,
            self.auth.auth_generation(),
            None,
            deadline,
            template.into(),
        ));
    }
}
pub fn text(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Owned loopback PostgreSQL wire proxy: drop only an acknowledged backend COMMIT frame.
pub struct CommitAckProxy {
    pub config: pool::DatabaseConfig,
    pub dropped: Arc<AtomicUsize>,
    drop_next: Arc<std::sync::atomic::AtomicBool>,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}
trait PgStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> PgStream for T {}
impl CommitAckProxy {
    pub async fn start(backend: &pool::DatabaseConfig) -> Result<Self, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(text)?;
        let mut config = backend.clone();
        config.host = "127.0.0.1".into();
        config.port = listener.local_addr().map_err(text)?.port();
        let backend = backend.clone();
        let drop_next = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let next = drop_next.clone();
        let count = dropped.clone();
        let (stop, mut stopping) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    changed=stopping.changed()=>{if changed.is_err()||*stopping.borrow(){break;}},
                    finished=children.join_next(),if !children.is_empty()=>{if let Some(result)=finished {result.map_err(text)?;}},
                    accepted=listener.accept()=>{
                        let (client,_)=accepted.map_err(text)?;
                        let server:Box<dyn PgStream>=if backend.host.starts_with('/') {Box::new(tokio::net::UnixStream::connect(std::path::Path::new(&backend.host).join(format!(".s.PGSQL.{}",backend.port))).await.map_err(text)?)} else {Box::new(tokio::net::TcpStream::connect((backend.host.as_str(),backend.port)).await.map_err(text)?)};
                        let next=next.clone();let count=count.clone();
                        children.spawn(async move {
                            let (mut client_read,mut client_write)=client.into_split();let (mut server_read,mut server_write)=tokio::io::split(server);
                            let frontend=async {tokio::io::copy(&mut client_read,&mut server_write).await.map(|_|())};
                            let backend=async {
                                loop {
                                    let kind=match server_read.read_u8().await {Ok(kind)=>kind,Err(error) if error.kind()==std::io::ErrorKind::UnexpectedEof=>return Ok::<(),std::io::Error>(()),Err(error)=>return Err(error)};
                                    let length=server_read.read_u32().await?;
                                    if !(4..=16*1024*1024).contains(&length){return Err(std::io::Error::other("invalid owned proxy frame"));}
                                    let mut payload=vec![0;usize::try_from(length-4).map_err(|_|std::io::Error::other("proxy length"))?];server_read.read_exact(&mut payload).await?;
                                    if kind==b'C'&&payload==b"COMMIT\0"&&next.swap(false,Ordering::SeqCst){count.fetch_add(1,Ordering::SeqCst);return Ok(());}
                                    client_write.write_u8(kind).await?;client_write.write_u32(length).await?;client_write.write_all(&payload).await?;
                                }
                            };
                            // Either clean EOF or the deliberately withheld COMMIT closes both halves.
                            tokio::select! {_=frontend=>{},_=backend=>{}}
                        });
                    }
                }
            }
            drop(listener);
            while let Some(result) = children.join_next().await {
                result.map_err(text)?;
            }
            Ok(())
        });
        Ok(Self {
            config,
            dropped,
            drop_next,
            stop,
            task,
        })
    }
    pub fn drop_next_commit_ack(&self) {
        self.drop_next.store(true, Ordering::SeqCst);
    }
    /// Close all owning pools first. A forced cleanup is reported as failure, never a normal join.
    pub async fn stop(self) -> Result<(), String> {
        self.stop.send_replace(true);
        let mut task = self.task;
        match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
            Ok(result) => result.map_err(text)?,
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err("owned commit proxy did not naturally join after pools closed".into())
            }
        }
    }
}
