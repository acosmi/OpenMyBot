//! Owned PostgreSQL v2 acceptance. These tests use the real shared assembly's binding,
//! original registry and ThreadDirectory; they do not fabricate a dataset grant.
#![cfg(feature = "server-runtime")]

mod harness;

use async_trait::async_trait;
use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{BeginThreadRunV2Request, ThreadDirectory, ThreadDirectoryError};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRunV2, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId},
    model_connections::{
        CreateModelConnection, CustomModelProtocol, DeleteModelConnection, ModelApiKey,
        ModelConnection, UpdateModelConnection,
    },
    versioned_model_selection::{ModelSelectionIntentSource, RunModelSelectionV2},
};
use openbot_domain::{
    remote_callback::RemoteRunAssertionSigner,
    vault::{KeyVersion, SecretBytes, WrappingKey},
};
use openbot_infra::{
    application_assembly::{
        ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
        assemble_postgres_application,
    },
    artifact_registry::ArtifactDatasetRegistry,
    db::{fresh, pool},
    model_connections::PostgresModelConnections,
    model_dataset::PostgresModelDatasetBinding,
    policy::PolicyStore,
    thread_directory::PostgresThreadDirectory,
    vault::CredentialRecordVault,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

const DEP: &str = "owned-v2-dataset-deployment";
const TENANT: &str = "owned-v2-dataset-tenant";
struct ClosedProbe;
#[async_trait]
impl RemoteAguiTransport for ClosedProbe {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}
fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        ActorId::new("alice"),
        AuthGeneration::new(7),
        false,
    )
    .with_roles([Role::User])
    .build()
}
struct Fixture {
    pool: pool::DatabasePool,
    config: pool::DatabaseConfig,
    assembly: PostgresApplicationAssembly,
    registry: Option<Arc<ArtifactDatasetRegistry>>,
    binding: Arc<PostgresModelDatasetBinding>,
    directory: PostgresThreadDirectory,
    models: PostgresModelConnections,
}
impl Fixture {
    async fn new(config: pool::DatabaseConfig, size: usize) -> Self {
        let config = config.with_max_pool_size(size);
        let p = pool::connect(&config).await.unwrap();
        let mut c = p.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','owned-v2-alice@example.test',7),('bob','owned-v2-bob@example.test',7);
            INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
            INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
            INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Owned bot','','owned','public');
            INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES('channel','Owned channel','',ARRAY[]::text[],ARRAY[]::text[]);
            INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');
            INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
        drop(c);
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x61; 32]).unwrap(),
        );
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                p.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .unwrap(),
        );
        let policy_store = PolicyStore::postgres(p.clone(), None);
        policy_store.load().await.unwrap();
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: p.clone(),
            listener_database: config.clone().into(),
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            single_user: false,
            admin_floor: None,
            model: "owned-model".into(),
            credential_key_id: "owned-key-ref".into(),
            credential_vault: vault.clone(),
            audit_key: SecretBytes::new(vec![0x62; 32]),
            remote_assertions: Arc::new(RemoteRunAssertionSigner::new(vec![0x63; 32]).unwrap()),
            mcp_oauth_state_key: SecretBytes::new(vec![0x64; 32]),
            policy_store,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(ClosedProbe),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: url::Url::parse("http://127.0.0.1:9/v1/chat/completions").unwrap(),
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".into()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .unwrap();
        let binding = assembly.model_dataset_binding.clone();
        binding.enroll_original_registry(&registry).unwrap();
        let directory = PostgresThreadDirectory::with_runtime(
            p.clone(),
            config.clone(),
            "owned-v2-runtime".into(),
            time::Duration::seconds(30),
        )
        .unwrap()
        .with_model_dataset_binding(binding.clone())
        .unwrap();
        let models = PostgresModelConnections::new(
            p.clone(),
            vault,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x62; 32]),
        )
        .unwrap();
        Self {
            pool: p,
            config,
            assembly,
            registry: Some(registry),
            binding,
            directory,
            models,
        }
    }
    async fn model(&self, protocol: CustomModelProtocol) -> ModelConnection {
        self.models
            .create(
                &auth(),
                &CreateModelConnection {
                    name: "Owned choice".into(),
                    protocol,
                    endpoint: "https://owned-v2.example.test/v1".into(),
                    model: "owned-selected-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new("OWNED_V2_SYNTHETIC_KEY".into()))
                        .unwrap(),
                },
            )
            .await
            .unwrap()
    }
    fn request(
        &self,
        index: u64,
        channel: bool,
        model: &ModelConnection,
    ) -> BeginThreadRunV2Request {
        let mut entropy = [0u8; 16];
        entropy[8..].copy_from_slice(&index.to_be_bytes());
        BeginThreadRunV2Request {
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            actor: ActorId::new("alice"),
            auth_generation: AuthGeneration::new(7),
            command: BeginThreadRunV2 {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),
                run_id: RunId::new(format!("owned-v2-run-{index}")),
                bot_id: BotId::new("bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: "Exact owned words".into(),
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
        }
    }
    async fn counts(&self) -> Vec<i64> {
        let c = self.pool.get().await.unwrap();
        let mut out = Vec::new();
        for table in [
            "public.threads",
            "public.thread_memberships",
            "public.thread_leases",
            "public.runs",
            "public.messages",
            "public.run_events",
            "public.outbox",
            "public.run_model_selections",
            "openbot_internal.run_model_selection_v2_snapshots",
        ] {
            out.push(
                c.query_one(&format!("SELECT count(*) FROM {table}"), &[])
                    .await
                    .unwrap()
                    .get(0),
            );
        }
        out
    }
    async fn finish(self) {
        self.assembly.shutdown().await;
        drop(self.directory);
        drop(self.models);
        drop(self.binding);
        drop(self.registry);
        let observations = self.pool.connection_observations();
        self.pool.close();
        let deadline = Instant::now() + Duration::from_secs(10);
        for o in observations {
            assert_eq!(
                o.wait_for_destruction_before(deadline).await.unwrap(),
                pool::ConnectionDestruction::ConnectionDestroyed
            );
        }
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
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn original_dataset_accepts_both_anchors_three_protocols_and_exact_replay() {
    let admin = harness::admin_config("v2_dataset_matrix");
    harness::with_temp_database(&admin,"v2datasetmatrix",|config|async move{
        let f=Fixture::new(config,4).await;let mut index=1;
        for channel in [false,true]{for protocol in [CustomModelProtocol::OpenaiChatCompletions,CustomModelProtocol::OpenaiResponses,CustomModelProtocol::AnthropicMessages]{
            let model=f.model(protocol).await;let req=f.request(index,channel,&model);index+=1;
            let receipt=f.directory.begin_thread_run_v2(req.clone()).await.unwrap();assert!(!receipt.replayed);
            let c=f.pool.get().await.unwrap();
            let s=c.query_one("SELECT s.*,r.created_at AS actual_run_time,m.content,e.event_seq,o.outbox_id,
                d.dataset_id AS actual_dataset,d.created_at AS actual_dataset_time,d.initial_origin AS actual_origin
                FROM openbot_internal.run_model_selection_v2_snapshots s JOIN public.runs r ON r.run_id=s.run_id
                JOIN public.messages m ON m.message_id=r.run_id||':input' JOIN public.run_events e ON e.run_id=r.run_id AND e.seq=0
                JOIN public.outbox o ON o.outbox_id=r.run_id||':agent_run_dispatch'
                JOIN openbot_internal.artifact_dataset_bindings d ON d.deployment_id=s.deployment_id AND d.tenant_id=s.tenant_id
                WHERE s.run_id=$1",&[&req.command.run_id.as_str()]).await.unwrap();
            let typed=openbot_infra::db::tables::run_model_selection_v2_snapshots::Row::try_from(&s).unwrap();
            assert_eq!(typed.run_id,req.command.run_id.as_str());assert_eq!(typed.deployment_id,DEP);assert_eq!(typed.tenant_id,TENANT);
            assert_eq!(typed.owner_user_id,"alice");assert_eq!(typed.auth_generation,7);assert_eq!(typed.connection_id,Uuid::parse_str(&model.id).unwrap());
            assert_eq!(typed.connection_revision,model.revision);assert_eq!(typed.protocol,protocol.as_str());assert_eq!(typed.endpoint,model.endpoint);
            assert_eq!(typed.model,model.model);assert_eq!(typed.created_at,s.get::<_,time::OffsetDateTime>("actual_run_time"));assert_eq!(typed.snapshot_schema,2);
            assert_eq!(typed.source,"custom");assert_eq!(typed.model_id,format!("custom:{}",model.id));assert_eq!(typed.catalog_revision,1);
            assert_eq!(typed.dataset_id,s.get::<_,String>("actual_dataset"));assert_eq!(typed.dataset_binding_schema,1);
            assert_eq!(typed.dataset_initial_origin,s.get::<_,String>("actual_origin"));assert_eq!(typed.dataset_binding_created_at,s.get::<_,time::OffsetDateTime>("actual_dataset_time"));
            assert_eq!(typed.credential_policy,"custom_fixed_secret_revision_v1");
            assert_eq!(s.get::<_,Value>("content"),json!({"text":req.command.message,"modelSelection":req.command.model_selection,"runAnchor":req.command.anchor}));
            assert!(c.query_opt("SELECT 1 FROM public.run_model_selections WHERE run_id=$1",&[&req.command.run_id.as_str()]).await.unwrap().is_none());drop(c);
            let before=f.counts().await;assert!(f.directory.begin_thread_run_v2(req.clone()).await.unwrap().replayed);assert_eq!(f.counts().await,before);
        }}f.finish().await;Ok(())
    }).await;
}

fn update(model: &ModelConnection) -> UpdateModelConnection {
    UpdateModelConnection {
        expected_revision: model.revision,
        name: model.name.clone(),
        protocol: model.protocol,
        endpoint: model.endpoint.clone(),
        model: model.model.clone(),
        enabled: model.enabled,
        api_key: None,
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn durable_receipt_keeps_original_definition_and_rejects_complete_intent_drift() {
    let admin = harness::admin_config("v2_dataset_replay");
    harness::with_temp_database(&admin,"v2datasetreplay",|config|async move {
        let f=Fixture::new(config,4).await;
        let model=f.model(CustomModelProtocol::OpenaiResponses).await;
        let c=f.pool.get().await.unwrap();
        // Real skill and Agent grant rows make both selected instruction snapshots
        // reachable through the original skills resolver before any replay attempt.
        c.batch_execute("INSERT INTO public.skills(id,slug,title,summary,instructions,origin,owner_user_id)
            VALUES('owned-replay-a','owned-replay-a','Owned A','','Owned A instruction.','yours','alice'),
                  ('owned-replay-z','owned-replay-z','Owned Z','','Owned Z instruction.','yours','alice');
            INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
            VALUES('skill','owned-replay-a','bot','bob'),('skill','owned-replay-z','bot','bob');").await.unwrap();drop(c);
        let mut req=f.request(20,false,&model);
        req.command.selected_skill_slugs=vec!["owned-replay-z".into(),"owned-replay-a".into()];
        let original=f.directory.begin_thread_run_v2(req.clone()).await.unwrap();
        let c=f.pool.get().await.unwrap();
        let skills=c.query("SELECT content->>'selectedSkillSlug' AS slug,content->>'text' AS instruction
            FROM public.messages WHERE run_id=$1 AND role='system' ORDER BY seq",&[&req.command.run_id.as_str()]).await.unwrap();
        assert_eq!(skills.len(),2);
        assert_eq!(skills[0].get::<_,String>("slug"),"owned-replay-z");
        assert_eq!(skills[0].get::<_,String>("instruction"),"Owned Z instruction.");
        assert_eq!(skills[1].get::<_,String>("slug"),"owned-replay-a");
        assert_eq!(skills[1].get::<_,String>("instruction"),"Owned A instruction.");
        let accepted_input:Value=c.query_one("SELECT content FROM public.messages WHERE message_id=$1||':input'",&[&req.command.run_id.as_str()]).await.unwrap().get(0);
        assert_eq!(accepted_input["selectedSkillSlugs"],json!(req.command.selected_skill_slugs));drop(c);
        let mut edit=update(&model);edit.model="changed-owned-model".into();edit.enabled=false;
        let changed=f.models.update(&auth(),&model.id,&edit).await.unwrap();
        f.models.delete(&auth(),&changed.id,&DeleteModelConnection{expected_revision:changed.revision}).await.unwrap();
        let before=f.counts().await;
        let exact=f.directory.begin_thread_run_v2(req.clone()).await.unwrap();
        assert!(exact.replayed);assert_eq!(exact.message_sequence,original.message_sequence);assert_eq!(exact.event_sequence,original.event_sequence);
        assert_eq!(f.counts().await,before);
        let mut conflicts=Vec::new();
        let mut changed=req.clone();changed.command.message.push('!');conflicts.push(changed);
        let mut changed=req.clone();changed.command.selected_skill_slugs.reverse();conflicts.push(changed);
        let mut changed=req.clone();changed.command.anchor=ThreadRunAnchor::Channel{channel_id:ChannelId::new("channel")};conflicts.push(changed);
        let mut changed=req.clone();changed.command.model_selection=RunModelSelectionV2::new(ModelSelectionIntentSource::Custom,
            model.id.clone(),model.revision+1,format!("custom:{}",model.id),1).unwrap();conflicts.push(changed);
        let mut changed=req.clone();changed.command.model_selection=RunModelSelectionV2::new(ModelSelectionIntentSource::Custom,
            model.id.clone(),model.revision,"custom:00000000-0000-4000-8000-000000000099".into(),1).unwrap();conflicts.push(changed);
        let mut changed=req.clone();changed.command.model_selection=RunModelSelectionV2::new(ModelSelectionIntentSource::Custom,
            model.id.clone(),model.revision,format!("custom:{}",model.id),2).unwrap();conflicts.push(changed);
        if model.id.to_uppercase()!=model.id {
            let mut changed=req.clone();changed.command.model_selection=RunModelSelectionV2::new(ModelSelectionIntentSource::Custom,
                model.id.to_uppercase(),model.revision,format!("custom:{}",model.id),1).unwrap();conflicts.push(changed);
        }
        let mut other=f.request(21,false,&model);other.command.run_id=req.command.run_id.clone();conflicts.push(other);
        for conflict in conflicts {
            assert_eq!(f.directory.begin_thread_run_v2(conflict).await,Err(ThreadDirectoryError::RequestConflict));
            assert_eq!(f.counts().await,before);
            let exact=f.directory.begin_thread_run_v2(req.clone()).await.unwrap();
            assert!(exact.replayed);assert_eq!(exact.message_sequence,original.message_sequence);assert_eq!(exact.event_sequence,original.event_sequence);
            assert_eq!(f.counts().await,before);
        }
        for source in [ModelSelectionIntentSource::SdkGateway,ModelSelectionIntentSource::AccountBridge] {
            let mut unsupported=req.clone();unsupported.command.model_selection=RunModelSelectionV2::new(source,
                model.id.clone(),model.revision,format!("custom:{}",model.id),1).unwrap();
            // These sources are rejected by the actual production preflight. They
            // are not relabeled as run-intent RequestConflict or enabled by this test.
            assert_eq!(f.directory.begin_thread_run_v2(unsupported).await,Err(ThreadDirectoryError::InvalidInput{field:"model_selection"}));
            assert_eq!(f.counts().await,before);
        }
        // Construct a real legacy request for the original legacy port. This is an
        // intentional cross-version conflict attempt, not a synthetic v1 proof for v2.
        let legacy_request=|r:&BeginThreadRunV2Request| openbot_application::BeginThreadRunRequest {
            deployment:r.deployment.clone(),tenant:r.tenant.clone(),actor:r.actor.clone(),auth_generation:r.auth_generation,
            command:openbot_contracts::command::BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id:r.command.thread_id.clone(),run_id:r.command.run_id.clone(),bot_id:r.command.bot_id.clone(),
                anchor:r.command.anchor.clone(),message:r.command.message.clone(),selected_skill_slugs:r.command.selected_skill_slugs.clone(),
                model_selection:Some(openbot_contracts::model_connections::RunModelSelection{
                    connection_id:r.command.model_selection.connection_id().to_owned(),
                    expected_revision:r.command.model_selection.expected_connection_revision(),
                }),
            },
        };
        assert_eq!(f.directory.begin_thread_run(legacy_request(&req)).await,Err(ThreadDirectoryError::RequestConflict));
        assert_eq!(f.counts().await,before);
        assert!(f.directory.begin_thread_run_v2(req.clone()).await.unwrap().replayed);
        assert_eq!(f.counts().await,before);

        let legacy_model=f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let mut legacy_as_v2=f.request(22,false,&legacy_model);legacy_as_v2.command.selected_skill_slugs=req.command.selected_skill_slugs.clone();
        let legacy=legacy_request(&legacy_as_v2);
        let legacy_original=f.directory.begin_thread_run(legacy.clone()).await.unwrap();
        let legacy_before=f.counts().await;
        assert!(f.directory.begin_thread_run(legacy.clone()).await.unwrap().replayed);assert_eq!(f.counts().await,legacy_before);
        assert_eq!(f.directory.begin_thread_run_v2(legacy_as_v2.clone()).await,Err(ThreadDirectoryError::RequestConflict));
        assert_eq!(f.counts().await,legacy_before);
        let legacy_exact=f.directory.begin_thread_run(legacy).await.unwrap();
        assert!(legacy_exact.replayed);assert_eq!(legacy_exact.message_sequence,legacy_original.message_sequence);assert_eq!(legacy_exact.event_sequence,legacy_original.event_sequence);
        assert_eq!(f.counts().await,legacy_before);
        let c=f.pool.get().await.unwrap();
        let actual=c.query_one("SELECT
            (SELECT count(*) FROM public.run_model_selections WHERE run_id=$1) AS legacy,
            (SELECT count(*) FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1) AS v2,
            (SELECT content FROM public.messages WHERE message_id=$1||':input') AS input",&[&legacy_as_v2.command.run_id.as_str()]).await.unwrap();
        assert_eq!(actual.get::<_,i64>("legacy"),1);assert_eq!(actual.get::<_,i64>("v2"),0);
        let input:Value=actual.get("input");assert!(input["modelSelection"].get("schemaVersion").is_none());assert!(input.get("runAnchor").is_none());drop(c);
        assert!(f.directory.begin_thread_run_v2(req).await.unwrap().replayed);assert_eq!(f.counts().await,legacy_before);
        f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn original_pool_scope_once_enrollment_and_owner_lifetime_are_closed() {
    let admin = harness::admin_config("v2_dataset_identity");
    harness::with_temp_database(&admin, "v2datasetidentity", |config| async move {
        let f = Fixture::new(config, 4).await;
        let model = f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let _req = f.request(30, false, &model);
        let before = f.counts().await;
        let other = pool::connect(&f.config).await.unwrap();
        assert!(!f.binding.matches_pool_scope(
            &other,
            &DeploymentId::new(DEP),
            &TenantId::new(TENANT)
        ));
        assert!(
            PostgresThreadDirectory::with_runtime(
                other.clone(),
                f.config.clone(),
                "other".into(),
                time::Duration::seconds(30)
            )
            .unwrap()
            .with_model_dataset_binding(f.binding.clone())
            .is_err()
        );
        other.close();
        assert!(f.binding.matches_pool_scope(
            &f.pool.clone(),
            &DeploymentId::new(DEP),
            &TenantId::new(TENANT)
        ));
        assert!(!f.binding.matches_pool_scope(
            &f.pool,
            &DeploymentId::new("wrong"),
            &TenantId::new(TENANT)
        ));
        assert!(!f.binding.matches_pool_scope(
            &f.pool,
            &DeploymentId::new(DEP),
            &TenantId::new("owned-wrong-tenant")
        ));
        let mut wrong_tenant = f.request(31, false, &model);
        wrong_tenant.tenant = TenantId::new("owned-wrong-tenant");
        assert_eq!(
            f.directory.begin_thread_run_v2(wrong_tenant).await,
            Err(ThreadDirectoryError::Corrupt {
                field: "model_dataset_binding"
            })
        );
        assert_eq!(f.counts().await, before);
        // The unchanged original clone still serves before the deliberate duplicate
        // enrollment test terminates this fixture's capability assembly.
        f.directory
            .begin_thread_run_v2(f.request(32, false, &model))
            .await
            .unwrap();
        let before = f.counts().await;
        assert!(
            f.binding
                .enroll_original_registry(f.registry.as_ref().unwrap())
                .is_err()
        );
        // The actual host propagates a duplicate enrollment failure and stops assembly.
        // This assertion does not pretend that ignoring that error is an authorized host.
        assert_eq!(f.counts().await, before);
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn dataset_and_snapshot_acl_drift_refuse_before_any_business_commit() {
    let admin = harness::admin_config("v2_dataset_drift");
    harness::with_temp_database(&admin,"v2datasetdrift",|config|async move{
        let f=Fixture::new(config,4).await;let model=f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let before=f.counts().await;let c=f.pool.get().await.unwrap();
        c.batch_execute("GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO PUBLIC").await.unwrap();drop(c);
        assert!(f.directory.begin_thread_run_v2(f.request(40,false,&model)).await.is_err());assert_eq!(f.counts().await,before);
        let c=f.pool.get().await.unwrap();c.batch_execute("REVOKE SELECT ON openbot_internal.run_model_selection_v2_snapshots FROM PUBLIC").await.unwrap();drop(c);
        // Explicit owner-only ACL is an allowed physical state, not a repair by production.
        f.directory.begin_thread_run_v2(f.request(41,false,&model)).await.unwrap();
        let before=f.counts().await;let c=f.pool.get().await.unwrap();
        let original_dataset:String=c.query_one("SELECT dataset_id FROM openbot_internal.artifact_dataset_bindings WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap().get(0);
        owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id='owned-tampered-dataset' WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap();drop(c);
        assert!(f.directory.begin_thread_run_v2(f.request(42,false,&model)).await.is_err());assert_eq!(f.counts().await,before);
        let c=f.pool.get().await.unwrap();
        owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id=$3 WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT,&original_dataset]).await.unwrap();drop(c);
        f.directory.begin_thread_run_v2(f.request(43,false,&model)).await.unwrap();
        f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn original_registry_owner_drop_and_pool_close_refuse_successor_accepts() {
    let admin = harness::admin_config("v2_dataset_owner_end");
    harness::with_temp_database(&admin, "v2datasetownerend", |config| async move {
        let mut f = Fixture::new(config, 4).await;
        let model = f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let before = f.counts().await;
        drop(f.registry.take());
        assert!(
            f.directory
                .begin_thread_run_v2(f.request(50, false, &model))
                .await
                .is_err()
        );
        assert_eq!(f.counts().await, before);
        f.pool.close();
        assert!(
            f.directory
                .begin_thread_run_v2(f.request(51, false, &model))
                .await
                .is_err()
        );
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn independent_snapshot_acl_policy_accepts_null_and_equivalent_owner_only_and_rejects_complete_drift()
 {
    let admin = harness::admin_config("v2_dataset_acl");
    harness::with_temp_database(&admin,"v2datasetacl",|config|async move{
        let f=Fixture::new(config,4).await;let model=f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let c=f.pool.get().await.unwrap();
        c.batch_execute("UPDATE pg_catalog.pg_class SET relacl=NULL WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass").await.unwrap();
        openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();
        let null=openbot_infra::db::custom_model_v2_schema::capture(&c).await.unwrap();
        let observation=serde_json::to_string(&null).unwrap();
        assert!(observation.len()<=1024*1024,"bounded actual NULL ACL schema observation");
        eprintln!("CUSTOM_V2_SCHEMA_OBSERVATION acl=null payload={observation}");
        c.batch_execute("UPDATE pg_catalog.pg_class SET relacl=pg_catalog.acldefault('r'::pg_catalog.\"char\",(SELECT relowner FROM pg_catalog.pg_class WHERE oid='public.model_connections'::regclass)) WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass").await.unwrap();
        openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();
        let explicit=openbot_infra::db::custom_model_v2_schema::capture(&c).await.unwrap();
        let observation=serde_json::to_string(&explicit).unwrap();
        assert!(observation.len()<=1024*1024,"bounded actual explicit owner-only ACL schema observation");
        eprintln!("CUSTOM_V2_SCHEMA_OBSERVATION acl=explicit_owner_only payload={observation}");
        assert_eq!(null["schema"],explicit["schema"]);assert_ne!(null["tableAclState"],explicit["tableAclState"]);drop(c);
        let before=f.counts().await;
        let challenges=[
            "GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO PUBLIC",
            "GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO pg_monitor",
            "GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO CURRENT_USER WITH GRANT OPTION",
            "REVOKE SELECT ON openbot_internal.run_model_selection_v2_snapshots FROM CURRENT_USER",
            "UPDATE pg_catalog.pg_class SET relacl=relacl||relacl WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass",
            "UPDATE pg_catalog.pg_class SET relacl='{}'::aclitem[] WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass",
            "UPDATE pg_catalog.pg_class SET relacl=pg_catalog.acldefault('r'::pg_catalog.\"char\",0::oid) WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass",
            "GRANT SELECT(model) ON openbot_internal.run_model_selection_v2_snapshots TO PUBLIC",
            "ALTER TABLE openbot_internal.run_model_selection_v2_snapshots OWNER TO pg_monitor",
        ];
        for(index,challenge)in challenges.into_iter().enumerate(){
            let c=f.pool.get().await.unwrap();
            c.batch_execute("UPDATE pg_catalog.pg_class SET relacl=pg_catalog.acldefault('r'::pg_catalog.\"char\",(SELECT relowner FROM pg_catalog.pg_class WHERE oid='public.model_connections'::regclass)) WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass;
                UPDATE pg_catalog.pg_attribute SET attacl=NULL WHERE attrelid='openbot_internal.run_model_selection_v2_snapshots'::regclass AND attnum>0").await.unwrap();
            // Each challenged fixture starts from a separately observed positive oracle.
            openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();
            c.batch_execute(challenge).await.unwrap();
            assert!(openbot_infra::db::custom_model_v2_schema::verify(&c).await.is_err(),"ACL challenge {index} must be observed and refused");drop(c);
            assert!(f.directory.begin_thread_run_v2(f.request(60+index as u64,false,&model)).await.is_err());assert_eq!(f.counts().await,before);
        }
        let c=f.pool.get().await.unwrap();
        c.batch_execute("DO $$ DECLARE actual_owner text; BEGIN
            SELECT r.rolname INTO STRICT actual_owner FROM pg_catalog.pg_roles r
              JOIN pg_catalog.pg_class c ON c.relowner=r.oid WHERE c.oid='public.model_connections'::regclass;
            EXECUTE format('ALTER TABLE openbot_internal.run_model_selection_v2_snapshots OWNER TO %I',actual_owner);
            END $$;
            UPDATE pg_catalog.pg_class SET relacl=NULL WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass;
            UPDATE pg_catalog.pg_attribute SET attacl=NULL WHERE attrelid='openbot_internal.run_model_selection_v2_snapshots'::regclass AND attnum>0").await.unwrap();
        openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();drop(c);
        f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn extra_owner_default_privileges_roll_back_native0047_without_repair_or_partial_ledger() {
    let admin = harness::admin_config("v2_dataset_default_acl");
    harness::with_temp_database(&admin,"v2datasetdefaultacl",|config|async move{
        let p=pool::connect(&config).await.unwrap();let mut c=p.get().await.unwrap();
        openbot_infra::db::baseline::apply(&c).await.unwrap();openbot_infra::db::native::apply_through(&mut c,46).await.unwrap();
        let before:String=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text FROM openbot_internal.schema_migrations m",&[]).await.unwrap().get(0);
        c.batch_execute("ALTER DEFAULT PRIVILEGES IN SCHEMA openbot_internal GRANT SELECT ON TABLES TO PUBLIC").await.unwrap();
        assert!(openbot_infra::db::native::apply(&mut c).await.is_err());
        // This original-connection barrier observes the DB after native's queued rollback;
        // it is not a fabricated per-frame C/Z witness or a claim about driver joins.
        c.simple_query("SELECT 1").await.unwrap();
        let clean:bool=c.query_one("SELECT to_regclass('openbot_internal.run_model_selection_v2_snapshots') IS NULL AND NOT EXISTS(SELECT 1 FROM openbot_internal.schema_migrations WHERE version=47)",&[]).await.unwrap().get(0);assert!(clean);
        let after:String=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text FROM openbot_internal.schema_migrations m",&[]).await.unwrap().get(0);assert_eq!(before,after);
        let unchanged:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl d CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a WHERE d.defaclnamespace='openbot_internal'::regnamespace AND a.grantee=0 AND a.privilege_type='SELECT')",&[]).await.unwrap().get(0);assert!(unchanged);
        drop(c);let observations=p.connection_observations();p.close();let deadline=Instant::now()+Duration::from_secs(10);
        for o in observations{assert_eq!(o.wait_for_destruction_before(deadline).await.unwrap(),pool::ConnectionDestruction::ConnectionDestroyed);}Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn v2_accept_rechecks_current_revocation_after_original_connection_lock_wait() {
    let admin = harness::admin_config("v2_accept_current_wait");
    harness::with_temp_database(&admin, "v2acceptcurrentwait", |config| async move {
        let f = Fixture::new(config, 6).await;
        let model = f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        for channel in [false, true] {
            let request = f.request(110 + u64::from(channel), channel, &model);
            let before = f.counts().await;
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
                    &[&Uuid::parse_str(&model.id).unwrap()],
                )
                .await
                .unwrap();
            let checker = f.pool.get().await.unwrap();
            let (result, ()) = tokio::join!(f.directory.begin_thread_run_v2(request), async {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let waiter = checker
                            .query_opt(
                                "SELECT pid FROM pg_stat_activity
                                WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))
                                  AND query LIKE '%FROM public.model_connections c%' LIMIT 1",
                                &[&blocker_pid],
                            )
                            .await
                            .unwrap();
                        if waiter.is_some() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("actual accept reached its original connection lock");
                // No positive row lock can lock a revoked_access absence. This commits
                // while acceptance is waiting and must be observed by the final conjunction.
                checker
                    .execute(
                        "INSERT INTO public.revoked_access(email,revoked_by)
                        VALUES('owned-v2-alice@example.test','bob')",
                        &[],
                    )
                    .await
                    .unwrap();
                barrier.commit().await.unwrap();
            });
            assert!(matches!(result, Err(ThreadDirectoryError::NotVisible)));
            // A known refusal is not an ACK witness; this separately checks visible business rows.
            assert_eq!(
                f.counts().await,
                before,
                "no new thread/lease/run/input/event/outbox/snapshot survives"
            );
            checker
                .execute(
                    "DELETE FROM public.revoked_access WHERE email='owned-v2-alice@example.test'",
                    &[],
                )
                .await
                .unwrap();
            drop(checker);
            drop(blocker);
        }
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; Server original namespace only"]
async fn server_original_six_tuple_checks_reject_reachable_drift_and_database_schema_violation() {
    let admin = harness::admin_config("v2_server_tuple_faults");
    harness::with_temp_database(&admin,"v2servertuplefaults",|config|async move {
        let f=Fixture::new(config,6).await;
        let model=f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let c=f.pool.get().await.unwrap();
        let original=c.query_one("SELECT * FROM openbot_internal.artifact_dataset_bindings WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap();
        let original_json:Value=c.query_one("SELECT to_jsonb(b) FROM openbot_internal.artifact_dataset_bindings b WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap().get(0);
        let deployment:String=original.get("deployment_id");let tenant:String=original.get("tenant_id");
        let dataset:String=original.get("dataset_id");let schema:i16=original.get("binding_schema");
        let origin:String=original.get("initial_origin");let created:time::OffsetDateTime=original.get("created_at");
        assert_eq!(schema,1);assert_eq!(origin,"server_first_adoption");
        let before=f.counts().await;
        // A schema=2 row is unreachable under the original validated CHECK. This
        // proves that original database constraint, not a fabricated consumer leg.
        let violation=owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings SET binding_schema=2 WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap_err();
        assert_eq!(violation.as_db_error().map(|error|error.code()),Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION));
        assert_eq!(violation.as_db_error().and_then(|error|error.constraint()),Some("artifact_dataset_bindings_schema_known"));
        let unchanged:Value=c.query_one("SELECT to_jsonb(b) FROM openbot_internal.artifact_dataset_bindings b WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap().get(0);
        assert_eq!(unchanged,original_json);drop(c);assert_eq!(f.counts().await,before);
        f.directory.begin_thread_run_v2(f.request(130,false,&model)).await.unwrap();
        for mode in 0..5u64 {
            let before=f.counts().await;let c=f.pool.get().await.unwrap();
            let statement=match mode {
                0=>"UPDATE openbot_internal.artifact_dataset_bindings SET deployment_id='owned-drifted-deployment' WHERE deployment_id=$1 AND tenant_id=$2",
                1=>"UPDATE openbot_internal.artifact_dataset_bindings SET tenant_id='owned-drifted-tenant' WHERE deployment_id=$1 AND tenant_id=$2",
                2=>"UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id='owned-drifted-dataset' WHERE deployment_id=$1 AND tenant_id=$2",
                3=>"UPDATE openbot_internal.artifact_dataset_bindings SET initial_origin='desktop_canary' WHERE deployment_id=$1 AND tenant_id=$2",
                _=>"UPDATE openbot_internal.artifact_dataset_bindings SET created_at=created_at+interval '1 second' WHERE deployment_id=$1 AND tenant_id=$2",
            };
            assert_eq!(owned_dataset_statement(&c,statement,&[&DEP,&TENANT]).await.unwrap(),1);
            let current_deployment=if mode==0 {"owned-drifted-deployment"} else {DEP};
            let current_tenant=if mode==1 {"owned-drifted-tenant"} else {TENANT};
            let drifted:Value=c.query_one("SELECT to_jsonb(b) FROM openbot_internal.artifact_dataset_bindings b WHERE deployment_id=$1 AND tenant_id=$2",&[&current_deployment,&current_tenant]).await.unwrap().get(0);
            assert_ne!(drifted,original_json);drop(c);
            assert_eq!(f.directory.begin_thread_run_v2(f.request(140+2*mode,false,&model)).await,
                Err(ThreadDirectoryError::Corrupt{field:"model_dataset_binding"}));
            assert_eq!(f.counts().await,before,"reachable tuple drift {mode} adds no business rows");
            let c=f.pool.get().await.unwrap();
            let after:Value=c.query_one("SELECT to_jsonb(b) FROM openbot_internal.artifact_dataset_bindings b WHERE deployment_id=$1 AND tenant_id=$2",&[&current_deployment,&current_tenant]).await.unwrap().get(0);
            assert_eq!(after,drifted,"consumer did not repair or replace the namespace");
            assert_eq!(c.query_one("SELECT count(*) FROM openbot_internal.artifact_dataset_bindings",&[]).await.unwrap().get::<_,i64>(0),1);
            assert_eq!(owned_dataset_statement(&c,"UPDATE openbot_internal.artifact_dataset_bindings
                SET deployment_id=$3,tenant_id=$4,dataset_id=$5,binding_schema=$6,initial_origin=$7,created_at=$8
                WHERE deployment_id=$1 AND tenant_id=$2",
                &[&current_deployment,&current_tenant,&deployment,&tenant,&dataset,&schema,&origin,&created]).await.unwrap(),1);
            let restored:Value=c.query_one("SELECT to_jsonb(b) FROM openbot_internal.artifact_dataset_bindings b WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap().get(0);
            assert_eq!(restored,original_json);drop(c);
            f.directory.begin_thread_run_v2(f.request(141+2*mode,false,&model)).await.unwrap();
        }
        f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; Server prefix and schema only"]
async fn server_namespace_schema_native_prefix_and_snapshot_shape_drift_never_accept_or_repair() {
    let admin = harness::admin_config("v2_server_physical_faults");
    harness::with_temp_database(&admin,"v2serverphysicalfaults",|config|async move {
        let f=Fixture::new(config,6).await;
        let model=f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let c=f.pool.get().await.unwrap();
        let original_ledger:Value=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM openbot_internal.schema_migrations m",&[]).await.unwrap().get(0);
        let latest=c.query_one("SELECT name,checksum FROM openbot_internal.schema_migrations WHERE version=47",&[]).await.unwrap();
        let latest_name:String=latest.get("name");let latest_checksum:String=latest.get("checksum");
        let gap=c.query_one("SELECT name,checksum,applied_at FROM openbot_internal.schema_migrations WHERE version=46",&[]).await.unwrap();
        let gap_name:String=gap.get("name");let gap_checksum:String=gap.get("checksum");let gap_applied:time::OffsetDateTime=gap.get("applied_at");
        let original_private=openbot_infra::db::custom_model_v2_schema::capture(&c).await.unwrap();
        let original_constraint:String=c.query_one("SELECT pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint
            WHERE conrelid='openbot_internal.artifact_dataset_bindings'::regclass AND conname='artifact_dataset_bindings_schema_known'",&[]).await.unwrap().get(0);
        let original_trigger:String=c.query_one("SELECT pg_get_triggerdef(oid) FROM pg_catalog.pg_trigger
            WHERE tgrelid='openbot_internal.artifact_dataset_bindings'::regclass AND tgname='artifact_dataset_bindings_append_only'",&[]).await.unwrap().get(0);drop(c);
        for mode in 0..7u64 {
            let before=f.counts().await;let c=f.pool.get().await.unwrap();
            match mode {
                0=>{c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings RENAME TO owned_v2_fault_namespace").await.unwrap();},
                1=>{c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings RENAME CONSTRAINT artifact_dataset_bindings_schema_known TO owned_v2_fault_constraint").await.unwrap();},
                2=>{c.execute("UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=47",&[]).await.unwrap();},
                3=>{c.execute("UPDATE openbot_internal.schema_migrations SET name='owned_wrong_native_name' WHERE version=47",&[]).await.unwrap();},
                4=>{c.execute("DELETE FROM openbot_internal.schema_migrations WHERE version=46",&[]).await.unwrap();},
                5=>{c.execute("INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(52,'owned_unknown_native_version',repeat('0',64))",&[]).await.unwrap();},
                _=>{c.batch_execute("ALTER TABLE openbot_internal.run_model_selection_v2_snapshots RENAME CONSTRAINT run_model_selection_v2_snapshots_protocol_check TO owned_v2_fault_snapshot_protocol").await.unwrap();},
            }
            if mode==6 {assert!(openbot_infra::db::custom_model_v2_schema::verify(&c).await.is_err());}
            drop(c);
            assert_eq!(f.directory.begin_thread_run_v2(f.request(160+2*mode,false,&model)).await,
                Err(ThreadDirectoryError::Corrupt{field:"model_dataset_binding"}));
            assert_eq!(f.counts().await,before,"owned physical drift {mode} adds no business rows");
            let c=f.pool.get().await.unwrap();
            // Restore only this test's exact recorded fault; production never calls DDL.
            match mode {
                0=>{assert!(c.query_one("SELECT to_regclass('openbot_internal.artifact_dataset_bindings') IS NULL",&[]).await.unwrap().get::<_,bool>(0));
                    c.batch_execute("ALTER TABLE openbot_internal.owned_v2_fault_namespace RENAME TO artifact_dataset_bindings").await.unwrap();},
                1=>{c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings RENAME CONSTRAINT owned_v2_fault_constraint TO artifact_dataset_bindings_schema_known").await.unwrap();},
                2=>{c.execute("UPDATE openbot_internal.schema_migrations SET checksum=$1 WHERE version=47",&[&latest_checksum]).await.unwrap();},
                3=>{c.execute("UPDATE openbot_internal.schema_migrations SET name=$1 WHERE version=47",&[&latest_name]).await.unwrap();},
                4=>{c.execute("INSERT INTO openbot_internal.schema_migrations(version,name,checksum,applied_at) VALUES(46,$1,$2,$3)",&[&gap_name,&gap_checksum,&gap_applied]).await.unwrap();},
                5=>{c.execute("DELETE FROM openbot_internal.schema_migrations WHERE version=52",&[]).await.unwrap();},
                _=>{c.batch_execute("ALTER TABLE openbot_internal.run_model_selection_v2_snapshots RENAME CONSTRAINT owned_v2_fault_snapshot_protocol TO run_model_selection_v2_snapshots_protocol_check").await.unwrap();},
            }
            let restored_ledger:Value=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM openbot_internal.schema_migrations m",&[]).await.unwrap().get(0);
            assert_eq!(restored_ledger,original_ledger);
            assert_eq!(openbot_infra::db::custom_model_v2_schema::capture(&c).await.unwrap(),original_private);
            openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();
            assert_eq!(c.query_one("SELECT pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint WHERE conrelid='openbot_internal.artifact_dataset_bindings'::regclass AND conname='artifact_dataset_bindings_schema_known'",&[]).await.unwrap().get::<_,String>(0),original_constraint);
            assert_eq!(c.query_one("SELECT pg_get_triggerdef(oid) FROM pg_catalog.pg_trigger WHERE tgrelid='openbot_internal.artifact_dataset_bindings'::regclass AND tgname='artifact_dataset_bindings_append_only'",&[]).await.unwrap().get::<_,String>(0),original_trigger);
            assert_eq!(c.query_one("SELECT count(*) FROM openbot_internal.artifact_dataset_bindings",&[]).await.unwrap().get::<_,i64>(0),1);drop(c);
            f.directory.begin_thread_run_v2(f.request(161+2*mode,false,&model)).await.unwrap();
        }
        f.finish().await;Ok(())
    }).await;
}
