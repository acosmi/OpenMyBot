//! Explicit custom run acceptance through real PostgreSQL/Vault management and ThreadDirectory.
mod harness;
use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::{BeginThreadRunRequest, ThreadDirectory, ThreadDirectoryError as Error};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRun, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId},
    model_connections::*,
};
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::{
    db::tables::run_model_selections,
    db::{fresh, pool},
    model_connections::PostgresModelConnections,
    thread_directory::PostgresThreadDirectory,
    vault::CredentialRecordVault,
};
use time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;
const DEP: &str = "selection-dep";
const TENANT: &str = "selection-tenant";
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
fn input(protocol: CustomModelProtocol) -> CreateModelConnection {
    CreateModelConnection {
        name: "Chosen model".into(),
        protocol,
        endpoint: "https://provider.example.test/v1".into(),
        model: "chosen-model-中文".into(),
        enabled: true,
        api_key: ModelApiKey::new(Zeroizing::new("PRIVATE_MODEL_KEY_CANARY".into())).unwrap(),
    }
}
fn update(row: &ModelConnection) -> UpdateModelConnection {
    UpdateModelConnection {
        expected_revision: row.revision,
        name: row.name.clone(),
        protocol: row.protocol,
        endpoint: row.endpoint.clone(),
        model: row.model.clone(),
        enabled: row.enabled,
        api_key: None,
    }
}
fn request(index: u64, channel: bool, row: Option<&ModelConnection>) -> BeginThreadRunRequest {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&index.to_be_bytes());
    BeginThreadRunRequest {
        deployment: DeploymentId::new(DEP),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new("alice"),
        auth_generation: AuthGeneration::new(7),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            thread_id: ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(bytes),
            run_id: RunId::new(format!("selection-run-{index}")),
            bot_id: BotId::new("bot"),
            anchor: if channel {
                ThreadRunAnchor::Channel {
                    channel_id: ChannelId::new("channel"),
                }
            } else {
                ThreadRunAnchor::DirectBot
            },
            message: "Only the user words".into(),
            selected_skill_slugs: vec![],
            model_selection: row.map(|r| RunModelSelection {
                connection_id: r.id.clone(),
                expected_revision: r.revision,
            }),
        },
    }
}
async fn setup(
    config: &openbot_infra::db::pool::DatabaseConfig,
) -> (
    openbot_infra::db::pool::DatabasePool,
    PostgresThreadDirectory,
    PostgresModelConnections,
) {
    let pool = pool::connect(config).await.unwrap();
    let mut c = pool.get().await.unwrap();
    fresh::apply(&mut c).await.unwrap();
    c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','alice@example.test',7),('bob','bob@example.test',7);INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
 INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Bot','built_in','{}'),('remote','Remote','remote_ag_ui','{}');
 INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Bot','','seed','public'),('remote','alice','Remote','','seed','public');
 INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES('channel','Channel','',ARRAY[]::text[],ARRAY[]::text[]);
 INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
    drop(c);
    let directory = PostgresThreadDirectory::with_runtime(
        pool.clone(),
        config.clone(),
        "selection-runtime".into(),
        Duration::seconds(30),
    )
    .unwrap();
    let vault = CredentialRecordVault::single_key(
        TenantId::new(TENANT),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x51; 32]).unwrap(),
    );
    let management = PostgresModelConnections::new(
        pool.clone(),
        vault,
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        SecretBytes::new(vec![0x52; 32]),
    )
    .unwrap();
    (pool, directory, management)
}
async fn counts(pool: &openbot_infra::db::pool::DatabasePool) -> Vec<i64> {
    let c = pool.get().await.unwrap();
    let mut out = vec![];
    for table in [
        "threads",
        "thread_memberships",
        "thread_leases",
        "runs",
        "messages",
        "run_events",
        "outbox",
        "run_model_selections",
    ] {
        out.push(
            c.query_one(&format!("SELECT count(*) FROM public.{table}"), &[])
                .await
                .unwrap()
                .get(0),
        );
    }
    out
}
async fn snapshot(
    pool: &openbot_infra::db::pool::DatabasePool,
    id: &str,
) -> run_model_selections::Row {
    let c = pool.get().await.unwrap();
    run_model_selections::Row::try_from(
        &c.query_one(
            "SELECT * FROM public.run_model_selections WHERE run_id=$1",
            &[&id],
        )
        .await
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn both_anchors_three_protocols_snapshot_all_fields_and_keep_private_facts_out_of_history() {
    let admin = harness::admin_config("selection_matrix");
    harness::with_temp_database(&admin,"selectionmatrix",|config|async move {
  let(pool,directory,management)=setup(&config).await;let mut index=1;
  for channel in [false,true] {for protocol in [CustomModelProtocol::OpenaiChatCompletions,CustomModelProtocol::OpenaiResponses,CustomModelProtocol::AnthropicMessages] {
   let connection=management.create(&auth(),&input(protocol)).await.unwrap();let req=request(index,channel,Some(&connection));index+=1;
   let receipt=directory.begin_thread_run(req.clone()).await.unwrap();assert!(!receipt.replayed);
   let s=snapshot(&pool,req.command.run_id.as_str()).await;
   assert_eq!(s.run_id,req.command.run_id.as_str());assert_eq!(s.deployment_id,DEP);assert_eq!(s.tenant_id,TENANT);assert_eq!(s.owner_user_id,"alice");assert_eq!(s.auth_generation,7);assert_eq!(s.connection_id,Uuid::parse_str(&connection.id).unwrap());assert_eq!(s.connection_revision,connection.revision);assert_eq!(s.protocol,protocol.as_str());assert_eq!(s.endpoint,connection.endpoint);assert_eq!(s.model,connection.model);
   let c=pool.get().await.unwrap();let fact=c.query_one("SELECT c.current_secret_id,r.created_at,m.content,e.payload,o.payload FROM public.model_connections c JOIN public.runs r ON r.run_id=$2 JOIN public.messages m ON m.message_id=$2||':input' JOIN public.run_events e ON e.run_id=r.run_id AND e.seq=0 JOIN public.outbox o ON o.outbox_id=$2||':agent_run_dispatch' WHERE c.id=$1",&[&s.connection_id,&s.run_id]).await.unwrap();
   assert_eq!(s.secret_id,fact.get::<_,Uuid>(0));assert_eq!(s.created_at,fact.get::<_,time::OffsetDateTime>(1));let content:serde_json::Value=fact.get(2);assert_eq!(content,serde_json::json!({"text":req.command.message,"modelSelection":req.command.model_selection}));
   for position in [2,3,4] {let value:serde_json::Value=fact.get(position);let text=value.to_string();for private in ["PRIVATE_MODEL_KEY_CANARY",&s.endpoint,&s.model,&s.secret_id.to_string(),"authGeneration"] {assert!(!text.contains(private));}}
   drop(c);
   let history=directory.thread_history(openbot_application::ThreadHistoryRequest{deployment:req.deployment.clone(),tenant:req.tenant.clone(),actor:req.actor.clone(),thread:req.command.thread_id.clone()}).await.unwrap();
   let history=serde_json::to_string(&history).unwrap();assert!(!history.contains("modelSelection"));assert!(!history.contains(&s.endpoint));assert!(!history.contains(&connection.id));
   let before=counts(&pool).await;assert!(directory.begin_thread_run(req.clone()).await.unwrap().replayed);assert_eq!(before,counts(&pool).await);assert_eq!(snapshot(&pool,&s.run_id).await,s);
  }}
  let none=request(index,false,None);directory.begin_thread_run(none.clone()).await.unwrap();let c=pool.get().await.unwrap();assert!(c.query_opt("SELECT 1 FROM public.run_model_selections WHERE run_id=$1",&[&none.command.run_id.as_str()]).await.unwrap().is_none());drop(c);pool.close();Ok(())
 }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn exact_replay_keeps_binding_after_edit_disable_delete_and_rejects_changed_intent() {
    let admin = harness::admin_config("selection_replay");
    harness::with_temp_database(&admin, "selectionreplay", |config| async move {
        let (pool, directory, management) = setup(&config).await;
        let original = management
            .create(&auth(), &input(CustomModelProtocol::OpenaiResponses))
            .await
            .unwrap();
        let req = request(10, false, Some(&original));
        directory.begin_thread_run(req.clone()).await.unwrap();
        let frozen = snapshot(&pool, req.command.run_id.as_str()).await;
        let mut edit = update(&original);
        edit.model = "replacement".into();
        edit.api_key =
            Some(ModelApiKey::new(Zeroizing::new("NEW_PRIVATE_KEY_CANARY".into())).unwrap());
        let changed = management
            .update(&auth(), &original.id, &edit)
            .await
            .unwrap();
        let mut disabled = update(&changed);
        disabled.enabled = false;
        let disabled = management
            .update(&auth(), &changed.id, &disabled)
            .await
            .unwrap();
        for phase in 0..2 {
            if phase == 1 {
                management
                    .delete(
                        &auth(),
                        &disabled.id,
                        &DeleteModelConnection {
                            expected_revision: disabled.revision,
                        },
                    )
                    .await
                    .unwrap();
            }
            let before = counts(&pool).await;
            assert!(
                directory
                    .begin_thread_run(req.clone())
                    .await
                    .unwrap()
                    .replayed
            );
            assert_eq!(counts(&pool).await, before);
            assert_eq!(snapshot(&pool, &frozen.run_id).await, frozen);
        }
        let other = management
            .create(&auth(), &input(CustomModelProtocol::AnthropicMessages))
            .await
            .unwrap();
        for kind in 0..5 {
            let mut bad = req.clone();
            match kind {
                0 => bad.command.model_selection = None,
                1 => bad.command.model_selection.as_mut().unwrap().connection_id = other.id.clone(),
                2 => {
                    bad.command
                        .model_selection
                        .as_mut()
                        .unwrap()
                        .expected_revision += 1
                }
                3 => bad.command.message.push('!'),
                _ => bad.command.selected_skill_slugs = vec!["changed-skill".into()],
            };
            assert_eq!(
                directory.begin_thread_run(bad).await.unwrap_err(),
                Error::RequestConflict
            );
        }
        let none = request(11, false, None);
        directory.begin_thread_run(none.clone()).await.unwrap();
        let mut changed = none;
        changed.command.model_selection = Some(RunModelSelection {
            connection_id: other.id.clone(),
            expected_revision: other.revision,
        });
        assert_eq!(
            directory.begin_thread_run(changed).await.unwrap_err(),
            Error::RequestConflict
        );
        let c = pool.get().await.unwrap();
        c.batch_execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'")
            .await
            .unwrap();
        drop(c);
        assert_eq!(
            directory.begin_thread_run(req.clone()).await.unwrap_err(),
            Error::NotVisible
        );
        let mut current = req.clone();
        current.auth_generation = AuthGeneration::new(8);
        assert!(directory.begin_thread_run(current).await.unwrap().replayed);
        assert_eq!(snapshot(&pool, &frozen.run_id).await.auth_generation, 7);
        let c = pool.get().await.unwrap();
        c.execute(
            "DELETE FROM public.thread_memberships WHERE thread_id=$1",
            &[&req.command.thread_id.as_str()],
        )
        .await
        .unwrap();
        drop(c);
        let mut current = req;
        current.auth_generation = AuthGeneration::new(8);
        assert_eq!(
            directory.begin_thread_run(current).await.unwrap_err(),
            Error::NotVisible
        );
        pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn unavailable_sources_auth_and_corrupt_config_fail_without_partial_acceptance() {
    let admin = harness::admin_config("selection_negative");
    harness::with_temp_database(&admin,"selectionnegative",|config|async move {
  let(pool,directory,management)=setup(&config).await;let connection=management.create(&auth(),&input(CustomModelProtocol::OpenaiResponses)).await.unwrap();
  let original=request(20,false,Some(&connection));let before=counts(&pool).await;
  for kind in 0..8 {let mut req=original.clone();match kind {0=>req.command.model_selection.as_mut().unwrap().expected_revision=2,1=>req.command.model_selection.as_mut().unwrap().connection_id=Uuid::from_u128(999).to_string(),2=>req.actor=ActorId::new("bob"),3=>req.auth_generation=AuthGeneration::new(6),4=>req.tenant=TenantId::new("foreign"),5=>{req.deployment=DeploymentId::new("foreign");req.command.thread_id=ThreadIdentity::new(&req.deployment).mint_from_entropy([4;16]);},6=>req.command.bot_id=BotId::new("remote"),_=>req.command.model_selection.as_mut().unwrap().expected_revision=0};let error=directory.begin_thread_run(req).await.unwrap_err();match kind {0=>assert_eq!(error,Error::RequestConflict),6|7=>assert_eq!(error,Error::InvalidInput{field:"model_selection"}),_=>assert_eq!(error,Error::NotVisible)};assert_eq!(counts(&pool).await,before);}
  for (mutation,restore,expected) in [
   ("UPDATE public.model_connections SET enabled=false","UPDATE public.model_connections SET enabled=true",Error::NotVisible),
   ("UPDATE public.model_connections SET deleted_at=now()","UPDATE public.model_connections SET deleted_at=NULL",Error::NotVisible),
   ("DELETE FROM public.user_roles WHERE user_id='alice'","INSERT INTO public.user_roles(user_id,role) VALUES('alice','user')",Error::NotVisible),
   ("INSERT INTO public.revoked_access(email,revoked_by) VALUES('alice@example.test','bob')","DELETE FROM public.revoked_access WHERE email='alice@example.test'",Error::NotVisible),
   ("UPDATE public.agent_profiles SET deleted_at=now() WHERE agent_id='bot'","UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='bot'",Error::NotVisible),
   ("UPDATE public.model_connections SET endpoint='http://unsafe.example.test'","UPDATE public.model_connections SET endpoint='https://provider.example.test/v1/responses'",Error::Corrupt{field:"model_selection"}),
   ("UPDATE public.model_connection_secrets SET retired_at=now()","UPDATE public.model_connection_secrets SET retired_at=NULL",Error::Corrupt{field:"model_selection"}),
  ] {let c=pool.get().await.unwrap();c.batch_execute(mutation).await.unwrap();drop(c);assert_eq!(directory.begin_thread_run(original.clone()).await.unwrap_err(),expected);assert_eq!(counts(&pool).await,before);let c=pool.get().await.unwrap();c.batch_execute(restore).await.unwrap();}
  // A only freezes an active envelope reference; no decryption or model egress occurs here.
  let c=pool.get().await.unwrap();c.batch_execute("UPDATE public.model_connection_secrets SET encrypted_value='broken-envelope'").await.unwrap();drop(c);directory.begin_thread_run(original).await.unwrap();pool.close();Ok(())
 }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn current_channel_and_package_tenant_gate_and_transaction_fault_roll_back_all_facts() {
    let admin = harness::admin_config("selection_context");
    harness::with_temp_database(&admin,"selectioncontext",|config|async move {
  let(pool,directory,management)=setup(&config).await;let connection=management.create(&auth(),&input(CustomModelProtocol::OpenaiResponses)).await.unwrap();let req=request(30,true,Some(&connection));
  let c=pool.get().await.unwrap();c.batch_execute("INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES('11111111-1111-1111-1111-111111111111','foreign','qa','qa')").await.unwrap();drop(c);
  for table in ["agents","channels"] {let c=pool.get().await.unwrap();c.batch_execute(&format!("UPDATE public.{table} SET package_id='11111111-1111-1111-1111-111111111111'")).await.unwrap();drop(c);let before=counts(&pool).await;assert_eq!(directory.begin_thread_run(req.clone()).await.unwrap_err(),Error::NotVisible);assert_eq!(counts(&pool).await,before);let c=pool.get().await.unwrap();c.batch_execute(&format!("UPDATE public.{table} SET package_id=NULL")).await.unwrap();}
  let c=pool.get().await.unwrap();c.batch_execute("DELETE FROM public.channel_memberships WHERE user_id='alice'").await.unwrap();drop(c);let before=counts(&pool).await;assert_eq!(directory.begin_thread_run(req.clone()).await.unwrap_err(),Error::NotVisible);assert_eq!(before,counts(&pool).await);
  let c=pool.get().await.unwrap();c.batch_execute("INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');DELETE FROM public.channel_agents WHERE agent_id='bot'").await.unwrap();drop(c);assert_eq!(directory.begin_thread_run(req.clone()).await.unwrap_err(),Error::NotVisible);
  let c=pool.get().await.unwrap();c.batch_execute("INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');CREATE FUNCTION selection_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'owned QA injected failure';END$$;CREATE TRIGGER selection_fault BEFORE INSERT ON public.run_model_selections FOR EACH ROW EXECUTE FUNCTION selection_fault();").await.unwrap();drop(c);let before=counts(&pool).await;assert!(directory.begin_thread_run(req.clone()).await.is_err());assert_eq!(before,counts(&pool).await);
  let c=pool.get().await.unwrap();c.batch_execute("DROP TRIGGER selection_fault ON public.run_model_selections;DROP FUNCTION selection_fault();").await.unwrap();drop(c);directory.begin_thread_run(req.clone()).await.unwrap();
  let c=pool.get().await.unwrap();c.batch_execute("DELETE FROM public.channel_memberships WHERE user_id='alice'").await.unwrap();drop(c);assert_eq!(directory.begin_thread_run(req).await.unwrap_err(),Error::NotVisible);pool.close();Ok(())
 }).await;
}

async fn wait_for_lock_waiters(pool: &openbot_infra::db::pool::DatabasePool, minimum: i64) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let c = tokio::time::timeout_at(deadline, pool.get())
            .await
            .expect("observer pool deadline")
            .unwrap();
        let waiting:i64=c.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND pid<>pg_backend_pid()",&[]).await.unwrap().get(0);
        if waiting >= minimum {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected actual PostgreSQL lock waiter"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn actor_and_connection_changes_serialize_in_both_orders_with_begin_snapshot() {
    let admin = harness::admin_config("selection_locks");
    harness::with_temp_database(&admin,"selectionlocks",|config|async move {
  let config=config.with_max_pool_size(4);
  let(pool,directory,management)=setup(&config).await;
  for actor in [true,false] {
   let row=management.create(&auth(),&input(CustomModelProtocol::OpenaiResponses)).await.unwrap();
   let id=Uuid::parse_str(&row.id).unwrap();let index=if actor {50}else{60};
   let mut blocker=pool.get().await.unwrap();let tx=blocker.transaction().await.unwrap();
   if actor {tx.batch_execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'").await.unwrap();}
   else {tx.execute("UPDATE public.model_connections SET enabled=false WHERE id=$1",&[&id]).await.unwrap();}
   let req=request(index,false,Some(&row));let cloned=directory.clone();
   let pending=tokio::spawn(async move{cloned.begin_thread_run(req).await});
   wait_for_lock_waiters(&pool,1).await;assert!(!pending.is_finished());tx.commit().await.unwrap();
   assert_eq!(pending.await.unwrap().unwrap_err(),Error::NotVisible);
   let c=pool.get().await.unwrap();c.batch_execute("UPDATE public.users SET auth_generation=7 WHERE id='alice'").await.unwrap();c.execute("UPDATE public.model_connections SET enabled=true WHERE id=$1",&[&id]).await.unwrap();drop(c);
   // Gate INSERT after Begin has acquired both actor and source Share locks. No timing-only proof.
   let c=pool.get().await.unwrap();c.batch_execute("CREATE FUNCTION selection_gate() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(8675309);RETURN NEW;END$$;CREATE TRIGGER selection_gate BEFORE INSERT ON public.run_model_selections FOR EACH ROW EXECUTE FUNCTION selection_gate();").await.unwrap();drop(c);
   let gate=blocker.transaction().await.unwrap();gate.query_one("SELECT pg_advisory_xact_lock(8675309)",&[]).await.unwrap();
   let req=request(index+1,false,Some(&row));let run=req.command.run_id.clone();let cloned=directory.clone();let accepted=tokio::spawn(async move{cloned.begin_thread_run(req).await});
   wait_for_lock_waiters(&pool,1).await;
   let changer=pool.get().await.unwrap();let changed=tokio::spawn(async move{
     if actor {changer.batch_execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'").await.unwrap();}
     else {changer.execute("UPDATE public.model_connections SET enabled=false,revision=revision+1 WHERE id=$1",&[&id]).await.unwrap();}
   });
   wait_for_lock_waiters(&pool,2).await;assert!(!accepted.is_finished());assert!(!changed.is_finished());gate.commit().await.unwrap();
   assert!(!accepted.await.unwrap().unwrap().replayed);changed.await.unwrap();
   let frozen=snapshot(&pool,run.as_str()).await;assert_eq!(frozen.auth_generation,7);assert_eq!(frozen.connection_revision,1);
   assert_eq!(directory.begin_thread_run(request(index+2,false,Some(&row))).await.unwrap_err(),Error::NotVisible);
   let c=pool.get().await.unwrap();c.batch_execute("DROP TRIGGER selection_gate ON public.run_model_selections;DROP FUNCTION selection_gate();UPDATE public.users SET auth_generation=7 WHERE id='alice'").await.unwrap();
  }
  pool.close();Ok(())
 }).await;
}

#[derive(Default)]
struct LegacyProviderSpy(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl openbot_application::ProviderAdapter for LegacyProviderSpy {
    async fn start(
        &self,
        request: openbot_application::ProviderRequest,
    ) -> Result<Box<dyn openbot_application::ProviderSession>, openbot_application::ProviderPortError>
    {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            request.route,
            openbot_application::ProviderRoute::PackageOpenAi
        ));
        Ok(Box::new(LegacyProviderSession(
            vec![
                openbot_application::ProviderEvent::ResponseStarted {
                    response_id: "legacy-positive".into(),
                },
                openbot_application::ProviderEvent::TextDelta {
                    index: 0,
                    delta: "Legacy route remains usable".into(),
                },
                openbot_application::ProviderEvent::Usage(openbot_application::ProviderUsage {
                    input_tokens: 2,
                    output_tokens: 3,
                    total_tokens: 5,
                }),
                openbot_application::ProviderEvent::Completed,
            ]
            .into(),
        )))
    }
}
struct LegacyProviderSession(std::collections::VecDeque<openbot_application::ProviderEvent>);
#[async_trait::async_trait]
impl openbot_application::ProviderSession for LegacyProviderSession {
    async fn next_event(
        &mut self,
    ) -> Result<Option<openbot_application::ProviderEvent>, openbot_application::ProviderPortError>
    {
        Ok(self.0.pop_front())
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn custom_binding_requires_both_halves_and_missing_adapter_never_starts_legacy_provider() {
    use openbot_application::{
        AgentContextError, AgentContextSource, RunExecutionLease, RunRuntime,
    };
    use openbot_infra::provider::context::PostgresAgentContextSource;
    use openbot_infra::run_runtime::{
        DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay,
    };
    use std::sync::{Arc, atomic::Ordering};
    let admin = harness::admin_config("selection_context_guard");
    harness::with_temp_database(&admin, "selectionguard", |config| async move {
        let config = config.with_max_pool_size(4);
        let (pool, directory, management) = setup(&config).await;
        let row = management.create(&auth(), &input(CustomModelProtocol::OpenaiResponses)).await.unwrap();
        let c = pool.get().await.unwrap();
        c.batch_execute("UPDATE public.agents SET configuration='{\"systemPrompt\":\"Normal standing prompt.\",\"providerSource\":\"package\"}' WHERE id='bot'").await.unwrap();
        drop(c);
        let context = Arc::new(PostgresAgentContextSource::new(pool.clone(), DeploymentId::new(DEP), TenantId::new(TENANT), Some(32)).unwrap());
        let mut runs = Vec::new();
        for mode in 0..5 {
            let req = request(70 + mode, false, (mode < 3).then_some(&row));
            directory.begin_thread_run(req.clone()).await.unwrap();
            let c = pool.get().await.unwrap();
            match mode {
                1 => {c.execute("DELETE FROM public.run_model_selections WHERE run_id=$1", &[&req.command.run_id.as_str()]).await.unwrap();},
                2 => {c.execute("UPDATE public.messages SET content=content-'modelSelection' WHERE message_id=$1||':input'", &[&req.command.run_id.as_str()]).await.unwrap();},
                3 => {c.execute("UPDATE public.messages SET content=content||'{\"modelSelection\":null}'::jsonb WHERE message_id=$1||':input'", &[&req.command.run_id.as_str()]).await.unwrap();},
                _ => {}
            }
            drop(c);
            let lease = RunExecutionLease::new(req.command.run_id.clone(), req.command.thread_id.clone(), req.command.bot_id.clone(), req.actor.clone(), openbot_domain::thread::FencingToken::new(1).unwrap(), 0).unwrap();
            if mode == 0 {
                assert!(matches!(context.load(&lease).await.unwrap().route, openbot_application::ProviderRoute::CustomModel(_)));
            } else if mode < 4 {
                assert_eq!(context.load(&lease).await.unwrap_err(), AgentContextError::Corrupt { field: "model_selection_storage" });
            } else {
                assert!(matches!(context.load(&lease).await.unwrap().route, openbot_application::ProviderRoute::PackageOpenAi));
            }
            runs.push(req.command.run_id);
        }
        let runtime: Arc<dyn RunRuntime> = Arc::new(PostgresRunRuntime::new(pool.clone(), "selection-runtime".into(), Duration::seconds(30), DEFAULT_DISPATCH_CLAIM_DURATION).unwrap());
        let provider = Arc::new(LegacyProviderSpy::default());
        let agent = openbot_agent::BuiltInAgentRuntime::start(
            runtime.clone(), context, Arc::new(openbot_agent::ProviderRouter::new(provider.clone(), None)), Arc::new(openbot_agent::NoAgentToolInvoker),
            Arc::new(openbot_infra::agent_audit::PostgresAgentAudit::new(pool.clone(), vec![0x52;32]).unwrap()),
            openbot_agent::BuiltInAgentConfig { queue_capacity: 8, max_concurrency: 2, max_tool_concurrency: 1,
                lease_renew_interval: std::time::Duration::from_secs(1), run_deadline: Some(std::time::Duration::from_secs(10)) },
        ).unwrap();
        let relay = RunRelay::start(runtime, agent.consumer());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut terminal = false;
        while tokio::time::Instant::now() < deadline {
            let c = pool.get().await.unwrap();
            let active:i64=c.query_one("SELECT count(*) FROM public.runs WHERE status='running'",&[]).await.unwrap().get(0);
            if active == 0 { terminal = true; break; }
            drop(c);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        relay.stop().await;
        agent.stop().await;
        assert!(terminal, "real runtime must produce closed terminal outcomes");
        let c = pool.get().await.unwrap();
        for (mode, run) in runs.iter().enumerate() {
            let row=c.query_one("SELECT r.status,r.error_code,(SELECT count(*) FROM public.run_events e WHERE e.run_id=r.run_id AND e.terminal) AS terminals,(SELECT count(*) FROM public.messages m WHERE m.run_id=r.run_id AND m.role='assistant') AS assistant_messages FROM public.runs r WHERE r.run_id=$1", &[&run.as_str()]).await.unwrap();
            assert_eq!(row.get::<_,i64>("terminals"),1);
            if mode < 4 {
                assert_eq!(row.get::<_,String>("status"),"failed");
                assert_eq!(row.get::<_,Option<String>>("error_code").as_deref(),Some("provider_invalid_response"));
                assert_eq!(row.get::<_,i64>("assistant_messages"),0);
            } else {assert_eq!(row.get::<_,String>("status"),"completed");assert_eq!(row.get::<_,i64>("assistant_messages"),1);}
        }
        assert_eq!(provider.0.load(Ordering::SeqCst),1,"only the marker-free legacy run reaches provider.start");
        println!("custom_binding valid=1; malformed_halves=3; missing_adapter_or_malformed_failed=4; legacy_completed=1; provider_starts=1; terminal_per_run=1");
        drop(c);pool.close();Ok(())
    }).await;
}

// Own-DB corruption control for the input-metadata matrix below. Each statement declares, in
// order, every exact refusal (trigger, 55000 message) that the 0050/0051 thread-history writer
// guards give it as ordinary DML; an empty declaration asserts the ordinary DML is accepted.
// Only each observed trigger is disabled, and every disabled trigger is origin-enabled again
// before the owned COMMIT.
const BODY_REFUSAL: &[(&str, &str)] = &[(
    "messages_history_body_before",
    "thread_history_writer_binding_invalid",
)];
async fn owned_dml(
    pool: &openbot_infra::db::pool::DatabasePool,
    table: &str,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    refusals: &[(&str, &str)],
) {
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
        .await
        .unwrap();
    let triggers: Vec<(String, String)> = tx
        .query(
            "SELECT t.tgname::text,p.proname::text FROM pg_catalog.pg_trigger t \
             JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid \
             WHERE t.tgrelid=('public.'||$1)::regclass AND NOT t.tgisinternal",
            &[&table],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let mut disabled = 0;
    loop {
        tx.batch_execute("SAVEPOINT owned_dml_probe").await.unwrap();
        match tx.execute(sql, params).await {
            Ok(changed) => {
                assert_eq!(
                    disabled,
                    refusals.len(),
                    "{sql}: declared refusal {:?} did not occur",
                    refusals.get(disabled)
                );
                assert!(changed > 0, "{sql}: owned corruption changed no row");
                break;
            }
            Err(error) => {
                let db = error
                    .as_db_error()
                    .unwrap_or_else(|| panic!("{sql}: {error}"));
                let observed: Vec<&str> = triggers
                    .iter()
                    .filter(|(_, function)| {
                        db.where_()
                            .is_some_and(|w| w.contains(&format!("{function}(")))
                    })
                    .map(|(trigger, _)| trigger.as_str())
                    .collect();
                let Some(&(trigger, message)) = refusals.get(disabled) else {
                    panic!(
                        "{sql}: undeclared refusal {} {} {observed:?}",
                        db.code().code(),
                        db.message()
                    );
                };
                assert_eq!(
                    (db.code().code(), db.message(), observed.as_slice()),
                    ("55000", message, [trigger].as_slice()),
                    "{sql}"
                );
                tx.batch_execute(&format!("ROLLBACK TO SAVEPOINT owned_dml_probe; ALTER TABLE public.{table} DISABLE TRIGGER {trigger}")).await.unwrap();
                disabled += 1;
            }
        }
    }
    for (trigger, _) in &refusals[..disabled] {
        tx.batch_execute(&format!(
            "ALTER TABLE public.{table} ENABLE TRIGGER {trigger}"
        ))
        .await
        .unwrap();
    }
    let disabled_now: i64 = tx
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid=('public.'||$1)::regclass AND NOT tgisinternal AND tgenabled<>'O'",
            &[&table],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        disabled_now, 0,
        "owned {table} guards were not restored before COMMIT"
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn custom_binding_requires_both_halves_even_when_input_metadata_is_corrupt() {
    use openbot_application::{
        AgentContextError, AgentContextSource, RunExecutionLease, RunRuntime,
    };
    use openbot_infra::provider::context::PostgresAgentContextSource;
    use openbot_infra::run_runtime::{
        DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay,
    };
    use std::sync::{Arc, atomic::Ordering};

    let admin = harness::admin_config("selection_marker_metadata");
    for mode in 0..4 {
        harness::with_temp_database(&admin, "selectionmarker", |config| async move {
            let config = config.with_max_pool_size(4);
            let (pool, directory, management) = setup(&config).await;
            let model = management.create(&auth(), &input(CustomModelProtocol::OpenaiResponses)).await.unwrap();
            let req = request(170 + mode, false, Some(&model));
            directory.begin_thread_run(req.clone()).await.unwrap();
            let c = pool.get().await.unwrap();
            c.batch_execute("UPDATE public.agents SET configuration='{\"systemPrompt\":\"Normal prompt.\",\"providerSource\":\"package\"}' WHERE id='bot'").await.unwrap();
            c.execute("DELETE FROM public.run_model_selections WHERE run_id=$1", &[&req.command.run_id.as_str()]).await.unwrap();
            let message_id = format!("{}:input", req.command.run_id.as_str());
            match mode {
                0 => owned_dml(&pool, "messages", "UPDATE public.messages SET role='assistant' WHERE message_id=$1", &[&message_id], &[]).await,
                1 => owned_dml(&pool, "messages", "UPDATE public.messages SET run_id='another-owned-run' WHERE message_id=$1", &[&message_id], BODY_REFUSAL).await,
                2 => {
                    owned_dml(&pool, "threads", "INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,next_message_seq,next_event_seq,created_at,updated_at) SELECT 'another-owned-thread',tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,next_message_seq,next_event_seq,created_at,updated_at FROM public.threads WHERE thread_id=$1", &[&req.command.thread_id.as_str()], &[]).await;
                    owned_dml(&pool, "messages", "UPDATE public.messages SET thread_id='another-owned-thread' WHERE message_id=$1", &[&message_id], BODY_REFUSAL).await
                }
                _ => owned_dml(&pool, "messages", "UPDATE public.messages SET actor_id='bob' WHERE message_id=$1", &[&message_id], &[]).await,
            }
            let marker: bool = c.query_one("SELECT content ? 'modelSelection' FROM public.messages WHERE message_id=$1", &[&message_id]).await.unwrap().get(0);
            assert!(marker, "the exact original input retains explicit intent in every corruption case");
            drop(c);
            let lease = RunExecutionLease::new(req.command.run_id.clone(), req.command.thread_id.clone(), req.command.bot_id.clone(), req.actor.clone(), openbot_domain::thread::FencingToken::new(1).unwrap(), 0).unwrap();
            let context = Arc::new(PostgresAgentContextSource::new(pool.clone(), DeploymentId::new(DEP), TenantId::new(TENANT), Some(32)).unwrap());
            assert_eq!(context.load(&lease).await.unwrap_err(), AgentContextError::Corrupt { field: "model_selection_storage" });
            let runtime: Arc<dyn RunRuntime> = Arc::new(PostgresRunRuntime::new(pool.clone(), "selection-runtime".into(), Duration::seconds(30), DEFAULT_DISPATCH_CLAIM_DURATION).unwrap());
            let provider = Arc::new(LegacyProviderSpy::default());
            let agent = openbot_agent::BuiltInAgentRuntime::start(runtime.clone(), context,
                Arc::new(openbot_agent::ProviderRouter::new(provider.clone(), None)), Arc::new(openbot_agent::NoAgentToolInvoker),
                Arc::new(openbot_infra::agent_audit::PostgresAgentAudit::new(pool.clone(), vec![0x52; 32]).unwrap()),
                openbot_agent::BuiltInAgentConfig { queue_capacity: 8, max_concurrency: 2, max_tool_concurrency: 1,
                    lease_renew_interval: std::time::Duration::from_secs(1), run_deadline: Some(std::time::Duration::from_secs(10)) },
            ).unwrap();
            let relay = RunRelay::start(runtime, agent.consumer());
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut finished = false;
            while tokio::time::Instant::now() < deadline {
                let c = pool.get().await.unwrap();
                let status: String = c.query_one("SELECT status FROM public.runs WHERE run_id=$1", &[&req.command.run_id.as_str()]).await.unwrap().get(0);
                if status != "running" { finished = true; break; }
                drop(c); tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            relay.stop().await; agent.stop().await;
            assert!(finished);
            let c = pool.get().await.unwrap();
            let row = c.query_one("SELECT status,error_code,(SELECT count(*) FROM public.run_events e WHERE e.run_id=r.run_id AND e.terminal) AS terminals FROM public.runs r WHERE run_id=$1", &[&req.command.run_id.as_str()]).await.unwrap();
            assert_eq!(row.get::<_, String>("status"), "failed");
            assert_eq!(row.get::<_, Option<String>>("error_code").as_deref(), Some("provider_invalid_response"));
            assert_eq!(row.get::<_, i64>("terminals"), 1);
            assert_eq!(provider.0.load(Ordering::SeqCst), 0, "metadata corruption with missing snapshot cannot start any fallback provider");
            println!("missing_snapshot + input_metadata_mode={mode}: marker=1; context=closed; terminal=failed/1; provider_starts=0");
            drop(c); pool.close(); Ok(())
        }).await;
    }
}
