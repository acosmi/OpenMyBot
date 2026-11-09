//! Exact migration/catalog and automation acceptance against explicitly owned PostgreSQL.

mod harness;

use openbot_infra::automation::schema;
use openbot_infra::db::{baseline, desktop_vault_canary, fresh, native, pool, schema_facts};

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn fresh_upgrade_and_current_schema_are_exact() {
    let admin = harness::admin_config("automation_schema");
    for fresh_install in [false, true] {
        harness::with_temp_database(&admin, "automation_schema", |config| async move {
            let pool = pool::connect(&config).await.unwrap();
            let mut client = pool.get().await.unwrap();
            if fresh_install {
                assert!(matches!(fresh::apply(&mut client).await.unwrap(),
                    fresh::FreshApplyOutcome::Applied(native::ApplyOutcome::Applied)));
            } else {
                baseline::apply(&client).await.unwrap();
                assert_eq!(native::apply_through(&mut client, native::NATIVE_0053_VERSION).await.unwrap(),
                    native::ApplyOutcome::Applied);
                let before = schema_facts::fetch(&client).await.unwrap();
                assert_eq!(native::apply(&mut client).await.unwrap(), native::ApplyOutcome::Applied);
                assert_eq!(schema_facts::fetch(&client).await.unwrap(), before,
                    "automation migration must preserve the complete original public layout");
            }
            assert_eq!(native::apply(&mut client).await.unwrap(), native::ApplyOutcome::AlreadyApplied);
            let tx = client.build_postgres_transaction().start().await.unwrap();
            let facts = schema::capture(&tx).await.unwrap();
            assert_eq!(facts["tables"].as_array().unwrap().len(), 13);
            assert_eq!(facts["constraints"].as_array().unwrap().len(), 111);
            schema::verify(&tx).await.unwrap();
            tx.rollback().await.unwrap();

            // Each real mutation is rolled back; the observer cannot learn or repair the drift.
            for mutation in [
                "ALTER TABLE openbot_internal.automation_definitions ADD COLUMN unexpected text",
                "ALTER TABLE openbot_internal.automation_workspace_capacity DROP CONSTRAINT automation_workspace_capacity_active_count_check",
                "ALTER TABLE openbot_internal.automation_definitions ALTER COLUMN created_at DROP DEFAULT",
                "ALTER TABLE openbot_internal.automation_definitions ENABLE ROW LEVEL SECURITY",
                "GRANT SELECT ON openbot_internal.automation_definitions TO PUBLIC",
                "CREATE TABLE openbot_internal.automation_unregistered(id text)",
            ] {
                let tx = client.build_postgres_transaction().start().await.unwrap();
                tx.batch_execute(mutation).await.unwrap();
                assert!(schema::verify(&tx).await.is_err(), "catalog drift was accepted: {mutation}");
                tx.rollback().await.unwrap();
            }
            // A committed extra index must also be refused by the real current migration entry.
            client.batch_execute("CREATE INDEX automation_unregistered_idx ON openbot_internal.automation_definitions(owner_id)").await.unwrap();
            assert!(native::apply(&mut client).await.is_err());
            client.batch_execute("DROP INDEX openbot_internal.automation_unregistered_idx").await.unwrap();
            assert_eq!(native::apply(&mut client).await.unwrap(), native::ApplyOutcome::AlreadyApplied);
            client.execute("UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=$1",
                &[&native::NATIVE_0054_VERSION]).await.unwrap();
            assert!(native::apply(&mut client).await.is_err());
            client.execute("UPDATE openbot_internal.schema_migrations SET checksum=$2 WHERE version=$1",
                &[&native::NATIVE_0054_VERSION, &native::native_0054_checksum()]).await.unwrap();
            assert_eq!(native::apply(&mut client).await.unwrap(), native::ApplyOutcome::AlreadyApplied);
            drop(client);
            pool.close();
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn canary_accepts_0053_before_upgrade_and_requires_0054_for_current() {
    let admin = harness::admin_config("automation_canary");
    harness::with_temp_database(&admin, "automation_canary", |config| async move {
        let pool = pool::connect(&config).await.unwrap();
        let mut client = pool.get().await.unwrap();
        baseline::apply(&client).await.unwrap();
        assert_eq!(
            native::apply_through(&mut client, native::NATIVE_0053_VERSION)
                .await
                .unwrap(),
            native::ApplyOutcome::Applied
        );
        drop(client);
        let before = desktop_vault_canary::verify_pre_upgrade_layout(&pool)
            .await
            .expect("an exact 0053 database must remain eligible to upgrade");
        assert_eq!(before.native_version(), native::NATIVE_0053_VERSION);
        assert!(
            desktop_vault_canary::verify_current_layout(&pool)
                .await
                .is_err()
        );

        let client = pool.get().await.unwrap();
        client.batch_execute(
            "ALTER FUNCTION openbot_internal.thread_history_terminal_payload(text,jsonb) COST 101",
        ).await.unwrap();
        drop(client);
        assert!(
            desktop_vault_canary::verify_pre_upgrade_layout(&pool)
                .await
                .is_err()
        );

        let mut client = pool.get().await.unwrap();
        client.batch_execute(
            "ALTER FUNCTION openbot_internal.thread_history_terminal_payload(text,jsonb) COST 100",
        ).await.unwrap();
        assert_eq!(
            native::apply(&mut client).await.unwrap(),
            native::ApplyOutcome::Applied
        );
        drop(client);
        let after = desktop_vault_canary::verify_pre_upgrade_layout(&pool)
            .await
            .unwrap();
        assert_eq!(after.native_version(), native::NATIVE_0054_VERSION);
        desktop_vault_canary::verify_current_layout(&pool)
            .await
            .unwrap();
        pool.close();
        Ok(())
    })
    .await;
}

#[cfg(feature = "server-runtime")]
#[path = "support/delegated_assembly_fixture.rs"]
pub mod assembly_fixture;
#[cfg(feature = "server-runtime")]
use openbot_application::automation::{
    AutomationDefinitions, AutomationDispatchQueue, AutomationDispatcher,
};
#[cfg(feature = "server-runtime")]
use openbot_contracts::{
    automation::*,
    command::{AppCommand, AppReply},
    error::AppError,
};
#[cfg(feature = "server-runtime")]
use serde_json::{Value, json};

#[cfg(feature = "server-runtime")]
fn config() -> AutomationConfigV1 {
    serde_json::from_value(json!({"schemaVersion":1,"title":"Manual","botId":"delegated-bot",
        "promptTemplate":"Inspect the original owner input.","trigger":{"kind":"manual"},"modelPolicy":"bot_current",
        "permissionCeiling":{"toolIds":[],"dataScopes":[]},"budget":[{"metric":"sampling_calls","totalLimit":"10"}],"runDeadlineSeconds":60})).unwrap()
}
#[cfg(feature = "server-runtime")]
fn id(raw: &str) -> AutomationId {
    raw.to_owned().try_into().unwrap()
}
#[cfg(feature = "server-runtime")]
fn revision(raw: i64) -> AutomationRevision {
    raw.try_into().unwrap()
}
#[cfg(feature = "server-runtime")]
async fn create(f: &assembly_fixture::Fixture, name: &str) -> AutomationDefinition {
    match f
        .assembly
        .application
        .execute(
            f.auth.clone(),
            AppCommand::CreateAutomationDefinition(CreateAutomationDefinition {
                automation_id: id(name),
                config: config(),
            }),
        )
        .await
        .unwrap()
    {
        AppReply::AutomationDefinitionCreated(definition) => definition,
        other => panic!("unexpected creation reply: {other:?}"),
    }
}
#[cfg(feature = "server-runtime")]
async fn enable(f: &assembly_fixture::Fixture, name: &str, expected: i64) -> AutomationDefinition {
    match f
        .assembly
        .application
        .execute(
            f.auth.clone(),
            AppCommand::UpdateAutomationDefinition {
                automation_id: id(name),
                input: UpdateAutomationDefinition::Enable {
                    expected_revision: revision(expected),
                    grant_consent: AutomationGrantConsent {
                        validity: AutomationGrantValidity::UntilRevoked {},
                    },
                },
            },
        )
        .await
        .unwrap()
    {
        AppReply::AutomationDefinition(definition) => definition,
        other => panic!("unexpected enable reply: {other:?}"),
    }
}
#[cfg(feature = "server-runtime")]
async fn install_budgets(f: &assembly_fixture::Fixture, limit: &str) {
    let wire:AutomationBudgetsFile=serde_json::from_value(json!({"schemaVersion":1,"revision":1,
        "workspaces":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),"budget":[{"metric":"sampling_calls","totalLimit":limit}]}],
        "owners":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),"ownerId":f.auth.actor(),"budget":[{"metric":"sampling_calls","totalLimit":limit}]}]})).unwrap();
    let budgets = openbot_domain::automation::AutomationBudgets::try_from(wire).unwrap();
    f.assembly
        .automations
        .as_ref()
        .unwrap()
        .install_budgets(Some(&budgets))
        .await
        .unwrap();
}
#[cfg(feature = "server-runtime")]
async fn trigger(
    f: &assembly_fixture::Fixture,
    name: &str,
    operation: &str,
    expected: i64,
) -> AutomationReceipt {
    match f
        .assembly
        .application
        .execute(
            f.auth.clone(),
            AppCommand::TriggerAutomationDefinition {
                automation_id: id(name),
                input: TriggerAutomationDefinition {
                    operation_id: operation.to_owned().try_into().unwrap(),
                    expected_revision: revision(expected),
                },
            },
        )
        .await
        .unwrap()
    {
        AppReply::AutomationReceiptAccepted(receipt) | AppReply::AutomationReceipt(receipt) => {
            receipt
        }
        other => panic!("unexpected manual reply: {other:?}"),
    }
}
#[cfg(feature = "server-runtime")]
async fn image(f: &assembly_fixture::Fixture) -> Value {
    let core = f.image().await.unwrap();
    let client = f.pool.get().await.unwrap();
    let mut automation = serde_json::Map::new();
    for table in [
        "automation_definitions",
        "automation_definition_revisions",
        "automation_delegations",
        "automation_receivers",
        "automation_deliveries",
        "automation_occurrences",
        "automation_cron_progress",
        "automation_workspace_capacity",
        "automation_budget_policies",
        "automation_budget_balances",
        "automation_budget_attempts",
        "automation_budget_reservations",
        "automation_receiver_refusals",
    ] {
        let value:Value=client.query_one(&format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM openbot_internal.{table} t"),&[]).await.unwrap().get(0);
        automation.insert(table.to_owned(), value);
    }
    let mut control = serde_json::Map::new();
    for table in [
        "public.thread_memberships",
        "public.thread_leases",
        "public.thread_run_occupancy",
        "public.audit_events",
        "openbot_internal.thread_pending_inputs",
        "openbot_internal.thread_history_heads",
    ] {
        let value:Value=client.query_one(&format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM {table} t"),&[]).await.unwrap().get(0);
        control.insert(table.to_owned(), value);
    }
    json!({"core":core,"automation":automation,"control":control})
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn definition_revision_owner_scope_and_exclusive_thread() {
    let admin = harness::admin_config("automation_definition");
    harness::with_temp_database(&admin,"automation_definition",|database|async move{
        use openbot_contracts::auth::{AuthContextBuilder,AuthGeneration,Role};
        use openbot_contracts::ids::{ActorId,DeploymentId,TenantId};
        let f=assembly_fixture::Fixture::with_options(&database,assembly_fixture::Options{automation:true,..Default::default()}).await?;
        let result:Result<(),String>=async{
            let created=create(&f,"definition").await;
            assert_eq!(created.state,AutomationDefinitionState::Paused);assert_eq!(created.revision.get(),1);assert!(!created.grant.valid);
            let client=f.pool.get().await.unwrap();
            let thread=client.query_one("SELECT t.deployment_id,t.tenant_id,t.created_by,t.anchor_kind,t.anchor_id,(SELECT count(*) FROM public.thread_memberships m WHERE m.thread_id=t.thread_id) AS members FROM public.threads t WHERE t.thread_id=$1",&[&created.thread_id.as_str()]).await.unwrap();
            assert_eq!(thread.get::<_,String>("deployment_id"),f.auth.deployment().as_str());
            assert_eq!(thread.get::<_,String>("tenant_id"),f.auth.tenant().as_str());
            assert_eq!(thread.get::<_,String>("created_by"),f.auth.actor().as_str());
            assert_eq!(thread.get::<_,String>("anchor_kind"),"direct_bot");assert_eq!(thread.get::<_,String>("anchor_id"),"delegated-bot");assert_eq!(thread.get::<_,i64>("members"),1);
            assert_eq!(client.query_one("SELECT count(*) FROM public.runs",&[]).await.unwrap().get::<_,i64>(0),0);
            client.execute("INSERT INTO public.user_roles(user_id,role) VALUES('other-owner','admin') ON CONFLICT DO NOTHING",&[]).await.unwrap();drop(client);
            let before=image(&f).await;
            let replay=f.assembly.application.execute(f.auth.clone(),AppCommand::CreateAutomationDefinition(CreateAutomationDefinition{automation_id:id("definition"),config:config()})).await.unwrap();
            assert!(matches!(replay,AppReply::AutomationDefinition(ref d) if d.thread_id==created.thread_id));assert_eq!(image(&f).await,before);
            let mut different=config();different.title="Different intent".to_owned();
            assert_eq!(f.assembly.application.execute(f.auth.clone(),AppCommand::CreateAutomationDefinition(CreateAutomationDefinition{automation_id:id("definition"),config:different})).await.unwrap_err(),AppError::AutomationOperationConflict);
            assert_eq!(image(&f).await,before);
            let other=AuthContextBuilder::from_verified_session(f.auth.deployment().clone(),f.auth.tenant().clone(),ActorId::new("other-owner"),AuthGeneration::new(0),false).with_roles([Role::Admin,Role::User]).build();
            for actor in [other,AuthContextBuilder::from_verified_session(DeploymentId::new("foreign-deployment"),TenantId::new("foreign-tenant"),f.auth.actor().clone(),f.auth.auth_generation(),false).with_roles([Role::Admin,Role::User]).build()]{
                let existing=f.assembly.application.execute(actor.clone(),AppCommand::GetAutomationDefinition{automation_id:id("definition")}).await.unwrap_err();
                let missing=f.assembly.application.execute(actor,AppCommand::GetAutomationDefinition{automation_id:id("absent")}).await.unwrap_err();
                assert_eq!(existing,AppError::NotVisible);assert_eq!(existing,missing);
            }
            let no_budget=f.assembly.application.execute(f.auth.clone(),AppCommand::UpdateAutomationDefinition{automation_id:id("definition"),input:UpdateAutomationDefinition::Enable{expected_revision:revision(1),grant_consent:AutomationGrantConsent{validity:AutomationGrantValidity::UntilRevoked{}}}}).await.unwrap_err();
            assert_eq!(no_budget,AppError::AutomationBudgetUnconfigured);assert_eq!(image(&f).await,before);
            install_budgets(&f,"20").await;let enabled=enable(&f,"definition",1).await;
            assert_eq!(enabled.revision.get(),2);assert!(enabled.grant.valid);assert_eq!(enabled.state,AutomationDefinitionState::Enabled);
            let before=image(&f).await;
            assert_eq!(f.assembly.application.execute(f.auth.clone(),AppCommand::UpdateAutomationDefinition{automation_id:id("definition"),input:UpdateAutomationDefinition::Pause{expected_revision:revision(1)}}).await.unwrap_err(),AppError::AutomationRevisionConflict);
            assert_eq!(image(&f).await,before);
            let registry=std::sync::Arc::new(openbot_infra::artifact_registry::ArtifactDatasetRegistry::from_server(
                f.pool.clone(),f.auth.deployment(),f.auth.tenant()).await.unwrap());
            f.assembly.model_dataset_binding.enroll_original_registry(&registry).unwrap();
            let before=image(&f).await;
            // All direct-assistant paths refuse the dedicated Thread before creating queue/Run facts.
            for command in [
                AppCommand::ListBotThreads{bot_id:config().bot_id,status:None,cursor:None,limit:None},
                AppCommand::SetThreadTitle{thread_id:created.thread_id.clone(),title:"Not direct work".to_owned()},
                AppCommand::SubmitThreadInput(openbot_contracts::command::BeginThreadRunV2{
                    artifact_refs:Vec::new(),thread_id:created.thread_id.clone(),run_id:openbot_contracts::ids::RunId::new("direct-input"),bot_id:config().bot_id,
                    anchor:openbot_contracts::command::ThreadRunAnchor::DirectBot,message:"Not an automation trigger".to_owned(),selected_skill_slugs:Vec::new(),
                    model_selection:openbot_contracts::versioned_model_selection::RunModelSelectionV2::new(
                        openbot_contracts::versioned_model_selection::ModelSelectionIntentSource::Custom,
                        "10000000-0000-4000-8000-000000000001".to_owned(),1,"custom:10000000-0000-4000-8000-000000000001".to_owned(),1).unwrap(),
                }),
                AppCommand::ListPendingInputs{thread_id:created.thread_id.clone()},
                AppCommand::WithdrawPendingInput{thread_id:created.thread_id.clone(),run_id:openbot_contracts::ids::RunId::new("absent")},
                AppCommand::ReleasePendingInput{thread_id:created.thread_id.clone(),run_id:openbot_contracts::ids::RunId::new("absent")},
                AppCommand::StopThreadWork{thread_id:created.thread_id.clone(),run_id:None},
                AppCommand::CompleteThread{thread_id:created.thread_id.clone()},
            ]{assert_eq!(f.assembly.application.execute(f.auth.clone(),command).await.unwrap_err(),AppError::AnchorUnsupported);}
            assert_eq!(image(&f).await,before);
            core_reference_counterexamples(&database,&f,&created.thread_id).await;
            let paused=f.assembly.application.execute(f.auth.clone(),AppCommand::UpdateAutomationDefinition{automation_id:id("definition"),input:UpdateAutomationDefinition::Pause{expected_revision:revision(2)}}).await.unwrap();
            assert!(matches!(paused,AppReply::AutomationDefinition(ref d) if d.revision.get()==3 && d.grant.valid && d.state==AutomationDefinitionState::Paused));
            let tombstoned=f.assembly.application.execute(f.auth.clone(),AppCommand::TombstoneAutomationDefinition{automation_id:id("definition"),input:TombstoneAutomationDefinition{expected_revision:revision(3)}}).await.unwrap();
            assert!(matches!(tombstoned,AppReply::AutomationDefinition(ref d) if d.revision.get()==4 && !d.grant.valid && d.state==AutomationDefinitionState::Tombstoned));
            assert_eq!(f.assembly.application.execute(f.auth.clone(),AppCommand::UpdateAutomationDefinition{automation_id:id("definition"),input:UpdateAutomationDefinition::Enable{expected_revision:revision(4),grant_consent:AutomationGrantConsent{validity:AutomationGrantValidity::UntilRevoked{}}}}).await.unwrap_err(),AppError::AutomationNotAccepting);
            // Draft admission consumes the pinned bundle only and creates no scheduling records.
            let mut draft=config();draft.trigger=AutomationTrigger::Cron{expression:"0 9 * * 1-5".to_owned(),timezone:"America/New_York".to_owned(),catch_up_latest:false};
            f.assembly.application.execute(f.auth.clone(),AppCommand::CreateAutomationDefinition(CreateAutomationDefinition{automation_id:id("cron-draft"),config:draft.clone()})).await.unwrap();
            let mut bad=draft.clone();bad.trigger=AutomationTrigger::Cron{expression:"0 9 * * 1-5".to_owned(),timezone:"Mars/Unknown".to_owned(),catch_up_latest:false};
            assert_eq!(f.assembly.application.execute(f.auth.clone(),AppCommand::CreateAutomationDefinition(CreateAutomationDefinition{automation_id:id("unknown-zone"),config:bad})).await.unwrap_err().http_status(),400);
            let before=image(&f).await;
            let mut replacement=draft.clone();replacement.trigger=AutomationTrigger::Cron{expression:"0 9 * * 1-5".to_owned(),timezone:"Mars/Unknown".to_owned(),catch_up_latest:false};
            assert_eq!(f.assembly.application.execute(f.auth.clone(),AppCommand::UpdateAutomationDefinition{automation_id:id("cron-draft"),input:UpdateAutomationDefinition::Replace{expected_revision:revision(1),config:replacement}}).await.unwrap_err().http_status(),400);
            assert_eq!(image(&f).await,before);
            draft.trigger=AutomationTrigger::Cron{expression:"0 9 * * 1-5".to_owned(),timezone:"Asia/Shanghai".to_owned(),catch_up_latest:false};
            let replaced=f.assembly.application.execute(f.auth.clone(),AppCommand::UpdateAutomationDefinition{automation_id:id("cron-draft"),input:UpdateAutomationDefinition::Replace{expected_revision:revision(1),config:draft}}).await.unwrap();
            assert!(matches!(replaced,AppReply::AutomationDefinition(ref d) if d.revision.get()==2 && d.state==AutomationDefinitionState::Paused));
            let client=f.pool.get().await.unwrap();assert_eq!(client.query_one("SELECT count(*) FROM openbot_internal.automation_cron_progress",&[]).await.unwrap().get::<_,i64>(0),0);drop(client);
            Ok(())
        }.await;
        f.assembly.shutdown().await;f.pool.close();result
    }).await;
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn manual_retry_and_two_workers_create_one_run() {
    let admin = harness::admin_config("automation_manual");
    harness::with_temp_database(&admin,"automation_manual",|database|async move{
        let f=assembly_fixture::Fixture::with_options(&database,assembly_fixture::Options{automation:true,..Default::default()}).await?;
        let result:Result<(),String>=async{
            create(&f,"manual").await;install_budgets(&f,"20").await;enable(&f,"manual",1).await;
            let accepted=trigger(&f,"manual","operation:one",2).await;
            assert_eq!(accepted.status,AutomationDeliveryStatus::Accepted);assert_eq!(accepted.occurrence.as_ref().unwrap().state,AutomationOccurrenceState::Pending);
            let before=image(&f).await;let replay=trigger(&f,"manual","operation:one",2).await;assert_eq!(replay,accepted);assert_eq!(image(&f).await,before);
            assert_eq!(f.assembly.application.execute(f.auth.clone(),AppCommand::TriggerAutomationDefinition{automation_id:id("manual"),input:TriggerAutomationDefinition{operation_id:"operation:one".to_owned().try_into().unwrap(),expected_revision:revision(1)}}).await.unwrap_err(),AppError::AutomationOperationConflict);
            assert_eq!(image(&f).await,before);
            let queue=f.assembly.automations.as_ref().unwrap().clone();
            let frozen=queue.pending().await.unwrap();assert_eq!(frozen.len(),1);
            let first=AutomationDispatcher::new(queue.clone(),f.assembly.delegated_entry.as_ref().unwrap().clone());let second=first.clone();
            let(a,b)=tokio::join!(first.scan(),second.scan());a.unwrap();b.unwrap();
            let client=f.pool.get().await.unwrap();
            let row=client.query_one("SELECT o.state,o.run_id,r.actor_id,r.thread_id,d.thread_id AS dedicated,d.pending_count,d.active_count,
                (SELECT pending_count FROM openbot_internal.automation_workspace_capacity) AS workspace_pending,
                (SELECT active_count FROM openbot_internal.automation_workspace_capacity) AS workspace_active,
                (SELECT count(*) FROM public.runs) AS runs,(SELECT count(*) FROM public.messages) AS messages,
                (SELECT count(*) FROM openbot_internal.automation_budget_attempts) AS attempts,
                (SELECT count(*) FROM openbot_internal.automation_deliveries) AS deliveries
                FROM openbot_internal.automation_occurrences o JOIN openbot_internal.automation_definitions d ON d.automation_id=o.automation_id JOIN public.runs r ON r.run_id=o.run_id WHERE o.occurrence_id=$1",&[&accepted.receipt_id.as_str()]).await.unwrap();
            assert_eq!(row.get::<_,String>("state"),"run_created");assert_eq!(row.get::<_,String>("run_id"),frozen[0].run_id.as_str());assert_eq!(row.get::<_,String>("actor_id"),f.auth.actor().as_str());assert_eq!(row.get::<_,String>("thread_id"),row.get::<_,String>("dedicated"));
            for field in ["pending_count","workspace_pending","deliveries"]{assert_eq!(row.get::<_,i64>(field),0,"{field}");}
            for field in ["active_count","workspace_active","runs","messages","attempts"]{assert_eq!(row.get::<_,i64>(field),1,"{field}");}drop(client);
            let before=image(&f).await;
            assert!(f.assembly.delegated_entry.as_ref().unwrap().begin(frozen[0].clone()).await.unwrap().replayed);
            assert_eq!(image(&f).await,before);
            let receipt=queue.receipt(&f.auth,accepted.receipt_id).await.unwrap();assert_eq!(receipt.occurrence.unwrap().state,AutomationOccurrenceState::RunCreated);
            Ok(())
        }.await;
        f.assembly.shutdown().await;f.pool.close();result
    }).await;
}

#[cfg(feature = "server-runtime")]
async fn core_reference_counterexamples(
    database: &pool::DatabaseConfig,
    f: &assembly_fixture::Fixture,
    dedicated: &openbot_contracts::ids::ThreadId,
) {
    use openbot_application::{BeginThreadRunRequest, DelegationAuthority, ThreadDirectory};
    use openbot_contracts::{
        auth::{AuthGeneration, DelegationSource},
        command::{BeginThreadRun, ThreadRunAnchor},
        ids::{ActorId, BotId, DeploymentId, RunId, TenantId},
    };
    use openbot_infra::{
        automation::PostgresAutomationAuthority, thread_directory::PostgresThreadDirectory,
    };
    let accepted = trigger(f, "definition", "operation:core-reference", 2).await;
    let request = f
        .assembly
        .automations
        .as_ref()
        .unwrap()
        .pending()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.trigger_id == accepted.receipt_id.as_str())
        .unwrap();
    let source = DelegationSource::AutomationDefinition {
        definition_id: "definition".to_owned(),
    };
    let authority = PostgresAutomationAuthority::new(
        f.pool.clone(),
        f.auth.deployment().clone(),
        f.auth.tenant().clone(),
    );
    let actual_grant = authority
        .verify_current(f.auth.deployment(), f.auth.tenant(), &source, 2)
        .await
        .unwrap();
    // Freeze a genuinely resolved old grant, then change only owned new-table references.
    // This forces the original begin transaction to reject changed core facts itself.
    let stale = assembly_fixture::Fixture::reopen(database).await.unwrap();
    *stale.authority.expected_source.lock().unwrap() = Some(source);
    *stale.authority.state.lock().unwrap() = Ok(actual_grant);
    let client = f.pool.get().await.unwrap();
    client.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('other-bot','Other','built_in','{}');INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('other-bot','dev-local-user','Other','Fixture','other','public')").await.unwrap();
    drop(client);
    let directory = PostgresThreadDirectory::with_runtime(
        f.pool.clone(),
        database.clone(),
        "automation-core-counterexample".to_owned(),
        time::Duration::minutes(10),
    )
    .unwrap();
    for scenario in ["scope", "owner", "bot", "thread"] {
        let deployment = if scenario == "scope" {
            DeploymentId::new("foreign-deployment")
        } else {
            f.auth.deployment().clone()
        };
        let tenant = if scenario == "scope" {
            TenantId::new("foreign-tenant")
        } else {
            f.auth.tenant().clone()
        };
        let actor = if scenario == "owner" {
            ActorId::new("other-owner")
        } else {
            f.auth.actor().clone()
        };
        let bot = BotId::new(if scenario == "bot" {
            "other-bot"
        } else {
            "delegated-bot"
        });
        let thread = openbot_infra::thread_id::mint_thread_id(&deployment).unwrap();
        directory
            .begin_thread_run(BeginThreadRunRequest {
                deployment,
                tenant,
                actor,
                auth_generation: AuthGeneration::new(0),
                command: BeginThreadRun {
                    thread_id: thread.clone(),
                    run_id: RunId::new(format!("core-{scenario}")),
                    bot_id: bot,
                    anchor: ThreadRunAnchor::DirectBot,
                    message: "Real ordinary native Thread".to_owned(),
                    selected_skill_slugs: Vec::new(),
                    artifact_refs: Vec::new(),
                    model_selection: None,
                },
            })
            .await
            .unwrap();
        let client = f.pool.get().await.unwrap();
        client.execute("UPDATE openbot_internal.automation_definitions SET thread_id=$1 WHERE automation_id='definition'",&[&thread.as_str()]).await.unwrap();
        let grant_before:Value=client.query_one("SELECT grant_snapshot FROM openbot_internal.automation_delegations WHERE automation_id='definition' AND delegation_revision=2",&[]).await.unwrap().get(0);
        if scenario == "thread" {
            client.execute("UPDATE openbot_internal.automation_delegations SET thread_id=$1,grant_snapshot=jsonb_set(grant_snapshot,'{threadId}',to_jsonb($1::text)) WHERE automation_id='definition' AND delegation_revision=2",&[&thread.as_str()]).await.unwrap();
        }
        drop(client);
        let before = image(f).await;
        let mut changed = request.clone();
        changed.thread_id = thread;
        let error = stale
            .assembly
            .delegated_entry
            .as_ref()
            .unwrap()
            .begin(changed)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            if scenario == "thread" {
                AppError::NotVisible
            } else {
                AppError::AutomationDelegationInvalid
            },
            "core {scenario}"
        );
        assert_eq!(
            image(f).await,
            before,
            "core {scenario} rejection must roll back Run, budget, occupancy, counts and audit"
        );
        let client = f.pool.get().await.unwrap();
        client.execute("UPDATE openbot_internal.automation_definitions SET thread_id=$1 WHERE automation_id='definition'",&[&dedicated.as_str()]).await.unwrap();
        if scenario == "thread" {
            client.execute("UPDATE openbot_internal.automation_delegations SET thread_id=$1,grant_snapshot=$2 WHERE automation_id='definition' AND delegation_revision=2",&[&dedicated.as_str(),&grant_before]).await.unwrap();
        }
    }
    stale.assembly.shutdown().await;
    stale.pool.close();
}

#[cfg(feature = "server-runtime")]
fn budget_file(
    f: &assembly_fixture::Fixture,
    rev: i64,
    workspace: Value,
    owner: Value,
) -> openbot_domain::automation::AutomationBudgets {
    openbot_domain::automation::AutomationBudgets::try_from(serde_json::from_value::<AutomationBudgetsFile>(json!({"schemaVersion":1,"revision":rev,
        "workspaces":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),"budget":workspace}],
        "owners":[{"deploymentId":f.auth.deployment(),"tenantId":f.auth.tenant(),"ownerId":f.auth.actor(),"budget":owner}]})).unwrap()).unwrap()
}
#[cfg(feature = "server-runtime")]
fn call_rules(limit: &str) -> Value {
    json!([{"metric":"sampling_calls","totalLimit":limit}])
}
#[cfg(feature = "server-runtime")]
async fn claim(f: &assembly_fixture::Fixture) -> openbot_application::RunExecutionLease {
    let dispatch = f
        .assembly
        .run_runtime
        .claim_dispatch()
        .await
        .unwrap()
        .expect("original dispatch row");
    f.assembly
        .run_runtime
        .acknowledge_dispatch(&dispatch)
        .await
        .unwrap()
}
#[cfg(feature = "server-runtime")]
fn budget_refusal(error: &AppError) -> bool {
    matches!(error,AppError::PolicyRefused{rule,..} if rule=="automation_budget_exceeded")
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn three_scope_reservations_race_and_settle_once() {
    use openbot_application::{
        ProviderUsage, RunRuntimeError, RunTerminal, automation::AutomationExecutionBudgets,
    };
    let admin = harness::admin_config("automation_budget_race");
    harness::with_temp_database(&admin,"automation_budget_race",|database|async move{
        let f=assembly_fixture::Fixture::with_options(&database,assembly_fixture::Options{automation:true,..Default::default()}).await?;
        let result:Result<(),String>=async{
            let store=f.assembly.automations.as_ref().unwrap();
            store.install_budgets(Some(&budget_file(&f,1,call_rules("1"),call_rules("10")))).await.unwrap();
            for name in ["budget-a","budget-b"]{
                let mut cfg=config();cfg.budget=serde_json::from_value(call_rules("1")).unwrap();
                f.assembly.application.execute(f.auth.clone(),AppCommand::CreateAutomationDefinition(CreateAutomationDefinition{automation_id:id(name),config:cfg})).await.unwrap();
                enable(&f,name,1).await;trigger(&f,name,"first",2).await;
            }
            let requests=store.pending().await.unwrap();assert_eq!(requests.len(),2);
            let entry=f.assembly.delegated_entry.as_ref().unwrap();
            let(a,b)=tokio::join!(entry.begin(requests[0].clone()),entry.begin(requests[1].clone()));
            assert_eq!(usize::from(a.is_ok())+usize::from(b.is_ok()),1,"one shared workspace reservation");
            for (request,result) in requests.iter().zip([&a,&b]){if let Err(error)=result{assert!(budget_refusal(error),"{error:?}");store.deferred(request,error).await.unwrap();}}
            let winner=if a.is_ok(){&requests[0]}else{&requests[1]};
            let loser=if a.is_err(){&requests[0]}else{&requests[1]};
            let client=f.pool.get().await.unwrap();
            assert_eq!(client.query_one("SELECT count(*) FROM public.runs",&[]).await.unwrap().get::<_,i64>(0),1);
            assert_eq!(client.query_one("SELECT count(*) FROM openbot_internal.automation_budget_attempts",&[]).await.unwrap().get::<_,i64>(0),1);
            assert_eq!(client.query_one("SELECT count(*) FROM openbot_internal.automation_budget_reservations WHERE reserved=1",&[]).await.unwrap().get::<_,i64>(0),3);drop(client);
            let lease=claim(&f).await;assert_eq!(lease.run_id(),&winner.run_id);
            store.reserve_sampling(&lease,0).await.unwrap();
            let before=image(&f).await;
            assert_eq!(store.reserve_sampling(&lease,0).await.unwrap_err(),AppError::ReconciliationRequired{accepted:true});
            assert_eq!(image(&f).await,before,"unknown attempt cannot be re-sent or reserved twice");
            let usage=ProviderUsage{input_tokens:2,output_tokens:3,total_tokens:5};
            f.assembly.run_runtime.record_provider_usage(&lease,0,usage,None,None,None).await.unwrap();
            let before=image(&f).await;
            f.assembly.run_runtime.record_provider_usage(&lease,0,usage,None,None,None).await.unwrap();
            assert_eq!(image(&f).await,before,"exact normalized usage replay is a no-op at all three scopes");
            assert!(matches!(f.assembly.run_runtime.record_provider_usage(&lease,0,ProviderUsage{total_tokens:6,..usage},None,None,None).await,Err(RunRuntimeError::Conflict)));
            assert_eq!(image(&f).await,before);
            let client=f.pool.get().await.unwrap();
            let rows=client.query("SELECT scope_kind,used,reserved FROM openbot_internal.automation_budget_balances WHERE used>0",&[]).await.unwrap();
            assert_eq!(rows.len(),3);for row in rows{assert_eq!((row.get::<_,i64>("used"),row.get::<_,i64>("reserved")),(1,0));}drop(client);
            // A higher workspace limit does not erase the owner's already-settled usage.
            store.install_budgets(Some(&budget_file(&f,2,call_rules("10"),call_rules("1")))).await.unwrap();
            let before=image(&f).await;
            assert!(budget_refusal(&entry.begin(loser.clone()).await.unwrap_err()));assert_eq!(image(&f).await,before);
            // Definite terminal releases capacity once; it does not refund a real sampling.
            let receipt=f.assembly.run_runtime.finish_run(&lease,lease.next_event_sequence(),RunTerminal::Completed).await.unwrap();
            assert!(!receipt.replayed);let before=image(&f).await;
            assert!(f.assembly.run_runtime.finish_run(&lease,lease.next_event_sequence(),RunTerminal::Completed).await.unwrap().replayed);
            assert_eq!(image(&f).await,before);
            store.install_budgets(Some(&budget_file(&f,3,call_rules("10"),call_rules("10")))).await.unwrap();
            let source_name=match &winner.source{openbot_contracts::auth::DelegationSource::AutomationDefinition{definition_id}=>definition_id,_=>panic!("automation source")};
            trigger(&f,source_name,"second",2).await;
            let next = store
                .pending()
                .await
                .unwrap()
                .into_iter()
                .find(|request| request.source == winner.source)
                .unwrap();
            let before=image(&f).await;assert!(budget_refusal(&entry.begin(next).await.unwrap_err()));assert_eq!(image(&f).await,before,"per-definition total survives a new occurrence and Run intent");
            let before=image(&f).await;
            assert!(store.install_budgets(Some(&budget_file(&f,2,call_rules("10"),call_rules("1")))).await.is_err());assert_eq!(image(&f).await,before);
            assert!(store.install_budgets(Some(&budget_file(&f,3,call_rules("20"),call_rules("10")))).await.is_err());assert_eq!(image(&f).await,before,"same policy revision is immutable");
            Ok(())
        }.await;
        f.assembly.shutdown().await;f.pool.close();result
    }).await;
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn manual_commit_faults_and_lost_notify_converge() {
    use openbot_application::automation::AutomationAcceptance;
    use openbot_infra::automation::PostgresAutomations;
    let admin = harness::admin_config("automation_commit");
    harness::with_temp_database(&admin, "automation_commit", |database| async move {
        let f = assembly_fixture::Fixture::with_options(
            &database,
            assembly_fixture::Options {
                automation: true,
                ..Default::default()
            },
        )
        .await?;
        create(&f, "commit").await;
        install_budgets(&f, "20").await;
        enable(&f, "commit", 1).await;
        let store = f.assembly.automations.as_ref().unwrap();
        let intent = TriggerAutomationDefinition {
            operation_id: "same-operation".to_owned().try_into().unwrap(),
            expected_revision: revision(2),
        };

        // A cancelled wait before the first capacity lock cannot be reported as accepted.
        let before = image(&f).await;
        let mut client = f.pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        tx.query_one(
            "SELECT pending_count FROM openbot_internal.automation_workspace_capacity
             WHERE deployment_id=$1 AND tenant_id=$2 FOR UPDATE",
            &[&f.auth.deployment().as_str(), &f.auth.tenant().as_str()],
        )
        .await
        .unwrap();
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            store.trigger(&f.auth, id("commit"), intent.clone()),
        )
        .await;
        assert!(blocked.is_err());
        tx.rollback().await.unwrap();
        drop(client);
        assert_eq!(image(&f).await, before);

        // The owned proxy withholds a real backend COMMIT acknowledgment, not the write.
        let proxy = assembly_fixture::CommitAckProxy::start(&database)
            .await
            .unwrap();
        let proxy_pool = pool::connect(&proxy.config).await.unwrap();
        let through_proxy = PostgresAutomations::new(
            proxy_pool.clone(),
            f.auth.deployment().clone(),
            f.auth.tenant().clone(),
            openbot_domain::vault::SecretBytes::new(vec![0x51; 32]),
        )
        .unwrap();
        proxy.drop_next_commit_ack();
        let error = through_proxy
            .trigger(&f.auth, id("commit"), intent.clone())
            .await
            .unwrap_err();
        assert_eq!(error.http_status(), 503);
        assert_eq!(proxy.dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
        let client = f.pool.get().await.unwrap();
        let receipt_id: String = client
            .query_one(
                "SELECT occurrence_id FROM openbot_internal.automation_occurrences
             WHERE manual_operation_id='same-operation'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        drop(client);
        let before = image(&f).await;
        let acceptance = store
            .trigger(&f.auth, id("commit"), intent.clone())
            .await
            .unwrap();
        let AutomationAcceptance::Replayed(replay) = acceptance else {
            panic!("unknown acknowledgment must converge to the original receipt");
        };
        assert_eq!(replay.receipt_id.as_str(), receipt_id);
        assert_eq!(image(&f).await, before);
        drop(through_proxy);
        proxy_pool.close();
        drop(proxy_pool);
        proxy.stop().await.unwrap();

        // The durable scan recovers the occurrence without a LISTEN consumer.
        let worker = AutomationDispatcher::new(
            store.clone(),
            f.assembly.delegated_entry.as_ref().unwrap().clone(),
        );
        assert_eq!(worker.scan().await.unwrap(), 1);
        let receipt = store
            .receipt(&f.auth, receipt_id.try_into().unwrap())
            .await
            .unwrap();
        assert_eq!(
            receipt.occurrence.unwrap().state,
            AutomationOccurrenceState::RunCreated
        );
        let before = image(&f).await;
        let replay = store.trigger(&f.auth, id("commit"), intent).await.unwrap();
        assert!(matches!(replay, AutomationAcceptance::Replayed(_)));
        assert_eq!(image(&f).await, before);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    })
    .await;
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn delegation_lifecycle_and_current_generation() {
    use openbot_application::{
        DelegationAuthority, DelegationAuthorityError, RunTerminal,
        automation::AutomationExecutionBudgets,
    };
    use openbot_contracts::auth::DelegationSource;
    let admin = harness::admin_config("automation_authority");
    harness::with_temp_database(&admin, "automation_authority", |database| async move {
        let f = assembly_fixture::Fixture::with_options(
            &database,
            assembly_fixture::Options { automation: true, ..Default::default() },
        ).await?;
        create(&f, "authority").await;
        install_budgets(&f, "20").await;
        enable(&f, "authority", 1).await;
        let store = f.assembly.automations.as_ref().unwrap();
        let deployment = f.auth.deployment();
        let tenant = f.auth.tenant();
        let source = DelegationSource::AutomationDefinition { definition_id: "authority".to_owned() };
        let external = DelegationSource::ExternalBinding { binding_id: "authority".to_owned() };
        let authority = openbot_infra::automation::PostgresAutomationAuthority::new(
            f.pool.clone(), deployment.clone(), tenant.clone(),
        );
        assert!(authority.verify_current(deployment, tenant, &source, 2).await.is_ok());
        assert!(matches!(
            authority.verify_current(deployment, tenant, &external, 2).await,
            Err(DelegationAuthorityError::NotCurrent),
        ));
        trigger(&f, "authority", "run", 2).await;
        let request = store.pending().await.unwrap().pop().unwrap();
        f.assembly.delegated_entry.as_ref().unwrap().begin(request).await.unwrap();
        let lease = claim(&f).await;
        f.assembly.application.execute(
            f.auth.clone(),
            AppCommand::UpdateAutomationDefinition {
                automation_id: id("authority"),
                input: UpdateAutomationDefinition::Pause { expected_revision: revision(2) },
            },
        ).await.unwrap();
        assert!(authority.verify_current(deployment, tenant, &source, 2).await.is_ok(),
            "pause retains the running grant");
        store.reserve_sampling(&lease, 0).await.unwrap();
        let client = f.pool.get().await.unwrap();
        let run = lease.run_id().as_str();
        let status: String = client.query_one(
            "SELECT status FROM public.runs WHERE run_id=$1", &[&run],
        ).await.unwrap().get(0);
        assert_eq!(status, "running");
        drop(client);
        let runtime = &f.assembly.run_runtime;
        assert!(runtime.claim_cancellation().await.unwrap().is_none());

        enable(&f, "authority", 3).await;
        assert!(matches!(
            authority.verify_current(deployment, tenant, &source, 2).await,
            Err(DelegationAuthorityError::NotCurrent),
        ));
        assert!(authority.verify_current(deployment, tenant, &source, 4).await.is_ok());
        let before = image(&f).await;
        assert_eq!(store.reserve_sampling(&lease, 1).await.unwrap_err(), AppError::AutomationDelegationInvalid);
        assert_eq!(image(&f).await, before);
        store.maintain().await.unwrap();
        let client = f.pool.get().await.unwrap();
        let row = client.query_one(
            "SELECT r.status,
                    (SELECT status FROM public.outbox WHERE aggregate_id=r.run_id AND destination='agent_run_cancel') AS cancellation,
                    (SELECT active_count FROM openbot_internal.automation_workspace_capacity) AS active,
                    (SELECT state FROM openbot_internal.automation_budget_attempts WHERE run_id=r.run_id) AS budget
             FROM public.runs r WHERE run_id=$1",
            &[&run],
        ).await.unwrap();
        assert_eq!(row.get::<_, String>("status"), "running");
        assert_eq!(row.get::<_, String>("cancellation"), "pending");
        assert_eq!(row.get::<_, i64>("active"), 1);
        assert_eq!(row.get::<_, String>("budget"), "unknown");
        drop(client);
        let accepted = image(&f).await;
        store.maintain().await.unwrap();
        assert_eq!(image(&f).await, accepted, "one durable cancellation request");
        let cancellation = runtime.claim_cancellation().await.unwrap().expect("original cancellation request");
        let cancellation_lease = cancellation.lease();
        assert_eq!(cancellation_lease.run_id(), lease.run_id());
        runtime.mark_cancellation_signalled(&cancellation).await.unwrap();
        runtime.finish_run(
            cancellation_lease,
            cancellation_lease.next_event_sequence(),
            RunTerminal::Cancelled,
        ).await.unwrap();
        // The relay observes the terminal on its next durable scan and delivers the control row.
        assert!(runtime.claim_cancellation().await.unwrap().is_none());
        let client = f.pool.get().await.unwrap();
        let row = client.query_one(
            "SELECT r.status,
                    (SELECT status FROM public.outbox WHERE aggregate_id=r.run_id AND destination='agent_run_cancel') AS cancellation,
                    (SELECT active_count FROM openbot_internal.automation_workspace_capacity) AS active,
                    (SELECT state FROM openbot_internal.automation_budget_attempts WHERE run_id=r.run_id) AS budget
             FROM public.runs r WHERE run_id=$1",
            &[&run],
        ).await.unwrap();
        assert_eq!(row.get::<_, String>("status"), "cancelled");
        assert_eq!(row.get::<_, String>("cancellation"), "delivered");
        assert_eq!(row.get::<_, i64>("active"), 0);
        assert_eq!(row.get::<_, String>("budget"), "unknown");
        client.execute(
            "UPDATE public.users SET auth_generation=coalesce(auth_generation,0)+1 WHERE id=$1",
            &[&f.auth.actor().as_str()],
        ).await.unwrap();
        drop(client);
        assert!(matches!(
            authority.verify_current(deployment, tenant, &source, 4).await,
            Err(DelegationAuthorityError::NotCurrent),
        ));
        let before = image(&f).await;
        let error = f.assembly.application.execute(
            f.auth.clone(),
            AppCommand::TriggerAutomationDefinition {
                automation_id: id("authority"),
                input: TriggerAutomationDefinition {
                    operation_id: "run".to_owned().try_into().unwrap(),
                    expected_revision: revision(2),
                },
            },
        ).await.unwrap_err();
        assert_eq!(error, AppError::NotVisible);
        assert_eq!(image(&f).await, before, "revocation precedes permanent key replay");
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn unknown_usage_survives_windows_and_policy_revisions() {
    use openbot_application::{ProviderUsage, automation::AutomationExecutionBudgets};
    use openbot_infra::automation_budget::AutomationBudgetStartupError;
    let admin = harness::admin_config("automation_window");
    harness::with_temp_database(&admin, "automation_window", |database| async move {
        let f = assembly_fixture::Fixture::with_options(
            &database,
            assembly_fixture::Options {
                automation: true,
                ..Default::default()
            },
        )
        .await?;
        let store = f.assembly.automations.as_ref().unwrap();
        let rule = json!([{"metric":"sampling_calls","totalLimit":"20",
            "window":{"origin":"2026-01-01T00:00:00Z","seconds":2,"limit":"10"}}]);
        let initial = budget_file(&f, 1, rule.clone(), rule.clone());
        let updated = budget_file(&f, 2, rule.clone(), rule);
        store.install_budgets(Some(&initial)).await.unwrap();
        create(&f, "window").await;
        enable(&f, "window", 1).await;
        trigger(&f, "window", "first", 2).await;
        let request = store.pending().await.unwrap().pop().unwrap();
        f.assembly
            .delegated_entry
            .as_ref()
            .unwrap()
            .begin(request)
            .await
            .unwrap();
        let lease = claim(&f).await;
        store.reserve_sampling(&lease, 0).await.unwrap();
        let client = f.pool.get().await.unwrap();
        let original_window: time::OffsetDateTime = client
            .query_one(
                "SELECT bucket_start FROM openbot_internal.automation_budget_reservations
             WHERE scope_kind='owner' AND NOT is_total",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        client.query_one("SELECT pg_sleep(2.1)", &[]).await.unwrap();
        drop(client);
        store.install_budgets(Some(&updated)).await.unwrap();
        let client = f.pool.get().await.unwrap();
        let total = client
            .query_one(
                "SELECT used,reserved FROM openbot_internal.automation_budget_balances
             WHERE scope_kind='owner' AND policy_revision=2 AND is_total",
                &[],
            )
            .await
            .unwrap();
        assert_eq!((total.get::<_, i64>(0), total.get::<_, i64>(1)), (0, 1));
        let original = client
            .query_one(
                "SELECT used,reserved FROM openbot_internal.automation_budget_balances
             WHERE scope_kind='owner' AND policy_revision=1 AND NOT is_total AND bucket_start=$1",
                &[&original_window],
            )
            .await
            .unwrap();
        assert_eq!(
            (original.get::<_, i64>(0), original.get::<_, i64>(1)),
            (0, 1)
        );
        drop(client);
        assert_eq!(
            store.reserve_sampling(&lease, 0).await.unwrap_err(),
            AppError::ReconciliationRequired { accepted: true }
        );
        f.assembly
            .run_runtime
            .record_provider_usage(
                &lease,
                0,
                ProviderUsage {
                    input_tokens: 4,
                    output_tokens: 2,
                    total_tokens: 6,
                },
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let client = f.pool.get().await.unwrap();
        let rows = client
            .query(
                "SELECT policy_revision,is_total,bucket_start,used,reserved
             FROM openbot_internal.automation_budget_balances WHERE scope_kind='owner'",
                &[],
            )
            .await
            .unwrap();
        assert!(rows.iter().any(|row| row.get::<_, i64>(0) == 2
            && !row.get::<_, bool>(1)
            && row.get::<_, time::OffsetDateTime>(2) > original_window));
        for row in rows {
            let billed =
                row.get::<_, bool>(1) || row.get::<_, time::OffsetDateTime>(2) == original_window;
            assert_eq!(
                (row.get::<_, i64>(3), row.get::<_, i64>(4)),
                (i64::from(billed), 0)
            );
        }
        drop(client);
        store.install_budgets(None).await.unwrap();
        assert!(budget_refusal(
            &store.reserve_sampling(&lease, 1).await.unwrap_err()
        ));
        let before = image(&f).await;
        assert!(matches!(
            store.install_budgets(Some(&initial)).await,
            Err(AutomationBudgetStartupError::RevisionRegressed)
        ));
        assert_eq!(
            image(&f).await,
            before,
            "a missing startup file cannot reset revision history"
        );
        store.install_budgets(Some(&updated)).await.unwrap();

        // Simulate a database clock behind an already committed settlement observation.
        // Only the isolated fixture changes; the host clock and Run lease stay real.
        let client = f.pool.get().await.unwrap();
        let last_observed: time::OffsetDateTime = client
            .query_one(
                "UPDATE openbot_internal.automation_budget_attempts
                 SET settled_at=statement_timestamp()+interval '1 hour'
                 WHERE deployment_id=$1 AND tenant_id=$2 AND run_id=$3
                   AND usage_kind='sampling' AND source_attempt_ref='sampling:0' AND state='settled'
                 RETURNING settled_at",
                &[
                    &f.auth.deployment().as_str(),
                    &f.auth.tenant().as_str(),
                    &lease.run_id().as_str(),
                ],
            )
            .await
            .unwrap()
            .get(0);
        drop(client);
        store.reserve_sampling(&lease, 1).await.unwrap();
        let client = f.pool.get().await.unwrap();
        let kept_clock_floor: bool = client
            .query_one(
                "SELECT (reserved_bound->>'chargeAt')::timestamptz >= $4
                 FROM openbot_internal.automation_budget_attempts
                 WHERE deployment_id=$1 AND tenant_id=$2 AND run_id=$3
                   AND usage_kind='sampling' AND source_attempt_ref='sampling:1'",
                &[
                    &f.auth.deployment().as_str(),
                    &f.auth.tenant().as_str(),
                    &lease.run_id().as_str(),
                    &last_observed,
                ],
            )
            .await
            .unwrap()
            .get(0);
        assert!(
            kept_clock_floor,
            "a rollback cannot reopen the settled budget window"
        );
        drop(client);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    })
    .await;
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn capacity_and_recovery_preserve_unknown() {
    use openbot_application::automation::{AutomationAcceptance, AutomationExecutionBudgets};
    let admin = harness::admin_config("automation_capacity");
    harness::with_temp_database(&admin, "automation_capacity", |database| async move {
        let options = || assembly_fixture::Options { automation: true, ..Default::default() };
        let f = assembly_fixture::Fixture::with_options(&database, options()).await?;
        install_budgets(&f, "10000").await;
        let mut receipts = Vec::new();
        let names = ["capacity-a","capacity-b","capacity-c","capacity-d","capacity-e",
            "capacity-f","capacity-g","capacity-h","capacity-i","capacity-j"];
        for name in &names[..5] {
            create(&f, name).await;
            enable(&f, name, 1).await;
            receipts.push(trigger(&f, name, "first", 2).await);
        }
        let store = f.assembly.automations.as_ref().unwrap();
        let dispatcher = AutomationDispatcher::new(store.clone(), f.assembly.delegated_entry.as_ref().unwrap().clone());
        assert_eq!(dispatcher.scan().await.unwrap(), 4);
        let lease = claim(&f).await;
        store.reserve_sampling(&lease, 0).await.unwrap();
        let client = f.pool.get().await.unwrap();
        assert_eq!(client.execute(
            "UPDATE public.thread_leases SET expires_at=statement_timestamp()-interval '1 second' WHERE thread_id=$1",
            &[&lease.thread_id().as_str()],
        ).await.unwrap(), 1);
        drop(client);
        assert!(f.assembly.run_runtime.recover_one_stale_run().await.unwrap().is_some());
        drop(dispatcher);
        f.assembly.shutdown().await;
        f.pool.close();

        let f = assembly_fixture::Fixture::reopen_with_options(&database, options()).await?;
        let store = f.assembly.automations.as_ref().unwrap();
        let dispatcher = AutomationDispatcher::new(store.clone(), f.assembly.delegated_entry.as_ref().unwrap().clone());
        let client = f.pool.get().await.unwrap();
        let row = client.query_one(
            "SELECT r.status,d.automation_id,d.active_count,
             (SELECT active_count FROM openbot_internal.automation_workspace_capacity) AS workspace_active,
             (SELECT state FROM openbot_internal.automation_budget_attempts WHERE run_id=r.run_id) AS attempt,
             EXISTS(SELECT 1 FROM public.thread_run_occupancy WHERE run_id=r.run_id) AS occupied
             FROM public.runs r JOIN openbot_internal.automation_occurrences o USING(run_id)
             JOIN openbot_internal.automation_definitions d USING(deployment_id,tenant_id,automation_id)
             WHERE r.run_id=$1", &[&lease.run_id().as_str()],
        ).await.unwrap();
        assert_eq!(row.get::<_,String>("status"), "reconciliation_required");
        assert_eq!(row.get::<_,i64>("active_count"), 1);
        assert_eq!(row.get::<_,i64>("workspace_active"), 4);
        assert_eq!(row.get::<_,String>("attempt"), "unknown");
        assert!(row.get::<_,bool>("occupied"));
        let occupied_name: String = row.get("automation_id");
        drop(client);
        let behind = trigger(&f, &occupied_name, "after-unknown", 2).await;
        assert_eq!(dispatcher.scan().await.unwrap(), 0);
        let behind = store.receipt(&f.auth, behind.receipt_id).await.unwrap().occurrence.unwrap();
        assert_eq!(behind.state, AutomationOccurrenceState::Pending);
        assert_eq!(
            behind.reason_code,
            Some(AutomationOccurrenceReason::ReconciliationRequired),
        );
        let idle = &receipts[4];
        let client = f.pool.get().await.unwrap();
        assert_eq!(client.execute(
            "UPDATE openbot_internal.automation_occurrences
             SET accepted_at=accepted_at-interval '25 hours',expires_at=expires_at-interval '25 hours'
             WHERE occurrence_id=$1 AND state='pending'", &[&idle.receipt_id.as_str()],
        ).await.unwrap(), 1);
        drop(client);
        store.maintain().await.unwrap();
        let replay = trigger(&f, "capacity-e", "first", 2).await;
        assert_eq!(replay.receipt_id, idle.receipt_id);
        assert_eq!(replay.occurrence.unwrap().state, AutomationOccurrenceState::Expired);
        for (index, name) in names.into_iter().enumerate() {
            if index >= 5 {
                create(&f, name).await;
                enable(&f, name, 1).await;
            }
            let existing = usize::from(name == occupied_name);
            for offset in existing..100 {
                let receipt = trigger(&f, name, &format!("fill:{offset}"), 2).await;
                assert_eq!(receipt.occurrence.unwrap().state, AutomationOccurrenceState::Pending);
            }
            if index == 0 {
                let before = image(&f).await;
                let error = store.trigger(&f.auth, id(name), TriggerAutomationDefinition {
                    operation_id: "one-over-definition".to_owned().try_into().unwrap(), expected_revision: revision(2),
                }).await.unwrap_err();
                assert_eq!(error, AppError::AutomationCapacityExceeded);
                assert_eq!(image(&f).await, before);
            }
        }
        create(&f, "capacity-k").await;
        enable(&f, "capacity-k", 1).await;
        let client = f.pool.get().await.unwrap();
        let pending: i64 = client.query_one(
            "SELECT pending_count FROM openbot_internal.automation_workspace_capacity", &[],
        ).await.unwrap().get(0);
        assert_eq!(pending, 1000);
        drop(client);
        let before = image(&f).await;
        assert_eq!(store.trigger(&f.auth, id("capacity-k"), TriggerAutomationDefinition {
            operation_id: "one-over-workspace".to_owned().try_into().unwrap(), expected_revision: revision(2),
        }).await.unwrap_err(), AppError::AutomationCapacityExceeded);
        assert_eq!(image(&f).await, before);
        assert!(matches!(store.trigger(&f.auth,id("capacity-e"), TriggerAutomationDefinition {
            operation_id: "first".to_owned().try_into().unwrap(), expected_revision: revision(2),
        }).await.unwrap(), AutomationAcceptance::Replayed(_)));
        assert_eq!(image(&f).await, before, "capacity rejection must not hide a durable exact replay");
        drop(dispatcher);
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}

#[cfg(feature = "server-runtime")]
async fn set_bot_provider_source(f: &assembly_fixture::Fixture, value: &str) {
    let client = f.pool.get().await.unwrap();
    let changed = client
        .execute(
            "UPDATE public.agents
         SET configuration=jsonb_set(configuration,'{providerSource}',to_jsonb($1::text))
         WHERE id='delegated-bot'",
            &[&value],
        )
        .await
        .unwrap();
    assert_eq!(changed, 1);
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn invalid_bot_route_keeps_original_occurrence_blocked() {
    let admin = harness::admin_config("automation_model_route");
    harness::with_temp_database(&admin, "automation_model_route", |database| async move {
        let f = assembly_fixture::Fixture::with_options(
            &database,
            assembly_fixture::Options {
                automation: true,
                ..Default::default()
            },
        )
        .await?;
        create(&f, "model-route").await;
        install_budgets(&f, "20").await;
        enable(&f, "model-route", 1).await;
        set_bot_provider_source(&f, "unregistered-route").await;

        let accepted = trigger(&f, "model-route", "same-operation", 2).await;
        let original_expiry = accepted.occurrence.as_ref().unwrap().expires_at;
        let store = f.assembly.automations.as_ref().unwrap();
        let dispatcher = AutomationDispatcher::new(
            store.clone(),
            f.assembly.delegated_entry.as_ref().unwrap().clone(),
        );
        assert_eq!(dispatcher.scan().await.unwrap(), 0);
        let blocked = store
            .receipt(&f.auth, accepted.receipt_id.clone())
            .await
            .unwrap();
        assert_eq!(blocked.received_at, accepted.received_at);
        let occurrence = blocked.occurrence.unwrap();
        assert_eq!(occurrence.state, AutomationOccurrenceState::BlockedModel);
        assert_eq!(
            occurrence.reason_code,
            Some(AutomationOccurrenceReason::ModelUnavailable)
        );
        assert_eq!(occurrence.expires_at, original_expiry);
        assert!(occurrence.run_id.is_none());
        let client = f.pool.get().await.unwrap();
        let empty: bool = client
            .query_one(
                "SELECT NOT EXISTS(SELECT 1 FROM public.runs)
                AND NOT EXISTS(SELECT 1 FROM openbot_internal.automation_budget_attempts)",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(empty);
        drop(client);

        set_bot_provider_source(&f, "package").await;
        assert_eq!(dispatcher.scan().await.unwrap(), 1);
        assert_eq!(dispatcher.scan().await.unwrap(), 0);
        let admitted = store
            .receipt(&f.auth, accepted.receipt_id.clone())
            .await
            .unwrap();
        assert_eq!(admitted.receipt_id, accepted.receipt_id);
        assert_eq!(admitted.received_at, accepted.received_at);
        let occurrence = admitted.occurrence.unwrap();
        assert_eq!(occurrence.state, AutomationOccurrenceState::RunCreated);
        assert_eq!(occurrence.expires_at, original_expiry);
        assert!(occurrence.run_id.is_some());
        assert!(occurrence.reason_code.is_none());
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    })
    .await;
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn restored_generation_requires_new_owner_authority() {
    let admin = harness::admin_config("automation_restore_gate");
    harness::with_temp_database(&admin, "automation_restore_gate", |database| async move {
        let mut f = assembly_fixture::Fixture::with_options(
            &database,
            assembly_fixture::Options { automation: true, ..Default::default() },
        ).await?;
        create(&f, "restore-gate").await;
        install_budgets(&f, "20").await;
        enable(&f, "restore-gate", 1).await;
        let accepted = trigger(&f, "restore-gate", "old-intent", 2).await;

        // Exercise the authoritative generation change installed by a restore operation.
        let prior_generation = f.auth.auth_generation().get();
        let client = f.pool.get().await.unwrap();
        let changed = client.execute(
            "UPDATE public.users SET auth_generation=auth_generation+1 WHERE id=$1",
            &[&f.auth.actor().as_str()],
        ).await.unwrap();
        assert_eq!(changed, 1);
        drop(client);

        let store = f.assembly.automations.as_ref().unwrap();
        let dispatcher = AutomationDispatcher::new(
            store.clone(),
            f.assembly.delegated_entry.as_ref().unwrap().clone(),
        );
        assert_eq!(dispatcher.scan().await.unwrap(), 0);
        let client = f.pool.get().await.unwrap();
        let row = client.query_one(
            "SELECT d.state, d.current_revision,
                    NOT EXISTS(SELECT 1 FROM public.runs) AS no_run,
                    NOT EXISTS(SELECT 1 FROM public.outbox WHERE destination='agent_run_dispatch') AS no_dispatch
             FROM openbot_internal.automation_definitions d WHERE d.automation_id='restore-gate'",
            &[],
        ).await.unwrap();
        assert_eq!(row.get::<_, String>("state"), "enabled");
        assert_eq!(row.get::<_, i64>("current_revision"), 2);
        assert!(row.get::<_, bool>("no_run"));
        assert!(row.get::<_, bool>("no_dispatch"));
        drop(client);

        f.auth = openbot_infra::auth::single_user::load_single_user_principal(
            &f.pool, f.auth.deployment().clone(), f.auth.tenant().clone(),
        ).await.unwrap().auth_context().clone();
        assert_eq!(f.auth.auth_generation().get(), prior_generation + 1);
        let pending = store.receipt(&f.auth, accepted.receipt_id.clone()).await.unwrap();
        let occurrence = pending.occurrence.unwrap();
        assert_eq!(occurrence.state, AutomationOccurrenceState::Pending);
        assert_eq!(occurrence.reason_code, Some(AutomationOccurrenceReason::AuthorityUnavailable));
        assert_eq!(pending.received_at, accepted.received_at);
        assert!(occurrence.run_id.is_none());

        let reauthorized = enable(&f, "restore-gate", 2).await;
        assert_eq!(reauthorized.revision.get(), 3);
        let old = store.receipt(&f.auth, accepted.receipt_id.clone()).await.unwrap().occurrence.unwrap();
        assert_eq!(old.state, AutomationOccurrenceState::Superseded);
        assert!(old.run_id.is_none());
        let current = trigger(&f, "restore-gate", "new-owner-intent", 3).await;
        assert_ne!(current.receipt_id, accepted.receipt_id);
        assert_eq!(dispatcher.scan().await.unwrap(), 1);
        let run = store.receipt(&f.auth, current.receipt_id).await.unwrap().occurrence.unwrap();
        assert_eq!(run.state, AutomationOccurrenceState::RunCreated);
        assert!(run.run_id.is_some());
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    }).await;
}

#[cfg(feature = "server-runtime")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn agent_sampling_reserves_before_provider_and_keeps_unknown() {
    use openbot_agent::{
        BuiltInAgentConfig, BuiltInAgentRuntime, BuiltInRunPorts, NoAgentToolInvoker,
    };
    use openbot_application::{
        NoAgentAudit, NoRemoteInterruptCoordinator, ProviderAdapter, ProviderEvent,
        ProviderPortError, ProviderRequest, ProviderRoute, ProviderSession, ProviderUsage,
        RunDispatchConsumer, RunDispatchDecision, RunExecutionLease,
        automation::AutomationExecutionBudgets,
    };
    use openbot_infra::provider::context::PostgresAgentContextSource;
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[derive(Default)]
    struct CountingProvider(AtomicUsize);
    struct Sample(VecDeque<ProviderEvent>);
    #[async_trait::async_trait]
    impl ProviderSession for Sample {
        async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
            Ok(self.0.pop_front())
        }
    }
    #[async_trait::async_trait]
    impl ProviderAdapter for CountingProvider {
        async fn start(
            &self,
            request: ProviderRequest,
        ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
            assert!(matches!(request.route, ProviderRoute::PackageOpenAi));
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Sample(VecDeque::from([
                ProviderEvent::TextDelta {
                    index: 0,
                    delta: "Owned sampling result.".to_owned(),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 2,
                    output_tokens: 1,
                    total_tokens: 3,
                }),
                ProviderEvent::Completed,
            ]))))
        }
    }

    async fn reserve_and_ack(
        f: &assembly_fixture::Fixture,
        consumer: &dyn RunDispatchConsumer,
    ) -> RunExecutionLease {
        let runtime = &f.assembly.run_runtime;
        let dispatch = runtime
            .claim_dispatch()
            .await
            .unwrap()
            .expect("original outbox");
        assert_eq!(
            consumer.dispatch(dispatch.lease().clone()).await,
            RunDispatchDecision::Accepted
        );
        runtime.acknowledge_dispatch(&dispatch).await.unwrap()
    }
    async fn activate_and_read_terminal(
        f: &assembly_fixture::Fixture,
        consumer: &dyn RunDispatchConsumer,
        lease: &RunExecutionLease,
    ) -> (String, Option<String>) {
        consumer.activate(lease).await.unwrap();
        let client = f.pool.get().await.unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let row = client
                    .query_one(
                        "SELECT status,error_code FROM public.runs WHERE run_id=$1",
                        &[&lease.run_id().as_str()],
                    )
                    .await
                    .unwrap();
                let status: String = row.get(0);
                if status != "running" {
                    return (status, row.get(1));
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        })
        .await
        .expect("original Agent committed its terminal")
    }

    let admin = harness::admin_config("automation_sampling_gate");
    harness::with_temp_database(&admin, "automation_sampling_gate", |database| async move {
        let f = assembly_fixture::Fixture::with_options(
            &database,
            assembly_fixture::Options {
                automation: true,
                ..Default::default()
            },
        )
        .await?;
        set_bot_provider_source(&f, "package").await;
        install_budgets(&f, "2").await;
        for name in ["budget-denied", "budget-uncertain"] {
            create(&f, name).await;
            enable(&f, name, 1).await;
            trigger(&f, name, "first", 2).await;
        }
        let store = f.assembly.automations.as_ref().unwrap();
        let dispatcher = AutomationDispatcher::new(
            store.clone(),
            f.assembly.delegated_entry.as_ref().unwrap().clone(),
        );
        assert_eq!(dispatcher.scan().await.unwrap(), 2);

        let provider = Arc::new(CountingProvider::default());
        let context = PostgresAgentContextSource::new(
            f.pool.clone(),
            f.auth.deployment().clone(),
            f.auth.tenant().clone(),
            Some(32),
        )
        .unwrap();
        let agent = BuiltInAgentRuntime::start_with_run_ports(
            BuiltInRunPorts {
                runtime: f.assembly.run_runtime.clone(),
                automation_budgets: Some(store.clone()),
            },
            Arc::new(context),
            provider.clone(),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            Arc::new(NoRemoteInterruptCoordinator),
            BuiltInAgentConfig::default(),
        )
        .unwrap();
        let consumer = agent.consumer();

        // Two original attempts are already held. The new finite limit only admits one.
        store
            .install_budgets(Some(&budget_file(&f, 2, call_rules("1"), call_rules("1"))))
            .await
            .unwrap();
        let denied = reserve_and_ack(&f, consumer.as_ref()).await;
        assert_eq!(
            activate_and_read_terminal(&f, consumer.as_ref(), &denied).await,
            (
                "failed".to_owned(),
                Some("automation_budget_exceeded".to_owned())
            ),
        );
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);

        store
            .install_budgets(Some(&budget_file(
                &f,
                3,
                call_rules("10"),
                call_rules("10"),
            )))
            .await
            .unwrap();
        let uncertain = reserve_and_ack(&f, consumer.as_ref()).await;
        // The original PG attempt was committed before a prior activation could send it.
        store.reserve_sampling(&uncertain, 0).await.unwrap();
        assert_eq!(
            activate_and_read_terminal(&f, consumer.as_ref(), &uncertain).await,
            (
                "reconciliation_required".to_owned(),
                Some("journal_commit_unknown".to_owned())
            ),
        );
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
        let client = f.pool.get().await.unwrap();
        let held = client
            .query_one(
                "SELECT b.state,b.actual_usage,
                    (SELECT sum(r.reserved-r.settled-r.released)::bigint
                     FROM openbot_internal.automation_budget_reservations r
                     WHERE r.attempt_id=b.attempt_id) AS reserved
             FROM openbot_internal.automation_budget_attempts b WHERE b.run_id=$1",
                &[&uncertain.run_id().as_str()],
            )
            .await
            .unwrap();
        assert_eq!(held.get::<_, String>("state"), "unknown");
        assert_eq!(held.get::<_, Option<Value>>("actual_usage"), None);
        assert_eq!(held.get::<_, i64>("reserved"), 3);
        drop(client);

        create(&f, "budget-allowed").await;
        enable(&f, "budget-allowed", 1).await;
        trigger(&f, "budget-allowed", "first", 2).await;
        assert_eq!(dispatcher.scan().await.unwrap(), 1);
        let allowed = reserve_and_ack(&f, consumer.as_ref()).await;
        assert_eq!(
            activate_and_read_terminal(&f, consumer.as_ref(), &allowed).await,
            ("completed".to_owned(), None),
        );
        assert_eq!(provider.0.load(Ordering::SeqCst), 1);
        let client = f.pool.get().await.unwrap();
        let settled = client
            .query_one(
                "SELECT b.state,b.actual_usage,
                    (SELECT m.content->>'text' FROM public.messages m
                     WHERE m.run_id=b.run_id AND m.role='assistant') AS answer
             FROM openbot_internal.automation_budget_attempts b WHERE b.run_id=$1",
                &[&allowed.run_id().as_str()],
            )
            .await
            .unwrap();
        assert_eq!(settled.get::<_, String>("state"), "settled");
        assert_eq!(
            settled.get::<_, Value>("actual_usage")["sampling_calls"],
            json!(1)
        );
        assert_eq!(settled.get::<_, String>("answer"), "Owned sampling result.");
        drop(client);
        agent.stop().await;
        f.assembly.shutdown().await;
        f.pool.close();
        Ok(())
    })
    .await;
}
