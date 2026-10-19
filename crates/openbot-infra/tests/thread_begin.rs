//! G3 thread/message/run/event/outbox 同事务 append 的 PostgreSQL 17 真库证据。

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{BeginThreadRunRequest, ThreadDirectory, ThreadDirectoryError};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::thread_directory::PostgresThreadDirectory;
use time::Duration;

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.users(id,email) VALUES
               ('actor-a','a@example.test'),('actor-b','b@example.test'),
               ('actor-admin','admin@example.test');
             INSERT INTO public.user_roles(user_id,role) VALUES('actor-admin','admin');
             INSERT INTO public.agents(id,name,type,configuration)
               VALUES('bot-1','Bot 1','built_in','{}'::jsonb),
                     ('bot-private','Private Bot','built_in','{}'::jsonb);
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES('bot-1',NULL,'Bot 1','test role','seed','public',NULL),
                     ('bot-private','actor-b','Private Bot','private role','private-seed','private',NULL);",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn request(
    deployment: &DeploymentId,
    actor: &str,
    thread_entropy: u64,
    run_id: &str,
    message: &str,
) -> BeginThreadRunRequest {
    let mut entropy = [0_u8; 16];
    entropy[8..].copy_from_slice(&thread_entropy.to_be_bytes());
    BeginThreadRunRequest {
        auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
        deployment: deployment.clone(),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new(actor),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            thread_id: ThreadIdentity::new(deployment).mint_from_entropy(entropy),
            run_id: RunId::new(run_id),
            bot_id: BotId::new("bot-1"),
            anchor: ThreadRunAnchor::DirectBot,
            message: message.to_owned(),
        },
    }
}

async fn count(client: &tokio_postgres::Client, table: &str) -> Result<i64, String> {
    let sql = format!("SELECT count(*)::bigint FROM public.{table}");
    client
        .query_one(&sql, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

async fn provision_skills(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let client = pool.get().await.map_err(|error| error.to_string())?;
    client.batch_execute(
        "INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user');
         UPDATE public.agents SET configuration=\
           '{\"systemPrompt\":\"Standing instruction.\",\"providerSource\":\"package\"}' WHERE id='bot-1';
         INSERT INTO public.skills(id,slug,title,summary,instructions,origin,owner_user_id)
           VALUES('a-skill','a-skill','A','','Second selected instruction.','yours','actor-b'),
                 ('z-skill','z-skill','Z','','Standing instruction.','yours',NULL),
                 ('not-granted','not-granted','N','','Must not appear.','yours','actor-a');
         INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
           VALUES('skill','a-skill','bot-1','actor-admin'),
                 ('skill','z-skill','bot-1','actor-admin');",
    ).await.map_err(|error| error.to_string())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn selected_skills_snapshot_order_provider_context_and_exact_replay_survive_revocation() {
    use openbot_application::{AgentContextSource, ProviderMessageRole, RunExecutionLease};
    use openbot_domain::thread::FencingToken;
    use openbot_infra::provider::context::PostgresAgentContextSource;

    let admin = admin_config(
        "selected_skills_snapshot_order_provider_context_and_exact_replay_survive_revocation",
    );
    with_temp_database(&admin, "skillrun", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            provision_skills(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config.clone(),
                "runtime-a".to_owned(),
                Duration::seconds(30),
            )
            .map_err(|error| error.to_string())?;
            let mut request = request(&deployment, "actor-a", 21, "skill-run", "My words only.");
            request.command.selected_skill_slugs = vec!["z-skill".to_owned(), "a-skill".to_owned()];
            let first = directory
                .begin_thread_run(request.clone())
                .await
                .map_err(|error| error.to_string())?;
            assert_eq!(first.message_sequence, 2);
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let rows = client
                .query(
                    "SELECT role,content,seq FROM public.messages ORDER BY seq",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0].get::<_, String>("role"), "system");
            assert_eq!(
                rows[0].get::<_, serde_json::Value>("content")["selectedSkillSlug"],
                "z-skill"
            );
            assert_eq!(
                rows[1].get::<_, serde_json::Value>("content")["selectedSkillSlug"],
                "a-skill"
            );
            assert_eq!(rows[2].get::<_, String>("role"), "user");
            assert_eq!(
                rows[2].get::<_, serde_json::Value>("content")["text"],
                "My words only."
            );
            assert_eq!(count(&client, "outbox").await?, 1);
            client
                .batch_execute(
                    "UPDATE public.skills SET instructions='Changed later.' WHERE slug='a-skill';
                DELETE FROM public.plugin_grants WHERE kind='skill';
                DELETE FROM public.skills WHERE slug='z-skill';",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let replay = directory
                .begin_thread_run(request.clone())
                .await
                .map_err(|error| error.to_string())?;
            assert!(replay.replayed);
            assert_eq!(replay.message_sequence, first.message_sequence);
            let history = directory
                .thread_history(openbot_application::ThreadHistoryRequest {
                    deployment: deployment.clone(),
                    tenant: request.tenant.clone(),
                    actor: request.actor.clone(),
                    thread: request.command.thread_id.clone(),
                })
                .await
                .map_err(|error| error.to_string())?;
            assert_eq!(history.messages[2].content, "My words only.");
            assert_eq!(
                history.messages[2].selected_skill_slugs,
                request.command.selected_skill_slugs
            );
            assert!(history.messages[0].selected_skill_slugs.is_empty());
            for selection in [vec![], vec!["a-skill".to_owned(), "z-skill".to_owned()]] {
                let mut changed = request.clone();
                changed.command.selected_skill_slugs = selection;
                assert_eq!(
                    directory.begin_thread_run(changed).await,
                    Err(ThreadDirectoryError::RequestConflict)
                );
            }
            // Reconstruct the production context source after all mutable source rows changed.
            let context = PostgresAgentContextSource::new(
                pool.clone(),
                deployment,
                TenantId::new("tenant-a"),
                Some(256),
            )
            .map_err(|error| error.to_string())?;
            let lease = RunExecutionLease::new(
                request.command.run_id.clone(),
                request.command.thread_id.clone(),
                request.command.bot_id.clone(),
                request.actor.clone(),
                FencingToken::new(1).unwrap(),
                0,
            )
            .map_err(|error| error.to_string())?;
            let loaded = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            assert!(
                loaded.tools.is_empty(),
                "instruction must not mint any tool definition"
            );
            let messages = loaded
                .messages
                .iter()
                .map(|message| (message.role, message.content.as_str()))
                .collect::<Vec<_>>();
            assert_eq!(messages[0].0, ProviderMessageRole::System);
            assert!(messages[0].1.starts_with("Standing instruction.\n\n"));
            assert_eq!(
                messages[1..],
                vec![
                    (ProviderMessageRole::System, "Standing instruction."),
                    (ProviderMessageRole::System, "Second selected instruction."),
                    (ProviderMessageRole::User, "My words only."),
                ]
            );
            let client = pool.get().await.map_err(|error| error.to_string())?;
            assert_eq!(count(&client, "messages").await?, 3);
            assert_eq!(count(&client, "runs").await?, 1);
            assert_eq!(count(&client, "outbox").await?, 1);
            client
                .execute(
                    "UPDATE public.users SET auth_generation=1 WHERE id='actor-a'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            assert_eq!(
                directory.begin_thread_run(request).await,
                Err(ThreadDirectoryError::NotVisible)
            );
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn unavailable_selected_skills_and_stale_actor_leave_no_run_or_partial_snapshot() {
    let admin = admin_config(
        "unavailable_selected_skills_and_stale_actor_leave_no_run_or_partial_snapshot",
    );
    with_temp_database(&admin, "skilldeny", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            provision_skills(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(pool.clone(), config.clone(),
                "runtime-a".to_owned(), Duration::seconds(30)).map_err(|error| error.to_string())?;
            let mut request = request(&deployment, "actor-a", 31, "denied-run", "No partial message.");
            for slug in ["missing", "not-granted"] {
                request.command.selected_skill_slugs = vec!["a-skill".to_owned(), slug.to_owned()];
                assert_eq!(directory.begin_thread_run(request.clone()).await, Err(ThreadDirectoryError::NotVisible));
            }
            request.command.selected_skill_slugs = vec!["a-skill".to_owned()];
            request.command.bot_id = BotId::new("bot-private");
            assert_eq!(directory.begin_thread_run(request.clone()).await, Err(ThreadDirectoryError::NotVisible));
            request.command.bot_id = BotId::new("bot-1");
            request.auth_generation = openbot_contracts::auth::AuthGeneration::new(1);
            assert_eq!(directory.begin_thread_run(request.clone()).await, Err(ThreadDirectoryError::NotVisible));
            request.auth_generation = openbot_contracts::auth::AuthGeneration::new(0);
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client.batch_execute("INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                VALUES('tenant-other','/fixture',repeat('a',64));
                UPDATE public.agents SET package_id=(SELECT id FROM public.deployment_packages WHERE tenant_id='tenant-other') WHERE id='bot-1';")
                .await.map_err(|error| error.to_string())?;
            assert_eq!(directory.begin_thread_run(request.clone()).await, Err(ThreadDirectoryError::NotVisible));
            client.batch_execute("UPDATE public.agents SET package_id=NULL WHERE id='bot-1';
                UPDATE public.skills SET instructions='' WHERE slug='a-skill';")
                .await.map_err(|error| error.to_string())?;
            assert_eq!(directory.begin_thread_run(request.clone()).await,
                Err(ThreadDirectoryError::Corrupt { field: "skill_instructions" }));
            client.batch_execute("UPDATE public.skills SET instructions='Valid again.' WHERE slug='a-skill';
                INSERT INTO public.revoked_access(email,revoked_by) VALUES('a@example.test','actor-admin');")
                .await.map_err(|error| error.to_string())?;
            assert_eq!(directory.begin_thread_run(request).await, Err(ThreadDirectoryError::NotVisible));
            for table in ["threads", "thread_memberships", "thread_leases", "messages", "runs", "run_events", "outbox"] {
                assert_eq!(count(&client, table).await?, 0, "partial row in {table}");
            }
            Ok(())
        }.await;
        pool.close(); result
    }).await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn begin_commits_every_surface_and_exact_replay_writes_nothing() {
    let admin = admin_config("begin_commits_every_surface_and_exact_replay_writes_nothing");
    with_temp_database(&admin, "threadbegin", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            provision_skills(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config.clone(),
                "runtime-a".to_owned(),
                Duration::seconds(30),
            )
            .map_err(|error| error.to_string())?;
            let request = request(&deployment, "actor-a", 1, "run-1", "hello native thread");
            let first = directory
                .begin_thread_run(request.clone())
                .await
                .map_err(|error| error.to_string())?;
            if first.replayed || first.message_sequence != 0 || first.event_sequence != 0 {
                return Err(format!("首个 receipt 形状错误：{first:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            for (table, expected) in [
                ("threads", 1),
                ("thread_memberships", 1),
                ("thread_leases", 1),
                ("messages", 1),
                ("runs", 1),
                ("run_events", 1),
                ("outbox", 1),
            ] {
                let actual = count(&client, table).await?;
                if actual != expected {
                    return Err(format!("{table} 应为 {expected} 行，实际 {actual}"));
                }
            }
            let shape = client
                .query_one(
                    "SELECT t.next_message_seq,t.next_event_seq,r.status,r.started_at IS NOT NULL,
                            e.event_type,e.terminal,o.destination,o.delivery_class,
                            o.payload ? 'message' AS leaks_message
                     FROM public.threads t
                     JOIN public.runs r ON r.thread_id=t.thread_id
                     JOIN public.run_events e ON e.run_id=r.run_id
                     JOIN public.outbox o ON o.aggregate_id=t.thread_id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let actual: (i64, i64, String, bool, String, bool, String, String, bool) = (
                shape.try_get(0).map_err(|error| error.to_string())?,
                shape.try_get(1).map_err(|error| error.to_string())?,
                shape.try_get(2).map_err(|error| error.to_string())?,
                shape.try_get(3).map_err(|error| error.to_string())?,
                shape.try_get(4).map_err(|error| error.to_string())?,
                shape.try_get(5).map_err(|error| error.to_string())?,
                shape.try_get(6).map_err(|error| error.to_string())?,
                shape.try_get(7).map_err(|error| error.to_string())?,
                shape.try_get(8).map_err(|error| error.to_string())?,
            );
            if actual
                != (
                    1,
                    1,
                    "running".to_owned(),
                    true,
                    "started".to_owned(),
                    false,
                    "agent_run_dispatch".to_owned(),
                    "internal".to_owned(),
                    false,
                )
            {
                return Err(format!("同事务终态错误：{actual:?}"));
            }
            drop(client);

            let replay = directory
                .begin_thread_run(request.clone())
                .await
                .map_err(|error| error.to_string())?;
            if !replay.replayed
                || replay.message_sequence != first.message_sequence
                || replay.event_sequence != first.event_sequence
            {
                return Err(format!("精确 replay 没返回原 receipt：{replay:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            for table in [
                "threads",
                "thread_memberships",
                "thread_leases",
                "messages",
                "runs",
                "run_events",
                "outbox",
            ] {
                if count(&client, table).await? != 1 {
                    return Err(format!("幂等 replay 改写了 {table}"));
                }
            }
            drop(client);

            let mut changed = request.clone();
            changed.command.message = "different payload".to_owned();
            if directory.begin_thread_run(changed).await
                != Err(ThreadDirectoryError::RequestConflict)
            {
                return Err("同 run_id 不同内容必须 request_conflict".to_owned());
            }
            let mut second = request.clone();
            second.command.run_id = RunId::new("run-2");
            if directory.begin_thread_run(second).await != Err(ThreadDirectoryError::LeaseConflict)
            {
                return Err("active foreground 必须 lease_conflict".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.threads SET status='deleted',deleted_at=now(),updated_at=now() \
                     WHERE thread_id=$1",
                    &[&request.command.thread_id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if directory.begin_thread_run(request).await != Err(ThreadDirectoryError::NotVisible) {
                return Err("deleted thread 的精确 replay 也不得伪装成重新开始".to_owned());
            }

            let mut refused = crate::request(
                &deployment,
                "actor-a",
                11,
                "run-private-refused",
                "must not run private",
            );
            refused.command.bot_id = BotId::new("bot-private");
            if directory.begin_thread_run(refused).await != Err(ThreadDirectoryError::NotVisible) {
                return Err("non-owner must not run a private Agent".to_owned());
            }
            let mut admin = crate::request(
                &deployment,
                "actor-admin",
                12,
                "run-private-admin",
                "admin may run private",
            );
            admin.command.bot_id = BotId::new("bot-private");
            directory
                .begin_thread_run(admin)
                .await
                .map_err(|error| format!("admin private Agent run failed: {error}"))?;
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_late_outbox_conflict_rolls_back_thread_message_run_event_and_lease() {
    let admin =
        admin_config("a_late_outbox_conflict_rolls_back_thread_message_run_event_and_lease");
    with_temp_database(&admin, "threadrollback", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            provision_skills(&pool).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.outbox(
                       outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload
                     ) VALUES(
                       'run-rollback:agent_run_dispatch','test','preexisting',0,
                       'agent_run_dispatch','internal','{}'::jsonb
                     )",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config.clone(),
                "runtime-a".to_owned(),
                Duration::seconds(30),
            )
            .map_err(|error| error.to_string())?;
            let mut candidate = request(&deployment, "actor-a", 2, "run-rollback", "must rollback");
            candidate.command.selected_skill_slugs =
                vec!["a-skill".to_owned(), "z-skill".to_owned()];
            let error = directory.begin_thread_run(candidate).await;
            if error != Err(ThreadDirectoryError::RequestConflict) {
                return Err(format!(
                    "末段 outbox collision 应 request_conflict：{error:?}"
                ));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            for table in [
                "threads",
                "thread_memberships",
                "thread_leases",
                "messages",
                "runs",
                "run_events",
            ] {
                let actual = count(&client, table).await?;
                if actual != 0 {
                    return Err(format!("outbox 末段失败后 {table} 仍有 {actual} 行"));
                }
            }
            if count(&client, "outbox").await? != 1 {
                return Err("预置 outbox 之外不应留下新行".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn existing_legacy_uuid_is_writable_but_a_new_foreign_uuid_is_rejected() {
    let admin = admin_config("existing_legacy_uuid_is_writable_but_a_new_foreign_uuid_is_rejected");
    with_temp_database(&admin, "threadlegacy", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id
                     ) VALUES(
                       '550e8400-e29b-41d4-a716-446655440000','tenant-a','dep-a','actor-a',
                       'direct_bot','bot-1'
                     );
                     INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('550e8400-e29b-41d4-a716-446655440000','actor-a');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let deployment = DeploymentId::new("dep-a");
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config.clone(),
                "runtime-a".to_owned(),
                Duration::seconds(30),
            )
            .map_err(|error| error.to_string())?;
            let mut legacy = request(&deployment, "actor-a", 3, "legacy-run", "legacy works");
            legacy.command.thread_id =
                openbot_contracts::ids::ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
            if ThreadIdentity::new(&deployment).owns(&legacy.command.thread_id) {
                return Err("前提失效：UUIDv4 不应被 dep-a owns".to_owned());
            }
            directory
                .begin_thread_run(legacy)
                .await
                .map_err(|error| error.to_string())?;

            let foreign_deployment = DeploymentId::new("dep-foreign");
            let mut entropy = [0_u8; 16];
            entropy[15] = 9;
            let foreign = BeginThreadRunRequest {
                auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                deployment: deployment.clone(),
                tenant: TenantId::new("tenant-a"),
                actor: ActorId::new("actor-a"),
                command: BeginThreadRun {
                    artifact_refs: Vec::new(),
                    model_selection: None,
                    selected_skill_slugs: Vec::new(),
                    thread_id: ThreadIdentity::new(&foreign_deployment).mint_from_entropy(entropy),
                    run_id: RunId::new("foreign-run"),
                    bot_id: BotId::new("bot-1"),
                    anchor: ThreadRunAnchor::DirectBot,
                    message: "must not create".to_owned(),
                },
            };
            if directory.begin_thread_run(foreign).await
                != Err(ThreadDirectoryError::InvalidInput { field: "thread_id" })
            {
                return Err("不存在的 foreign UUID 不得在当前 deployment 创建".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn concurrent_grant_revocation_finishes_before_skill_snapshot_acceptance() {
    let admin =
        admin_config("concurrent_grant_revocation_finishes_before_skill_snapshot_acceptance");
    with_temp_database(&admin, "skillrace", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let observer_pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            provision_skills(&pool).await?;
            let directory = PostgresThreadDirectory::with_runtime(pool.clone(), config.clone(),
                "runtime-a".to_owned(), Duration::seconds(30)).map_err(|error| error.to_string())?;
            let mut request = request(&DeploymentId::new("dep-a"), "actor-a", 41, "racing-run", "Must see revocation.");
            request.command.selected_skill_slugs = vec!["a-skill".to_owned()];
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            let revoke = client.transaction().await.map_err(|error| error.to_string())?;
            revoke.execute("DELETE FROM public.plugin_grants WHERE kind='skill' AND ref='a-skill'", &[])
                .await.map_err(|error| error.to_string())?;
            let pending = tokio::spawn(async move { directory.begin_thread_run(request).await });
            let observer = observer_pool.get().await.map_err(|error| error.to_string())?;
            let blocked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let blocked: bool = observer.query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() \
                          AND wait_event_type='Lock' AND query LIKE 'SELECT s.slug,s.instructions%')", &[])
                        .await.map_err(|error| error.to_string())?.get(0);
                    if blocked { return Ok::<_, String>(()); }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await;
            // Always release the writer lock and join the pending task, including a failed premise.
            revoke.commit().await.map_err(|error| error.to_string())?;
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), pending).await
                .map_err(|_| "snapshot did not finish after revoke commit".to_owned())?
                .map_err(|error| error.to_string())?;
            blocked.map_err(|_| "snapshot query never demonstrably waited on the grant lock".to_owned())??;
            assert_eq!(outcome, Err(ThreadDirectoryError::NotVisible));
            for table in ["threads", "messages", "runs", "thread_leases", "outbox"] {
                assert_eq!(count(&client, table).await?, 0);
            }
            Ok(())
        }.await;
        observer_pool.close(); pool.close(); result
    }).await;
}
