//! PostgreSQL 17 evidence for atomic user channel + native thread creation.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    BeginThreadRunRequest, ChannelAdministration, ChannelAdministrationError, ChannelCreateRequest,
    ChannelCreateScope, ThreadDirectory,
};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::ChannelRepo;
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

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
               ('actor','actor@example.test'),('other','other@example.test'),
               ('admin','admin@example.test');
             INSERT INTO public.user_roles(user_id,role) VALUES ('actor','user'),('admin','admin');
             INSERT INTO public.deployment_packages(tenant_id,source_path,checksum) VALUES
               ('tenant-a','/tenant-a','checksum-a'),('tenant-b','/tenant-b','checksum-b');
             INSERT INTO public.agents(id,name,type,configuration,package_id) VALUES
               ('agent-b','Zeta','built_in','{}',NULL),
               ('agent-private-other','Other private','built_in','{}',NULL),
               ('agent-deleted','Deleted','built_in','{}',NULL),
               ('agent-long',repeat('界',140),'built_in','{}',NULL);
             INSERT INTO public.agents(id,name,type,configuration,package_id)
               SELECT 'agent-a','Alpha','built_in','{}',id
                 FROM public.deployment_packages WHERE tenant_id='tenant-a';
             INSERT INTO public.agents(id,name,type,configuration,package_id)
               SELECT 'agent-foreign','Foreign','built_in','{}',id
                 FROM public.deployment_packages WHERE tenant_id='tenant-b';
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES
               ('agent-a',NULL,'Alpha','alpha role','a','public',NULL),
               ('agent-b','actor','Zeta','zeta role','b','private',NULL),
               ('agent-private-other','other','Other','other role','o','private',NULL),
               ('agent-deleted','actor','Deleted','deleted role','d','public',now()),
               ('agent-long','actor','Long','long role','l','private',NULL),
               ('agent-foreign',NULL,'Foreign','foreign role','f','public',NULL);",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn request(actor: &str, admin: bool, agents: &[&str]) -> ChannelCreateRequest {
    ChannelCreateRequest {
        scope: ChannelCreateScope {
            deployment: DeploymentId::new("dep-a"),
            tenant: TenantId::new("tenant-a"),
            actor: ActorId::new(actor),
            auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
            admin,
        },
        agent_ids: agents.iter().map(|id| BotId::new(*id)).collect(),
    }
}

async fn surface_counts(
    pool: &openbot_infra::db::pool::DatabasePool,
) -> Result<(i64, i64, i64, i64, i64, i64), String> {
    let client = pool.get().await.map_err(|error| error.to_string())?;
    let row = client
        .query_one(
            "SELECT
               (SELECT count(*)::bigint FROM public.channels),
               (SELECT count(*)::bigint FROM public.channel_memberships),
               (SELECT count(*)::bigint FROM public.channel_agents),
               (SELECT count(*)::bigint FROM public.threads),
               (SELECT count(*)::bigint FROM public.thread_memberships),
               (SELECT count(*)::bigint FROM public.intelligence_channel_mappings)",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok((
        row.try_get(0).map_err(|error| error.to_string())?,
        row.try_get(1).map_err(|error| error.to_string())?,
        row.try_get(2).map_err(|error| error.to_string())?,
        row.try_get(3).map_err(|error| error.to_string())?,
        row.try_get(4).map_err(|error| error.to_string())?,
        row.try_get(5).map_err(|error| error.to_string())?,
    ))
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn create_is_atomic_scoped_independent_native_and_single_connection() {
    let admin = admin_config("create_is_atomic_scoped_independent_native_and_single_connection");
    with_temp_database(&admin, "channelcreate", |mut config| async move {
        config.max_pool_size = 1;
        let runtime_config = config.clone();
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let repo = ChannelRepo::new(pool.clone());
            let first = repo
                .create_channel(request("actor", false, &["agent-a", "agent-b"]))
                .await
                .map_err(|error| error.to_string())?;
            if !first.id.as_str().starts_with("channel_")
                || first.name != "Alpha, Zeta"
                || first.agent_ids != [BotId::new("agent-a"), BotId::new("agent-b")]
                || !first.active
            {
                return Err(format!("created channel projection drifted: {first:?}"));
            }
            let thread = first
                .thread_id
                .as_ref()
                .ok_or_else(|| "created channel omitted native thread".to_owned())?;
            if !ThreadIdentity::new(&DeploymentId::new("dep-a")).owns(thread) {
                return Err("created thread lacks deployment fingerprint".to_owned());
            }
            if surface_counts(&pool).await? != (1, 1, 2, 1, 0, 0) {
                return Err(format!(
                    "first create surfaces drifted: {:?}",
                    surface_counts(&pool).await?
                ));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT c.description,m.user_id,t.tenant_id,t.deployment_id,t.created_by,
                            t.anchor_kind,t.anchor_id,t.status
                     FROM public.channels c
                     JOIN public.channel_memberships m ON m.channel_id=c.id
                     JOIN public.threads t ON t.anchor_id=c.id AND t.anchor_kind='channel'
                     WHERE c.id=$1",
                    &[&first.id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            let shape: (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
            ) = (
                row.try_get(0).map_err(|error| error.to_string())?,
                row.try_get(1).map_err(|error| error.to_string())?,
                row.try_get(2).map_err(|error| error.to_string())?,
                row.try_get(3).map_err(|error| error.to_string())?,
                row.try_get(4).map_err(|error| error.to_string())?,
                row.try_get(5).map_err(|error| error.to_string())?,
                row.try_get(6).map_err(|error| error.to_string())?,
                row.try_get(7).map_err(|error| error.to_string())?,
            );
            if shape
                != (
                    "Private agent channel.".to_owned(),
                    "actor".to_owned(),
                    "tenant-a".to_owned(),
                    "dep-a".to_owned(),
                    "actor".to_owned(),
                    "channel".to_owned(),
                    first.id.as_str().to_owned(),
                    "active".to_owned(),
                )
            {
                return Err(format!("stored channel/thread shape drifted: {shape:?}"));
            }
            drop(client);

            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                runtime_config,
                "runtime-channel-create".to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let started = directory
                .begin_thread_run(BeginThreadRunRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    deployment: DeploymentId::new("dep-a"),
                    tenant: TenantId::new("tenant-a"),
                    actor: ActorId::new("actor"),
                    command: BeginThreadRun {
                        artifact_refs: Vec::new(),
                        model_selection: None,
                        selected_skill_slugs: Vec::new(),
                        thread_id: thread.clone(),
                        run_id: RunId::new("run-created-channel"),
                        bot_id: BotId::new("agent-a"),
                        anchor: ThreadRunAnchor::Channel {
                            channel_id: first.id.clone(),
                        },
                        message: "first real channel message".to_owned(),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if started.replayed || started.thread_id != *thread {
                return Err(format!(
                    "created channel could not begin native run: {started:?}"
                ));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let bridge: (i64, i64, i64, Option<String>) = client
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.thread_memberships
                         WHERE thread_id=$1 AND user_id='actor'),
                       (SELECT count(*)::bigint FROM public.messages WHERE thread_id=$1),
                       (SELECT count(*)::bigint FROM public.runs WHERE thread_id=$1),
                       (SELECT last_message FROM public.channels WHERE id=$2)",
                    &[&thread.as_str(), &first.id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())
                .and_then(|row| {
                    Ok((
                        row.try_get(0).map_err(|error| error.to_string())?,
                        row.try_get(1).map_err(|error| error.to_string())?,
                        row.try_get(2).map_err(|error| error.to_string())?,
                        row.try_get(3).map_err(|error| error.to_string())?,
                    ))
                })?;
            if bridge != (1, 1, 1, Some("first real channel message".to_owned())) {
                return Err(format!(
                    "created channel/native begin bridge drifted: {bridge:?}"
                ));
            }
            drop(client);

            let second = repo
                .create_channel(request("actor", false, &["agent-a", "agent-b"]))
                .await
                .map_err(|error| error.to_string())?;
            if second.id == first.id || second.thread_id == first.thread_id {
                return Err("repeated selection reused channel/thread identity".to_owned());
            }
            if surface_counts(&pool).await? != (2, 2, 4, 2, 1, 0) {
                return Err("repeated create surfaces drifted".to_owned());
            }

            let long = repo
                .create_channel(request("actor", false, &["agent-long"]))
                .await
                .map_err(|error| error.to_string())?;
            if long.name.chars().count() != 120 || !long.name.ends_with('…') {
                return Err(format!("Unicode name truncation drifted: {}", long.name));
            }

            let before_denials = surface_counts(&pool).await?;
            for denied in [
                "agent-private-other",
                "agent-deleted",
                "agent-foreign",
                "missing",
            ] {
                if repo
                    .create_channel(request("actor", false, &[denied]))
                    .await
                    != Err(ChannelAdministrationError::NotVisible)
                {
                    return Err(format!(
                        "denied Agent {denied} did not collapse to NotVisible"
                    ));
                }
                if surface_counts(&pool).await? != before_denials {
                    return Err(format!("denied Agent {denied} left partial channel state"));
                }
            }
            repo.create_channel(request("admin", true, &["agent-private-other"]))
                .await
                .map_err(|error| error.to_string())?;
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
async fn deletion_committing_mid_creation_is_seen_after_the_profile_lock() {
    let admin = admin_config("deletion_committing_mid_creation_is_seen_after_the_profile_lock");
    with_temp_database(&admin, "channelcreaterace", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let mut blocker = pool.get().await.map_err(|error| error.to_string())?;
            let transaction = blocker
                .transaction()
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "UPDATE public.agent_profiles SET deleted_at=clock_timestamp()
                     WHERE agent_id='agent-a'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;

            let repo = ChannelRepo::new(pool.clone());
            let mut create = tokio::spawn(async move {
                repo.create_channel(request("actor", false, &["agent-a"]))
                    .await
            });
            if tokio::time::timeout(std::time::Duration::from_millis(100), &mut create)
                .await
                .is_ok()
            {
                return Err("channel create did not wait for concurrent profile lock".to_owned());
            }
            transaction
                .commit()
                .await
                .map_err(|error| error.to_string())?;
            if create.await.map_err(|error| error.to_string())?
                != Err(ChannelAdministrationError::NotVisible)
            {
                return Err("post-lock deleted profile was not refused".to_owned());
            }
            if surface_counts(&pool).await? != (0, 0, 0, 0, 0, 0) {
                return Err("concurrent deletion refusal left partial state".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
