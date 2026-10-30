//! W-5 G2 ledger batch 7：Tenant Package loader、事务同步与 membership 投影。

mod harness;

use std::future::Future;
use std::path::PathBuf;

use harness::{admin_config, with_temp_database};
use openbot_application::tenant::package::{
    BuiltInProviderSource, LoadedTenantPackage, TenantAgentConfiguration, TenantAgentType,
    TenantPackageApplyError, TenantPackageAudienceContext, TenantPackageCollision,
    TenantPackageEnvironment, TenantPackageFiles, TenantPackageStoreError,
    synchronize_tenant_package, validate_tenant_package,
};
use openbot_application::{
    AgentContextSource, ProviderAdapter, ProviderExtensionKey, ProviderExtensions,
    ProviderPortError, ProviderRequest, ProviderRoute, ProviderSession, RunExecutionLease,
};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::identity::groups::{
    GroupClaimPath, GroupNormalization, IdentityProviderId, IdpGroupMapping,
};
use openbot_domain::thread::FencingToken;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::tenant::{PostgresTenantPackageSynchronizer, load_tenant_package};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const PRINCIPAL: &str = "dev-local-user";

#[test]
fn loads_the_mounted_fintech_package_without_a_theme_file() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/fintech");
    let loaded = load_tenant_package(&directory, &TenantPackageEnvironment::default()).unwrap();
    assert_eq!(loaded.package.tenant_id, "fintech");
    assert_eq!(loaded.package.product_name, "Ledgerline");
    assert_eq!(loaded.package.theme_status.code(), "absent");
    assert_eq!(loaded.checksum.len(), 64);
    assert!(loaded.checksum.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(
        loaded
            .package
            .agents
            .iter()
            .any(|agent| agent.id == "general-assistant")
    );
    let risk = loaded
        .package
        .agents
        .iter()
        .find(|agent| agent.id == "risk-analyst")
        .expect("未配置外部覆盖时 managed slot 应由 Rust built-in Agent 承接");
    assert_eq!(risk.agent_type, TenantAgentType::BuiltIn);
    assert!(matches!(
        &risk.configuration,
        TenantAgentConfiguration::BuiltIn {
            provider_source: BuiltInProviderSource::Managed,
            ..
        }
    ));
    assert!(
        loaded
            .package
            .channels
            .iter()
            .any(|channel| channel.id == "general-assistant" && channel.audience.is_everyone())
    );
}

async fn with_package_database<F, Fut>(test_name: &'static str, tag: &'static str, body: F)
where
    F: FnOnce(openbot_infra::db::pool::DatabasePool, PostgresTenantPackageSynchronizer) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(test_name);
    with_temp_database(&admin, tag, move |config| async move {
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
            drop(client);
            body(
                pool.clone(),
                PostgresTenantPackageSynchronizer::new(pool.clone()),
            )
            .await
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[derive(Clone, Copy)]
struct PackageSpec<'a> {
    tenant: &'a str,
    agent: &'a str,
    name: &'a str,
    title: &'a str,
    role: &'a str,
    avatar: Option<&'a str>,
    groups: &'a [&'a str],
    checksum_byte: char,
}

fn loaded(spec: PackageSpec<'_>) -> LoadedTenantPackage {
    let avatar = spec
        .avatar
        .map_or(String::new(), |value| format!(", avatar_seed: {value}"));
    let files = TenantPackageFiles {
        brand: format!(
            "tenant: {{ id: {}, product_name: Ledgerline }}",
            spec.tenant
        ),
        agents: format!(
            "agents: [{{ id: {}, name: {}, title: {}, role_description: {}{avatar}, type: built-in, system_prompt: Answer carefully. }}]",
            spec.agent, spec.name, spec.title, spec.role
        ),
        channels: format!(
            "channels: [{{ id: channel-{}, name: Channel, description: Test channel., permitted_agents: [{}], allowed_groups: [{}] }}]",
            spec.tenant,
            spec.agent,
            spec.groups.join(", ")
        ),
        model:
            "model: { provider: openai, credential_secret_ref: openai-key, default_model: gpt-4.1 }"
                .to_owned(),
        knowledge: "sources: []".to_owned(),
    };
    LoadedTenantPackage::new(
        validate_tenant_package(files).unwrap(),
        format!("/packages/{}", spec.tenant),
        std::iter::repeat_n(spec.checksum_byte, 64).collect(),
    )
    .unwrap()
}

fn single() -> TenantPackageAudienceContext {
    TenantPackageAudienceContext::single_user(ActorId::new(PRINCIPAL)).unwrap()
}

fn multi() -> TenantPackageAudienceContext {
    TenantPackageAudienceContext::multi_user([], Vec::new()).unwrap()
}

fn multi_with_mapping() -> TenantPackageAudienceContext {
    let provider = IdentityProviderId::new("directory");
    TenantPackageAudienceContext::multi_user(
        [provider.clone()],
        vec![IdpGroupMapping::new(
            provider,
            GroupClaimPath::from_dotted("groups").unwrap(),
            GroupNormalization::TrimLowercase,
        )],
    )
    .unwrap()
}

async fn insert_user(
    pool: &openbot_infra::db::pool::DatabasePool,
    id: &str,
    email: &str,
    groups: &[&str],
) -> Result<(), String> {
    let groups: Vec<String> = groups.iter().map(|group| (*group).to_owned()).collect();
    pool.get()
        .await
        .map_err(|error| error.to_string())?
        .execute(
            "INSERT INTO public.users(id,email,name,email_verified,groups,auth_generation) \
             VALUES($1,$2,$1,true,$3,0)",
            &[&id, &email, &groups],
        )
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

async fn scalar(
    pool: &openbot_infra::db::pool::DatabasePool,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<i64, String> {
    pool.get()
        .await
        .map_err(|error| error.to_string())?
        .query_one(sql, params)
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn creates_a_public_ownerless_profile_for_a_canonical_package_agent() {
    with_package_database(
        "creates_a_public_ownerless_profile_for_a_canonical_package_agent",
        "tenant_profile",
        |pool, synchronizer| async move {
            insert_user(&pool, PRINCIPAL, "dev@openbot.local", &[]).await?;
            let package = loaded(PackageSpec {
                tenant: "tenant-a",
                agent: "assistant-a",
                name: "Assistant",
                title: "Everyday Work",
                role: "Help with work.",
                avatar: None,
                groups: &["risk"],
                checksum_byte: 'a',
            });
            let report = synchronize_tenant_package(&synchronizer, &package, &single())
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT a.name,p.owner_user_id,p.title,p.role_description,p.avatar_seed,\
                            p.visibility::text,p.deleted_at,\
                            EXISTS(SELECT 1 FROM public.channel_memberships m \
                                   WHERE m.channel_id='channel-tenant-a' AND m.user_id=$1) AS member \
                     FROM public.agents a JOIN public.agent_profiles p ON p.agent_id=a.id \
                     WHERE a.id='assistant-a'",
                    &[&PRINCIPAL],
                )
                .await
                .map_err(|error| error.to_string())?;
            if row.try_get::<_, &str>("name").unwrap() != "Assistant"
                || row.try_get::<_, Option<&str>>("owner_user_id").unwrap().is_some()
                || row.try_get::<_, &str>("title").unwrap() != "Everyday Work"
                || row.try_get::<_, &str>("role_description").unwrap() != "Help with work."
                || row.try_get::<_, &str>("avatar_seed").unwrap() != "assistant-a"
                || row.try_get::<_, &str>("visibility").unwrap() != "public"
                || row
                    .try_get::<_, Option<OffsetDateTime>>("deleted_at")
                    .unwrap()
                    .is_some()
                || !row.try_get::<_, bool>("member").unwrap()
                || !report.single_user_groups_ignored
                || report.memberships_granted != 1
            {
                return Err("canonical/profile/single-user membership 投影不完整".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn refuses_to_synchronize_while_a_bot_named_after_a_deployment_route_exists() {
    with_package_database(
        "refuses_to_synchronize_while_a_bot_named_after_a_deployment_route_exists",
        "tenant_reserved",
        |pool, synchronizer| async move {
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "INSERT INTO public.agents(id,name,type,configuration) \
                     VALUES('policy','Old','built_in','{}')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let package = loaded(PackageSpec {
                tenant: "tenant-b",
                agent: "assistant-b",
                name: "Assistant",
                title: "Work",
                role: "Help.",
                avatar: None,
                groups: &["all"],
                checksum_byte: 'b',
            });
            let error = synchronize_tenant_package(&synchronizer, &package, &multi())
                .await
                .unwrap_err();
            if error
                != TenantPackageApplyError::Store(TenantPackageStoreError::Collision {
                    kind: TenantPackageCollision::ReservedAgent,
                })
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.deployment_packages",
                    &[],
                )
                .await?
                    != 0
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.agents WHERE id='assistant-b'",
                    &[],
                )
                .await?
                    != 0
            {
                return Err("保留 Bot 没有让整个同步事务零副作用拒绝".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn synchronizes_normally_when_no_such_bot_exists() {
    with_package_database(
        "synchronizes_normally_when_no_such_bot_exists",
        "tenant_normal",
        |pool, synchronizer| async move {
            insert_user(&pool, "person-1", "person@example.com", &[]).await?;
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "INSERT INTO public.agents(id,name,type,configuration) \
                     VALUES('policy-desk','Ordinary','built_in','{}')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let package = loaded(PackageSpec {
                tenant: "tenant-c",
                agent: "assistant-c",
                name: "Assistant",
                title: "Work",
                role: "Help.",
                avatar: None,
                groups: &["all"],
                checksum_byte: 'c',
            });
            let report = synchronize_tenant_package(&synchronizer, &package, &multi())
                .await
                .map_err(|error| error.to_string())?;
            if report.agents != 1
                || report.channels != 1
                || report.memberships_granted != 1
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.agents WHERE id='assistant-c'",
                    &[],
                )
                .await?
                    != 1
            {
                return Err("普通 Bot 存在时 package 没有正常同步".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn resynchronizes_and_undeletes_an_existing_package_profile() {
    with_package_database(
        "resynchronizes_and_undeletes_an_existing_package_profile",
        "tenant_resync",
        |pool, synchronizer| async move {
            insert_user(&pool, "person-2", "person2@example.com", &[]).await?;
            let first = loaded(PackageSpec {
                tenant: "tenant-d",
                agent: "assistant-d",
                name: "Old",
                title: "Old Title",
                role: "Old role.",
                avatar: Some("old-avatar"),
                groups: &["all"],
                checksum_byte: 'd',
            });
            synchronize_tenant_package(&synchronizer, &first, &multi())
                .await
                .map_err(|error| error.to_string())?;
            let now = OffsetDateTime::now_utc();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.agent_profiles SET visibility='private',deleted_at=$1 \
                     WHERE agent_id='assistant-d'",
                    &[&now],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.sessions(id,user_id,token,expires_at,auth_generation) \
                     VALUES('session-d','person-2','sh1_test', $1,0)",
                    &[&(now + Duration::hours(1))],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let second = loaded(PackageSpec {
                tenant: "tenant-d",
                agent: "assistant-d",
                name: "Updated",
                title: "Updated Title",
                role: "Updated role.",
                avatar: Some("updated-avatar"),
                groups: &["risk"],
                checksum_byte: 'e',
            });
            let report = synchronize_tenant_package(
                &synchronizer,
                &second,
                &multi_with_mapping(),
            )
            .await
            .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT a.name,p.title,p.role_description,p.avatar_seed,p.visibility::text,\
                            p.deleted_at,coalesce(u.auth_generation,0) AS generation,\
                            EXISTS(SELECT 1 FROM public.sessions s WHERE s.user_id=u.id) AS has_session \
                     FROM public.agents a JOIN public.agent_profiles p ON p.agent_id=a.id \
                     CROSS JOIN public.users u WHERE a.id='assistant-d' AND u.id='person-2'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if row.try_get::<_, &str>("name").unwrap() != "Updated"
                || row.try_get::<_, &str>("title").unwrap() != "Updated Title"
                || row.try_get::<_, &str>("role_description").unwrap() != "Updated role."
                || row.try_get::<_, &str>("avatar_seed").unwrap() != "updated-avatar"
                || row.try_get::<_, &str>("visibility").unwrap() != "public"
                || row
                    .try_get::<_, Option<OffsetDateTime>>("deleted_at")
                    .unwrap()
                    .is_some()
                || row.try_get::<_, i64>("generation").unwrap() != 1
                || row.try_get::<_, bool>("has_session").unwrap()
                || report.memberships_revoked != 1
                || report.generations_advanced != 1
            {
                return Err("resync/profile/audience 收紧没有原子落地".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn rejects_a_user_created_canonical_and_profile_collision_without_changing_them() {
    with_package_database(
        "rejects_a_user_created_canonical_and_profile_collision_without_changing_them",
        "tenant_user_agent",
        |pool, synchronizer| async move {
            insert_user(&pool, "owner-1", "owner1@example.com", &[]).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.agents(id,name,type,configuration) \
                     VALUES('assistant-e','User Agent','built_in','{\"systemPrompt\":\"user\"}');
                     INSERT INTO public.agent_profiles(\
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility) \
                     VALUES('assistant-e','owner-1','User Title','User role.','user-avatar','private');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let package = loaded(PackageSpec {
                tenant: "tenant-e",
                agent: "assistant-e",
                name: "Package Agent",
                title: "Package Title",
                role: "Package role.",
                avatar: None,
                groups: &["all"],
                checksum_byte: 'f',
            });
            let error = synchronize_tenant_package(&synchronizer, &package, &multi())
                .await
                .unwrap_err();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT a.name,a.package_id,p.owner_user_id,p.title FROM public.agents a \
                     JOIN public.agent_profiles p ON p.agent_id=a.id WHERE a.id='assistant-e'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if error
                != TenantPackageApplyError::Store(TenantPackageStoreError::Collision {
                    kind: TenantPackageCollision::UserAgent,
                })
                || row.try_get::<_, &str>("name").unwrap() != "User Agent"
                || row.try_get::<_, Option<Uuid>>("package_id").unwrap().is_some()
                || row.try_get::<_, &str>("owner_user_id").unwrap() != "owner-1"
                || row.try_get::<_, &str>("title").unwrap() != "User Title"
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.deployment_packages WHERE tenant_id='tenant-e'",
                    &[],
                )
                .await?
                    != 0
            {
                return Err("user-created collision 没有全事务回滚".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn rejects_a_user_owned_profile_collision_and_rolls_back_canonical_changes() {
    with_package_database(
        "rejects_a_user_owned_profile_collision_and_rolls_back_canonical_changes",
        "tenant_user_profile",
        |pool, synchronizer| async move {
            insert_user(&pool, "owner-2", "owner2@example.com", &[]).await?;
            let package = loaded(PackageSpec {
                tenant: "tenant-f",
                agent: "assistant-f",
                name: "Original",
                title: "Original Title",
                role: "Original role.",
                avatar: None,
                groups: &["all"],
                checksum_byte: '1',
            });
            synchronize_tenant_package(&synchronizer, &package, &multi())
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.agent_profiles SET owner_user_id='owner-2',title='User Title',\
                     visibility='private' WHERE agent_id='assistant-f'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let checksum_before: String = client
                .query_one(
                    "SELECT checksum FROM public.deployment_packages WHERE tenant_id='tenant-f'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(client);
            let changed = loaded(PackageSpec {
                tenant: "tenant-f",
                agent: "assistant-f",
                name: "Changed",
                title: "Changed Title",
                role: "Changed role.",
                avatar: None,
                groups: &["all"],
                checksum_byte: '2',
            });
            let error = synchronize_tenant_package(&synchronizer, &changed, &multi())
                .await
                .unwrap_err();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT a.name,p.owner_user_id,p.title,dp.checksum FROM public.agents a \
                     JOIN public.agent_profiles p ON p.agent_id=a.id \
                     JOIN public.deployment_packages dp ON dp.id=a.package_id \
                     WHERE a.id='assistant-f'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if error
                != TenantPackageApplyError::Store(TenantPackageStoreError::Collision {
                    kind: TenantPackageCollision::UserProfile,
                })
                || row.try_get::<_, &str>("name").unwrap() != "Original"
                || row.try_get::<_, &str>("owner_user_id").unwrap() != "owner-2"
                || row.try_get::<_, &str>("title").unwrap() != "User Title"
                || row.try_get::<_, &str>("checksum").unwrap() != checksum_before
            {
                return Err("user-owned profile collision 没有回滚 canonical/package".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn rejects_a_cross_package_agent_collision_and_rolls_back_both_packages() {
    with_package_database(
        "rejects_a_cross_package_agent_collision_and_rolls_back_both_packages",
        "tenant_cross_package",
        |pool, synchronizer| async move {
            let package_a = loaded(PackageSpec {
                tenant: "tenant-g-a",
                agent: "shared-agent",
                name: "Package A",
                title: "A Title",
                role: "A role.",
                avatar: None,
                groups: &["all"],
                checksum_byte: '3',
            });
            synchronize_tenant_package(&synchronizer, &package_a, &multi())
                .await
                .map_err(|error| error.to_string())?;
            let package_b = loaded(PackageSpec {
                tenant: "tenant-g-b",
                agent: "shared-agent",
                name: "Package B",
                title: "B Title",
                role: "B role.",
                avatar: None,
                groups: &["all"],
                checksum_byte: '4',
            });
            let error = synchronize_tenant_package(&synchronizer, &package_b, &multi())
                .await
                .unwrap_err();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT a.name,dp.tenant_id FROM public.agents a \
                     JOIN public.deployment_packages dp ON dp.id=a.package_id \
                     WHERE a.id='shared-agent'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if error
                != TenantPackageApplyError::Store(TenantPackageStoreError::Collision {
                    kind: TenantPackageCollision::OtherPackageAgent,
                })
                || row.try_get::<_, &str>("name").unwrap() != "Package A"
                || row.try_get::<_, &str>("tenant_id").unwrap() != "tenant-g-a"
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.deployment_packages WHERE tenant_id='tenant-g-b'",
                    &[],
                )
                .await?
                    != 0
            {
                return Err("cross-package collision 没有回滚两个 package 的观察面".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

fn extension_package() -> LoadedTenantPackage {
    let files = TenantPackageFiles {
        brand: "tenant: { id: tenant-x, product_name: Ledgerline }".to_owned(),
        agents: "agents:\n  - id: crab-agent\n    name: Crab\n    title: Crab\n    role_description: Host bot.\n    type: built-in\n    system_prompt: Answer carefully.\n    providerSource: extension:crabcode\n".to_owned(),
        channels: "channels: [{ id: channel-tenant-x, name: Channel, description: Test channel., permitted_agents: [crab-agent], allowed_groups: [all] }]".to_owned(),
        model: "model: { provider: openai, credential_secret_ref: openai-key, default_model: gpt-4.1 }"
            .to_owned(),
        knowledge: "sources: []".to_owned(),
    };
    LoadedTenantPackage::new(
        validate_tenant_package(files).unwrap(),
        "/packages/tenant-x".to_owned(),
        "c".repeat(64),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn synchronize_writes_extension_provider_source_verbatim() {
    with_package_database(
        "synchronize_writes_extension_provider_source_verbatim",
        "tenant_extension_write",
        |pool, synchronizer| async move {
            synchronize_tenant_package(&synchronizer, &extension_package(), &multi())
                .await
                .map_err(|error| error.to_string())?;
            let source: String = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT configuration->>'providerSource' FROM public.agents WHERE id='crab-agent'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if source != "extension:crabcode" {
                return Err(format!("providerSource 未原样写入：{source}"));
            }
            Ok(())
        },
    )
    .await;
}

struct ContextOnlyAdapter;

#[async_trait::async_trait]
impl ProviderAdapter for ContextOnlyAdapter {
    async fn start(
        &self,
        _: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        panic!("context-only evidence must not start provider")
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn context_source_routes_extension_provider_source_after_sync() {
    with_package_database(
        "context_source_routes_extension_provider_source_after_sync",
        "tenant_extension_route",
        |pool, synchronizer| async move {
            insert_user(&pool, PRINCIPAL, "dev@openbot.local", &[]).await?;
            synchronize_tenant_package(&synchronizer, &extension_package(), &single())
                .await
                .map_err(|error| error.to_string())?;
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .batch_execute(
                    "INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       next_message_seq,next_event_seq,created_at,updated_at
                     ) VALUES('thread-x','tenant-x','deployment-x','dev-local-user','direct_bot',
                              'crab-agent','active',1,0,clock_timestamp(),clock_timestamp());
                     INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('thread-x','dev-local-user');
                     INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                       next_event_seq,created_at,started_at
                     ) VALUES('run-x','thread-x','crab-agent','dev-local-user',true,'running',1,0,
                              clock_timestamp(),clock_timestamp());
                     INSERT INTO public.messages(
                       message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at
                     ) VALUES('message-x','thread-x',0,'user','{\"text\":\"Hello.\"}',
                              'Hello.','run-x','dev-local-user',clock_timestamp());",
                )
                .await
                .map_err(|error| error.to_string())?;
            let key = ProviderExtensionKey::new("crabcode").unwrap();
            let extensions = ProviderExtensions::try_new(vec![(
                key.clone(),
                std::sync::Arc::new(ContextOnlyAdapter) as std::sync::Arc<dyn ProviderAdapter>,
            )])
            .map_err(|error| error.to_string())?;
            let context = PostgresAgentContextSource::new(
                pool.clone(),
                DeploymentId::new("deployment-x"),
                TenantId::new("tenant-x"),
                None,
            )
            .map_err(|error| error.to_string())?
            .with_extensions(extensions);
            let lease = RunExecutionLease::new(
                RunId::new("run-x"),
                ThreadId::new("thread-x"),
                BotId::new("crab-agent"),
                ActorId::new(PRINCIPAL),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let request = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if request.route != ProviderRoute::Extension(key) {
                return Err(format!(
                    "同步后的 extension 路由不成立：{:?}",
                    request.route
                ));
            }
            Ok(())
        },
    )
    .await;
}
