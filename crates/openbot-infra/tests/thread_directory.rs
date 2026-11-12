//! Native thread directory 的 scope、防枚举与无 Intelligence 真库证据。

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::ThreadDirectory;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId, ThreadId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::thread_directory::PostgresThreadDirectory;

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn native_thread_status_is_scope_aware_and_never_uses_identity_as_visibility() {
    let admin =
        admin_config("native_thread_status_is_scope_aware_and_never_uses_identity_as_visibility");
    with_temp_database(&admin, "threadscope", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
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
                       ('actor-a','a@example.test'),('actor-b','b@example.test');
                     INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       deleted_at
                     ) VALUES
                       ('550e8400-e29b-41d4-a716-446655440000','tenant-a','dep-a','actor-a',
                        'direct_bot','bot-a','active',NULL),
                       ('550e8400-e29b-41d4-a716-446655440001','tenant-a','dep-a','actor-a',
                        'direct_bot','bot-a','active',NULL),
                       ('550e8400-e29b-41d4-a716-446655440002','tenant-a','dep-a','actor-a',
                        'direct_bot','bot-a','deleted',now());
                     INSERT INTO public.thread_memberships(thread_id,user_id) VALUES
                       ('550e8400-e29b-41d4-a716-446655440000','actor-a'),
                       ('550e8400-e29b-41d4-a716-446655440002','actor-a');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let directory = PostgresThreadDirectory::new(
                pool.clone(),
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                    &pool,
                    &openbot_contracts::ids::DeploymentId::new("outside"),
                    &openbot_contracts::ids::TenantId::new("outside"),
                ),
            );
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let actor = ActorId::new("actor-a");
            let legacy = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");

            if ThreadIdentity::new(&deployment).owns(&legacy) {
                return Err("前提失效：legacy UUID 不应被 dep-a identity 认领".to_owned());
            }
            if !directory
                .thread_known(&deployment, &tenant, &actor, &legacy)
                .await
                .map_err(|error| error.to_string())?
            {
                return Err("有精确 scope+membership 的 legacy UUID 必须 known".to_owned());
            }

            for (label, dep, ten, user, thread) in [
                (
                    "错 deployment",
                    "dep-b",
                    "tenant-a",
                    "actor-a",
                    legacy.as_str(),
                ),
                ("错 tenant", "dep-a", "tenant-b", "actor-a", legacy.as_str()),
                ("错 actor", "dep-a", "tenant-a", "actor-b", legacy.as_str()),
                (
                    "无 membership",
                    "dep-a",
                    "tenant-a",
                    "actor-a",
                    "550e8400-e29b-41d4-a716-446655440001",
                ),
                (
                    "已删除",
                    "dep-a",
                    "tenant-a",
                    "actor-a",
                    "550e8400-e29b-41d4-a716-446655440002",
                ),
                (
                    "不存在",
                    "dep-a",
                    "tenant-a",
                    "actor-a",
                    "550e8400-e29b-41d4-a716-446655440099",
                ),
            ] {
                let known = directory
                    .thread_known(
                        &DeploymentId::new(dep),
                        &TenantId::new(ten),
                        &ActorId::new(user),
                        &ThreadId::new(thread),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                if known {
                    return Err(format!("{label} 必须与不存在合并为 known=false"));
                }
            }

            let minted = directory
                .mint_thread_id(&deployment)
                .await
                .map_err(|error| error.to_string())?;
            if !ThreadIdentity::new(&deployment).owns(&minted) {
                return Err("production directory 铸造的 ID 不属于权威 deployment".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
