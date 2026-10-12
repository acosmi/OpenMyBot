//! W-2 当前 schema repository 的 PostgreSQL 17 真库矩阵。

mod harness;

use core::time::Duration;

use harness::{admin_config, with_temp_database};
use openbot_application::ChannelReader;
use openbot_contracts::ids::{ActorId, AuditEventId};
use openbot_domain::audit::chain::{ChainAnchor, ChainVerification, verify_chain};
use openbot_domain::audit::checkpoint::{AuditCheckpointKind, ChainSegment};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::tool::commit::CommitState;
use serde_json::json;
use time::OffsetDateTime;

use openbot_infra::db::tables::{self, tool_attempts, tool_calls};
use openbot_infra::db::{InfraError, baseline, native, pool};
use openbot_infra::repo::agents::{AgentPreferenceRepo, AgentProfileRepo, AgentRepo};
use openbot_infra::repo::audit::AuditEventRepo;
use openbot_infra::repo::channels::{
    ChannelAgentRepo, ChannelMembershipRepo, ChannelRepo, LegacyIntelligenceMappingRepo,
};
use openbot_infra::repo::components::{
    ComponentExclusionRepo, ComponentFunctionRepo, ComponentRepo, SandboxedComponentRepo,
};
use openbot_infra::repo::computer::{ActionPolicyRepo, SnapshotRepo};
use openbot_infra::repo::import::ImportCursorRepo;
use openbot_infra::repo::memory::{MemoryEventRepo, MemoryRepo};
use openbot_infra::repo::outbox::OutboxRepo;
use openbot_infra::repo::people::{
    AccountRepo, IdentityProviderRepo, RevokedAccessRepo, RoleRepo, SessionRepo, UserRepo,
    VerificationRepo,
};
use openbot_infra::repo::plugins::{
    McpServerRepo, McpToolRepo, McpUserCredentialRepo, PluginGrantRepo, SkillRepo,
};
use openbot_infra::repo::run::{RunEventRepo, RunRepo};
use openbot_infra::repo::tenant::DeploymentPackageRepo;
use openbot_infra::repo::thread::{MessageRepo, ThreadLeaseRepo, ThreadMembershipRepo, ThreadRepo};
use openbot_infra::repo::tools::{
    FirstDurableDecision, PersistedToolOutcome, ToolAttemptRepo, ToolCallRepo,
};
use openbot_infra::vault::CredentialRepo;

const SEED_SQL: &str = include_str!("../../../fixtures/db/seed-0012.sql");

async fn provision(pool: &openbot_infra::db::pool::DatabasePool, seed: bool) -> Result<(), String> {
    let mut client = pool
        .get()
        .await
        .map_err(|error| format!("取连接失败：{error}"))?;
    baseline::apply(&client)
        .await
        .map_err(|error| format!("应用 baseline 失败：{error}"))?;
    // seed-0012 is schema-0012 legacy data (including free channel previews). It is
    // loaded where it was generated and then upgraded; current 0051 guards rightly
    // refuse a new non-NULL preview without a canonical source.
    if seed {
        client
            .batch_execute(SEED_SQL)
            .await
            .map_err(|error| format!("灌入 seed-0012 失败：{error}"))?;
    }
    native::apply(&mut client)
        .await
        .map_err(|error| format!("应用 native migrations 失败：{error}"))?;
    Ok(())
}

async fn seed_tool_run(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    pool.get()
        .await
        .map_err(|error| error.to_string())?
        .batch_execute(
            "INSERT INTO public.threads(\
               thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id) \
             VALUES('thread-tool-1','tenant-1','deployment-1','actor-1','direct_bot','bot-1'); \
             INSERT INTO public.runs(\
               run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at) \
             VALUES('run-1','thread-tool-1','bot-1','actor-1',false,'running',1,now());",
        )
        .await
        .map_err(|error| error.to_string())
}

macro_rules! expect_six {
    ($pool:expr, $repo:ty) => {{
        let rows = <$repo>::new($pool.clone())
            .list_all()
            .await
            .map_err(|error| format!("{} list_all 失败：{error}", stringify!($repo)))?;
        if rows.len() != 6 {
            return Err(format!(
                "{} 应读出 seed 的 6 行，实际 {}",
                stringify!($repo),
                rows.len(),
            ));
        }
    }};
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn all_forty_current_repositories_touch_their_real_tables() {
    let admin = admin_config("all_forty_current_repositories_touch_their_real_tables");
    with_temp_database(&admin, "repo_inventory", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            provision(&pool, true).await?;

            expect_six!(pool, UserRepo);
            expect_six!(pool, SessionRepo);
            expect_six!(pool, AccountRepo);
            expect_six!(pool, VerificationRepo);
            expect_six!(pool, RoleRepo);
            expect_six!(pool, RevokedAccessRepo);
            expect_six!(pool, IdentityProviderRepo);
            expect_six!(pool, DeploymentPackageRepo);
            expect_six!(pool, AgentRepo);
            expect_six!(pool, AgentProfileRepo);
            expect_six!(pool, AgentPreferenceRepo);
            expect_six!(pool, ChannelMembershipRepo);
            expect_six!(pool, ChannelAgentRepo);
            expect_six!(pool, LegacyIntelligenceMappingRepo);
            expect_six!(pool, ComponentRepo);
            expect_six!(pool, ComponentExclusionRepo);
            expect_six!(pool, ComponentFunctionRepo);
            expect_six!(pool, SandboxedComponentRepo);
            expect_six!(pool, ActionPolicyRepo);
            expect_six!(pool, SnapshotRepo);
            expect_six!(pool, McpServerRepo);
            expect_six!(pool, McpToolRepo);
            expect_six!(pool, McpUserCredentialRepo);
            expect_six!(pool, PluginGrantRepo);
            expect_six!(pool, SkillRepo);
            expect_six!(pool, CredentialRepo);

            let audit = AuditEventRepo::new(pool.clone())
                .list_all()
                .await
                .map_err(|error| format!("AuditEventRepo list_all 失败：{error}"))?;
            if audit.len() != 6 {
                return Err(format!("AuditEventRepo 应读 6 行，实际 {}", audit.len()));
            }
            let calls = ToolCallRepo::new(pool.clone())
                .list_all()
                .await
                .map_err(|error| format!("ToolCallRepo list_all 失败：{error}"))?;
            let attempts = ToolAttemptRepo::new(pool.clone())
                .list_all()
                .await
                .map_err(|error| format!("ToolAttemptRepo list_all 失败：{error}"))?;
            if !calls.is_empty() || !attempts.is_empty() {
                return Err("全新 0013 的 tool 表必须为空".to_owned());
            }

            macro_rules! expect_empty {
                ($repo:ty) => {
                    if !<$repo>::new(pool.clone())
                        .list_all()
                        .await
                        .map_err(|error| format!("{} list_all 失败：{error}", stringify!($repo)))?
                        .is_empty()
                    {
                        return Err(format!("{} 在全新 0016 应为空", stringify!($repo)));
                    }
                };
            }
            expect_empty!(ThreadRepo);
            expect_empty!(ThreadMembershipRepo);
            expect_empty!(MessageRepo);
            expect_empty!(ThreadLeaseRepo);
            expect_empty!(RunRepo);
            expect_empty!(RunEventRepo);
            expect_empty!(OutboxRepo);
            expect_empty!(MemoryRepo);
            expect_empty!(MemoryEventRepo);
            expect_empty!(ImportCursorRepo);

            let visible = ChannelRepo::new(pool.clone())
                .list_visible_channels(&ActorId::new("users_00"), 100, None)
                .await
                .map_err(|error| format!("ChannelRepo 真业务查询失败：{error}"))?;
            if visible.is_empty() {
                return Err("ChannelRepo 对 seed actor 不应返回空".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn people_and_auth_repositories_use_their_authoritative_unique_keys() {
    let admin = admin_config("people_and_auth_repositories_use_their_authoritative_unique_keys");
    with_temp_database(&admin, "repo_people", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            provision(&pool, true).await?;

            let users = UserRepo::new(pool.clone());
            let user = users
                .list_all()
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .next()
                .ok_or_else(|| "seed 缺 user".to_owned())?;
            if users
                .find_by_email(&user.email)
                .await
                .map_err(|error| error.to_string())?
                .as_ref()
                .map(|row| row.id.as_str())
                != Some(user.id.as_str())
            {
                return Err("UserRepo email unique lookup 不符".to_owned());
            }

            let sessions = SessionRepo::new(pool.clone());
            let session = sessions
                .list_all()
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .next()
                .ok_or_else(|| "seed 缺 session".to_owned())?;
            if sessions
                .find_by_token(&session.token)
                .await
                .map_err(|error| error.to_string())?
                .as_ref()
                .map(|row| row.id.as_str())
                != Some(session.id.as_str())
            {
                return Err("SessionRepo token unique lookup 不符".to_owned());
            }

            let accounts = AccountRepo::new(pool.clone());
            let account = accounts
                .list_all()
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .next()
                .ok_or_else(|| "seed 缺 account".to_owned())?;
            if accounts
                .find_by_provider_account(&account.provider_id, &account.account_id)
                .await
                .map_err(|error| error.to_string())?
                .as_ref()
                .map(|row| row.id.as_str())
                != Some(account.id.as_str())
            {
                return Err("AccountRepo provider/account unique lookup 不符".to_owned());
            }

            let verifications = VerificationRepo::new(pool.clone());
            let verification = verifications
                .list_all()
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .next()
                .ok_or_else(|| "seed 缺 verification".to_owned())?;
            if !verifications
                .list_by_identifier(&verification.identifier)
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .any(|row| row.id == verification.id)
            {
                return Err("VerificationRepo identifier lookup 漏行".to_owned());
            }

            let roles = RoleRepo::new(pool.clone());
            let all_roles = roles.list_all().await.map_err(|error| error.to_string())?;
            let admin_rows = all_roles
                .iter()
                .filter(|row| row.role == openbot_infra::db::types::Role::Admin)
                .count();
            if roles
                .count_admins()
                .await
                .map_err(|error| error.to_string())?
                != i64::try_from(admin_rows).unwrap()
            {
                return Err("RoleRepo admin 计数与 typed 行不符".to_owned());
            }
            let role = all_roles.first().ok_or_else(|| "seed 缺 role".to_owned())?;
            if !roles
                .list_for_user(&role.user_id)
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .any(|row| row.role == role.role)
            {
                return Err("RoleRepo user lookup 漏角色".to_owned());
            }

            let revoked = RevokedAccessRepo::new(pool.clone());
            let revoked_row = revoked
                .list_all()
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .next()
                .ok_or_else(|| "seed 缺 revoked_access".to_owned())?;
            if !revoked
                .is_revoked(&revoked_row.email)
                .await
                .map_err(|error| error.to_string())?
            {
                return Err("RevokedAccessRepo 没认出已有撤权".to_owned());
            }

            let providers = IdentityProviderRepo::new(pool.clone());
            let provider = providers
                .list_all()
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .next()
                .ok_or_else(|| "seed 缺 sso provider".to_owned())?;
            if providers
                .find_by_provider_id(&provider.provider_id)
                .await
                .map_err(|error| error.to_string())?
                .as_ref()
                .map(|row| row.id.as_str())
                != Some(provider.id.as_str())
                || !providers
                    .list_by_domain(&provider.domain)
                    .await
                    .map_err(|error| error.to_string())?
                    .iter()
                    .any(|row| row.id == provider.id)
            {
                return Err("IdentityProviderRepo provider/domain lookup 不符".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn tool_decision_and_attempt_transitions_are_durable_and_compare_and_swap() {
    let admin =
        admin_config("tool_decision_and_attempt_transitions_are_durable_and_compare_and_swap");
    with_temp_database(&admin, "repo_tools", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            provision(&pool, false).await?;
            seed_tool_run(&pool).await?;
            let calls = ToolCallRepo::new(pool.clone());
            let attempts = ToolAttemptRepo::new(pool.clone());
            let decided_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
            let first = decision_rows("call-1", "decision-1", "attempt-1", decided_at);
            let receipt = calls
                .record_first_decision(&first)
                .await
                .map_err(|error| format!("写 first decision 失败：{error}"))?;
            if receipt.decision().as_str() != "decision-1"
                || receipt.attempt().as_str() != "attempt-1"
            {
                return Err("commit 后 receipt 的 id 不符".to_owned());
            }

            let mut colliding = decision_rows("call-2", "decision-2", "attempt-1", decided_at);
            colliding.call.call_seq = 1;
            let error = calls
                .record_first_decision(&colliding)
                .await
                .expect_err("重复 attempt_id 必须让整个事务失败");
            if error.sqlstate() != Some("23505") {
                return Err(format!("重复 attempt 应命中 23505，实际 {error:?}"));
            }
            if calls
                .find_by_id("call-2")
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("attempt 写失败却留下了 call-2，decision/attempt 非原子".to_owned());
            }

            let started = decided_at + Duration::from_secs(1);
            if attempts
                .attach_capability("call-1", 9, "cap-wrong", started)
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("不存在的 attempt 不得绑定 capability".to_owned());
            }
            let executing = attempts
                .attach_capability("call-1", 0, "cap-1", started)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "合法 capability 没绑上".to_owned())?;
            if executing.status != "executing" {
                return Err(format!("绑定后状态不是 executing：{}", executing.status));
            }
            if attempts
                .attach_capability("call-1", 0, "cap-2", started)
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("同一 attempt 第二张 capability 不得覆盖第一张".to_owned());
            }

            let completed = PersistedToolOutcome {
                commit_state: CommitState::Committed,
                output_bytes: 17,
                duration: Duration::from_millis(25),
                error_code: None,
                finished_at: started + Duration::from_millis(25),
            };
            if attempts
                .record_outcome("call-1", 0, "cap-wrong", &completed)
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("错误 capability 不得写 outcome".to_owned());
            }
            let completed_row = attempts
                .record_outcome("call-1", 0, "cap-1", &completed)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "合法 outcome 没写入".to_owned())?;
            if completed_row.status != "completed"
                || completed_row.commit_state.as_deref() != Some("committed")
            {
                return Err(format!("完成状态不符：{completed_row:?}"));
            }
            if attempts
                .record_outcome("call-1", 0, "cap-1", &completed)
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("terminal attempt 不得重复写 outcome".to_owned());
            }

            let retry = pristine_attempt("call-1", 1, "attempt-2", decided_at);
            attempts
                .insert_retry(&retry)
                .await
                .map_err(|error| format!("写 retry 失败：{error}"))?;
            attempts
                .attach_capability("call-1", 1, "cap-reconcile", started)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "retry capability 没绑上".to_owned())?;
            let unknown = PersistedToolOutcome {
                commit_state: CommitState::Unknown,
                output_bytes: 0,
                duration: Duration::from_millis(10),
                error_code: Some("dependency_unavailable"),
                finished_at: started + Duration::from_millis(10),
            };
            let reconciled = attempts
                .record_outcome("call-1", 1, "cap-reconcile", &unknown)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "unknown outcome 没写入".to_owned())?;
            if reconciled.status != "reconciliation_required"
                || reconciled.commit_state.as_deref() != Some("unknown")
            {
                return Err(format!("unknown 没进入 reconciliation：{reconciled:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn audit_chain_checkpoints_and_vault_rotation_hold_on_real_postgres() {
    let admin = admin_config("audit_chain_checkpoints_and_vault_rotation_hold_on_real_postgres");
    with_temp_database(&admin, "repo_audit_vault", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            provision(&pool, true).await?;
            let audit = AuditEventRepo::new(pool.clone());
            // seed 的最大审计时刻是 2038-01-19；repository 新链必须严格排在它之后。
            let first_event = audit_event("018f47d2-2c00-7a00-8000-000000000001", 2_200_000_000);
            let second_event = audit_event("018f47d2-2c00-7a00-8000-000000000002", 2_200_000_001);
            let key = b"repository-test-checkpoint-key";
            let first = audit
                .append(&first_event, key)
                .await
                .map_err(|error| format!("追加 genesis 失败：{error}"))?;
            let second = audit
                .append(&second_event, key)
                .await
                .map_err(|error| format!("追加第二行失败：{error}"))?;
            match verify_chain(&[first.clone(), second.clone()], ChainAnchor::ChainStart) {
                ChainVerification::Intact { linked_rows: 2, .. } => {}
                other => return Err(format!("repository 写出的链不自洽：{other:?}")),
            }
            let out_of_order = audit
                .append(
                    &audit_event("018f47d2-2c00-7a00-8000-000000000003", 2_200_000_000),
                    key,
                )
                .await;
            if !matches!(
                out_of_order,
                Err(InfraError::RepositoryInvariant {
                    code: "audit_event_order_not_monotonic"
                })
            ) {
                return Err(format!(
                    "倒序 audit event 没有 fail-closed：{out_of_order:?}"
                ));
            }
            let checkpoints = audit
                .list_checkpoints()
                .await
                .map_err(|error| error.to_string())?;
            if checkpoints.len() != 1 || checkpoints[0].unlinked_rows_before != Some(6) {
                return Err(format!("genesis 没记下 6 条 legacy 行：{checkpoints:?}"));
            }
            let segment = ChainSegment {
                first_event: first_event.id.clone(),
                first_row_hash: first.row_hash.expect("link 必有 hash"),
                last_event: second_event.id.clone(),
                last_row_hash: second.row_hash.expect("link 必有 hash"),
                event_count: 2,
            };
            let periodic = audit
                .append_checkpoint(
                    AuditCheckpointKind::Periodic {
                        segment: segment.clone(),
                    },
                    OffsetDateTime::from_unix_timestamp(2_200_000_002).unwrap(),
                    key,
                )
                .await
                .map_err(|error| format!("写 periodic checkpoint 失败：{error}"))?;
            if periodic.sequence != 1 {
                return Err(format!(
                    "periodic sequence 应为1，实际 {}",
                    periodic.sequence
                ));
            }
            let mut bad_segment = segment;
            bad_segment.event_count = 3;
            let bad = audit
                .append_checkpoint(
                    AuditCheckpointKind::Periodic {
                        segment: bad_segment,
                    },
                    OffsetDateTime::from_unix_timestamp(2_200_000_003).unwrap(),
                    key,
                )
                .await;
            if !matches!(
                bad,
                Err(InfraError::RepositoryInvariant {
                    code: "audit_checkpoint_event_count_mismatch"
                })
            ) {
                return Err(format!("伪造区间条数没有 fail-closed：{bad:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.audit_events \
                     (id,event_type,target_type,payload,created_at,prev_hash,row_hash) \
                     VALUES ('018f47d2-2c00-7a00-8000-000000000004', \
                             'computer.action_allowed','browser_tab','{}'::jsonb, \
                             to_timestamp(2200000010),NULL,NULL)",
                    &[],
                )
                .await
                .map_err(|error| format!("制造链后 unlinked 行失败：{error}"))?;
            drop(client);
            let after_unlinked = audit
                .append(
                    &audit_event("018f47d2-2c00-7a00-8000-000000000005", 2_200_000_011),
                    key,
                )
                .await;
            if !matches!(
                after_unlinked,
                Err(InfraError::RepositoryInvariant {
                    code: "unlinked_audit_row_after_chain_start"
                })
            ) {
                return Err(format!("链后 unlinked 行未被发现：{after_unlinked:?}"));
            }

            let vault = CredentialRepo::new(pool.clone());
            let seeded = vault
                .list_all()
                .await
                .map_err(|error| format!("列 credential 失败：{error}"))?;
            let original = seeded
                .iter()
                .find(|row| row.revoked_at.is_none())
                .ok_or_else(|| "seed 没有 active credential".to_owned())?;
            if vault
                .rotate_if_current(
                    &original.id,
                    "wrong-key",
                    "cipher-v2",
                    "key-v2",
                    &json!({"version":2}),
                    OffsetDateTime::from_unix_timestamp(1_900_000_004).unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("错误 expected_key_id 不得覆盖密文".to_owned());
            }
            let rotated = vault
                .rotate_if_current(
                    &original.id,
                    &original.key_id,
                    "cipher-v2",
                    "key-v2",
                    &json!({"version":2}),
                    OffsetDateTime::from_unix_timestamp(1_900_000_004).unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "正确 CAS 轮换没成功".to_owned())?;
            if rotated.key_id != "key-v2" || rotated.encrypted_value != "cipher-v2" {
                return Err("轮换后的密文/key id 没读回".to_owned());
            }
            let revoked = vault
                .revoke(
                    &original.id,
                    OffsetDateTime::from_unix_timestamp(1_900_000_005).unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if revoked.is_none()
                || vault
                    .find_active_by_id(&original.id)
                    .await
                    .map_err(|error| error.to_string())?
                    .is_some()
            {
                return Err("撤销后仍能从 active 入口读到凭据".to_owned());
            }
            if vault
                .revoke(
                    &original.id,
                    OffsetDateTime::from_unix_timestamp(1_900_000_006).unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("二次撤销不应改写首次 revoked_at".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn generic_crud_is_typed_and_database_errors_do_not_echo_secret_values() {
    let admin = admin_config("generic_crud_is_typed_and_database_errors_do_not_echo_secret_values");
    with_temp_database(&admin, "repo_crud", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            provision(&pool, false).await?;
            let users = UserRepo::new(pool.clone());
            let sessions = SessionRepo::new(pool.clone());
            let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
            let user = tables::users::Row {
                id: "user-repo-1".to_owned(),
                email: "repo@example.invalid".to_owned(),
                name: Some("Repo".to_owned()),
                image: None,
                email_verified: true,
                groups: Vec::new(),
                created_at: now,
                updated_at: now,
            };
            users
                .insert(&user)
                .await
                .map_err(|error| format!("插 user 失败：{error}"))?;
            if users
                .find_by_id("user-repo-1")
                .await
                .map_err(|error| error.to_string())?
                != Some(user)
            {
                return Err("typed find 没读回同一 user".to_owned());
            }
            let session = tables::sessions::Row {
                id: "session-repo-1".to_owned(),
                user_id: "user-repo-1".to_owned(),
                token: "SENTINEL-SESSION-TOKEN-DO-NOT-LOG".to_owned(),
                expires_at: now + Duration::from_secs(3600),
                ip_address: None,
                user_agent: None,
                created_at: now,
                updated_at: now,
            };
            sessions
                .insert(&session)
                .await
                .map_err(|error| format!("插 session 失败：{error}"))?;
            let duplicate = sessions
                .insert(&session)
                .await
                .expect_err("重复 session 必须返回 unique/PK 错误");
            if duplicate.sqlstate() != Some("23505") {
                return Err(format!("重复 session SQLSTATE 不对：{duplicate:?}"));
            }
            let rendered = format!("{duplicate:?} {duplicate}");
            if rendered.contains("SENTINEL-SESSION-TOKEN") {
                return Err(format!("数据库错误泄漏了 session token：{rendered}"));
            }
            if !users
                .delete("user-repo-1")
                .await
                .map_err(|error| error.to_string())?
            {
                return Err("删除已存在 user 应返回 true".to_owned());
            }
            if sessions
                .find_by_id("session-repo-1")
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("user delete 后 session 没按 FK cascade".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

fn decision_rows(
    call_id: &str,
    decision_id: &str,
    attempt_id: &str,
    at: OffsetDateTime,
) -> FirstDurableDecision {
    FirstDurableDecision {
        call: tool_calls::Row {
            tool_call_id: call_id.to_owned(),
            run_id: "run-1".to_owned(),
            call_seq: 0,
            decision_id: decision_id.to_owned(),
            actor_id: "actor-1".to_owned(),
            bot_id: "bot-1".to_owned(),
            tool_name: "tool-1".to_owned(),
            schema_hash: "a".repeat(64),
            catalog_generation: 1,
            args_hash: "b".repeat(64),
            target_kind: "browser_tab".to_owned(),
            target_id: "tab-1".to_owned(),
            effect: "write".to_owned(),
            effect_downgraded: false,
            idempotency: "keyed".to_owned(),
            idempotency_key: Some("idem-1".to_owned()),
            approval_class: "every_call".to_owned(),
            policy_version: "pv-1".to_owned(),
            decided_at: at,
        },
        approval_id: None,
        attempt: pristine_attempt(call_id, 0, attempt_id, at),
    }
}

fn pristine_attempt(
    call_id: &str,
    sequence: i64,
    attempt_id: &str,
    at: OffsetDateTime,
) -> tool_attempts::Row {
    tool_attempts::Row {
        tool_call_id: call_id.to_owned(),
        attempt_seq: sequence,
        attempt_id: attempt_id.to_owned(),
        capability_id: None,
        status: "decision_recorded".to_owned(),
        commit_state: None,
        output_bytes: None,
        duration_ms: None,
        error_code: None,
        started_at: None,
        finished_at: None,
        created_at: at,
    }
}

fn audit_event(id: &str, unix_seconds: i64) -> AuditEvent {
    AuditEvent {
        id: AuditEventId::new(id),
        actor: Some(ActorId::new("actor-1")),
        event_type: AuditEventType::COMPUTER_ACTION_ALLOWED,
        target_kind: AuditLabel::new("browser_tab"),
        target_id: Some(AuditIdentifier::new("tab-1").unwrap()),
        payload: AuditPayload::empty(),
        created_at: OffsetDateTime::from_unix_timestamp(unix_seconds).unwrap(),
    }
}
