//! R415/R417 production skill writes on a newly owned PostgreSQL database.
//! Every writer uses PostgresMcpConnections; SQL only arranges or observes counterexamples.

mod harness;

use std::sync::Arc;
use std::time::Duration;

use openbot_application::{
    AgentContextSource, BeginThreadRunRequest, McpConnectionAdministration,
    McpConnectionError as Error, ProviderMessageRole, RunExecutionLease, ThreadDirectory,
    ThreadDirectoryError,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRun, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, DeploymentId, RunId, TenantId},
    mcp::{McpAdminSkill, PluginGrantKind, PluginGrantMutation, PluginSkillMutation, PluginSkills},
};
use openbot_domain::{
    thread::FencingToken,
    vault::{KeyVersion, WrappingKey},
};
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::{
    db::{fresh, pool},
    mcp::SafeRmcpClient,
    mcp_catalog::PostgresMcpCatalog,
    mcp_connections::PostgresMcpConnections,
    mcp_oauth::McpOAuthClient,
    net::safe_http::{EgressPolicy, SafeDialer, SchemePolicy},
    provider::context::PostgresAgentContextSource,
    thread_directory::PostgresThreadDirectory,
    vault::CredentialRecordVault,
};
use serde_json::Value;

const DEPLOYMENT: &str = "skill-cas-deployment";
const TENANT: &str = "skill-cas-tenant";
const ADMIN: &str = "skill-cas-admin";
const OWNER: &str = "skill-cas-owner";
const OTHER: &str = "skill-cas-other";
const BOT: &str = "skill-cas-bot";
const LOCK_SEED: i64 = 0x504c_5547_494e_4131;
const AUDIT_GATE: i64 = 0x534b_494c_4c54_4553;
const AUDIT_KEY: &[u8] = b"owned-skill-cas-audit-key-at-least-32-bytes";

fn auth(actor: &str, role: Role, generation: u64) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        ActorId::new(actor),
        AuthGeneration::new(generation),
        false,
    )
    .with_roles([role])
    .build()
}

fn mutation(slug: &str, expected_revision: Option<i64>, title: &str) -> PluginSkillMutation {
    PluginSkillMutation {
        expected_revision,
        slug: slug.to_owned(),
        title: title.to_owned(),
        summary: "Synthetic bounded summary".to_owned(),
        instructions: format!("{title}: instruction mentions remember, but grants no tool."),
        deployment_wide: false,
    }
}

fn grant(slug: &str) -> PluginGrantMutation {
    PluginGrantMutation {
        kind: PluginGrantKind::Skill,
        reference: slug.to_owned(),
        agent_id: BOT.to_owned(),
    }
}

fn selected(page: PluginSkills, slug: &str) -> McpAdminSkill {
    page.skills
        .into_iter()
        .find(|skill| skill.slug == slug)
        .expect("successful production response contains the edited visible skill")
}

async fn current(port: &PostgresMcpConnections, actor: &AuthContext, slug: &str) -> McpAdminSkill {
    port.list_admin_page(actor)
        .await
        .unwrap()
        .skills
        .into_iter()
        .find(|skill| skill.slug == slug)
        .unwrap()
}

async fn setup(p: &Pool) -> PostgresMcpConnections {
    let mut c = p.get().await.unwrap();
    fresh::apply(&mut c).await.unwrap();
    c.batch_execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES
           ('skill-cas-admin','admin@skill-cas.test',0),
           ('skill-cas-owner','owner@skill-cas.test',0),
           ('skill-cas-other','other@skill-cas.test',0);
         INSERT INTO public.user_roles(user_id,role) VALUES
           ('skill-cas-admin','admin'),('skill-cas-owner','user'),('skill-cas-other','user');
         INSERT INTO public.agents(id,name,type,configuration) VALUES
           ('skill-cas-bot','Owned fixture bot','built_in',
            '{\"systemPrompt\":\"Standing instruction.\",\"providerSource\":\"package\"}');
         INSERT INTO public.agent_profiles(
           agent_id,owner_user_id,title,role_description,avatar_seed,visibility
         ) VALUES('skill-cas-bot','skill-cas-owner','Owned fixture bot','','seed','private');",
    )
    .await
    .unwrap();
    drop(c);
    let dialer = SafeDialer::new(EgressPolicy::default());
    let catalog = Arc::new(
        PostgresMcpCatalog::new(
            p.clone(),
            SafeRmcpClient::new(
                dialer.clone(),
                SchemePolicy::HttpsOnly,
                Some(Duration::from_secs(1)),
            ),
            AUDIT_KEY.to_vec(),
        )
        .unwrap(),
    );
    PostgresMcpConnections::new(
        p.clone(),
        CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x62; 32]).unwrap(),
        ),
        McpOAuthClient::new(dialer, SchemePolicy::HttpsOnly),
        catalog,
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        vec![0x63; 32],
        AUDIT_KEY.to_vec(),
        None,
        None,
        SchemePolicy::HttpsOnly,
    )
    .unwrap()
}

async fn durable(p: &Pool) -> Value {
    let c = p.get().await.unwrap();
    c.query_one(
        "SELECT jsonb_build_object(
          'skills',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY slug),'[]') FROM public.skills s),
          'grants',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY kind,ref,agent_id),'[]') FROM public.plugin_grants g),
          'retired',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY slug),'[]') FROM public.skill_retired_slugs r),
          'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a))",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

async fn pool_pids(p: &Pool) -> Vec<i32> {
    let first = p.get().await.unwrap();
    let second = p.get().await.unwrap();
    let mut pids = Vec::new();
    for c in [&first, &second] {
        c.batch_execute("SET default_transaction_isolation='repeatable read'")
            .await
            .unwrap();
        assert_eq!(
            c.query_one("SHOW default_transaction_isolation", &[])
                .await
                .unwrap()
                .get::<_, String>(0),
            "repeatable read"
        );
        pids.push(
            c.query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0),
        );
    }
    pids
}

async fn wait_blocked<C: tokio_postgres::GenericClient + Sync>(c: &C, pids: &[i32]) {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            c.batch_execute("SELECT pg_stat_clear_snapshot()")
                .await
                .unwrap();
            let waiting: i64 = c
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1)
                  AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0",
                    &[&pids],
                )
                .await
                .unwrap()
                .get(0);
            if waiting == pids.len() as i64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("actual production writers must reach the independently owned lock barrier");
}

async fn wait_first<C: tokio_postgres::GenericClient + Sync>(c: &C, pids: &[i32]) -> i32 {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            c.batch_execute("SELECT pg_stat_clear_snapshot()")
                .await
                .unwrap();
            if let Some(row) = c
                .query_opt(
                    "SELECT pid FROM pg_stat_activity WHERE pid=ANY($1)
                  AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0",
                    &[&pids],
                )
                .await
                .unwrap()
            {
                break row.get(0);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first production request must be observed waiting before the second starts")
}

fn assert_retired(error: Error) {
    assert_eq!(
        error,
        Error::NotVisible,
        "retired and missing identities have no active snapshot"
    );
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn stale_mutations_return_current_closed_configuration_without_any_durable_effect() {
    harness::with_temp_database(&harness::admin_config("skillcasstale"), "skillcasstale", |config| async move {
        let p = pool::connect(&config).await.unwrap();
        let port = setup(&p).await;
        let actor = auth(OWNER, Role::User, 0);
        let slug = "stale-skill";
        let first = selected(port.save_skill(&actor, &mutation(slug, None, "first")).await.unwrap(), slug);
        assert_eq!(first.revision, 1);
        port.set_grant(&actor, &grant(slug), true).await.unwrap();
        let second = selected(port.save_skill(&actor, &mutation(slug, Some(1), "second")).await.unwrap(), slug);
        assert_eq!(second.revision, 2);
        assert_eq!(second.owner_user_id.as_deref(), Some(OWNER));
        assert_eq!(second.granted_to, [BOT]);
        let equal_content = selected(port.save_skill(&actor, &mutation(slug, Some(2), "second")).await.unwrap(), slug);
        assert_eq!((equal_content.title.as_str(), equal_content.instructions.as_str()), (second.title.as_str(), second.instructions.as_str()));
        assert_eq!(equal_content.revision, 3, "even an equal-content accepted write consumes its revision");
        let expected = Error::StaleSnapshot(equal_content.revision_snapshot().unwrap());
        let before = durable(&p).await;
        for version in [Some(1), Some(2), None] {
            assert_eq!(port.save_skill(&actor, &mutation(slug, version, "overwrite")).await.unwrap_err(), expected);
        }
        assert_eq!(port.remove_skill(&actor, slug, 1).await.unwrap_err(), expected);
        assert_eq!(port.save_skill(&actor, &mutation("missing-skill", Some(1), "missing")).await.unwrap_err(), Error::NotVisible);
        assert_eq!(durable(&p).await, before);
        let body = serde_json::to_value(equal_content.revision_snapshot().unwrap()).unwrap();
        assert_eq!(body.as_object().unwrap().len(), 3);
        assert_eq!(body["currentRevision"], 3);
        assert_eq!(body["currentSha256"].as_str().unwrap().len(), 64);
        assert!(time::OffsetDateTime::parse(body["updatedAt"].as_str().unwrap(), &time::format_description::well_known::Rfc3339).is_ok());
        assert!(!body.to_string().contains("instruction"));
        let c = p.get().await.unwrap();
        let revisions: Vec<i64> = c.query("SELECT (payload->>'skill_revision')::bigint FROM public.audit_events WHERE target_id=$1 AND payload ? 'skill_revision' ORDER BY (payload->>'skill_revision')::bigint", &[&slug]).await.unwrap().iter().map(|r| r.get(0)).collect();
        assert_eq!(revisions, [1, 2, 3]);
        drop(c); p.close(); Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn two_old_version_writers_wait_on_real_advisory_lock_then_commit_one_current_winner() {
    harness::with_temp_database(
        &harness::admin_config("skillcaswriters"),
        "skillcaswriters",
        |config| async move {
            let config = config.with_max_pool_size(2);
            let p = pool::connect(&config).await.unwrap();
            let port = Arc::new(setup(&p).await);
            let slug = "writer-skill";
            port.save_skill(
                &auth(OWNER, Role::User, 0),
                &mutation(slug, None, "initial"),
            )
            .await
            .unwrap();
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config
                .to_pg_config()
                .connect(tokio_postgres::NoTls)
                .await
                .unwrap();
            let connection_task = tokio::spawn(connection);
            let tx = barrier.transaction().await.unwrap();
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,$2))",
                &[&slug, &LOCK_SEED],
            )
            .await
            .unwrap();
            let left = port.clone();
            let a = tokio::spawn(async move {
                left.save_skill(
                    &auth(OWNER, Role::User, 0),
                    &mutation(slug, Some(1), "left"),
                )
                .await
            });
            let right = port.clone();
            let b = tokio::spawn(async move {
                right
                    .save_skill(
                        &auth(OWNER, Role::User, 0),
                        &mutation(slug, Some(1), "right"),
                    )
                    .await
            });
            wait_blocked(&tx, &pids).await;
            tx.commit().await.unwrap();
            let (won, lost) = match (a.await.unwrap(), b.await.unwrap()) {
                (Ok(a), Err(b)) | (Err(b), Ok(a)) => (selected(a, slug), b),
                other => panic!("expected one CAS winner after real waiting: {other:?}"),
            };
            assert_eq!(won.revision, 2);
            assert_eq!(lost, Error::StaleSnapshot(won.revision_snapshot().unwrap()));
            assert_eq!(current(&port, &auth(OWNER, Role::User, 0), slug).await, won);
            let c = p.get().await.unwrap();
            assert_eq!(
                c.query_one(
                    "SELECT count(*) FROM public.audit_events WHERE target_id=$1",
                    &[&slug]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
                2
            );
            drop(c);
            drop(barrier);
            connection_task.await.unwrap().unwrap();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn two_creators_wait_on_current_actor_and_never_overwrite_the_initial_skill() {
    harness::with_temp_database(
        &harness::admin_config("skillcascreators"),
        "skillcascreators",
        |config| async move {
            let config = config.with_max_pool_size(2);
            let p = pool::connect(&config).await.unwrap();
            let port = Arc::new(setup(&p).await);
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config
                .to_pg_config()
                .connect(tokio_postgres::NoTls)
                .await
                .unwrap();
            let connection_task = tokio::spawn(connection);
            let tx = barrier.transaction().await.unwrap();
            tx.query_one(
                "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
                &[&OWNER],
            )
            .await
            .unwrap();
            let slug = "creator-skill";
            let left = port.clone();
            let a = tokio::spawn(async move {
                left.save_skill(&auth(OWNER, Role::User, 0), &mutation(slug, None, "left"))
                    .await
            });
            let right = port.clone();
            let b = tokio::spawn(async move {
                right
                    .save_skill(&auth(OWNER, Role::User, 0), &mutation(slug, None, "right"))
                    .await
            });
            wait_blocked(&tx, &pids).await;
            tx.commit().await.unwrap();
            let (won, lost) = match (a.await.unwrap(), b.await.unwrap()) {
                (Ok(a), Err(b)) | (Err(b), Ok(a)) => (selected(a, slug), b),
                other => panic!("expected one initial creator: {other:?}"),
            };
            assert_eq!(won.revision, 1);
            assert_eq!(lost, Error::StaleSnapshot(won.revision_snapshot().unwrap()));
            assert_eq!(current(&port, &auth(OWNER, Role::User, 0), slug).await, won);
            let c = p.get().await.unwrap();
            assert_eq!(
                c.query_one(
                    "SELECT count(*) FROM public.audit_events WHERE target_id=$1",
                    &[&slug]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
                1
            );
            drop(c);
            drop(barrier);
            connection_task.await.unwrap().unwrap();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn current_scope_owner_role_generation_and_deny_precede_stale_metadata() {
    harness::with_temp_database(&harness::admin_config("skillcasauthority"), "skillcasauthority", |config| async move {
        let config = config.with_max_pool_size(2);
        let p = pool::connect(&config).await.unwrap();
        let port = Arc::new(setup(&p).await);
        let actor = auth(OWNER, Role::User, 0);
        let slug = "authority-skill";
        port.save_skill(&actor, &mutation(slug, None, "first")).await.unwrap();
        port.save_skill(&actor, &mutation(slug, Some(1), "second")).await.unwrap();
        let before = durable(&p).await;
        for version in [None, Some(1)] {
            assert_eq!(port.save_skill(&auth(OTHER, Role::User, 0), &mutation(slug, version, "foreign")).await.unwrap_err(), Error::NotVisible);
        }
        assert_eq!(port.remove_skill(&auth(OTHER, Role::User, 0), slug, 1).await.unwrap_err(), Error::NotVisible);
        let mut global = mutation(slug, Some(1), "pretend deployment");
        global.deployment_wide = true;
        assert_eq!(port.save_skill(&actor, &global).await.unwrap_err(), Error::NotVisible);
        let foreign_scope = AuthContextBuilder::from_verified_session(DeploymentId::new("other-deployment"), TenantId::new(TENANT), ActorId::new(OWNER), AuthGeneration::new(0), false).with_roles([Role::User]).build();
        assert_eq!(port.save_skill(&foreign_scope, &mutation(slug, Some(1), "cross scope")).await.unwrap_err(), Error::NotVisible);
        assert_eq!(durable(&p).await, before);
        for change in [
            "UPDATE public.users SET auth_generation=1 WHERE id='skill-cas-owner'",
            "DELETE FROM public.user_roles WHERE user_id='skill-cas-owner'",
            "INSERT INTO public.revoked_access(email,revoked_by) VALUES('owner@skill-cas.test','skill-cas-admin')",
        ] {
            let before = durable(&p).await;
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
            let connection_task = tokio::spawn(connection);
            let tx = barrier.transaction().await.unwrap();
            tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE", &[&OWNER]).await.unwrap();
            tx.batch_execute(change).await.unwrap();
            let writer = port.clone();
            let pending = tokio::spawn(async move { writer.save_skill(&auth(OWNER, Role::User, 0), &mutation(slug, Some(1), "unauthorized")).await });
            let first_pid = wait_first(&tx, &pids).await;
            assert!(pids.contains(&first_pid));
            tx.commit().await.unwrap();
            assert_eq!(pending.await.unwrap().unwrap_err(), Error::NotVisible);
            assert_eq!(port.remove_skill(&actor, slug, 1).await.unwrap_err(), Error::NotVisible);
            assert_eq!(durable(&p).await, before);
            let c = p.get().await.unwrap(); c.batch_execute("UPDATE public.users SET auth_generation=0 WHERE id='skill-cas-owner'; INSERT INTO public.user_roles(user_id,role) VALUES('skill-cas-owner','user') ON CONFLICT DO NOTHING; DELETE FROM public.revoked_access WHERE email='owner@skill-cas.test'").await.unwrap(); drop(c);
            drop(barrier); connection_task.await.unwrap().unwrap();
        }
        let c = p.get().await.unwrap(); c.batch_execute("DELETE FROM public.user_roles WHERE user_id='skill-cas-admin'; INSERT INTO public.user_roles(user_id,role) VALUES('skill-cas-admin','user')").await.unwrap(); drop(c);
        let before = durable(&p).await;
        assert_eq!(port.save_skill(&auth(ADMIN, Role::Admin, 0), &mutation(slug, Some(1), "revoked admin")).await.unwrap_err(), Error::NotVisible);
        assert_eq!(port.remove_skill(&auth(ADMIN, Role::Admin, 0), slug, 1).await.unwrap_err(), Error::NotVisible);
        assert_eq!(durable(&p).await, before);
        p.close(); Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn audit_failure_rolls_back_skill_grants_retirement_and_audit_for_save_and_delete() {
    harness::with_temp_database(&harness::admin_config("skillcasrollback"), "skillcasrollback", |config| async move {
        let p = pool::connect(&config).await.unwrap();
        let port = setup(&p).await;
        let actor = auth(OWNER, Role::User, 0);
        let slug = "rollback-skill";
        port.save_skill(&actor, &mutation(slug, None, "first")).await.unwrap();
        port.set_grant(&actor, &grant(slug), true).await.unwrap();
        let c = p.get().await.unwrap();
        c.batch_execute("CREATE FUNCTION skill_cas_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned synthetic audit failure'; END $$; CREATE TRIGGER skill_cas_audit_fault BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION skill_cas_audit_fault()").await.unwrap();
        drop(c);
        let before = durable(&p).await;
        assert_eq!(port.save_skill(&actor, &mutation(slug, Some(1), "failed update")).await.unwrap_err(), Error::Unavailable);
        assert_eq!(durable(&p).await, before);
        assert_eq!(port.save_skill(&actor, &mutation("failed-create", None, "failed initial")).await.unwrap_err(), Error::Unavailable);
        assert_eq!(durable(&p).await, before);
        assert_eq!(port.remove_skill(&actor, slug, 1).await.unwrap_err(), Error::Unavailable);
        assert_eq!(durable(&p).await, before);
        let c = p.get().await.unwrap(); c.batch_execute("DROP TRIGGER skill_cas_audit_fault ON public.audit_events; DROP FUNCTION skill_cas_audit_fault()").await.unwrap(); drop(c);
        port.remove_skill(&actor, slug, 1).await.unwrap();
        let c = p.get().await.unwrap();
        assert_eq!(c.query_one("SELECT count(*) FROM public.plugin_grants WHERE kind='skill' AND ref=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 0);
        assert_eq!(c.query_one("SELECT retired_revision FROM public.skill_retired_slugs WHERE slug=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 2);
        let revisions: Vec<i64> = c.query("SELECT (payload->>'skill_revision')::bigint FROM public.audit_events WHERE target_id=$1 AND payload ? 'skill_revision' ORDER BY (payload->>'skill_revision')::bigint", &[&slug]).await.unwrap().iter().map(|r| r.get(0)).collect();
        assert_eq!(revisions, [1, 2]);
        drop(c); p.close(); Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn delete_create_wait_chains_in_both_orders_and_owner_cascade_cannot_reuse_identity() {
    harness::with_temp_database(&harness::admin_config("skillcasretirement"), "skillcasretirement", |config| async move {
        let config = config.with_max_pool_size(2);
        let p = pool::connect(&config).await.unwrap();
        let port = Arc::new(setup(&p).await);
        let actor = auth(OWNER, Role::User, 0);
        for delete_first in [false, true] {
            let slug = if delete_first { "delete-first-skill" } else { "create-first-skill" };
            let original = selected(port.save_skill(&actor, &mutation(slug, None, "original")).await.unwrap(), slug);
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
            let connection_task = tokio::spawn(connection);
            let tx = barrier.transaction().await.unwrap();
            tx.query_one("SELECT pg_advisory_xact_lock(hashtextextended($1,$2))", &[&slug, &LOCK_SEED]).await.unwrap();
            let first_port = port.clone();
            let first = tokio::spawn(async move {
                if delete_first { first_port.remove_skill(&auth(OWNER, Role::User, 0), slug, 1).await.map(|_| None) }
                else { first_port.save_skill(&auth(OWNER, Role::User, 0), &mutation(slug, None, "duplicate")).await.map(Some) }
            });
            let first_pid = wait_first(&tx, &pids).await;
            let second_port = port.clone();
            let second = tokio::spawn(async move {
                if delete_first { second_port.save_skill(&auth(OWNER, Role::User, 0), &mutation(slug, None, "duplicate")).await.map(Some) }
                else { second_port.remove_skill(&auth(OWNER, Role::User, 0), slug, 1).await.map(|_| None) }
            });
            wait_blocked(&tx, &pids).await;
            assert!(pids.contains(&first_pid));
            tx.commit().await.unwrap();
            let a = first.await.unwrap(); let b = second.await.unwrap();
            if delete_first { assert_eq!(a.unwrap(), None); assert_retired(b.unwrap_err()); }
            else { assert_eq!(a.unwrap_err(), Error::StaleSnapshot(original.revision_snapshot().unwrap())); assert_eq!(b.unwrap(), None); }
            let c = p.get().await.unwrap();
            assert_eq!(c.query_one("SELECT count(*) FROM public.skills WHERE slug=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 0);
            assert_eq!(c.query_one("SELECT retired_revision FROM public.skill_retired_slugs WHERE slug=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 2);
            assert_eq!(c.query_one("SELECT count(*) FROM public.audit_events WHERE target_id=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 2);
            drop(c);
            let before = durable(&p).await;
            assert_retired(port.save_skill(&actor, &mutation(slug, None, "recreate")).await.unwrap_err());
            assert_retired(port.save_skill(&actor, &mutation(slug, Some(1), "old update")).await.unwrap_err());
            assert_retired(port.remove_skill(&actor, slug, 1).await.unwrap_err());
            assert_eq!(durable(&p).await, before);
            drop(barrier); connection_task.await.unwrap().unwrap();
        }
        let admin = auth(ADMIN, Role::Admin, 0);

        // Cascade reaches the source first; admin creation waits on its deleted tuple.
        // A retirement read made before that wait would miss the committed tombstone.
        let slug = "cascade-first-skill";
        port.save_skill(&auth(OTHER, Role::User, 0), &mutation(slug, None, "other owner lifetime")).await.unwrap();
        let before = durable(&p).await;
        let pids = pool_pids(&p).await;
        let (mut barrier, connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
        let connection_task = tokio::spawn(connection);
        let tx = barrier.build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start().await.unwrap();
        assert_eq!(tx.query_one("SHOW transaction_isolation", &[]).await.unwrap().get::<_, String>(0), "read committed");
        tx.execute("DELETE FROM public.users WHERE id=$1", &[&OTHER]).await.unwrap();
        let creator = port.clone();
        let pending = tokio::spawn(async move { creator.save_skill(&auth(ADMIN, Role::Admin, 0), &mutation(slug, None, "old slug reuse")).await });
        let first_pid = wait_first(&tx, &pids).await;
        assert!(pids.contains(&first_pid));
        tx.commit().await.unwrap();
        assert_retired(pending.await.unwrap().unwrap_err());
        let after = durable(&p).await;
        assert_eq!(after["grants"], before["grants"]);
        assert_eq!(after["audit"], before["audit"]);
        let c = p.get().await.unwrap();
        assert_eq!(c.query_one("SELECT count(*) FROM public.skills WHERE slug=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 0);
        assert_eq!(c.query_one("SELECT retired_revision FROM public.skill_retired_slugs WHERE slug=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 2);
        drop(c); drop(barrier); connection_task.await.unwrap().unwrap();

        // A valid admin CAS update holds the source first. A synthetic audit gate lets us
        // observe the FK cascade waiting behind that real production write before either commits.
        let slug = "admin-first-cascade";
        port.save_skill(&actor, &mutation(slug, None, "owner lifetime")).await.unwrap();
        let c = p.get().await.unwrap();
        c.batch_execute(&format!("CREATE FUNCTION skill_cas_audit_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({AUDIT_GATE}); RETURN NEW; END $$; CREATE TRIGGER skill_cas_audit_gate BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION skill_cas_audit_gate()")).await.unwrap();
        drop(c);
        let pids = pool_pids(&p).await;
        let (mut barrier, connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
        let connection_task = tokio::spawn(connection);
        let tx = barrier.transaction().await.unwrap();
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_GATE]).await.unwrap();
        let updater = port.clone();
        let update = tokio::spawn(async move { updater.save_skill(&auth(ADMIN, Role::Admin, 0), &mutation(slug, Some(1), "admin update before cascade")).await });
        let first_pid = wait_first(&tx, &pids).await;
        assert!(pids.contains(&first_pid));
        // This is an owned SQL fixture controller, not a delivered user-deletion API.
        // Keep production skill pool defaults at RR; choose RC explicitly for the FK
        // controller so its source-lock wait observes the committed CAS revision.
        let (mut cascade_client, cascade_connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
        let cascade_connection_task = tokio::spawn(cascade_connection);
        let cascading_pid: i32 = cascade_client.query_one("SELECT pg_backend_pid()", &[]).await.unwrap().get(0);
        assert!(!pids.contains(&cascading_pid));
        let cascade = tokio::spawn(async move {
            let cascade_tx = cascade_client.build_transaction()
                .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
                .start().await.unwrap();
            assert_eq!(cascade_tx.query_one("SHOW transaction_isolation", &[]).await.unwrap().get::<_, String>(0), "read committed");
            let removed = cascade_tx.execute("DELETE FROM public.users WHERE id=$1", &[&OWNER]).await.unwrap();
            cascade_tx.commit().await.unwrap();
            removed
        });
        wait_blocked(&tx, &[first_pid, cascading_pid]).await;
        let blockers: Vec<i32> = tx.query_one("SELECT pg_blocking_pids($1)", &[&cascading_pid]).await.unwrap().get(0);
        assert!(blockers.contains(&first_pid), "owner cascade must demonstrably wait behind the production CAS source lock");
        tx.commit().await.unwrap();
        assert_eq!(selected(update.await.unwrap().unwrap(), slug).revision, 2);
        assert_eq!(cascade.await.unwrap(), 1);
        cascade_connection_task.await.unwrap().unwrap();
        let c = p.get().await.unwrap();
        c.batch_execute("DROP TRIGGER skill_cas_audit_gate ON public.audit_events; DROP FUNCTION skill_cas_audit_gate()").await.unwrap();
        assert_eq!(c.query_one("SELECT count(*) FROM public.skills WHERE slug=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 0);
        assert_eq!(c.query_one("SELECT retired_revision FROM public.skill_retired_slugs WHERE slug=$1", &[&slug]).await.unwrap().get::<_, i64>(0), 3);
        drop(c); drop(barrier); connection_task.await.unwrap().unwrap();
        let before = durable(&p).await;
        assert_retired(port.save_skill(&admin, &mutation(slug, None, "resurrected owner")).await.unwrap_err());
        assert_eq!(durable(&p).await, before);
        let fresh = selected(port.save_skill(&admin, &mutation("fresh-independent", None, "new identity")).await.unwrap(), "fresh-independent");
        assert_eq!(fresh.revision, 1);
        p.close(); Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn nullable_legacy_revision_and_grant_changes_preserve_separate_configuration_identity() {
    harness::with_temp_database(
        &harness::admin_config("skillcasnullgrant"),
        "skillcasnullgrant",
        |config| async move {
            let p = pool::connect(&config).await.unwrap();
            let port = setup(&p).await;
            let actor = auth(OWNER, Role::User, 0);
            let slug = "legacy-skill";
            port.save_skill(&actor, &mutation(slug, None, "legacy"))
                .await
                .unwrap();
            let c = p.get().await.unwrap();
            c.execute(
                "UPDATE public.skills SET revision=NULL WHERE slug=$1",
                &[&slug],
            )
            .await
            .unwrap();
            drop(c);
            let old = current(&port, &actor, slug).await;
            assert_eq!(old.revision, 1);
            assert!(old.granted_to.is_empty());
            port.set_grant(&actor, &grant(slug), true).await.unwrap();
            let enabled = current(&port, &actor, slug).await;
            assert_eq!(enabled.granted_to, [BOT]);
            assert_eq!(
                old.revision_snapshot().unwrap(),
                enabled.revision_snapshot().unwrap()
            );
            assert_eq!(
                (old.revision, old.updated_at),
                (enabled.revision, enabled.updated_at)
            );
            let offered = port.list_for_agent(&actor, &BotId::new(BOT)).await.unwrap();
            assert_eq!(offered.skills.len(), 1);
            assert_eq!(offered.skills[0].slug, slug);
            assert!(
                offered.tools.is_empty(),
                "skill instruction does not create any tool grant"
            );
            port.set_grant(&actor, &grant(slug), false).await.unwrap();
            let disabled = current(&port, &actor, slug).await;
            assert!(disabled.granted_to.is_empty());
            assert_eq!(
                disabled.revision_snapshot().unwrap(),
                old.revision_snapshot().unwrap()
            );
            assert!(
                port.list_for_agent(&actor, &BotId::new(BOT))
                    .await
                    .unwrap()
                    .skills
                    .is_empty()
            );
            let next = selected(
                port.save_skill(&actor, &mutation(slug, Some(1), "current"))
                    .await
                    .unwrap(),
                slug,
            );
            assert_eq!(next.revision, 2);
            assert_ne!(
                next.revision_snapshot().unwrap(),
                old.revision_snapshot().unwrap()
            );
            let c = p.get().await.unwrap();
            assert_eq!(
                c.query_one("SELECT revision FROM public.skills WHERE slug=$1", &[&slug])
                    .await
                    .unwrap()
                    .get::<_, Option<i64>>(0),
                Some(2)
            );
            drop(c);
            let c = p.get().await.unwrap();
            c.execute(
                "UPDATE public.skills SET revision=$2 WHERE slug=$1",
                &[&slug, &i64::MAX],
            )
            .await
            .unwrap();
            drop(c);
            let before = durable(&p).await;
            assert_eq!(
                port.save_skill(&actor, &mutation(slug, Some(i64::MAX), "overflow"))
                    .await
                    .unwrap_err(),
                Error::Corrupt {
                    field: "skill_revision"
                }
            );
            assert_eq!(
                port.remove_skill(&actor, slug, i64::MAX).await.unwrap_err(),
                Error::Corrupt {
                    field: "skill_revision"
                }
            );
            assert_eq!(durable(&p).await, before);
            let c = p.get().await.unwrap();
            let overflow = c
                .execute("DELETE FROM public.users WHERE id=$1", &[&OWNER])
                .await
                .unwrap_err();
            assert_eq!(
                overflow.code(),
                Some(&tokio_postgres::error::SqlState::NUMERIC_VALUE_OUT_OF_RANGE)
            );
            assert_eq!(
                c.query_one("SELECT count(*) FROM public.users WHERE id=$1", &[&OWNER])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                1
            );
            drop(c);
            assert_eq!(
                durable(&p).await,
                before,
                "cascade retirement overflow must roll back the entire deletion"
            );
            p.close();
            Ok(())
        },
    )
    .await;
}

fn begin(slug: &str, entropy: u64, run: &str) -> BeginThreadRunRequest {
    let deployment = DeploymentId::new(DEPLOYMENT);
    let mut bytes = [0_u8; 16];
    bytes[8..].copy_from_slice(&entropy.to_be_bytes());
    BeginThreadRunRequest {
        auth_generation: AuthGeneration::new(0),
        deployment: deployment.clone(),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(OWNER),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            model_selection: None,
            selected_skill_slugs: vec![slug.to_owned()],
            thread_id: ThreadIdentity::new(&deployment).mint_from_entropy(bytes),
            run_id: RunId::new(run),
            bot_id: BotId::new(BOT),
            anchor: ThreadRunAnchor::DirectBot,
            message: "Keep my literal words.".to_owned(),
        },
    }
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn accepted_instruction_snapshot_survives_cas_edit_and_revocation_without_new_capability() {
    harness::with_temp_database(&harness::admin_config("skillcasrun"), "skillcasrun", |config| async move {
        let p = pool::connect(&config).await.unwrap();
        let port = setup(&p).await;
        let actor = auth(OWNER, Role::User, 0);
        let slug = "selected-skill";
        let original = selected(port.save_skill(&actor, &mutation(slug, None, "accepted instruction")).await.unwrap(), slug);
        port.set_grant(&actor, &grant(slug), true).await.unwrap();
        let directory = PostgresThreadDirectory::with_runtime(p.clone(), config.clone(), "skill-cas-runtime".to_owned(), time::Duration::seconds(30)).unwrap();
        let request = begin(slug, 1, "skill-cas-run");
        let first = directory.begin_thread_run(request.clone()).await.unwrap();
        port.save_skill(&actor, &mutation(slug, Some(1), "later instruction")).await.unwrap();
        port.set_grant(&actor, &grant(slug), false).await.unwrap();
        assert!(port.list_for_agent(&actor, &BotId::new(BOT)).await.unwrap().skills.is_empty());
        let c = p.get().await.unwrap();
        let accepted: Value = c.query_one("SELECT jsonb_build_object('messages',(SELECT jsonb_agg(to_jsonb(m) ORDER BY thread_id,seq) FROM public.messages m),'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM public.runs r),'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY outbox_id) FROM public.outbox o))", &[]).await.unwrap().get(0);
        drop(c);
        let replay = directory.begin_thread_run(request.clone()).await.unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.message_sequence, first.message_sequence);
        assert_eq!(directory.begin_thread_run(begin(slug, 2, "skill-cas-revoked-run")).await.unwrap_err(), ThreadDirectoryError::NotVisible);
        let c = p.get().await.unwrap();
        let after: Value = c.query_one("SELECT jsonb_build_object('messages',(SELECT jsonb_agg(to_jsonb(m) ORDER BY thread_id,seq) FROM public.messages m),'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM public.runs r),'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY outbox_id) FROM public.outbox o))", &[]).await.unwrap().get(0);
        assert_eq!(after, accepted);
        drop(c);
        let context = PostgresAgentContextSource::new(p.clone(), DeploymentId::new(DEPLOYMENT), TenantId::new(TENANT), Some(256)).unwrap();
        let lease = RunExecutionLease::new(request.command.run_id.clone(), request.command.thread_id.clone(), request.command.bot_id.clone(), request.actor.clone(), FencingToken::new(1).unwrap(), 0).unwrap();
        let loaded = context.load(&lease).await.unwrap();
        assert!(loaded.tools.is_empty(), "mentioning remember in a skill must mint zero tools");
        assert!(loaded.messages.iter().any(|m| m.role == ProviderMessageRole::System && m.content == original.instructions));
        assert!(!loaded.messages.iter().any(|m| m.content.contains("later instruction")));
        assert!(loaded.messages.iter().any(|m| m.role == ProviderMessageRole::User && m.content == request.command.message));
        let c = p.get().await.unwrap(); c.execute("UPDATE public.users SET auth_generation=1 WHERE id=$1", &[&OWNER]).await.unwrap(); drop(c);
        assert_eq!(directory.begin_thread_run(request).await.unwrap_err(), ThreadDirectoryError::NotVisible);
        p.close(); Ok(())
    }).await;
}
