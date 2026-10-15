//! R423 current source/workspace observations in caller-owned disposable PostgreSQL databases.
//! These tests exercise lower-level NotVisible errors, not an HTTP route or artifact byte access.
//! Materialized identity/membership rows and AuthContext snapshots are explicit local fixtures;
//! they do not certify a live SSO login, permanent authority, artifact registration or readiness.

#![cfg(feature = "server-runtime")]

mod harness;

use std::future::Future;

use harness::{admin_config, with_temp_database};
use openbot_application::{BeginThreadRunRequest, RunRuntime, RunTerminal, ThreadDirectory};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::artifact::ArtifactWorkspaceKind;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_source::{ArtifactSourceError, VerifiedArtifactSource};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use serde_json::Value;
use time::OffsetDateTime;

const DEPLOYMENT: &str = "artifact-source-deployment";
const TENANT: &str = "artifact-source-tenant";
const OWNER: &str = "actor-a";
const OTHER: &str = "actor-b";
const RUNTIME_OWNER: &str = "artifact-source-fixture-owner";
const PRIVATE_MARKER: &str = "PRIVATE_SOURCE_SENTINEL_003";

struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    registry: ArtifactDatasetRegistry,
    directory: PostgresThreadDirectory,
    begin: BeginThreadRunRequest,
    channel: ChannelId,
}

impl Fixture {
    async fn new(config: pool::DatabaseConfig, channel: bool) -> Result<Self, String> {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
        }
        // This is startup adoption after actual baseline/native application, before ordinary source
        // requests. Registry-only migration/adoption behavior has its own independent test file.
        let registry = ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
            .await
            .map_err(|error| error.to_string())?;
        let direct_thread = ThreadIdentity::new(&deployment).mint_from_entropy([3; 16]);
        let channel_id = ChannelId::new(direct_thread.as_str());
        {
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation,groups) VALUES
                   ('actor-a','Owner@Example.Test',0,ARRAY['fixture-risk']),
                   ('actor-b','other@example.test',0,ARRAY['fixture-risk']);
                 INSERT INTO public.user_roles(user_id,role) VALUES
                   ('actor-a','user'),('actor-b','admin');
                 INSERT INTO public.agents(id,name,type,configuration) VALUES
                   ('bot-a','Source fixture','built_in','{}'),
                   ('bot-b','Other fixture','built_in','{}');
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                 ) VALUES
                   ('bot-a','actor-a','Fixture','fixture','fixture','public'),
                   ('bot-b','actor-b','Other fixture','fixture','other','public');
                 INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES
                   ('00000000-0000-4000-8000-000000000041','artifact-source-tenant','fixture','fixture'),
                   ('00000000-0000-4000-8000-000000000042','other-tenant','fixture','fixture');"
            ).await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.channels(id,name,description,allowed_groups)
                 VALUES($1,'Source fixture','fixture',ARRAY['fixture-risk'])",
                    &[&channel_id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.channel_memberships(channel_id,user_id)
                 VALUES($1,'actor-a'),($1,'actor-b')",
                    &[&channel_id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.channel_agents(channel_id,agent_id) VALUES($1,'bot-a')",
                    &[&channel_id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        let begin = BeginThreadRunRequest {
            auth_generation: AuthGeneration::new(0),
            deployment,
            tenant,
            actor: ActorId::new(OWNER),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: if channel {
                    ThreadIdentity::new(&DeploymentId::new(DEPLOYMENT)).mint_from_entropy([2; 16])
                } else {
                    direct_thread
                },
                run_id: RunId::new("opaque/source%成果"),
                bot_id: BotId::new("bot-a"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: channel_id.clone(),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: PRIVATE_MARKER.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config,
            RUNTIME_OWNER.to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|error| error.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|error| error.to_string())?;
        pool.get()
            .await
            .map_err(|error| error.to_string())?
            .execute(
                "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,'actor-b')",
                &[&begin.command.thread_id.as_str()],
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self {
            pool,
            registry,
            directory,
            begin,
            channel: channel_id,
        })
    }

    fn auth(&self) -> AuthContext {
        self.auth_as(DEPLOYMENT, TENANT, OWNER, 0)
    }

    fn auth_as(&self, deployment: &str, tenant: &str, actor: &str, generation: u64) -> AuthContext {
        // Explicit test snapshot of the seeded principal, not session/SSO authentication evidence.
        AuthContextBuilder::from_verified_session(
            DeploymentId::new(deployment),
            TenantId::new(tenant),
            ActorId::new(actor),
            AuthGeneration::new(generation),
            false,
        )
        .with_role(if actor == OTHER {
            Role::Admin
        } else {
            Role::User
        })
        .build()
    }

    async fn observe(&self) -> Result<VerifiedArtifactSource, String> {
        self.registry
            .observe_source(
                &self.auth(),
                &self.begin.command.thread_id,
                &self.begin.command.run_id,
            )
            .await
            .map_err(|error| error.to_string())
    }

    async fn expect_invisible(
        &self,
        auth: &AuthContext,
        thread: &ThreadId,
        run: &RunId,
        message: &str,
    ) -> Result<(), String> {
        match self.registry.observe_source(auth, thread, run).await {
            Err(ArtifactSourceError::NotVisible) => Ok(()),
            Err(error) => Err(format!(
                "{message}: expected NotVisible, received {error:?}"
            )),
            Ok(_) => Err(format!("{message}: source remained visible")),
        }
    }

    async fn expect_current_invisible(&self, message: &str) -> Result<(), String> {
        self.expect_invisible(
            &self.auth(),
            &self.begin.command.thread_id,
            &self.begin.command.run_id,
            message,
        )
        .await
    }

    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|error| error.to_string())
    }

    async fn tamper_thread_identity(&self, sql: &str) -> Result<(), String> {
        let mut client = self.pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tamper_owned_thread_identity(&tx, sql, &[]).await?;
        tx.commit().await.map_err(|e| e.to_string())
    }

    async fn tamper_channel_run_source(&self, sql: &str) -> Result<(), String> {
        let mut client = self.pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tamper_owned_channel_run_source(&tx, sql).await?;
        tx.commit().await.map_err(|e| e.to_string())
    }

    fn runtime(&self) -> Result<PostgresRunRuntime, String> {
        PostgresRunRuntime::new(
            self.pool.clone(),
            RUNTIME_OWNER.to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|error| error.to_string())
    }

    async fn status(&self) -> Result<String, String> {
        self.pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .query_one(
                "SELECT status FROM public.runs WHERE run_id=$1",
                &[&self.begin.command.run_id.as_str()],
            )
            .await
            .map_err(|error| error.to_string())?
            .try_get(0)
            .map_err(|error| error.to_string())
    }

    async fn database_now(&self) -> Result<OffsetDateTime, String> {
        self.pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .query_one("SELECT statement_timestamp()", &[])
            .await
            .map_err(|error| error.to_string())?
            .try_get(0)
            .map_err(|error| error.to_string())
    }

    async fn persisted_state(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|error| error.to_string())?.query_one(
            "SELECT jsonb_build_object(
              'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM public.runs r),
              'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY run_id,seq) FROM public.run_events e),
              'threads',(SELECT jsonb_agg(to_jsonb(t) ORDER BY thread_id) FROM public.threads t),
              'thread_memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY thread_id,user_id) FROM public.thread_memberships m),
              'channel_memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY channel_id,user_id) FROM public.channel_memberships m),
              'leases',(SELECT jsonb_agg(to_jsonb(l) ORDER BY thread_id) FROM public.thread_leases l),
              'occupancy',(SELECT jsonb_agg(to_jsonb(o) ORDER BY thread_id) FROM public.thread_run_occupancy o),
              'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY outbox_id) FROM public.outbox o),
              'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM public.audit_events a),
              'registry',(SELECT jsonb_agg(to_jsonb(b) ORDER BY deployment_id,tenant_id) FROM openbot_internal.artifact_dataset_bindings b))",
            &[],
        ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())
    }
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

async fn with_fixture<F, Fut>(name: &str, channel: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(name);
    with_temp_database(&admin, name, |config| async move {
        let fixture = Fixture::new(config, channel).await?;
        let pool = fixture.pool.clone();
        let outcome = body(fixture).await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn source_workspace_channel_anchor_and_direct_thread_keep_same_text_distinct() {
    with_fixture("as_workspace", true, |fixture| async move {
        let channel = fixture.observe().await?;
        require(
            channel.workspace().kind() == ArtifactWorkspaceKind::Channel,
            "channel kind drifted",
        )?;
        require(
            channel.workspace().id() == fixture.channel.as_str(),
            "channel workspace must use anchor",
        )?;
        let mut direct = fixture.begin.clone();
        direct.command.thread_id =
            ThreadIdentity::new(&fixture.begin.deployment).mint_from_entropy([3; 16]);
        direct.command.run_id = RunId::new("direct-source-run");
        direct.command.anchor = ThreadRunAnchor::DirectBot;
        fixture
            .directory
            .begin_thread_run(direct.clone())
            .await
            .map_err(|error| error.to_string())?;
        let thread = fixture
            .registry
            .observe_source(
                &fixture.auth(),
                &direct.command.thread_id,
                &direct.command.run_id,
            )
            .await
            .map_err(|error| error.to_string())?;
        require(
            thread.workspace().kind() == ArtifactWorkspaceKind::Thread,
            "direct kind drifted",
        )?;
        require(
            thread.workspace().id() == direct.command.thread_id.as_str(),
            "direct workspace must use thread",
        )?;
        require(
            thread.workspace().id() != direct.command.bot_id.as_str(),
            "direct workspace used Bot anchor",
        )?;
        require(
            channel.workspace().id() == thread.workspace().id(),
            "fixture must use equal raw workspace text",
        )?;
        require(
            channel.workspace() != thread.workspace(),
            "kind must keep equal workspace text distinct",
        )?;
        require(
            channel.owner_actor_id() == &fixture.begin.actor
                && thread.owner_actor_id() == &fixture.begin.actor,
            "source owner drifted",
        )?;
        require(
            channel.thread_id() == &fixture.begin.command.thread_id
                && thread.thread_id() == &direct.command.thread_id,
            "source thread drifted",
        )?;
        require(
            channel.run_id() == &fixture.begin.command.run_id
                && thread.run_id() == &direct.command.run_id,
            "source run drifted",
        )?;
        fixture
            .expect_invisible(
                &fixture.auth(),
                &fixture.begin.command.thread_id,
                &direct.command.run_id,
                "two existing source IDs must still belong to the same run/thread pair",
            )
            .await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn source_allows_real_running_and_completed_without_mutating_records() {
    with_fixture("as_lifecycle", false, |fixture| async move {
        // Begin starts the persisted Run in its own transaction. A second Begin on this Thread
        // returns LeaseConflict; there is no production queue/promotion path to certify here.
        require(
            fixture.status().await? == "running",
            "real Begin must persist the running run before dispatch acknowledgement",
        )?;
        let before = fixture.persisted_state().await?;
        let earliest = fixture.database_now().await?;
        let begun = fixture.observe().await?;
        let latest = fixture.database_now().await?;
        require(
            begun.observed_at() >= earliest && begun.observed_at() <= latest,
            "observation must use current DB time",
        )?;
        require(
            before == fixture.persisted_state().await?,
            "pre-dispatch running source read mutated durable records",
        )?;
        let runtime = fixture.runtime()?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|error| error.to_string())?
            .ok_or("fixture dispatch missing")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|error| error.to_string())?;
        require(
            lease.run_id() == &fixture.begin.command.run_id,
            "dispatch acknowledgement must belong to the observed real run",
        )?;
        require(
            fixture.status().await? == "running",
            "dispatch acknowledgement must preserve the real running run",
        )?;
        let before = fixture.persisted_state().await?;
        let running = fixture.observe().await?;
        require(
            before == fixture.persisted_state().await?,
            "running source read mutated durable records",
        )?;
        runtime
            .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map_err(|error| error.to_string())?;
        require(
            fixture.status().await? == "completed",
            "runtime must finish the real run",
        )?;
        let before = fixture.persisted_state().await?;
        let completed = fixture.observe().await?;
        require(
            before == fixture.persisted_state().await?,
            "completed source read mutated durable records",
        )?;
        require(
            begun.workspace() == running.workspace()
                && running.workspace() == completed.workspace(),
            "ordinary source workspace changed with run state",
        )?;
        require(
            begun.run_id() == running.run_id() && running.run_id() == completed.run_id(),
            "source observations must remain on the same real run",
        )?;
        // Delete only this fixture's already-completed run through normal enabled triggers. This
        // proves missing-source lookup, not artifact retention or explicit-saved preservation.
        fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .execute(
                "DELETE FROM public.runs WHERE run_id=$1",
                &[&fixture.begin.command.run_id.as_str()],
            )
            .await
            .map_err(|error| error.to_string())?;
        fixture
            .expect_current_invisible("hard-deleted fixture run must be hidden")
            .await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn source_shared_channel_membership_and_admin_do_not_bypass_run_owner() {
    with_fixture("as_owner", true, |fixture| async move {
        let owner = fixture.observe().await?;
        let other_auth = fixture.auth_as(DEPLOYMENT, TENANT, OTHER, 0);
        fixture
            .expect_invisible(
                &other_auth,
                &fixture.begin.command.thread_id,
                &fixture.begin.command.run_id,
                "another channel/thread member with current admin role cannot observe owner's run",
            )
            .await?;
        let mut other = fixture.begin.clone();
        other.actor = ActorId::new(OTHER);
        other.command.thread_id =
            ThreadIdentity::new(&fixture.begin.deployment).mint_from_entropy([4; 16]);
        other.command.run_id = RunId::new("other-owner-run");
        fixture
            .directory
            .begin_thread_run(other.clone())
            .await
            .map_err(|error| error.to_string())?;
        let own = fixture
            .registry
            .observe_source(&other_auth, &other.command.thread_id, &other.command.run_id)
            .await
            .map_err(|error| error.to_string())?;
        require(
            owner.workspace() == own.workspace(),
            "actors in one channel must share its workspace key",
        )?;
        require(
            own.owner_actor_id() == &ActorId::new(OTHER),
            "other actor's own source must remain visible",
        )?;
        fixture
            .expect_invisible(
                &fixture.auth(),
                &other.command.thread_id,
                &other.command.run_id,
                "shared workspace cannot expand owner into another actor's run",
            )
            .await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn source_wrong_namespace_generation_or_missing_selection_is_uniformly_not_visible() {
    with_fixture("as_selection", false, |fixture| async move {
        fixture.observe().await?;
        for auth in [
            fixture.auth_as("other-deployment", TENANT, OWNER, 0),
            fixture.auth_as(DEPLOYMENT, "other-tenant", OWNER, 0),
            fixture.auth_as(DEPLOYMENT, TENANT, OWNER, 1),
            fixture.auth_as(DEPLOYMENT, TENANT, OWNER, u64::MAX),
            fixture.auth_as(DEPLOYMENT, TENANT, "missing-actor", 0),
            fixture.auth_as(DEPLOYMENT, TENANT, OTHER, 0),
        ] {
            fixture
                .expect_invisible(
                    &auth,
                    &fixture.begin.command.thread_id,
                    &fixture.begin.command.run_id,
                    "namespace, generation or actor mismatch must be NotVisible",
                )
                .await?;
        }
        let missing_thread =
            ThreadIdentity::new(&fixture.begin.deployment).mint_from_entropy([9; 16]);
        let missing_run = RunId::new(PRIVATE_MARKER);
        for (thread, run) in [
            (&missing_thread, &fixture.begin.command.run_id),
            (&fixture.begin.command.thread_id, &missing_run),
            (&missing_thread, &missing_run),
        ] {
            fixture
                .expect_invisible(
                    &fixture.auth(),
                    thread,
                    run,
                    "missing selection must be NotVisible",
                )
                .await?;
        }
        fixture
            .sql("UPDATE public.users SET auth_generation=1 WHERE id='actor-a'")
            .await?;
        fixture
            .expect_current_invisible("previous identity generation must be hidden")
            .await?;
        fixture
            .registry
            .observe_source(
                &fixture.auth_as(DEPLOYMENT, TENANT, OWNER, 1),
                &fixture.begin.command.thread_id,
                &fixture.begin.command.run_id,
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    })
    .await;
}

// Privileged corruption control is confined to this owned disposable test DB.
// Probe the real guard for every change/restore and re-enable it in the same transaction.
async fn tamper_owned_thread_identity(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    const NEW_GUARDS: [&str; 3] = [
        "threads_history_body_before_update",
        "threads_history_canonical_before",
        "threads_history_source_final",
    ];
    const OLD: &str = "threads_history_protect_identity_update";
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned registered Thread guard {guard} was not normally enabled"
            ));
        }
    }
    tx.batch_execute("SAVEPOINT owned_current_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_current_identity_probe; RELEASE SAVEPOINT owned_current_identity_probe").await.map_err(|e|e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && matches!(
                    e.message(),
                    "thread_history_state_binding_invalid"
                        | "thread_history_writer_binding_invalid"
                        | "thread_history_writer_source_mutation_refused"
                )
        })
    {
        return Err("ordinary current Thread identity DML was not explicitly refused".into());
    }
    // Suppress only these owned fixture events BEFORE corrupting DML. Re-enabling
    // at COMMIT cannot remove an already queued deferred event; none is bypassed.
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads DISABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.batch_execute("SAVEPOINT owned_original50_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let original = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_original50_identity_probe; RELEASE SAVEPOINT owned_original50_identity_probe").await.map_err(|e|e.to_string())?;
    if !original
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000" && e.message() == "thread_history_state_binding_invalid"
        })
    {
        return Err("original0050 single identity guard control lost its exact refusal".into());
    }
    tx.batch_execute(
        "ALTER TABLE public.threads DISABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    let changed = tx.execute(sql, params).await.map_err(|e| e.to_string())?;
    tx.batch_execute(
        "ALTER TABLE public.threads ENABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads ENABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned Thread guard {guard} was not restored before product entry"
            ));
        }
    }
    if changed == 0 {
        return Err("owned identity control changed no row".into());
    }
    Ok(())
}

// A channel source pins its canonical Run's Bot (0051 item 10/11): ordinary Run.bot DML is
// refused immediately. Only in this owned disposable DB, after proving that refusal, the
// exact reverse and source-final Run guards are suppressed for the change and restored.
async fn tamper_owned_channel_run_source(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
) -> Result<(), String> {
    const GUARDS: [&str; 2] = ["runs_history_canonical_before", "runs_history_source_final"];
    for guard in GUARDS {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.runs'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned registered Run guard {guard} was not normally enabled"
            ));
        }
    }
    tx.batch_execute("SAVEPOINT owned_channel_run_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, &[]).await;
    tx.batch_execute(
        "ROLLBACK TO SAVEPOINT owned_channel_run_probe; RELEASE SAVEPOINT owned_channel_run_probe",
    )
    .await
    .map_err(|e| e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && e.message() == "thread_history_writer_source_mutation_refused"
        })
    {
        return Err("ordinary channel source Run.bot DML was not explicitly refused".into());
    }
    for guard in GUARDS {
        tx.batch_execute(&format!("ALTER TABLE public.runs DISABLE TRIGGER {guard}"))
            .await
            .map_err(|e| e.to_string())?;
    }
    // The still-enabled deferred Run guards (e.g. terminal final) check this change at
    // statement end instead of queuing an event that would block re-enabling the guards.
    tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
        .await
        .map_err(|e| e.to_string())?;
    let changed = tx.execute(sql, &[]).await.map_err(|e| e.to_string())?;
    for guard in GUARDS {
        tx.batch_execute(&format!("ALTER TABLE public.runs ENABLE TRIGGER {guard}"))
            .await
            .map_err(|e| e.to_string())?;
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.runs'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned Run guard {guard} was not restored before product entry"
            ));
        }
    }
    if changed == 0 {
        return Err("owned channel Run control changed no row".into());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn source_direct_current_role_deny_membership_profile_package_and_thread_are_rechecked() {
    with_fixture("as_direct_acl", false, |fixture| async move {
        fixture.observe().await?;
        for (change, restore, reason) in [
            ("DELETE FROM public.user_roles WHERE user_id='actor-a'",
             "INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user')", "current role removed"),
            ("INSERT INTO public.revoked_access(email,revoked_by) VALUES('owner@example.test','actor-b')",
             "DELETE FROM public.revoked_access WHERE email='owner@example.test'", "current lowercased email deny"),
            ("DELETE FROM public.thread_memberships WHERE user_id='actor-a'",
             "INSERT INTO public.thread_memberships(thread_id,user_id) SELECT thread_id,'actor-a' FROM public.threads", "direct membership removed"),
            ("UPDATE public.threads SET status='deleted',deleted_at=now()",
             "UPDATE public.threads SET status='active',deleted_at=NULL", "current thread deleted"),
            ("UPDATE public.threads SET tenant_id='other-tenant'",
             "UPDATE public.threads SET tenant_id='artifact-source-tenant'", "current source tenant differs from binding"),
            ("UPDATE public.threads SET deployment_id='other-deployment'",
             "UPDATE public.threads SET deployment_id='artifact-source-deployment'", "current source deployment differs from binding"),
            ("UPDATE public.agent_profiles SET deleted_at=now() WHERE agent_id='bot-a'",
             "UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='bot-a'", "current Bot profile deleted"),
            ("UPDATE public.agent_profiles SET visibility='private',owner_user_id='actor-b' WHERE agent_id='bot-a'",
             "UPDATE public.agent_profiles SET visibility='public',owner_user_id='actor-a' WHERE agent_id='bot-a'", "current private Bot belongs to other actor"),
            ("UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000042' WHERE id='bot-a'",
             "UPDATE public.agents SET package_id=NULL WHERE id='bot-a'", "Bot package belongs to other tenant"),
            ("UPDATE public.runs SET bot_id='bot-b'",
             "UPDATE public.runs SET bot_id='bot-a'", "source selected Bot no longer matches direct anchor"),
        ] {
            let corrupts_thread_identity = matches!(change,
                "UPDATE public.threads SET tenant_id='other-tenant'"
                | "UPDATE public.threads SET deployment_id='other-deployment'");
            if corrupts_thread_identity {
                fixture.tamper_thread_identity(change).await?;
            } else {
                fixture.sql(change).await?;
            }
            fixture.expect_current_invisible(reason).await?;
            if corrupts_thread_identity {
                fixture.tamper_thread_identity(restore).await?;
            } else {
                fixture.sql(restore).await?;
            }
            fixture.observe().await?;
        }
        fixture.sql("UPDATE public.agent_profiles SET visibility='private' WHERE agent_id='bot-a';
                     UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000041' WHERE id='bot-a';
                     UPDATE public.threads SET status='archived'").await?;
        fixture.observe().await?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn source_channel_current_membership_bot_link_and_both_packages_are_rechecked() {
    with_fixture("as_channel_acl", true, |fixture| async move {
        fixture.observe().await?;
        for (change, restore, reason) in [
            ("DELETE FROM public.channel_memberships WHERE user_id='actor-a'",
             "INSERT INTO public.channel_memberships(channel_id,user_id) SELECT id,'actor-a' FROM public.channels", "current channel membership removed"),
            ("DELETE FROM public.channel_agents WHERE agent_id='bot-a'",
             "INSERT INTO public.channel_agents(channel_id,agent_id) SELECT id,'bot-a' FROM public.channels", "selected Bot no longer belongs to channel"),
            ("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000042'",
             "UPDATE public.channels SET package_id=NULL", "channel package belongs to other tenant"),
            ("UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000042' WHERE id='bot-a'",
             "UPDATE public.agents SET package_id=NULL WHERE id='bot-a'", "selected Bot package belongs to other tenant"),
            ("UPDATE public.runs SET bot_id='bot-b'",
             "UPDATE public.runs SET bot_id='bot-a'", "source selected Bot has no channel link"),
        ] {
            let pinned_run_source = change == "UPDATE public.runs SET bot_id='bot-b'";
            if pinned_run_source {
                fixture.tamper_channel_run_source(change).await?;
            } else {
                fixture.sql(change).await?;
            }
            fixture.expect_current_invisible(reason).await?;
            if pinned_run_source {
                fixture.tamper_channel_run_source(restore).await?;
            } else {
                fixture.sql(restore).await?;
            }
            fixture.observe().await?;
        }
        fixture.sql("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000041';
                     UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000041' WHERE id='bot-a';
                     DELETE FROM public.thread_memberships WHERE user_id='actor-a'").await?;
        // R398's channel arm consumes channel membership; a copied direct-only membership condition
        // would incorrectly hide this currently authorized channel source.
        fixture.observe().await?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn source_observation_does_not_survive_current_materialized_membership_revocation() {
    with_fixture("as_observation", true, |fixture| async move {
        let old = fixture.observe().await?;
        let workspace = old.workspace().clone();
        // Raw groups describe provisioning inputs. The current R398 predicate consumes the actual
        // materialized membership, as inherited by this own local fixture; no live SSO is claimed.
        fixture.sql("UPDATE public.users SET groups='{}' WHERE id='actor-a';
                     UPDATE public.channels SET allowed_groups=ARRAY['different-group']").await?;
        fixture.observe().await?;
        fixture.sql("DELETE FROM public.channel_memberships WHERE user_id='actor-a';
                     UPDATE public.users SET groups=ARRAY['fixture-risk'] WHERE id='actor-a';
                     UPDATE public.channels SET allowed_groups=ARRAY['fixture-risk']").await?;
        let before = fixture.persisted_state().await?;
        fixture.expect_current_invisible("old observation and matching group strings cannot replace current membership").await?;
        require(before == fixture.persisted_state().await?, "rejected source read mutated durable records")?;
        require(old.workspace() == &workspace && old.owner_actor_id() == &fixture.begin.actor,
            "old value should remain an observation, not acquire fresh authority")?;
        fixture.sql("INSERT INTO public.channel_memberships(channel_id,user_id) SELECT id,'actor-a' FROM public.channels").await?;
        require(fixture.observe().await?.workspace() == &workspace, "restored current source should retain workspace identity")
    }).await;
}
