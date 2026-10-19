//! R424 registration against caller-owned disposable PostgreSQL and real private filesystem IO.
//! Seeded principals are local fixtures, not live SSO or deployed-role evidence. The producer
//! message is written by the real Begin transaction. These tests do not certify byte handles,
//! deletion, backup/restore, Linux IO, or complete artifact readiness.

#![cfg(all(unix, feature = "server-runtime"))]

mod harness;

use std::fs::File;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use harness::{admin_config, with_temp_database};
use openbot_application::{
    ArtifactAdministration, ArtifactAdministrationError, BeginThreadRunRequest, RunRuntime,
    RunTerminal, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, ArtifactRetentionClass,
    SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;

const DEPLOYMENT: &str = "artifact-registration-deployment";
const TENANT: &str = "artifact-registration-tenant";
const OWNER: &str = "actor-a";
const OTHER: &str = "actor-b";
const EXACT_TEXT: &str = "  ARTIFACT_REGISTRATION_PRIVATE_CANARY\n成果 café 🦀\t  ";

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn sha256(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn fact_count(facts: &Value, key: &str) -> Result<usize, String> {
    facts[key]
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| format!("missing owned fixture fact {key}"))
}

/// The only filesystem tree this fixture may remove; freshly created random roots cannot name
/// user data. Production objects are read independently below rather than through download APIs.
struct OwnedRoot(PathBuf);

impl OwnedRoot {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;

        let path =
            std::env::temp_dir().join(format!("openbot-artifact-registration-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        Ok(Self(path))
    }
}

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let outcome = std::fs::remove_dir_all(&self.0);
        let absent = !self.0.exists();
        eprintln!(
            "ARTIFACT_REGISTRATION_ROOT_CLEANUP removed={} absent={absent}",
            outcome.is_ok()
        );
        if !std::thread::panicking() {
            assert!(
                outcome.is_ok() && absent,
                "owned artifact registration root cleanup failed"
            );
        }
    }
}

const BODY_GUARD: &str = "messages_history_body_before";
const CANONICAL_GUARD: &str = "messages_history_canonical_before";
const SOURCE_FINAL_GUARD: &str = "messages_history_source_final";
// Each 0051 messages guard and the trigger function its refusal context names.
const MESSAGE_GUARDS: [(&str, &str); 3] = [
    (BODY_GUARD, "guard_thread_history_body()"),
    (CANONICAL_GUARD, "guard_thread_history_canonical_reverse()"),
    (SOURCE_FINAL_GUARD, "require_thread_history_channel_final()"),
];
type GuardRefusals = &'static [(&'static str, &'static str)];

fn observed_refusal(error: &tokio_postgres::Error) -> String {
    let Some(db) = error.as_db_error() else {
        return error.to_string();
    };
    let guards: Vec<&str> = MESSAGE_GUARDS
        .iter()
        .filter(|(_, function)| db.where_().is_some_and(|w| w.contains(function)))
        .map(|(guard, _)| *guard)
        .collect();
    format!("{} {} {guards:?}", db.code().code(), db.message())
}

struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    config: DatabaseConfig,
    registry: Arc<ArtifactDatasetRegistry>,
    directory: PostgresThreadDirectory,
    begin: BeginThreadRunRequest,
    channel: ChannelId,
    root: OwnedRoot,
}

impl Fixture {
    async fn new(config: DatabaseConfig, channel: bool) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,auth_generation,groups) VALUES
                       ('actor-a','owner@example.test',0,ARRAY['artifact-fixture']),
                       ('actor-b','other@example.test',0,ARRAY['artifact-fixture']);
                     INSERT INTO public.user_roles(user_id,role) VALUES
                       ('actor-a','user'),('actor-b','admin');
                     INSERT INTO public.agents(id,name,type,configuration) VALUES
                       ('bot-a','Artifact fixture','built_in','{}');
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                     ) VALUES('bot-a','actor-a','Artifact fixture','fixture','fixture','public');
                     INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                       VALUES('00000000-0000-4000-8000-000000000041',
                              'artifact-registration-tenant','fixture','fixture');",
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let direct = ThreadIdentity::new(&deployment).mint_from_entropy([3; 16]);
        // Equal text in channel/thread keys is intentional; the kind must separate their charge.
        let channel_id = ChannelId::new(direct.as_str());
        {
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.channels(id,name,description,allowed_groups)
                     VALUES($1,'Artifact fixture','fixture',ARRAY['artifact-fixture'])",
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
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|error| error.to_string())?,
        );
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
                    direct
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
                message: EXACT_TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "artifact-registration-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|error| error.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self {
            pool,
            config,
            registry,
            directory,
            begin,
            channel: channel_id,
            root: OwnedRoot::new()?,
        })
    }

    fn auth(&self) -> AuthContext {
        self.auth_as(OWNER, 0)
    }

    fn auth_as(&self, actor: &str, generation: u64) -> AuthContext {
        AuthContextBuilder::from_verified_session(
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
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

    fn message_id(&self) -> String {
        format!("{}:input", self.begin.command.run_id.as_str())
    }

    async fn store(
        &self,
        policy: ArtifactQuotaPolicy,
    ) -> Result<Arc<DatasetBoundArtifactStore>, String> {
        let file = File::open(&self.root.0).map_err(|error| error.to_string())?;
        DatasetBoundArtifactStore::bind_host_root(file, Arc::clone(&self.registry), policy)
            .await
            .map(Arc::new)
            .map_err(|error| error.to_string())
    }

    async fn administration(
        &self,
        policy: ArtifactQuotaPolicy,
    ) -> Result<Arc<PostgresArtifactAdministration>, String> {
        let store = self.store(policy).await?;
        PostgresArtifactAdministration::new(
            Arc::clone(&self.registry),
            store,
            policy,
            SecretBytes::new(vec![0x81; 32]),
        )
        .map(Arc::new)
        .map_err(|error| error.to_string())
    }

    fn request(&self) -> SaveRunMessageTextArtifact {
        self.request_for(&self.begin, Uuid::now_v7().to_string())
    }

    fn request_for(
        &self,
        begin: &BeginThreadRunRequest,
        request_id: String,
    ) -> SaveRunMessageTextArtifact {
        SaveRunMessageTextArtifact {
            request_id,
            source_thread_id: begin.command.thread_id.clone(),
            source_run_id: begin.command.run_id.clone(),
            source_message_id: format!("{}:input", begin.command.run_id.as_str()),
            expected_sha256: sha256(&begin.command.message),
        }
    }

    fn object_bytes(&self, artifact_id: &str) -> Result<Vec<u8>, String> {
        std::fs::read(self.root.0.join("objects").join(artifact_id))
            .map_err(|error| error.to_string())
    }

    fn object_count(&self) -> Result<usize, String> {
        std::fs::read_dir(self.root.0.join("objects"))
            .map(|entries| entries.count())
            .map_err(|error| error.to_string())
    }

    async fn save(
        &self,
        administration: &PostgresArtifactAdministration,
        request: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, String> {
        administration
            .save_run_message_text(&self.auth(), request)
            .await
            .map_err(|error| error.to_string())
    }

    async fn second_channel_begin(&self, actor: &str) -> Result<BeginThreadRunRequest, String> {
        let mut begin = self.begin.clone();
        begin.actor = ActorId::new(actor);
        begin.command.thread_id = ThreadIdentity::new(&begin.deployment).mint_from_entropy([4; 16]);
        begin.command.run_id = RunId::new("other/channel/source");
        begin.command.anchor = ThreadRunAnchor::Channel {
            channel_id: self.channel.clone(),
        };
        self.directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|error| error.to_string())?;
        Ok(begin)
    }

    async fn complete_source(&self) -> Result<(), String> {
        let runtime = PostgresRunRuntime::new(
            self.pool.clone(),
            "artifact-registration-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|error| error.to_string())?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|error| error.to_string())?
            .ok_or("real fixture dispatch missing")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|error| error.to_string())?;
        require(
            lease.run_id() == &self.begin.command.run_id,
            "fixture completed a different Run",
        )?;
        runtime
            .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn observe_actor_wait(&self) -> Result<(), String> {
        for _ in 0..100 {
            let blocked: bool = self
                .pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity a
                     WHERE a.datname=current_database() AND a.pid<>pg_backend_pid()
                       AND cardinality(pg_catalog.pg_blocking_pids(a.pid))>0
                       AND a.query ILIKE '%users%')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if blocked {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Err("save never entered the real PostgreSQL actor row wait".to_owned())
    }

    async fn set_all_pool_sessions_repeatable_read(&self) -> Result<(), String> {
        // Hold every owned Pool connection so no default-RC recycled session can accidentally
        // make the explicit producer-transaction contract appear to work.
        let mut connections = Vec::new();
        for _ in 0..self.config.max_pool_size {
            let client = self.pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute("SET default_transaction_isolation='repeatable read'")
                .await
                .map_err(|error| error.to_string())?;
            let setting: String = client
                .query_one("SHOW default_transaction_isolation", &[])
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            require(
                setting == "repeatable read",
                "owned Pool session default was not changed",
            )?;
            connections.push(client);
        }
        drop(connections);
        Ok(())
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

    // Own-DB corruption control for the static canonical-message matrix. Each statement declares,
    // in order, every exact 0051 messages-guard refusal (55000 thread_history_writer_*) it meets
    // as ordinary DML; an empty declaration asserts the ordinary DML itself is accepted. Only each
    // observed guard is disabled, before its statement queues any source-final event, and every
    // guard is back to origin-enabled before the owned COMMIT.
    async fn owned_message_sql(&self, sql: &str, refusals: GuardRefusals) -> Result<(), String> {
        let mut client = self.pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
            .await
            .map_err(|e| e.to_string())?;
        let mut disabled = 0;
        loop {
            tx.batch_execute("SAVEPOINT owned_message_probe")
                .await
                .map_err(|e| e.to_string())?;
            match tx.batch_execute(sql).await {
                Ok(()) if disabled == refusals.len() => break,
                Ok(()) => {
                    return Err(format!(
                        "{sql}: declared refusal {:?} did not occur",
                        refusals[disabled]
                    ));
                }
                Err(error) => {
                    let observed = observed_refusal(&error);
                    let Some(&(guard, message)) = refusals.get(disabled) else {
                        return Err(format!("{sql}: undeclared refusal {observed}"));
                    };
                    if observed != format!("55000 {message} {:?}", [guard]) {
                        return Err(format!(
                            "{sql}: expected {guard} {message}, observed {observed}"
                        ));
                    }
                    tx.batch_execute(&format!(
                        "ROLLBACK TO SAVEPOINT owned_message_probe; \
                         ALTER TABLE public.messages DISABLE TRIGGER {guard}"
                    ))
                    .await
                    .map_err(|e| e.to_string())?;
                    disabled += 1;
                }
            }
        }
        for (guard, _) in &refusals[..disabled] {
            tx.batch_execute(&format!(
                "ALTER TABLE public.messages ENABLE TRIGGER {guard}"
            ))
            .await
            .map_err(|e| e.to_string())?;
        }
        let states: Vec<String> = tx
            .query(
                "SELECT tgenabled::text FROM pg_catalog.pg_trigger \
                 WHERE tgrelid='public.messages'::regclass AND tgname=ANY($1) AND NOT tgisinternal",
                &[&MESSAGE_GUARDS.map(|(guard, _)| guard).to_vec()],
            )
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .map(|row| row.get(0))
            .collect();
        if states != ["O", "O", "O"] {
            return Err(format!(
                "owned message guards were not restored: {states:?}"
            ));
        }
        tx.commit().await.map_err(|e| e.to_string())
    }

    async fn source_text(&self) -> Result<String, String> {
        self.pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .query_one(
                "SELECT content->>'text' FROM public.messages WHERE message_id=$1",
                &[&self.message_id()],
            )
            .await
            .map_err(|error| error.to_string())?
            .try_get(0)
            .map_err(|error| error.to_string())
    }

    async fn facts(&self) -> Result<Value, String> {
        self.facts_using(&self.pool).await
    }

    async fn facts_using(
        &self,
        pool: &openbot_infra::db::pool::DatabasePool,
    ) -> Result<Value, String> {
        let client = pool.get().await.map_err(|error| error.to_string())?;
        client
            .query_one(
                "SELECT jsonb_build_object(
              'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]')
                            FROM openbot_internal.artifact_save_operations o),
              'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]')
                         FROM openbot_internal.artifact_records r),
              'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]')
                          FROM openbot_internal.artifact_saved_receipts r),
              'workspaces',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]')
                            FROM openbot_internal.artifact_workspace_quotas q),
              'runs',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]')
                      FROM openbot_internal.artifact_run_quotas q),
              'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]')
                       FROM public.audit_events a WHERE event_type='artifact.saved'))",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?
            .try_get(0)
            .map_err(|error| error.to_string())
    }
}

async fn with_fixture<F, Fut>(tag: &str, channel: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(tag);
    with_temp_database(&admin, tag, |config| async move {
        body(Fixture::new(config, channel).await?).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn trusted_root_reopen_preserves_store_and_second_owner_is_refused() {
    with_fixture("ar_root_owner", false, |fixture| async move {
        require(
            fixture.source_text().await? == EXACT_TEXT,
            "real Begin text changed",
        )?;
        let owner = fixture.store(ArtifactQuotaPolicy::default()).await?;
        let store_id = owner.store_id();
        let second = DatasetBoundArtifactStore::bind_host_root(
            File::open(&fixture.root.0).map_err(|error| error.to_string())?,
            Arc::clone(&fixture.registry),
            ArtifactQuotaPolicy::default(),
        )
        .await;
        require(second.is_err(), "two owners acquired the same root")?;
        drop(owner);
        let reopened = fixture.store(ArtifactQuotaPolicy::default()).await?;
        require(
            reopened.store_id() == store_id,
            "ordinary reopen minted a second store",
        )?;
        drop(reopened);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn copied_marker_at_different_root_is_not_a_restore_proof() {
    with_fixture("ar_root_copy", false, |fixture| async move {
        let owner = fixture.store(ArtifactQuotaPolicy::default()).await?;
        let copied = OwnedRoot::new()?;
        for entry in std::fs::read_dir(&fixture.root.0).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let metadata =
                std::fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
            if metadata.is_file() {
                std::fs::copy(entry.path(), copied.0.join(entry.file_name()))
                    .map_err(|error| error.to_string())?;
            }
        }
        drop(owner);
        let result = DatasetBoundArtifactStore::bind_host_root(
            File::open(&copied.0).map_err(|error| error.to_string())?,
            Arc::clone(&fixture.registry),
            ArtifactQuotaPolicy::default(),
        )
        .await;
        require(
            result.is_err(),
            "copied marker authorized different device/inode",
        )?;
        let reopened = fixture.store(ArtifactQuotaPolicy::default()).await?;
        drop(reopened);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn existing_marker_without_current_pg_store_binding_cannot_reinitialize() {
    with_fixture("ar_missing_store_binding", false, |fixture| async move {
        let owner = fixture.store(ArtifactQuotaPolicy::default()).await?;
        drop(owner);
        // This controlled fault is confined to the owned test DB. Restore the real append-only
        // trigger immediately; the existing marker must not authorize adoption of a missing row.
        fixture.sql(
            "ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only;
             DELETE FROM openbot_internal.artifact_store_bindings;
             ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only;"
        ).await?;
        require(fixture.store(ArtifactQuotaPolicy::default()).await.is_err(), "existing marker reinitialized missing PG binding")?;
        let count:i64=fixture.pool.get().await.map_err(|error|error.to_string())?
            .query_one("SELECT count(*) FROM openbot_internal.artifact_store_bindings",&[])
            .await.map_err(|error|error.to_string())?.get(0);
        require(count==0,"missing binding was adopted from marker alone")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn original_root_rejects_other_namespace_and_changed_physical_pg_tuple() {
    with_fixture("ar_root_scope", false, |fixture| async move {
        let owner = fixture.store(ArtifactQuotaPolicy::default()).await?;
        drop(owner);
        let wrong_namespace = Arc::new(ArtifactDatasetRegistry::from_server(
            fixture.pool.clone(), &DeploymentId::new("other-artifact-deployment"), &TenantId::new(TENANT)
        ).await.map_err(|error|error.to_string())?);
        let wrong = DatasetBoundArtifactStore::bind_host_root(
            File::open(&fixture.root.0).map_err(|error|error.to_string())?, wrong_namespace,
            ArtifactQuotaPolicy::default()
        ).await;
        require(wrong.is_err(),"root marker supplied authority for a different namespace")?;
        // Inject only the owned binding data, then restore enabled production triggers. A local
        // dev/inode/uid mismatch is refused; this test does not implement a restore producer.
        fixture.sql(
            "ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only;
             UPDATE openbot_internal.artifact_store_bindings SET root_inode=CASE WHEN root_inode='0' THEN '1' ELSE '0' END;
             ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only;"
        ).await?;
        require(fixture.store(ArtifactQuotaPolicy::default()).await.is_err(),"ordinary reopen replaced a changed physical PG tuple")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn real_user_text_receipt_byte_charge_and_audit_commit_once() {
    with_fixture("ar_exact_once", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        require(
            fixture.source_text().await? == EXACT_TEXT,
            "real Begin source text changed",
        )?;
        let request = fixture.request();
        let receipt = fixture.save(&administration, request.clone()).await?;
        require(
            fixture.object_bytes(&receipt.artifact_id)? == EXACT_TEXT.as_bytes(),
            "saved object trimmed or reserialized logical message text",
        )?;
        require(
            receipt.request_id == request.request_id,
            "request locator changed",
        )?;
        require(
            receipt.source_call_seq.is_none() && receipt.source_attempt_seq.is_none(),
            "user save fabricated tool provenance",
        )?;
        let metadata = administration
            .get_metadata(&fixture.auth(), &receipt.artifact_id)
            .await
            .map_err(|error| error.to_string())?;
        let ArtifactMetadata::Available(record) = metadata else {
            return Err("confirmed exact bytes were not available".to_owned());
        };
        require(
            record.byte_length == EXACT_TEXT.len() as u64,
            "record did not use actual UTF8 byte length",
        )?;
        require(
            record.sha256 == sha256(EXACT_TEXT),
            "record did not use actual full SHA256",
        )?;
        require(
            record.retention_class == ArtifactRetentionClass::ExplicitSaved,
            "retention drifted",
        )?;
        require(
            record.saved_by == Some(ActorId::new(OWNER)) && record.saved_at.is_some(),
            "save provenance missing",
        )?;
        let facts = fixture.facts().await?;
        for field in [
            "operations",
            "records",
            "receipts",
            "audit",
            "workspaces",
            "runs",
        ] {
            require(
                fact_count(&facts, field)? == 1,
                "registration duplicated a persistent fact",
            )?;
        }
        require(
            facts["workspaces"][0]["charged_bytes"] == EXACT_TEXT.len() as u64,
            "reservation and bytes were double charged",
        )?;
        require(
            facts["runs"][0]["identity_count"] == 1,
            "one operation used multiple Run slots",
        )?;
        let audit = facts["audit"][0]["payload"].to_string();
        require(
            !audit.contains("ARTIFACT_REGISTRATION_PRIVATE_CANARY")
                && !audit.contains(&record.sha256),
            "audit contains body or hash",
        )?;
        let mut alias = request;
        alias.request_id = alias.request_id.to_uppercase();
        let replay = fixture.save(&administration, alias).await?;
        require(
            replay == receipt,
            "parsed UUID case alias created a second operation",
        )?;
        require(
            fixture.facts().await? == facts && fixture.object_count()? == 1,
            "observation replay mutated records or bytes",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn changed_intent_on_original_locator_is_conflict_without_second_io() {
    with_fixture("ar_changed_intent", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let request = fixture.request();
        let receipt = fixture.save(&administration, request.clone()).await?;
        let before = fixture.facts().await?;
        let mut changed = request;
        changed.expected_sha256 = "a".repeat(64);
        require(
            administration
                .save_run_message_text(&fixture.auth(), changed)
                .await
                == Err(ArtifactAdministrationError::RequestConflict),
            "original locator accepted changed digest intent",
        )?;
        require(
            fixture.facts().await? == before,
            "changed intent mutated durable facts",
        )?;
        require(
            fixture.object_count()? == 1
                && fixture.object_bytes(&receipt.artifact_id)? == EXACT_TEXT.as_bytes(),
            "changed intent rewrote original bytes",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn concurrent_original_locator_has_one_actual_object_and_positive_fact() {
    with_fixture("ar_same_locator", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let request = fixture.request();
        let barrier = Arc::new(tokio::sync::Barrier::new(4));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let administration = Arc::clone(&administration);
            let request = request.clone();
            let auth = fixture.auth();
            let barrier = Arc::clone(&barrier);
            tasks.spawn(async move {
                barrier.wait().await;
                administration.save_run_message_text(&auth, request).await
            });
        }
        let mut confirmed = None;
        while let Some(outcome) = tasks.join_next().await {
            match outcome.map_err(|error| error.to_string())? {
                Ok(receipt) => {
                    if let Some(original) = &confirmed {
                        require(original == &receipt, "concurrent replay changed identity")?;
                    }
                    confirmed = Some(receipt);
                }
                Err(
                    ArtifactAdministrationError::Unavailable
                    | ArtifactAdministrationError::CommitUnknown,
                ) => {}
                Err(error) => {
                    return Err(format!(
                        "unexpected concurrent registration failure: {error}"
                    ));
                }
            }
        }
        let receipt = confirmed.ok_or("no concurrent operation confirmed a registration")?;
        require(
            fixture.save(&administration, request).await? == receipt,
            "final current replay changed confirmed identity",
        )?;
        let facts = fixture.facts().await?;
        for field in ["operations", "records", "receipts", "audit"] {
            require(
                fact_count(&facts, field)? == 1,
                "concurrent save duplicated effect",
            )?;
        }
        require(
            fixture.object_count()? == 1,
            "concurrent save wrote second object",
        )?;
        require(
            facts["workspaces"][0]["charged_bytes"] == EXACT_TEXT.len() as u64,
            "concurrent save charged more than actual bytes",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn tightened_single_object_quota_refuses_before_any_record_or_object() {
    with_fixture("ar_small_single", false, |fixture| async move {
        let policy = ArtifactQuotaPolicy::new(EXACT_TEXT.len() as u64 - 1, 32, 1024)
            .map_err(|error| error.to_string())?;
        let administration = fixture.administration(policy).await?;
        let before = fixture.facts().await?;
        require(
            administration
                .save_run_message_text(&fixture.auth(), fixture.request())
                .await
                == Err(ArtifactAdministrationError::PolicyRefused {
                    rule: "artifact_quota",
                }),
            "visible oversized source did not return the frozen artifact_quota refusal",
        )?;
        require(
            fixture.facts().await? == before && fixture.object_count()? == 0,
            "write-before-quota left effect or partial object",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn channel_charge_is_shared_across_actors_without_shared_read_authority() {
    with_fixture("ar_shared_quota", true, |fixture| async move {
        let policy = ArtifactQuotaPolicy::new(1024, 32, EXACT_TEXT.len() as u64)
            .map_err(|error| error.to_string())?;
        let administration = fixture.administration(policy).await?;
        let receipt = fixture.save(&administration, fixture.request()).await?;
        let other = fixture.second_channel_begin(OTHER).await?;
        require(
            administration
                .get_metadata(&fixture.auth_as(OTHER, 0), &receipt.artifact_id)
                .await
                == Err(ArtifactAdministrationError::NotVisible),
            "shared channel/admin bypassed Run owner",
        )?;
        let before = fixture.facts().await?;
        require(
            matches!(
                administration
                    .save_run_message_text(
                        &fixture.auth_as(OTHER, 0),
                        fixture.request_for(&other, Uuid::now_v7().to_string())
                    )
                    .await,
                Err(ArtifactAdministrationError::PolicyRefused { .. })
            ),
            "actor-specific quota bypassed already full channel workspace",
        )?;
        require(
            fixture.facts().await? == before && fixture.object_count()? == 1,
            "shared quota refusal changed effects",
        )?;
        require(
            before["workspaces"][0]["workspace_kind"] == "channel"
                && before["workspaces"][0]["workspace_id"] == fixture.channel.as_str(),
            "charge used actor or Thread instead of channel anchor",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn equal_workspace_text_with_different_kinds_has_independent_charge() {
    with_fixture("ar_workspace_kind", true, |fixture| async move {
        let policy = ArtifactQuotaPolicy::new(1024, 32, EXACT_TEXT.len() as u64)
            .map_err(|error| error.to_string())?;
        let administration = fixture.administration(policy).await?;
        fixture.save(&administration, fixture.request()).await?;
        let mut direct = fixture.begin.clone();
        direct.command.thread_id =
            ThreadIdentity::new(&direct.deployment).mint_from_entropy([3; 16]);
        direct.command.run_id = RunId::new("direct/equal-workspace-text");
        direct.command.anchor = ThreadRunAnchor::DirectBot;
        fixture
            .directory
            .begin_thread_run(direct.clone())
            .await
            .map_err(|error| error.to_string())?;
        let request = fixture.request_for(&direct, Uuid::now_v7().to_string());
        fixture.save(&administration, request).await?;
        let facts = fixture.facts().await?;
        require(
            fact_count(&facts, "workspaces")? == 2,
            "workspace kinds merged quota identity",
        )?;
        for workspace in facts["workspaces"].as_array().ok_or("missing workspaces")? {
            require(
                workspace["workspace_id"] == fixture.channel.as_str(),
                "fixture equal identity text drifted",
            )?;
            require(
                workspace["charged_bytes"] == EXACT_TEXT.len() as u64,
                "workspace charged wrong actual bytes",
            )?;
        }
        require(
            fact_count(&facts, "records")? == 2 && fixture.object_count()? == 2,
            "separate workspace lost an actual registration",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn thirty_two_distinct_operations_use_lifetime_slots_and_thirty_third_is_refused() {
    with_fixture("ar_lifetime_32", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        for _ in 0..32 {
            fixture.save(&administration, fixture.request()).await?;
        }
        let before = fixture.facts().await?;
        require(
            fact_count(&before, "records")? == 32 && fixture.object_count()? == 32,
            "32 real operations did not create 32 actual objects",
        )?;
        require(
            before["runs"][0]["identity_count"] == 32,
            "Run identity count differs from actual operations",
        )?;
        require(
            before["workspaces"][0]["charged_bytes"] == EXACT_TEXT.len() as u64 * 32,
            "actual bytes double charged or lost",
        )?;
        require(
            matches!(
                administration
                    .save_run_message_text(&fixture.auth(), fixture.request())
                    .await,
                Err(ArtifactAdministrationError::PolicyRefused { .. })
            ),
            "33rd operation reused a lifetime slot",
        )?;
        require(
            fixture.facts().await? == before && fixture.object_count()? == 32,
            "33rd refusal left durable effect",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_source_hard_delete_keeps_saved_bytes_receipts_and_lifetime_count() {
    with_fixture("ar_source_delete", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let receipt = fixture.save(&administration, fixture.request()).await?;
        fixture.complete_source().await?;
        let before = fixture.facts().await?;
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
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .execute(
                "DELETE FROM public.threads WHERE thread_id=$1",
                &[&fixture.begin.command.thread_id.as_str()],
            )
            .await
            .map_err(|error| error.to_string())?;
        require(
            administration
                .get_metadata(&fixture.auth(), &receipt.artifact_id)
                .await
                == Err(ArtifactAdministrationError::NotVisible),
            "hard-deleted source remained readable",
        )?;
        require(
            fixture.facts().await? == before,
            "source delete cascaded or refunded artifact effect",
        )?;
        require(
            fixture.object_bytes(&receipt.artifact_id)? == EXACT_TEXT.as_bytes(),
            "source delete erased explicit-saved bytes",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_actor_wait_rechecks_generation_after_the_wait() {
    with_fixture("ar_actor_wait", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        fixture.set_all_pool_sessions_repeatable_read().await?;
        let before = fixture.facts().await?;
        let mut blocker = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let transaction = blocker
            .transaction()
            .await
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT id FROM public.users WHERE id='actor-a' FOR UPDATE",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        let task = {
            let administration = Arc::clone(&administration);
            let auth = fixture.auth();
            let request = fixture.request();
            tokio::spawn(async move { administration.save_run_message_text(&auth, request).await })
        };
        fixture.observe_actor_wait().await?;
        transaction
            .execute(
                "UPDATE public.users SET auth_generation=1 WHERE id='actor-a'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        transaction
            .commit()
            .await
            .map_err(|error| error.to_string())?;
        require(
            task.await.map_err(|error| error.to_string())?
                == Err(ArtifactAdministrationError::NotVisible),
            "stale pre-wait generation authorized IO",
        )?;
        require(
            fixture.facts().await? == before && fixture.object_count()? == 0,
            "revoked actor wait left bytes or effects",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn equal_database_identity_does_not_combine_foreign_pool_and_store_owner() {
    with_fixture("ar_foreign_pool", false, |fixture| async move {
        let store = fixture.store(ArtifactQuotaPolicy::default()).await?;
        let foreign = pool::connect(&fixture.config)
            .await
            .map_err(|error| error.to_string())?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                foreign.clone(),
                &DeploymentId::new(DEPLOYMENT),
                &TenantId::new(TENANT),
            )
            .await
            .map_err(|error| error.to_string())?,
        );
        let administration = PostgresArtifactAdministration::new(
            registry,
            store,
            ArtifactQuotaPolicy::default(),
            SecretBytes::new(vec![0x81; 32]),
        );
        require(
            administration.is_err(),
            "same dataset text granted foreign Pool authority",
        )?;
        require(
            fixture.object_count()? == 0 && fact_count(&fixture.facts().await?, "operations")? == 0,
            "foreign Pool composition began IO or admission",
        )?;
        foreign.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_permission_row_lock_refuses_reverse_order_without_waiting_for_actor() {
    with_fixture("ar_role_nowait", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let before = fixture.facts().await?;
        let mut blocker = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let transaction = blocker
            .transaction()
            .await
            .map_err(|error| error.to_string())?;
        // Match the existing People writer's relevant role-first row lock. Do not lock users:
        // the producer holds that row first and must NOWAIT this opposite-order permission row.
        transaction
            .execute("DELETE FROM public.user_roles WHERE user_id='actor-a'", &[])
            .await
            .map_err(|error| error.to_string())?;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            administration.save_run_message_text(&fixture.auth(), fixture.request()),
        )
        .await
        .map_err(|_| "role NOWAIT blocked in a reverse-order row-lock cycle".to_owned())?;
        require(
            outcome == Err(ArtifactAdministrationError::Unavailable),
            "locked permission row failed open or used stale visibility",
        )?;
        transaction
            .rollback()
            .await
            .map_err(|error| error.to_string())?;
        require(
            fixture.facts().await? == before && fixture.object_count()? == 0,
            "reverse-order refusal left admitted effects",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn authoritative_source_selector_role_and_json_text_failures_create_no_object() {
    with_fixture("ar_source_shape", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let before = fixture.facts().await?;
        let request = fixture.request();
        require(
            administration
                .save_run_message_text(&fixture.auth_as(OTHER, 0), request.clone())
                .await
                == Err(ArtifactAdministrationError::NotVisible),
            "admin actor saved another actor's source message",
        )?;
        let mut wrong = request.clone();
        wrong.source_message_id = "existing-selector-does-not-name-a-source-message".to_owned();
        require(
            administration
                .save_run_message_text(&fixture.auth(), wrong)
                .await
                == Err(ArtifactAdministrationError::NotVisible),
            "missing source message was accepted",
        )?;
        let other = fixture.second_channel_begin(OWNER).await?;
        let mut crossed = request.clone();
        crossed.source_run_id = other.command.run_id;
        require(
            administration
                .save_run_message_text(&fixture.auth(), crossed)
                .await
                == Err(ArtifactAdministrationError::NotVisible),
            "two real but mismatched source selectors were accepted",
        )?;
        // Every statement also rewrites the second channel Run's canonical source message: the
        // 0051 canonical-reverse guard refuses that first, then the deferred source-final check
        // refuses the invalid source unless its guard is off before the statement.
        const SOURCE_MUTATION: GuardRefusals = &[
            (
                CANONICAL_GUARD,
                "thread_history_writer_source_mutation_refused",
            ),
            (SOURCE_FINAL_GUARD, "thread_history_writer_binding_invalid"),
        ];
        for (content, refusals) in [
            (
                "UPDATE public.messages SET role='assistant' WHERE role='user'",
                SOURCE_MUTATION,
            ),
            (
                "UPDATE public.messages SET role='user',content='{}'::jsonb",
                SOURCE_MUTATION,
            ),
            (
                "UPDATE public.messages SET content='[]'::jsonb",
                SOURCE_MUTATION,
            ),
            (
                "UPDATE public.messages SET content='{\"text\":null}'::jsonb",
                SOURCE_MUTATION,
            ),
            (
                "UPDATE public.messages SET content='{\"text\":17}'::jsonb",
                SOURCE_MUTATION,
            ),
            (
                "UPDATE public.messages SET content='{\"text\":\"\"}'::jsonb",
                SOURCE_MUTATION,
            ),
        ] {
            fixture.owned_message_sql(content, refusals).await?;
            require(
                administration
                    .save_run_message_text(&fixture.auth(), request.clone())
                    .await
                    == Err(ArtifactAdministrationError::NotVisible),
                "non-user or absent/empty logical text manufactured artifact",
            )?;
            require(
                fixture.facts().await? == before && fixture.object_count()? == 0,
                "invalid source left artifact effects",
            )?;
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn wrong_expected_digest_is_a_prewrite_refusal_without_fake_partial_metadata() {
    with_fixture("ar_wrong_digest", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let before = fixture.facts().await?;
        let mut request = fixture.request();
        request.expected_sha256 = "a".repeat(64);
        require(
            administration
                .save_run_message_text(&fixture.auth(), request)
                .await
                == Err(ArtifactAdministrationError::InvalidInput {
                    field: "expectedSha256",
                }),
            "wrong expected digest was treated as actual verified bytes",
        )?;
        require(
            fixture.facts().await? == before && fixture.object_count()? == 0,
            "digest mismatch created a fake failed_partial or quota debit",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn real_staging_permission_failure_does_not_invent_metadata_for_absent_bytes() {
    with_fixture("ar_stage_absence", false, |fixture| async move {
        use std::os::unix::fs::PermissionsExt as _;

        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let staging = fixture.root.0.join("staging");
        let permissions = std::fs::metadata(&staging)
            .map_err(|error| error.to_string())?
            .permissions();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o000))
            .map_err(|error| error.to_string())?;
        let outcome = administration
            .save_run_message_text(&fixture.auth(), fixture.request())
            .await;
        // Always restore only this owned fixture directory before assertions or root cleanup.
        std::fs::set_permissions(&staging, permissions).map_err(|error| error.to_string())?;
        require(
            outcome.is_err(),
            "permission-denied actual staging IO produced a positive receipt",
        )?;
        let facts = fixture.facts().await?;
        require(
            fact_count(&facts, "operations")? == 1
                && fact_count(&facts, "records")? == 0
                && fact_count(&facts, "receipts")? == 0
                && fact_count(&facts, "audit")? == 0,
            "actual absent file manufactured failed_partial metadata or a positive fact",
        )?;
        require(
            fixture.object_count()? == 0,
            "staging permission failure installed bytes",
        )?;
        let operation = &facts["operations"][0];
        require(
            operation["actual_byte_length"].is_null() && operation["actual_sha256"].is_null(),
            "absence was represented by fabricated byte length or expected hash",
        )?;
        require(
            operation["state"] != "available",
            "actual failed IO published available",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn opaque_512_byte_source_message_identity_is_not_narrowed_to_audit_id() {
    with_fixture("ar_message_512", false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let message_id = format!("MiX%{}", "m".repeat(508));
        // Keep the actual Begin message's text/role/run/actor facts. Only its opaque fixture ID
        // is selected at the frozen 512-byte boundary; this is not a second message producer.
        fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .execute(
                "UPDATE public.messages SET message_id=$2 WHERE message_id=$1",
                &[&fixture.message_id(), &message_id],
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut request = fixture.request();
        request.source_message_id = message_id.clone();
        let receipt = fixture.save(&administration, request).await?;
        require(
            receipt.source_message_id == message_id && message_id.len() == 512,
            "opaque source ID was normalized or narrowed",
        )?;
        let facts = fixture.facts().await?;
        require(
            fact_count(&facts, "audit")? == 1
                && !facts["audit"][0]["payload"]
                    .to_string()
                    .contains(&message_id),
            "artifact.saved attempted to pack source512 into AuditIdentifier256",
        )?;
        require(
            fixture.object_bytes(&receipt.artifact_id)? == EXACT_TEXT.as_bytes(),
            "bounded source identity changed bytes",
        )?;
        Ok(())
    })
    .await;
}

/// Only the owned test PostgreSQL TCP leg is proxied. Drop or hold the selected backend COMMIT
/// CommandComplete after the server actually committed; SQL and durable effects remain real.
struct CommitAckProxy {
    port: u16,
    remaining: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    held: Arc<AtomicUsize>,
    hold_at_commit: Arc<tokio::sync::Mutex<Option<CommitHold>>>,
    task: tokio::task::JoinHandle<()>,
}

struct CommitHold {
    arrived: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

struct HeldCommitAck {
    arrived: tokio::sync::oneshot::Receiver<()>,
    release: tokio::sync::oneshot::Sender<()>,
}

impl HeldCommitAck {
    async fn wait(&mut self) -> Result<(), String> {
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.arrived)
            .await
            .map_err(|_| "owned proxy did not observe the selected committed ACK".to_owned())?
            .map_err(|_| "owned proxy ACK arrival controller closed".to_owned())
    }

    fn release(self) -> Result<(), String> {
        self.release
            .send(())
            .map_err(|()| "owned proxy ACK release receiver closed".to_owned())
    }
}

impl CommitAckProxy {
    async fn start(host: String, port: u16) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let proxy_port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let remaining = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicUsize::new(0));
        let hold_at_commit = Arc::new(tokio::sync::Mutex::new(None::<CommitHold>));
        let countdown = Arc::clone(&remaining);
        let count = Arc::clone(&dropped);
        let held_count = Arc::clone(&held);
        let hold_controller = Arc::clone(&hold_at_commit);
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                    break;
                };
                let countdown = Arc::clone(&countdown);
                let count = Arc::clone(&count);
                let held_count = Arc::clone(&held_count);
                let hold_controller = Arc::clone(&hold_controller);
                children.spawn(async move {
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let backend = async {
                        loop {
                            let kind = server_read.read_u8().await?;
                            let length = server_read.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&length) {
                                return Err(std::io::Error::other("invalid owned proxy frame"));
                            }
                            let mut payload = vec![0; (length - 4) as usize];
                            server_read.read_exact(&mut payload).await?;
                            if kind == b'C' && payload == b"COMMIT\0" {
                                let previous = countdown.fetch_update(
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                    |value| value.checked_sub(1),
                                );
                                if previous == Ok(1) {
                                    let hold = hold_controller.lock().await.take();
                                    if let Some(hold) = hold {
                                        held_count.fetch_add(1, Ordering::SeqCst);
                                        hold.arrived.send(()).map_err(|()| {
                                            std::io::Error::other("owned ACK controller closed")
                                        })?;
                                        tokio::time::timeout(
                                            std::time::Duration::from_secs(10),
                                            hold.release,
                                        )
                                        .await
                                        .map_err(|_| {
                                            std::io::Error::other("owned ACK hold timed out")
                                        })?
                                        .map_err(|_| {
                                            std::io::Error::other("owned ACK release closed")
                                        })?;
                                        // Forward this exact successful backend frame only after
                                        // the direct observer's real committed mutation.
                                    } else {
                                        count.fetch_add(1, Ordering::SeqCst);
                                        return Ok::<(), std::io::Error>(());
                                    }
                                }
                            }
                            client_write.write_u8(kind).await?;
                            client_write.write_u32(length).await?;
                            client_write.write_all(&payload).await?;
                        }
                    };
                    tokio::select! {
                        _ = tokio::io::copy(&mut client_read, &mut server_write) => {},
                        _ = backend => {},
                    }
                });
            }
        });
        Ok(Self {
            port: proxy_port,
            remaining,
            dropped,
            held,
            hold_at_commit,
            task,
        })
    }

    fn arm(&self, ordinal: usize) {
        self.remaining.store(ordinal, Ordering::SeqCst);
    }

    async fn hold(&self, ordinal: usize) -> Result<HeldCommitAck, String> {
        require(ordinal > 0, "owned ACK ordinal must be positive")?;
        let (arrived_sender, arrived) = tokio::sync::oneshot::channel();
        let (release, release_receiver) = tokio::sync::oneshot::channel();
        let mut controller = self.hold_at_commit.lock().await;
        require(controller.is_none(), "owned ACK hold already armed")?;
        *controller = Some(CommitHold {
            arrived: arrived_sender,
            release: release_receiver,
        });
        self.remaining.store(ordinal, Ordering::SeqCst);
        Ok(HeldCommitAck { arrived, release })
    }
}

impl Drop for CommitAckProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn with_ack_loss<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Fixture, CommitAckProxy) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(tag);
    with_temp_database(&admin, tag, |config| async move {
        let proxy = CommitAckProxy::start(config.host.clone(), config.port).await?;
        let mut proxied = config;
        proxied.host = "127.0.0.1".to_owned();
        proxied.port = proxy.port;
        body(Fixture::new(proxied, false).await?, proxy).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn admission_ack_loss_keeps_charge_without_granting_io_or_a_second_operation() {
    with_ack_loss("ar_admission_ack", |fixture, proxy| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let request = fixture.request();
        proxy.arm(1);
        require(
            administration
                .save_run_message_text(&fixture.auth(), request.clone())
                .await
                == Err(ArtifactAdministrationError::CommitUnknown),
            "lost admission ACK became known rollback or IO permission",
        )?;
        require(
            proxy.dropped.load(Ordering::SeqCst) == 1,
            "proxy did not drop a real COMMIT completion",
        )?;
        let facts = fixture.facts().await?;
        require(
            fact_count(&facts, "operations")? == 1
                && fact_count(&facts, "records")? == 0
                && fact_count(&facts, "receipts")? == 0
                && fact_count(&facts, "audit")? == 0,
            "admission uncertainty fabricated or removed a business effect",
        )?;
        require(
            facts["runs"][0]["identity_count"] == 1
                && facts["workspaces"][0]["charged_bytes"] == EXACT_TEXT.len() as u64
                && fixture.object_count()? == 0,
            "unknown admission released charge or started IO",
        )?;
        require(
            matches!(
                administration
                    .save_run_message_text(&fixture.auth(), request)
                    .await,
                Err(ArtifactAdministrationError::CommitUnknown
                    | ArtifactAdministrationError::Unavailable)
            ),
            "unresolved admission observation blindly retried writing",
        )?;
        require(
            fixture.facts().await? == facts && fixture.object_count()? == 0,
            "unknown admission replay mutated reserved facts",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn io_fence_ack_loss_does_not_start_io_or_refund_charge() {
    with_ack_loss("ar_io_fence_ack", |fixture, proxy| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let request = fixture.request();
        proxy.arm(2);
        require(
            administration
                .save_run_message_text(&fixture.auth(), request.clone())
                .await
                == Err(ArtifactAdministrationError::CommitUnknown),
            "lost IO-start ACK authorized IO",
        )?;
        require(
            proxy.dropped.load(Ordering::SeqCst) == 1,
            "proxy did not drop the selected real COMMIT",
        )?;
        let facts = fixture.facts().await?;
        require(
            fact_count(&facts, "operations")? == 1
                && fact_count(&facts, "records")? == 0
                && fixture.object_count()? == 0,
            "unknown IO-start wrote bytes or a record",
        )?;
        require(
            facts["runs"][0]["identity_count"] == 1
                && facts["workspaces"][0]["charged_bytes"] == EXACT_TEXT.len() as u64,
            "unknown IO-start refunded original reservation",
        )?;
        require(
            administration
                .save_run_message_text(&fixture.auth(), request)
                .await
                .is_err(),
            "durable unresolved fence resumed IO",
        )?;
        require(
            fixture.facts().await? == facts && fixture.object_count()? == 0,
            "unresolved fence observation mutated effects",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn final_commit_ack_loss_retains_actual_blob_and_current_positive_receipt() {
    with_ack_loss("ar_final_ack", |fixture, proxy| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let request = fixture.request();
        proxy.arm(3);
        require(
            administration
                .save_run_message_text(&fixture.auth(), request.clone())
                .await
                == Err(ArtifactAdministrationError::CommitUnknown),
            "lost registration ACK became known negative result",
        )?;
        require(
            proxy.dropped.load(Ordering::SeqCst) == 1,
            "proxy did not drop the final real COMMIT",
        )?;
        let facts = fixture.facts().await?;
        for field in ["operations", "records", "receipts", "audit"] {
            require(
                fact_count(&facts, field)? == 1,
                "committed unknown lost an atomic positive fact",
            )?;
        }
        require(
            facts["records"][0]["status"] == "available",
            "lost ACK downgraded committed bytes to failed_partial",
        )?;
        let receipt = fixture.save(&administration, request).await?;
        require(
            fixture.object_bytes(&receipt.artifact_id)? == EXACT_TEXT.as_bytes(),
            "lost ACK erased or rewrote installed bytes",
        )?;
        require(
            fixture.facts().await? == facts && fixture.object_count()? == 1,
            "positive observation recharged or wrote a second artifact",
        )?;
        Ok(())
    })
    .await;
}

#[derive(Clone, Copy)]
enum MutationAtHeldIoCommit {
    RevokeActorGeneration,
    HardDeleteMessage,
}

#[derive(Debug, PartialEq, Eq)]
struct ActualObjectFingerprint {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    byte_length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn object_fingerprint(
    fixture: &Fixture,
    artifact_id: &str,
) -> Result<ActualObjectFingerprint, String> {
    use std::os::unix::fs::MetadataExt as _;

    let path = fixture.root.0.join("objects").join(artifact_id);
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file(),
        "actual owned object is not a regular file",
    )?;
    Ok(ActualObjectFingerprint {
        bytes: std::fs::read(path).map_err(|error| error.to_string())?,
        device: metadata.dev(),
        inode: metadata.ino(),
        byte_length: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

async fn mutate_source_at_real_held_io_commit(tag: &str, mutation: MutationAtHeldIoCommit) {
    let admin = admin_config(tag);
    with_temp_database(&admin, tag, |config| async move {
        // This independent observer/controller connects directly to the same owned database.
        // Only the real producer's Pool goes through the ACK forwarding control.
        let observer = pool::connect(&config.clone().with_max_pool_size(3))
            .await
            .map_err(|error| error.to_string())?;
        let proxy = CommitAckProxy::start(config.host.clone(), config.port).await?;
        let mut proxied = config;
        proxied.host = "127.0.0.1".to_owned();
        proxied.port = proxy.port;
        let fixture = Fixture::new(proxied, false).await?;
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let auth = fixture.auth();
        let request = fixture.request();
        let mut held = proxy.hold(2).await?;
        let save = administration.save_run_message_text(&auth, request.clone());
        tokio::pin!(save);
        tokio::select! {
            _ = &mut save => return Err("save completed before the selected real IO ACK barrier".to_owned()),
            arrived = held.wait() => arrived?,
        }
        require(
            proxy.held.load(Ordering::SeqCst) == 1
                && proxy.dropped.load(Ordering::SeqCst) == 0,
            "owned ACK control did not hold exactly one successful real COMMIT frame",
        )?;
        let fenced = fixture.facts_using(&observer).await?;
        require(
            fact_count(&fenced, "operations")? == 1
                && fenced["operations"][0]["state"] == "io_started"
                && fenced["operations"][0]["request_id"] == request.request_id
                && fenced["operations"][0]["expected_sha256"] == sha256(EXACT_TEXT)
                && fenced["operations"][0]["expected_bytes"] == EXACT_TEXT.len() as u64
                && fenced["runs"][0]["identity_count"] == 1
                && fenced["workspaces"][0]["charged_bytes"] == EXACT_TEXT.len() as u64,
            "direct observer did not prove the selected durable IO fence and original reservation",
        )?;
        for table in ["records", "receipts", "audit"] {
            require(
                fact_count(&fenced, table)? == 0,
                "IO fence already manufactured a positive business fact",
            )?;
        }
        require(
            fixture.object_count()? == 0
                && std::fs::read_dir(fixture.root.0.join("staging"))
                    .map_err(|error| error.to_string())?
                    .next()
                    .is_none(),
            "real IO began before its actual successful ACK was forwarded",
        )?;
        let artifact_id = fenced["operations"][0]["artifact_id"]
            .as_str()
            .ok_or("direct observer did not find the actual reserved artifact ID")?
            .to_owned();
        let controller = observer.get().await.map_err(|error| error.to_string())?;
        controller
            .batch_execute("SET lock_timeout='2s'; SET statement_timeout='2s'")
            .await
            .map_err(|error| error.to_string())?;
        match mutation {
            MutationAtHeldIoCommit::RevokeActorGeneration => {
                let affected = controller
                    .execute(
                        "UPDATE public.users SET auth_generation=auth_generation+1 WHERE id=$1",
                        &[&OWNER],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let actual_generation: i64 = controller
                    .query_one("SELECT auth_generation FROM public.users WHERE id=$1", &[&OWNER])
                    .await
                    .map_err(|error| error.to_string())?
                    .get(0);
                require(
                    affected == 1 && actual_generation == 1,
                    "direct controller did not commit the actual actor generation revocation",
                )?;
            }
            MutationAtHeldIoCommit::HardDeleteMessage => {
                let affected = controller
                    .execute(
                        "DELETE FROM public.messages WHERE message_id=$1",
                        &[&fixture.message_id()],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let remains: bool = controller
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM public.messages WHERE message_id=$1)",
                        &[&fixture.message_id()],
                    )
                    .await
                    .map_err(|error| error.to_string())?
                    .get(0);
                require(
                    affected == 1 && !remains,
                    "direct controller did not harddelete the actual Begin producer message",
                )?;
            }
        }
        drop(controller);
        held.release()?;
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(15), &mut save)
            .await
            .map_err(|_| "post-IO source revalidation did not complete".to_owned())?;
        require(
            outcome == Err(ArtifactAdministrationError::Unavailable),
            "changed post-IO authority fabricated available or a positive receipt",
        )?;
        let facts = fixture.facts_using(&observer).await?;
        require(
            fact_count(&facts, "operations")? == 1
                && facts["operations"][0]["state"] == "unresolved"
                && facts["operations"][0]["artifact_id"] == artifact_id
                && facts["operations"][0]["charged_bytes"] == EXACT_TEXT.len() as u64
                && facts["runs"][0]["identity_count"] == 1
                && facts["workspaces"][0]["charged_bytes"] == EXACT_TEXT.len() as u64,
            "post-IO revocation erased actual bytes, identity or original charge",
        )?;
        for table in ["records", "receipts", "audit"] {
            require(
                fact_count(&facts, table)? == 0,
                "post-IO changed source published a record, receipt or artifact.saved audit",
            )?;
        }
        let actual = object_fingerprint(&fixture, &artifact_id)?;
        let actual_sha256 = format!("{:x}", Sha256::digest(&actual.bytes));
        let operation = &facts["operations"][0];
        require(
            actual.bytes == EXACT_TEXT.as_bytes()
                && actual.byte_length == EXACT_TEXT.len() as u64
                && fixture.object_count()? == 1
                && operation["actual_absent"] == false
                && operation["actual_byte_length"] == actual.byte_length
                && operation["actual_sha256"] == actual_sha256
                && operation["actual_location"] == "object"
                && operation["observation_phase"] == "installed",
            "post-IO private facts used expected data instead of independently read actual bytes",
        )?;
        require(
            administration
                .save_run_message_text(&auth, request.clone())
                .await
                == Err(ArtifactAdministrationError::NotVisible),
            "old or deleted source received a positive retry",
        )?;
        if matches!(mutation, MutationAtHeldIoCommit::RevokeActorGeneration) {
            require(
                matches!(
                    administration
                        .save_run_message_text(&fixture.auth_as(OWNER, 1), request)
                        .await,
                    Err(ArtifactAdministrationError::Unavailable
                        | ArtifactAdministrationError::CommitUnknown)
                ),
                "fresh actor generation resumed the original unresolved IO operation",
            )?;
        }
        require(
            fixture.facts_using(&observer).await? == facts
                && fixture.object_count()? == 1
                && object_fingerprint(&fixture, &artifact_id)? == actual,
            "post-IO retry wrote or changed the actual object or recharged reserved facts",
        )?;
        require(
            proxy.held.load(Ordering::SeqCst) == 1
                && proxy.dropped.load(Ordering::SeqCst) == 0,
            "held successful ACK was later silently dropped or held again",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_io_fence_ack_hold_actor_revocation_retains_only_accurate_private_bytes() {
    mutate_source_at_real_held_io_commit(
        "ar_post_io_revoke",
        MutationAtHeldIoCommit::RevokeActorGeneration,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_io_fence_ack_hold_source_harddelete_retains_only_accurate_private_bytes() {
    mutate_source_at_real_held_io_commit(
        "ar_post_io_delete",
        MutationAtHeldIoCommit::HardDeleteMessage,
    )
    .await;
}

#[derive(Clone, Copy)]
enum LockedInvisibleTarget {
    NonownerRun,
    ForeignMessageWithOwnedRun,
}

async fn locked_invisible_source_is_still_not_visible(tag: &str, target: LockedInvisibleTarget) {
    with_fixture(tag, false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let mut request = fixture.request();
        let auth = match target {
            LockedInvisibleTarget::NonownerRun => fixture.auth_as(OTHER, 0),
            LockedInvisibleTarget::ForeignMessageWithOwnedRun => {
                let foreign = fixture.second_channel_begin(OTHER).await?;
                request.source_message_id = format!("{}:input", foreign.command.run_id.as_str());
                fixture.auth()
            }
        };
        let before = fixture.facts().await?;
        let mut controller = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let transaction = controller
            .transaction()
            .await
            .map_err(|error| error.to_string())?;
        transaction
            .batch_execute("SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='2s'")
            .await
            .map_err(|error| error.to_string())?;
        // Await the actual row lock before invoking the producer. There is no sleep or race:
        // its 404 must be established before attempting NOWAIT on this unowned/mismatched row.
        match target {
            LockedInvisibleTarget::NonownerRun => {
                let locked: String = transaction
                    .query_one(
                        "SELECT run_id FROM public.runs WHERE run_id=$1 FOR UPDATE",
                        &[&request.source_run_id.as_str()],
                    )
                    .await
                    .map_err(|error| error.to_string())?
                    .get(0);
                require(
                    locked == request.source_run_id.as_str(),
                    "controller did not lock the selected actual nonowned run",
                )?;
            }
            LockedInvisibleTarget::ForeignMessageWithOwnedRun => {
                let locked: String = transaction
                    .query_one(
                        "SELECT message_id FROM public.messages WHERE message_id=$1 FOR UPDATE",
                        &[&request.source_message_id],
                    )
                    .await
                    .map_err(|error| error.to_string())?
                    .get(0);
                require(
                    locked == request.source_message_id,
                    "controller did not lock the real foreign producer message",
                )?;
            }
        }
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            administration.save_run_message_text(&auth, request.clone()),
        )
        .await
        .map_err(|_| {
            "producer waited on a source outside the selected actor/run relation".to_owned()
        })?;
        require(
            outcome == Err(ArtifactAdministrationError::NotVisible),
            "locked invisible source leaked a lock-dependent 503 or was admitted",
        )?;
        require(
            fixture.facts().await? == before && fixture.object_count()? == 0,
            "locked invisible source charged, created an operation or performed actual IO",
        )?;
        transaction
            .rollback()
            .await
            .map_err(|error| error.to_string())?;
        require(
            administration.save_run_message_text(&auth, request).await
                == Err(ArtifactAdministrationError::NotVisible),
            "same invisible source changed its result after releasing its actual row lock",
        )?;
        require(
            fixture.facts().await? == before && fixture.object_count()? == 0,
            "unlocked invisible source created an artifact effect",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_nonowner_run_update_lock_does_not_change_not_visible_into_unavailable() {
    locked_invisible_source_is_still_not_visible(
        "ar_locked_nonowner",
        LockedInvisibleTarget::NonownerRun,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_foreign_message_update_lock_with_owned_run_remains_not_visible() {
    locked_invisible_source_is_still_not_visible(
        "ar_locked_foreign_message",
        LockedInvisibleTarget::ForeignMessageWithOwnedRun,
    )
    .await;
}

#[derive(Clone, Copy)]
enum SavedMessageMutation {
    HardDelete,
    ForeignActor,
    AssistantRole,
    LogicalText,
}

async fn current_run_thread_owner_facts(fixture: &Fixture) -> Result<Value, String> {
    fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?
        .query_one(
            "SELECT jsonb_build_object(
               'run',to_jsonb(r),'thread',to_jsonb(t),'owner',to_jsonb(u),
               'roles',(SELECT coalesce(jsonb_agg(to_jsonb(ur) ORDER BY ur.role),'[]')
                        FROM public.user_roles ur WHERE ur.user_id=u.id))
             FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id
             JOIN public.users u ON u.id=r.actor_id
             WHERE r.run_id=$1 AND r.thread_id=$2 AND r.actor_id=$3",
            &[
                &fixture.begin.command.run_id.as_str(),
                &fixture.begin.command.thread_id.as_str(),
                &OWNER,
            ],
        )
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

async fn actual_saved_message_current_relation_controls_visibility(
    tag: &str,
    mutation: SavedMessageMutation,
) {
    with_fixture(tag, false, |fixture| async move {
        let administration = fixture
            .administration(ArtifactQuotaPolicy::default())
            .await?;
        let auth = fixture.auth();
        let request = fixture.request();
        let receipt = fixture.save(&administration, request.clone()).await?;
        let metadata = administration
            .get_metadata(&auth, &receipt.artifact_id)
            .await
            .map_err(|error| error.to_string())?;
        let ArtifactMetadata::Available(record) = &metadata else {
            return Err("actual saved message did not initially have available metadata".to_owned());
        };
        let object = object_fingerprint(&fixture, &receipt.artifact_id)?;
        let actual_sha256 = format!("{:x}", Sha256::digest(&object.bytes));
        require(
            object.bytes == EXACT_TEXT.as_bytes()
                && object.byte_length == EXACT_TEXT.len() as u64
                && record.byte_length == object.byte_length
                && record.sha256 == actual_sha256
                && record.retention_class == ArtifactRetentionClass::ExplicitSaved,
            "initial saved metadata was not bound to independently observed actual bytes",
        )?;
        let artifact_facts = fixture.facts().await?;
        // These are the six named registration fact sets. Source Run quota identity remains
        // occupied once against the lifetime 32 limit; deletion is not an artifact producer.
        for table in ["operations", "records", "receipts", "workspaces", "runs", "audit"] {
            require(
                fact_count(&artifact_facts, table)? == 1,
                "initial actual save did not create exactly one of each named artifact fact",
            )?;
        }
        require(
            artifact_facts["records"][0]["status"] == "available"
                && artifact_facts["records"][0]["source_message_id"] == fixture.message_id()
                && artifact_facts["records"][0]["sha256"] == actual_sha256
                && artifact_facts["receipts"][0]["operation_id"] == receipt.operation_id
                && artifact_facts["receipts"][0]["artifact_id"] == receipt.artifact_id
                && artifact_facts["runs"][0]["identity_count"] == 1
                && artifact_facts["workspaces"][0]["charged_bytes"] == object.byte_length
                && fixture.object_count()? == 1,
            "initial saved source identities, receipt, lifetime charge or object count differ",
        )?;
        let authority_facts = current_run_thread_owner_facts(&fixture).await?;
        require(
            authority_facts["run"]["actor_id"] == OWNER
                && authority_facts["run"]["thread_id"] == fixture.begin.command.thread_id.as_str()
                && authority_facts["thread"]["created_by"] == OWNER
                && authority_facts["owner"]["id"] == OWNER
                && authority_facts["owner"]["auth_generation"] == 0,
            "real source Run, Thread and current owner were not present before message mutation",
        )?;
        let controller = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let changed_text = "q".repeat(EXACT_TEXT.len());
        let affected = match mutation {
            SavedMessageMutation::HardDelete => {
                controller
                    .execute(
                        "DELETE FROM public.messages WHERE message_id=$1",
                        &[&fixture.message_id()],
                    )
                    .await
            }
            SavedMessageMutation::ForeignActor => {
                controller
                    .execute(
                        "UPDATE public.messages SET actor_id=$2 WHERE message_id=$1",
                        &[&fixture.message_id(), &OTHER],
                    )
                    .await
            }
            SavedMessageMutation::AssistantRole => {
                controller
                    .execute(
                        "UPDATE public.messages SET role='assistant' WHERE message_id=$1",
                        &[&fixture.message_id()],
                    )
                    .await
            }
            SavedMessageMutation::LogicalText => {
                // Only this actual Begin message is changed. Equal UTF-8 byte length isolates
                // source content from the original immutable artifact's byte/hash metadata.
                controller
                    .execute(
                        "UPDATE public.messages SET content=jsonb_set(content,'{text}',to_jsonb($2::text)),
                         search_text=$2 WHERE message_id=$1",
                        &[&fixture.message_id(), &changed_text],
                    )
                    .await
            }
        }
        .map_err(|error| error.to_string())?;
        require(affected == 1, "controller did not mutate exactly the actual source message")?;
        let source = controller
            .query_opt(
                "SELECT to_jsonb(m) FROM public.messages m WHERE message_id=$1",
                &[&fixture.message_id()],
            )
            .await
            .map_err(|error| error.to_string())?
            .map(|row| row.try_get::<_, Value>(0))
            .transpose()
            .map_err(|error| error.to_string())?;
        match mutation {
            SavedMessageMutation::HardDelete => require(source.is_none(), "source message was not really harddeleted")?,
            SavedMessageMutation::ForeignActor => require(source.as_ref().is_some_and(|m| m["actor_id"]==OTHER && m["role"]=="user"), "source message actor mutation was not observed")?,
            SavedMessageMutation::AssistantRole => require(source.as_ref().is_some_and(|m| m["actor_id"]==OWNER && m["role"]=="assistant"), "source message role mutation was not observed")?,
            SavedMessageMutation::LogicalText => require(source.as_ref().is_some_and(|m| m["actor_id"]==OWNER && m["role"]=="user" && m["content"]["text"]==changed_text), "source message logical text mutation was not observed")?,
        }
        drop(controller);
        require(
            current_run_thread_owner_facts(&fixture).await? == authority_facts,
            "message-only mutation changed the actual source Run, Thread or current owner",
        )?;
        let current_metadata = administration.get_metadata(&auth, &receipt.artifact_id).await;
        if matches!(mutation, SavedMessageMutation::LogicalText) {
            require(
                current_metadata == Ok(metadata),
                "metadata re-read mutable source text instead of the original saved byte facts",
            )?;
        } else {
            require(
                current_metadata == Err(ArtifactAdministrationError::NotVisible),
                "metadata exposed a deleted, foreign-actor or non-user source message",
            )?;
        }
        require(
            administration.save_run_message_text(&auth, request).await
                == Err(ArtifactAdministrationError::NotVisible),
            "original save replay bypassed the current exact source-message relation or digest",
        )?;
        require(
            fixture.facts().await? == artifact_facts
                && fixture.object_count()? == 1
                && object_fingerprint(&fixture, &receipt.artifact_id)? == object
                && current_run_thread_owner_facts(&fixture).await? == authority_facts,
            "message mutation or denied replay changed saved records, receipt, once-audit, quota or actual object fingerprint",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn only_actual_source_message_harddelete_hides_metadata_and_replay_without_erasing_saved_facts()
 {
    actual_saved_message_current_relation_controls_visibility(
        "ar_saved_message_delete",
        SavedMessageMutation::HardDelete,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_source_message_foreign_actor_hides_metadata_and_replay_without_changing_saved_facts()
 {
    actual_saved_message_current_relation_controls_visibility(
        "ar_saved_message_actor",
        SavedMessageMutation::ForeignActor,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_source_message_assistant_role_hides_metadata_and_replay_without_changing_saved_facts()
 {
    actual_saved_message_current_relation_controls_visibility(
        "ar_saved_message_role",
        SavedMessageMutation::AssistantRole,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_source_message_text_change_keeps_original_saved_metadata_and_bytes() {
    actual_saved_message_current_relation_controls_visibility(
        "ar_saved_message_text",
        SavedMessageMutation::LogicalText,
    )
    .await;
}
