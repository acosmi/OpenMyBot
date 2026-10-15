//! Owned-PG metadata tests with a trusted-test issuer. Genuine host proof is tested separately.
#![cfg(all(unix, feature = "server-runtime"))]

use openbot_application::{ArtifactAdministration, BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifacts::{
    ArtifactRegistrationReceipt, GetSourceRunArtifactIds, SaveRunMessageTextArtifact,
    SourceRunArtifactIds,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_contracts::request_binding::*;
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::session::SessionLifetimePolicy;
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_read_authority::PostgresArtifactReadAuthority;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use std::fs::{self, File};
use std::future::Future;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Instant;
use time::OffsetDateTime;
use uuid::Uuid;

mod harness;
const DEPLOYMENT: &str = "artifact-read-owned-deployment";
const TENANT: &str = "artifact-read-owned-tenant";
const OWNER: &str = "read-owner";
const OTHER: &str = "read-other";
const EXACT: &str = "  SOURCE_IDS_OWNED_MESSAGE\n成果 café 🦀\t  ";
fn require(ok: bool, msg: &'static str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(msg.to_owned()) }
}
struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("openbot-source-ids-{}", Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| e.to_string())?;
        Ok(Self(fs::canonicalize(path).map_err(|e| e.to_string())?))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = fs::remove_dir_all(&self.0).is_ok();
        let absent = !self.0.exists();
        eprintln!("ARTIFACT_SOURCE_IDS_ROOT_CLEANUP removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(removed && absent, "owned read-root cleanup failed");
        }
    }
}

struct Fixture {
    config: DatabaseConfig,
    pool: Pool,
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    administration: Arc<PostgresArtifactAdministration>,
    _lease: RequestBindingOwnerLease,
    issuer: RequestBindingIssuer,
    created: OffsetDateTime,
    begin: BeginThreadRunRequest,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig, channel: bool) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&client).await.map_err(|e| e.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|e| e.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation,groups) VALUES
              ('read-owner','read-owner@example.test',0,ARRAY['read-fixture']),
              ('read-other','read-other@example.test',0,ARRAY['read-fixture']);
              INSERT INTO public.user_roles(user_id,role) VALUES('read-owner','user'),('read-other','admin');
              INSERT INTO public.agents(id,name,type,configuration) VALUES('read-bot','Read fixture','built_in','{}');
              INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('read-bot','read-owner','Read fixture','fixture','fixture','public');
              INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                VALUES('00000000-0000-4000-8000-000000000051','artifact-read-owned-tenant','fixture','fixture');
              INSERT INTO public.channels(id,name,description,allowed_groups)
                VALUES('read-channel','Read fixture','fixture',ARRAY['read-fixture']);
              INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('read-channel','read-owner'),('read-channel','read-other');
              INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('read-channel','read-bot');")
                .await.map_err(|e| e.to_string())?;
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|e| e.to_string())?,
        );
        let begin = BeginThreadRunRequest {
            auth_generation: AuthGeneration::new(0),
            deployment,
            tenant,
            actor: ActorId::new(OWNER),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEPLOYMENT))
                    .mint_from_entropy([9; 16]),
                run_id: RunId::new("read/source%成果"),
                bot_id: BotId::new("read-bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("read-channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: EXACT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "source-ids-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let root = OwnedRoot::new()?;
        let policy = ArtifactQuotaPolicy::default();
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                File::open(&root.0).map_err(|e| e.to_string())?,
                Arc::clone(&registry),
                policy,
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let administration = Arc::new(
            PostgresArtifactAdministration::new(
                Arc::clone(&registry),
                Arc::clone(&store),
                policy,
                SecretBytes::new(vec![0x83; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let created = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let expires = created + time::Duration::hours(1);
        pool.get().await.map_err(|e| e.to_string())?.execute(
            "INSERT INTO public.sessions(id,user_id,token,created_at,updated_at,expires_at,auth_generation) VALUES($1,$2,$3,$4,$4,$5,0),($6,$2,$7,$4,$4,$5,0)",
            &[&"core-read-session-a", &OWNER, &"owned-test-session-column-a", &created, &expires, &"core-read-session-b", &"owned-test-session-column-b"],
        ).await.map_err(|e| e.to_string())?;
        // PostgreSQL stores microseconds. The immutable epoch is copied from the actual row,
        // rather than comparing a pre-insert nanosecond clock value against that row.
        let created: OffsetDateTime = pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT created_at FROM public.sessions WHERE id='core-read-session-a'",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let (_lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        administration.read_authority();
        Ok(Self {
            config,
            pool,
            registry,
            store,
            administration,
            _lease,
            issuer,
            created,
            begin,
            root,
        })
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
    fn auth(&self) -> AuthContext {
        self.session_auth("core-read-session-a", "owned-test-session-column-a")
    }
    fn session_auth(&self, id: &str, token: &str) -> AuthContext {
        let auth = self.auth_as(OWNER, 0);
        let guard = CoreSessionGuard {
            issuer: self.issuer.clone(),
            authority: Arc::downgrade(&self.administration.read_authority()),
            lifetime: lifetime(),
        };
        let epoch = ServerSessionBindingIdentity::from_verified_row(
            id.into(),
            auth.actor().clone(),
            token.into(),
            self.created,
            auth.auth_generation(),
        );
        let binding = self
            .issuer
            .bind_server_session(&auth, epoch, Arc::new(guard))
            .expect("owned real-row epoch");
        auth.with_verified_request_binding(binding)
            .expect("owned attachment")
    }
    fn message_id(&self) -> String {
        format!("{}:input", self.begin.command.run_id.as_str())
    }
    async fn save(&self) -> Result<ArtifactRegistrationReceipt, String> {
        self.administration
            .save_run_message_text(
                &self.auth(),
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: self.begin.command.thread_id.clone(),
                    source_run_id: self.begin.command.run_id.clone(),
                    source_message_id: self.message_id(),
                    expected_sha256: Sha256Digest::of(EXACT.as_bytes()).to_hex(),
                },
            )
            .await
            .map_err(|e| e.to_string())
    }
    fn input(&self) -> GetSourceRunArtifactIds {
        GetSourceRunArtifactIds {
            source_thread_id: self.begin.command.thread_id.clone(),
            source_run_id: self.begin.command.run_id.clone(),
        }
    }
    async fn ids(&self) -> Result<SourceRunArtifactIds, String> {
        openbot_application::get_source_run_artifact_ids(
            self.administration.as_ref(),
            &self.auth(),
            self.input(),
        )
        .await
        .map_err(|_| "current source IDs observation refused".to_owned())
    }
    async fn outcome(
        &self,
        input: GetSourceRunArtifactIds,
    ) -> Result<SourceRunArtifactIds, AppError> {
        openbot_application::get_source_run_artifact_ids(
            self.administration.as_ref(),
            &self.auth(),
            input,
        )
        .await
    }
    fn object(&self, id: &str) -> PathBuf {
        self.root.0.join("objects").join(id)
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|_| "fixture pool unavailable".to_owned())?
            .batch_execute(sql)
            .await
            .map_err(|_| "owned fixture mutation failed".to_owned())
    }
}
fn lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(
        time::Duration::minutes(30),
        time::Duration::hours(1),
        time::Duration::seconds(1),
    )
    .unwrap()
}
struct CoreSessionGuard {
    issuer: RequestBindingIssuer,
    authority: Weak<PostgresArtifactReadAuthority>,
    lifetime: SessionLifetimePolicy,
}
impl HostRequestBindingGuard for CoreSessionGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Err(HostRequestBindingError::Unavailable) })
    }
    fn verify_source_run_artifact_ids_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn SourceRunArtifactIdsCurrentTarget,
        deadline: Instant,
    ) -> SourceRunArtifactIdsCurrentCheck<'a> {
        Box::pin(async move {
            let authority = self
                .authority
                .upgrade()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ))?;
            let identity = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Missing,
                ))?
                .identity();
            let epoch = self
                .issuer
                .borrow_server_session_epoch(identity)
                .map_err(ArtifactReadCurrentError::Host)?;
            authority
                .observe_source_run_ids_server_session(auth, target, epoch, self.lifetime, deadline)
                .await
        })
    }
}

async fn with_fixture<F, Fut>(tag: &str, channel: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        body(Fixture::new(config, channel).await?).await
    })
    .await;
}

async fn owned_record_transition(f: &Fixture, id: &str, status: &str) -> Result<(), String> {
    let mut client = f
        .pool
        .get()
        .await
        .map_err(|_| "owned mutation pool".to_owned())?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| "owned mutation transaction".to_owned())?;
    tx.batch_execute("SET LOCAL session_replication_role='replica'")
        .await
        .map_err(|_| "owned history control".to_owned())?;
    let erased = matches!(status, "deleted" | "expired");
    let op_sql = if erased {
        "UPDATE openbot_internal.artifact_save_operations SET state=$2,store_id=NULL,workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL WHERE artifact_id=$1"
    } else {
        "UPDATE openbot_internal.artifact_save_operations SET state=$2 WHERE artifact_id=$1"
    };
    let record_sql = if erased {
        "UPDATE openbot_internal.artifact_records SET status=$2,workspace_kind=NULL,workspace_id=NULL,media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL WHERE artifact_id=$1"
    } else {
        "UPDATE openbot_internal.artifact_records SET status=$2 WHERE artifact_id=$1"
    };
    require(
        tx.execute(op_sql, &[&id, &status])
            .await
            .map_err(|_| "owned operation transition".to_owned())?
            == 1,
        "owned operation target",
    )?;
    require(
        tx.execute(record_sql, &[&id, &status])
            .await
            .map_err(|_| "owned record transition".to_owned())?
            == 1,
        "owned record target",
    )?;
    tx.commit()
        .await
        .map_err(|_| "owned transition COMMIT ACK".to_owned())
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

// Own-DB corruption control for the static source-message matrix below. Each statement declares,
// in order, every exact 0051 messages-guard refusal (55000 thread_history_writer_*) it meets as
// ordinary DML; an empty declaration asserts the ordinary DML itself is accepted. Only each
// observed guard is disabled, before its statement queues any source-final event, and every
// guard is back to origin-enabled before the owned COMMIT.
async fn owned_message_dml(
    pool: &openbot_infra::db::pool::DatabasePool,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    refusals: GuardRefusals,
) -> Result<u64, String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    let tx = client.transaction().await.map_err(|e| e.to_string())?;
    tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
        .await
        .map_err(|e| e.to_string())?;
    let mut disabled = 0;
    let changed = loop {
        tx.batch_execute("SAVEPOINT owned_message_probe")
            .await
            .map_err(|e| e.to_string())?;
        match tx.execute(sql, params).await {
            Ok(changed) if disabled == refusals.len() => break changed,
            Ok(_) => {
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
    };
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
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(changed)
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_begin_save_source_run_ids_match_registered_metadata_and_empty_visible_run() {
    with_fixture("source_ids_materialized",false,|f| async move {
        require(f.ids().await?.artifact_ids.is_empty(),"visible empty source must return []")?;
        let receipt=f.save().await?;
        let first=f.ids().await?;
        require(first.source_thread_id==f.begin.command.thread_id && first.source_run_id==f.begin.command.run_id,"exact original selector")?;
        require(first.artifact_ids==[receipt.artifact_id.clone()],"real Save must materialize original ID")?;
        let request=SaveRunMessageTextArtifact {
            request_id:receipt.request_id.clone(),source_thread_id:f.input().source_thread_id,
            source_run_id:f.input().source_run_id,source_message_id:f.message_id(),
            expected_sha256:Sha256Digest::of(EXACT.as_bytes()).to_hex(),
        };
        let replay=f.administration.save_run_message_text(&f.auth(),request).await.map_err(|_| "real replay refused".to_owned())?;
        require(replay==receipt,"same locator real replay identity")?;
        require(f.ids().await?.artifact_ids==first.artifact_ids,"replay must not create a second ID")?;
        let second=f.save().await?;
        let mut expected=vec![receipt.artifact_id.clone(),second.artifact_id.clone()]; expected.sort();
        require(f.ids().await?.artifact_ids==expected,"different real locator creates two sorted IDs")?;
        // Remove only the known fixture object's directory entry. Listing must not open/hash it.
        struct RestoreObject { original:PathBuf,held:PathBuf }
        impl Drop for RestoreObject { fn drop(&mut self) { let _=fs::rename(&self.held,&self.original); } }
        let original=f.object(&receipt.artifact_id);let held=f.root.0.join("owned-temporarily-held-object");
        fs::rename(&original,&held).map_err(|_| "owned temporary object move".to_owned())?;
        let restore=RestoreObject{original,held};
        require(!restore.original.exists(),"original object must actually be absent")?;
        require(f.ids().await?.artifact_ids==expected,"body absence is not an IDs availability promise")?;
        drop(restore);
        require(f.object(&receipt.artifact_id).exists(),"restore original fixture object")?;
        for state in ["failed_partial","deleted","expired"] {
            // Controlled own history only, preserving the actual schema and original identities.
            owned_record_transition(&f,if state=="expired" { &second.artifact_id } else { &receipt.artifact_id },state).await?;
            require(f.ids().await?.artifact_ids==expected,"all four materialized statuses remain identities")?;
        }
        let mut receipt_client=f.pool.get().await.map_err(|_| "own receipt pool".to_owned())?;
        let record:serde_json::Value=receipt_client.query_one("SELECT to_jsonb(a) FROM openbot_internal.artifact_records a WHERE artifact_id=$1",&[&second.artifact_id]).await.map_err(|_| "own original record snapshot".to_owned())?.get(0);
        let tx=receipt_client.transaction().await.map_err(|_| "own receipt history transaction".to_owned())?;
        tx.batch_execute("SET LOCAL session_replication_role='replica'").await.map_err(|_| "own receipt history control".to_owned())?;
        require(tx.execute("DELETE FROM openbot_internal.artifact_records WHERE artifact_id=$1",&[&second.artifact_id]).await.map_err(|_| "own record removal".to_owned())?==1,"own exact materialized record removed")?;
        tx.commit().await.map_err(|_| "own record removal COMMIT ACK".to_owned())?;
        require(f.ids().await?.artifact_ids==[receipt.artifact_id.clone()],"receipt-only identity is not materialized")?;
        receipt_client.execute("INSERT INTO openbot_internal.artifact_records SELECT (jsonb_populate_record(NULL::openbot_internal.artifact_records,$1::jsonb)).*",&[&record]).await.map_err(|_| "own materialized record restore".to_owned())?;
        require(f.ids().await?.artifact_ids==expected,"restore actual materialized record")?;
        drop(receipt_client);
        let saved_unresolved_seed=f.save().await?;
        expected.push(saved_unresolved_seed.artifact_id.clone());expected.sort();
        let allocated=Uuid::now_v7().to_string();
        let op=Uuid::now_v7().to_string();let request=Uuid::now_v7().to_string();
        let client=f.pool.get().await.map_err(|_| "owned allocation pool".to_owned())?;
        client.execute("INSERT INTO openbot_internal.artifact_save_operations SELECT (jsonb_populate_record(NULL::openbot_internal.artifact_save_operations,to_jsonb(o)||jsonb_build_object('artifact_id',$1::text,'operation_id',$2::text,'request_id',$3::text,'state','unresolved','actual_absent',NULL,'actual_byte_length',NULL,'actual_sha256',NULL,'actual_location',NULL,'observation_phase',NULL))).* FROM openbot_internal.artifact_save_operations o WHERE artifact_id=$4",&[&allocated,&op,&request,&saved_unresolved_seed.artifact_id]).await.map_err(|_| "owned unresolved allocation".to_owned())?;
        require(f.ids().await?.artifact_ids==expected,"operation-only/unresolved IDs must not appear")?;
        require(f.registry.binding().deployment_id()==DEPLOYMENT && !f.store.store_id().is_nil(),"actual registry/store fixture scope")?;
        drop(client); f.pool.close();Ok(())
    }).await;
}

struct ForeignGuard {
    issuer: RequestBindingIssuer,
    foreign: Arc<PostgresArtifactReadAuthority>,
}
impl HostRequestBindingGuard for ForeignGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Err(HostRequestBindingError::Unavailable) })
    }
    fn verify_source_run_artifact_ids_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn SourceRunArtifactIdsCurrentTarget,
        deadline: Instant,
    ) -> SourceRunArtifactIdsCurrentCheck<'a> {
        Box::pin(async move {
            let epoch = self
                .issuer
                .borrow_server_session_epoch(auth.request_binding().unwrap().identity())
                .map_err(ArtifactReadCurrentError::Host)?;
            self.foreign
                .observe_source_run_ids_server_session(auth, target, epoch, lifetime(), deadline)
                .await
        })
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_current_source_scope_and_materialized_identity_integrity_are_enforced() {
    for channel in [false, true] {
        with_fixture(if channel {"source_ids_scope_channel"}else{"source_ids_scope_direct"},channel,|f| async move {
            let saved=f.save().await?;
            let other_plain=f.auth_as(OTHER,0);
            let other_created=f.created;let other_expires=other_created+time::Duration::hours(1);
            f.pool.get().await.map_err(|_| "other own actor pool".to_owned())?.execute(
                "INSERT INTO public.sessions(id,user_id,token,created_at,updated_at,expires_at,auth_generation) VALUES('source-ids-other-session',$1,'owned-other-column',$2,$2,$3,0)",
                &[&OTHER,&other_created,&other_expires],
            ).await.map_err(|_| "other own actual session".to_owned())?;
            let other_epoch=ServerSessionBindingIdentity::from_verified_row("source-ids-other-session".into(),other_plain.actor().clone(),"owned-other-column".into(),other_created,other_plain.auth_generation());
            let other_guard=CoreSessionGuard{issuer:f.issuer.clone(),authority:Arc::downgrade(&f.administration.read_authority()),lifetime:lifetime()};
            let other_binding=f.issuer.bind_server_session(&other_plain,other_epoch,Arc::new(other_guard)).map_err(|_| "other own actor binding".to_owned())?;
            let other_auth=other_plain.with_verified_request_binding(other_binding).map_err(|_| "other own actor attachment".to_owned())?;
            require(openbot_application::get_source_run_artifact_ids(f.administration.as_ref(),&other_auth,f.input()).await.err()==Some(AppError::NotVisible),"shared workspace cannot expose another actor Run")?;
            for status in ["queued","running","completed"] {
                let client=f.pool.get().await.map_err(|_| "owned Run status pool".to_owned())?;
                // A completed Run carries its exactly-once terminal event in the same statement (0051).
                client.execute("WITH r AS (UPDATE public.runs SET status=$1,started_at=CASE WHEN $1='queued' THEN NULL ELSE statement_timestamp() END,finished_at=CASE WHEN $1='completed' THEN statement_timestamp() ELSE NULL END,terminal_event_seq=CASE WHEN $1='completed' THEN (SELECT coalesce(max(e.seq)+1,0) FROM public.run_events e WHERE e.run_id=$2) ELSE NULL END WHERE run_id=$2 RETURNING run_id,thread_id,status,terminal_event_seq) INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal) SELECT r.run_id,r.terminal_event_seq,r.thread_id,(SELECT coalesce(max(e.event_seq)+1,0) FROM public.run_events e WHERE e.thread_id=r.thread_id),r.status,'{}'::jsonb,true FROM r WHERE r.status='completed'",&[&status,&f.begin.command.run_id.as_str()]).await.map_err(|_| "ordinary Run status fixture".to_owned())?;
                require(f.ids().await?.artifact_ids==[saved.artifact_id.clone()],"R398 ordinary statuses are visible")?;
            }
            let mut changes=vec![
                ("UPDATE public.agent_profiles SET deleted_at=clock_timestamp() WHERE agent_id='read-bot'","UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='read-bot'"),
                ("UPDATE public.agent_profiles SET visibility='private',owner_user_id='read-other' WHERE agent_id='read-bot'","UPDATE public.agent_profiles SET visibility='public',owner_user_id='read-owner' WHERE agent_id='read-bot'"),
                ("UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000051' WHERE id='read-bot';UPDATE public.deployment_packages SET tenant_id='foreign' WHERE id='00000000-0000-4000-8000-000000000051'","UPDATE public.agents SET package_id=NULL WHERE id='read-bot';UPDATE public.deployment_packages SET tenant_id='artifact-read-owned-tenant' WHERE id='00000000-0000-4000-8000-000000000051'"),
                ("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp()","UPDATE public.threads SET status='active',deleted_at=NULL"),
            ];
            if channel {
                changes.push(("DELETE FROM public.channel_memberships WHERE channel_id='read-channel' AND user_id='read-owner'","INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('read-channel','read-owner')"));
                changes.push(("DELETE FROM public.channel_agents WHERE channel_id='read-channel'","INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('read-channel','read-bot')"));
                changes.push(("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000051' WHERE id='read-channel';UPDATE public.deployment_packages SET tenant_id='foreign' WHERE id='00000000-0000-4000-8000-000000000051'","UPDATE public.channels SET package_id=NULL WHERE id='read-channel';UPDATE public.deployment_packages SET tenant_id='artifact-read-owned-tenant' WHERE id='00000000-0000-4000-8000-000000000051'"));
            } else {
                changes.push(("DELETE FROM public.thread_memberships WHERE user_id='read-owner'","INSERT INTO public.thread_memberships(thread_id,user_id) SELECT thread_id,'read-owner' FROM public.threads"));
            }
            for (change,restore) in changes {
                f.sql(change).await?;
                let result=f.outcome(f.input()).await;
                f.sql(restore).await?;
                require(result.err()==Some(AppError::NotVisible),"current R398 source relation must be observed")?;
                require(f.ids().await?.artifact_ids==[saved.artifact_id.clone()],"actual restore must restore current source")?;
            }
            let client=f.pool.get().await.map_err(|_| "owned message pool".to_owned())?;
            // Ordinary DML the 0051 messages guards accept is declared []; every refusal is listed
            // in the order the guards meet it, separately for the direct and channel source. On a
            // channel the message is the canonical source: canonical-reverse refuses the change,
            // and the deferred source-final check refuses the resulting invalid source unless its
            // guard is off before the statement; a restore leaves a valid source behind.
            const MUTATION:&str="thread_history_writer_source_mutation_refused";
            const INVALID:&str="thread_history_writer_binding_invalid";
            let identity:GuardRefusals=if channel {&[(CANONICAL_GUARD,MUTATION),(SOURCE_FINAL_GUARD,INVALID)]} else {&[]};
            let identity_restore:GuardRefusals=if channel {&[(CANONICAL_GUARD,MUTATION)]} else {&[]};
            let run_unbound:GuardRefusals=if channel {&[(BODY_GUARD,INVALID),(CANONICAL_GUARD,MUTATION),(SOURCE_FINAL_GUARD,INVALID)]} else {&[(BODY_GUARD,INVALID)]};
            let run_restore:GuardRefusals=if channel {&[(BODY_GUARD,INVALID),(CANONICAL_GUARD,MUTATION)]} else {&[(BODY_GUARD,INVALID)]};
            let removal:GuardRefusals=if channel {&[(SOURCE_FINAL_GUARD,INVALID)]} else {&[]};
            for (field,value,original,mutation,restore) in [("role","assistant","user",identity,identity_restore),("actor_id",OTHER,OWNER,identity,identity_restore),("run_id","own-mismatched-run",f.begin.command.run_id.as_str(),run_unbound,run_restore)] {
                // Field choices are this closed static fixture matrix, never public SQL input.
                owned_message_dml(&f.pool,&format!("UPDATE public.messages SET {field}=$1 WHERE message_id=$2"),&[&value,&f.message_id()],mutation).await.map_err(|e| format!("own source message relation mutation: {e}"))?;
                let observed=f.ids().await;
                owned_message_dml(&f.pool,&format!("UPDATE public.messages SET {field}=$1 WHERE message_id=$2"),&[&original,&f.message_id()],restore).await.map_err(|e| format!("own source message relation restore: {e}"))?;
                require(observed?.artifact_ids.is_empty(),"ineligible original message identity omitted")?;
            }
            let original_message:serde_json::Value=client.query_one("SELECT to_jsonb(m) FROM public.messages m WHERE message_id=$1",&[&f.message_id()]).await.map_err(|_| "own exact message snapshot".to_owned())?.get(0);
            require(owned_message_dml(&f.pool,"DELETE FROM public.messages WHERE message_id=$1",&[&f.message_id()],removal).await.map_err(|e| format!("own source message removal: {e}"))?==1,"actual original source message removed")?;
            require(f.ids().await?.artifact_ids.is_empty(),"absent source message identity omitted")?;
            owned_message_dml(&f.pool,"INSERT INTO public.messages SELECT (jsonb_populate_record(NULL::public.messages,$1::jsonb)).*",&[&original_message],&[]).await.map_err(|e| format!("own original message restore: {e}"))?;
            drop(client);
            let foreign_pool=pool::connect(&f.config).await.map_err(|_| "independent owned manager".to_owned())?;
            require(!f.administration.read_authority().matches_pool_scope(&foreign_pool,&DeploymentId::new(DEPLOYMENT),&TenantId::new(TENANT)),"foreign actual manager must fail same-Pool enrollment")?;
            foreign_pool.close();
            let other=Arc::new(PostgresArtifactAdministration::new(f.registry.clone(),f.store.clone(),ArtifactQuotaPolicy::default(),SecretBytes::new(vec![0x84;32])).map_err(|_| "owned second adapter".to_owned())?);
            let plain=f.auth_as(OWNER,0);
            let guard=ForeignGuard{issuer:f.issuer.clone(),foreign:other.read_authority()};
            let epoch=ServerSessionBindingIdentity::from_verified_row("core-read-session-a".into(),plain.actor().clone(),"owned-test-session-column-a".into(),f.created,plain.auth_generation());
            let binding=f.issuer.bind_server_session(&plain,epoch,Arc::new(guard)).map_err(|_| "own second adapter binding".to_owned())?;
            let foreign_auth=plain.with_verified_request_binding(binding).map_err(|_| "own second adapter attachment".to_owned())?;
            require(openbot_application::get_source_run_artifact_ids(f.administration.as_ref(),&foreign_auth,f.input()).await.err()==Some(AppError::Unauthenticated),"private adapter identity cannot be exchanged")?;
            drop(other);
            let changed_request=Uuid::now_v7().to_string();
            let mut client=f.pool.get().await.map_err(|_| "owned corruption pool".to_owned())?;
            let tx=client.transaction().await.map_err(|_| "owned corruption transaction".to_owned())?;
            tx.batch_execute("SET LOCAL session_replication_role='replica'").await.map_err(|_| "owned history control".to_owned())?;
            tx.execute("UPDATE openbot_internal.artifact_save_operations SET request_id=$1 WHERE artifact_id=$2",&[&changed_request,&saved.artifact_id]).await.map_err(|_| "owned tuple corruption".to_owned())?;
            tx.commit().await.map_err(|_| "owned corruption COMMIT ACK".to_owned())?;
            require(f.outcome(f.input()).await.err()==Some(AppError::DependencyUnavailable{dependency:"artifacts"}),"LEFT JOIN corruption must refuse503")?;
            let tx=client.transaction().await.map_err(|_| "owned restore transaction".to_owned())?;
            tx.batch_execute("SET LOCAL session_replication_role='replica'").await.map_err(|_| "owned restore control".to_owned())?;
            tx.execute("UPDATE openbot_internal.artifact_save_operations SET request_id=$1 WHERE artifact_id=$2",&[&saved.request_id,&saved.artifact_id]).await.map_err(|_| "owned tuple restore".to_owned())?;
            tx.commit().await.map_err(|_| "owned restore COMMIT ACK".to_owned())?;
            for _ in 0..32 {
                let id=Uuid::now_v7().to_string();let op=Uuid::now_v7().to_string();let request=Uuid::now_v7().to_string();
                client.execute("INSERT INTO openbot_internal.artifact_save_operations SELECT (jsonb_populate_record(NULL::openbot_internal.artifact_save_operations,to_jsonb(o)||jsonb_build_object('artifact_id',$1::text,'operation_id',$2::text,'request_id',$3::text))).* FROM openbot_internal.artifact_save_operations o WHERE artifact_id=$4",&[&id,&op,&request,&saved.artifact_id]).await.map_err(|_| "owned excess operation".to_owned())?;
                client.execute("INSERT INTO openbot_internal.artifact_records SELECT (jsonb_populate_record(NULL::openbot_internal.artifact_records,to_jsonb(a)||jsonb_build_object('artifact_id',$1::text,'operation_id',$2::text,'request_id',$3::text))).* FROM openbot_internal.artifact_records a WHERE artifact_id=$4",&[&id,&op,&request,&saved.artifact_id]).await.map_err(|_| "owned excess record".to_owned())?;
            }
            require(f.outcome(f.input()).await.err()==Some(AppError::DependencyUnavailable{dependency:"artifacts"}),"33 actual IDs must refuse without truncation")?;
            // Hard-delete the actual source under explicit fixture control; IDs remain historical.
            let tx=client.transaction().await.map_err(|_| "owned delete transaction".to_owned())?;
            tx.batch_execute("SET LOCAL session_replication_role='replica'").await.map_err(|_| "owned delete control".to_owned())?;
            tx.execute("DELETE FROM public.runs WHERE run_id=$1",&[&f.begin.command.run_id.as_str()]).await.map_err(|_| "owned hard delete".to_owned())?;
            tx.commit().await.map_err(|_| "owned hard delete COMMIT ACK".to_owned())?;
            require(f.outcome(f.input()).await.err()==Some(AppError::NotVisible),"hard deleted source refuses404 before retained IDs")?;
            let row=client.query_one("SELECT count(*),bool_and(retention_class='explicit_saved') FROM openbot_internal.artifact_records",&[]).await.map_err(|_| "retained own facts".to_owned())?;
            require(row.get::<_,i64>(0)==33 && row.get::<_,Option<bool>>(1)==Some(true),"source removal cannot erase saved facts")?;
            drop(client);f.pool.close();Ok(())
        }).await;
    }
}
