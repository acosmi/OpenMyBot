//! Owned-PG metadata tests with a trusted-test issuer. Genuine host proof is tested separately.

use crate::artifact_administration::PostgresArtifactAdministration;
use crate::artifact_read_authority::PostgresArtifactReadAuthority;
use crate::artifact_registry::ArtifactDatasetRegistry;
use crate::artifact_store::DatasetBoundArtifactStore;
use crate::db::pool::DatabaseConfig;
use crate::db::pool::DatabasePool as Pool;
use crate::db::{baseline, native, pool};
use crate::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
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
use std::fs::{self, File};
use std::future::Future;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use uuid::Uuid;

mod harness {
    use crate as openbot_infra;
    include!("../../../../test-support/postgres_harness.rs");
}
use super::*;
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
            config,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_rollback_pending_ack_precedes_original_binding_tail_for_all_outcomes() {
    for source in 0..3 {
        for expire in [false, true] {
            let tag = format!("source_ids_rollback_{source}_{}", u8::from(expire));
            harness::with_temp_database(&harness::admin_config(&tag),&tag,|config| async move {
                let f=Fixture::new(config,false).await?;
                let saved=f.save().await?;
                require(f.ids().await?.artifact_ids==[saved.artifact_id.clone()],"actual Begin/Save baseline")?;
                require(f.object(&saved.artifact_id).exists() && !f.store.store_id().is_nil()
                    && f.registry.binding().deployment_id()==DEPLOYMENT,"owned original actual registration")?;
                let mut input=f.input();
                if source==1 { input.source_run_id=RunId::new("owned-missing-source-run"); }
                if source==2 {
                    let mut client=f.pool.get().await.map_err(|_| "own corruption pool".to_owned())?;
                    let tx=client.transaction().await.map_err(|_| "own corruption tx".to_owned())?;
                    tx.batch_execute("SET LOCAL session_replication_role='replica'").await.map_err(|_| "own corruption control".to_owned())?;
                    let other=Uuid::now_v7().to_string();
                    tx.execute("UPDATE openbot_internal.artifact_save_operations SET request_id=$1 WHERE artifact_id=$2",&[&other,&saved.artifact_id]).await.map_err(|_| "own tuple corruption".to_owned())?;
                    tx.commit().await.map_err(|_| "own corruption COMMIT ACK".to_owned())?;
                }
                let baseline=f.outcome(input.clone()).await;
                require(match source {
                    0=>baseline.as_ref().is_ok_and(|ids| ids.artifact_ids==[saved.artifact_id.clone()]),
                    1=>baseline.err()==Some(AppError::NotVisible),
                    _=>baseline.err()==Some(AppError::DependencyUnavailable{dependency:"artifacts"}),
                },"actual original source class before controlled rollback")?;
                let expiry=if expire {
                    let client=f.pool.get().await.map_err(|_| "own expiry pool".to_owned())?;
                    let row=client.query_one("UPDATE public.sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id='core-read-session-a' RETURNING expires_at",&[]).await.map_err(|_| "own actual expiry update".to_owned())?;
                    Some(row.get::<_,OffsetDateTime>(0))
                } else {None};
                let (pending_send,pending)=tokio::sync::oneshot::channel();
                let (resume_send,resume)=tokio::sync::oneshot::channel();
                let (ack_send,ack)=tokio::sync::oneshot::channel();
                let authority=f.administration.read_authority();
                *authority.source_run_ids_rollback_gate.lock().map_err(|_| "own gate lock".to_owned())?=
                    Some(SourceRunIdsRollbackGate{first_pending:pending_send,resume,actual_ack:ack_send});
                let original_auth=f.auth();
                let administration=f.administration.clone();
                let deadline=Instant::now()+Duration::from_secs(5);
                let task=tokio::spawn(async move {
                    let original=original_auth.request_binding().unwrap().clone();
                    let outcome=administration.observe_source_run_artifact_ids_current(&original_auth,&input,deadline).await;
                    original.check_source_run_artifact_ids_attachment(&original_auth,deadline).map_err(AppError::from)?;
                    let (witness,source)=outcome.map_err(AppError::from)?;
                    original.verify_source_run_artifact_ids_tail(&original_auth,witness.as_ref(),deadline).map_err(AppError::from)?;
                    source.map_err(AppError::from)
                });
                let mut resume_send=Some(resume_send);
                let control=async {
                    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),pending).await
                        .map_err(|_| "real rollback Pending deadline".to_owned())?
                        .map_err(|_| "original rollback first poll was not Pending".to_owned())?;
                    require(!task.is_finished(),"original task must retain the real rollback future")?;
                    if let Some(expiry)=expiry {
                        while OffsetDateTime::now_utc()<expiry {
                            require(Instant::now()<deadline,"original absolute expiry budget")?;
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    } else { f._lease.close(); }
                    require(!task.is_finished(),"paused original future must remain uncompleted")?;
                    resume_send.take().ok_or_else(|| "own resume missing".to_owned())?.send(())
                        .map_err(|_| "original resume receiver missing".to_owned())?;
                    let actual=tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),ack).await
                        .map_err(|_| "actual rollback ACK deadline".to_owned())?
                        .map_err(|_| "actual rollback ACK unobserved".to_owned())?;
                    require(actual,"same original future must return actual successful rollback ACK")
                }.await;
                // Failure also releases the original gate and observes the owned task. Its
                // own unchanged deadline bounds it; task Drop is never reported as an ACK.
                if let Some(sender)=resume_send.take() {let _=sender.send(());}
                let joined=task.await.map_err(|_| "original controlled task did not join".to_owned());
                let result=(|| {
                    control?;
                    require(joined?.err()==Some(AppError::Unauthenticated),"original owner/Session clock must withhold every held source outcome")
                })();
                f.sql("SELECT 1").await?;
                f.pool.close();drop(authority);drop(f);
                eprintln!("SOURCE_IDS_ACTUAL_ROLLBACK inline_source={source} clock_expiry={expire} pending_ack_tail_verified={}",result.is_ok());
                result
            }).await;
        }
    }
}
