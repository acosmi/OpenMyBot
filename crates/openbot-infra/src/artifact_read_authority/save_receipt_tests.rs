//! Owned-PG receipt tests with a manually minted trusted-test epoch. Genuine host producers are tested separately.

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
    ArtifactRegistrationReceipt, GetArtifactSaveReceipt, SaveRunMessageTextArtifact,
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
use serde_json::Value;
use std::fs::{self, File};
use std::future::Future;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
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
const TERMINAL_FINAL_GUARD: &str = "runs_history_terminal_final";
// Each 0051 runs row guard and the trigger function its refusal context names.
const RUN_GUARDS: [(&str, &str); 4] = [
    ("runs_history_body_before", "guard_thread_history_body()"),
    (
        "runs_history_canonical_before",
        "guard_thread_history_canonical_reverse()",
    ),
    (
        "runs_history_source_final",
        "require_thread_history_channel_final()",
    ),
    (
        TERMINAL_FINAL_GUARD,
        "require_thread_history_terminal_final()",
    ),
];
type GuardRefusals = &'static [(&'static str, &'static str)];

fn observed_refusal(error: &tokio_postgres::Error) -> String {
    let Some(db) = error.as_db_error() else {
        return error.to_string();
    };
    let guards: Vec<&str> = RUN_GUARDS
        .iter()
        .filter(|(_, function)| db.where_().is_some_and(|w| w.contains(function)))
        .map(|(guard, _)| *guard)
        .collect();
    format!("{} {} {guards:?}", db.code().code(), db.message())
}
struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("openbot-save-receipt-{}", Uuid::now_v7()));
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
        eprintln!("ARTIFACT_SAVE_RECEIPT_ROOT_CLEANUP removed={removed} absent={absent}");
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
    async fn other_admin_auth(&self) -> Result<AuthContext, String> {
        let auth = self.auth_as(OTHER, 0);
        let expires = self.created + time::Duration::hours(1);
        self.pool.get().await.map_err(|_| "own other Session pool".to_owned())?.execute(
            "INSERT INTO public.sessions(id,user_id,token,created_at,updated_at,expires_at,auth_generation) VALUES($1,$2,$3,$4,$4,$5,0)",
            &[&"core-receipt-other-session", &OTHER, &"owned-other-test-session-column", &self.created, &expires])
            .await.map_err(|_| "own other actual Session row".to_owned())?;
        let epoch = ServerSessionBindingIdentity::from_verified_row(
            "core-receipt-other-session".into(),
            auth.actor().clone(),
            "owned-other-test-session-column".into(),
            self.created,
            auth.auth_generation(),
        );
        let guard = CoreSessionGuard {
            issuer: self.issuer.clone(),
            authority: Arc::downgrade(&self.administration.read_authority()),
            lifetime: lifetime(),
        };
        let binding = self
            .issuer
            .bind_server_session(&auth, epoch, Arc::new(guard))
            .map_err(|_| "own other controlled epoch".to_owned())?;
        auth.with_verified_request_binding(binding)
            .map_err(|_| "own other attachment".to_owned())
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
    fn request(&self) -> SaveRunMessageTextArtifact {
        SaveRunMessageTextArtifact {
            request_id: Uuid::now_v7().to_string(),
            source_thread_id: self.begin.command.thread_id.clone(),
            source_run_id: self.begin.command.run_id.clone(),
            source_message_id: self.message_id(),
            expected_sha256: Sha256Digest::of(EXACT.as_bytes()).to_hex(),
        }
    }
    async fn outcome(&self, request: &str) -> Result<ArtifactRegistrationReceipt, AppError> {
        openbot_application::get_artifact_save_receipt(
            self.administration.as_ref(),
            &self.auth(),
            GetArtifactSaveReceipt {
                request_id: request.into(),
            },
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
            .map_err(|_| "own fixture pool unavailable".to_owned())?
            .batch_execute(sql)
            .await
            .map_err(|e| format!("own fixture mutation failed: {e:?}"))
    }
    async fn facts(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|_| "own fact pool".to_owned())?.query_one(
            "SELECT jsonb_build_object(
              'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_save_operations o),
              'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]') FROM openbot_internal.artifact_records r),
              'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_saved_receipts r),
              'workspaces',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q),
              'runs',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q),
              'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a WHERE event_type='artifact.saved'))", &[])
            .await.map_err(|_| "own facts read".to_owned())?.try_get(0).map_err(|_| "own fact shape".to_owned())
    }
    async fn actual_receipt(&self, request: &str) -> Result<ArtifactRegistrationReceipt, String> {
        let row = self
            .pool
            .get()
            .await
            .map_err(|_| "own receipt pool".to_owned())?
            .query_one(
                "SELECT * FROM openbot_internal.artifact_saved_receipts WHERE request_id=$1",
                &[&request],
            )
            .await
            .map_err(|_| "own actual positive row".to_owned())?;
        crate::artifact_administration::decode_receipt(&row)
            .map_err(|_| "own actual receipt shape".to_owned())
    }
    async fn mutate(&self, sql: &str, id: &str) -> Result<(), String> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| "own mutation pool".to_owned())?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| "own mutation tx".to_owned())?;
        // This bypass is confined to a disposable reader-corruption fixture, never production.
        tx.batch_execute("SET LOCAL session_replication_role='replica'")
            .await
            .map_err(|_| "own corruption control".to_owned())?;
        tx.execute(sql, &[&id])
            .await
            .map_err(|_| "own reader fixture mutation".to_owned())?;
        tx.commit()
            .await
            .map_err(|_| "own reader fixture COMMIT ACK".to_owned())
    }
    // Own-DB reader-input control for the source Run. The statement declares, in order, every
    // exact 0051 runs-guard refusal (55000 thread_history_writer_*) it meets as ordinary DML;
    // an empty declaration asserts the ordinary DML itself is accepted. Only each observed guard
    // is disabled, before its statement queues any deferred event, and every guard is back to
    // origin-enabled before the owned COMMIT.
    async fn owned_run_dml(&self, sql: &str, refusals: GuardRefusals) -> Result<u64, String> {
        let mut client = self.pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
            .await
            .map_err(|e| e.to_string())?;
        let mut disabled = 0;
        let changed = loop {
            tx.batch_execute("SAVEPOINT owned_run_probe")
                .await
                .map_err(|e| e.to_string())?;
            match tx.execute(sql, &[]).await {
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
                        "ROLLBACK TO SAVEPOINT owned_run_probe; \
                         ALTER TABLE public.runs DISABLE TRIGGER {guard}"
                    ))
                    .await
                    .map_err(|e| e.to_string())?;
                    disabled += 1;
                }
            }
        };
        for (guard, _) in &refusals[..disabled] {
            tx.batch_execute(&format!("ALTER TABLE public.runs ENABLE TRIGGER {guard}"))
                .await
                .map_err(|e| e.to_string())?;
        }
        let states: Vec<String> = tx
            .query(
                "SELECT tgenabled::text FROM pg_catalog.pg_trigger \
                 WHERE tgrelid='public.runs'::regclass AND tgname=ANY($1) AND NOT tgisinternal",
                &[&RUN_GUARDS.map(|(guard, _)| guard).to_vec()],
            )
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .map(|row| row.get(0))
            .collect();
        if states != ["O", "O", "O", "O"] {
            return Err(format!("owned run guards were not restored: {states:?}"));
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(changed)
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
    fn verify_artifact_save_receipt_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactSaveReceiptCurrentTarget,
        deadline: Instant,
    ) -> ArtifactSaveReceiptCurrentCheck<'a> {
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
                .observe_artifact_save_receipt_server_session(
                    auth,
                    target,
                    epoch,
                    self.lifetime,
                    deadline,
                )
                .await
        })
    }
}

/// Only new owned loopback connections pass through this frame-forwarder. It drops a selected
/// actual COMMIT CommandComplete after the backend has committed; it never simulates PG state.
struct CommitAckProxy {
    port: u16,
    remaining: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl CommitAckProxy {
    async fn start(host: String, port: u16) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "own proxy listener".to_owned())?;
        let proxy_port = listener
            .local_addr()
            .map_err(|_| "own proxy address".to_owned())?
            .port();
        let remaining = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let countdown = remaining.clone();
        let dropped_count = dropped.clone();
        let (shutdown_send, mut shutdown) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown => break,
                    value = listener.accept() => value,
                };
                let Ok((client, _)) = accepted else {
                    break;
                };
                let host = host.clone();
                let countdown = countdown.clone();
                let dropped_count = dropped_count.clone();
                children.spawn(async move {
                    let server = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let backend = async {
                        loop {
                            let kind = server_read.read_u8().await?;
                            let length = server_read.read_u32().await?;
                            if !(4..=16*1024*1024).contains(&length) {
                                return Err(std::io::Error::other("invalid own proxy frame"));
                            }
                            let mut payload = vec![0; (length-4) as usize];
                            server_read.read_exact(&mut payload).await?;
                            if kind == b'C' && payload == b"COMMIT\0"
                                && countdown.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1)) == Ok(1)
                            {
                                dropped_count.fetch_add(1, Ordering::SeqCst);
                                return Ok::<(), std::io::Error>(());
                            }
                            client_write.write_u8(kind).await?; client_write.write_u32(length).await?;
                            client_write.write_all(&payload).await?;
                        }
                    };
                    tokio::select! { _ = tokio::io::copy(&mut client_read, &mut server_write) => {}, _ = backend => {} }
                    Ok::<(), std::io::Error>(())
                });
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Ok(Self {
            port: proxy_port,
            remaining,
            dropped,
            shutdown: Some(shutdown_send),
            task: Some(task),
        })
    }
    fn arm(&self, ordinal: usize) {
        self.remaining.store(ordinal, Ordering::SeqCst);
    }
    async fn shutdown(mut self) -> Result<(), String> {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        let mut original = self
            .task
            .take()
            .ok_or_else(|| "own proxy original task missing".to_owned())?;
        match tokio::time::timeout(Duration::from_secs(5), &mut original).await {
            Ok(joined) => joined.map_err(|_| "own proxy original task join failed".to_owned()),
            Err(_) => {
                original.abort();
                let _ = original.await;
                Err("own proxy shutdown did not finish normally".to_owned())
            }
        }
    }
}
impl Drop for CommitAckProxy {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_saved_receipt_lookup_recovers_final_commit_ack_loss_without_reexecution() {
    for ordinal in 1..=3 {
        let tag = format!("save_receipt_ack_{ordinal}");
        harness::with_temp_database(&harness::admin_config(&tag), &tag, |config| async move {
            let proxy = CommitAckProxy::start(config.host.clone(), config.port).await?;
            let mut proxied = config; proxied.host = "127.0.0.1".into(); proxied.port = proxy.port;
            let f = Fixture::new(proxied, false).await?;
            let result = async {
                let request = f.request(); proxy.arm(ordinal);
                require(f.administration.save_run_message_text(&f.auth(), request.clone()).await
                    == Err(openbot_application::ArtifactAdministrationError::CommitUnknown), "actual lost ACK must remain Unknown")?;
                require(proxy.dropped.load(Ordering::SeqCst) == 1, "proxy did not drop the actual selected COMMIT ACK")?;
                let before = f.facts().await?;
                let observed = f.outcome(&request.request_id).await;
                if ordinal == 3 {
                    let actual = f.actual_receipt(&request.request_id).await?;
                    require(observed == Ok(actual.clone()), "lookup must return the real persisted positive after final ACK loss")?;
                    require(fs::read(f.object(&actual.artifact_id)).map_err(|_| "own original installed bytes".to_owned())? == EXACT.as_bytes(),
                        "lookup changed original installed bytes")?;
                    for field in ["operations", "records", "receipts", "audit"] {
                        require(before[field].as_array().is_some_and(|rows| rows.len() == 1), "final Unknown requires actual atomic positive facts")?;
                    }
                } else {
                    require(observed.err() == Some(AppError::DependencyUnavailable { dependency: "artifacts" }),
                        "admission/IO-start ACK loss cannot produce a positive or NotCommitted claim")?;
                    require(before["records"].as_array().is_some_and(Vec::is_empty)
                        && before["receipts"].as_array().is_some_and(Vec::is_empty), "pre-IO Unknown has no fabricated record or receipt")?;
                    require(fs::read_dir(f.root.0.join("objects")).map_err(|_| "own object inventory".to_owned())?.next().is_none(),
                        "lost admission/IO-start ACK must not authorize bytes")?;
                }
                require(f.facts().await? == before, "read-only observer changed operation/record/receipt/audit/charge/identity facts")
            }.await;
            f.pool.close(); drop(f);
            let closed = proxy.shutdown().await;
            eprintln!("SAVE_RECEIPT_REAL_ACK ordinal={ordinal} observer_no_reexecution={} proxy_closed={}", result.is_ok(), closed.is_ok());
            result.and(closed)
        }).await;
    }
}

async fn make_terminal(f: &Fixture, artifact: &str, status: &'static str) -> Result<(), String> {
    require(
        matches!(status, "deleted" | "expired"),
        "closed terminal reader fixture status",
    )?;
    f.mutate(&format!("UPDATE openbot_internal.artifact_save_operations SET state='{status}',store_id=NULL,workspace_kind=NULL,workspace_id=NULL,
        expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,
        actual_location=NULL,observation_phase=NULL,created_at=NULL WHERE artifact_id=$1"), artifact).await?;
    f.mutate(&format!("UPDATE openbot_internal.artifact_records SET status='{status}',workspace_kind=NULL,workspace_id=NULL,
        media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL WHERE artifact_id=$1"), artifact).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_request_scope_source_visibility_and_receipt_integrity_are_one_snapshot() {
    for case in 0..25 {
        let tag = format!("save_receipt_scope_{case}");
        harness::with_temp_database(&harness::admin_config(&tag), &tag, |config| async move {
            let f = Fixture::new(config, false).await?; let saved = f.save().await?;
            require(f.registry.binding().deployment_id() == DEPLOYMENT && !f.store.store_id().is_nil(),
                "original genuine registration authority/root fixture")?;
            require(f.outcome(&saved.request_id).await == Ok(saved.clone()), "real Begin/Save original positive baseline")?;
            let mut request = saved.request_id.clone();
            let mut observation_auth = f.auth();
            let expected = match case {
                0 => { f.sql("UPDATE public.messages SET content='{}'::jsonb").await?; request = request.to_uppercase(); Ok(saved.clone()) },
                1 => { request = Uuid::now_v7().to_string(); Err(AppError::NotVisible) },
                2 => { f.mutate("UPDATE openbot_internal.artifact_save_operations SET owner_actor_id='read-other' WHERE artifact_id=$1", &saved.artifact_id).await?; Err(AppError::NotVisible) },
                3 => { f.sql("DELETE FROM public.thread_memberships WHERE user_id='read-owner'").await?; Err(AppError::NotVisible) },
                4 => { f.sql("UPDATE public.messages SET actor_id='read-other'").await?; Err(AppError::NotVisible) },
                5 => { f.sql("UPDATE public.messages SET role='assistant'").await?; Err(AppError::NotVisible) },
                6 => { f.sql("UPDATE public.agent_profiles SET visibility='private',owner_user_id='read-other'").await?; Err(AppError::NotVisible) },
                7 => { f.sql("UPDATE public.agent_profiles SET deleted_at=now()").await?; Err(AppError::NotVisible) },
                8 => { f.sql("UPDATE public.deployment_packages SET tenant_id='foreign-tenant'; UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000051'").await?; Err(AppError::NotVisible) },
                9 => { f.sql("DELETE FROM public.messages").await?; Err(AppError::NotVisible) },
                10 => { f.mutate("UPDATE openbot_internal.artifact_saved_receipts SET request_id='019a7777-abcd-7abc-8abc-0123456789ab' WHERE artifact_id=$1", &saved.artifact_id).await?;
                    Err(AppError::DependencyUnavailable { dependency: "artifacts" }) },
                11 => { f.mutate("UPDATE openbot_internal.artifact_records SET source_message_id='different-owned-message' WHERE artifact_id=$1", &saved.artifact_id).await?;
                    Err(AppError::DependencyUnavailable { dependency: "artifacts" }) },
                12 => { f.mutate("UPDATE openbot_internal.artifact_records SET sha256=repeat('0',64) WHERE artifact_id=$1", &saved.artifact_id).await?;
                    Err(AppError::DependencyUnavailable { dependency: "artifacts" }) },
                13 => { f.mutate("DELETE FROM openbot_internal.artifact_saved_receipts WHERE artifact_id=$1", &saved.artifact_id).await?;
                    Err(AppError::DependencyUnavailable { dependency: "artifacts" }) },
                14 => { make_terminal(&f, &saved.artifact_id, "deleted").await?; Err(AppError::ArtifactGone { status: ArtifactGoneStatus::Deleted }) },
                15 => { make_terminal(&f, &saved.artifact_id, "expired").await?; Err(AppError::ArtifactGone { status: ArtifactGoneStatus::Expired }) },
                16 => { f.sql("UPDATE public.users SET auth_generation=1 WHERE id='read-owner'").await?; request=Uuid::now_v7().to_string(); Err(AppError::Unauthenticated) },
                17 => { f.sql("DELETE FROM public.sessions WHERE id='core-read-session-a'").await?;
                    f.mutate("UPDATE openbot_internal.artifact_saved_receipts SET source_message_id='bad-owned-message' WHERE artifact_id=$1", &saved.artifact_id).await?;
                    Err(AppError::Unauthenticated) },
                18..=20 => {
                    let status = ["completed", "failed", "reconciliation_required"][case-18];
                    // Reader inputs only; this does not accept a Run writer. 0051 refuses a terminal
                    // Run without its matching terminal event, so the ordinary DML declares exactly
                    // that refusal and only its guard is suppressed for this owned statement.
                    require(f.owned_run_dml(&format!("UPDATE public.runs SET status='{status}',terminal_event_seq=0,started_at=now(),finished_at=now(),error_code='owned_reader_fixture'"),
                        &[(TERMINAL_FINAL_GUARD, "thread_history_writer_binding_invalid")]).await? == 1, "own terminal reader Run status")?;
                    Ok(saved.clone())
                },
                21 => { observation_auth = f.other_admin_auth().await?; Err(AppError::NotVisible) },
                22 => { f.mutate("UPDATE openbot_internal.artifact_save_operations SET dataset_id='different-owned-dataset' WHERE artifact_id=$1", &saved.artifact_id).await?;
                    Err(AppError::NotVisible) },
                23 => { f.mutate("UPDATE openbot_internal.artifact_save_operations SET state='unresolved' WHERE artifact_id=$1", &saved.artifact_id).await?;
                    Err(AppError::DependencyUnavailable { dependency: "artifacts" }) },
                _ => { f.mutate("UPDATE openbot_internal.artifact_saved_receipts SET source_call_seq=1,source_attempt_seq=1 WHERE artifact_id=$1", &saved.artifact_id).await?;
                    Err(AppError::DependencyUnavailable { dependency: "artifacts" }) },
            };
            let before = f.facts().await?;
            let before_bytes = fs::read(f.object(&saved.artifact_id)).map_err(|_| "own original byte inventory".to_owned())?;
            require(openbot_application::get_artifact_save_receipt(f.administration.as_ref(), &observation_auth,
                GetArtifactSaveReceipt { request_id: request }).await == expected,
                "actual current locator/source/full-tuple class mismatch")?;
            require(f.facts().await? == before && fs::read(f.object(&saved.artifact_id)).map_err(|_| "own original bytes after query".to_owned())? == before_bytes,
                "observer changed original durable facts or bytes")?;
            f.pool.close(); drop(f);
            eprintln!("SAVE_RECEIPT_SCOPE case={case} original_positive_and_no_effect_verified=true terminal_reader_only={}", matches!(case,14|15));
            Ok(())
        }).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_receipt_rollback_ack_precedes_original_owner_and_clock_tail_for_all_outcomes() {
    for source in 0..4 {
        for expire in [false, true] {
            let tag = format!("save_receipt_rollback_{source}_{}", u8::from(expire));
            harness::with_temp_database(&harness::admin_config(&tag), &tag, |config| async move {
                let f = Fixture::new(config, false).await?; let saved = f.save().await?;
                let mut request = saved.request_id.clone();
                let baseline = match source {
                    0 => Ok(saved.clone()),
                    1 => { request=Uuid::now_v7().to_string(); Err(AppError::NotVisible) },
                    2 => { make_terminal(&f, &saved.artifact_id, "deleted").await?; Err(AppError::ArtifactGone { status: ArtifactGoneStatus::Deleted }) },
                    _ => { f.mutate("UPDATE openbot_internal.artifact_saved_receipts SET source_message_id='corrupt-owned-message' WHERE artifact_id=$1", &saved.artifact_id).await?;
                        Err(AppError::DependencyUnavailable { dependency: "artifacts" }) },
                };
                require(f.outcome(&request).await == baseline, "original outcome before real rollback pause")?;
                let before = f.facts().await?;
                let expiry = if expire {
                    Some(f.pool.get().await.map_err(|_| "own expiry pool".to_owned())?.query_one(
                        "UPDATE public.sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id='core-read-session-a' RETURNING expires_at", &[])
                        .await.map_err(|_| "own actual expiry".to_owned())?.get::<_,OffsetDateTime>(0))
                } else { None };
                let (pending_send, pending) = tokio::sync::oneshot::channel();
                let (resume_send, resume) = tokio::sync::oneshot::channel();
                let (ack_send, ack) = tokio::sync::oneshot::channel();
                let authority = f.administration.read_authority();
                *authority.save_receipt_rollback_gate.lock().map_err(|_| "own gate lock".to_owned())? =
                    Some(SaveReceiptRollbackGate { first_pending: pending_send, resume, actual_ack: ack_send });
                let original_auth = f.auth(); let administration = f.administration.clone();
                let task = tokio::spawn(async move {
                    openbot_application::get_artifact_save_receipt(administration.as_ref(), &original_auth,
                        GetArtifactSaveReceipt { request_id: request }).await
                });
                let controller_admission_limit = Instant::now()+Duration::from_secs(5);
                let mut resume_send = Some(resume_send);
                let control = async {
                    let deadline = tokio::time::timeout_at(tokio::time::Instant::from_std(controller_admission_limit),pending).await
                        .map_err(|_| "original rollback Pending deadline".to_owned())?
                        .map_err(|_| "original rollback first poll was not Pending".to_owned())?;
                    require(!task.is_finished(), "same original rollback task must remain pending")?;
                    if let Some(expiry) = expiry {
                        while OffsetDateTime::now_utc() < expiry {
                            require(Instant::now()<deadline, "actual Session expiry must remain within original budget")?;
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    } else { f._lease.close(); }
                    resume_send.take().ok_or_else(|| "own original resume missing".to_owned())?.send(())
                        .map_err(|_| "own original resume receiver gone".to_owned())?;
                    let actual_ack = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),ack).await
                        .map_err(|_| "same rollback ACK deadline".to_owned())?
                        .map_err(|_| "same rollback ACK absent".to_owned())?;
                    require(actual_ack, "same original rollback future must return real successful ACK")
                }.await;
                if let Some(sender) = resume_send.take() { let _ = sender.send(()); }
                let joined = task.await.map_err(|_| "own original task not joined".to_owned());
                let result = (|| { control?;
                    require(joined?.err() == Some(AppError::Unauthenticated), "original owner/clock tail must withhold every saved result")
                })();
                require(f.facts().await? == before, "rollback observation changed artifact business facts")?;
                f.pool.close(); drop(authority); drop(f);
                eprintln!("SAVE_RECEIPT_REAL_ROLLBACK source={source} clock_expiry={expire} pending_same_future_ack_tail_verified={}", result.is_ok());
                result
            }).await;
        }
    }
}
