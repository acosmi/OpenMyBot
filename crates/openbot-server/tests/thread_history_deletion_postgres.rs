//! V7-IMPL-031 part 1: public thread history deletion on real Server Hosts and an owned
//! PostgreSQL. The command runs through the shared production Application assembly and, for the
//! HTTP cases, the real Axum router. The fixtures, the run consumer and the reader snapshots are
//! test-owned and grant no authority.

#![cfg(unix)]

#[path = "support/transport_fixture.rs"]
mod transport_fixture;

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, BeginThreadRunRequest, OpenBotApplication, RunCancellationDisposition,
    RunDispatchConsumer, RunDispatchDecision, RunExecutionLease, RunFailureCode, RunRuntime,
    RunTerminal, ThreadDirectory,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{
    AppCommand, AppReply, BeginThreadRun, ThreadHistoryDeletionReceipt, ThreadHistoryDeletionState,
    ThreadRunAnchor,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{BotId, ChannelId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
    assemble_postgres_application,
};
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::db::{fresh, pool};
use openbot_infra::policy::PolicyStore;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::thread::ThreadRepo;
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::thread_history_authority::{
    PostgresThreadHistoryAuthority, ThreadHistoryStopClearConfirmation as Confirmation,
};
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder,
    SingleUserAuthResolver,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use uuid::Uuid;

type Result<T = ()> = std::result::Result<T, String>;
type Deletion = std::result::Result<ThreadHistoryDeletionReceipt, AppError>;

const DEP: &str = "owned-delete-deployment";
const TENANT: &str = "owned-delete-tenant";
const A: &str = "delete-a";
const B: &str = "delete-b";
const C: &str = "delete-admin";
const BOT: &str = "delete-bot";
const PROCESS: &str = "owned-delete-runtime";
const TEXT: &str = "OWNED_HISTORY_DELETION_BODY_CANARY café";
const SESSION_KEY: &[u8] = b"owned-history-deletion-session-key";
const ORIGIN: &str = "https://wrok-ui.example.test";
/// Resends of one request id before a test gives up on its deletion clearing.
const RESENDS: usize = 40;

fn check(ok: bool, reason: &str) -> Result {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn request_id() -> String {
    Uuid::now_v7().to_string()
}
fn text<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}
fn refused<T: std::fmt::Debug>(
    result: &std::result::Result<T, AppError>,
    expected: &AppError,
    status: u16,
) -> Result {
    match result {
        Err(error) if error == expected && error.http_status() == status => Ok(()),
        other => Err(format!("expected {expected:?} ({status}), got {other:?}")),
    }
}
fn receipt(result: &Deletion, j: &str, request: &str) -> Result<ThreadHistoryDeletionState> {
    let receipt = result
        .as_ref()
        .map_err(|error| format!("deletion refused: {error:?}"))?;
    check(
        receipt.thread_id.as_str() == j && receipt.request_id == request,
        "the receipt names another Thread or request",
    )?;
    Ok(receipt.state)
}

/// A test-owned dispatch consumer. It starts no model or tool and has no local child to stop.
#[derive(Default)]
struct Consumer {
    revoked: Mutex<HashSet<String>>,
}
#[async_trait]
impl RunDispatchConsumer for Consumer {
    async fn dispatch(&self, _: RunExecutionLease) -> RunDispatchDecision {
        RunDispatchDecision::RetryableBusy
    }
    async fn activate(&self, _: &RunExecutionLease) -> std::result::Result<(), RunFailureCode> {
        Ok(())
    }
    async fn revoke(&self, lease: &RunExecutionLease) -> RunCancellationDisposition {
        self.revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(lease.run_id().as_str().to_owned());
        RunCancellationDisposition::NoLocalChild
    }
}

#[derive(Default)]
struct NoRemote;
#[async_trait]
impl openbot_application::provider::RemoteAguiTransport for NoRemote {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> std::result::Result<
        Box<dyn openbot_application::provider::RemoteAguiEventStream>,
        openbot_application::provider::RemoteAguiTransportError,
    > {
        Err(openbot_application::provider::RemoteAguiTransportError::Unavailable)
    }
}

struct Fixture {
    pool: pool::DatabasePool,
    registry: Arc<ArtifactDatasetRegistry>,
    authority: Arc<PostgresThreadHistoryAuthority>,
    resolver: Arc<PostgresSessionAuthResolver>,
    assembly: PostgresApplicationAssembly,
    directory: PostgresThreadDirectory,
    router: axum::Router,
}
impl Fixture {
    async fn new(config: pool::DatabaseConfig, generation: u64) -> Result<Self> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config).await.map_err(text)?;
        {
            let mut c = pool.get().await.map_err(text)?;
            fresh::apply(&mut c).await.map_err(text)?;
            let g = i64::try_from(generation).map_err(text)?;
            for (actor, email, role) in [
                (A, "delete-a@example.test", "user"),
                (B, "delete-b@example.test", "user"),
                (C, "delete-admin@example.test", "admin"),
                ("dev-local-user", "dev@openbot.local", "admin"),
            ] {
                c.execute(
                    "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,$3)",
                    &[&actor, &email, &g],
                )
                .await
                .map_err(text)?;
                c.execute(
                    "INSERT INTO public.user_roles(user_id,role) VALUES($1,$2::text::public.role)",
                    &[&actor, &role],
                )
                .await
                .map_err(text)?;
            }
            c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('delete-bot','Delete bot','built_in','{\"systemPrompt\":\"Owned delete prompt\",\"providerSource\":\"managed\"}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('delete-bot','delete-a','Delete bot','','delete','public');").await.map_err(text)?;
            let now = OffsetDateTime::now_utc() - time::Duration::seconds(1);
            for actor in [A, B, C] {
                let id = format!("{actor}-session-1");
                let cookie = format!("owned-delete-cookie-{actor}-01");
                let hash = SessionTokenHash::compute(
                    SessionToken::new(cookie.as_bytes()),
                    SessionHashKey::new(SESSION_KEY),
                )
                .to_column_value();
                c.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,$6)",&[&id,&actor,&hash,&(now+time::Duration::hours(1)),&now,&g]).await.map_err(text)?;
            }
        }
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                pool.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .map_err(text)?,
        );
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x61; 32]).map_err(text)?,
        );
        let policy_store = PolicyStore::postgres(pool.clone(), None);
        policy_store.load().await.map_err(text)?;
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: pool.clone(),
            listener_database: config.clone().into(),
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            single_user: false,
            admin_floor: None,
            model: "owned-model".into(),
            credential_key_id: "owned-key-ref".into(),
            credential_vault: vault,
            audit_key: SecretBytes::new(vec![0x62; 32]),
            remote_assertions: Arc::new(
                RemoteRunAssertionSigner::new(vec![0x63; 32]).map_err(text)?,
            ),
            mcp_oauth_state_key: SecretBytes::new(vec![0x64; 32]),
            policy_store,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(NoRemote),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: url::Url::parse("http://127.0.0.1:9/v1/chat/completions")
                    .map_err(text)?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".into()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
            extra_provider_adapters: Vec::new(),
            run_event_subscriber: None,
            delegation_authority: None,
        })
        .await
        .map_err(text)?;
        assembly
            .model_dataset_binding
            .enroll_original_registry(&registry)
            .map_err(text)?;
        let authority = Arc::clone(&assembly.thread_history_authority);
        authority
            .enroll_original_registry(&registry)
            .map_err(text)?;
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                openbot_infra::auth::config::default_session_lifetime(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .map_err(text)?,
        );
        resolver
            .install_thread_history_authority(&authority)
            .map_err(text)?;
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config,
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(text)?;
        let security = SensitiveWriteSecurity::new(
            openbot_infra::auth::config::default_session_lifetime(),
            TrustedOrigins::from_configured([ORIGIN]).map_err(text)?,
        );
        let router = transport_fixture::loopback_router(
            ServerBuilder::new(assembly.application.clone(), resolver.clone())
                .with_transport_policy(transport_fixture::loopback_policy())
                .with_sensitive_write_security(security)
                .build(),
        );
        Ok(Self {
            pool,
            registry,
            authority,
            resolver,
            assembly,
            directory,
            router,
        })
    }
    async fn auth(&self, actor: &str) -> Result<AuthContext> {
        self.resolver
            .resolve(
                &http::Request::builder()
                    .uri("/owned-delete")
                    .header(
                        "cookie",
                        format!("openbot_session=owned-delete-cookie-{actor}-01"),
                    )
                    .body(())
                    .map_err(text)?
                    .into_parts()
                    .0,
            )
            .await
            .map_err(text)
    }
    async fn sql(&self, sql: &str) -> Result {
        self.pool
            .get()
            .await
            .map_err(text)?
            .batch_execute(sql)
            .await
            .map_err(text)
    }
    async fn one<T: tokio_postgres::types::FromSqlOwned>(&self, sql: &str, key: &str) -> Result<T> {
        self.pool
            .get()
            .await
            .map_err(text)?
            .query_one(sql, &[&key])
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)
    }
    /// One public deletion step through the shared production Application.
    async fn delete(&self, auth: &AuthContext, j: &str, request: &str) -> Deletion {
        self.assembly
            .application
            .execute(
                auth.clone(),
                AppCommand::DeleteThreadHistory {
                    thread_id: ThreadId::new(j),
                    request_id: request.to_owned(),
                },
            )
            .await
            .and_then(|reply| match reply {
                AppReply::ThreadHistoryDeletion(receipt) => Ok(receipt),
                _ => Err(AppError::DependencyUnavailable {
                    dependency: "unexpected_reply",
                }),
            })
    }
    /// Resend the same request id, boundedly, until the deletion is cleared. Returns how many
    /// pending receipts came first.
    async fn delete_until_cleared(
        &self,
        auth: &AuthContext,
        j: &str,
        request: &str,
    ) -> Result<usize> {
        for pending in 0..RESENDS {
            let state = receipt(&self.delete(auth, j, request).await, j, request)?;
            if state == ThreadHistoryDeletionState::Cleared {
                return Ok(pending);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("the deletion never cleared within the bounded resends".into())
    }
    fn request(
        &self,
        auth: &AuthContext,
        index: u64,
        anchor: ThreadRunAnchor,
    ) -> BeginThreadRunRequest {
        let mut entropy = [0; 16];
        entropy[8..].copy_from_slice(&index.to_be_bytes());
        BeginThreadRunRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(auth.deployment()).mint_from_entropy(entropy),
                run_id: RunId::new(format!("owned-delete-run-{index}")),
                bot_id: BotId::new(BOT),
                anchor,
                message: TEXT.into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        }
    }
    async fn claim(&self, run: &str) -> Result<(PostgresRunRuntime, RunExecutionLease)> {
        let runtime = PostgresRunRuntime::new(
            self.pool.clone(),
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(text)?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(text)?
            .ok_or("pending real dispatch absent")?;
        let lease = runtime.acknowledge_dispatch(&claim).await.map_err(text)?;
        check(
            lease.run_id().as_str() == run,
            "a different run was claimed",
        )?;
        Ok((runtime, lease))
    }
    /// A settled direct Thread of the actor: its only Run begun, claimed and completed.
    async fn settled(&self, auth: &AuthContext, index: u64) -> Result<String> {
        let req = self.request(auth, index, ThreadRunAnchor::DirectBot);
        self.directory
            .begin_thread_run(req.clone())
            .await
            .map_err(text)?;
        let (runtime, lease) = self.claim(req.command.run_id.as_str()).await?;
        runtime
            .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map_err(text)?;
        Ok(req.command.thread_id.as_str().to_owned())
    }
    /// A private agent channel of the creator with the other actors added as members.
    async fn channel(&self, creator: &AuthContext, members: &[&str]) -> Result<(String, String)> {
        let created = openbot_application::create_channel(
            &ChannelRepo::new(self.pool.clone()),
            creator,
            vec![BotId::new(BOT)],
        )
        .await
        .map_err(text)?;
        let channel: String = created.id.as_str().into();
        for member in members {
            self.sql(&format!(
                "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('{channel}','{member}')"
            ))
            .await?;
        }
        let thread = created
            .thread_id
            .ok_or("channel producer did not mint a Thread")?;
        Ok((channel, thread.as_str().into()))
    }
    /// A member's Run in a channel Thread, begun, dispatched and leased: in flight.
    async fn channel_in_flight(
        &self,
        member: &AuthContext,
        index: u64,
        channel: &str,
        j: &str,
    ) -> Result<String> {
        let mut req = self.request(
            member,
            index,
            ThreadRunAnchor::Channel {
                channel_id: ChannelId::new(channel),
            },
        );
        req.command.thread_id = ThreadId::new(j);
        self.directory
            .begin_thread_run(req.clone())
            .await
            .map_err(text)?;
        self.claim(req.command.run_id.as_str()).await?;
        Ok(req.command.run_id.as_str().to_owned())
    }
    fn relay(&self, consumer: &Arc<Consumer>) -> Result<RunRelay> {
        let runtime: Arc<dyn RunRuntime> = Arc::new(
            PostgresRunRuntime::new(
                self.pool.clone(),
                PROCESS.into(),
                DEFAULT_THREAD_LEASE_DURATION,
                DEFAULT_DISPATCH_CLAIM_DURATION,
            )
            .map_err(text)?,
        );
        let consumer: Arc<dyn RunDispatchConsumer> = consumer.clone();
        Ok(RunRelay::start(runtime, consumer))
    }
    async fn run_status(&self, run: &str) -> Result<String> {
        self.one("SELECT status FROM public.runs WHERE run_id=$1", run)
            .await
    }
    async fn run_is(&self, run: &str, status: &str) -> Result<bool> {
        Ok(self.run_status(run).await? == status)
    }
    async fn thread_status(&self, j: &str) -> Result<String> {
        self.one("SELECT status FROM public.threads WHERE thread_id=$1", j)
            .await
    }
    /// Every history deletion fact of the database with row versions, and every Thread's status:
    /// any new intent, batch, completion or soft delete changes this value.
    async fn history_facts(&self) -> Result<Value> {
        let c = self.pool.get().await.map_err(text)?;
        let mut out = serde_json::Map::new();
        for (name, order) in [
            ("openbot_internal.thread_history_heads", "x.thread_id"),
            (
                "openbot_internal.thread_history_clear_intents",
                "x.operation_id",
            ),
            (
                "openbot_internal.thread_history_clear_batches",
                "x.operation_id,x.batch_seq",
            ),
            (
                "openbot_internal.thread_history_clear_completions",
                "x.operation_id",
            ),
        ] {
            let sql = format!(
                "SELECT coalesce(jsonb_agg(to_jsonb(x)||jsonb_build_object('xmin',x.xmin::text) ORDER BY {order}),'[]'::jsonb) FROM {name} x"
            );
            let value: Value = c
                .query_one(&sql, &[])
                .await
                .map_err(text)?
                .try_get(0)
                .map_err(text)?;
            out.insert(name.into(), value);
        }
        let threads: Value = c
            .query_one(
                "SELECT coalesce(jsonb_agg(jsonb_build_object('id',thread_id,'status',status,'deleted_at',deleted_at,'xmin',xmin::text) ORDER BY thread_id),'[]'::jsonb) FROM public.threads",
                &[],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        out.insert("public.threads".into(), threads);
        Ok(Value::Object(out))
    }
    /// The cleared and soft-deleted end state of J for this request and actor, read independently.
    async fn cleared(&self, auth: &AuthContext, j: &str, request: &str) -> Result {
        let c = self.pool.get().await.map_err(text)?;
        let exact: bool = c
            .query_one(
                "SELECT t.status='deleted' AND t.deleted_at IS NOT NULL AND t.title IS NULL \
                   AND h.phase='closed' AND h.closure_operation_id=q.operation_id \
                   AND q.intent_kind='stop_clear' AND q.request_id=$2 AND q.actor_id=$3 \
                   AND c.source='stop_clear' AND c.operation_id=q.operation_id \
                   AND NOT EXISTS(SELECT 1 FROM public.messages m WHERE m.thread_id=t.thread_id \
                                  AND m.content<>'{\"text\":\"\",\"retained\":false}'::jsonb) \
                 FROM public.threads t \
                 JOIN openbot_internal.thread_history_heads h ON h.thread_id=t.thread_id \
                 JOIN openbot_internal.thread_history_clear_intents q ON q.thread_id=t.thread_id \
                 JOIN openbot_internal.thread_history_clear_completions c ON c.thread_id=t.thread_id \
                 WHERE t.thread_id=$1",
                &[&j, &request, &auth.actor().as_str()],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        check(
            exact,
            "J is not cleared and soft deleted under this request's own stop/clear operation",
        )?;
        // Every read of the deleted Thread is gone for its creator.
        refused(
            &self
                .assembly
                .application
                .execute(
                    auth.clone(),
                    AppCommand::GetThreadHistory {
                        thread_id: ThreadId::new(j),
                    },
                )
                .await,
            &AppError::NotVisible,
            404,
        )?;
        refused(
            &self
                .assembly
                .application
                .execute(
                    auth.clone(),
                    AppCommand::GetThreadConversation {
                        thread_id: ThreadId::new(j),
                    },
                )
                .await,
            &AppError::NotVisible,
            404,
        )?;
        let status = self
            .assembly
            .application
            .execute(
                auth.clone(),
                AppCommand::GetThreadStatus {
                    thread_id: ThreadId::new(j),
                },
            )
            .await
            .map_err(text)?;
        check(
            matches!(status, AppReply::ThreadStatus(ref s) if !s.known),
            "the deleted Thread is still known",
        )
    }
    /// A real old snapshot of another backend: it holds a REPEATABLE READ snapshot from now on.
    async fn reader(&self, j: &str) -> Result<pool::PooledClient> {
        let reader = self.pool.get().await.map_err(text)?;
        reader
            .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .await
            .map_err(text)?;
        reader
            .query_one(
                "SELECT count(*) FROM public.messages WHERE thread_id=$1",
                &[&j],
            )
            .await
            .map_err(text)?;
        let pid: i32 = reader
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        let held: bool = self
            .pool
            .get()
            .await
            .map_err(text)?
            .query_one(
                "SELECT backend_xmin IS NOT NULL FROM pg_stat_activity WHERE pid=$1",
                &[&pid],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        check(held, "the reader does not own a real snapshot")?;
        Ok(reader)
    }
    async fn post(&self, actor: &str, j: &str, body: &str) -> Result<(StatusCode, Value)> {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/threads/{j}/history/deletions"))
                    .header(
                        http::header::COOKIE,
                        format!("openbot_session=owned-delete-cookie-{actor}-01"),
                    )
                    .header(http::header::ORIGIN, ORIGIN)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_owned()))
                    .map_err(text)?,
            )
            .await
            .map_err(text)?;
        let status = response.status();
        check(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                == Some("no-store"),
            "the deletion route answered without no-store",
        )?;
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .map_err(text)?;
        let value = serde_json::from_slice(&body).map_err(text)?;
        Ok((status, value))
    }
    async fn finish(self) -> Result {
        self.resolver.close_request_bindings();
        self.assembly.shutdown().await;
        drop(self.router);
        drop(self.directory);
        drop(self.authority);
        drop(self.registry);
        drop(self.resolver);
        close_pool(self.pool).await
    }
}
async fn close_pool(p: pool::DatabasePool) -> Result {
    let observations = p.connection_observations();
    p.close();
    for o in observations {
        check(
            o.wait_for_destruction_before(Instant::now() + Duration::from_secs(10))
                .await
                .map_err(text)?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "own connection destruction unobserved",
        )?;
    }
    Ok(())
}
async fn owned<F, Fut>(tag: &str, generation: u64, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let f = Fixture::new(config, generation).await?;
        body(f).await
    })
    .await;
}
async fn until<F, Fut>(what: &str, mut probe: F) -> Result
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if probe().await? {
            return Ok(());
        }
        check(Instant::now() < end, &format!("timed out waiting: {what}"))?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// T1 and T2.
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_deletion_creator_clears_and_soft_deletes_then_resend_is_not_visible() {
    owned("delete01", 7, |f| async move {
        let a = f.auth(A).await?;
        let j = f.settled(&a, 101).await?;
        let request = request_id();
        let first = f.delete(&a, &j, &request).await;
        let state = receipt(&first, &j, &request)?;
        check(
            matches!(
                state,
                ThreadHistoryDeletionState::Pending | ThreadHistoryDeletionState::Cleared
            ),
            "the first call is neither pending nor cleared",
        )?;
        let pending = if state == ThreadHistoryDeletionState::Cleared {
            0
        } else {
            1 + f.delete_until_cleared(&a, &j, &request).await?
        };
        f.cleared(&a, &j, &request).await?;
        // T2: once cleared, the same request is a resend on a deleted Thread: not visible, and
        // nothing is written.
        let facts = f.history_facts().await?;
        refused(&f.delete(&a, &j, &request).await, &AppError::NotVisible, 404)?;
        refused(&f.delete(&a, &j, &request_id()).await, &AppError::NotVisible, 404)?;
        check(
            facts == f.history_facts().await?,
            "a resend after the deletion wrote a history fact",
        )?;
        eprintln!(
            "THREAD_HISTORY_DELETION id=T1 first={state:?} pending_resends={pending} cleared=true soft_deleted=true reads_not_visible=true T2_resend=404"
        );
        f.finish().await
    })
    .await;
}

// T3.
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_deletion_non_creator_admin_legacy_and_missing_are_not_visible() {
    owned("delete03", 7, |f| async move {
        let a = f.auth(A).await?;
        let b = f.auth(B).await?;
        let admin = f.auth(C).await?;
        let (_, channel_j) = f.channel(&a, &[B, C]).await?;
        let direct = f.settled(&a, 301).await?;
        f.sql(&format!(
            "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES('{direct}','{B}')"
        ))
        .await?;
        let legacy = f
            .request(&a, 302, ThreadRunAnchor::DirectBot)
            .command
            .thread_id
            .as_str()
            .to_owned();
        let now = OffsetDateTime::now_utc();
        ThreadRepo::new(f.pool.clone())
            .insert(&openbot_infra::db::tables::threads::Row {
                thread_id: legacy.clone(),
                deployment_id: DEP.into(),
                tenant_id: TENANT.into(),
                created_by: A.into(),
                anchor_kind: "direct_bot".into(),
                anchor_id: BOT.into(),
                title: Some("Legacy".into()),
                status: "active".into(),
                next_message_seq: 0,
                next_event_seq: 0,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            })
            .await
            .map_err(text)?;
        f.sql(&format!(
            "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES('{legacy}','{A}')"
        ))
        .await?;
        let missing = f
            .request(&a, 399, ThreadRunAnchor::DirectBot)
            .command
            .thread_id
            .as_str()
            .to_owned();
        let facts = f.history_facts().await?;
        let request = request_id();
        for (who, j) in [
            (&b, &channel_j),
            (&admin, &channel_j),
            (&b, &direct),
            (&admin, &direct),
            (&a, &legacy),
            (&a, &missing),
        ] {
            refused(&f.delete(who, j, &request).await, &AppError::NotVisible, 404)?;
        }
        check(
            facts == f.history_facts().await?,
            "a refused deletion wrote an intent or another history fact",
        )?;
        // None of that consumed the request id or the creator's right.
        f.delete_until_cleared(&a, &direct, &request).await?;
        f.cleared(&a, &direct, &request).await?;
        eprintln!(
            "THREAD_HISTORY_DELETION id=T3 member=404 admin=404 legacy=404 missing=404 intents_written=0 creator_then_cleared=true"
        );
        f.finish().await
    })
    .await;
}

// T4.
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_deletion_closed_thread_conflicts_and_other_actor_never_advances_clearing() {
    owned("delete04", 7, |f| async move {
        let a = f.auth(A).await?;
        let b = f.auth(B).await?;
        let (_, j) = f.channel(&a, &[B]).await?;
        let own_b = f.settled(&b, 402).await?;
        // J is closed by the creator's own ACK1 for r1 and nothing after it ran yet.
        let r1 = request_id();
        let intent = f
            .authority
            .close_for_stop_clear_before(&a, &j, &r1, deadline())
            .await
            .map_err(text)?;
        check(
            intent.confirmation() == Confirmation::CommitAcknowledged,
            "premise: J was not closed by a new intent",
        )?;
        let facts = f.history_facts().await?;
        // Another actor with the same request id never advances J's clearing: on J that actor is
        // not the creator, and on that actor's own Thread the id is already taken.
        let foreign = f.delete(&b, &j, &r1).await;
        check(
            facts == f.history_facts().await?,
            "another actor's deletion with the same request id advanced J's clearing",
        )?;
        refused(&foreign, &AppError::NotVisible, 404)?;
        let taken = f.delete(&b, &own_b, &r1).await;
        check(
            facts == f.history_facts().await?,
            "another actor's deletion of its own Thread with a taken request id wrote a fact",
        )?;
        refused(
            &taken,
            &AppError::RequestConflict {
                resource: "thread_history",
            },
            409,
        )?;
        // Another request on the closed J, even by its creator, conflicts.
        let other = f.delete(&a, &j, &request_id()).await;
        check(
            facts == f.history_facts().await?,
            "another request on the closed J wrote a batch, completion, intent or soft delete",
        )?;
        refused(
            &other,
            &AppError::RequestConflict {
                resource: "thread_history",
            },
            409,
        )?;
        // The creator resumes r1 after its bare ACK1.
        f.delete_until_cleared(&a, &j, &r1).await?;
        f.cleared(&a, &j, &r1).await?;
        check(
            f.thread_status(&own_b).await? == "active",
            "the other actor's own Thread changed",
        )?;
        eprintln!(
            "THREAD_HISTORY_DELETION id=T4 other_actor_on_j=404 other_actor_same_request=409 other_request=409 clearing_advanced=false creator_resumed=cleared"
        );
        f.finish().await
    })
    .await;
}

// T5.
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_deletion_waits_for_other_members_running_run_before_soft_delete() {
    owned("delete05", 7, |f| async move {
        let a = f.auth(A).await?;
        let b = f.auth(B).await?;
        let (channel, j) = f.channel(&a, &[B]).await?;
        let run = f.channel_in_flight(&b, 501, &channel, &j).await?;
        let request = request_id();
        let first = f.delete(&a, &j, &request).await;
        check(
            receipt(&first, &j, &request)? == ThreadHistoryDeletionState::Pending,
            "a deletion with another member's running Run was not pending",
        )?;
        check(
            f.thread_status(&j).await? != "deleted",
            "the Thread was soft deleted before its clearing completed",
        )?;
        check(
            f.run_status(&run).await? == "running"
                && f.one::<i64>(
                    "SELECT count(*) FROM public.outbox WHERE outbox_id=$1 AND status='pending'",
                    &format!("{run}:agent_run_cancel"),
                )
                .await?
                    == 1,
            "the drain did not request the other member's Run to stop",
        )?;
        // A resend while the Run still runs stays pending and still does not soft delete.
        check(
            receipt(&f.delete(&a, &j, &request).await, &j, &request)?
                == ThreadHistoryDeletionState::Pending
                && f.thread_status(&j).await? != "deleted",
            "a resend with the Run still running soft deleted the Thread",
        )?;
        // The existing consumer ends the Run cancelled; then the same request clears.
        let consumer = Arc::new(Consumer::default());
        let relay = f.relay(&consumer)?;
        until("the other member's Run is cancelled", || {
            f.run_is(&run, "cancelled")
        })
        .await?;
        relay.stop().await;
        check(
            consumer
                .revoked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&run),
            "the relay did not revoke the other member's Run",
        )?;
        f.delete_until_cleared(&a, &j, &request).await?;
        f.cleared(&a, &j, &request).await?;
        eprintln!(
            "THREAD_HISTORY_DELETION id=T5 first=Pending soft_deleted_while_running=false run_cancelled=true then=cleared"
        );
        f.finish().await
    })
    .await;
}

// T6.
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_deletion_old_reader_snapshot_keeps_it_pending() {
    owned("delete06", 7, |f| async move {
        let a = f.auth(A).await?;
        let j = f.settled(&a, 601).await?;
        let reader = f.reader(&j).await?;
        let request = request_id();
        check(
            receipt(&f.delete(&a, &j, &request).await, &j, &request)?
                == ThreadHistoryDeletionState::Pending,
            "an old reader snapshot did not keep the deletion pending",
        )?;
        let progress: bool = f
            .one(
                "SELECT EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_batches b \
                   JOIN openbot_internal.thread_history_clear_intents q USING(operation_id) \
                   WHERE q.thread_id=$1) \
                 AND NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_completions \
                   WHERE thread_id=$1)",
                &j,
            )
            .await?;
        check(
            progress && f.thread_status(&j).await? != "deleted",
            "the waiting deletion lost its batches, completed or soft deleted",
        )?;
        let old: String = reader
            .query_one(
                "SELECT content->>'text' FROM public.messages WHERE thread_id=$1 AND role='user'",
                &[&j],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        check(old == TEXT, "the old snapshot changed")?;
        reader.batch_execute("ROLLBACK").await.map_err(text)?;
        drop(reader);
        f.delete_until_cleared(&a, &j, &request).await?;
        f.cleared(&a, &j, &request).await?;
        eprintln!(
            "THREAD_HISTORY_DELETION id=T6 awaiting_readers=Pending batches_kept=true then=cleared"
        );
        f.finish().await
    })
    .await;
}

// T7.
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_deletion_real_single_user_owner_clears() {
    owned("delete07", 0, |f| async move {
        let principal = openbot_infra::auth::single_user::load_single_user_principal(
            &f.pool,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )
        .await
        .map_err(text)?;
        let resolver = SingleUserAuthResolver::from_verified_principal(
            principal,
            openbot_infra::auth::config::default_session_lifetime(),
        );
        let authority = Arc::new(
            PostgresThreadHistoryAuthority::new(
                f.pool.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .map_err(text)?,
        );
        authority
            .enroll_original_registry(&f.registry)
            .map_err(text)?;
        authority
            .enroll_clear_audit_checkpoint_key(SecretBytes::new(vec![0x65; 32]))
            .map_err(text)?;
        resolver
            .install_thread_history_authority(&authority, &f.pool)
            .map_err(text)?;
        let application = OpenBotApplication::new(ChannelRepo::new(f.pool.clone()))
            .with_thread_history_deletion(authority.clone());
        let auth = resolver
            .resolve(
                &http::Request::builder()
                    .uri("/owned-delete-single")
                    .body(())
                    .map_err(text)?
                    .into_parts()
                    .0,
            )
            .await
            .map_err(text)?;
        let j = f.settled(&auth, 701).await?;
        let request = request_id();
        let mut cleared = false;
        for _ in 0..RESENDS {
            let reply = application
                .execute(
                    auth.clone(),
                    AppCommand::DeleteThreadHistory {
                        thread_id: ThreadId::new(&j),
                        request_id: request.clone(),
                    },
                )
                .await
                .map_err(text)?;
            let AppReply::ThreadHistoryDeletion(r) = reply else {
                return Err("unexpected reply".into());
            };
            check(
                r.thread_id.as_str() == j && r.request_id == request,
                "the receipt names another Thread or request",
            )?;
            if r.state == ThreadHistoryDeletionState::Cleared {
                cleared = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        check(cleared, "the single-user owner deletion never cleared")?;
        f.cleared(&auth, &j, &request).await?;
        resolver.close_request_bindings();
        drop(application);
        drop(resolver);
        drop(authority);
        eprintln!("THREAD_HISTORY_DELETION id=T7 host=ServerSingleUserOwner cleared=true");
        f.finish().await
    })
    .await;
}

// T8.
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_deletion_http_route_statuses_closed_body_and_no_store() {
    owned("delete08", 7, |f| async move {
        let a = f.auth(A).await?;
        let j = f.settled(&a, 801).await?;
        let request = request_id();
        let facts = f.history_facts().await?;
        let v4 = Uuid::new_v4().to_string();
        for body in [
            json!({"requestId": request, "threadId": j}).to_string(),
            json!({}).to_string(),
            "not json".to_owned(),
            json!({"requestId": request.to_uppercase()}).to_string(),
            json!({"requestId": v4}).to_string(),
        ] {
            let (status, value) = f.post(A, &j, &body).await?;
            check(
                status == StatusCode::BAD_REQUEST && value == json!({"code": "malformed_payload"}),
                "a closed-body or malformed request id deletion was not 400",
            )?;
        }
        check(
            facts == f.history_facts().await?,
            "a 400 deletion wrote a history fact",
        )?;
        let body = json!({"requestId": request}).to_string();
        let reader = f.reader(&j).await?;
        let (status, value) = f.post(A, &j, &body).await?;
        check(
            status == StatusCode::ACCEPTED
                && value == json!({"threadId": j, "requestId": request, "state": "pending"}),
            "a pending deletion was not 202 with its pending receipt",
        )?;
        reader.batch_execute("ROLLBACK").await.map_err(text)?;
        drop(reader);
        let mut cleared = false;
        for _ in 0..RESENDS {
            let (status, value) = f.post(A, &j, &body).await?;
            if status == StatusCode::OK {
                check(
                    value == json!({"threadId": j, "requestId": request, "state": "cleared"}),
                    "a cleared deletion did not return its cleared receipt",
                )?;
                cleared = true;
                break;
            }
            check(status == StatusCode::ACCEPTED, "a resend was neither 202 nor 200")?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        check(cleared, "the HTTP deletion never cleared")?;
        f.cleared(&a, &j, &request).await?;
        let (status, value) = f.post(A, &j, &body).await?;
        check(
            status == StatusCode::NOT_FOUND && value == json!({"code": "not_visible"}),
            "a resend after the deletion was not 404",
        )?;
        eprintln!(
            "THREAD_HISTORY_DELETION id=T8 closed_body=400 malformed_request=400 pending=202 cleared=200 resend=404 no_store=true"
        );
        f.finish().await
    })
    .await;
}
