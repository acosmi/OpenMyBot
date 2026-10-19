//! V7-IMPL-038: real Server Host -> one-J stop/clear intent producer -> owned PostgreSQL.
//! Eight outer cases (C01-C08) on production Server Host producers. The fixtures, the protocol
//! relay and the lock probes are test-owned. They grant no Host authority and credit neither
//! ACK2 nor Run drain, byte deletion or Ready.

#![cfg(unix)]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::{
    BeginThreadRunRequest, BeginThreadRunV2Request, RunExecutionLease, RunRuntime, RunRuntimeError,
    RunSemanticChannel, RunTerminal, ThreadDirectory, ThreadDirectoryError,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, BeginThreadRunV2, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::model_connections::{
    CreateModelConnection, CustomModelProtocol, ModelApiKey,
};
use openbot_contracts::versioned_model_selection::{
    ModelSelectionIntentSource, RunModelSelectionV2,
};
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
    assemble_postgres_application,
};
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::db::{InfraError, fresh, pool};
use openbot_infra::model_connections::PostgresModelConnections;
use openbot_infra::policy::PolicyStore;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::thread::{MessageRepo, ThreadRepo};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::thread_history_authority::{
    PostgresThreadHistoryAuthority, ThreadHistoryStopClearConfirmation as Confirmation,
    ThreadHistoryStopClearError as Stop, ThreadHistoryStopClearIntent as Intent,
};
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::{AuthResolver, PostgresSessionAuthResolver, SingleUserAuthResolver};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use uuid::Uuid;
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, String>;
type Close = std::result::Result<Intent, Stop>;

const DEP: &str = "owned-stop-deployment";
const TENANT: &str = "owned-stop-tenant";
const A: &str = "stop-a";
const B: &str = "stop-b";
const C: &str = "stop-admin";
const BOT: &str = "stop-bot";
const PROCESS: &str = "owned-stop-runtime";
const TEXT: &str = "OWNED_STOP_CLEAR_BODY_CANARY café";
const SESSION_KEY: &[u8] = b"owned-stop-clear-session-key";
const BEGUN: &[u8] = b"START TRANSACTION\0";
const COMMIT: &[u8] = b"COMMIT\0";
const ROLLBACK: &[u8] = b"ROLLBACK\0";
const INSERTED: &[u8] = b"INSERT 0 1\0";
const UPDATED: &[u8] = b"UPDATE 1\0";
const SETTLED: &[u8] = b"SET CONSTRAINTS\0";

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
fn not_visible(r: &Close) -> Result {
    check(
        matches!(r, Err(Stop::NotVisible)),
        "expected exact current NotVisible",
    )
}
fn conflict(r: &Close) -> Result {
    check(matches!(r, Err(Stop::Conflict)), "expected exact Conflict")
}
fn unavailable(r: &Close) -> Result {
    check(
        matches!(r, Err(Stop::Unavailable)),
        "expected exact Unavailable",
    )
}
fn host_refused(r: &Close) -> Result {
    check(
        matches!(r, Err(Stop::Host(_))),
        "expected actual Host refusal",
    )
}
/// The exact acknowledged-commit result for this request; returns the new operation id.
fn committed(r: &Close, auth: &AuthContext, j: &str, request: &str) -> Result<String> {
    let intent = r.as_ref().map_err(|e| format!("not committed: {e:?}"))?;
    check(
        intent.confirmation() == Confirmation::CommitAcknowledged
            && intent.request_id() == request
            && intent.thread_id().as_str() == j
            && intent.deployment_id() == auth.deployment()
            && intent.tenant_id() == auth.tenant(),
        "result is not the exact acknowledged commit for this J and request",
    )?;
    let operation = intent.operation_id();
    let shown = format!("{intent:?}");
    check(
        !shown.contains(operation) && !shown.contains(j) && !shown.contains(request),
        "the result's Debug output leaks an identifier",
    )?;
    let parsed = Uuid::parse_str(operation).map_err(text)?;
    check(
        parsed.get_version_num() == 7 && parsed.hyphenated().to_string() == operation,
        "operation id is not canonical lowercase UUIDv7",
    )?;
    Ok(operation.to_owned())
}
/// The exact replay of an earlier intent: its original operation id, no new write.
fn replayed(r: &Close, j: &str, request: &str, operation: &str) -> Result {
    let intent = r.as_ref().map_err(|e| format!("not replayed: {e:?}"))?;
    check(
        intent.confirmation() == Confirmation::ExactReplayRollbackAcknowledged
            && intent.request_id() == request
            && intent.thread_id().as_str() == j
            && intent.operation_id() == operation,
        "result is not the exact replay with the original operation id",
    )
}

#[derive(Default)]
struct NoRemote;
#[async_trait::async_trait]
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
    config: pool::DatabaseConfig,
    registry: Arc<ArtifactDatasetRegistry>,
    authority: Arc<PostgresThreadHistoryAuthority>,
    resolver: Arc<PostgresSessionAuthResolver>,
    assembly: PostgresApplicationAssembly,
    directory: PostgresThreadDirectory,
    models: PostgresModelConnections,
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
                (A, "stop-a@example.test", "user"),
                (B, "stop-b@example.test", "user"),
                (C, "stop-admin@example.test", "admin"),
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
            c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('stop-bot','Stop bot','built_in','{\"systemPrompt\":\"Owned stop prompt\",\"providerSource\":\"managed\"}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('stop-bot','stop-a','Stop bot','','stop','public');").await.map_err(text)?;
            let now = OffsetDateTime::now_utc() - time::Duration::seconds(1);
            for (actor, index) in [(A, 1_u8), (A, 2), (B, 1), (C, 1)] {
                let id = format!("{actor}-session-{index}");
                let cookie = format!("owned-stop-cookie-{actor}-{index:02}");
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
            credential_vault: vault.clone(),
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
            config.clone(),
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(text)?
        .with_model_dataset_binding(Arc::clone(&assembly.model_dataset_binding))
        .map_err(text)?;
        let models = PostgresModelConnections::new(
            pool.clone(),
            vault,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x62; 32]),
        )
        .map_err(text)?;
        Ok(Self {
            pool,
            config,
            registry,
            authority,
            resolver,
            assembly,
            directory,
            models,
        })
    }
    async fn auth(&self, actor: &str, index: u8) -> Result<AuthContext> {
        self.resolver
            .resolve(
                &http::Request::builder()
                    .uri("/owned-stop")
                    .header(
                        "cookie",
                        format!("openbot_session=owned-stop-cookie-{actor}-{index:02}"),
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
    async fn close(&self, auth: &AuthContext, j: &str, request: &str) -> Close {
        self.authority
            .close_for_stop_clear_before(auth, j, request, deadline())
            .await
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
                run_id: RunId::new(format!("owned-stop-run-{index}")),
                bot_id: BotId::new(BOT),
                anchor,
                message: TEXT.into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        }
    }
    async fn begin(&self, auth: &AuthContext, index: u64) -> Result<BeginThreadRunRequest> {
        let req = self.request(auth, index, ThreadRunAnchor::DirectBot);
        self.directory
            .begin_thread_run(req.clone())
            .await
            .map_err(text)?;
        Ok(req)
    }
    /// A further new Run on the same J; only a closed H may make this refuse.
    async fn begin_again(
        &self,
        req: &BeginThreadRunRequest,
        run: &str,
    ) -> std::result::Result<(), ThreadDirectoryError> {
        let mut again = req.clone();
        again.command.run_id = RunId::new(run);
        self.directory.begin_thread_run(again).await.map(|_| ())
    }
    /// A settled direct V1 Thread: begin it, then claim and complete its only Run.
    async fn settled(
        &self,
        auth: &AuthContext,
        index: u64,
    ) -> Result<(BeginThreadRunRequest, String)> {
        let req = self.begin(auth, index).await?;
        self.settle(req.command.run_id.as_str()).await?;
        let j = req.command.thread_id.as_str().to_owned();
        Ok((req, j))
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
        check(lease.run_id().as_str() == run, "different run claimed")?;
        Ok((runtime, lease))
    }
    async fn settle(&self, run: &str) -> Result {
        let (runtime, lease) = self.claim(run).await?;
        runtime
            .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map_err(text)
            .map(|_| ())
    }
    async fn channel(&self, auth: &AuthContext) -> Result<(String, String)> {
        let created = openbot_application::create_channel(
            &ChannelRepo::new(self.pool.clone()),
            auth,
            vec![BotId::new(BOT)],
        )
        .await
        .map_err(text)?;
        Ok((
            created.id.as_str().into(),
            created
                .thread_id
                .ok_or("channel producer did not mint Thread")?
                .as_str()
                .into(),
        ))
    }
    fn channel_request(
        &self,
        auth: &AuthContext,
        index: u64,
        channel: &str,
        j: &str,
    ) -> BeginThreadRunRequest {
        let mut req = self.request(
            auth,
            index,
            ThreadRunAnchor::Channel {
                channel_id: ChannelId::new(channel),
            },
        );
        req.command.thread_id = ThreadId::new(j);
        req
    }
    async fn v2_selection(&self, auth: &AuthContext, label: &str) -> Result<RunModelSelectionV2> {
        let model = self
            .models
            .create(
                auth,
                &CreateModelConnection {
                    name: format!("Owned stop choice {label}"),
                    protocol: CustomModelProtocol::OpenaiResponses,
                    endpoint: "https://owned-stop.example.test/v1".into(),
                    model: "owned-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new("OWNED_STOP_SYNTHETIC_KEY".into()))
                        .map_err(text)?,
                },
            )
            .await
            .map_err(text)?;
        RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            model.id.clone(),
            model.revision,
            format!("custom:{}", model.id),
            1,
        )
        .map_err(text)
    }
    fn v2_request(
        &self,
        auth: &AuthContext,
        req: &BeginThreadRunRequest,
        run: &str,
        selection: RunModelSelectionV2,
    ) -> BeginThreadRunV2Request {
        BeginThreadRunV2Request {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
            command: BeginThreadRunV2 {
                artifact_refs: Vec::new(),
                thread_id: req.command.thread_id.clone(),
                run_id: RunId::new(run),
                bot_id: req.command.bot_id.clone(),
                anchor: req.command.anchor.clone(),
                message: req.command.message.clone(),
                selected_skill_slugs: vec![],
                model_selection: selection,
            },
        }
    }
    /// Every original fact except H and Q; a producer may never change these.
    async fn facts(&self) -> Result<Value> {
        let c = self.pool.get().await.map_err(text)?;
        let mut out = serde_json::Map::new();
        for table in [
            "public.users",
            "public.user_roles",
            "public.revoked_access",
            "public.sessions",
            "public.threads",
            "public.thread_memberships",
            "public.channels",
            "public.channel_memberships",
            "public.channel_agents",
            "public.messages",
            "public.runs",
            "public.run_events",
            "public.outbox",
            "openbot_internal.thread_origins",
            "openbot_internal.artifact_records",
            "openbot_internal.artifact_cleanup_fences",
        ] {
            let sql = format!(
                "SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) FROM (SELECT to_jsonb(t) AS v FROM {table} t) q"
            );
            let value: Value = c
                .query_one(&sql, &[])
                .await
                .map_err(text)?
                .try_get(0)
                .map_err(text)?;
            out.insert(table.into(), value);
        }
        Ok(Value::Object(out))
    }
    /// Both whole tables with row versions: any rewrite, new row or repair changes this value.
    async fn hq(&self) -> Result<Value> {
        let c = self.pool.get().await.map_err(text)?;
        let mut out = serde_json::Map::new();
        for (name, order) in [
            ("openbot_internal.thread_history_heads", "x.thread_id"),
            (
                "openbot_internal.thread_history_clear_intents",
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
        Ok(Value::Object(out))
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
    async fn intents(&self, j: &str) -> Result<i64> {
        self.one(
            "SELECT count(*) FROM openbot_internal.thread_history_clear_intents WHERE thread_id=$1",
            j,
        )
        .await
    }
    /// The operation id stored for J, read independently of any producer result.
    async fn operation_of(&self, j: &str) -> Result<String> {
        self.one(
            "SELECT operation_id FROM openbot_internal.thread_history_clear_intents WHERE thread_id=$1",
            j,
        )
        .await
    }
    /// One producer call as its own task, so a test can hold or contend it from outside.
    fn spawn_close(
        &self,
        auth: &AuthContext,
        j: &str,
        request: &str,
        original: Instant,
    ) -> tokio::task::JoinHandle<Close> {
        spawn_close_with(&self.authority, auth, j, request, original)
    }
    async fn phase(&self, j: &str) -> Result<Option<String>> {
        let c = self.pool.get().await.map_err(text)?;
        let row = c
            .query_opt(
                "SELECT phase FROM openbot_internal.thread_history_heads WHERE thread_id=$1",
                &[&j],
            )
            .await
            .map_err(text)?;
        row.map(|r| r.try_get(0).map_err(text)).transpose()
    }
    /// Independent exact check of the stored Q and the H closed from it.
    async fn stored(
        &self,
        auth: &AuthContext,
        j: &str,
        request: &str,
        operation: &str,
        generation: i64,
    ) -> Result {
        let c = self.pool.get().await.map_err(text)?;
        let row = c
            .query_one(
                "SELECT (SELECT count(*) FROM openbot_internal.thread_history_clear_intents WHERE thread_id=$1) AS q_rows, \
                        (SELECT count(*) FROM openbot_internal.thread_history_heads WHERE thread_id=$1) AS h_rows, \
                        EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_intents q \
                               JOIN openbot_internal.thread_history_heads h ON h.thread_id=q.thread_id \
                               JOIN public.threads t ON t.thread_id=q.thread_id \
                               WHERE q.thread_id=$1 AND q.deployment_id=$2 AND q.tenant_id=$3 \
                                 AND q.intent_schema=1 AND q.intent_kind='stop_clear' AND q.operation_id=$4 \
                                 AND q.request_id=$5 AND q.actor_id=$6 AND q.auth_generation=$7 \
                                 AND q.anchor_kind=t.anchor_kind AND q.anchor_id=t.anchor_id \
                                 AND q.thread_created_at=t.created_at \
                                 AND h.head_schema=1 AND h.phase='closed' AND h.closure_operation_id=q.operation_id \
                                 AND h.closure_request_id=q.request_id AND h.closure_actor_id=q.actor_id \
                                 AND h.closure_auth_generation=q.auth_generation AND h.closed_at=q.recorded_at \
                                 AND h.anchor_kind=q.anchor_kind AND h.anchor_id=q.anchor_id \
                                 AND h.thread_created_at=q.thread_created_at) AS exact",
                &[
                    &j,
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &operation,
                    &request,
                    &auth.actor().as_str(),
                    &generation,
                ],
            )
            .await
            .map_err(text)?;
        let q: i64 = row.try_get("q_rows").map_err(text)?;
        let h: i64 = row.try_get("h_rows").map_err(text)?;
        let exact: bool = row.try_get("exact").map_err(text)?;
        check(
            q == 1 && h == 1 && exact,
            "stored Q/H pair is not the exact single acknowledged intent",
        )
    }
    /// A committed close through the real producer; nothing but H and Q may change.
    async fn commit_close(
        &self,
        auth: &AuthContext,
        j: &str,
        generation: i64,
    ) -> Result<(String, String)> {
        let request = request_id();
        let before = self.facts().await?;
        let result = self.close(auth, j, &request).await;
        let operation = committed(&result, auth, j, &request)?;
        self.stored(auth, j, &request, &operation, generation)
            .await?;
        check(
            before == self.facts().await?,
            "producer changed an original fact other than H and Q",
        )?;
        Ok((request, operation))
    }
    /// The creator is still observable by the pure 034 observer after closure.
    async fn observable(&self, auth: &AuthContext, j: &str) -> Result {
        self.authority
            .observe_management_before(auth, j, deadline())
            .await
            .map(|_| ())
            .map_err(text)
    }
    async fn finish(self) -> Result {
        self.resolver.close_request_bindings();
        self.assembly.shutdown().await;
        drop(self.directory);
        drop(self.models);
        drop(self.authority);
        drop(self.registry);
        drop(self.resolver);
        close_pool(self.pool).await
    }
}
/// One producer call of this authority as its own task.
fn spawn_close_with(
    authority: &Arc<PostgresThreadHistoryAuthority>,
    auth: &AuthContext,
    j: &str,
    request: &str,
    original: Instant,
) -> tokio::task::JoinHandle<Close> {
    let authority = Arc::clone(authority);
    let (auth, j, request) = (auth.clone(), j.to_owned(), request.to_owned());
    tokio::spawn(async move {
        authority
            .close_for_stop_clear_before(&auth, &j, &request, original)
            .await
    })
}
/// A genuine further producer stack on the same Pool and registry: a new authority and a new
/// Session resolver with its own request-binding issuer. Closing one stack never touches another.
struct FreshHost {
    authority: Arc<PostgresThreadHistoryAuthority>,
    resolver: PostgresSessionAuthResolver,
}
impl FreshHost {
    fn new(f: &Fixture) -> Result<Self> {
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
        let resolver = PostgresSessionAuthResolver::new(
            f.pool.clone(),
            SESSION_KEY,
            openbot_infra::auth::config::default_session_lifetime(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )
        .map_err(text)?;
        resolver
            .install_thread_history_authority(&authority)
            .map_err(text)?;
        Ok(Self {
            authority,
            resolver,
        })
    }
    async fn auth(&self, actor: &str, index: u8) -> Result<AuthContext> {
        self.resolver
            .resolve(
                &http::Request::builder()
                    .uri("/owned-stop-new-producer")
                    .header(
                        "cookie",
                        format!("openbot_session=owned-stop-cookie-{actor}-{index:02}"),
                    )
                    .body(())
                    .map_err(text)?
                    .into_parts()
                    .0,
            )
            .await
            .map_err(text)
    }
    async fn close(&self, auth: &AuthContext, j: &str, request: &str) -> Close {
        self.authority
            .close_for_stop_clear_before(auth, j, request, deadline())
            .await
    }
    fn spawn_close(
        &self,
        auth: &AuthContext,
        j: &str,
        request: &str,
        original: Instant,
    ) -> tokio::task::JoinHandle<Close> {
        spawn_close_with(&self.authority, auth, j, request, original)
    }
    /// Close this stack's request bindings and release its Pool handles.
    fn retire(self) {
        self.resolver.close_request_bindings();
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
async fn backend_pid(c: &pool::PooledClient) -> Result<i32> {
    c.query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(text)?
        .try_get(0)
        .map_err(text)
}
/// A compact view of the other backends, only for a failed wait probe's message.
async fn activity_snapshot(pool: &pool::DatabasePool) -> Result<String> {
    let c = pool.get().await.map_err(text)?;
    let rows = c
        .query(
            "SELECT pid,state,coalesce(wait_event_type,''),coalesce(wait_event,''),pg_blocking_pids(pid)::text,left(query,90) \
             FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state<>'idle'",
            &[],
        )
        .await
        .map_err(text)?;
    Ok(rows
        .iter()
        .map(|r| {
            format!(
                "[{} {} {}/{} blocked_by={} {}]",
                r.get::<_, i32>(0),
                r.get::<_, String>(1),
                r.get::<_, String>(2),
                r.get::<_, String>(3),
                r.get::<_, String>(4),
                r.get::<_, String>(5)
            )
        })
        .collect::<Vec<_>>()
        .join(" "))
}
/// Polls the real server for a backend that is Lock-waiting behind `blocker` on this statement.
/// The wait itself is the evidence; a poll interval stands in for no lock fact.
async fn wait_blocked(pool: &pool::DatabasePool, blocker: i32, statement: &str) -> Result<i32> {
    let until = Instant::now() + Duration::from_secs(3);
    let pattern = format!("%{statement}%");
    loop {
        let c = pool.get().await.map_err(text)?;
        let r = c
            .query_opt(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() \
                 AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) \
                 AND query LIKE $2 AND pid<>pg_backend_pid() LIMIT 1",
                &[&blocker, &pattern],
            )
            .await
            .map_err(text)?;
        if let Some(r) = r {
            return r.try_get(0).map_err(text);
        }
        drop(c);
        if Instant::now() >= until {
            let seen = activity_snapshot(pool).await?;
            return Err(format!(
                "real lock wait on `{statement}` never reached; blocker {blocker}; backends: {seen}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
/// A test-owned raw H+Q close of another J: exactly the pair a producer would write.
async fn raw_close(
    tx: &tokio_postgres::Transaction<'_>,
    j: &str,
    request: &str,
    actor: &str,
) -> Result<String> {
    let operation = request_id();
    let at: OffsetDateTime = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(text)?
        .try_get(0)
        .map_err(text)?;
    tx.execute(
        "INSERT INTO openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at) \
         SELECT deployment_id,tenant_id,thread_id,1,'stop_clear',$2,$3,$4,7,anchor_kind,anchor_id,thread_created_at,$5 \
         FROM openbot_internal.thread_history_heads WHERE thread_id=$1",
        &[&j, &operation, &request, &actor, &at],
    )
    .await
    .map_err(text)?;
    tx.execute(
        "UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id=$2,closure_request_id=$3,closure_actor_id=$4,closure_auth_generation=7,closed_at=$5 WHERE thread_id=$1",
        &[&j, &operation, &request, &actor, &at],
    )
    .await
    .map_err(text)?;
    Ok(operation)
}

/// The real backend waiting for the migration ledger behind exactly this blocker.
async fn ledger_waiter(pool: &pool::DatabasePool, blocker: i32) -> Result<i32> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let c = pool.get().await.map_err(text)?;
        let row = c
            .query_opt(
                "SELECT pid FROM pg_catalog.pg_locks WHERE locktype='relation' AND NOT granted \
                 AND relation='openbot_internal.schema_migrations'::regclass \
                 AND pg_catalog.pg_blocking_pids(pid)=ARRAY[$1::integer] ORDER BY pid LIMIT 1",
                &[&blocker],
            )
            .await
            .map_err(text)?;
        if let Some(row) = row {
            return row.try_get(0).map_err(text);
        }
        drop(c);
        check(
            Instant::now() < until,
            "the producer never waited on the schema observation",
        )?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
/// Row-level lock footprint of one backend on the rows a producer locks: tuple and advisory
/// locks plus ROW SHARE / ROW EXCLUSIVE on those tables. A backend that has only read catalogs
/// and the ledger holds none.
async fn row_lock_footprint(pool: &pool::DatabasePool, pid: i32) -> Result<i64> {
    pool.get()
        .await
        .map_err(text)?
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_locks WHERE pid=$1 AND granted AND ( \
               locktype IN ('tuple','advisory') OR (locktype='relation' \
               AND mode IN ('RowShareLock','RowExclusiveLock') AND relation IN ( \
                 'public.users'::regclass,'public.user_roles'::regclass,'public.sessions'::regclass, \
                 'public.threads'::regclass,'public.thread_memberships'::regclass,'public.agents'::regclass, \
                 'public.agent_profiles'::regclass,'public.channels'::regclass, \
                 'public.channel_memberships'::regclass,'public.deployment_packages'::regclass, \
                 'openbot_internal.thread_history_heads'::regclass, \
                 'openbot_internal.thread_history_clear_intents'::regclass)))",
            &[&pid],
        )
        .await
        .map_err(text)?
        .try_get(0)
        .map_err(text)
}
/// The one backend that is idle inside its transaction: a producer paused at a withheld ACK.
/// The backend leaves `active` a moment after the acknowledgement was sent, so this polls.
async fn open_transaction_pid(f: &Fixture) -> Result<i32> {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        let rows = f
            .pool
            .get()
            .await
            .map_err(text)?
            .query(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() \
                 AND state='idle in transaction' AND pid<>pg_backend_pid()",
                &[],
            )
            .await
            .map_err(text)?;
        if let [row] = rows.as_slice() {
            return row.try_get(0).map_err(text);
        }
        check(
            Instant::now() < until,
            "no single backend idle in its transaction",
        )?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
/// A typed RepoCore Message row for an existing Run of J; only a closed head may refuse it.
fn typed_message(j: &str, run: &str, id: &str) -> openbot_infra::db::tables::messages::Row {
    openbot_infra::db::tables::messages::Row {
        message_id: id.into(),
        thread_id: j.into(),
        seq: 900,
        role: "user".into(),
        content: json!({"text": "typed body"}),
        search_text: "typed body".into(),
        run_id: Some(run.into()),
        actor_id: Some(A.into()),
        created_at: OffsetDateTime::now_utc(),
    }
}
/// A pre-0050 Thread has no head yet. Only an owned superuser transaction may remove one.
async fn drop_head(f: &Fixture, j: &str) -> Result {
    let mut c = f.pool.get().await.map_err(text)?;
    let tx = c.transaction().await.map_err(text)?;
    tx.batch_execute("ALTER TABLE openbot_internal.thread_history_heads DISABLE TRIGGER USER")
        .await
        .map_err(text)?;
    let removed = tx
        .execute(
            "DELETE FROM openbot_internal.thread_history_heads WHERE thread_id=$1",
            &[&j],
        )
        .await
        .map_err(text)?;
    // The delete queued deferred reference checks; fire them before the table may be altered.
    tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
        .await
        .map_err(text)?;
    tx.batch_execute("ALTER TABLE openbot_internal.thread_history_heads ENABLE TRIGGER USER")
        .await
        .map_err(text)?;
    check(
        removed == 1,
        "owned head removal did not hit exactly one row",
    )?;
    tx.commit().await.map_err(text)
}

// Protocol-aware owned PG relay. Only the armed backend CommandComplete is held or dropped.
struct Armed {
    tag: &'static [u8],
    /// `None` drops the proxied connection at that CommandComplete instead of delivering it.
    gate: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
}
struct AckProxy {
    port: u16,
    armed: Arc<Mutex<Option<Armed>>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
struct AckHold {
    arrived: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
}
impl AckHold {
    async fn wait(&mut self) -> Result {
        tokio::time::timeout(Duration::from_secs(3), &mut self.arrived)
            .await
            .map_err(|_| "the armed backend acknowledgement never reached the relay".to_owned())?
            .map_err(text)
    }
    fn release(self) -> Result {
        self.release
            .send(())
            .map_err(|()| "original ACK release closed".into())
    }
}
impl AckProxy {
    async fn start(host: String, port: u16) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(text)?;
        let local = listener.local_addr().map_err(text)?.port();
        let armed = Arc::new(Mutex::new(None::<Armed>));
        let slot = armed.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    Some(_) = children.join_next() => {},
                    pair = listener.accept() => {
                        let Ok((client, _)) = pair else { break };
                        let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else { break };
                        // Small protocol frames must not wait on delayed ACKs: the original
                        // deadlines being tested are real and a relay must not eat them.
                        let (Ok(()), Ok(())) = (client.set_nodelay(true), server.set_nodelay(true)) else { break };
                        let slot = slot.clone();
                        children.spawn(async move {
                            let (mut cr, mut cw) = client.into_split();
                            let (mut sr, mut sw) = server.into_split();
                            let backend = async {
                                loop {
                                    let kind = sr.read_u8().await?;
                                    let length = sr.read_u32().await?;
                                    if !(4..=16 * 1024 * 1024).contains(&length) {
                                        return Err(std::io::Error::other("invalid owned PG frame"));
                                    }
                                    let mut payload = vec![0; (length - 4) as usize];
                                    sr.read_exact(&mut payload).await?;
                                    let hit = if kind == b'C' {
                                        let mut armed = slot.lock().map_err(|_| std::io::Error::other("owned ACK controller poisoned"))?;
                                        if armed.as_ref().is_some_and(|a| a.tag == payload.as_slice()) { armed.take() } else { None }
                                    } else { None };
                                    if let Some(hit) = hit {
                                        // No gate: drop this connection with the ACK still unsent.
                                        let Some((arrived, release)) = hit.gate else { return Ok::<(), std::io::Error>(()) };
                                        arrived.send(()).map_err(|()| std::io::Error::other("owned ACK controller closed"))?;
                                        tokio::time::timeout(Duration::from_secs(8), release)
                                            .await
                                            .map_err(|_| std::io::Error::other("owned ACK timeout"))?
                                            .map_err(|_| std::io::Error::other("owned ACK release closed"))?;
                                    }
                                    let mut frame = Vec::with_capacity(payload.len() + 5);
                                    frame.push(kind);
                                    frame.extend_from_slice(&length.to_be_bytes());
                                    frame.extend_from_slice(&payload);
                                    cw.write_all(&frame).await?;
                                }
                            };
                            tokio::select! { _ = tokio::io::copy(&mut cr, &mut sw) => {}, _ = backend => {} }
                        });
                    }
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Ok(Self {
            port: local,
            armed,
            stop: Some(stop),
            task: Some(task),
        })
    }
    fn arm(&self, armed: Armed) -> Result {
        let mut slot = self.armed.lock().map_err(text)?;
        check(slot.is_none(), "ACK controller already armed")?;
        *slot = Some(armed);
        Ok(())
    }
    /// Hold the next real CommandComplete with this tag until released.
    fn hold(&self, tag: &'static [u8]) -> Result<AckHold> {
        let (a, arrived) = oneshot::channel();
        let (release, r) = oneshot::channel();
        self.arm(Armed {
            tag,
            gate: Some((a, r)),
        })?;
        Ok(AckHold { arrived, release })
    }
    /// Lose the next real CommandComplete with this tag: its connection closes unacknowledged.
    fn drop_next(&self, tag: &'static [u8]) -> Result {
        self.arm(Armed { tag, gate: None })
    }
    async fn finish(mut self) -> Result {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.task.take() {
            t.await.map_err(text)?;
        }
        Ok(())
    }
}
impl Drop for AckProxy {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}
async fn owned_proxy<F, Fut>(tag: &str, generation: u64, body: F)
where
    F: FnOnce(Fixture, AckProxy) -> Fut,
    Fut: Future<Output = Result>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |mut config| async move {
        let proxy = AckProxy::start(config.host.clone(), config.port).await?;
        config.host = "127.0.0.1".into();
        config.port = proxy.port;
        body(Fixture::new(config, generation).await?, proxy).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_creator_commits_one_intent_and_closes_admission() {
    owned("stop01", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        // Direct V1: a further Run is admitted while open and refused for every writer once closed.
        let (v1, j1) = f.settled(&a, 101).await?;
        check(
            f.phase(&j1).await?.as_deref() == Some("open") && f.intents(&j1).await? == 0,
            "premise: J1 head is open without an intent",
        )?;
        f.begin_again(&v1, "owned-stop-run-1011")
            .await
            .map_err(text)?;
        f.settle("owned-stop-run-1011").await?;
        f.commit_close(&a, &j1, 7).await?;
        check(
            matches!(
                f.begin_again(&v1, "owned-stop-run-1012").await,
                Err(ThreadDirectoryError::NotVisible)
            ),
            "closed J1 admitted a new V1 Run",
        )?;
        let message = typed_message(&j1, v1.command.run_id.as_str(), "owned-stop-closed-message");
        check(
            matches!(
                MessageRepo::new(f.pool.clone()).insert(&message).await,
                Err(InfraError::RepositoryInvariant {
                    code: "thread_history_writer_closed"
                })
            ),
            "typed RepoCore Message insert admitted closed J1",
        )?;
        // Direct V2.
        let v2 = f.request(&a, 102, ThreadRunAnchor::DirectBot);
        let j2 = v2.command.thread_id.as_str().to_owned();
        let selection = f.v2_selection(&a, "first").await?;
        f.directory
            .begin_thread_run_v2(f.v2_request(&a, &v2, "owned-stop-run-102", selection))
            .await
            .map_err(text)?;
        f.settle("owned-stop-run-102").await?;
        f.commit_close(&a, &j2, 7).await?;
        let selection = f.v2_selection(&a, "second").await?;
        check(
            matches!(
                f.directory
                    .begin_thread_run_v2(f.v2_request(&a, &v2, "owned-stop-run-1022", selection))
                    .await,
                Err(ThreadDirectoryError::NotVisible)
            ),
            "closed J2 admitted a new V2 Run",
        )?;
        // Private agent channel: a message Run is admitted while open and refused once closed.
        let (channel, j3) = f.channel(&a).await?;
        f.directory
            .begin_thread_run(f.channel_request(&a, 103, &channel, &j3))
            .await
            .map_err(text)?;
        f.settle("owned-stop-run-103").await?;
        f.commit_close(&a, &j3, 7).await?;
        check(
            matches!(
                f.directory
                    .begin_thread_run(f.channel_request(&a, 1033, &channel, &j3))
                    .await,
                Err(ThreadDirectoryError::NotVisible)
            ),
            "closed channel J3 admitted a new message Run",
        )?;
        // A pre-0050 Thread has no head: the producer recreates it open and closes it in one commit.
        let (_, j4) = f.settled(&a, 104).await?;
        drop_head(&f, &j4).await?;
        check(f.phase(&j4).await?.is_none(), "premise: J4 has no head")?;
        f.commit_close(&a, &j4, 7).await?;
        for j in [&j1, &j2, &j3, &j4] {
            f.observable(&a, j).await?;
        }
        let tables = f.hq().await?;
        let intents = &tables["openbot_internal.thread_history_clear_intents"];
        let heads = &tables["openbot_internal.thread_history_heads"];
        check(
            intents.as_array().is_some_and(|rows| rows.len() == 4)
                && heads.as_array().is_some_and(|rows| {
                    rows.len() == 4 && rows.iter().all(|h| h["phase"] == "closed")
                }),
            "exactly four closed heads with exactly four intents",
        )?;
        f.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_non_creator_legacy_and_deleted_base_never_close() {
    owned("stop02", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let admin = f.auth(C, 1).await?;
        let (channel, channel_j) = f.channel(&a).await?;
        f.sql(&format!("INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('{channel}','{B}'),('{channel}','{C}')")).await?;
        let (_, direct) = f.settled(&a, 201).await?;
        // LegacyUnknown: no native producer minted this Thread, so it has no origin and gets none.
        let legacy = f
            .request(&a, 202, ThreadRunAnchor::DirectBot)
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
        f.sql(&format!("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES('{legacy}','{A}')")).await?;
        let (_, soft) = f.settled(&a, 203).await?;
        let (_, hard) = f.settled(&a, 204).await?;
        let missing = f
            .request(&a, 299, ThreadRunAnchor::DirectBot)
            .command
            .thread_id
            .as_str()
            .to_owned();
        f.sql(&format!("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp() WHERE thread_id='{soft}'")).await?;
        f.sql(&format!("DELETE FROM public.threads WHERE thread_id='{hard}'"))
            .await?;
        let tables = f.hq().await?;
        let facts = f.facts().await?;
        let request = request_id();
        // Later members, an admin, LegacyUnknown, soft/hard-deleted and never-created bases.
        for (who, j) in [
            (&b, &channel_j),
            (&admin, &channel_j),
            (&b, &direct),
            (&admin, &direct),
            (&a, &legacy),
            (&a, &soft),
            (&a, &hard),
            (&a, &missing),
        ] {
            not_visible(&f.close(who, j, &request).await)?;
        }
        for bad in ["", "not-a-thread", "00000000-0000-4000-8000-000000000000\n"] {
            check(
                matches!(
                    f.close(&a, bad, &request).await,
                    Err(Stop::InvalidInput { field: "thread_id" })
                ),
                "invalid Thread id must fail the exact input boundary",
            )?;
        }
        let bad_requests = [
            String::new(),
            request.to_uppercase(),
            format!("{}{}", request[..8].to_uppercase(), &request[8..]),
            format!(" {request}"),
            format!("{request}\n"),
            request.replace('-', ""),
            format!("{{{request}}}"),
            "6ba7b810-9dad-41d1-80b4-00c04fd430c8".into(),
            "018f8d3a-0000-8000-8000-000000000000".into(),
            "018f8d3a-0000-7000-c000-000000000000".into(),
        ];
        for bad in &bad_requests {
            check(
                matches!(
                    f.close(&a, &direct, bad).await,
                    Err(Stop::InvalidInput {
                        field: "request_id"
                    })
                ),
                "request id must be the exact canonical lowercase UUIDv7",
            )?;
        }
        check(
            tables == f.hq().await? && facts == f.facts().await?,
            "a refusal wrote H, Q or an original fact",
        )?;
        // None of that consumed the request id or the creator's right.
        let closed = f.close(&a, &direct, &request).await;
        let operation = committed(&closed, &a, &direct, &request)?;
        f.stored(&a, &direct, &request, &operation, 7).await?;
        // A closed head without its exact intent is a corrupt binding, never repaired.
        let (_, broken) = f.settled(&a, 205).await?;
        {
            let mut c = f.pool.get().await.map_err(text)?;
            let tx = c.transaction().await.map_err(text)?;
            tx.batch_execute("SET LOCAL session_replication_role = replica")
                .await
                .map_err(text)?;
            let (op, rq) = (request_id(), request_id());
            let hit = tx
                .execute(
                    "UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id=$2,closure_request_id=$3,closure_actor_id='stop-a',closure_auth_generation=7,closed_at=clock_timestamp() WHERE thread_id=$1",
                    &[&broken, &op, &rq],
                )
                .await
                .map_err(text)?;
            check(hit == 1, "owned tamper did not hit exactly one head")?;
            tx.commit().await.map_err(text)?;
        }
        let tampered = f.hq().await?;
        let result = f.close(&a, &broken, &request_id()).await;
        check(
            matches!(
                result,
                Err(Stop::Corrupt {
                    field: "history_binding"
                })
            ),
            "a closed head without its intent must be a corrupt history binding",
        )?;
        check(
            tampered == f.hq().await?,
            "producer repaired or rewrote a broken head",
        )?;
        f.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_exact_replay_returns_original_and_other_requests_conflict() {
    owned("stop03", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let (_, j1) = f.settled(&a, 301).await?;
        let (_, j2) = f.settled(&a, 302).await?;
        let (first, operation) = f.commit_close(&a, &j1, 7).await?;
        let tables = f.hq().await?;
        let facts = f.facts().await?;
        // An exact replay returns the original operation, again and again, and writes nothing.
        for _ in 0..2 {
            replayed(&f.close(&a, &j1, &first).await, &j1, &first, &operation)?;
            check(
                tables == f.hq().await? && facts == f.facts().await?,
                "exact replay wrote a row or rewrote a version",
            )?;
        }
        // Another request on the closed J, and the same request on another J, both conflict.
        let second = request_id();
        conflict(&f.close(&a, &j1, &second).await)?;
        conflict(&f.close(&a, &j2, &first).await)?;
        check(
            tables == f.hq().await? && facts == f.facts().await?,
            "a conflict wrote",
        )?;
        check(
            f.phase(&j2).await?.as_deref() == Some("open") && f.intents(&j2).await? == 0,
            "a conflicting request touched J2",
        )?;
        // Neither conflict consumed `second`: J2 closes with it and gets its own operation.
        let closed = f.close(&a, &j2, &second).await;
        let other = committed(&closed, &a, &j2, &second)?;
        f.stored(&a, &j2, &second, &other, 7).await?;
        check(other != operation, "two intents share one operation id")?;
        // The stored generation is not compared: a new generation replays, a stale one is refused.
        f.sql("UPDATE public.users SET auth_generation=8 WHERE id='stop-a'; UPDATE public.sessions SET auth_generation=8 WHERE user_id='stop-a'").await?;
        let next = f.auth(A, 1).await?;
        not_visible(&f.close(&a, &j1, &first).await)?;
        let tables = f.hq().await?;
        replayed(&f.close(&next, &j1, &first).await, &j1, &first, &operation)?;
        f.stored(&a, &j1, &first, &operation, 7).await?;
        check(tables == f.hq().await?, "replay at a new generation wrote")?;
        // Revoked access ends even an exact replay, and restoring it does not poison the next one.
        f.sql("INSERT INTO public.revoked_access(email,revoked_by) VALUES('stop-a@example.test','stop-admin')").await?;
        not_visible(&f.close(&next, &j1, &first).await)?;
        check(tables == f.hq().await?, "revoked replay wrote")?;
        f.sql("DELETE FROM public.revoked_access WHERE email='stop-a@example.test'")
            .await?;
        replayed(&f.close(&next, &j1, &first).await, &j1, &first, &operation)?;
        // The same refusal must not persist a lazily minted H for a pre-head Thread.
        let (_, lazy_j) = f.settled(&next, 303).await?;
        drop_head(&f, &lazy_j).await?;
        check(f.phase(&lazy_j).await?.is_none(), "owned lazy premise still has a head")?;
        let lazy_before = f.hq().await?;
        let lazy_facts = f.facts().await?;
        conflict(&f.close(&next, &lazy_j, &first).await)?;
        check(
            f.phase(&lazy_j).await?.is_none()
                && f.intents(&lazy_j).await? == 0
                && f.hq().await? == lazy_before
                && f.facts().await? == lazy_facts,
            "refused cross-J request persisted a lazy head or any other write",
        )?;
        f.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_waits_recheck_and_writer_h_share_refuses_nowait() {
    owned_proxy("stop04", 7, |f, proxy| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let (_, j) = f.settled(&a, 401).await?;
        let (_, other1) = f.settled(&b, 402).await?;
        let (_, other2) = f.settled(&b, 403).await?;
        let untouched = f.hq().await?;
        // (a) The actor-row wait ends in a committed generation change: the fresh joint refuses.
        {
            let mut raw = f.pool.get().await.map_err(text)?;
            let blocker = backend_pid(&raw).await?;
            let tx = raw.transaction().await.map_err(text)?;
            tx.execute(
                "UPDATE public.users SET auth_generation=auth_generation WHERE id=$1",
                &[&A],
            )
            .await
            .map_err(text)?;
            let task = f.spawn_close(&a, &j, &request_id(), deadline());
            let waiting = wait_blocked(&f.pool, blocker, "users").await?;
            check(waiting != blocker, "the writer waited on itself")?;
            tx.execute(
                "UPDATE public.users SET auth_generation=8 WHERE id=$1",
                &[&A],
            )
            .await
            .map_err(text)?;
            tx.commit().await.map_err(text)?;
            not_visible(&task.await.map_err(text)?)?;
        }
        check(untouched == f.hq().await?, "a refused producer wrote H or Q")?;
        f.sql("UPDATE public.users SET auth_generation=7 WHERE id='stop-a'")
            .await?;
        // (b) The Q unique-key wait ends in a deny that only a later statement can see: J2 refuses.
        {
            let mut raw = f.pool.get().await.map_err(text)?;
            let blocker = backend_pid(&raw).await?;
            let tx = raw.transaction().await.map_err(text)?;
            let shared = request_id();
            raw_close(&tx, &other1, &shared, B).await?;
            let task = f.spawn_close(&a, &j, &shared, deadline());
            wait_blocked(&f.pool, blocker, "thread_history_clear_intents").await?;
            f.sql("INSERT INTO public.revoked_access(email,revoked_by) VALUES('stop-a@example.test','stop-admin')").await?;
            tx.rollback().await.map_err(text)?;
            not_visible(&task.await.map_err(text)?)?;
        }
        f.sql("DELETE FROM public.revoked_access WHERE email='stop-a@example.test'")
            .await?;
        check(
            untouched == f.hq().await?,
            "a producer refused after its unique wait wrote H or Q",
        )?;
        // (b2) The same wait ends in a committed winner: classified by reading it, not swallowed.
        let winner = {
            let mut raw = f.pool.get().await.map_err(text)?;
            let blocker = backend_pid(&raw).await?;
            let tx = raw.transaction().await.map_err(text)?;
            let shared = request_id();
            let operation = raw_close(&tx, &other2, &shared, B).await?;
            let task = f.spawn_close(&a, &j, &shared, deadline());
            wait_blocked(&f.pool, blocker, "thread_history_clear_intents").await?;
            tx.commit().await.map_err(text)?;
            conflict(&task.await.map_err(text)?)?;
            operation
        };
        check(
            f.phase(&other2).await?.as_deref() == Some("closed")
                && f.operation_of(&other2).await? == winner
                && f.phase(&j).await?.as_deref() == Some("open")
                && f.intents(&j).await? == 0,
            "the Conflict loser changed state or the winner is not intact",
        )?;
        // (e) Every positive current row is NOWAIT: a held row lock is Unavailable, never a wait.
        for (lock, key) in [
            ("SELECT thread_id FROM public.threads WHERE thread_id=$1 FOR UPDATE", j.as_str()),
            ("SELECT thread_id FROM public.thread_memberships WHERE thread_id=$1 FOR UPDATE", j.as_str()),
            ("SELECT id FROM public.sessions WHERE id=$1 FOR UPDATE", "stop-a-session-1"),
            ("SELECT user_id FROM public.user_roles WHERE user_id=$1 FOR UPDATE", A),
        ] {
            let mut raw = f.pool.get().await.map_err(text)?;
            let tx = raw.transaction().await.map_err(text)?;
            tx.query(lock, &[&key]).await.map_err(text)?;
            unavailable(&f.close(&a, &j, &request_id()).await)?;
            tx.rollback().await.map_err(text)?;
        }
        // (c) A writer-style SHARE on H held by another transaction: Unavailable, nothing written.
        let request = request_id();
        {
            let mut raw = f.pool.get().await.map_err(text)?;
            let tx = raw.transaction().await.map_err(text)?;
            let open: bool = tx
                .query_one(
                    "SELECT openbot_internal.thread_history_lock_joint($1,NULL::text)",
                    &[&j],
                )
                .await
                .map_err(text)?
                .try_get(0)
                .map_err(text)?;
            check(open, "premise: writer admission sees an open head")?;
            unavailable(&f.close(&a, &j, &request).await)?;
            check(
                f.phase(&j).await?.as_deref() == Some("open") && f.intents(&j).await? == 0,
                "a contended producer wrote",
            )?;
            tx.rollback().await.map_err(text)?;
        }
        let closed = f.close(&a, &j, &request).await;
        let operation = committed(&closed, &a, &j, &request)?;
        f.stored(&a, &j, &request, &operation, 7).await?;
        // (d) Reverse, before the head update: the producer holds the exclusive head. Every writer
        // admission statement is refused at once (NOWAIT), a Run-locked writer first queues behind
        // the producer's Thread SHARE, and no writer is ever admitted as open.
        let req = f.begin(&a, 404).await?;
        let jd = req.command.thread_id.as_str().to_owned();
        let (runtime, lease) = f.claim(req.command.run_id.as_str()).await?;
        let (runtime, lease) = (Arc::new(runtime), Arc::new(lease));
        let seq = lease.next_event_sequence();
        runtime
            .append_semantic_chunk(&lease, seq, RunSemanticChannel::Text, "admitted while open")
            .await
            .map_err(text)?;
        let mut hold = proxy.hold(INSERTED)?;
        let paused = request_id();
        let first = f.spawn_close(&a, &jd, &paused, deadline());
        hold.wait().await?;
        let producer = open_transaction_pid(&f).await?;
        check(
            !first.is_finished(),
            "the producer finished while its Q insert acknowledgement was withheld",
        )?;
        let admission = async {
            let c = f.pool.get().await.map_err(text)?;
            c.query_one(
                "SELECT openbot_internal.thread_history_lock_joint($1,NULL::text)",
                &[&jd],
            )
            .await
            .err()
            .ok_or_else(|| "writer admission passed the producer's exclusive head".to_owned())
        };
        let refused = tokio::time::timeout(Duration::from_secs(3), admission)
            .await
            .map_err(|_| "writer admission waited behind the producer's exclusive head")??;
        check(
            refused.code() == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE),
            "writer admission was not a NOWAIT refusal",
        )?;
        // The paused producer has the original five seconds in all: everything below runs in
        // parallel and short, and each probe only needs the producer to stay paused.
        let typed = {
            let repo = MessageRepo::new(f.pool.clone());
            let row = typed_message(&jd, req.command.run_id.as_str(), "owned-stop-typed-d");
            tokio::spawn(async move { repo.insert(&row).await.map(|_| ()) })
        };
        let writer = {
            let (runtime, lease) = (Arc::clone(&runtime), Arc::clone(&lease));
            tokio::spawn(async move {
                runtime
                    .append_semantic_chunk(&lease, seq + 1, RunSemanticChannel::Text, "while closing")
                    .await
                    .map(|_| ())
            })
        };
        wait_blocked(&f.pool, producer, "thread_leases").await?;
        let typed = tokio::time::timeout(Duration::from_secs(3), typed)
            .await
            .map_err(|_| "a typed RepoCore writer waited behind the producer's exclusive head")?
            .map_err(text)?;
        check(
            typed.as_ref().is_err_and(|e| e.sqlstate() == Some("55P03")),
            "a typed RepoCore writer was not refused by the NOWAIT head lock",
        )?;
        check(
            !first.is_finished() && !writer.is_finished(),
            "the first producer or the queued writer was disturbed",
        )?;
        hold.release()?;
        let result = first.await.map_err(text)?;
        let ack = committed(&result, &a, &jd, &paused)?;
        f.stored(&a, &jd, &paused, &ack, 7).await?;
        check(
            matches!(
                writer.await.map_err(text)?,
                Err(RunRuntimeError::StaleLease)
            ),
            "the queued writer was admitted instead of seeing the closed head",
        )?;
        // (d2) After the head update and before COMMIT, an admission queues on the head's unique
        // key behind the producer and is then answered as closed, never as open.
        let req = f.begin(&a, 405).await?;
        let jw = req.command.thread_id.as_str().to_owned();
        let mut hold = proxy.hold(UPDATED)?;
        let paused = request_id();
        let first = f.spawn_close(&a, &jw, &paused, deadline());
        hold.wait().await?;
        let producer = open_transaction_pid(&f).await?;
        let typed = typed_message(&jw, req.command.run_id.as_str(), "owned-stop-typed-d2");
        let queued = {
            let repo = MessageRepo::new(f.pool.clone());
            tokio::spawn(async move { repo.insert(&typed).await.map(|_| ()) })
        };
        wait_blocked(&f.pool, producer, "lock_joint").await?;
        check(
            !first.is_finished() && !queued.is_finished(),
            "the first producer or the queued admission was disturbed",
        )?;
        hold.release()?;
        let result = first.await.map_err(text)?;
        let ack = committed(&result, &a, &jw, &paused)?;
        f.stored(&a, &jw, &paused, &ack, 7).await?;
        check(
            matches!(
                queued.await.map_err(text)?,
                Err(InfraError::RepositoryInvariant {
                    code: "thread_history_writer_closed"
                })
            ),
            "the queued admission was not answered as closed",
        )?;
        // Its pending Run still settles on the closed path, so later claims find their own.
        f.settle(req.command.run_id.as_str()).await?;
        // (d3) The H/Q pair is settled by an ordinary statement before COMMIT: paused at the real
        // SET CONSTRAINTS acknowledgement, the transaction is still uncommitted and invisible.
        let (_, jx) = f.settled(&a, 407).await?;
        let mut hold = proxy.hold(SETTLED)?;
        let pending = request_id();
        let first = f.spawn_close(&a, &jx, &pending, deadline());
        hold.wait().await?;
        let producer = open_transaction_pid(&f).await?;
        let last: String = f
            .pool
            .get()
            .await
            .map_err(text)?
            .query_one("SELECT query FROM pg_stat_activity WHERE pid=$1", &[&producer])
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        check(
            last.starts_with("SET CONSTRAINTS")
                && last.contains("thread_history_clear_intents_head_base_fkey")
                && last.contains("thread_history_heads_closed_intent_fkey")
                && last.contains("thread_history_clear_intents_require_closed_head")
                && last.ends_with("IMMEDIATE"),
            "the pair is not settled by an ordinary statement before COMMIT",
        )?;
        check(
            f.phase(&jx).await?.as_deref() == Some("open") && f.intents(&jx).await? == 0,
            "the pair was visible before COMMIT",
        )?;
        hold.release()?;
        let result = first.await.map_err(text)?;
        let ack = committed(&result, &a, &jx, &pending)?;
        f.stored(&a, &jx, &pending, &ack, 7).await?;
        // (f) The complete schema proof precedes the producer's first row lock. Its BEGIN
        // acknowledgement is held, a real ACCESS EXCLUSIVE lock goes on the migration ledger, and
        // the backend waiting there is inspected: it holds no row, tuple or advisory lock yet.
        let (_, jf) = f.settled(&a, 406).await?;
        {
            // Not vacuous: a real row lock holder shows in the same footprint.
            let mut holder = f.pool.get().await.map_err(text)?;
            let me = backend_pid(&holder).await?;
            let tx = holder.transaction().await.map_err(text)?;
            tx.query("SELECT id FROM public.users WHERE id=$1 FOR SHARE", &[&A])
                .await
                .map_err(text)?;
            check(
                row_lock_footprint(&f.pool, me).await? > 0,
                "the lock footprint probe is vacuous",
            )?;
            tx.rollback().await.map_err(text)?;
        }
        let mut begun = proxy.hold(BEGUN)?;
        let observed = request_id();
        let first = f.spawn_close(&a, &jf, &observed, deadline());
        begun.wait().await?;
        let mut ledger = f.pool.get().await.map_err(text)?;
        let blocker = backend_pid(&ledger).await?;
        let lock = ledger.transaction().await.map_err(text)?;
        lock.batch_execute("LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE")
            .await
            .map_err(text)?;
        begun.release()?;
        let waiter = ledger_waiter(&f.pool, blocker).await?;
        let footprint = row_lock_footprint(&f.pool, waiter).await?;
        let mut probe = f.pool.get().await.map_err(text)?;
        let tx = probe.transaction().await.map_err(text)?;
        let mut locked = Vec::new();
        for (sql, key) in [
            ("SELECT 1 FROM public.users WHERE id=$1 FOR UPDATE NOWAIT", A),
            ("SELECT 1 FROM public.sessions WHERE id=$1 FOR UPDATE NOWAIT", "stop-a-session-1"),
            ("SELECT 1 FROM public.threads WHERE thread_id=$1 FOR UPDATE NOWAIT", jf.as_str()),
            ("SELECT 1 FROM openbot_internal.thread_history_heads WHERE thread_id=$1 FOR UPDATE NOWAIT", jf.as_str()),
        ] {
            if tx.query_one(sql, &[&key]).await.is_err() {
                locked.push(sql);
                break;
            }
        }
        tx.rollback().await.map_err(text)?;
        lock.rollback().await.map_err(text)?;
        drop(probe);
        drop(ledger);
        check(
            footprint == 0 && locked.is_empty(),
            "the producer held row locks while still observing the schema",
        )?;
        let result = first.await.map_err(text)?;
        let ack = committed(&result, &a, &jf, &observed)?;
        f.stored(&a, &jf, &observed, &ack, 7).await?;
        f.finish().await?;
        proxy.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_in_flight_run_finishes_on_closed_path_without_body() {
    owned("stop05", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let req = f.begin(&a, 501).await?;
        let j = req.command.thread_id.as_str().to_owned();
        let run = req.command.run_id.as_str().to_owned();
        let (runtime, lease) = f.claim(&run).await?;
        let seq = lease.next_event_sequence();
        runtime
            .append_semantic_chunk(
                &lease,
                seq,
                RunSemanticChannel::Text,
                "BODY_ACCEPTED_WHILE_OPEN",
            )
            .await
            .map_err(text)?;
        let (request, operation) = f.commit_close(&a, &j, 7).await?;
        // ACK1 neither cancels nor drains the in-flight Run.
        check(
            f.one::<String>("SELECT status FROM public.runs WHERE run_id=$1", &run)
                .await?
                == "running"
                && f.one::<i64>(
                    "SELECT count(*) FROM public.run_events WHERE run_id=$1 AND terminal",
                    &run,
                )
                .await?
                    == 0,
            "closing admission cancelled or drained the in-flight Run",
        )?;
        let before = f.facts().await?;
        check(
            matches!(
                runtime
                    .append_semantic_chunk(
                        &lease,
                        seq + 1,
                        RunSemanticChannel::Text,
                        "BODY_REFUSED_WHEN_CLOSED"
                    )
                    .await,
                Err(RunRuntimeError::StaleLease)
            ),
            "closed J admitted a new chunk",
        )?;
        check(
            before == f.facts().await?,
            "a refused chunk changed original facts",
        )?;
        // The original lease still settles the Run, on the closed path: no body is aggregated.
        let receipt = runtime
            .finish_run(&lease, seq + 1, RunTerminal::Completed)
            .await
            .map_err(text)?;
        check(!receipt.replayed, "the first closed terminal was a replay")?;
        check(
            f.one::<i64>(
                "SELECT count(*) FROM public.messages WHERE run_id=$1 AND role='assistant'",
                &run,
            )
            .await?
                == 0,
            "closed finish materialised an assistant body",
        )?;
        let payload: Value = f
            .one(
                "SELECT payload FROM public.run_events WHERE run_id=$1 AND terminal",
                &run,
            )
            .await?;
        check(
            payload == json!({"status": "completed"}),
            "closed terminal is not the fixed payload",
        )?;
        check(
            f.one::<String>("SELECT status FROM public.runs WHERE run_id=$1", &run)
                .await?
                == "completed",
            "closed finish did not settle the Run",
        )?;
        let settled = f.facts().await?;
        check(
            runtime
                .finish_run(&lease, seq + 1, RunTerminal::Completed)
                .await
                .map_err(text)?
                .replayed,
            "closed exact terminal replay was not accepted",
        )?;
        check(
            settled == f.facts().await?,
            "closed terminal replay rewrote the body or metadata",
        )?;
        // Settling never reopens admission or touches the stored intent.
        f.stored(&a, &j, &request, &operation, 7).await?;
        replayed(&f.close(&a, &j, &request).await, &j, &request, &operation)?;
        f.finish().await
    })
    .await;
}

/// One refusal or replay whose real original ROLLBACK ACK is withheld; the result may not escape.
async fn withheld_rollback(
    f: &Fixture,
    proxy: &AckProxy,
    auth: &AuthContext,
    j: &str,
    request: &str,
) -> Result<Close> {
    let mut hold = proxy.hold(ROLLBACK)?;
    let task = f.spawn_close(auth, j, request, deadline());
    hold.wait().await?;
    check(
        !task.is_finished(),
        "a result escaped before the real original ROLLBACK ACK",
    )?;
    hold.release()?;
    task.await.map_err(text)
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_original_commit_ack_held_late_and_lost_are_classified() {
    owned_proxy("stop06", 7, |f, proxy| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let (_, j1) = f.settled(&a, 601).await?;
        let (_, j2) = f.settled(&a, 602).await?;
        let (_, j3) = f.settled(&a, 603).await?;
        // The typed result waits for the real original COMMIT ACK; the server has already acted.
        let first = request_id();
        let mut hold = proxy.hold(COMMIT)?;
        let task = f.spawn_close(&a, &j1, &first, deadline());
        hold.wait().await?;
        check(
            !task.is_finished(),
            "a typed result escaped before the real original COMMIT ACK",
        )?;
        check(
            f.phase(&j1).await?.as_deref() == Some("closed") && f.intents(&j1).await? == 1,
            "the server had not committed while the ACK was withheld",
        )?;
        hold.release()?;
        let result = task.await.map_err(text)?;
        let operation = committed(&result, &a, &j1, &first)?;
        f.stored(&a, &j1, &first, &operation, 7).await?;
        // A COMMIT ACK withheld past the original deadline is Unknown, never a success; the
        // committed fact is then proven by the same request replaying the original operation.
        let second = request_id();
        let mut hold = proxy.hold(COMMIT)?;
        let task = f.spawn_close(
            &a,
            &j2,
            &second,
            Instant::now() + Duration::from_millis(3000),
        );
        hold.wait().await?;
        let late = task.await.map_err(text)?;
        check(
            matches!(late, Err(Stop::CommitUnknown)),
            "a COMMIT ACK withheld past the deadline was not Unknown",
        )?;
        let _ = hold.release();
        check(
            f.phase(&j2).await?.as_deref() == Some("closed") && f.intents(&j2).await? == 1,
            "the unknown COMMIT left no committed fact",
        )?;
        let late_operation = f.operation_of(&j2).await?;
        replayed(
            &f.close(&a, &j2, &second).await,
            &j2,
            &second,
            &late_operation,
        )?;
        // A lost COMMIT ACK is Unknown too, and replays the same way.
        let third = request_id();
        proxy.drop_next(COMMIT)?;
        let lost = f.close(&a, &j3, &third).await;
        check(
            matches!(lost, Err(Stop::CommitUnknown)),
            "a lost COMMIT ACK was not Unknown",
        )?;
        check(
            f.phase(&j3).await?.as_deref() == Some("closed") && f.intents(&j3).await? == 1,
            "the lost COMMIT ACK left no committed fact",
        )?;
        let lost_operation = f.operation_of(&j3).await?;
        replayed(
            &f.close(&a, &j3, &third).await,
            &j3,
            &third,
            &lost_operation,
        )?;
        // Refusals and exact replays return only after their own real original ROLLBACK ACK.
        let tables = f.hq().await?;
        conflict(&withheld_rollback(&f, &proxy, &a, &j1, &request_id()).await?)?;
        not_visible(&withheld_rollback(&f, &proxy, &b, &j1, &request_id()).await?)?;
        replayed(
            &withheld_rollback(&f, &proxy, &a, &j1, &first).await?,
            &j1,
            &first,
            &operation,
        )?;
        check(
            tables == f.hq().await?,
            "a withheld ROLLBACK ACK changed H or Q",
        )?;
        f.finish().await?;
        proxy.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_real_session_withdrawal_and_closed_host_refuse_before_commit() {
    owned_proxy("stop07", 7, |f, proxy| async move {
        let old = f.auth(A, 1).await?;
        let (_, j) = f.settled(&old, 701).await?;
        let untouched = f.hq().await?;
        // Leg 1: the original Session is withdrawn while the producer waits for the actor row.
        {
            let mut writer = f.pool.get().await.map_err(text)?;
            let blocker = backend_pid(&writer).await?;
            let tx = writer.transaction().await.map_err(text)?;
            tx.execute(
                "UPDATE public.users SET auth_generation=auth_generation WHERE id=$1",
                &[&A],
            )
            .await
            .map_err(text)?;
            let task = f.spawn_close(&old, &j, &request_id(), deadline());
            wait_blocked(&f.pool, blocker, "users").await?;
            tx.batch_execute("DELETE FROM public.sessions WHERE id='stop-a-session-1'")
                .await
                .map_err(text)?;
            tx.commit().await.map_err(text)?;
            not_visible(&task.await.map_err(text)?)?;
        }
        check(
            untouched == f.hq().await?,
            "a withdrawn Session left H or Q behind",
        )?;
        // Leg 2: the real Host closes while the producer's transaction is still open. The
        // producer is paused at the real SET CONSTRAINTS acknowledgement, so the intent, the
        // closed head and the settled pair exist only in its uncommitted transaction. It must
        // refuse and roll back. Its ROLLBACK acknowledgement is withheld in turn: the server has
        // already undone every write while the result still waits for the real acknowledgement.
        let next = f.auth(A, 2).await?;
        let mut settled = proxy.hold(SETTLED)?;
        let attempt = f.spawn_close(&next, &j, &request_id(), deadline());
        settled.wait().await?;
        let mut rollback = proxy.hold(ROLLBACK)?;
        f.resolver.close_request_bindings();
        settled.release()?;
        rollback.wait().await?;
        check(
            !attempt.is_finished(),
            "a result escaped before the real original ROLLBACK ACK",
        )?;
        check(
            untouched == f.hq().await?,
            "a write survived although the Host closed before COMMIT",
        )?;
        rollback.release()?;
        host_refused(&attempt.await.map_err(text)?)?;
        check(
            untouched == f.hq().await?
                && f.phase(&j).await?.as_deref() == Some("open")
                && f.intents(&j).await? == 0,
            "a Host closed before COMMIT left H or Q behind",
        )?;
        host_refused(&f.close(&next, &j, &request_id()).await)?;
        // Leg 3: a genuine new producer is not poisoned by the closed old owner and still closes
        // the same Thread. Its COMMIT ACK is withheld while its own Host closes: a Host failure
        // after a known COMMIT is that failure, never Unknown, and keeps the stored fact.
        let second = FreshHost::new(&f)?;
        let after = second.auth(A, 2).await?;
        let request = request_id();
        let mut hold = proxy.hold(COMMIT)?;
        let task = second.spawn_close(&after, &j, &request, deadline());
        hold.wait().await?;
        second.resolver.close_request_bindings();
        check(
            !task.is_finished(),
            "the owner escaped before the original COMMIT ACK",
        )?;
        hold.release()?;
        host_refused(&task.await.map_err(text)?)?;
        check(
            f.phase(&j).await?.as_deref() == Some("closed") && f.intents(&j).await? == 1,
            "a post-commit Host failure undid the committed intent",
        )?;
        let operation = f.operation_of(&j).await?;
        host_refused(&second.close(&after, &j, &request).await)?;
        second.retire();
        // Leg 4: yet another genuine producer replays the stored fact.
        let third = FreshHost::new(&f)?;
        let current = third.auth(A, 2).await?;
        let replay = third.close(&current, &j, &request).await;
        replayed(&replay, &j, &request, &operation)?;
        drop(current);
        third.retire();
        f.finish().await?;
        proxy.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_real_single_user_owner_closes_and_synthetic_owner_refuses() {
    owned("stop08", 0, |f| async move {
        let single = |principal| {
            SingleUserAuthResolver::from_verified_principal(
                principal,
                openbot_infra::auth::config::default_session_lifetime(),
            )
        };
        let principal = openbot_infra::auth::single_user::load_single_user_principal(
            &f.pool,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )
        .await
        .map_err(text)?;
        let resolver = single(principal);
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
        resolver
            .install_thread_history_authority(&authority, &f.pool)
            .map_err(text)?;
        let auth = resolver
            .resolve(
                &http::Request::builder()
                    .uri("/owned-stop-single")
                    .body(())
                    .map_err(text)?
                    .into_parts()
                    .0,
            )
            .await
            .map_err(text)?;
        let (_, j1) = f.settled(&auth, 801).await?;
        let (_, j2) = f.settled(&auth, 802).await?;
        let (_, j3) = f.settled(&auth, 803).await?;
        // The real verified owner closes its own Thread at generation zero.
        let r1 = request_id();
        let first = authority
            .close_for_stop_clear_before(&auth, &j1, &r1, deadline())
            .await;
        let o1 = committed(&first, &auth, &j1, &r1)?;
        f.stored(&auth, &j1, &r1, &o1, 0).await?;
        // A NULL stored generation reads as zero and stays NULL.
        f.sql("UPDATE public.users SET auth_generation=NULL WHERE id='dev-local-user'")
            .await?;
        let r2 = request_id();
        let second = authority
            .close_for_stop_clear_before(&auth, &j2, &r2, deadline())
            .await;
        let o2 = committed(&second, &auth, &j2, &r2)?;
        f.stored(&auth, &j2, &r2, &o2, 0).await?;
        check(
            f.one::<bool>(
                "SELECT auth_generation IS NULL FROM public.users WHERE id=$1",
                "dev-local-user",
            )
            .await?,
            "the producer rewrote the NULL generation",
        )?;
        f.sql("UPDATE public.users SET auth_generation=0 WHERE id='dev-local-user'")
            .await?;
        // Enrollment is once, owner-bound and Pool-bound; a context-only owner has no Host.
        check(
            resolver
                .install_thread_history_authority(&authority, &f.pool)
                .is_err(),
            "duplicate enrollment succeeded",
        )?;
        // The production constructor of a context-only owner is test-only; the same value built by
        // hand carries no request binding, so it borrows no Host and the producer refuses it.
        let unbound = AuthContextBuilder::from_verified_session(
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            ActorId::new("dev-local-user"),
            AuthGeneration::new(0),
            true,
        )
        .with_roles([Role::Admin, Role::User])
        .build();
        host_refused(
            &authority
                .close_for_stop_clear_before(&unbound, &j3, &request_id(), deadline())
                .await,
        )?;
        let other = pool::connect(&f.config).await.map_err(text)?;
        let principal = openbot_infra::auth::single_user::load_single_user_principal(
            &f.pool,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )
        .await
        .map_err(text)?;
        let different = single(principal);
        check(
            different
                .install_thread_history_authority(&authority, &other)
                .is_err(),
            "the same DSN with a different Pool accepted the original principal",
        )?;
        different.close_request_bindings();
        close_pool(other).await?;
        // Canonical email, role and deny drift each refuse; restoring them poisons nothing.
        let before = f.hq().await?;
        for (bad, restore) in [
            (
                "UPDATE public.users SET email='other@example.test' WHERE id='dev-local-user'",
                "UPDATE public.users SET email='dev@openbot.local' WHERE id='dev-local-user'",
            ),
            (
                "DELETE FROM public.user_roles WHERE user_id='dev-local-user'",
                "INSERT INTO public.user_roles(user_id,role) VALUES('dev-local-user','admin')",
            ),
            (
                "INSERT INTO public.revoked_access(email,revoked_by) VALUES('dev@openbot.local','stop-admin')",
                "DELETE FROM public.revoked_access WHERE email='dev@openbot.local'",
            ),
        ] {
            f.sql(bad).await?;
            not_visible(
                &authority
                    .close_for_stop_clear_before(&auth, &j3, &request_id(), deadline())
                    .await,
            )?;
            check(
                before == f.hq().await?,
                "a stale canonical SingleUser grant wrote H or Q",
            )?;
            f.sql(restore).await?;
        }
        let r3 = request_id();
        let third = authority
            .close_for_stop_clear_before(&auth, &j3, &r3, deadline())
            .await;
        let o3 = committed(&third, &auth, &j3, &r3)?;
        f.stored(&auth, &j3, &r3, &o3, 0).await?;
        resolver.close_request_bindings();
        host_refused(
            &authority
                .close_for_stop_clear_before(&auth, &j3, &r3, deadline())
                .await,
        )?;
        drop(resolver);
        drop(authority);
        f.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_stop_clear_two_original_producers_on_same_j_keep_one_intent() {
    owned("stop-two-producers", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let (_, j) = f.settled(&a, 990).await?;
        let other = Arc::new(
            PostgresThreadHistoryAuthority::new(
                f.pool.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .map_err(text)?,
        );
        other.enroll_original_registry(&f.registry).map_err(text)?;
        let resolver = PostgresSessionAuthResolver::new(
            f.pool.clone(),
            SESSION_KEY,
            openbot_infra::auth::config::default_session_lifetime(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )
        .map_err(text)?;
        resolver
            .install_thread_history_authority(&other)
            .map_err(text)?;
        let parts = http::Request::builder()
            .uri("/owned-two-producers")
            .header(
                "cookie",
                format!("openbot_session=owned-stop-cookie-{A}-01"),
            )
            .body(())
            .map_err(text)?
            .into_parts()
            .0;
        let b = resolver.resolve(&parts).await.map_err(text)?;
        let left = request_id();
        let right = request_id();
        let (one, two) = tokio::join!(
            f.close(&a, &j, &left),
            other.close_for_stop_clear_before(&b, &j, &right, deadline()),
        );
        let one_committed = one
            .as_ref()
            .is_ok_and(|x| x.confirmation() == Confirmation::CommitAcknowledged);
        let two_committed = two
            .as_ref()
            .is_ok_and(|x| x.confirmation() == Confirmation::CommitAcknowledged);
        check(
            one_committed != two_committed,
            "two producers did not select exactly one original commit",
        )?;
        let (winner, loser, winner_result) = if one_committed {
            check(
                matches!(two, Err(Stop::Conflict | Stop::Unavailable)),
                "second producer had an unexpected refusal",
            )?;
            (&left, &right, &one)
        } else {
            check(
                matches!(one, Err(Stop::Conflict | Stop::Unavailable)),
                "first producer had an unexpected refusal",
            )?;
            (&right, &left, &two)
        };
        let operation = committed(winner_result, &a, &j, winner)?;
        check(
            f.intents(&j).await? == 1,
            "same-J producers persisted two intents",
        )?;
        let before = f.hq().await?;
        conflict(&f.close(&a, &j, loser).await)?;
        conflict(
            &other
                .close_for_stop_clear_before(&b, &j, loser, deadline())
                .await,
        )?;
        replayed(&f.close(&a, &j, winner).await, &j, winner, &operation)?;
        replayed(
            &other
                .close_for_stop_clear_before(&b, &j, winner, deadline())
                .await,
            &j,
            winner,
            &operation,
        )?;
        check(
            f.hq().await? == before,
            "mutual refusal or exact replay rewrote the winning intent",
        )?;
        resolver.close_request_bindings();
        drop((resolver, other, b));
        f.finish().await
    })
    .await;
}
