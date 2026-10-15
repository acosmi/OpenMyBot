//! R454: twelve fixed outer cases, H01-H11 on real Server Host producers.
//! Test-owned PG only. Permissions below are independent expectations, not captured oracle data.
use super::{AuthResolver, PostgresSessionAuthResolver, SingleUserAuthResolver};
use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::{
    ArtifactAdministration, BeginThreadRunRequest, BeginThreadRunV2Request,
    IntelligenceImportReportStatus, RunRuntime, RunTerminal, ThreadDirectory,
    VerifiedIntelligenceBundle, compute_intelligence_thread_checksum, import_intelligence_bundle,
};
use openbot_contracts::{
    artifacts::SaveRunMessageTextArtifact,
    auth::AuthContext,
    command::{BeginThreadRun, BeginThreadRunV2, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId},
    intelligence::{
        INTELLIGENCE_BUNDLE_SCHEMA_VERSION, IntelligenceBundlePayload,
        IntelligenceBundleProvenance, IntelligenceImportMapping, IntelligenceThreadAnchor,
        IntelligenceThreadChecksum, IntelligenceThreadExport, IntelligenceThreadStatus,
    },
    model_connections::{CreateModelConnection, CustomModelProtocol, ModelApiKey},
    versioned_model_selection::{ModelSelectionIntentSource, RunModelSelectionV2},
};
use openbot_domain::{
    artifact::ArtifactQuotaPolicy,
    identity::session::{SessionHashKey, SessionToken, SessionTokenHash},
    remote_callback::RemoteRunAssertionSigner,
    vault::{KeyVersion, SecretBytes, WrappingKey},
};
use openbot_infra::{
    application_assembly::{
        ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
        assemble_postgres_application,
    },
    artifact_administration::PostgresArtifactAdministration,
    artifact_registry::ArtifactDatasetRegistry,
    artifact_source::ArtifactSourceError,
    artifact_store::DatasetBoundArtifactStore,
    db::{fresh, pool},
    intelligence_import::PostgresIntelligenceImportStore,
    model_connections::PostgresModelConnections,
    policy::PolicyStore,
    repo::{ChannelRepo, thread::ThreadRepo},
    run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime},
    thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory},
    thread_history_authority::{
        ObservedThreadHistoryManagement, PostgresThreadHistoryAuthority,
        ThreadHistoryObservationError as Error,
    },
    vault::CredentialRecordVault,
};
use serde_json::Value;
use std::os::unix::fs::DirBuilderExt as _;
use std::{
    fs::File,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use uuid::Uuid;
use zeroize::Zeroizing;
mod harness {
    use std::future::Future;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}
type Result<T = ()> = std::result::Result<T, String>;
const DEP: &str = "owned-history-deployment";
const TENANT: &str = "owned-history-tenant";
const A: &str = "history-a";
const B: &str = "history-b";
const C: &str = "history-admin";
const BOT: &str = "history-bot";
const PROCESS: &str = "owned-history-runtime";
const TEXT: &str = "OWNED_THREAD_HISTORY_BODY_CANARY café";
const SESSION_KEY: &[u8] = b"owned-thread-history-session-key";
fn check(ok: bool, reason: &str) -> Result {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn refused(r: std::result::Result<ObservedThreadHistoryManagement, Error>) -> Result {
    check(
        matches!(r, Err(Error::NotVisible)),
        "expected exact current NotVisible",
    )
}
fn host_refused(r: std::result::Result<ObservedThreadHistoryManagement, Error>) -> Result {
    check(
        matches!(r, Err(Error::Host(_))),
        "expected actual Host refusal",
    )
}
fn unavailable(r: std::result::Result<ObservedThreadHistoryManagement, Error>) -> Result {
    check(
        matches!(
            r,
            Err(Error::Unavailable
                | Error::DeadlineExceeded
                | Error::RollbackUnproven
                | Error::RollbackAcknowledgedAfterDeadline
                | Error::BeginUnavailable)
        ),
        "expected bounded original database/deadline refusal",
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
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut c = pool.get().await.map_err(|e| e.to_string())?;
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
            let g = i64::try_from(generation).map_err(|e| e.to_string())?;
            for (actor, email, role) in [
                (A, "history-a@example.test", "user"),
                (B, "history-b@example.test", "user"),
                (C, "history-admin@example.test", "admin"),
                ("dev-local-user", "dev@openbot.local", "admin"),
            ] {
                c.execute(
                    "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,$3)",
                    &[&actor, &email, &g],
                )
                .await
                .map_err(|e| e.to_string())?;
                c.execute(
                    "INSERT INTO public.user_roles(user_id,role) VALUES($1,$2::text::public.role)",
                    &[&actor, &role],
                )
                .await
                .map_err(|e| e.to_string())?;
            }
            c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('history-bot','History bot','built_in','{\"systemPrompt\":\"Owned history prompt\",\"providerSource\":\"managed\"}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('history-bot','history-a','History bot','','history','public');").await.map_err(|e|e.to_string())?;
            let now = OffsetDateTime::now_utc() - time::Duration::seconds(1);
            for (actor, index) in [(A, 1_u8), (A, 2), (B, 1), (C, 1)] {
                let id = format!("{actor}-session-{index}");
                let cookie = format!("owned-history-cookie-{actor}-{index:02}");
                let hash = SessionTokenHash::compute(
                    SessionToken::new(cookie.as_bytes()),
                    SessionHashKey::new(SESSION_KEY),
                )
                .to_column_value();
                c.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,$6)",&[&id,&actor,&hash,&(now+time::Duration::hours(1)),&now,&g]).await.map_err(|e|e.to_string())?;
            }
        }
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                pool.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x61; 32]).map_err(|e| e.to_string())?,
        );
        let policy_store = PolicyStore::postgres(pool.clone(), None);
        policy_store.load().await.map_err(|e| e.to_string())?;
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
                RemoteRunAssertionSigner::new(vec![0x63; 32]).map_err(|e| e.to_string())?,
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
                    .map_err(|e| e.to_string())?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".into()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .map_err(|e| e.to_string())?;
        assembly
            .model_dataset_binding
            .enroll_original_registry(&registry)
            .map_err(|e| format!("{e:?}"))?;
        let authority = Arc::clone(&assembly.thread_history_authority);
        authority
            .enroll_original_registry(&registry)
            .map_err(|e| format!("{e:?}"))?;
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                openbot_infra::auth::config::default_session_lifetime(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .map_err(|e| e.to_string())?,
        );
        resolver
            .install_thread_history_authority(&authority)
            .map_err(|e| format!("{e:?}"))?;
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?
        .with_model_dataset_binding(Arc::clone(&assembly.model_dataset_binding))
        .map_err(|e| e.to_string())?;
        let models = PostgresModelConnections::new(
            pool.clone(),
            vault,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x62; 32]),
        )
        .map_err(|e| e.to_string())?;
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
                    .uri("/owned-history")
                    .header(
                        "cookie",
                        format!("openbot_session=owned-history-cookie-{actor}-{index:02}"),
                    )
                    .body(())
                    .map_err(|e| e.to_string())?
                    .into_parts()
                    .0,
            )
            .await
            .map_err(|e| e.to_string())
    }
    async fn sql(&self, sql: &str) -> Result {
        self.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|e| e.to_string())
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
                run_id: RunId::new(format!("owned-history-run-{index}")),
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
            .map_err(|e| e.to_string())?;
        Ok(req)
    }
    async fn eligible(&self, auth: &AuthContext, j: &str) -> Result {
        let before = self.facts().await?;
        let result = self
            .authority
            .observe_management_before(auth, j, deadline())
            .await
            .map_err(|e| format!("{e:?}"))?;
        check(
            result.deployment_id() == auth.deployment()
                && result.tenant_id() == auth.tenant()
                && result.thread_id().as_str() == j,
            "snapshot must be exact J only",
        )?;
        check(
            before == self.facts().await?,
            "pure management observation wrote original facts",
        )
    }
    async fn facts(&self) -> Result<Value> {
        let c = self.pool.get().await.map_err(|e| e.to_string())?;
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
                .map_err(|e| e.to_string())?
                .try_get(0)
                .map_err(|e| e.to_string())?;
            out.insert(table.into(), value);
        }
        Ok(Value::Object(out))
    }
    async fn settle(&self, run: &str) -> Result {
        let runtime = PostgresRunRuntime::new(
            self.pool.clone(),
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|e| e.to_string())?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("pending real dispatch absent")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|e| e.to_string())?;
        check(lease.run_id().as_str() == run, "different run claimed")?;
        runtime
            .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map_err(|e| e.to_string())
            .map(|_| ())
    }
    async fn origin(&self, j: &str) -> Result<Value> {
        self.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT to_jsonb(o) FROM openbot_internal.thread_origins o WHERE thread_id=$1",
                &[&j],
            )
            .await
            .map_err(|e| e.to_string())?
            .try_get(0)
            .map_err(|e| e.to_string())
    }
    async fn channel(&self, auth: &AuthContext) -> Result<(String, String)> {
        let created = openbot_application::create_channel(
            &ChannelRepo::new(self.pool.clone()),
            auth,
            vec![BotId::new(BOT)],
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok((
            created.id.as_str().into(),
            created
                .thread_id
                .ok_or("channel producer did not mint Thread")?
                .as_str()
                .into(),
        ))
    }
    async fn v2(&self, auth: &AuthContext, index: u64) -> Result<String> {
        let model = self
            .models
            .create(
                auth,
                &CreateModelConnection {
                    name: "Owned history choice".into(),
                    protocol: CustomModelProtocol::OpenaiResponses,
                    endpoint: "https://owned-history.example.test/v1".into(),
                    model: "owned-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new("OWNED_HISTORY_SYNTHETIC_KEY".into()))
                        .map_err(|e| e.to_string())?,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        let req = self.request(auth, index, ThreadRunAnchor::DirectBot);
        let command = BeginThreadRunV2 {
            artifact_refs: Vec::new(),
            thread_id: req.command.thread_id.clone(),
            run_id: req.command.run_id.clone(),
            bot_id: req.command.bot_id,
            anchor: req.command.anchor,
            message: req.command.message,
            selected_skill_slugs: vec![],
            model_selection: RunModelSelectionV2::new(
                ModelSelectionIntentSource::Custom,
                model.id.clone(),
                model.revision,
                format!("custom:{}", model.id),
                1,
            )
            .map_err(|e| e.to_string())?,
        };
        self.directory
            .begin_thread_run_v2(BeginThreadRunV2Request {
                deployment: auth.deployment().clone(),
                tenant: auth.tenant().clone(),
                actor: auth.actor().clone(),
                auth_generation: auth.auth_generation(),
                command,
            })
            .await
            .map_err(|e| e.to_string())?;
        Ok(req.command.thread_id.as_str().into())
    }
    async fn import(&self, index: u64) -> Result<String> {
        let j = Uuid::from_u128(0x00000000000040008000000000000000_u128 + u128::from(index))
            .to_string();
        let z = "0".repeat(64);
        let mut thread = IntelligenceThreadExport {
            thread_id: j.clone(),
            created_by: "legacy-creator".into(),
            members: vec!["legacy-creator".into()],
            title: Some("Owned history import".into()),
            anchor: IntelligenceThreadAnchor::DirectBot {
                bot_id: "legacy-bot".into(),
            },
            status: IntelligenceThreadStatus::Active,
            messages: vec![],
            runs: vec![],
            memories: vec![],
            checksum: IntelligenceThreadChecksum {
                projection_hash: z.clone(),
                message_count: 0,
                message_hash: z.clone(),
                event_count: 0,
                event_hash: z.clone(),
                terminal_state_hash: z.clone(),
                memory_count: 0,
                memory_hash: z.clone(),
                sample_render_hash: z,
            },
            created_at: time::macros::datetime!(2026-09-01 00:00 UTC),
            updated_at: time::macros::datetime!(2026-09-01 00:00 UTC),
            deleted_at: None,
        };
        thread.checksum =
            compute_intelligence_thread_checksum(&thread).map_err(|e| e.to_string())?;
        let payload = IntelligenceBundlePayload {
            schema_version: INTELLIGENCE_BUNDLE_SCHEMA_VERSION,
            bundle_id: format!("owned-history-bundle-{index}"),
            source_deployment_id: "owned-history-source".into(),
            exported_at: time::macros::datetime!(2026-09-01 01:00 UTC),
            provenance: IntelligenceBundleProvenance {
                upstream_commit: openbot_application::INTELLIGENCE_SOURCE_COMMIT.into(),
                exporter_version: "owned-history-v1".into(),
                project_id: "owned-history-project".into(),
            },
            threads: vec![thread],
        };
        let bundle =
            VerifiedIntelligenceBundle::new(payload, "c".repeat(64), "owned-history-key".into())
                .map_err(|e| e.to_string())?;
        let mapping = IntelligenceImportMapping {
            target_deployment_id: DEP.into(),
            target_tenant_id: TENANT.into(),
            users: [("legacy-creator".into(), A.into())].into_iter().collect(),
            bots: [("legacy-bot".into(), BOT.into())].into_iter().collect(),
            channels: Default::default(),
            claimed_thread_ids: [j.clone()].into_iter().collect(),
        };
        let report = import_intelligence_bundle(
            &PostgresIntelligenceImportStore::new(self.pool.clone()),
            bundle,
            mapping,
        )
        .await
        .map_err(|e| e.to_string())?;
        check(
            report.status == IntelligenceImportReportStatus::Completed && report.thread_count == 1,
            "actual maintenance import failed",
        )?;
        Ok(j)
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
async fn close_pool(p: pool::DatabasePool) -> Result {
    let observations = p.connection_observations();
    p.close();
    for o in observations {
        check(
            o.wait_for_destruction_before(Instant::now() + Duration::from_secs(10))
                .await
                .map_err(|e| e.to_string())?
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
async fn wait_actor_lock(pool: &pool::DatabasePool, blocker: i32) -> Result<i32> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let c = pool.get().await.map_err(|e| e.to_string())?;
        let r=c.query_opt("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%users%' AND pid<>pg_backend_pid() LIMIT 1",&[&blocker]).await.map_err(|e|e.to_string())?;
        if let Some(r) = r {
            return r.try_get(0).map_err(|e| e.to_string());
        }
        drop(c);
        check(Instant::now() < until, "real actor lock wait never reached")?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_current_creator_native_and_import_origins_bind_exact_j() {
    owned("history01", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let admin = f.auth(C, 1).await?;
        let req = f.begin(&a, 101).await?;
        let v1 = req.command.thread_id.as_str().to_owned();
        f.settle(req.command.run_id.as_str()).await?;
        let v2 = f.v2(&a, 102).await?;
        f.settle("owned-history-run-102").await?;
        let (_, channel) = f.channel(&a).await?;
        let imported = f.import(103).await?;
        for (j, kind) in [
            (&v1, "native_begin_v1"),
            (&v2, "native_begin_v2"),
            (&channel, "private_agent_channel"),
            (&imported, "maintenance_import"),
        ] {
            let origin = f.origin(j).await?;
            check(
                origin["creator_actor_id"] == A
                    && origin["origin_kind"] == kind
                    && origin["deployment_id"] == DEP
                    && origin["tenant_id"] == TENANT,
                "independent immutable origin identity differs",
            )?;
            f.eligible(&a, j).await?;
            refused(
                f.authority
                    .observe_management_before(&b, j, deadline())
                    .await,
            )?;
            refused(
                f.authority
                    .observe_management_before(&admin, j, deadline())
                    .await,
            )?;
            check(f.origin(j).await? == origin, "observer reminted origin")?;
        }
        check(
            !ThreadIdentity::new(&DeploymentId::new(DEP))
                .owns(&openbot_contracts::ids::ThreadId::new(&imported)),
            "imported legacy UUID must distinguish current deployment ownership",
        )?;
        for bad in ["", "not-a-thread", "00000000-0000-4000-8000-000000000000\n"] {
            check(
                matches!(
                    f.authority
                        .observe_management_before(&a, bad, deadline())
                        .await,
                    Err(Error::InvalidInput { field: "thread_id" })
                ),
                "invalid ID must fail exact input boundary",
            )?;
        }
        f.finish().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_later_channel_member_and_admin_never_take_creator() {
    owned("history02", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let c = f.auth(C, 1).await?;
        let (channel, j) = f.channel(&a).await?;
        {
            let p = f.pool.get().await.map_err(|e| e.to_string())?;
            for actor in [B, C] {
                p.execute(
                    "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES($1,$2)",
                    &[&channel, &actor],
                )
                .await
                .map_err(|e| e.to_string())?;
            }
        }
        let mut req = f.request(
            &b,
            201,
            ThreadRunAnchor::Channel {
                channel_id: ChannelId::new(&channel),
            },
        );
        req.command.thread_id = openbot_contracts::ids::ThreadId::new(&j);
        f.directory
            .begin_thread_run(req.clone())
            .await
            .map_err(|e| e.to_string())?;
        f.settle(req.command.run_id.as_str()).await?;
        f.eligible(&a, &j).await?;
        refused(
            f.authority
                .observe_management_before(&b, &j, deadline())
                .await,
        )?;
        refused(
            f.authority
                .observe_management_before(&c, &j, deadline())
                .await,
        )?;
        check(
            matches!(
                f.registry
                    .observe_source(&a, &req.command.thread_id, &req.command.run_id)
                    .await,
                Err(ArtifactSourceError::NotVisible)
            ),
            "creator management opened B Run",
        )?;
        f.registry
            .observe_source(&b, &req.command.thread_id, &req.command.run_id)
            .await
            .map_err(|e| e.to_string())?;
        f.sql("INSERT INTO public.user_roles(user_id,role) VALUES('history-b','admin')")
            .await?;
        let b_admin = f.auth(B, 1).await?;
        refused(
            f.authority
                .observe_management_before(&b_admin, &j, deadline())
                .await,
        )?;
        f.registry
            .observe_source(&b_admin, &req.command.thread_id, &req.command.run_id)
            .await
            .map_err(|e| e.to_string())?;
        f.finish().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_scope_is_one_j_and_preserves_source_read_and_saved_owner() {
    owned("history03", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let ja = f.begin(&a, 301).await?;
        f.settle(ja.command.run_id.as_str()).await?;
        let jb = f.begin(&b, 302).await?;
        f.settle(jb.command.run_id.as_str()).await?;
        f.eligible(&a, ja.command.thread_id.as_str()).await?;
        refused(
            f.authority
                .observe_management_before(&a, jb.command.thread_id.as_str(), deadline())
                .await,
        )?;
        check(
            matches!(
                f.registry
                    .observe_source(&a, &jb.command.thread_id, &jb.command.run_id)
                    .await,
                Err(ArtifactSourceError::NotVisible)
            ),
            "J scope opened foreign Run",
        )?;
        let root =
            std::env::temp_dir().join(format!("owned-history-saved-{}", Uuid::now_v7().simple()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|e| e.to_string())?;
        let policy = ArtifactQuotaPolicy::default();
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                File::open(&root).map_err(|e| e.to_string())?,
                f.registry.clone(),
                policy,
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let administration = Arc::new(
            PostgresArtifactAdministration::new(
                f.registry.clone(),
                store.clone(),
                policy,
                SecretBytes::new(vec![0x83; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        f.resolver
            .install_artifact_read_authority(&administration.read_authority())
            .map_err(|e| format!("{e:?}"))?;
        use sha2::Digest as _;
        let digest = format!("{:x}", sha2::Sha256::digest(TEXT.as_bytes()));
        let saved = administration
            .save_run_message_text(
                &b,
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: jb.command.thread_id.clone(),
                    source_run_id: jb.command.run_id.clone(),
                    source_message_id: format!("{}:input", jb.command.run_id),
                    expected_sha256: digest,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        f.eligible(&a, ja.command.thread_id.as_str()).await?;
        check(
            administration
                .arm_explicit_saved_delete_before(&a, &saved.artifact_id, deadline())
                .await
                .is_err(),
            "creator eligibility adopted B saved-owner",
        )?;
        {
            let p = f.pool.get().await.map_err(|e| e.to_string())?;
            p.execute(
                "DELETE FROM public.threads WHERE thread_id=$1",
                &[&jb.command.thread_id.as_str()],
            )
            .await
            .map_err(|e| e.to_string())?;
        }
        refused(
            f.authority
                .observe_management_before(&b, jb.command.thread_id.as_str(), deadline())
                .await,
        )?;
        let armed = administration
            .arm_explicit_saved_delete_before(&b, &saved.artifact_id, deadline())
            .await
            .map_err(|e| e.to_string())?;
        drop(armed);
        drop(administration);
        drop(store);
        std::fs::remove_dir_all(&root).map_err(|e| e.to_string())?;
        f.finish().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_direct_profile_membership_and_package_are_current() {
    owned("history04",7,|f|async move{
 let a=f.auth(A,1).await?;let req=f.begin(&a,401).await?;f.settle(req.command.run_id.as_str()).await?;let j=req.command.thread_id.as_str();f.eligible(&a,j).await?;
 f.sql("UPDATE public.agent_profiles SET visibility='private' WHERE agent_id='history-bot'").await?;f.eligible(&a,j).await?;
 f.sql("INSERT INTO public.user_roles(user_id,role) VALUES('history-a','admin')").await?;let admin=f.auth(A,1).await?;
 for (bad,restore) in [("UPDATE public.agent_profiles SET owner_user_id='history-b' WHERE agent_id='history-bot'","UPDATE public.agent_profiles SET owner_user_id='history-a' WHERE agent_id='history-bot'"),("UPDATE public.agent_profiles SET deleted_at=clock_timestamp() WHERE agent_id='history-bot'","UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='history-bot'")]{f.sql(bad).await?;refused(f.authority.observe_management_before(&admin,j,deadline()).await)?;f.sql(restore).await?;f.eligible(&admin,j).await?;}
 {let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("DELETE FROM public.thread_memberships WHERE thread_id=$1 AND user_id=$2",&[&j,&A]).await.map_err(|e|e.to_string())?;}refused(f.authority.observe_management_before(&admin,j,deadline()).await)?;{let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,$2)",&[&j,&A]).await.map_err(|e|e.to_string())?;}
 f.sql("INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES('00000000-0000-4000-8000-000000000404','owned-history-tenant','owned','owned'); UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000404' WHERE id='history-bot'").await?;f.eligible(&admin,j).await?;f.sql("UPDATE public.deployment_packages SET tenant_id='history-other-tenant' WHERE id='00000000-0000-4000-8000-000000000404'").await?;refused(f.authority.observe_management_before(&admin,j,deadline()).await)?;f.sql("UPDATE public.agents SET package_id=NULL WHERE id='history-bot'").await?;f.eligible(&admin,j).await?;
 f.finish().await
}).await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_channel_membership_and_package_do_not_choose_a_bot() {
    owned("history05",7,|f|async move{
 let a=f.auth(A,1).await?;let(channel,j)=f.channel(&a).await?;let mut req=f.request(&a,501,ThreadRunAnchor::Channel{channel_id:ChannelId::new(&channel)});req.command.thread_id=openbot_contracts::ids::ThreadId::new(&j);f.directory.begin_thread_run(req.clone()).await.map_err(|e|e.to_string())?;f.settle(req.command.run_id.as_str()).await?;
 f.registry.observe_source(&a,&req.command.thread_id,&req.command.run_id).await.map_err(|e|e.to_string())?;{let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("DELETE FROM public.channel_agents WHERE channel_id=$1",&[&channel]).await.map_err(|e|e.to_string())?;}
 f.eligible(&a,&j).await?;check(matches!(f.registry.observe_source(&a,&req.command.thread_id,&req.command.run_id).await,Err(ArtifactSourceError::NotVisible)),"management bypassed original selected Run Bot requirement")?;
 {let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("DELETE FROM public.channel_memberships WHERE channel_id=$1 AND user_id=$2",&[&channel,&A]).await.map_err(|e|e.to_string())?;}refused(f.authority.observe_management_before(&a,&j,deadline()).await)?;{let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("INSERT INTO public.channel_memberships(channel_id,user_id) VALUES($1,$2)",&[&channel,&A]).await.map_err(|e|e.to_string())?;}
 f.sql("INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES('00000000-0000-4000-8000-000000000505','owned-history-tenant','owned','owned')").await?;{let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000505' WHERE id=$1",&[&channel]).await.map_err(|e|e.to_string())?;}f.eligible(&a,&j).await?;f.sql("UPDATE public.deployment_packages SET tenant_id='history-other-tenant' WHERE id='00000000-0000-4000-8000-000000000505'").await?;refused(f.authority.observe_management_before(&a,&j,deadline()).await)?;{let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("UPDATE public.channels SET package_id=NULL WHERE id=$1",&[&channel]).await.map_err(|e|e.to_string())?;}f.eligible(&a,&j).await?;
 f.finish().await
}).await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_generation_null_zero_roles_deny_and_missing_user_are_current() {
    owned("history06",0,|f|async move{
 let a=f.auth(A,1).await?;let req=f.begin(&a,601).await?;f.settle(req.command.run_id.as_str()).await?;let j=req.command.thread_id.as_str();f.eligible(&a,j).await?;
 f.sql("UPDATE public.users SET auth_generation=NULL WHERE id='history-a'").await?;f.eligible(&a,j).await?;f.sql("UPDATE public.users SET auth_generation=1 WHERE id='history-a'").await?;refused(f.authority.observe_management_before(&a,j,deadline()).await)?;f.sql("UPDATE public.users SET auth_generation=0 WHERE id='history-a'").await?;
 for(bad,restore) in [("DELETE FROM public.user_roles WHERE user_id='history-a'","INSERT INTO public.user_roles(user_id,role) VALUES('history-a','user')"),("INSERT INTO public.revoked_access(email,revoked_by) VALUES('history-a@example.test','history-admin')","DELETE FROM public.revoked_access WHERE email='history-a@example.test'")]{f.sql(bad).await?;refused(f.authority.observe_management_before(&a,j,deadline()).await)?;f.sql(restore).await?;f.eligible(&a,j).await?;}
 f.sql("UPDATE public.users SET email='HISTORY-A@EXAMPLE.TEST' WHERE id='history-a'; INSERT INTO public.revoked_access(email,revoked_by) VALUES('history-a@example.test','history-admin')").await?;refused(f.authority.observe_management_before(&a,j,deadline()).await)?;f.sql("DELETE FROM public.revoked_access WHERE email='history-a@example.test'; UPDATE public.users SET email='history-a@example.test' WHERE id='history-a'").await?;f.eligible(&a,j).await?;
 f.sql("DELETE FROM public.users WHERE id='history-a'").await?;check(f.authority.observe_management_before(&a,j,deadline()).await.is_err(),"missing real user accepted stale Host/origin")?;
 f.finish().await
}).await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_legacy_unknown_and_missing_or_deleted_base_never_adopt() {
    owned("history07",7,|f|async move{
 let a=f.auth(A,1).await?;let known=f.import(701).await?;let original=f.origin(&known).await?;f.eligible(&a,&known).await?;
 let generic=f.request(&a,702,ThreadRunAnchor::DirectBot).command.thread_id.as_str().to_owned();let now=OffsetDateTime::now_utc();let row=openbot_infra::db::tables::threads::Row{thread_id:generic.clone(),deployment_id:DEP.into(),tenant_id:TENANT.into(),created_by:A.into(),anchor_kind:"direct_bot".into(),anchor_id:BOT.into(),title:Some("Legacy".into()),status:"active".into(),next_message_seq:0,next_event_seq:0,created_at:now,updated_at:now,deleted_at:None};ThreadRepo::new(f.pool.clone()).insert(&row).await.map_err(|e|e.to_string())?;
 {let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,$2)",&[&generic,&A]).await.map_err(|e|e.to_string())?;}refused(f.authority.observe_management_before(&a,&generic,deadline()).await)?;{let p=f.pool.get().await.map_err(|e|e.to_string())?;let n:i64=p.query_one("SELECT count(*) FROM openbot_internal.thread_origins WHERE thread_id=$1",&[&generic]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;check(n==0,"LegacyUnknown was adopted")?;p.execute("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp() WHERE thread_id=$1",&[&known]).await.map_err(|e|e.to_string())?;}
 refused(f.authority.observe_management_before(&a,&known,deadline()).await)?;{let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("DELETE FROM public.threads WHERE thread_id=$1",&[&known]).await.map_err(|e|e.to_string())?;}refused(f.authority.observe_management_before(&a,&known,deadline()).await)?;check(f.origin(&known).await?==original,"hard deletion rewrote historical origin")?;
 f.finish().await
}).await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_bad_known_binding_and_database_failures_are_distinct() {
    owned("history08",7,|f|async move{
 let a=f.auth(A,1).await?;let j=f.import(801).await?;let original=f.origin(&j).await?;
 {let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("UPDATE public.threads SET created_by=$2 WHERE thread_id=$1",&[&j,&B]).await.map_err(|e|e.to_string())?;}check(matches!(f.authority.observe_management_before(&a,&j,deadline()).await,Err(Error::Corrupt{field:"origin_binding"})),"valid-CHECK base mismatch did not reach origin-binding refusal")?;{let p=f.pool.get().await.map_err(|e|e.to_string())?;p.execute("UPDATE public.threads SET created_by=$2 WHERE thread_id=$1",&[&j,&A]).await.map_err(|e|e.to_string())?;}f.eligible(&a,&j).await?;
 f.sql("CREATE INDEX owned_history_unknown_origin_index ON openbot_internal.thread_origins(creator_actor_id)").await?;check(matches!(f.authority.observe_management_before(&a,&j,deadline()).await,Err(Error::Corrupt{field:"schema"})),"actual extra index did not fail schema")?;f.sql("DROP INDEX openbot_internal.owned_history_unknown_origin_index").await?;f.eligible(&a,&j).await?;
 for number in ["0.0","1.0"] {let mut p=f.pool.get().await.map_err(|e|e.to_string())?;let tx=p.transaction().await.map_err(|e|e.to_string())?;tx.batch_execute("ALTER TABLE openbot_internal.thread_origins DISABLE TRIGGER USER").await.map_err(|e|e.to_string())?;tx.execute("UPDATE openbot_internal.thread_origins SET import_thread_checksum=jsonb_set(import_thread_checksum,'{messageCount}',$2::text::jsonb) WHERE thread_id=$1",&[&j,&number]).await.map_err(|e|e.to_string())?;tx.batch_execute("ALTER TABLE openbot_internal.thread_origins ENABLE TRIGGER USER").await.map_err(|e|e.to_string())?;tx.commit().await.map_err(|e|e.to_string())?;drop(p);f.eligible(&a,&j).await?;}
 for number in ["1.5","-1","18446744073709551616"] {let mut p=f.pool.get().await.map_err(|e|e.to_string())?;let tx=p.transaction().await.map_err(|e|e.to_string())?;tx.batch_execute("ALTER TABLE openbot_internal.thread_origins DISABLE TRIGGER USER").await.map_err(|e|e.to_string())?;let e=tx.execute("UPDATE openbot_internal.thread_origins SET import_thread_checksum=jsonb_set(import_thread_checksum,'{messageCount}',$2::text::jsonb) WHERE thread_id=$1",&[&j,&number]).await.err().ok_or("invalid count unexpectedly stored")?;check(e.code()==Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION),"count rejection was not original CHECK")?;tx.rollback().await.map_err(|e|e.to_string())?;eprintln!("THREAD_HISTORY_OBSERVATION id=H08 invalid_count={number} actual_CHECK_refusal=true origin_row_decode_credit=0");}
 {let mut p=f.pool.get().await.map_err(|e|e.to_string())?;let tx=p.transaction().await.map_err(|e|e.to_string())?;tx.batch_execute("ALTER TABLE openbot_internal.thread_origins DISABLE TRIGGER USER").await.map_err(|e|e.to_string())?;tx.execute("UPDATE openbot_internal.thread_origins SET import_thread_checksum=$2 WHERE thread_id=$1",&[&j,&original["import_thread_checksum"]]).await.map_err(|e|e.to_string())?;tx.batch_execute("ALTER TABLE openbot_internal.thread_origins ENABLE TRIGGER USER").await.map_err(|e|e.to_string())?;tx.commit().await.map_err(|e|e.to_string())?;}f.eligible(&a,&j).await?;
 f.resolver.close_request_bindings();host_refused(f.authority.observe_management_before(&a,&j,deadline()).await)?;eprintln!("THREAD_HISTORY_OBSERVATION id=H08 schema_and_original_host_errors_distinct=true actual_RowDecode_credit=0");f.finish().await
}).await;
}
// Proxy-side ends of one `AckHold`: signal the real ROLLBACK ACK arrived, then await its release.
type ProxyAckHold = (oneshot::Sender<()>, oneshot::Receiver<()>);
// Protocol-aware owned PG relay. Only a real backend ROLLBACK CommandComplete is held/dropped.
struct AckProxy {
    port: u16,
    remaining: Arc<AtomicUsize>,
    control: Arc<tokio::sync::Mutex<Option<ProxyAckHold>>>,
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
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
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
            .map_err(|e| e.to_string())?;
        let local = listener.local_addr().map_err(|e| e.to_string())?.port();
        let remaining = Arc::new(AtomicUsize::new(0));
        let control = Arc::new(tokio::sync::Mutex::new(None::<ProxyAckHold>));
        let count = remaining.clone();
        let gate = control.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {_= &mut stopped=>break,Some(_)=children.join_next()=>{},pair=listener.accept()=>{let Ok((client,_))=pair else{break};let Ok(server)=tokio::net::TcpStream::connect((host.as_str(),port)).await else{break};let count=count.clone();let gate=gate.clone();children.spawn(async move{let(mut cr,mut cw)=client.into_split();let(mut sr,mut sw)=server.into_split();let backend=async{loop{let kind=sr.read_u8().await?;let length=sr.read_u32().await?;if !(4..=16*1024*1024).contains(&length){return Err(std::io::Error::other("invalid owned PG frame"));}let mut payload=vec![0;(length-4)as usize];sr.read_exact(&mut payload).await?;if kind==b'C'&&payload==b"ROLLBACK\0"&&count.fetch_update(Ordering::SeqCst,Ordering::SeqCst,|v|v.checked_sub(1))==Ok(1){let hold=gate.lock().await.take();let Some((arrived,release))=hold else{return Ok::<(),std::io::Error>(())};arrived.send(()).map_err(|()|std::io::Error::other("owned ACK controller closed"))?;tokio::time::timeout(Duration::from_secs(8),release).await.map_err(|_|std::io::Error::other("owned ACK timeout"))?.map_err(|_|std::io::Error::other("owned ACK release closed"))?;}cw.write_u8(kind).await?;cw.write_u32(length).await?;cw.write_all(&payload).await?;}};tokio::select!{_=tokio::io::copy(&mut cr,&mut sw)=>{},_=backend=>{}}});}}
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Ok(Self {
            port: local,
            remaining,
            control,
            stop: Some(stop),
            task: Some(task),
        })
    }
    async fn hold(&self) -> Result<AckHold> {
        let (a, arrived) = oneshot::channel();
        let (release, r) = oneshot::channel();
        let mut g = self.control.lock().await;
        check(g.is_none(), "ACK controller already armed")?;
        *g = Some((a, r));
        self.remaining.store(1, Ordering::SeqCst);
        Ok(AckHold { arrived, release })
    }
    fn drop_next(&self) {
        self.remaining.store(1, Ordering::SeqCst);
    }
    async fn finish(mut self) -> Result {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.task.take() {
            t.await.map_err(|e| e.to_string())?;
        }
        eprintln!(
            "THREAD_HISTORY_ACK_PROXY original_acceptor_joined=true original_children_reaped=true"
        );
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
async fn owned_proxy<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Fixture, AckProxy) -> Fut,
    Fut: Future<Output = Result>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |mut config| async move {
        let proxy = AckProxy::start(config.host.clone(), config.port).await?;
        config.host = "127.0.0.1".into();
        config.port = proxy.port;
        body(Fixture::new(config, 7).await?, proxy).await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_waits_recheck_current_facts_and_use_positive_nowait() {
    owned_proxy("history09",|f,proxy|async move{
 let a=f.auth(A,1).await?;let req=f.begin(&a,901).await?;f.settle(req.command.run_id.as_str()).await?;let j=req.command.thread_id.as_str().to_owned();
 let mut writer=f.pool.get().await.map_err(|e|e.to_string())?;let pid:i32=writer.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;let tx=writer.transaction().await.map_err(|e|e.to_string())?;tx.execute("UPDATE public.users SET auth_generation=auth_generation WHERE id=$1",&[&A]).await.map_err(|e|e.to_string())?;
 let authority=f.authority.clone();let aa=a.clone();let jj=j.clone();let task=tokio::spawn(async move{authority.observe_management_before(&aa,&jj,deadline()).await});let observed=wait_actor_lock(&f.pool,pid).await?;tx.execute("UPDATE public.users SET auth_generation=8 WHERE id=$1",&[&A]).await.map_err(|e|e.to_string())?;tx.commit().await.map_err(|e|e.to_string())?;refused(task.await.map_err(|e|e.to_string())?)?;drop(writer);eprintln!("THREAD_HISTORY_OBSERVATION id=H09 actual_actor_wait_pid={observed} writer_pid={pid} original_commit_ack=true fresh_joint_refused=true");f.sql("UPDATE public.users SET auth_generation=7 WHERE id='history-a'").await?;
 let mut writer=f.pool.get().await.map_err(|e|e.to_string())?;let tx=writer.transaction().await.map_err(|e|e.to_string())?;tx.execute("UPDATE public.threads SET title=title WHERE thread_id=$1",&[&j]).await.map_err(|e|e.to_string())?;unavailable(f.authority.observe_management_before(&a,&j,deadline()).await)?;tx.rollback().await.map_err(|e|e.to_string())?;drop(writer);f.eligible(&a,&j).await?;
 let(r1,r2)=tokio::join!(f.authority.observe_management_before(&a,&j,deadline()),f.authority.observe_management_before(&a,&j,deadline()));check(r1.is_ok()&&r2.is_ok(),"parallel valid original observations failed")?;
 let mut hold=proxy.hold().await?;let authority=f.authority.clone();let aa=a.clone();let jj=j.clone();let task=tokio::spawn(async move{authority.observe_management_before(&aa,&jj,deadline()).await});hold.wait().await?;check(!task.is_finished(),"success escaped before real original ROLLBACK ACK")?;hold.release()?;check(task.await.map_err(|e|e.to_string())?.is_ok(),"released original ACK did not permit bounded snapshot")?;
 let mut writer=f.pool.get().await.map_err(|e|e.to_string())?;let pid:i32=writer.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;let tx=writer.transaction().await.map_err(|e|e.to_string())?;tx.execute("UPDATE public.users SET auth_generation=auth_generation WHERE id=$1",&[&A]).await.map_err(|e|e.to_string())?;let original=Instant::now()+Duration::from_secs(2);let authority=f.authority.clone();let aa=a.clone();let jj=j.clone();let task=tokio::spawn(async move{authority.observe_management_before(&aa,&jj,original).await});let _=wait_actor_lock(&f.pool,pid).await?;check(!task.is_finished(),"original observer ended before the real actor lock wait")?;unavailable(tokio::time::timeout_at(tokio::time::Instant::from_std(original+Duration::from_secs(1)),task).await.map_err(|_|"original deadline renewed during the actor lock wait".to_string())?.map_err(|e|e.to_string())?)?;check(Instant::now()<=original+Duration::from_secs(1),"original deadline renewed during the actor lock wait")?;tx.rollback().await.map_err(|e|e.to_string())?;drop(writer);f.eligible(&a,&j).await?;
 f.finish().await?;proxy.finish().await
}).await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_real_server_session_epoch_lifetime_and_new_request_recover() {
    owned_proxy("history10",|f,proxy|async move{
 let old=f.auth(A,1).await?;let req=f.begin(&old,1001).await?;f.settle(req.command.run_id.as_str()).await?;let j=req.command.thread_id.as_str().to_owned();f.eligible(&old,&j).await?;
 // Withdraw the real Session while the original observer is blocked before its fresh joint.
 let mut writer=f.pool.get().await.map_err(|e|e.to_string())?;let pid:i32=writer.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;let tx=writer.transaction().await.map_err(|e|e.to_string())?;tx.execute("UPDATE public.users SET auth_generation=auth_generation WHERE id=$1",&[&A]).await.map_err(|e|e.to_string())?;
 let authority=f.authority.clone();let auth=old.clone();let jj=j.clone();let task=tokio::spawn(async move{authority.observe_management_before(&auth,&jj,deadline()).await});let blocked=wait_actor_lock(&f.pool,pid).await?;tx.batch_execute("DELETE FROM public.sessions WHERE id='history-a-session-1'").await.map_err(|e|e.to_string())?;tx.commit().await.map_err(|e|e.to_string())?;refused(task.await.map_err(|e|e.to_string())?)?;drop(writer);eprintln!("THREAD_HISTORY_OBSERVATION id=H10 actual_old_session_withdrawal=true original_actor_wait_pid={blocked} original_writer_commit_ack=true");
 let next=f.auth(A,2).await?;f.eligible(&next,&j).await?;let before=f.facts().await?;f.eligible(&next,&j).await?;check(before==f.facts().await?,"observer idle-touched Session")?;
 f.sql("UPDATE public.sessions SET created_at=created_at+interval '1 microsecond',updated_at=updated_at+interval '1 microsecond' WHERE id='history-a-session-2'").await?;refused(f.authority.observe_management_before(&next,&j,deadline()).await)?;let current=f.auth(A,2).await?;f.eligible(&current,&j).await?;
 f.sql("UPDATE public.sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id='history-a-session-2'").await?;check(f.authority.observe_management_before(&current,&j,deadline()).await.is_err(),"actual expired Session accepted")?;f.sql("UPDATE public.sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id='history-a-session-2'").await?;let valid=f.auth(A,2).await?;f.eligible(&valid,&j).await?;
 let mut hold=proxy.hold().await?;let authority=f.authority.clone();let auth=valid.clone();let jj=j.clone();let original=Instant::now()+Duration::from_secs(2);let task=tokio::spawn(async move{authority.observe_management_before(&auth,&jj,original).await});hold.wait().await?;check(Instant::now()<original,"original ROLLBACK reached the proxy after the original deadline")?;check(!task.is_finished(),"original observer ended while the real ROLLBACK ACK was held")?;tokio::time::sleep_until(tokio::time::Instant::from_std(original+Duration::from_millis(200))).await;check(task.await.map_err(|e|e.to_string())?.is_err(),"late original ACK accepted")?;check(Instant::now()<=original+Duration::from_secs(1),"original deadline renewed while the ROLLBACK ACK was held")?;let _=hold.release();f.eligible(&valid,&j).await?;
 proxy.drop_next();check(matches!(f.authority.observe_management_before(&valid,&j,deadline()).await,Err(Error::RollbackUnproven|Error::DeadlineExceeded|Error::Unavailable)),"missing original rollback ACK not classified")?;f.eligible(&valid,&j).await?;
 // Hold the actual original ACK, close its real producer, then check the synchronous tail.
 let mut hold=proxy.hold().await?;let authority=f.authority.clone();let auth=valid.clone();let jj=j.clone();let task=tokio::spawn(async move{authority.observe_management_before(&auth,&jj,deadline()).await});hold.wait().await?;f.resolver.close_request_bindings();check(!task.is_finished(),"old owner escaped before original rollback ACK")?;hold.release()?;host_refused(task.await.map_err(|e|e.to_string())?)?;
 let fresh_authority=Arc::new(PostgresThreadHistoryAuthority::new(f.pool.clone(),DeploymentId::new(DEP),TenantId::new(TENANT)).map_err(|e|format!("{e:?}"))?);fresh_authority.enroll_original_registry(&f.registry).map_err(|e|format!("{e:?}"))?;let fresh_resolver=PostgresSessionAuthResolver::new(f.pool.clone(),SESSION_KEY,openbot_infra::auth::config::default_session_lifetime(),DeploymentId::new(DEP),TenantId::new(TENANT)).map_err(|e|e.to_string())?;fresh_resolver.install_thread_history_authority(&fresh_authority).map_err(|e|format!("{e:?}"))?;
 let fresh_auth=fresh_resolver.resolve(&http::Request::builder().uri("/owned-history-new-producer").header("cookie",format!("openbot_session=owned-history-cookie-{A}-02")).body(()).map_err(|e|e.to_string())?.into_parts().0).await.map_err(|e|e.to_string())?;check(fresh_authority.observe_management_before(&fresh_auth,&j,deadline()).await.is_ok(),"closed old owner permanently poisoned genuine new producer")?;fresh_resolver.close_request_bindings();drop(fresh_auth);drop(fresh_resolver);drop(fresh_authority);f.finish().await?;proxy.finish().await
}).await;
}
#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_management_real_single_user_original_owner_and_pool_are_required() {
    owned("history11",0,|f|async move{
 let principal=openbot_infra::auth::single_user::load_single_user_principal(&f.pool,DeploymentId::new(DEP),TenantId::new(TENANT)).await.map_err(|e|e.to_string())?;let resolver=SingleUserAuthResolver::from_verified_principal(principal,openbot_infra::auth::config::default_session_lifetime());let authority=Arc::new(PostgresThreadHistoryAuthority::new(f.pool.clone(),DeploymentId::new(DEP),TenantId::new(TENANT)).map_err(|e|format!("{e:?}"))?);authority.enroll_original_registry(&f.registry).map_err(|e|format!("{e:?}"))?;resolver.install_thread_history_authority(&authority,&f.pool).map_err(|e|format!("{e:?}"))?;
 let auth=resolver.resolve(&http::Request::builder().uri("/owned-history-single").body(()).map_err(|e|e.to_string())?.into_parts().0).await.map_err(|e|e.to_string())?;let req=f.begin(&auth,1101).await?;f.settle(req.command.run_id.as_str()).await?;let j=req.command.thread_id.as_str();check(authority.observe_management_before(&auth,j,deadline()).await.is_ok(),"real SingleUser owner failed")?;
 f.sql("UPDATE public.users SET auth_generation=NULL WHERE id='dev-local-user'").await?;check(authority.observe_management_before(&auth,j,deadline()).await.is_ok(),"management NULL0 rejected genuine nonnull0-minted SingleUser Host")?;f.sql("UPDATE public.users SET auth_generation=0 WHERE id='dev-local-user'").await?;
 check(resolver.install_thread_history_authority(&authority,&f.pool).is_err(),"duplicate enrollment succeeded")?;
 let synthetic=SingleUserAuthResolver::new(DeploymentId::new(DEP),TenantId::new(TENANT),ActorId::new("dev-local-user"),openbot_infra::auth::config::default_session_lifetime());check(synthetic.install_thread_history_authority(&authority,&f.pool).is_err(),"context-only SingleUser borrowed actual owner")?;
 let other=pool::connect(&f.config).await.map_err(|e|e.to_string())?;let principal=openbot_infra::auth::single_user::load_single_user_principal(&f.pool,DeploymentId::new(DEP),TenantId::new(TENANT)).await.map_err(|e|e.to_string())?;let different=SingleUserAuthResolver::from_verified_principal(principal,openbot_infra::auth::config::default_session_lifetime());check(different.install_thread_history_authority(&authority,&other).is_err(),"same DSN different Pool accepted original principal")?;different.close_request_bindings();close_pool(other).await?;
 for(bad,restore)in[("UPDATE public.users SET email='other@example.test' WHERE id='dev-local-user'","UPDATE public.users SET email='dev@openbot.local' WHERE id='dev-local-user'"),("DELETE FROM public.user_roles WHERE user_id='dev-local-user'","INSERT INTO public.user_roles(user_id,role) VALUES('dev-local-user','admin')"),("INSERT INTO public.revoked_access(email,revoked_by) VALUES('dev@openbot.local','history-admin')","DELETE FROM public.revoked_access WHERE email='dev@openbot.local'")]{f.sql(bad).await?;check(authority.observe_management_before(&auth,j,deadline()).await.is_err(),"stale canonical SingleUser grant accepted")?;f.sql(restore).await?;check(authority.observe_management_before(&auth,j,deadline()).await.is_ok(),"canonical restoration permanently poisoned new observation")?;}
 resolver.close_request_bindings();host_refused(authority.observe_management_before(&auth,j,deadline()).await)?;drop(resolver);drop(authority);f.finish().await
}).await;
}
