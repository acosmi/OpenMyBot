//! Finite original reconciliation contracts: real run, policy, capability, memory and journal
//! producers, then the shared Application's authenticated HTTP and bound Desktop reads.
//! The injected post-effect journal Unavailable is not a physical COMMIT-ACK-loss experiment.
//! It leaves the persisted attempt executing/null and the real memory receipt intact; the
//! production RunRuntime writes the original ReconciliationRequired terminal and occupancy.

mod harness {
    include!("../../../../test-support/postgres_harness.rs");
}

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{
        HeaderMap, Request, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, SET_COOKIE},
    },
};
use openbot_application::ToolCallSequence as _;
use openbot_application::{
    CommittedMemoryEffect, MemoryAdministrationError, RememberToolMemory,
    RememberToolMemoryRequest, RunFailureCode, RunTerminal, ToolDecisionDraft, ToolJournal,
    ToolOutcomeDraft, ToolPortError, ToolRefusalDraft, invoke_tool,
    provider::{RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError},
};
use openbot_contracts::{
    auth::{AuthContext, Role},
    command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor},
    error::AppError,
    ids::{BotId, CapabilityId, DeploymentId, RunId, TenantId, ToolCallId, thread::ThreadIdentity},
    reconciliation::{
        MAX_RUN_RECONCILIATION_RESPONSE_BYTES, RunEffectReceipt, RunEffectReceiptFact,
        RunEffectReceiptsSnapshot, RunReconciliationAttempt, RunReconciliationAttemptStatus,
        RunReconciliationCommitState, RunReconciliationCursor, RunReconciliationSnapshot,
        RunReconciliationStatus,
    },
    tool::{ToolCommitState, ToolInvocation},
};
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_domain::{
    identity::session::{SessionHashKey, SessionToken, SessionTokenHash},
    policy::{ActionPolicy, PolicyMode},
    remote_callback::RemoteRunAssertionSigner,
    tool::{commit::CommitState, pipeline::DurableDecisionReceipt},
    vault::{KeyVersion, SecretBytes, WrappingKey},
};
use openbot_infra::{
    agent_tools::{PostgresAgentToolSequence, PostgresBuiltInToolControlPlane},
    application_assembly::{
        ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
        assemble_postgres_application,
    },
    auth::config::default_session_lifetime,
    db::{
        baseline, native,
        pool::{self, DatabaseConfig, DatabasePool},
    },
    memory_admin::PostgresMemoryAdministration,
    policy::PolicyStore,
    repo::tools::PostgresToolJournal,
    ui_preferences::PostgresUiPreferenceAdministration,
    vault::CredentialRecordVault,
};
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver,
    auth::ResolvedAuth,
    config::{EnvMap, ServerConfig},
    http::{ServerBuilder, router},
};
use serde_json::{Value, json};
use std::{
    any::Any,
    future::Future,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const ACTORS: [&str; 2] = ["owned-reconcarrier-a", "owned-reconcarrier-b"];
const TOKENS: [&str; 2] = [
    "OWNED_RECONCARRIER_SESSION_A",
    "OWNED_RECONCARRIER_SESSION_B",
];
const SESSION_KEY: &[u8] = b"owned-reconcarrier-session-hash-key-at-least-32-bytes";
const AUDIT_KEY: &[u8] = b"owned-reconcarrier-real-producer-audit-key-024";
const CONTENT: &str = "PRIVATE_RECONCARRIER_REMEMBER_CONTENT";
const PRIVATE_TAG: &str = "PRIVATE_RECONCARRIER_TAG";
const BOT: &str = "owned-reconcarrier-bot";

#[derive(Clone, Copy)]
pub(crate) enum Case {
    JournalFacts,
    RememberReceipt,
    Pagination,
    CurrentAuthority,
}
impl Case {
    fn id(self) -> &'static str {
        match self {
            Self::JournalFacts => "C9.producer-journal-074-http-desktop-facts",
            Self::RememberReceipt => "C9.producer-remember-075-http-desktop-receipt",
            Self::Pagination => "C9.producer-receipt-pagination-readonly",
            Self::CurrentAuthority => "C9.producer-current-authority-owner-isolation",
        }
    }
}
fn require(ok: bool, stage: &'static str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(stage.to_owned()) }
}

type Panic = Box<dyn Any + Send>;

// Preserve the original panic payload. The host owners and temporary database are closed before
// resume_unwind; a panic never skips cleanup or produces a successful evidence line.
async fn caught<F: Future>(future: F) -> Result<F::Output, Panic> {
    let mut future = Box::pin(future);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(value) => value.map(Ok),
            Err(panic) => Poll::Ready(Err(panic)),
        }
    })
    .await
}

pub(crate) async fn run(case: Case) {
    assert_eq!(
        std::env::var("OPENBOT_RECONCILIATION_CARRIER_OWNED_PG").as_deref(),
        Ok("1"),
        "owned_pg_marker_required"
    );
    let admin = harness::admin_config("reconciliationcarrier");
    assert!(
        admin.user == "v7_comp024_admin"
            && admin.dbname == "postgres"
            && matches!(admin.host.as_str(), "127.0.0.1" | "::1")
            && admin.port > 1024,
        "owned_loopback_admin_required"
    );
    let head =
        std::env::var("OPENBOT_RECONCILIATION_CARRIER_SOURCE_HEAD").expect("source_head_required");
    let spec =
        std::env::var("OPENBOT_RECONCILIATION_CARRIER_SPEC_SHA").expect("spec_digest_required");
    assert!(
        head.len() == 40
            && spec.len() == 64
            && head
                .bytes()
                .chain(spec.bytes())
                .all(|b| b.is_ascii_hexdigit()),
        "source_metadata_shape"
    );
    let original_panic = Arc::new(Mutex::new(None::<Panic>));
    let saved_panic = original_panic.clone();
    let completed = caught(harness::with_temp_database(
        &admin,
        "reconciliationcarrier",
        |config| async move {
            let pool = pool::connect(&config.clone().with_max_pool_size(8))
                .await
                .map_err(|_| "owned_pool_connect")?;
            let mut host = Host {
                pool,
                assets: std::env::temp_dir()
                    .join(format!("openbot-reconcarrier-{}", Uuid::new_v4())),
                assembly: None,
                auth: None,
                transport: None,
                protocol: None,
                router: None,
                identities: Vec::new(),
                wire: Arc::new(AtomicUsize::new(0)),
            };
            let outcome = caught(async {
                host.prepare(config).await?;
                host.exercise(case).await
            })
            .await;
            let cleanup = caught(host.finish()).await;
            host.pool.close();
            match outcome {
                Err(panic) => {
                    *saved_panic.lock().map_err(|_| "panic_owner_lock")? = Some(panic);
                    // Still surface cleanup failure after the database harness performs its DROP.
                    match cleanup {
                        Ok(result) => result,
                        Err(_) => Err("cleanup_panic_after_original_failure".to_owned()),
                    }
                }
                Ok(result) => match cleanup {
                    Ok(closed) => {
                        closed?;
                        result
                    }
                    Err(panic) => {
                        *saved_panic.lock().map_err(|_| "panic_owner_lock")? = Some(panic);
                        Ok(())
                    }
                },
            }
        },
    ))
    .await;
    if let Some(panic) = original_panic.lock().expect("panic_owner_lock").take() {
        std::panic::resume_unwind(panic);
    }
    if let Err(panic) = completed {
        std::panic::resume_unwind(panic);
    }
    println!(
        "C9_EVIDENCE {}",
        json!({"caseId":case.id(),"sourceHead":head,"specSha256":spec,"realProducer":true,"sharedApplication":true,"positiveChecksPassed":true,"negativeChecksPassed":true,"ownedResourcesClosed":true})
    );
}

struct ClosedRemote(Arc<AtomicUsize>);
#[async_trait]
impl RemoteAguiTransport for ClosedRemote {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(RemoteAguiTransportError::Unavailable)
    }
}

struct CapturingMemory {
    inner: PostgresMemoryAdministration,
    request: Mutex<Option<RememberToolMemoryRequest>>,
    committed: Mutex<Option<CommittedMemoryEffect>>,
}
#[async_trait]
impl RememberToolMemory for CapturingMemory {
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> Result<CommittedMemoryEffect, MemoryAdministrationError> {
        *self.request.lock().unwrap() = Some(request.clone());
        let committed = self.inner.remember_from_tool(request).await?;
        *self.committed.lock().unwrap() = Some(committed.clone());
        Ok(committed)
    }
}

struct OutcomeUnavailableJournal {
    inner: PostgresToolJournal,
    inject_after_effect: bool,
    outcome: Mutex<Option<ToolOutcomeDraft>>,
}
#[async_trait]
impl ToolJournal for OutcomeUnavailableJournal {
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        self.inner.record_refusal(draft).await
    }
    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        self.inner.record_decision(draft).await
    }
    async fn attach_capability(
        &self,
        call: &ToolCallId,
        capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        self.inner.attach_capability(call, capability).await
    }
    async fn record_outcome(&self, draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        *self.outcome.lock().unwrap() = Some(draft.clone());
        if self.inject_after_effect {
            // Explicit, pre-write test injection after the real memory transaction acknowledged.
            // No SQL outcome is invented; this is not physical ACK loss or a vendor receipt.
            Err(ToolPortError::Unavailable {
                dependency: "owned_injected_post_effect_journal_unavailable",
            })
        } else {
            self.inner.record_outcome(draft).await
        }
    }
}

struct ProducedCall {
    request: RememberToolMemoryRequest,
    effect: CommittedMemoryEffect,
    journal_written: bool,
}
struct ProducedRun {
    command: BeginThreadRun,
    terminal_sequence: u64,
    calls: Vec<ProducedCall>,
    attempts: Vec<RunReconciliationAttempt>,
    receipts: Vec<RunEffectReceipt>,
}
#[derive(Clone, Copy)]
enum ReadKind {
    Attempts,
    Receipts,
}
impl ReadKind {
    fn command(
        self,
        run: &ProducedRun,
        after: Option<RunReconciliationCursor>,
        limit: Option<u32>,
    ) -> AppCommand {
        let thread_id = run.command.thread_id.clone();
        let run_id = run.command.run_id.clone();
        match self {
            Self::Attempts => AppCommand::GetRunReconciliation {
                thread_id,
                run_id,
                after,
                limit,
            },
            Self::Receipts => AppCommand::GetRunEffectReceipts {
                thread_id,
                run_id,
                after,
                limit,
            },
        }
    }
    fn path(self, run: &ProducedRun, query: &str) -> String {
        format!(
            "/api/threads/{}/runs/{}/reconciliation{}{}",
            run.command.thread_id.as_str(),
            encode_segment(run.command.run_id.as_str()),
            if matches!(self, Self::Receipts) {
                "/receipts"
            } else {
                ""
            },
            query
        )
    }
}

struct Host {
    pool: DatabasePool,
    assets: PathBuf,
    assembly: Option<PostgresApplicationAssembly>,
    auth: Option<Arc<PostgresSessionAuthResolver>>,
    transport: Option<Arc<InProcessTransport>>,
    protocol: Option<Arc<DesktopTauriProtocol>>,
    router: Option<Router>,
    identities: Vec<ResolvedAuth>,
    wire: Arc<AtomicUsize>,
}

impl Host {
    async fn prepare(&mut self, config: DatabaseConfig) -> Result<(), String> {
        let mut client = self.pool.get().await.map_err(|_| "migration_connection")?;
        baseline::apply(&client)
            .await
            .map_err(|_| "baseline_migration")?;
        native::apply(&mut client)
            .await
            .map_err(|_| "native_migration")?;
        let now = OffsetDateTime::now_utc();
        let tx = client.transaction().await.map_err(|_| "owned_seed_begin")?;
        for (index, (actor, token)) in ACTORS.iter().zip(TOKENS).enumerate() {
            let hash = SessionTokenHash::compute(
                SessionToken::new(token.as_bytes()),
                SessionHashKey::new(SESSION_KEY),
            )
            .to_column_value();
            tx.execute(
                "INSERT INTO public.users(id,email,name,auth_generation) VALUES($1,$2,$1,0)",
                &[actor, &format!("{actor}@owned.test")],
            )
            .await
            .map_err(|_| "owned_user_seed")?;
            tx.execute(
                "INSERT INTO public.user_roles(user_id,role) VALUES($1,$2::text::public.role)",
                &[actor, &if index == 0 { "user" } else { "admin" }],
            )
            .await
            .map_err(|_| "owned_role_seed")?;
            tx.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)", &[&Uuid::new_v4().to_string(), actor, &hash, &(now + time::Duration::hours(1)), &now]).await.map_err(|_| "owned_session_seed")?;
        }
        tx.execute("INSERT INTO public.agents(id,name,type,configuration) VALUES($1,'Owned reconciliation carrier','built_in','{}')", &[&BOT]).await.map_err(|_| "owned_bot_seed")?;
        tx.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES($1,NULL,'Owned producer','synthetic fixture','owned-recon','public')", &[&BOT]).await.map_err(|_| "owned_profile_seed")?;
        tx.commit().await.map_err(|_| "owned_seed_commit")?;
        drop(client);
        let deployment = DeploymentId::new("reconcarrier-deployment");
        let tenant = TenantId::new("reconcarrier-tenant");
        self.auth = Some(Arc::new(
            PostgresSessionAuthResolver::new(
                self.pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment.clone(),
                tenant.clone(),
            )
            .map_err(|_| "production_session_resolver")?,
        ));
        let auth = self.auth.as_ref().ok_or("resolver_missing")?;
        for token in TOKENS {
            let resolved = auth
                .resolve_with_assurance(&parts(token)?)
                .await
                .map_err(|_| "production_session_resolve")?;
            resolved
                .context()
                .request_binding()
                .ok_or("session_binding_missing")?
                .verify_current(resolved.context())
                .await
                .map_err(|_| "current_session_binding")?;
            self.identities.push(resolved);
        }
        require(
            self.identities[0].context().has_role(Role::User)
                && self.identities[1].context().has_role(Role::Admin),
            "owned_real_user_admin_roles",
        )?;
        let policy = PolicyStore::postgres(self.pool.clone(), None);
        policy
            .set(
                ActionPolicy {
                    mode: PolicyMode::Enforce,
                    deny: Vec::new(),
                    allow: vec!["tool.name == \"remember\"".to_owned()],
                },
                Some(ACTORS[0]),
            )
            .await
            .map_err(|_| "production_remember_policy")?;
        policy.load().await.map_err(|_| "production_policy_load")?;
        self.assembly = Some(
            assemble_postgres_application(PostgresApplicationAssemblyInput {
                pool: self.pool.clone(),
                listener_database: config.into(),
                deployment: deployment.clone(),
                tenant: tenant.clone(),
                single_user: false,
                admin_floor: None,
                model: "unused-reconcarrier-model".to_owned(),
                credential_key_id: "unused-reconcarrier-key".to_owned(),
                credential_vault: CredentialRecordVault::single_key(
                    tenant.clone(),
                    KeyVersion::new(1),
                    WrappingKey::from_bytes(vec![0xb1; 32]).map_err(|_| "owned_vault_key")?,
                ),
                audit_key: SecretBytes::new(AUDIT_KEY.to_vec()),
                remote_assertions: Arc::new(
                    RemoteRunAssertionSigner::new(vec![0xb3; 32])
                        .map_err(|_| "owned_assertion_signer")?,
                ),
                mcp_oauth_state_key: SecretBytes::new(vec![0xb4; 32]),
                policy_store: policy,
                ui_preferences: Arc::new(
                    PostgresUiPreferenceAdministration::new(
                        self.pool.clone(),
                        deployment,
                        tenant,
                        SecretBytes::new(AUDIT_KEY.to_vec()),
                    )
                    .map_err(|_| "postgres_preferences")?,
                ),
                screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
                artifacts: None,
                runtime_capabilities: None,
                remote_agent_probe: Arc::new(ClosedRemote(self.wire.clone())),
                managed_slot_available: false,
                channel_routing_provider: ChannelRoutingProviderInput {
                    endpoint: Url::parse("http://127.0.0.1:9/v1/chat/completions")
                        .map_err(|_| "unused_endpoint")?,
                    environment_api_key: None,
                    egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
                    allow_http: true,
                },
                stall_timeout: Some(Duration::from_secs(2)),
                oauth_public_url: None,
                app_url: None,
            })
            .await
            .map_err(|_| "production_application_assembly")?,
        );
        let application = self
            .assembly
            .as_ref()
            .ok_or("assembly_missing")?
            .application
            .clone();
        self.transport = Some(Arc::new(InProcessTransport::new(application.clone())));
        let transport = self.transport.as_ref().ok_or("transport_missing")?;
        require(
            Arc::ptr_eq(&application, transport.service()),
            "typed_shared_application_allocation",
        )?;
        let server = ServerBuilder::new(application.clone(), auth.clone())
            .with_transport_policy(
                ServerConfig::from_env_map(&EnvMap::new())
                    .map_err(|_| "transport_policy")?
                    .transport_policy(true),
            )
            .build();
        require(
            core::ptr::addr_eq(Arc::as_ptr(&application), server.application()),
            "http_shared_application_allocation",
        )?;
        self.router = Some(router(server)); // In-process Router: no HTTP listener or server task.
        std::fs::create_dir(&self.assets).map_err(|_| "owned_assets_create")?;
        std::fs::write(self.assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|_| "owned_index_write")?;
        std::fs::write(self.assets.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|_| "owned_bootstrap_write")?;
        self.protocol = Some(Arc::new(
            DesktopTauriProtocol::open(&self.assets, transport.clone())
                .map_err(|_| "production_desktop_protocol")?,
        ));
        for (label, identity) in ["main", "other"].into_iter().zip(&self.identities) {
            self.protocol
                .as_ref()
                .ok_or("protocol_missing")?
                .bind_window(label, identity.context().clone(), None)
                .map_err(|_| "verified_window_bind")?;
        }
        snapshot(&self.pool).await?;
        Ok(())
    }

    async fn produce(&self, actor: usize, count: usize, tag: &str) -> Result<ProducedRun, String> {
        let identity = self.identities.get(actor).ok_or("producer_identity")?;
        let auth = identity.context();
        let assembly = self.assembly.as_ref().ok_or("assembly_missing")?;
        let transport = self.transport.as_ref().ok_or("transport_missing")?;
        let command =
            BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(auth.deployment())
                    .mint_from_entropy(if actor == 0 { [24; 16] } else { [25; 16] }),
                run_id: RunId::new(format!("producer/{tag}%原始")),
                bot_id: BotId::new(BOT),
                anchor: ThreadRunAnchor::DirectBot,
                message: "PRIVATE_RECONCARRIER_ORIGINAL_USER_MESSAGE".to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            };
        // A preceding real completed run makes thread-global and run-local event coordinates
        // unequal. The Unknown query must return the original terminal run_events.seq.
        let mut prior = command.clone();
        prior.run_id = RunId::new(format!("producer/{tag}-prior-completed"));
        let AppReply::ThreadRunStarted(prior_started) = transport
            .execute(auth.clone(), AppCommand::BeginThreadRun(prior.clone()))
            .await
            .map_err(|_| "production_prior_begin")?
        else {
            return Err("prior_begin_reply_variant".to_owned());
        };
        require(
            prior_started.run_id == prior.run_id && !prior_started.replayed,
            "real_prior_begin",
        )?;
        let prior_claim = assembly
            .run_runtime
            .claim_dispatch()
            .await
            .map_err(|_| "prior_dispatch_claim")?
            .ok_or("prior_dispatch_missing")?;
        let prior_lease = assembly
            .run_runtime
            .acknowledge_dispatch(&prior_claim)
            .await
            .map_err(|_| "prior_dispatch_ack")?;
        require(prior_lease.run_id() == &prior.run_id, "real_prior_lease")?;
        assembly
            .run_runtime
            .finish_run(
                &prior_lease,
                prior_lease.next_event_sequence(),
                RunTerminal::Completed,
            )
            .await
            .map_err(|_| "production_prior_completed_terminal")?;
        let AppReply::ThreadRunStarted(started) = transport
            .execute(auth.clone(), AppCommand::BeginThreadRun(command.clone()))
            .await
            .map_err(|_| "production_begin_run")?
        else {
            return Err("begin_run_reply_variant".to_owned());
        };
        require(
            started.run_id == command.run_id
                && started.thread_id == command.thread_id
                && !started.replayed,
            "real_begin_receipt",
        )?;
        let claim = assembly
            .run_runtime
            .claim_dispatch()
            .await
            .map_err(|_| "production_dispatch_claim")?
            .ok_or("production_dispatch_missing")?;
        let lease = assembly
            .run_runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|_| "production_dispatch_ack")?;
        require(
            lease.run_id() == &command.run_id
                && lease.thread_id() == &command.thread_id
                && lease.actor_id() == auth.actor(),
            "real_dispatch_lease_binding",
        )?;
        let policy = PolicyStore::postgres(self.pool.clone(), None);
        policy.load().await.map_err(|_| "producer_policy_load")?;
        let sequence = PostgresAgentToolSequence::new(self.pool.clone());
        let mut calls = Vec::new();
        for index in 0..count {
            let call_seq = sequence
                .next(&command.run_id)
                .await
                .map_err(|_| "production_call_sequence")?;
            require(call_seq == index as u64, "real_call_sequence_order")?;
            let memory = Arc::new(CapturingMemory {
                inner: PostgresMemoryAdministration::new(self.pool.clone())
                    .with_effect_audit_key(AUDIT_KEY.to_vec())
                    .map_err(|_| "producer_memory_adapter")?,
                request: Mutex::new(None),
                committed: Mutex::new(None),
            });
            let control = PostgresBuiltInToolControlPlane::new(
                self.pool.clone(),
                auth.deployment().clone(),
                auth.tenant().clone(),
                policy.clone(),
                memory.clone(),
            );
            let inject_after_effect = index + 1 == count;
            let journal = OutcomeUnavailableJournal {
                inner: PostgresToolJournal::new(self.pool.clone(), AUDIT_KEY.to_vec())
                    .map_err(|_| "producer_journal_adapter")?,
                inject_after_effect,
                outcome: Mutex::new(None),
            };
            let invocation = ToolInvocation {
                call_id: ToolCallId::new(format!("producer-{tag}-call-{index}")),
                run_id: command.run_id.clone(),
                bot_id: command.bot_id.clone(),
                call_seq,
                tool_name: "remember".to_owned(),
                arguments: json!({"memoryKind":"preference","scope":"user","content":format!("{CONTENT}-{index}"),"tags":[PRIVATE_TAG],"sensitivity":"normal"}),
            };
            let result = invoke_tool(&control, &journal, auth, invocation).await;
            if inject_after_effect {
                require(
                    matches!(
                        result,
                        Err(AppError::ReconciliationRequired { accepted: false })
                    ),
                    "injected_journal_unavailable_preserves_unknown",
                )?;
            } else {
                require(
                    matches!(result, Ok(ref value) if value.commit_state == ToolCommitState::Committed),
                    "real_journal_committed_result",
                )?;
            }
            let request = memory
                .request
                .lock()
                .map_err(|_| "captured_request_lock")?
                .take()
                .ok_or("real_producer_request_missing")?;
            let effect = memory
                .committed
                .lock()
                .map_err(|_| "captured_effect_lock")?
                .take()
                .ok_or("real_memory_commit_missing")?;
            let outcome = journal
                .outcome
                .lock()
                .map_err(|_| "captured_outcome_lock")?
                .take()
                .ok_or("real_outcome_missing")?;
            require(
                outcome.outcome.commit_state == CommitState::Committed
                    && outcome.capability_id == *request.capability()
                    && request.actor() == auth.actor()
                    && request.run() == &command.run_id
                    && request.thread() == &command.thread_id,
                "real_effect_outcome_and_authoritative_scope",
            )?;
            calls.push(ProducedCall {
                request,
                effect,
                journal_written: !inject_after_effect,
            });
        }
        let terminal = assembly
            .run_runtime
            .finish_run(
                &lease,
                lease.next_event_sequence(),
                RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown),
            )
            .await
            .map_err(|_| "production_reconciliation_terminal")?;
        require(
            !terminal.replayed && terminal.run_event_sequence != terminal.thread_event_sequence,
            "terminal_real_first_write_distinct_event_coordinates",
        )?;
        let mut run = ProducedRun {
            command,
            terminal_sequence: terminal.run_event_sequence,
            calls,
            attempts: Vec::new(),
            receipts: Vec::new(),
        };
        run.verify_producer(&self.pool, auth).await?;
        Ok(run)
    }

    async fn exercise(&mut self, case: Case) -> Result<(), String> {
        let count = match case {
            Case::JournalFacts => 2,
            Case::Pagination => 3,
            _ => 1,
        };
        let tag = match case {
            Case::JournalFacts => "074",
            Case::RememberReceipt => "075",
            Case::Pagination => "page",
            Case::CurrentAuthority => "owner-a",
        };
        let run = self.produce(0, count, tag).await?;
        let before = snapshot(&self.pool).await?;
        for kind in [ReadKind::Attempts, ReadKind::Receipts] {
            self.read_carriers(&run, 0, "main", kind, None, None)
                .await?;
        }
        match case {
            Case::JournalFacts => {
                require(
                    run.attempts.len() == 2
                        && run.attempts[0].status == RunReconciliationAttemptStatus::Completed
                        && run.attempts[0].recorded_commit_state
                            == Some(RunReconciliationCommitState::Committed)
                        && run.attempts[1].status == RunReconciliationAttemptStatus::Executing
                        && run.attempts[1].recorded_commit_state.is_none()
                        && run.attempts[1].finished_at.is_none(),
                    "074_real_committed_and_unrecorded_facts",
                )?;
                for kind in [ReadKind::Attempts, ReadKind::Receipts] {
                    self.read_carriers(&run, 0, "main", kind, None, Some(1))
                        .await?;
                    self.read_carriers(
                        &run,
                        0,
                        "main",
                        kind,
                        Some(RunReconciliationCursor {
                            call_sequence: 0,
                            attempt_sequence: 0,
                        }),
                        Some(1),
                    )
                    .await?;
                    self.deny_other_owner(&run, kind).await?;
                }
                self.refuse_new_foreground(&run).await?;
            }
            Case::RememberReceipt => {
                require(
                    run.receipts.len() == 1
                        && run.receipts[0].receipt_id == run.calls[0].effect.receipt_id
                        && run.attempts[0].recorded_commit_state.is_none(),
                    "075_real_positive_receipt_does_not_rewrite_unknown_attempt",
                )?;
                for kind in [ReadKind::Attempts, ReadKind::Receipts] {
                    self.read_carriers(&run, 0, "main", kind, None, Some(100))
                        .await?;
                    self.deny_other_owner(&run, kind).await?;
                    self.closed_request_denials(&run, kind).await?;
                }
                self.refuse_new_foreground(&run).await?;
            }
            Case::Pagination => {
                // Positions come from three actual capability/memory/journal invocations. No SQL
                // call/attempt/receipt seeding or nonzero-attempt relabelling is used here.
                for kind in [ReadKind::Attempts, ReadKind::Receipts] {
                    for (after, limit) in [
                        (None, Some(1)),
                        (None, Some(2)),
                        (None, Some(100)),
                        (
                            Some(RunReconciliationCursor {
                                call_sequence: 0,
                                attempt_sequence: 0,
                            }),
                            Some(1),
                        ),
                        (
                            Some(RunReconciliationCursor {
                                call_sequence: 1,
                                attempt_sequence: 0,
                            }),
                            Some(1),
                        ),
                        (
                            Some(RunReconciliationCursor {
                                call_sequence: 2,
                                attempt_sequence: 0,
                            }),
                            Some(1),
                        ),
                        (
                            Some(RunReconciliationCursor {
                                call_sequence: i64::MAX,
                                attempt_sequence: i64::MAX,
                            }),
                            Some(100),
                        ),
                    ] {
                        self.read_carriers(&run, 0, "main", kind, after, limit)
                            .await?;
                    }
                    // The cursor marks an exclusive run-local position, not a fixed cross-page
                    // snapshot; repeating the first page returns the same facts with fresh time.
                    self.read_carriers(&run, 0, "main", kind, None, Some(1))
                        .await?;
                    self.closed_request_denials(&run, kind).await?;
                }
                self.refuse_new_foreground(&run).await?;
            }
            Case::CurrentAuthority => {
                self.current_authority(&run).await?;
                return Ok(()); // This case deliberately changes only owned authority fixtures.
            }
        }
        unchanged(
            &self.pool,
            &before,
            "all_business_tables_changed_after_reads_or_denials",
        )
        .await
    }

    async fn read_carriers(
        &self,
        run: &ProducedRun,
        actor: usize,
        label: &str,
        kind: ReadKind,
        after: Option<RunReconciliationCursor>,
        limit: Option<u32>,
    ) -> Result<(), String> {
        let before = snapshot(&self.pool).await?;
        let lower = database_time(&self.pool).await?;
        let typed = self
            .transport
            .as_ref()
            .ok_or("transport_missing")?
            .execute(
                self.identities[actor].context().clone(),
                kind.command(run, after, limit),
            )
            .await
            .map_err(|_| "typed_reconciliation_read")?;
        let path = kind.path(run, &page_query(after, limit));
        let http = http(
            self.router.as_ref().ok_or("router_missing")?,
            TOKENS[actor],
            &path,
            Vec::new(),
        )
        .await?;
        // A renderer cookie for the other principal cannot replace this window's real binding.
        let desktop = window(
            self.protocol.as_ref().ok_or("protocol_missing")?,
            label,
            TOKENS[1 - actor],
            &path,
            Vec::new(),
        )
        .await?;
        let upper = database_time(&self.pool).await?;
        run.verify_reply(kind, typed, after, limit, lower, upper)?;
        for response in [&http, &desktop] {
            response.closed_json()?;
            require(response.status == StatusCode::OK, "host_read_status")?;
            run.verify_reply(
                kind,
                decode_reply(kind, &response.body)?,
                after,
                limit,
                lower,
                upper,
            )?;
            run.redacted(&response.body)?;
        }
        unchanged(
            &self.pool,
            &before,
            "read_changed_full_business_or_physical_rows",
        )
        .await
    }

    async fn deny_other_owner(&self, run: &ProducedRun, kind: ReadKind) -> Result<(), String> {
        let before = snapshot(&self.pool).await?;
        let denied = self
            .transport
            .as_ref()
            .ok_or("transport_missing")?
            .execute(
                self.identities[1].context().clone(),
                kind.command(run, None, None),
            )
            .await;
        require(
            matches!(denied, Err(AppError::NotVisible)),
            "typed_admin_cannot_read_other_owner",
        )?;
        let path = kind.path(run, "");
        http(
            self.router.as_ref().ok_or("router_missing")?,
            TOKENS[1],
            &path,
            Vec::new(),
        )
        .await?
        .error(StatusCode::NOT_FOUND, "not_visible")?;
        window(
            self.protocol.as_ref().ok_or("protocol_missing")?,
            "other",
            TOKENS[0],
            &path,
            Vec::new(),
        )
        .await?
        .error(StatusCode::NOT_FOUND, "not_visible")?;
        unchanged(&self.pool, &before, "owner_denial_changed_business_rows").await
    }

    async fn closed_request_denials(
        &self,
        run: &ProducedRun,
        kind: ReadKind,
    ) -> Result<(), String> {
        let before = snapshot(&self.pool).await?;
        let router = self.router.as_ref().ok_or("router_missing")?;
        let protocol = self.protocol.as_ref().ok_or("protocol_missing")?;
        for query in [
            "?actor=PRIVATE_RECONCARRIER_TAG",
            "?limit=1&limit=2",
            "?limit=1&%6cimit=2",
            "?afterCallSequence=0",
            "?afterAttemptSequence=0",
            "?limit=0",
            "?limit=101",
            "?limit=4294967296",
            "?afterCallSequence=-1&afterAttemptSequence=0",
            "?afterCallSequence=0&afterAttemptSequence=-1",
            "?afterCallSequence=9223372036854775808&afterAttemptSequence=0",
            "?limit=%GG",
        ] {
            let path = kind.path(run, query);
            for response in [
                http(router, TOKENS[0], &path, Vec::new()).await?,
                window(protocol, "main", TOKENS[1], &path, Vec::new()).await?,
            ] {
                response.error(StatusCode::BAD_REQUEST, "malformed_payload")?;
                run.redacted(&response.body)?;
            }
        }
        let path = kind.path(run, "");
        for response in [
            http(router, TOKENS[0], &path, vec![b'x']).await?,
            window(protocol, "main", TOKENS[1], &path, vec![b'x']).await?,
        ] {
            response.error(StatusCode::BAD_REQUEST, "malformed_payload")?;
        }
        for (after, limit) in [
            (None, Some(0)),
            (None, Some(101)),
            (
                Some(RunReconciliationCursor {
                    call_sequence: -1,
                    attempt_sequence: 0,
                }),
                Some(1),
            ),
        ] {
            require(
                matches!(
                    self.transport
                        .as_ref()
                        .ok_or("transport_missing")?
                        .execute(
                            self.identities[0].context().clone(),
                            kind.command(run, after, limit)
                        )
                        .await,
                    Err(AppError::MalformedPayload { .. })
                ),
                "typed_page_boundary_denial",
            )?;
        }
        let twice_encoded = path.replace(
            &encode_segment(run.command.run_id.as_str()),
            &encode_segment(&encode_segment(run.command.run_id.as_str())),
        );
        for response in [
            http(router, TOKENS[0], &twice_encoded, Vec::new()).await?,
            window(protocol, "main", TOKENS[1], &twice_encoded, Vec::new()).await?,
        ] {
            response.error(StatusCode::NOT_FOUND, "not_visible")?;
        }
        http(
            router,
            "OWNED_INVALID_RECONCARRIER_SESSION",
            &path,
            Vec::new(),
        )
        .await?
        .error(StatusCode::UNAUTHORIZED, "unauthenticated")?;
        window(
            protocol,
            "unknown-owned-window",
            TOKENS[0],
            &path,
            Vec::new(),
        )
        .await?
        .error(StatusCode::UNAUTHORIZED, "unauthenticated")?;
        unchanged(
            &self.pool,
            &before,
            "malformed_or_identity_denials_changed_business_rows",
        )
        .await
    }

    async fn refuse_new_foreground(&self, run: &ProducedRun) -> Result<(), String> {
        let before = snapshot(&self.pool).await?;
        let mut command = run.command.clone();
        command.run_id = RunId::new("owned-new-run-must-not-pass-unknown-occupancy");
        require(
            matches!(
                self.transport
                    .as_ref()
                    .ok_or("transport_missing")?
                    .execute(
                        self.identities[0].context().clone(),
                        AppCommand::BeginThreadRun(command)
                    )
                    .await,
                Err(AppError::LeaseConflict { holder: None })
            ),
            "unknown_still_blocks_new_foreground",
        )?;
        unchanged(
            &self.pool,
            &before,
            "denied_foreground_changed_unknown_or_occupancy",
        )
        .await
    }

    async fn current_authority(&mut self, run: &ProducedRun) -> Result<(), String> {
        let other = self.produce(1, 1, "owner-b").await?;
        self.pool
            .get()
            .await
            .map_err(|_| "owned_membership_connection")?
            .execute(
                "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,$2)",
                &[&run.command.thread_id.as_str(), &ACTORS[1]],
            )
            .await
            .map_err(|_| "owned_other_direct_membership")?;
        let initial = snapshot(&self.pool).await?;
        for kind in [ReadKind::Attempts, ReadKind::Receipts] {
            self.read_carriers(run, 0, "main", kind, None, None).await?;
            self.read_carriers(&other, 1, "other", kind, None, None)
                .await?;
            self.deny_other_owner(run, kind).await?;
            self.closed_request_denials(run, kind).await?;
            // B has a valid admin session AND direct membership, yet the original run is A's.
            // Replace the same label with B while the real query awaits an owned PG table lock.
            self.rebind_during_real_read(run, kind).await?;
        }
        self.refuse_new_foreground(run).await?;
        unchanged(
            &self.pool,
            &initial,
            "initial_authority_reads_changed_business_rows",
        )
        .await?;
        let stale = self.identities[0].context().clone();
        self.pool
            .get()
            .await
            .map_err(|_| "generation_fixture_connection")?
            .execute(
                "UPDATE public.users SET auth_generation=1 WHERE id=$1",
                &[&ACTORS[0]],
            )
            .await
            .map_err(|_| "owned_generation_change")?;
        let changed = snapshot(&self.pool).await?;
        same_except(
            &initial,
            &changed,
            &["public.users"],
            "generation_change_touched_other_business_rows",
        )?;
        for kind in [ReadKind::Attempts, ReadKind::Receipts] {
            let path = kind.path(run, "");
            require(
                matches!(
                    self.transport
                        .as_ref()
                        .ok_or("transport_missing")?
                        .execute(stale.clone(), kind.command(run, None, None))
                        .await,
                    Err(AppError::NotVisible)
                ),
                "stale_generation_typed_refused",
            )?;
            // Recon's current PG owner predicate returns 404 for the bound old generation.
            // The HTTP resolver independently invalidates the old session as 401. No Models
            // original-session deletion guard is asserted for this different read contract.
            window(
                self.protocol.as_ref().ok_or("protocol_missing")?,
                "main",
                TOKENS[1],
                &path,
                Vec::new(),
            )
            .await?
            .error(StatusCode::NOT_FOUND, "not_visible")?;
            http(
                self.router.as_ref().ok_or("router_missing")?,
                TOKENS[0],
                &path,
                Vec::new(),
            )
            .await?
            .error(StatusCode::UNAUTHORIZED, "unauthenticated")?;
        }
        unchanged(
            &self.pool,
            &changed,
            "stale_generation_denial_changed_business_rows",
        )
        .await?;
        self.pool
            .get()
            .await
            .map_err(|_| "session_generation_fixture_connection")?
            .execute(
                "UPDATE public.sessions SET auth_generation=1 WHERE user_id=$1",
                &[&ACTORS[0]],
            )
            .await
            .map_err(|_| "owned_current_session_generation")?;
        let fresh = self
            .auth
            .as_ref()
            .ok_or("resolver_missing")?
            .resolve_with_assurance(&parts(TOKENS[0])?)
            .await
            .map_err(|_| "new_generation_real_session_resolve")?;
        require(
            fresh.context().auth_generation().get() == 1,
            "fresh_current_generation",
        )?;
        fresh
            .context()
            .request_binding()
            .ok_or("fresh_binding_missing")?
            .verify_current(fresh.context())
            .await
            .map_err(|_| "fresh_binding_current")?;
        let protocol = self.protocol.as_ref().ok_or("protocol_missing")?;
        require(
            protocol
                .unbind_window("main")
                .map_err(|_| "old_window_unbind")?,
            "old_window_existed",
        )?;
        for kind in [ReadKind::Attempts, ReadKind::Receipts] {
            window(protocol, "main", TOKENS[0], &kind.path(run, ""), Vec::new())
                .await?
                .error(StatusCode::UNAUTHORIZED, "unauthenticated")?;
        }
        protocol
            .bind_window("main", fresh.context().clone(), None)
            .map_err(|_| "fresh_window_bind")?;
        self.identities[0] = fresh;
        let current = snapshot(&self.pool).await?;
        same_except(
            &changed,
            &current,
            &["public.sessions"],
            "session_generation_change_touched_other_business_rows",
        )?;
        for kind in [ReadKind::Attempts, ReadKind::Receipts] {
            // Current generation may read the original generation-0 positive receipt. The
            // receipt remains immutable and is never replaced with a fresh-generation effect.
            self.read_carriers(run, 0, "main", kind, None, None).await?;
            require(
                matches!(
                    self.transport
                        .as_ref()
                        .ok_or("transport_missing")?
                        .execute(stale.clone(), kind.command(run, None, None))
                        .await,
                    Err(AppError::NotVisible)
                ),
                "original_generation_stays_stale",
            )?;
            self.deny_other_owner(run, kind).await?;
        }
        self.refuse_new_foreground(run).await?;
        unchanged(
            &self.pool,
            &current,
            "fresh_generation_history_read_changed_business_rows",
        )
        .await
    }

    async fn rebind_during_real_read(
        &self,
        run: &ProducedRun,
        kind: ReadKind,
    ) -> Result<(), String> {
        let before = snapshot(&self.pool).await?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| "owned_read_gate_connection")?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| "owned_read_gate_begin")?;
        tx.batch_execute(
            "SET LOCAL lock_timeout='5s'; LOCK TABLE public.tool_calls IN ACCESS EXCLUSIVE MODE",
        )
        .await
        .map_err(|_| "owned_read_gate_lock")?;
        let protocol = self.protocol.as_ref().ok_or("protocol_missing")?;
        let path = kind.path(run, "");
        let mut request = Box::pin(window(protocol, "main", TOKENS[1], &path, Vec::new()));
        let mut early = None;
        let gate = tokio::select! {
            result = &mut request => { early = Some(result); Err("real_read_completed_before_owned_pg_gate".to_owned()) }
            observed = observe_read_lock(&self.pool) => observed,
        };
        let rebound = if gate.is_ok() {
            (|| {
                require(
                    protocol
                        .unbind_window("main")
                        .map_err(|_| "pending_window_unbind")?,
                    "pending_original_window_existed",
                )?;
                protocol
                    .bind_window("main", self.identities[1].context().clone(), None)
                    .map_err(|_| "pending_replacement_bind")?;
                Ok::<(), String>(())
            })()
        } else {
            Ok(())
        };
        // The lock transaction explicitly acknowledges rollback, and the original real request
        // is awaited to completion. No spawn handle, delayed query or transport future is hidden.
        let rolled_back = tx.rollback().await.map_err(|_| "owned_read_gate_rollback");
        let response = match early {
            Some(result) => result,
            None => request.await,
        }?;
        rolled_back?;
        gate?;
        rebound?;
        response.error(StatusCode::UNAUTHORIZED, "unauthenticated")?;
        window(protocol, "main", TOKENS[0], &path, Vec::new())
            .await?
            .error(StatusCode::NOT_FOUND, "not_visible")?;
        require(
            protocol
                .unbind_window("main")
                .map_err(|_| "replacement_window_unbind")?,
            "replacement_window_existed",
        )?;
        protocol
            .bind_window("main", self.identities[0].context().clone(), None)
            .map_err(|_| "original_window_rebind")?;
        unchanged(
            &self.pool,
            &before,
            "window_replacement_read_changed_business_rows",
        )
        .await
    }

    async fn finish(&mut self) -> Result<(), String> {
        let mut clean = true;
        if let Some(auth) = &self.auth {
            auth.close_request_bindings();
            for identity in &self.identities {
                if let Some(binding) = identity.context().request_binding() {
                    clean &= binding.verify_current(identity.context()).await.is_err();
                } else {
                    clean = false;
                }
            }
        }
        if let Some(protocol) = self.protocol.take() {
            for label in ["main", "other"] {
                clean &= protocol.unbind_window(label).is_ok();
            }
            clean &= Arc::strong_count(&protocol) == 1;
            drop(protocol);
        }
        self.router.take();
        if let Some(transport) = self.transport.take() {
            let report = transport.shutdown().await;
            clean &= report.within_deadline && report.pumps_total == 0 && report.pumps_aborted == 0;
        }
        if let Some(assembly) = self.assembly.take() {
            assembly.shutdown().await;
        }
        self.identities.clear();
        self.auth.take();
        self.pool.close();
        for file in ["index.html", "openbot-bootstrap.mjs"] {
            if let Err(error) = std::fs::remove_file(self.assets.join(file)) {
                clean &= error.kind() == std::io::ErrorKind::NotFound;
            }
        }
        if let Err(error) = std::fs::remove_dir(&self.assets) {
            clean &= error.kind() == std::io::ErrorKind::NotFound;
        }
        require(
            clean && self.wire.load(Ordering::SeqCst) == 0,
            "owned_resource_close_or_unexpected_provider_wire",
        )
    }
}

impl ProducedRun {
    async fn verify_producer(
        &mut self,
        pool: &DatabasePool,
        auth: &AuthContext,
    ) -> Result<(), String> {
        let client = pool.get().await.map_err(|_| "producer_fact_connection")?;
        let row = client.query_one(
            "SELECT to_jsonb(r) AS run,to_jsonb(e) AS terminal,to_jsonb(o) AS occupancy,to_jsonb(l) AS lease
             FROM public.runs r JOIN public.run_events e ON e.run_id=r.run_id AND e.seq=r.terminal_event_seq
             JOIN public.thread_run_occupancy o ON o.run_id=r.run_id AND o.thread_id=r.thread_id
             JOIN public.thread_leases l ON l.thread_id=r.thread_id WHERE r.run_id=$1",
            &[&self.command.run_id.as_str()],
        ).await.map_err(|_| "real_terminal_occupancy_facts")?;
        let run: Value = row.try_get("run").map_err(|_| "raw_run_shape")?;
        let terminal: Value = row.try_get("terminal").map_err(|_| "raw_terminal_shape")?;
        let occupancy: Value = row
            .try_get("occupancy")
            .map_err(|_| "raw_occupancy_shape")?;
        let lease: Value = row.try_get("lease").map_err(|_| "raw_lease_shape")?;
        require(
            run["status"] == "reconciliation_required"
                && run["foreground"] == true
                && run["actor_id"] == auth.actor().as_str()
                && run["bot_id"] == self.command.bot_id.as_str()
                && run["thread_id"] == self.command.thread_id.as_str()
                && run["terminal_event_seq"] == json!(self.terminal_sequence)
                && run["error_code"] == "journal_commit_unknown"
                && terminal["seq"] == json!(self.terminal_sequence)
                && terminal["terminal"] == true
                && terminal["event_type"] == "reconciliation_required"
                && terminal["thread_id"] == self.command.thread_id.as_str()
                && terminal["payload"]
                    == json!({"status":"reconciliation_required","errorCode":"journal_commit_unknown"})
                && occupancy["run_id"] == self.command.run_id.as_str()
                && occupancy["thread_id"] == self.command.thread_id.as_str()
                && lease["fencing_token"] == run["fencing_token"],
            "real_unknown_terminal_and_original_occupancy",
        )?;
        let delivered: i64 = client.query_one("SELECT count(*) FROM public.outbox WHERE payload->>'runId'=$1 AND destination='agent_run_dispatch' AND status='delivered'", &[&self.command.run_id.as_str()]).await.map_err(|_| "real_dispatch_delivery_fact")?.try_get(0).map_err(|_| "dispatch_count_shape")?;
        require(delivered == 1, "one_actual_dispatch_ack")?;
        for (index, produced) in self.calls.iter().enumerate() {
            let request = &produced.request;
            let row = client.query_one(
                "SELECT to_jsonb(r) AS receipt,to_jsonb(m) AS memory,to_jsonb(e) AS memory_event,
                        to_jsonb(a) AS audit,to_jsonb(c) AS call,to_jsonb(t) AS attempt,to_jsonb(s) AS source,
                        t.created_at AS attempt_created_at,t.started_at AS attempt_started_at,t.finished_at AS attempt_finished_at,
                        r.recorded_at AS receipt_recorded_at
                 FROM public.remember_effect_receipts r
                 JOIN public.memories m ON m.memory_id=r.memory_id
                 JOIN public.memory_events e ON e.memory_id=r.memory_id AND e.seq=r.memory_event_seq
                 JOIN public.audit_events a ON a.id::text=r.audit_event_id
                 JOIN public.tool_calls c ON c.tool_call_id=r.tool_call_id
                 JOIN public.tool_attempts t ON t.attempt_id=r.attempt_id
                 JOIN public.messages s ON s.message_id=m.source_message_id WHERE r.receipt_id=$1",
                &[&produced.effect.receipt_id],
            ).await.map_err(|_| "real_memory_receipt_audit_source_join")?;
            let receipt: Value = row.try_get("receipt").map_err(|_| "receipt_fact_shape")?;
            let memory: Value = row.try_get("memory").map_err(|_| "memory_fact_shape")?;
            let event: Value = row
                .try_get("memory_event")
                .map_err(|_| "memory_event_fact_shape")?;
            let audit: Value = row.try_get("audit").map_err(|_| "audit_fact_shape")?;
            let call: Value = row.try_get("call").map_err(|_| "call_fact_shape")?;
            let attempt: Value = row.try_get("attempt").map_err(|_| "attempt_fact_shape")?;
            let source: Value = row.try_get("source").map_err(|_| "source_fact_shape")?;
            require(
                receipt["receipt_id"] == produced.effect.receipt_id
                    && receipt["memory_id"] == produced.effect.memory_id
                    && receipt["deployment_id"] == request.deployment().as_str()
                    && receipt["tenant_id"] == request.tenant().as_str()
                    && receipt["thread_id"] == request.thread().as_str()
                    && receipt["run_id"] == request.run().as_str()
                    && receipt["actor_id"] == request.actor().as_str()
                    && receipt["bot_id"] == request.bot().as_str()
                    && receipt["auth_generation"] == json!(request.auth_generation().get())
                    && receipt["tool_call_id"] == request.call().as_str()
                    && receipt["attempt_id"] == request.attempt().as_str()
                    && receipt["decision_id"] == request.decision().as_str()
                    && receipt["capability_id"] == request.capability().as_str()
                    && receipt["args_hash"] == request.args_hash().to_hex()
                    && receipt["schema_hash"] == request.schema_hash().to_hex()
                    && receipt["catalog_generation"] == json!(request.catalog_generation().get())
                    && receipt["target_kind"] == request.target().kind
                    && receipt["target_id"] == request.target().id
                    && receipt["call_seq"] == json!(index as i64)
                    && receipt["attempt_seq"] == 0
                    && receipt["memory_event_seq"] == 0,
                "full_genuine_effect_binding_chain",
            )?;
            require(
                call["run_id"] == receipt["run_id"]
                    && call["actor_id"] == receipt["actor_id"]
                    && call["bot_id"] == receipt["bot_id"]
                    && call["tool_name"] == "remember"
                    && call["tool_call_id"] == receipt["tool_call_id"]
                    && call["decision_id"] == receipt["decision_id"]
                    && call["call_seq"] == receipt["call_seq"]
                    && call["args_hash"] == receipt["args_hash"]
                    && call["schema_hash"] == receipt["schema_hash"]
                    && call["catalog_generation"] == receipt["catalog_generation"]
                    && call["target_kind"] == receipt["target_kind"]
                    && call["target_id"] == receipt["target_id"]
                    && attempt["tool_call_id"] == receipt["tool_call_id"]
                    && attempt["attempt_seq"] == receipt["attempt_seq"]
                    && attempt["capability_id"] == receipt["capability_id"]
                    && attempt["attempt_id"] == receipt["attempt_id"],
                "genuine_journal_matches_positive_receipt",
            )?;
            let status = if produced.journal_written {
                RunReconciliationAttemptStatus::Completed
            } else {
                RunReconciliationAttemptStatus::Executing
            };
            let commit = produced
                .journal_written
                .then_some(RunReconciliationCommitState::Committed);
            require(
                attempt["status"]
                    == if produced.journal_written {
                        "completed"
                    } else {
                        "executing"
                    }
                    && attempt["commit_state"]
                        == if produced.journal_written {
                            json!("committed")
                        } else {
                            Value::Null
                        },
                "original_attempt_outcome_kept_exactly",
            )?;
            require(
                memory["tenant_id"] == request.tenant().as_str()
                    && memory["owner_user_id"] == request.actor().as_str()
                    && memory["created_by"] == request.actor().as_str()
                    && memory["scope_kind"] == "user"
                    && memory["origin"] == "remember_tool"
                    && memory["content"] == format!("{CONTENT}-{index}")
                    && memory["tags"] == json!([PRIVATE_TAG])
                    && memory["source_run_id"] == request.run().as_str()
                    && memory["source_thread_id"] == request.thread().as_str()
                    && memory["source_message_id"] == source["message_id"]
                    && source["run_id"] == request.run().as_str()
                    && source["thread_id"] == request.thread().as_str()
                    && source["actor_id"] == request.actor().as_str()
                    && source["role"] == "user"
                    && memory["source_authorization_snapshot"]["actorId"]
                        == request.actor().as_str()
                    && memory["source_authorization_snapshot"]["tenantId"]
                        == request.tenant().as_str()
                    && memory["source_authorization_snapshot"]["deploymentId"]
                        == request.deployment().as_str()
                    && memory["source_authorization_snapshot"]["authGeneration"]
                        == json!(request.auth_generation().get())
                    && event["actor_id"] == request.actor().as_str()
                    && event["event_type"] == "create"
                    && event["seq"] == 0
                    && event["memory_id"] == produced.effect.memory_id,
                "real_memory_actor_and_original_message_provenance",
            )?;
            require(
                audit["event_type"] == "memory.effect_committed"
                    && audit["actor_user_id"] == request.actor().as_str()
                    && audit["target_type"] == "memory_effect_receipt"
                    && audit["target_id"] == produced.effect.receipt_id
                    && audit["payload"]
                        == json!({"bot":request.bot().as_str(),"decision_id":request.decision().as_str(),"target_kind":"memory_create","target_id":produced.effect.memory_id,"commit_state":"committed","tool_attempt_id":request.attempt().as_str(),"memory_event_sequence":0}),
                "real_effect_audit_binding",
            )?;
            let created_at: OffsetDateTime = row
                .try_get("attempt_created_at")
                .map_err(|_| "attempt_created_time")?;
            let started_at: Option<OffsetDateTime> = row
                .try_get("attempt_started_at")
                .map_err(|_| "attempt_started_time")?;
            let finished_at: Option<OffsetDateTime> = row
                .try_get("attempt_finished_at")
                .map_err(|_| "attempt_finished_time")?;
            require(
                started_at.is_some() && finished_at.is_some() == produced.journal_written,
                "real_attempt_time_nullness",
            )?;
            self.attempts.push(RunReconciliationAttempt {
                tool_call_id: request.call().as_str().to_owned(),
                call_sequence: index as i64,
                attempt_id: request.attempt().as_str().to_owned(),
                attempt_sequence: 0,
                status,
                recorded_commit_state: commit,
                created_at,
                started_at,
                finished_at,
            });
            self.receipts.push(RunEffectReceipt {
                receipt_id: produced.effect.receipt_id.clone(),
                tool_call_id: request.call().as_str().to_owned(),
                call_sequence: index as i64,
                attempt_id: request.attempt().as_str().to_owned(),
                attempt_sequence: 0,
                fact: RunEffectReceiptFact::MemoryCreated,
                recorded_at: row
                    .try_get("receipt_recorded_at")
                    .map_err(|_| "receipt_recorded_time")?,
            });
        }
        require(
            self.attempts.len() == self.calls.len() && self.receipts.len() == self.calls.len(),
            "complete_producer_oracle",
        )
    }

    fn verify_reply(
        &self,
        kind: ReadKind,
        reply: AppReply,
        after: Option<RunReconciliationCursor>,
        limit: Option<u32>,
        lower: OffsetDateTime,
        upper: OffsetDateTime,
    ) -> Result<(), String> {
        let limit = limit.unwrap_or(50) as usize;
        match (kind, reply) {
            (ReadKind::Attempts, AppReply::RunReconciliation(actual)) => {
                require(
                    actual.observed_at >= lower && actual.observed_at <= upper,
                    "attempt_statement_time_is_current_pg_time",
                )?;
                let selected: Vec<_> = self
                    .attempts
                    .iter()
                    .filter(|row| {
                        after.is_none_or(|a| {
                            RunReconciliationCursor {
                                call_sequence: row.call_sequence,
                                attempt_sequence: row.attempt_sequence,
                            } > a
                        })
                    })
                    .cloned()
                    .collect();
                let more = selected.len() > limit;
                let attempts: Vec<_> = selected.into_iter().take(limit).collect();
                let next = if more {
                    attempts.last().map(|row| RunReconciliationCursor {
                        call_sequence: row.call_sequence,
                        attempt_sequence: row.attempt_sequence,
                    })
                } else {
                    None
                };
                let expected = RunReconciliationSnapshot {
                    thread_id: self.command.thread_id.clone(),
                    run_id: self.command.run_id.clone(),
                    status: RunReconciliationStatus::ReconciliationRequired,
                    terminal_event_sequence: self.terminal_sequence,
                    observed_at: actual.observed_at,
                    foreground_blocked: true,
                    attempts,
                    next,
                    available_actions: [],
                };
                require(
                    actual == expected,
                    "complete_074_snapshot_matches_real_producer",
                )
            }
            (ReadKind::Receipts, AppReply::RunEffectReceipts(actual)) => {
                require(
                    actual.observed_at >= lower && actual.observed_at <= upper,
                    "receipt_statement_time_is_current_pg_time",
                )?;
                let selected: Vec<_> = self
                    .receipts
                    .iter()
                    .filter(|row| {
                        after.is_none_or(|a| {
                            RunReconciliationCursor {
                                call_sequence: row.call_sequence,
                                attempt_sequence: row.attempt_sequence,
                            } > a
                        })
                    })
                    .cloned()
                    .collect();
                let more = selected.len() > limit;
                let receipts: Vec<_> = selected.into_iter().take(limit).collect();
                let next = if more {
                    receipts.last().map(|row| RunReconciliationCursor {
                        call_sequence: row.call_sequence,
                        attempt_sequence: row.attempt_sequence,
                    })
                } else {
                    None
                };
                let expected = RunEffectReceiptsSnapshot {
                    thread_id: self.command.thread_id.clone(),
                    run_id: self.command.run_id.clone(),
                    status: RunReconciliationStatus::ReconciliationRequired,
                    terminal_event_sequence: self.terminal_sequence,
                    observed_at: actual.observed_at,
                    foreground_blocked: true,
                    receipts,
                    next,
                    available_actions: [],
                };
                require(
                    actual == expected,
                    "complete_075_snapshot_matches_real_producer",
                )
            }
            _ => Err("reconciliation_reply_variant".to_owned()),
        }
    }

    fn redacted(&self, body: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(body).map_err(|_| "host_response_utf8")?;
        require(
            ![
                CONTENT,
                PRIVATE_TAG,
                "PRIVATE_RECONCARRIER_ORIGINAL_USER_MESSAGE",
                TOKENS[0],
                TOKENS[1],
                ACTORS[0],
                ACTORS[1],
                BOT,
            ]
            .iter()
            .any(|secret| text.contains(secret)),
            "private_producer_content_or_principal_leak",
        )?;
        for call in &self.calls {
            require(
                ![
                    call.effect.memory_id.as_str(),
                    call.request.capability().as_str(),
                    call.request.decision().as_str(),
                    &call.request.args_hash().to_hex(),
                    &call.request.schema_hash().to_hex(),
                ]
                .iter()
                .any(|private| text.contains(private)),
                "private_effect_binding_or_hash_leak",
            )?;
        }
        Ok(())
    }
}

struct WireReply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}
impl WireReply {
    fn closed_json(&self) -> Result<(), String> {
        require(
            self.headers.get_all(CACHE_CONTROL).iter().count() == 1
                && self
                    .headers
                    .get(CACHE_CONTROL)
                    .is_some_and(|value| value == "no-store")
                && self.headers.get_all(CONTENT_TYPE).iter().count() == 1
                && self
                    .headers
                    .get(CONTENT_TYPE)
                    .is_some_and(|value| value == "application/json")
                && !self.headers.contains_key(SET_COOKIE)
                && self.headers.keys().all(|name| {
                    matches!(
                        name.as_str(),
                        "cache-control" | "content-type" | "content-length" | "x-request-id"
                    ) && self.headers.get_all(name).iter().count() == 1
                })
                && self.headers.get("content-length").is_none_or(|value| {
                    value
                        .to_str()
                        .is_ok_and(|value| value == self.body.len().to_string())
                })
                && self.headers.get("x-request-id").is_none_or(|value| {
                    value
                        .to_str()
                        .is_ok_and(|value| Uuid::parse_str(value).is_ok())
                })
                && self.body.len() <= MAX_RUN_RECONCILIATION_RESPONSE_BYTES,
            "closed_json_headers_no_store_or_response_bound",
        )
    }
    fn error(&self, status: StatusCode, code: &'static str) -> Result<(), String> {
        self.closed_json()?;
        let body: Value = serde_json::from_slice(&self.body).map_err(|_| "error_body_json")?;
        require(
            self.status == status && body == json!({"code":code}),
            "full_error_status_and_closed_body",
        )
    }
}

fn decode_reply(kind: ReadKind, body: &[u8]) -> Result<AppReply, String> {
    let value: Value = serde_json::from_slice(body).map_err(|_| "host_snapshot_json")?;
    require(
        value.as_object().is_some_and(|object| object.len() == 9),
        "full_nine_field_snapshot",
    )?;
    match kind {
        ReadKind::Attempts => serde_json::from_slice::<RunReconciliationSnapshot>(body)
            .map(AppReply::RunReconciliation)
            .map_err(|_| "closed_074_host_dto".to_owned()),
        ReadKind::Receipts => serde_json::from_slice::<RunEffectReceiptsSnapshot>(body)
            .map(AppReply::RunEffectReceipts)
            .map_err(|_| "closed_075_host_dto".to_owned()),
    }
}
fn parts(token: &str) -> Result<axum::http::request::Parts, String> {
    Ok(Request::builder()
        .uri("/api/me")
        .header(COOKIE, format!("openbot_session={token}"))
        .body(())
        .map_err(|_| "session_request_parts")?
        .into_parts()
        .0)
}
fn encode_segment(raw: &str) -> String {
    raw.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
fn page_query(after: Option<RunReconciliationCursor>, limit: Option<u32>) -> String {
    let mut parts = Vec::new();
    if let Some(after) = after {
        parts.push(format!(
            "afterCallSequence={}&afterAttemptSequence={}",
            after.call_sequence, after.attempt_sequence
        ));
    }
    if let Some(limit) = limit {
        parts.push(format!("limit={limit}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}
async fn http(
    router: &Router,
    token: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<WireReply, String> {
    let mut request = Request::builder()
        .uri(path)
        .header(COOKIE, format!("openbot_session={token}"))
        .body(Body::from(body))
        .map_err(|_| "http_request")?;
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:32124"
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "owned_http_peer")?,
    ));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .map_err(|_| "http_router")?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(
        response.into_body(),
        MAX_RUN_RECONCILIATION_RESPONSE_BYTES + 1,
    )
    .await
    .map_err(|_| "http_response_body_bound")?
    .to_vec();
    Ok(WireReply {
        status,
        headers,
        body,
    })
}
async fn window(
    protocol: &DesktopTauriProtocol,
    label: &str,
    cookie: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<WireReply, String> {
    let request = Request::builder()
        .uri(path)
        .header(COOKIE, format!("openbot_session={cookie}"))
        .body(body)
        .map_err(|_| "window_request")?;
    let response = protocol.handle(label, request).await;
    Ok(WireReply {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.into_body(),
    })
}

async fn observe_read_lock(pool: &DatabasePool) -> Result<(), String> {
    let client = pool
        .get()
        .await
        .map_err(|_| "read_gate_observer_connection")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let blocked: bool = client.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.relation='public.tool_calls'::regclass AND NOT l.granted AND a.datname=current_database() AND a.wait_event_type='Lock')", &[]).await.map_err(|_| "actual_pg_read_lock_observation")?.try_get(0).map_err(|_| "read_lock_observation_shape")?;
        if blocked {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("actual_pg_query_wait_not_observed".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn database_time(pool: &DatabasePool) -> Result<OffsetDateTime, String> {
    pool.get()
        .await
        .map_err(|_| "pg_time_connection")?
        .query_one("SELECT statement_timestamp()", &[])
        .await
        .map_err(|_| "pg_statement_time")?
        .try_get(0)
        .map_err(|_| "pg_statement_time_shape".to_owned())
}

// Ordinary HTTP Session resolution legitimately updates only the session idle updated_at.
// Every session field other than that timestamp is retained. Its physical xmin/ctid advance
// with that admitted idle update, so sessions are the sole explicitly separated table. All
// ordinary business rows, including every empty table and internal heap table, retain both
// physical coordinates; same-value UPDATE is therefore detectable. The data is never printed.
async fn snapshot(pool: &DatabasePool) -> Result<Value, String> {
    let mut client = pool.get().await.map_err(|_| "snapshot_connection")?;
    let tx = client
        .build_transaction()
        .read_only(true)
        .isolation_level(deadpool_postgres::tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await
        .map_err(|_| "snapshot_readonly_begin")?;
    let identity = tx
        .query_one(
            "SELECT current_database(),current_user,current_setting('transaction_read_only')",
            &[],
        )
        .await
        .map_err(|_| "snapshot_pg_identity")?;
    let database: String = identity.try_get(0).map_err(|_| "snapshot_database_shape")?;
    let user: String = identity.try_get(1).map_err(|_| "snapshot_user_shape")?;
    let readonly: String = identity.try_get(2).map_err(|_| "snapshot_readonly_shape")?;
    require(
        database.starts_with("openbot_it_reconciliationcarrier_")
            && user == "v7_comp024_admin"
            && readonly == "on",
        "snapshot_owned_pg_fence",
    )?;
    let tables = tx.query("SELECT n.nspname,c.relname,format('%I.%I',n.nspname,c.relname) AS qualified,format('%L',n.nspname||'.'||c.relname) AS literal FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname IN ('public','openbot_internal') ORDER BY n.nspname,c.relname", &[]).await.map_err(|_| "full_heap_table_inventory")?;
    require(!tables.is_empty(), "full_table_inventory_empty")?;
    let mut projections = Vec::new();
    for table in tables {
        let schema: String = table.try_get(0).map_err(|_| "snapshot_schema_shape")?;
        let name: String = table.try_get(1).map_err(|_| "snapshot_table_shape")?;
        let qualified: String = table
            .try_get("qualified")
            .map_err(|_| "snapshot_identifier_shape")?;
        let literal: String = table
            .try_get("literal")
            .map_err(|_| "snapshot_literal_shape")?;
        let projection = if schema == "public" && name == "sessions" {
            "to_jsonb(t)-'updated_at'"
        } else {
            "to_jsonb(t)||jsonb_build_object('__xmin',t.xmin::text,'__ctid',t.ctid::text)"
        };
        projections.push(format!("SELECT {literal}::text AS name,coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) AS rows FROM (SELECT {projection} AS v FROM {qualified} t) s"));
    }
    let sql = format!(
        "SELECT jsonb_object_agg(name,rows) FROM ({}) whole_business",
        projections.join(" UNION ALL ")
    );
    let value: Value = tx
        .query_one(&sql, &[])
        .await
        .map_err(|_| "full_table_physical_snapshot")?
        .try_get(0)
        .map_err(|_| "full_snapshot_shape")?;
    for required in [
        "public.users",
        "public.sessions",
        "public.runs",
        "public.run_events",
        "public.threads",
        "public.thread_leases",
        "public.thread_run_occupancy",
        "public.outbox",
        "public.messages",
        "public.tool_calls",
        "public.tool_attempts",
        "public.remember_effect_receipts",
        "public.memories",
        "public.memory_events",
        "public.audit_events",
        "public.audit_checkpoints",
    ] {
        require(
            value.get(required).is_some_and(Value::is_array),
            "full_snapshot_missing_required_table",
        )?;
    }
    tx.rollback()
        .await
        .map_err(|_| "snapshot_readonly_rollback_ack")?;
    Ok(value)
}
async fn unchanged(pool: &DatabasePool, before: &Value, stage: &'static str) -> Result<(), String> {
    require(snapshot(pool).await? == *before, stage)
}
fn same_except(
    before: &Value,
    after: &Value,
    allowed: &[&str],
    stage: &'static str,
) -> Result<(), String> {
    let mut before = before.clone();
    let mut after = after.clone();
    for name in allowed {
        before
            .as_object_mut()
            .ok_or("snapshot_object_shape")?
            .remove(*name);
        after
            .as_object_mut()
            .ok_or("snapshot_object_shape")?
            .remove(*name);
    }
    require(before == after, stage)
}
