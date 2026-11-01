//! One production Application/Pool/Vault; no GUI, native OS, model wire or Run execution.

mod harness {
    include!("../../../../test-support/postgres_harness.rs");
}

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode, header::COOKIE},
};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_contracts::{
    auth::{AuthContext, Role},
    command::{AppCommand, AppReply, SubscriptionRequest},
    error::AppError,
    ids::{ActorId, DeploymentId, TenantId},
    model_connections::{
        CreateModelConnection, CustomModelProtocol, ModelApiKey, ModelConnection,
        ModelConnectionPageRequest,
    },
    people::CurrentUserResponse,
    request_binding::HostRequestBindingError,
    runtime_capabilities::{RuntimeCapabilitiesResponse, RuntimeCapabilityHostMode},
};
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_domain::{
    identity::session::{SessionHashKey, SessionToken, SessionTokenHash},
    policy::{ActionPolicy, PolicyMode},
    remote_callback::RemoteRunAssertionSigner,
    vault::{KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey},
};
use openbot_infra::{
    application_assembly::{
        ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
        assemble_postgres_application,
    },
    auth::config::default_session_lifetime,
    db::{
        baseline, native,
        pool::{self, DatabaseConfig, DatabasePool},
    },
    policy::PolicyStore,
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

const ACTORS: [&str; 2] = ["owned-typedcarrier-a", "owned-typedcarrier-b"];
const TOKENS: [&str; 2] = [
    "OWNED_TYPEDCARRIER_SESSION_A",
    "OWNED_TYPEDCARRIER_SESSION_B",
];
const KEY: &str = "OWNED_TYPEDCARRIER_MODEL_KEY";
const SESSION_KEY: &[u8] = b"owned-typedcarrier-session-hash-key-at-least-32-bytes";

#[derive(Clone, Copy)]
pub(crate) enum Case {
    CurrentUser,
    ModelStorage,
    PrincipalIsolation,
    WindowGeneration,
    SessionCapabilities,
}
impl Case {
    fn id(self) -> &'static str {
        match self {
            Self::CurrentUser => "C8.typed-shared-application-current-user",
            Self::ModelStorage => "C8.typed-model-storage-http-window-roundtrip",
            Self::PrincipalIsolation => "C8.typed-principal-isolation",
            Self::WindowGeneration => "C8.window-unbind-generation-current-authority",
            Self::SessionCapabilities => "C8.session-revoke-capability-source-denial",
        }
    }
}
fn require(ok: bool, stage: &'static str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(stage.to_owned()) }
}

// Catch the entire setup/body and cleanup futures; an unexpected panic must still close owners.
async fn caught<F: Future>(future: F) -> Result<F::Output, String> {
    let mut future = Box::pin(future);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err("typedcarrier_panic_retained_as_failure".to_owned())),
        }
    })
    .await
}

pub(crate) async fn run(case: Case) {
    assert_eq!(
        std::env::var("OPENBOT_TYPED_CARRIER_OWNED_PG").as_deref(),
        Ok("1"),
        "owned_pg_marker_required"
    );
    let admin = harness::admin_config("typedcarrier");
    assert!(
        admin.user == "v7_comp023_admin"
            && admin.dbname == "postgres"
            && matches!(admin.host.as_str(), "127.0.0.1" | "::1")
            && admin.port > 1024,
        "owned_loopback_admin_required"
    );
    let head = std::env::var("OPENBOT_TYPED_CARRIER_SOURCE_HEAD").expect("source_head_required");
    let spec = std::env::var("OPENBOT_TYPED_CARRIER_SPEC_SHA").expect("spec_digest_required");
    assert!(
        head.len() == 40
            && spec.len() == 64
            && head
                .bytes()
                .chain(spec.bytes())
                .all(|b| b.is_ascii_hexdigit()),
        "source_metadata_shape"
    );
    harness::with_temp_database(&admin, "typedcarrier", |config| async move {
        let vault = CredentialRecordVault::single_key(
            TenantId::new("typedcarrier-tenant"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0xa1; 32]).map_err(|_| "owned_vault_key")?,
        );
        let pool = pool::connect(&config.clone().with_max_pool_size(8))
            .await
            .map_err(|_| "owned_pool_connect")?;
        let mut host = Host {
            pool,
            vault,
            assets: std::env::temp_dir().join(format!("openbot-typedcarrier-{}", Uuid::new_v4())),
            assembly: None,
            auth: None,
            transport: None,
            protocol: None,
            router: None,
            capability_replies: None,
            identities: Vec::new(),
            wire: Arc::new(AtomicUsize::new(0)),
        };
        let outcome = caught(async {
            host.prepare(config).await?;
            host.exercise(case).await
        })
        .await
        .and_then(|value| value);
        let cleanup = caught(host.finish()).await.and_then(|value| value);
        host.pool.close();
        cleanup?;
        outcome
    })
    .await;
    println!(
        "C8_EVIDENCE {}",
        json!({"caseId":case.id(),"sourceHead":head,"specSha256":spec,"sharedApplication":true,"positiveChecksPassed":true,"negativeChecksPassed":true,"ownedResourcesClosed":true})
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
// Observe the original production reply before either carrier returns/serializes it.
// Each fresh collector query advances its own opaque revision, so only the same
// original reply is an equality oracle. The delegate and its reply stay unchanged.
struct CapabilityReplyObserver {
    actual: Arc<dyn openbot_application::ApplicationService>,
    reply: Mutex<Option<RuntimeCapabilitiesResponse>>,
}
impl CapabilityReplyObserver {
    fn take_original(&self) -> Result<RuntimeCapabilitiesResponse, String> {
        self.reply
            .lock()
            .map_err(|_| "capability_observer_poisoned")?
            .take()
            .ok_or_else(|| "capability_original_reply_missing".to_owned())
    }
}
#[async_trait]
impl openbot_application::ApplicationService for CapabilityReplyObserver {
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        let reply = self.actual.execute(auth, command).await?;
        if let AppReply::RuntimeCapabilities(value) = &reply {
            let mut original = self
                .reply
                .lock()
                .map_err(|_| AppError::DependencyUnavailable {
                    dependency: "owned_capability_observer",
                })?;
            if original.is_some() {
                return Err(AppError::DependencyUnavailable {
                    dependency: "owned_capability_observer",
                });
            }
            *original = Some(value.clone());
        }
        Ok(reply)
    }
    async fn subscribe(
        &self,
        auth: AuthContext,
        request: SubscriptionRequest,
    ) -> Result<openbot_application::AppEventStream, AppError> {
        self.actual.subscribe(auth, request).await
    }
}

struct Host {
    pool: DatabasePool,
    vault: CredentialRecordVault,
    assets: PathBuf,
    assembly: Option<PostgresApplicationAssembly>,
    auth: Option<Arc<PostgresSessionAuthResolver>>,
    transport: Option<Arc<InProcessTransport>>,
    protocol: Option<DesktopTauriProtocol>,
    router: Option<Router>,
    capability_replies: Option<Arc<CapabilityReplyObserver>>,
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
        for (actor, token) in ACTORS.iter().zip(TOKENS) {
            let hash = SessionTokenHash::compute(
                SessionToken::new(token.as_bytes()),
                SessionHashKey::new(SESSION_KEY),
            )
            .to_column_value();
            let tx = client
                .transaction()
                .await
                .map_err(|_| "session_seed_begin")?;
            tx.execute(
                "INSERT INTO public.users(id,email,name,auth_generation) VALUES($1,$2,$1,0)",
                &[actor, &format!("{actor}@owned.test")],
            )
            .await
            .map_err(|_| "owned_user_seed")?;
            tx.execute(
                "INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')",
                &[actor],
            )
            .await
            .map_err(|_| "owned_role_seed")?;
            tx.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)", &[&Uuid::new_v4().to_string(), actor, &hash, &(now + time::Duration::hours(1)), &now]).await.map_err(|_| "owned_session_seed")?;
            tx.commit().await.map_err(|_| "session_seed_commit")?;
        }
        drop(client);
        let deployment = DeploymentId::new("typedcarrier-deployment");
        let tenant = TenantId::new("typedcarrier-tenant");
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
            self.identities.push(
                auth.resolve_with_assurance(&parts(token)?)
                    .await
                    .map_err(|_| "production_session_resolve")?,
            );
        }
        let policy = PolicyStore::postgres(self.pool.clone(), None);
        policy
            .set(
                ActionPolicy {
                    mode: PolicyMode::Enforce,
                    deny: vec!["true".to_owned()],
                    allow: Vec::new(),
                },
                None,
            )
            .await
            .map_err(|_| "deny_all_policy")?;
        policy.load().await.map_err(|_| "policy_load")?;
        self.assembly = Some(
            assemble_postgres_application(PostgresApplicationAssemblyInput {
                recovery_gate:
                    openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                        &self.pool,
                        &deployment,
                        &tenant,
                    ),
                pool: self.pool.clone(),
                listener_database: config.into(),
                deployment: deployment.clone(),
                tenant: tenant.clone(),
                single_user: false,
                admin_floor: None,
                model: "unused-typedcarrier-model".to_owned(),
                credential_key_id: "unused-typedcarrier-key".to_owned(),
                credential_vault: self.vault.clone(),
                audit_key: SecretBytes::new(vec![0xa2; 32]),
                remote_assertions: Arc::new(
                    RemoteRunAssertionSigner::new(vec![0xa3; 32])
                        .map_err(|_| "assertion_signer")?,
                ),
                mcp_oauth_state_key: SecretBytes::new(vec![0xa4; 32]),
                policy_store: policy,
                ui_preferences: Arc::new(
                    PostgresUiPreferenceAdministration::new(
                        self.pool.clone(),
                        deployment,
                        tenant,
                        SecretBytes::new(vec![0xa2; 32]),
                    )
                    .map_err(|_| "postgres_preferences")?,
                ),
                screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
                artifacts: None,
                runtime_capabilities: Some(
                    auth.runtime_capability_factory(None)
                        .map_err(|_| "production_capability_factory")?,
                ),
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
                extra_provider_adapters: Vec::new(),
                run_event_subscriber: None,
                delegation_authority: None,
            })
            .await
            .map_err(|_| "production_application_assembly")?,
        );
        let actual = self
            .assembly
            .as_ref()
            .ok_or("assembly_missing")?
            .application
            .clone();
        let observed = Arc::new(CapabilityReplyObserver {
            actual,
            reply: Mutex::new(None),
        });
        let application: Arc<dyn openbot_application::ApplicationService> = observed.clone();
        self.capability_replies = Some(observed);
        self.transport = Some(Arc::new(InProcessTransport::new(application.clone())));
        let transport = self.transport.as_ref().ok_or("transport_missing")?;
        require(
            Arc::ptr_eq(&application, transport.service()),
            "typed_application_allocation",
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
            "http_application_allocation",
        )?;
        self.router = Some(router(server)); // No listener/server task is started.
        std::fs::create_dir(&self.assets).map_err(|_| "owned_assets_create")?;
        std::fs::write(self.assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|_| "owned_index_write")?;
        std::fs::write(self.assets.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|_| "owned_bootstrap_write")?;
        self.protocol = Some(
            DesktopTauriProtocol::open(&self.assets, transport.clone())
                .map_err(|_| "production_window_protocol")?,
        );
        let protocol = self.protocol.as_ref().ok_or("protocol_missing")?;
        for (label, resolved) in ["main", "other"].into_iter().zip(&self.identities) {
            protocol
                .bind_window(label, resolved.context().clone(), None)
                .map_err(|_| "verified_window_bind")?;
            resolved
                .context()
                .request_binding()
                .ok_or("real_session_binding_missing")?
                .verify_current(resolved.context())
                .await
                .map_err(|_| "positive_session_guard")?;
        }
        snapshot(&self.pool).await?;
        Ok(())
    }

    async fn exercise(&self, case: Case) -> Result<(), String> {
        let transport = self.transport.as_ref().ok_or("transport_missing")?;
        let protocol = self.protocol.as_ref().ok_or("protocol_missing")?;
        let router = self.router.as_ref().ok_or("router_missing")?;
        let auth = self.auth.as_ref().ok_or("resolver_missing")?;
        let a = self.identities.first().ok_or("identity_a_missing")?;
        let b = self.identities.get(1).ok_or("identity_b_missing")?;
        let before = snapshot(&self.pool).await?;
        match case {
            Case::CurrentUser => {
                for (index, identity) in self.identities.iter().enumerate() {
                    let AppReply::CurrentUser(user) = transport
                        .execute(identity.context().clone(), AppCommand::GetCurrentUser)
                        .await
                        .map_err(|_| "typed_current_user")?
                    else {
                        return Err("typed_current_user_variant".to_owned());
                    };
                    require(
                        user.id == ActorId::new(ACTORS[index]) && user.role == Role::User,
                        "current_user_real_actor_role",
                    )?;
                    let (status, body) = http(router, TOKENS[index], "/api/me").await?;
                    let http_user: CurrentUserResponse =
                        serde_json::from_slice(&body).map_err(|_| "http_current_user_dto")?;
                    require(
                        status == StatusCode::OK && http_user.user == user,
                        "typed_http_current_user_parity",
                    )?;
                    let (status, body) = window(
                        protocol,
                        ["main", "other"][index],
                        TOKENS[1 - index],
                        "/api/me",
                    )
                    .await?;
                    let window_user: CurrentUserResponse =
                        serde_json::from_slice(&body).map_err(|_| "window_current_user_dto")?;
                    require(
                        status == StatusCode::OK && window_user.user == user,
                        "renderer_cookie_cannot_change_actor",
                    )?;
                }
                require(
                    window(protocol, "unknown", TOKENS[0], "/api/me").await?.0
                        == StatusCode::UNAUTHORIZED,
                    "unknown_window_refused",
                )?;
                require(
                    http(router, "missing-owned-session", "/api/me").await?.0
                        == StatusCode::UNAUTHORIZED,
                    "unverified_session_refused",
                )?;
            }
            Case::ModelStorage | Case::PrincipalIsolation | Case::WindowGeneration => {
                let model = self.create(transport, a.context()).await?;
                let path = format!("/api/me/model-connections/{}", model.id);
                let stable = snapshot(&self.pool).await?;
                let (status, body) = http(router, TOKENS[0], &path).await?;
                let http_model: ModelConnection =
                    serde_json::from_slice(&body).map_err(|_| "http_model_dto")?;
                require(
                    status == StatusCode::OK && http_model == model,
                    "typed_http_model_parity",
                )?;
                let (status, body) = window(protocol, "main", TOKENS[1], &path).await?;
                let window_model: ModelConnection =
                    serde_json::from_slice(&body).map_err(|_| "window_model_dto")?;
                require(
                    status == StatusCode::OK && window_model == model,
                    "typed_window_model_parity",
                )?;
                match case {
                    Case::ModelStorage => {
                        let mut invalid = model_input()?;
                        invalid.name.clear();
                        require(
                            matches!(
                                transport
                                    .execute(
                                        a.context().clone(),
                                        AppCommand::CreateModelConnection(invalid)
                                    )
                                    .await,
                                Err(AppError::MalformedPayload { .. })
                            ),
                            "invalid_model_no_mutation",
                        )?;
                    }
                    Case::PrincipalIsolation => {
                        require(
                            matches!(
                                transport
                                    .execute(
                                        b.context().clone(),
                                        AppCommand::GetModelConnection {
                                            connection_id: model.id.clone()
                                        }
                                    )
                                    .await,
                                Err(AppError::NotVisible)
                            ),
                            "typed_other_owner_refused",
                        )?;
                        require(
                            http(router, TOKENS[1], &path).await?.0 == StatusCode::NOT_FOUND
                                && window(protocol, "other", TOKENS[0], &path).await?.0
                                    == StatusCode::NOT_FOUND,
                            "http_window_other_owner_refused",
                        )?;
                        let AppReply::ModelConnections(page) = transport
                            .execute(
                                b.context().clone(),
                                AppCommand::ListModelConnections(ModelConnectionPageRequest {
                                    cursor: None,
                                }),
                            )
                            .await
                            .map_err(|_| "typed_other_inventory")?
                        else {
                            return Err("other_inventory_variant".to_owned());
                        };
                        require(page.connections.is_empty(), "other_owner_inventory_empty")?;
                    }
                    Case::WindowGeneration => {
                        require(
                            protocol
                                .bind_window("main", b.context().clone(), None)
                                .is_err(),
                            "bound_label_replacement_refused",
                        )?;
                        require(
                            protocol
                                .unbind_window("main")
                                .map_err(|_| "window_unbind")?,
                            "window_removed",
                        )?;
                        require(
                            window(protocol, "main", TOKENS[0], &path).await?.0
                                == StatusCode::UNAUTHORIZED,
                            "closed_window_refused",
                        )?;
                        protocol
                            .bind_window("main", b.context().clone(), None)
                            .map_err(|_| "same_label_new_binding")?;
                        require(
                            window(protocol, "main", TOKENS[0], &path).await?.0
                                == StatusCode::NOT_FOUND,
                            "rebound_label_new_principal",
                        )?;
                        protocol
                            .unbind_window("main")
                            .map_err(|_| "rebound_unbind")?;
                        protocol
                            .bind_window("main", a.context().clone(), None)
                            .map_err(|_| "verified_a_rebind")?;
                        require(
                            window(protocol, "main", TOKENS[0], &path).await?.0 == StatusCode::OK,
                            "rebound_positive_before_generation",
                        )?;
                        let client = self.pool.get().await.map_err(|_| "generation_connection")?;
                        require(client.execute("UPDATE public.users SET auth_generation=auth_generation+1 WHERE id=$1 AND auth_generation=0", &[&ACTORS[0]]).await.map_err(|_| "owned_generation_update")? == 1, "one_actor_generation_advanced")?;
                        drop(client);
                        let changed = snapshot(&self.pool).await?;
                        let mut expected = stable.clone();
                        expected["users"][0]["auth_generation"] = json!(1);
                        require(changed == expected, "generation_only_one_row_changed")?;
                        require(
                            matches!(
                                transport
                                    .execute(
                                        a.context().clone(),
                                        AppCommand::GetModelConnection {
                                            connection_id: model.id.clone()
                                        }
                                    )
                                    .await,
                                Err(AppError::NotVisible)
                            ),
                            "typed_stale_generation_refused",
                        )?;
                        require(
                            window(protocol, "main", TOKENS[0], &path).await?.0
                                == StatusCode::NOT_FOUND
                                && http(router, TOKENS[0], &path).await?.0
                                    == StatusCode::UNAUTHORIZED,
                            "window_http_stale_generation_refused",
                        )?;
                        require(
                            a.context()
                                .request_binding()
                                .ok_or("binding_missing")?
                                .verify_current(a.context())
                                .await
                                == Err(HostRequestBindingError::NotCurrent),
                            "real_guard_stale_generation_refused",
                        )?;
                        require(
                            http(router, TOKENS[1], "/api/me").await?.0 == StatusCode::OK,
                            "other_actor_remains_current",
                        )?;
                        require(
                            snapshot(&self.pool).await? == changed,
                            "generation_refusals_read_only",
                        )?;
                        return Ok(());
                    }
                    _ => return Err("unexpected_model_case".to_owned()),
                }
                require(
                    snapshot(&self.pool).await? == stable,
                    "model_reads_refusals_read_only",
                )?;
                return Ok(());
            }
            Case::SessionCapabilities => {
                let AppReply::RuntimeCapabilities(typed) = transport
                    .execute(a.context().clone(), AppCommand::GetRuntimeCapabilities)
                    .await
                    .map_err(|_| "typed_real_capabilities")?
                else {
                    return Err("capabilities_variant".to_owned());
                };
                let original_typed = self
                    .capability_replies
                    .as_ref()
                    .ok_or("capability_observer_missing")?
                    .take_original()?;
                let (status, body) = http(router, TOKENS[0], "/api/me/capabilities").await?;
                let original_http = self
                    .capability_replies
                    .as_ref()
                    .ok_or("capability_observer_missing")?
                    .take_original()?;
                let from_http: RuntimeCapabilitiesResponse =
                    serde_json::from_slice(&body).map_err(|_| "http_capability_dto")?;
                require(
                    status == StatusCode::OK
                        && typed.host_mode() == RuntimeCapabilityHostMode::Server
                        && typed.capabilities().len() == 13
                        && typed == original_typed
                        && from_http == original_http
                        && from_http.schema_version() == typed.schema_version()
                        && from_http.host_mode() == typed.host_mode()
                        && from_http.capabilities() == typed.capabilities()
                        && from_http.revision() != typed.revision(),
                    "typed_http_actual_server_capabilities",
                )?;
                require(
                    window(protocol, "main", TOKENS[0], "/api/me").await?.0 == StatusCode::OK,
                    "bound_window_positive_control",
                )?;
                require(
                    window(protocol, "main", TOKENS[0], "/api/me/capabilities")
                        .await?
                        .0
                        == StatusCode::UNAUTHORIZED,
                    "server_collector_window_issuer_refused",
                )?;
                require(
                    snapshot(&self.pool).await? == before,
                    "capability_positive_and_source_denial_read_only",
                )?;
                auth.revoke_session(a)
                    .await
                    .map_err(|_| "production_session_revoke")?;
                let revoked = snapshot(&self.pool).await?;
                let mut expected = before.clone();
                expected["sessions"]
                    .as_array_mut()
                    .ok_or("session_snapshot_shape")?
                    .retain(|row| row["user_id"] != ACTORS[0]);
                require(revoked == expected, "exact_owned_session_deleted")?;
                require(
                    matches!(
                        auth.resolve_with_assurance(&parts(TOKENS[0])?).await,
                        Err(AppError::Unauthenticated)
                    ),
                    "revoked_session_resolve_refused",
                )?;
                require(
                    a.context()
                        .request_binding()
                        .ok_or("binding_missing")?
                        .verify_current(a.context())
                        .await
                        == Err(HostRequestBindingError::NotCurrent),
                    "original_session_guard_revoked",
                )?;
                require(
                    matches!(
                        transport
                            .execute(a.context().clone(), AppCommand::GetRuntimeCapabilities)
                            .await,
                        Err(AppError::Unauthenticated)
                    ) && http(router, TOKENS[0], "/api/me/capabilities").await?.0
                        == StatusCode::UNAUTHORIZED,
                    "typed_http_revoked_capabilities_refused",
                )?;
                require(
                    matches!(
                        transport
                            .execute(b.context().clone(), AppCommand::GetRuntimeCapabilities)
                            .await,
                        Ok(AppReply::RuntimeCapabilities(_))
                    ),
                    "other_session_capability_positive",
                )?;
                // Models check actor/generation, not sessions; this is intentionally still readable.
                require(
                    window(protocol, "main", TOKENS[0], "/api/me/model-connections")
                        .await?
                        .0
                        == StatusCode::OK,
                    "models_do_not_invent_session_guard",
                )?;
                auth.close_request_bindings();
                require(
                    matches!(
                        transport
                            .execute(b.context().clone(), AppCommand::GetRuntimeCapabilities)
                            .await,
                        Err(AppError::Unauthenticated)
                    ),
                    "closed_resolver_source_refused",
                )?;
                require(
                    snapshot(&self.pool).await? == revoked,
                    "session_revocation_checks_read_only",
                )?;
                return Ok(());
            }
        }
        require(
            snapshot(&self.pool).await? == before,
            "current_user_business_read_only",
        )
    }

    async fn create(
        &self,
        transport: &InProcessTransport,
        auth: &AuthContext,
    ) -> Result<ModelConnection, String> {
        let before = snapshot(&self.pool).await?;
        let AppReply::ModelConnection(model) = transport
            .execute(
                auth.clone(),
                AppCommand::CreateModelConnection(model_input()?),
            )
            .await
            .map_err(|_| "typed_model_create")?
        else {
            return Err("model_create_variant".to_owned());
        };
        require(
            model.revision == 1 && model.has_credential && !model.enabled,
            "actual_created_model",
        )?;
        let after = snapshot(&self.pool).await?;
        // The first audit event creates the production genesis checkpoint in the same commit.
        require(
            before["audit"] == json!([]) && before["checkpoints"] == json!([]),
            "fresh_audit_chain",
        )?;
        for table in ["models", "secrets", "audit", "checkpoints"] {
            let old = before[table].as_array().ok_or("snapshot_array")?;
            let new = after[table].as_array().ok_or("snapshot_array")?;
            require(
                new.len() == old.len() + 1 && new.starts_with(old),
                "create_exact_single_row_deltas",
            )?;
        }
        let mut rest = after.clone();
        for table in ["models", "secrets", "audit", "checkpoints"] {
            rest[table] = before[table].clone();
        }
        require(rest == before, "create_other_business_unchanged")?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| "vault_record_connection")?;
        let id = Uuid::parse_str(&model.id).map_err(|_| "model_uuid")?;
        let row = client.query_one("SELECT s.id,s.encrypted_value,s.owner_user_id FROM public.model_connection_secrets s JOIN public.model_connections c ON c.current_secret_id=s.id AND c.id=s.connection_id WHERE c.id=$1", &[&id]).await.map_err(|_| "actual_secret_record")?;
        let secret_id: Uuid = row.try_get(0).map_err(|_| "secret_uuid")?;
        let encrypted: String = row.try_get(1).map_err(|_| "secret_envelope")?;
        let owner: String = row.try_get(2).map_err(|_| "secret_owner")?;
        require(
            owner == ACTORS[0] && !encrypted.contains(KEY),
            "pg_secret_owner_and_ciphertext",
        )?;
        let consumer = SecretPrincipal::Service(ServiceId::new(model.id.clone()));
        let opened = self
            .vault
            .open(
                &secret_id,
                SecretKind::Model,
                SecretPrincipal::Actor(auth.actor().clone()),
                consumer.clone(),
                &encrypted,
            )
            .map_err(|_| "production_vault_open")?;
        require(
            !opened.needs_migration()
                && opened
                    .into_secret()
                    .ct_eq(&SecretBytes::new(KEY.as_bytes().to_vec())),
            "actual_v2_vault_roundtrip",
        )?;
        require(
            self.vault
                .open(
                    &secret_id,
                    SecretKind::Model,
                    SecretPrincipal::Actor(ActorId::new(ACTORS[1])),
                    consumer,
                    &encrypted,
                )
                .is_err(),
            "actual_envelope_other_owner_refused",
        )?;
        Ok(model)
    }

    async fn finish(&mut self) -> Result<(), String> {
        let mut clean = true;
        if let Some(auth) = &self.auth {
            auth.close_request_bindings();
        }
        if let Some(protocol) = self.protocol.take() {
            for label in ["main", "other"] {
                clean &= protocol.unbind_window(label).is_ok();
            }
            drop(protocol);
        }
        self.router.take(); // In-memory Router has no server task or socket to join.
        if let Some(transport) = self.transport.take() {
            let report = transport.shutdown().await;
            clean &= report.within_deadline && report.pumps_total == 0 && report.pumps_aborted == 0;
        }
        if let Some(assembly) = self.assembly.take() {
            assembly.shutdown().await;
        }
        self.capability_replies.take();
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
            "owned_resources_or_wire_not_closed",
        )
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
fn model_input() -> Result<CreateModelConnection, String> {
    Ok(CreateModelConnection {
        name: "Owned typed carrier model".to_owned(),
        protocol: CustomModelProtocol::OpenaiChatCompletions,
        endpoint: "https://models.typedcarrier.test/v1".to_owned(),
        model: "owned-disabled-model".to_owned(),
        enabled: false,
        api_key: ModelApiKey::new(KEY.to_owned().into()).map_err(|_| "owned_model_key_shape")?,
    })
}
fn safe_body(body: &[u8]) -> Result<(), String> {
    require(
        [KEY, TOKENS[0], TOKENS[1]].iter().all(|secret| {
            !body
                .windows(secret.len())
                .any(|part| part == secret.as_bytes())
        }),
        "response_secret_leak",
    )
}
async fn http(router: &Router, token: &str, path: &str) -> Result<(StatusCode, Vec<u8>), String> {
    let mut request = Request::builder()
        .uri(path)
        .header(COOKIE, format!("openbot_session={token}"))
        .body(Body::empty())
        .map_err(|_| "http_request")?;
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:32123"
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "owned_peer")?,
    ));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .map_err(|_| "http_router")?;
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .map_err(|_| "http_body")?
        .to_vec();
    safe_body(&body)?;
    Ok((status, body))
}
async fn window(
    protocol: &DesktopTauriProtocol,
    label: &str,
    token: &str,
    path: &str,
) -> Result<(StatusCode, Vec<u8>), String> {
    let request = Request::builder()
        .uri(path)
        .header(COOKIE, format!("openbot_session={token}"))
        .body(Vec::new())
        .map_err(|_| "window_request")?;
    let response = protocol.handle(label, request).await;
    safe_body(response.body())?;
    Ok((response.status(), response.into_body()))
}

// Session idle updated_at legitimately advances on ordinary HTTP GET; every other owned
// session field participates. No secret/ciphertext or audit signature enters this projection.
const BUSINESS: &str = "SELECT jsonb_build_object(
 'users',(SELECT coalesce(jsonb_agg(to_jsonb(u) ORDER BY id),'[]'::jsonb) FROM public.users u),
 'roles',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY user_id,role),'[]'::jsonb) FROM public.user_roles r),
 'sessions',(SELECT coalesce(jsonb_agg((to_jsonb(s)-'token'-'updated_at') ORDER BY user_id,id),'[]'::jsonb) FROM public.sessions s),
 'models',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb) FROM public.model_connections m),
 'secrets',(SELECT coalesce(jsonb_agg((to_jsonb(s)-'encrypted_value') ORDER BY id),'[]'::jsonb) FROM public.model_connection_secrets s),
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM public.audit_events a),
 'checkpoints',(SELECT coalesce(jsonb_agg((to_jsonb(c)-'signature') ORDER BY sequence),'[]'::jsonb) FROM public.audit_checkpoints c),
 'policy',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY id),'[]'::jsonb) FROM public.action_policy p),
 'quiet',jsonb_build_array((SELECT count(*) FROM public.agents),(SELECT count(*) FROM public.runs),(SELECT count(*) FROM public.run_events),(SELECT count(*) FROM public.outbox),(SELECT count(*) FROM public.tool_calls),(SELECT count(*) FROM public.tool_attempts),(SELECT count(*) FROM public.remember_effect_receipts),(SELECT count(*) FROM public.memories)))";
async fn snapshot(pool: &DatabasePool) -> Result<Value, String> {
    let mut client = pool.get().await.map_err(|_| "readonly_connection")?;
    let tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "readonly_begin")?;
    let identity = tx
        .query_one(
            "SELECT current_database(),current_user,current_setting('transaction_read_only')",
            &[],
        )
        .await
        .map_err(|_| "readonly_pg_identity")?;
    let db: String = identity.try_get(0).map_err(|_| "database_identity")?;
    let user: String = identity.try_get(1).map_err(|_| "database_user")?;
    let readonly: String = identity.try_get(2).map_err(|_| "readonly_setting")?;
    require(
        db.starts_with("openbot_it_typedcarrier_")
            && user == "v7_comp023_admin"
            && readonly == "on",
        "owned_pg_readonly_identity",
    )?;
    let value: Value = tx
        .query_one(BUSINESS, &[])
        .await
        .map_err(|_| "readonly_business")?
        .try_get(0)
        .map_err(|_| "business_shape")?;
    require(
        value["quiet"] == json!([0, 0, 0, 0, 0, 0, 0, 0]),
        "unexpected_run_tool_or_effect",
    )?;
    tx.commit().await.map_err(|_| "readonly_commit")?;
    Ok(value)
}
