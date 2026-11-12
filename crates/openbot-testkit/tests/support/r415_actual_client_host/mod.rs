//! Dedicated fixture; every business route uses the production PostgreSQL assembly.

mod control;
mod gates;
mod observe;
mod read_fault;

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::identity::session::TrustedOrigins;
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssemblyInput, assemble_postgres_application,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::db::{fresh, pool};
use openbot_infra::policy::PolicyStore;
use openbot_infra::ui_preferences::PostgresUiPreferenceAdministration;
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::config::{EnvMap, ServerConfig};
use openbot_server::{
    PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder, StaticApp,
};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc, oneshot};
use url::Url;

const DEPLOYMENT: &str = "owned-r415-client-deployment";
const TENANT: &str = "owned-r415-client-tenant";
const SESSION_KEY: &[u8] = b"owned-r415-client-session-key-at-least-32-bytes";
const TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone)]
struct Case {
    id: String,
    object: String,
    scope: String,
    actor: String,
    session_a: String,
    token_a: String,
    token_b: String,
    slug: String,
    object_id: Option<String>,
    bound: bool,
    closed: bool,
    fault_enabled: bool,
}

impl Case {
    fn update_path(&self) -> Result<String, String> {
        match self.object.as_str() {
            "models" => self
                .object_id
                .as_ref()
                .map(|id| format!("/api/me/model-connections/{id}"))
                .ok_or_else(|| "object_not_bound".to_owned()),
            "sandbox" => Ok("/api/sandboxed".to_owned()),
            "skills" => Ok("/api/plugins/skills".to_owned()),
            "preferences" => Ok("/api/me/preferences".to_owned()),
            _ => Err("invalid_object".to_owned()),
        }
    }

    fn method(&self) -> &'static str {
        if self.object == "models" || self.object == "preferences" {
            "PUT"
        } else {
            "POST"
        }
    }
}

struct State {
    observer: Pool,
    cases: Mutex<BTreeMap<String, Case>>,
    gates: Mutex<BTreeMap<String, Arc<gates::Gate>>>,
    read_controls: Mutex<BTreeMap<String, Arc<read_fault::ReadControl>>>,
    used_controls: Mutex<std::collections::BTreeSet<String>>,
    requests: Mutex<Vec<Value>>,
    controls: Mutex<Vec<Value>>,
    collection_error: Mutex<Option<&'static str>>,
    sequence: AtomicU64,
    api_ingress_count: AtomicU64,
    remote_calls: Arc<AtomicU64>,
}

impl State {
    async fn fail_collection(&self, reason: &'static str) {
        let mut error = self.collection_error.lock().await;
        if error.is_none() {
            *error = Some(reason);
        }
    }

    async fn reserve_control_id(&self, id: &str) -> Result<(), String> {
        let mut used = self.used_controls.lock().await;
        if used.contains(id) {
            return Err("transport_control_id_reused".to_owned());
        }
        if used.len() >= 512 {
            drop(used);
            self.fail_collection("transport_control_record_limit").await;
            return Err("transport_control_record_limit".to_owned());
        }
        used.insert(id.to_owned());
        Ok(())
    }

    async fn record_control(&self, value: Value) -> Result<(), String> {
        let mut records = self.controls.lock().await;
        if records.len() >= 512 {
            drop(records);
            self.fail_collection("fixture_control_record_limit").await;
            return Err("fixture_control_record_limit".to_owned());
        }
        records.push(value);
        Ok(())
    }
}

struct UnavailableRemote(Arc<AtomicU64>);

#[async_trait]
impl RemoteAguiTransport for UnavailableRemote {
    async fn validate_endpoint(&self, _endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(RemoteAguiTransportError::Unavailable)
    }

    async fn start(
        &self,
        _endpoint: &str,
        _authorization: Option<&openbot_application::RemoteAguiAuthorization>,
        _body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(RemoteAguiTransportError::Unavailable)
    }
}

fn emit(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|_| "protocol_encode")?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // libtest may leave its test-name prelude unterminated; the protocol starts a fresh line.
    writeln!(out, "\nR415_HOST {text}").map_err(|_| "protocol_write")?;
    out.flush().map_err(|_| "protocol_flush".to_owned())
}

fn stdin_owner() -> (
    mpsc::Receiver<Result<Value, String>>,
    std::thread::JoinHandle<()>,
) {
    let (sender, receiver) = mpsc::channel(8);
    let thread = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut bytes = Vec::new();
            let message = loop {
                let available = match input.fill_buf() {
                    Ok(v) => v,
                    Err(_) => break Err("protocol_read".to_owned()),
                };
                if available.is_empty() {
                    if bytes.is_empty() {
                        return;
                    }
                    break Err("protocol_partial_eof".to_owned());
                }
                let length = available
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(available.len(), |n| n + 1);
                if bytes.len() + length > 65_536 {
                    break Err("protocol_line_limit".to_owned());
                }
                let newline = available[length - 1] == b'\n';
                bytes.extend_from_slice(&available[..length]);
                input.consume(length);
                if newline {
                    break serde_json::from_slice(&bytes)
                        .map_err(|_| "protocol_invalid_json_or_utf8".to_owned());
                }
            };
            let invalid = message.is_err();
            if sender.blocking_send(message).is_err() || invalid {
                break;
            }
        }
    });
    (receiver, thread)
}

pub(super) async fn run(config: pool::DatabaseConfig) -> Result<(), String> {
    // No DB URL/config is ever included in IPC, diagnostics or errors.
    let dist = std::env::var("R415_CLIENT_DIST").map_err(|_| "missing_owned_dist")?;
    let source_head = std::env::var("R415_SOURCE_HEAD").map_err(|_| "missing_source_head")?;
    let spec_sha = std::env::var("R415_SPEC_SHA256").map_err(|_| "missing_spec_sha")?;
    if source_head.len() != 40 || spec_sha.len() != 64 || !std::path::Path::new(&dist).is_absolute()
    {
        return Err("invalid_outer_receipt_identity".to_owned());
    }
    let static_app = StaticApp::open(&dist).map_err(|_| "invalid_owned_dist")?;
    let application_pool = pool::connect(&config)
        .await
        .map_err(|_| "application_pool")?;
    let mut observer_config = config.clone();
    observer_config.application_name = Some("owned-r415-independent-observer".to_owned());
    observer_config.max_pool_size = 4;
    let observer_pool = pool::connect(&observer_config)
        .await
        .map_err(|_| "observer_pool")?;
    let mut client = application_pool
        .get()
        .await
        .map_err(|_| "migration_connection")?;
    fresh::apply(&mut client)
        .await
        .map_err(|_| "fresh_owned_migration")?;
    drop(client);
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| "owned_bind")?;
    let address = listener.local_addr().map_err(|_| "owned_local_address")?;
    let origin = format!("http://{address}");
    let tenant = TenantId::new(TENANT);
    let vault = CredentialRecordVault::single_key(
        tenant.clone(),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x71; 32]).map_err(|_| "owned_vault_key")?,
    );
    let policies = PolicyStore::postgres(application_pool.clone(), None);
    policies.load().await.map_err(|_| "owned_policy_load")?;
    let remote_calls = Arc::new(AtomicU64::new(0));
    let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
        recovery_gate: openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
            &application_pool,
            &DeploymentId::new(DEPLOYMENT),
            &tenant,
        ),
        pool: application_pool.clone(),
        listener_database: config.clone().into(),
        deployment: DeploymentId::new(DEPLOYMENT),
        tenant: tenant.clone(),
        single_user: false,
        admin_floor: None,
        model: "unused-routing-model".to_owned(),
        credential_key_id: "unused-routing-key".to_owned(),
        credential_vault: vault,
        audit_key: SecretBytes::new(vec![0x72; 32]),
        remote_assertions: Arc::new(
            RemoteRunAssertionSigner::new(vec![0x73; 32]).map_err(|_| "owned_assertion_key")?,
        ),
        mcp_oauth_state_key: SecretBytes::new(vec![0x74; 32]),
        policy_store: policies,
        ui_preferences: Arc::new(
            PostgresUiPreferenceAdministration::new(
                application_pool.clone(),
                DeploymentId::new(DEPLOYMENT),
                tenant.clone(),
                SecretBytes::new(vec![0x72; 32]),
            )
            .map_err(|_| "owned_preferences_adapter")?,
        ),
        screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
        artifacts: None,
        runtime_capabilities: None,
        remote_agent_probe: Arc::new(UnavailableRemote(remote_calls.clone())),
        managed_slot_available: false,
        channel_routing_provider: ChannelRoutingProviderInput {
            endpoint: Url::parse("http://127.0.0.1:9/v1/chat/completions")
                .map_err(|_| "owned_unused_endpoint")?,
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
    .map_err(|_| "owned_production_assembly")?;
    let resolver = Arc::new(
        PostgresSessionAuthResolver::new(
            application_pool.clone(),
            SESSION_KEY,
            default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT),
            tenant,
        )
        .map_err(|_| "owned_session_resolver")?,
    );
    let state = Arc::new(State {
        observer: observer_pool.clone(),
        cases: Mutex::new(BTreeMap::new()),
        gates: Mutex::new(BTreeMap::new()),
        read_controls: Mutex::new(BTreeMap::new()),
        used_controls: Mutex::new(std::collections::BTreeSet::new()),
        requests: Mutex::new(Vec::new()),
        controls: Mutex::new(Vec::new()),
        collection_error: Mutex::new(None),
        sequence: AtomicU64::new(0),
        api_ingress_count: AtomicU64::new(0),
        remote_calls,
    });
    let transport = ServerConfig::from_env_map(&EnvMap::new())
        .map_err(|_| "owned_transport_config")?
        .transport_policy(true);
    let router = ServerBuilder::new(assembly.application.clone(), resolver.clone())
        .with_transport_policy(transport)
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            default_session_lifetime(),
            TrustedOrigins::from_configured([origin.as_str()]).map_err(|_| "owned_origin")?,
        ))
        .with_static_app(static_app)
        .into_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            gates::observe_response,
        ));
    let (stop_sender, stop_receiver) = oneshot::channel();
    let mut listener_task = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_receiver.await;
        })
        .await
    });
    let (mut input, stdin_thread) = stdin_owner();
    let result = async {
        emit(&json!({"schemaVersion":1,"event":"ready","origin":origin,"dist":dist,
            "sourceHead":source_head,"specSha256":spec_sha,
            "producer":"PostgresApplicationAssembly/ApplicationService/SessionAuthResolver/ServerBuilder.StaticApp/Axum.ConnectInfo",
            "remote":"validate_endpoint/start typed Unavailable; no IO","caseEvidence":"none"}))?;
        let mut command_ids = std::collections::BTreeSet::new();
        loop {
            let message = tokio::time::timeout(Duration::from_secs(90),input.recv()).await
                .map_err(|_| "protocol_idle_timeout")?.ok_or("protocol_unexpected_eof")??;
            let id = control::text(&message,"id")?.to_owned();
            if id.len()>64 || !command_ids.insert(id.clone()) { return Err("protocol_duplicate_or_long_id".to_owned()); }
            if command_ids.len()>4096 { return Err("protocol_command_limit".to_owned()); }
            let reply = control::execute(&state,&message).await;
            let shutdown = reply.is_ok() && control::text(&message,"command")? == "shutdown";
            let frame = match reply {
                Ok(value) => json!({"schemaVersion":1,"id":id,"ok":true,"result":value}),
                Err(error) => json!({"schemaVersion":1,"id":id,"ok":false,"error":error}),
            };
            emit(&frame)?;
            if shutdown { return Ok::<(),String>(()); }
        }
    }.await;
    gates::close_all(&state).await;
    read_fault::close_all(&state).await;
    let _ = stop_sender.send(());
    let listener_joined = match tokio::time::timeout(TIMEOUT, &mut listener_task).await {
        Ok(Ok(Ok(()))) => true,
        _ => {
            listener_task.abort();
            let _ = listener_task.await;
            false
        }
    };
    resolver.close_request_bindings();
    let assembly_closed = tokio::time::timeout(TIMEOUT, assembly.shutdown())
        .await
        .is_ok();
    observer_pool.close();
    application_pool.close();
    drop(input);
    // The driver closes the pipe after shutdown. EOF is a required observed cleanup boundary.
    let mut stdin_join = tokio::task::spawn_blocking(move || stdin_thread.join());
    let stdin_joined = matches!(
        tokio::time::timeout(TIMEOUT, &mut stdin_join).await,
        Ok(Ok(Ok(())))
    );
    let remaining = gates::open_count(&state).await;
    let remaining_read = read_fault::open_count(&state).await;
    let collection_error = *state.collection_error.lock().await;
    let control_failures =
        gates::failed_count(&state).await + read_fault::failed_count(&state).await;
    let remote = state.remote_calls.load(Ordering::Relaxed);
    emit(
        &json!({"schemaVersion":1,"event":"closed","listenerJoined":listener_joined,
        "assemblyClosed":assembly_closed,"stdinJoined":stdin_joined,"remainingGates":remaining,
        "remainingReadControls":remaining_read,"collectionFailed":collection_error.is_some(),
        "collectionError":collection_error,"transportControlFailures":control_failures,"remoteCalls":remote}),
    )?;
    if !listener_joined
        || !assembly_closed
        || !stdin_joined
        || remaining != 0
        || remaining_read != 0
    {
        return Err("owned_cleanup_incomplete".to_owned());
    }
    if collection_error.is_some() {
        return Err("owned_evidence_collection_failed".to_owned());
    }
    if control_failures != 0 {
        return Err("owned_transport_control_failed".to_owned());
    }
    result
}
