//! Actual SDK5 -> PostgreSQL/Vault authority -> production transport -> owned TLS.
//! Every test is opt-in because it creates an isolated PostgreSQL database and local TLS listener.

#[path = "harness/mod.rs"]
mod harness;

use acosmi::{Client, Config, TokenSet};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openbot_application::PeopleAdministration;
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    ids::{ActorId, DeploymentId, TenantId},
};
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::{
    db::{fresh, pool},
    gateway_authority::{GatewayAuthorityError, PostgresGatewayAccounts},
    gateway_transport::{GatewayAttempt, GatewayAttemptSnapshot, GatewayHttpOutcomes},
    net::safe_http::{CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer},
    repo::people_admin::PostgresPeopleAdministration,
    vault::CredentialRecordVault,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

include!("gateway_sdk_transport/tls.rs");

#[path = "gateway_authority/enroll_ready.rs"]
mod enroll_ready;
#[path = "gateway_authority/pending_failures.rs"]
mod pending_failures;
#[path = "gateway_authority/rotation_and_revoke.rs"]
mod rotation_and_revoke;

const DEPLOYMENT: &str = "sdk-gateway-deployment";
const TENANT: &str = "sdk-gateway-tenant";
const ACTOR: &str = "alice";
const CLIENT_ID: &str = "wrok-owned-client";
const ACCOUNT_ID: &str = "gateway-account-opaque";
const AUDIT_KEY: &[u8] = b"sdk-gateway-audit-checkpoint-key-32";

#[derive(Default)]
struct Outcomes(Mutex<Vec<GatewayAttempt>>);

impl GatewayHttpOutcomes for Outcomes {
    fn started(&self, attempt: GatewayAttempt) {
        let mut attempts = self.0.lock().unwrap();
        assert!(attempts.len() < 64);
        attempts.push(attempt);
    }
}

impl Outcomes {
    fn snapshots(&self) -> Vec<GatewayAttemptSnapshot> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(GatewayAttempt::snapshot)
            .collect()
    }
}

struct DatabaseFixture {
    pool: openbot_infra::db::pool::DatabasePool,
    vault: CredentialRecordVault,
    accounts: PostgresGatewayAccounts,
}

impl DatabaseFixture {
    async fn new(config: openbot_infra::db::pool::DatabaseConfig, tls: &TlsFixture) -> Self {
        let pool = pool::connect(&config.with_max_pool_size(16)).await.unwrap();
        let mut client = pool.get().await.unwrap();
        fresh::apply(&mut client).await.unwrap();
        client
            .batch_execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES
                   ('alice','alice@example.test',7),('bob','bob@example.test',3),
                   ('charlie','charlie@example.test',1);
                 INSERT INTO public.user_roles(user_id,role) VALUES
                   ('alice','user'),('bob','admin');",
            )
            .await
            .unwrap();
        drop(client);
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x47; 32]).unwrap(),
        );
        let accounts = PostgresGatewayAccounts::new(
            pool.clone(),
            vault.clone(),
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
            SecretBytes::new(AUDIT_KEY.to_vec()),
            tls.dialer_with(false, true),
            &tls.endpoint(),
            openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                &pool,
                &DeploymentId::new(DEPLOYMENT),
                &TenantId::new(TENANT),
            ),
        )
        .unwrap();
        Self {
            pool,
            vault,
            accounts,
        }
    }
}

fn auth(actor: &str, generation: u64, role: Role) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        ActorId::new(actor),
        AuthGeneration::new(generation),
        false,
    )
    .with_roles([role])
    .build()
}

fn owner() -> AuthContext {
    auth(ACTOR, 7, Role::User)
}

fn json_plan(body: String) -> ResponsePlan {
    let mut plan = ResponsePlan::ok(body);
    plan.content_type = "application/json";
    plan
}

fn metadata_body() -> String {
    json!({
        "issuer": "OWNED_ORIGIN",
        "authorization_endpoint": "OWNED_ORIGIN/oauth/desktop/authorize",
        "token_endpoint": "OWNED_ORIGIN/oauth/desktop/token",
        "registration_endpoint": "OWNED_ORIGIN/oauth/desktop/register",
        "revocation_endpoint": "OWNED_ORIGIN/oauth/desktop/revoke",
        "scopes_supported": ["ai", "account"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "crabcode_auth_contract_version": 2,
        "gateway_error_contract_version": 1
    })
    .to_string()
}

fn profile_body(account_id: &str, organization_id: &str) -> String {
    json!({
        "id": account_id,
        "uuid": account_id,
        "account": {"uuid": account_id, "email": "must-not-persist@example.test"},
        "organization": {"uuid": organization_id},
        "name": "must not persist"
    })
    .to_string()
}

fn tokens(origin: &str, expired: bool, generation: u8) -> TokenSet {
    TokenSet {
        access_token: format!("QA_ACCESS_{generation}"),
        refresh_token: format!("QA_REFRESH_{generation}"),
        expires_at: if expired {
            "2000-01-01T00:00:00Z"
        } else {
            "2099-01-01T00:00:00Z"
        }
        .to_owned(),
        scope: "ai account".to_owned(),
        client_id: CLIENT_ID.to_owned(),
        server_url: origin.to_owned(),
    }
}

fn refresh_response(generation: u8) -> String {
    json!({
        "access_token": format!("QA_ACCESS_{generation}"),
        "refresh_token": format!("QA_REFRESH_{generation}"),
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "ai account"
    })
    .to_string()
}

fn catalogue() -> String {
    json!({"code":0,"data":[{
        "id":"qa-model","name":"QA","provider":"openai","modelId":"qa-upstream",
        "maxTokens":256,"isEnabled":true,
        "capabilities":{
            "supports_thinking":false,"supports_adaptive_thinking":false,
            "supports_isp":false,"supports_web_search":false,
            "supports_tool_search":false,"supports_structured_output":false,
            "supports_effort":false,"supports_max_effort":false,
            "supports_fast_mode":false,"supports_auto_mode":false,
            "supports_1m_context":false,"supports_prompt_cache":false,
            "supports_cache_editing":false,"supports_token_efficient":false,
            "supports_redact_thinking":false,"max_input_tokens":2048,
            "max_output_tokens":256
        }
    }]})
    .to_string()
}

fn sdk_config(origin: &str) -> Config {
    Config {
        server_url: Some(origin.to_owned()),
        ..Default::default()
    }
}

async fn enroll(
    fixture: &DatabaseFixture,
    tls: &TlsFixture,
    initial: &TokenSet,
) -> openbot_infra::gateway_authority::GatewayConnectionReceipt {
    let intent = fixture
        .accounts
        .prepare_enrollment(owner(), "Owned SDK account", CLIENT_ID)
        .unwrap();
    let receipt = fixture
        .accounts
        .enroll(
            &intent,
            initial,
            CancellationToken::new(),
            Arc::new(Outcomes::default()),
        )
        .await
        .unwrap();
    assert_eq!(receipt.id(), intent.id());
    assert_eq!(receipt.revision(), 1);
    assert_eq!(receipt.credential_generation(), 1);
    assert_eq!(tls.count(), 2);
    receipt
}

async fn operation_client(
    fixture: &DatabaseFixture,
    origin: &str,
    id: Uuid,
    revision: i64,
    cancel: CancellationToken,
    outcomes: Arc<Outcomes>,
) -> Result<Client, GatewayAuthorityError> {
    let operation = fixture
        .accounts
        .operation(
            owner(),
            id,
            revision,
            cancel.clone(),
            Instant::now() + Duration::from_secs(30),
            outcomes,
        )
        .await?;
    Client::create_with_authority(
        sdk_config(origin),
        operation.transport(),
        operation.authority(),
        Some(cancel),
    )
    .await
    .map_err(|_| GatewayAuthorityError::ReconciliationRequired)
}
