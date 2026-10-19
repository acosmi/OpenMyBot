use std::io::{self, Write};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::db::pool::DatabasePool as Pool;
use deadpool_postgres::ClientWrapper;
use openbot_contracts::auth::{AuthContext, Role};
use openbot_domain::audit::{
    event::{AuditEvent, AuditEventType},
    payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload},
};
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_postgres::{Row, types::ToSql};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroize as _;
use zeroize::Zeroizing;

use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::vault::CredentialRecordVault;

use super::{GatewayAuthorityError, Scope};

const SQL_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
static SESSION_PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn permits() -> Arc<Semaphore> {
    SESSION_PERMITS
        .get_or_init(|| Arc::new(Semaphore::new(8)))
        .clone()
}

/// Borrow the original shared eight permits; acquisition caller supplies one absolute subcap.
pub(super) async fn acquire_enrollment_session_permit(
    cancel: &CancellationToken,
    acquisition_deadline: Instant,
) -> Result<OwnedSemaphorePermit, GatewayAuthorityError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(GatewayAuthorityError::Cancelled),
        () = tokio::time::sleep_until(acquisition_deadline) => Err(GatewayAuthorityError::Timeout),
        permit = permits().acquire_owned() => permit.map_err(|_| GatewayAuthorityError::Unavailable),
    }
}

pub(super) struct DetachedSession {
    client: tokio::sync::Mutex<Option<ClientWrapper>>,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    in_transaction: AtomicBool,
    closing: AtomicBool,
}

impl DetachedSession {
    pub(super) async fn acquire(
        pool: &Pool,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Arc<Self>, GatewayAuthorityError> {
        let sql_deadline = deadline.min(Instant::now() + SQL_TIMEOUT);
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(GatewayAuthorityError::Cancelled),
            _ = tokio::time::sleep_until(sql_deadline) => return Err(GatewayAuthorityError::Timeout),
            permit = permits().acquire_owned() => permit.map_err(|_| GatewayAuthorityError::Unavailable)?,
        };
        let pooled = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(GatewayAuthorityError::Cancelled),
            _ = tokio::time::sleep_until(sql_deadline) => return Err(GatewayAuthorityError::Timeout),
            client = pool.get() => client.map_err(|_| GatewayAuthorityError::Unavailable)?,
        };
        let client = crate::db::pool::PooledClient::take(pooled);
        let session = Arc::new(Self {
            client: tokio::sync::Mutex::new(Some(client)),
            permit: Mutex::new(Some(permit)),
            in_transaction: AtomicBool::new(false),
            closing: AtomicBool::new(false),
        });
        session
            .batch_execute(
                "SET statement_timeout='5000ms';SET lock_timeout='5000ms';SET idle_in_transaction_session_timeout='15000ms'",
                cancel,
                sql_deadline,
            )
            .await?;
        Ok(session)
    }

    async fn run<T>(
        self: &Arc<Self>,
        cancel: &CancellationToken,
        deadline: Instant,
        future: impl std::future::Future<Output = Result<T, tokio_postgres::Error>>,
    ) -> Result<T, GatewayAuthorityError> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(GatewayAuthorityError::ReconciliationRequired);
        }
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(GatewayAuthorityError::Cancelled),
            _ = tokio::time::sleep_until(deadline.min(Instant::now()+SQL_TIMEOUT)) => Err(GatewayAuthorityError::Timeout),
            result = future => result.map_err(|_| GatewayAuthorityError::Unavailable),
        };
        if matches!(
            &result,
            Err(GatewayAuthorityError::Cancelled
                | GatewayAuthorityError::Timeout
                | GatewayAuthorityError::Unavailable)
        ) {
            self.schedule_close();
        }
        result
    }

    pub(super) async fn lock_client(
        self: &Arc<Self>,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<ClientWrapper>>, GatewayAuthorityError> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(GatewayAuthorityError::ReconciliationRequired);
        }
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(GatewayAuthorityError::Cancelled),
            _ = tokio::time::sleep_until(deadline.min(Instant::now() + SQL_TIMEOUT)) => Err(GatewayAuthorityError::Timeout),
            guard = self.client.lock() => Ok(guard),
        };
        if matches!(
            &result,
            Err(GatewayAuthorityError::Cancelled | GatewayAuthorityError::Timeout)
        ) {
            self.schedule_close();
        }
        result
    }

    pub(super) async fn batch_execute(
        self: &Arc<Self>,
        sql: &str,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<(), GatewayAuthorityError> {
        let guard = self.lock_client(cancel, deadline).await?;
        let client = guard.as_ref().ok_or(GatewayAuthorityError::Unavailable)?;
        self.run(cancel, deadline, client.batch_execute(sql)).await
    }

    pub(super) async fn query_opt(
        self: &Arc<Self>,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Option<Row>, GatewayAuthorityError> {
        let guard = self.lock_client(cancel, deadline).await?;
        let client = guard.as_ref().ok_or(GatewayAuthorityError::Unavailable)?;
        self.run(cancel, deadline, client.query_opt(sql, params))
            .await
    }

    pub(super) async fn query_one(
        self: &Arc<Self>,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Row, GatewayAuthorityError> {
        let guard = self.lock_client(cancel, deadline).await?;
        let client = guard.as_ref().ok_or(GatewayAuthorityError::Unavailable)?;
        self.run(cancel, deadline, client.query_one(sql, params))
            .await
    }

    pub(super) async fn begin(
        self: &Arc<Self>,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<(), GatewayAuthorityError> {
        if self.in_transaction.swap(true, Ordering::SeqCst) {
            return Err(GatewayAuthorityError::ReconciliationRequired);
        }
        if let Err(error) = self.batch_execute("BEGIN", cancel, deadline).await {
            self.in_transaction.store(false, Ordering::SeqCst);
            return Err(error);
        }
        Ok(())
    }

    pub(super) async fn rollback(
        self: &Arc<Self>,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<(), GatewayAuthorityError> {
        if !self.in_transaction.load(Ordering::SeqCst) {
            return Ok(());
        }
        let result = self.batch_execute("ROLLBACK", cancel, deadline).await;
        if result.is_ok() {
            self.in_transaction.store(false, Ordering::SeqCst);
        }
        result.map_err(|_| GatewayAuthorityError::ReconciliationRequired)
    }

    pub(super) async fn advisory_lock(
        self: &Arc<Self>,
        key: i64,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<(), GatewayAuthorityError> {
        self.query_one("SELECT pg_advisory_lock($1)", &[&key], cancel, deadline)
            .await
            .map(|_| ())
    }

    pub(super) async fn verify_actor(
        self: &Arc<Self>,
        auth: &AuthContext,
        cancel: &CancellationToken,
        deadline: Instant,
        lock: bool,
    ) -> Result<i64, GatewayAuthorityError> {
        if !(auth.has_role(Role::User) || auth.has_role(Role::Admin)) {
            return Err(GatewayAuthorityError::NotVisible);
        }
        let generation = i64::try_from(auth.auth_generation().get())
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        let suffix = if lock { " FOR SHARE OF u" } else { "" };
        let row = self
            .query_opt(
                &format!("SELECT coalesce(u.auth_generation,0) AS auth_generation FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 AND EXISTS(SELECT 1 FROM public.user_roles r WHERE r.user_id=u.id AND r.role IN ('user','admin')) AND NOT EXISTS(SELECT 1 FROM public.revoked_access a WHERE a.email=lower(u.email)){suffix}"),
                &[&auth.actor().as_str(), &generation],
                cancel,
                deadline,
            )
            .await?
            .ok_or(GatewayAuthorityError::NotVisible)?;
        row.try_get("auth_generation")
            .map_err(|_| GatewayAuthorityError::Corrupt)
    }

    pub(super) fn schedule_close(self: &Arc<Self>) {
        if self.closing.swap(true, Ordering::SeqCst) {
            return;
        }
        let session = Arc::clone(self);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let close = async {
                    let client = session.client.lock().await.take();
                    drop(client);
                    session
                        .permit
                        .lock()
                        .ok()
                        .and_then(|mut permit| permit.take());
                };
                let _ = tokio::time::timeout(CLEANUP_TIMEOUT, close).await;
            });
        }
    }
}

async fn bounded_operation<T>(
    session: &Arc<DetachedSession>,
    cancel: &CancellationToken,
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T, GatewayAuthorityError>>,
) -> Result<T, GatewayAuthorityError> {
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(GatewayAuthorityError::Cancelled),
        _ = tokio::time::sleep_until(deadline) => Err(GatewayAuthorityError::Timeout),
        result = future => result,
    };
    if matches!(
        &result,
        Err(GatewayAuthorityError::Cancelled
            | GatewayAuthorityError::Timeout
            | GatewayAuthorityError::Unavailable
            | GatewayAuthorityError::CommitUnknown)
    ) {
        session.schedule_close();
    }
    result
}

impl Drop for DetachedSession {
    fn drop(&mut self) {
        let client = self.client.get_mut().take();
        drop(client);
        if let Ok(mut permit) = self.permit.lock() {
            permit.take();
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredTokenEnvelopeRef<'a> {
    schema_version: u8,
    connection_id: String,
    credential_generation: i64,
    auth_generation: i64,
    issuer: &'a str,
    account_id: &'a str,
    organization_id: Option<&'a str>,
    client_id: &'a str,
    tokens: StoredTokenRef<'a>,
}

#[derive(Serialize)]
struct StoredTokenRef<'a> {
    access_token: &'a str,
    refresh_token: &'a str,
    expires_at: &'a str,
    scope: &'a str,
    client_id: &'a str,
    server_url: &'a str,
}

#[derive(Default)]
struct SensitiveString(String);

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredTokenEnvelope {
    schema_version: u8,
    connection_id: SensitiveString,
    credential_generation: i64,
    auth_generation: i64,
    issuer: SensitiveString,
    account_id: SensitiveString,
    organization_id: Option<SensitiveString>,
    client_id: SensitiveString,
    tokens: StoredToken,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredToken {
    access_token: SensitiveString,
    refresh_token: SensitiveString,
    expires_at: SensitiveString,
    scope: SensitiveString,
    client_id: SensitiveString,
    server_url: SensitiveString,
}

pub(super) struct SensitiveTokens(acosmi::TokenSet);

impl SensitiveTokens {
    pub(super) fn new(tokens: acosmi::TokenSet) -> Self {
        Self(tokens)
    }

    pub(super) fn clone_plain(&self) -> acosmi::TokenSet {
        self.0.clone()
    }
}

impl Deref for SensitiveTokens {
    type Target = acosmi::TokenSet;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveTokens {
    fn drop(&mut self) {
        self.0.access_token.zeroize();
        self.0.refresh_token.zeroize();
        self.0.expires_at.zeroize();
        self.0.scope.zeroize();
        self.0.client_id.zeroize();
        self.0.server_url.zeroize();
    }
}

struct CountWriter {
    bytes: usize,
}

impl Write for CountWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buf.len())
            .filter(|value| *value <= 65_536)
            .ok_or_else(|| io::Error::other("bounded token envelope"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct ConnectionRow {
    pub(super) credential_generation: i64,
    pub(super) state: String,
    pub(super) current_secret_id: Option<Uuid>,
    pub(super) pending_operation_id: Option<Uuid>,
}

pub(super) struct OperationRow {
    pub(super) id: Uuid,
    pub(super) from_generation: i64,
    pub(super) to_generation: i64,
    pub(super) state: String,
    pub(super) candidate_secret_id: Option<Uuid>,
    pub(super) token_admitted_at: Option<OffsetDateTime>,
}

pub(super) fn validate_token(
    tokens: &acosmi::TokenSet,
    scope: &Scope,
    generation: i64,
) -> Result<(), GatewayAuthorityError> {
    validate_token_shape(tokens, &scope.issuer, &scope.client_id)?;
    if generation <= 0 {
        return Err(GatewayAuthorityError::InvalidInput);
    }
    Ok(())
}

pub(super) fn validate_token_shape(
    tokens: &acosmi::TokenSet,
    issuer: &str,
    client_id: &str,
) -> Result<(), GatewayAuthorityError> {
    let valid_secret = |value: &str| {
        !value.is_empty()
            && value.len() <= 16_377
            && value.as_bytes().iter().all(u8::is_ascii_graphic)
    };
    let fields = tokens.scope.split_ascii_whitespace().collect::<Vec<_>>();
    if !valid_secret(&tokens.access_token)
        || !valid_secret(&tokens.refresh_token)
        || tokens.client_id != client_id
        || tokens.server_url != issuer
        || tokens.expires_at.is_empty()
        || tokens.expires_at.len() > 64
        || OffsetDateTime::parse(&tokens.expires_at, &Rfc3339).is_err()
        || tokens.scope.len() > 128
        || fields.len() != 2
        || fields.iter().filter(|value| **value == "ai").count() != 1
        || fields.iter().filter(|value| **value == "account").count() != 1
    {
        return Err(GatewayAuthorityError::InvalidInput);
    }
    Ok(())
}

fn principal(connection: Uuid) -> SecretPrincipal {
    SecretPrincipal::Service(ServiceId::new(connection.to_string()))
}

pub(super) fn seal_tokens(
    vault: &CredentialRecordVault,
    secret_id: Uuid,
    scope: &Scope,
    generation: i64,
    tokens: &acosmi::TokenSet,
) -> Result<String, GatewayAuthorityError> {
    validate_token(tokens, scope, generation)?;
    let envelope = StoredTokenEnvelopeRef {
        schema_version: 1,
        connection_id: scope.connection_id.to_string(),
        credential_generation: generation,
        auth_generation: scope.auth_generation,
        issuer: &scope.issuer,
        account_id: &scope.account_id,
        organization_id: scope.organization_id.as_deref(),
        client_id: &scope.client_id,
        tokens: StoredTokenRef {
            access_token: &tokens.access_token,
            refresh_token: &tokens.refresh_token,
            expires_at: &tokens.expires_at,
            scope: &tokens.scope,
            client_id: &tokens.client_id,
            server_url: &tokens.server_url,
        },
    };
    let mut count = CountWriter { bytes: 0 };
    serde_json::to_writer(&mut count, &envelope)
        .map_err(|_| GatewayAuthorityError::InvalidInput)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(count.bytes));
    let fixed_capacity = encoded.capacity();
    serde_json::to_writer(&mut *encoded, &envelope).map_err(|_| GatewayAuthorityError::Corrupt)?;
    if encoded.len() != count.bytes || encoded.capacity() != fixed_capacity {
        return Err(GatewayAuthorityError::Corrupt);
    }
    vault
        .seal(
            &secret_id,
            SecretKind::Model,
            SecretPrincipal::Actor(scope.auth.actor().clone()),
            principal(scope.connection_id),
            &SecretBytes::new(encoded.to_vec()),
        )
        .map_err(|_| GatewayAuthorityError::Corrupt)
}

pub(super) fn open_tokens(
    vault: &CredentialRecordVault,
    secret_id: Uuid,
    encrypted: &str,
    scope: &Scope,
    generation: i64,
) -> Result<SensitiveTokens, GatewayAuthorityError> {
    let opened = vault
        .open(
            &secret_id,
            SecretKind::Model,
            SecretPrincipal::Actor(scope.auth.actor().clone()),
            principal(scope.connection_id),
            encrypted,
        )
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if opened.needs_migration() {
        return Err(GatewayAuthorityError::Corrupt);
    }
    let plaintext = opened.into_secret();
    if plaintext.expose().len() > 65_536 {
        return Err(GatewayAuthorityError::Corrupt);
    }
    let mut stored: StoredTokenEnvelope =
        serde_json::from_slice(plaintext.expose()).map_err(|_| GatewayAuthorityError::Corrupt)?;
    if stored.schema_version != 1
        || stored.connection_id.0.as_str() != scope.connection_id.to_string()
        || stored.credential_generation != generation
        || stored.auth_generation != scope.auth_generation
        || stored.issuer.0.as_str() != scope.issuer
        || stored.account_id.0.as_str() != scope.account_id
        || stored
            .organization_id
            .as_ref()
            .map(|value| value.0.as_str())
            != scope.organization_id.as_deref()
        || stored.client_id.0.as_str() != scope.client_id
        || stored.tokens.client_id.0.as_str() != stored.client_id.0.as_str()
        || stored.tokens.server_url.0.as_str() != stored.issuer.0.as_str()
    {
        return Err(GatewayAuthorityError::Corrupt);
    }
    let tokens = SensitiveTokens(acosmi::TokenSet {
        access_token: std::mem::take(&mut stored.tokens.access_token.0),
        refresh_token: std::mem::take(&mut stored.tokens.refresh_token.0),
        expires_at: std::mem::take(&mut stored.tokens.expires_at.0),
        scope: std::mem::take(&mut stored.tokens.scope.0),
        client_id: std::mem::take(&mut stored.tokens.client_id.0),
        server_url: std::mem::take(&mut stored.tokens.server_url.0),
    });
    validate_token(&tokens, scope, generation)?;
    Ok(tokens)
}

pub(super) async fn load_connection(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    for_update: bool,
) -> Result<ConnectionRow, GatewayAuthorityError> {
    session
        .verify_actor(&scope.auth, &scope.cancel, scope.deadline, true)
        .await?;
    let lock = if for_update {
        " FOR UPDATE"
    } else {
        " FOR SHARE"
    };
    let row = session.query_opt(&format!("SELECT issuer,client_id,account_id,organization_id,revision,credential_generation,auth_generation,state,current_secret_id,pending_operation_id FROM public.sdk_gateway_connections WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND enabled AND deleted_at IS NULL{lock}"),
        &[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str()],&scope.cancel,scope.deadline).await?
        .ok_or(GatewayAuthorityError::NotVisible)?;
    if !binding_matches(&row, scope)? {
        return Err(GatewayAuthorityError::Conflict);
    }
    let result = ConnectionRow {
        credential_generation: row
            .try_get("credential_generation")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
        state: row
            .try_get("state")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
        current_secret_id: row
            .try_get("current_secret_id")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
        pending_operation_id: row
            .try_get("pending_operation_id")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
    };
    Ok(result)
}

pub(super) async fn load_operation(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    id: Uuid,
    for_update: bool,
) -> Result<OperationRow, GatewayAuthorityError> {
    let lock = if for_update {
        " FOR UPDATE"
    } else {
        " FOR SHARE"
    };
    let row = session.query_opt(&format!("SELECT id,from_generation,to_generation,state,candidate_secret_id,token_admitted_at FROM public.sdk_gateway_operations WHERE id=$1 AND connection_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND owner_user_id=$5 AND expected_revision=$6 AND auth_generation=$7{lock}"),
        &[&id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation],&scope.cancel,scope.deadline).await?
        .ok_or(GatewayAuthorityError::Corrupt)?;
    Ok(OperationRow {
        id: row
            .try_get("id")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
        from_generation: row
            .try_get("from_generation")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
        to_generation: row
            .try_get("to_generation")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
        state: row
            .try_get("state")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
        candidate_secret_id: row
            .try_get("candidate_secret_id")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
        token_admitted_at: row
            .try_get("token_admitted_at")
            .map_err(|_| GatewayAuthorityError::Corrupt)?,
    })
}

pub(super) async fn load_secret(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    id: Uuid,
    generation: i64,
) -> Result<String, GatewayAuthorityError> {
    let row = session.query_opt("SELECT encrypted_value FROM public.sdk_gateway_secrets WHERE id=$1 AND connection_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND owner_user_id=$5 AND credential_generation=$6 AND retired_at IS NULL FOR SHARE",
        &[&id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&generation],&scope.cancel,scope.deadline).await?
        .ok_or(GatewayAuthorityError::Corrupt)?;
    row.try_get("encrypted_value")
        .map_err(|_| GatewayAuthorityError::Corrupt)
}

async fn append_audit(
    tx: &tokio_postgres::Transaction<'_>,
    scope: &Scope,
    audit_key: &[u8],
    change: &'static str,
) -> Result<(), GatewayAuthorityError> {
    let (id, created_at) = next_event_coordinates(tx)
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(scope.auth.actor().clone()),
        event_type: AuditEventType::parse("configuration.changed")
            .ok_or(GatewayAuthorityError::Corrupt)?,
        target_kind: AuditLabel::new("sdk_gateway_connection"),
        target_id: Some(
            AuditIdentifier::new(scope.connection_id.to_string())
                .map_err(|_| GatewayAuthorityError::Corrupt)?,
        ),
        payload: AuditPayload::from_facts(vec![AuditFact::ConfigurationChange(AuditLabel::new(
            change,
        ))])
        .map_err(|_| GatewayAuthorityError::Corrupt)?,
        created_at,
    };
    append_event_in_transaction(tx, &event, audit_key)
        .await
        .map(|_| ())
        .map_err(|_| GatewayAuthorityError::Unavailable)
}

async fn verify_actor_tx(
    tx: &deadpool_postgres::Transaction<'_>,
    scope: &Scope,
) -> Result<(), GatewayAuthorityError> {
    let row = tx.query_opt("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 AND EXISTS(SELECT 1 FROM public.user_roles r WHERE r.user_id=u.id AND r.role IN ('user','admin')) AND NOT EXISTS(SELECT 1 FROM public.revoked_access a WHERE a.email=lower(u.email)) FOR SHARE OF u",
        &[&scope.auth.actor().as_str(),&scope.auth_generation]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    row.map(|_| ()).ok_or(GatewayAuthorityError::NotVisible)
}

fn binding_matches(row: &Row, scope: &Scope) -> Result<bool, GatewayAuthorityError> {
    let issuer: String = row
        .try_get("issuer")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let client_id: String = row
        .try_get("client_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let account_id: String = row
        .try_get("account_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let organization_id: Option<String> = row
        .try_get("organization_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let revision: i64 = row
        .try_get("revision")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let auth_generation: i64 = row
        .try_get("auth_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    Ok(issuer == scope.issuer
        && client_id == scope.client_id
        && account_id == scope.account_id
        && organization_id == scope.organization_id
        && revision == scope.expected_revision
        && auth_generation == scope.auth_generation)
}

async fn insert_enrollment_inner(
    session: &Arc<DetachedSession>,
    vault: &CredentialRecordVault,
    audit_key: &[u8],
    scope: &Scope,
    name: &str,
    tokens: &acosmi::TokenSet,
) -> Result<Uuid, GatewayAuthorityError> {
    let secret_id = Uuid::now_v7();
    let encrypted = seal_tokens(vault, secret_id, scope, 1, tokens)?;
    let mut guard = session.lock_client(&scope.cancel, scope.deadline).await?;
    let client = guard.as_mut().ok_or(GatewayAuthorityError::Unavailable)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?;
    verify_actor_tx(&tx, scope).await?;
    let now: OffsetDateTime = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?
        .try_get(0)
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    tx.execute("INSERT INTO public.sdk_gateway_connections(id,deployment_id,tenant_id,owner_user_id,name,issuer,client_id,account_id,organization_id,auth_contract_version,error_contract_version,enabled,revision,credential_generation,auth_generation,state,current_secret_id,pending_operation_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,2,1,true,1,1,$10,'ready',$11,NULL,$12,$12)",
        &[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&name,&scope.issuer,&scope.client_id,&scope.account_id,&scope.organization_id,&scope.auth_generation,&secret_id,&now]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    tx.execute("INSERT INTO public.sdk_gateway_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation,encrypted_value,created_at) VALUES($1,$2,$3,$4,$5,1,$6,$7)",
        &[&secret_id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&encrypted,&now]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    let stored: String = tx.query_one("SELECT encrypted_value FROM public.sdk_gateway_secrets WHERE id=$1 AND connection_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND owner_user_id=$5 AND credential_generation=1 AND retired_at IS NULL FOR SHARE",&[&secret_id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str()]).await.map_err(|_|GatewayAuthorityError::Unavailable)?.try_get(0).map_err(|_|GatewayAuthorityError::Corrupt)?;
    let verified = open_tokens(vault, secret_id, &stored, scope, 1)?;
    if !token_bytes_equal(&verified, tokens) {
        return Err(GatewayAuthorityError::Corrupt);
    }
    append_audit(&tx, scope, audit_key, "gateway_connection_enrolled").await?;
    tx.commit()
        .await
        .map_err(|_| GatewayAuthorityError::CommitUnknown)?;
    Ok(secret_id)
}

pub(super) fn token_bytes_equal(left: &acosmi::TokenSet, right: &acosmi::TokenSet) -> bool {
    left.access_token == right.access_token
        && left.refresh_token == right.refresh_token
        && left.expires_at == right.expires_at
        && left.scope == right.scope
        && left.client_id == right.client_id
        && left.server_url == right.server_url
}

async fn begin_rotation_inner(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    audit_key: &[u8],
) -> Result<OperationRow, GatewayAuthorityError> {
    let operation_id = Uuid::now_v7();
    let mut guard = session.lock_client(&scope.cancel, scope.deadline).await?;
    let client = guard.as_mut().ok_or(GatewayAuthorityError::Unavailable)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?;
    verify_actor_tx(&tx, scope).await?;
    let row = tx.query_opt("SELECT issuer,client_id,account_id,organization_id,revision,credential_generation,auth_generation,state,current_secret_id,pending_operation_id FROM public.sdk_gateway_connections WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND enabled AND deleted_at IS NULL FOR UPDATE",
        &[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str()]).await.map_err(|_|GatewayAuthorityError::Unavailable)?.ok_or(GatewayAuthorityError::NotVisible)?;
    let revision: i64 = row
        .try_get("revision")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let from: i64 = row
        .try_get("credential_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let state: String = row
        .try_get("state")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let current: Option<Uuid> = row
        .try_get("current_secret_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let pending: Option<Uuid> = row
        .try_get("pending_operation_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if !binding_matches(&row, scope)? || state != "ready" || current.is_none() || pending.is_some()
    {
        return Err(GatewayAuthorityError::Conflict);
    }
    let to = from.checked_add(1).ok_or(GatewayAuthorityError::Conflict)?;
    let now: OffsetDateTime = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?
        .try_get(0)
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    tx.execute("INSERT INTO public.sdk_gateway_operations(id,connection_id,deployment_id,tenant_id,owner_user_id,expected_revision,auth_generation,from_generation,to_generation,state,candidate_secret_id,token_admitted_at,created_at,updated_at,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',NULL,NULL,$10,$10,NULL)",
        &[&operation_id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&revision,&scope.auth_generation,&from,&to,&now]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    let affected=tx.execute("UPDATE public.sdk_gateway_connections SET state='rotation_pending',pending_operation_id=$2,updated_at=$3 WHERE id=$1 AND deployment_id=$4 AND tenant_id=$5 AND owner_user_id=$6 AND enabled AND deleted_at IS NULL AND revision=$7 AND auth_generation=$8 AND credential_generation=$9 AND state='ready' AND current_secret_id IS NOT NULL AND pending_operation_id IS NULL",&[&scope.connection_id,&operation_id,&now,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation,&from]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    if affected != 1 {
        return Err(GatewayAuthorityError::Conflict);
    }
    append_audit(&tx, scope, audit_key, "gateway_rotation_begun").await?;
    tx.commit()
        .await
        .map_err(|_| GatewayAuthorityError::CommitUnknown)?;
    Ok(OperationRow {
        id: operation_id,
        from_generation: from,
        to_generation: to,
        state: "pending".into(),
        candidate_secret_id: None,
        token_admitted_at: None,
    })
}

async fn admit_token_send_inner(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    operation_id: Uuid,
    audit_key: &[u8],
) -> Result<(), GatewayAuthorityError> {
    let mut guard = session.lock_client(&scope.cancel, scope.deadline).await?;
    let client = guard.as_mut().ok_or(GatewayAuthorityError::Unavailable)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?;
    verify_actor_tx(&tx, scope).await?;
    let conn=tx.query_opt("SELECT issuer,client_id,account_id,organization_id,state,pending_operation_id,revision,auth_generation,credential_generation,current_secret_id FROM public.sdk_gateway_connections WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND enabled AND deleted_at IS NULL FOR UPDATE",&[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str()]).await.map_err(|_|GatewayAuthorityError::Unavailable)?.ok_or(GatewayAuthorityError::NotVisible)?;
    let state: String = conn
        .try_get("state")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let pending: Option<Uuid> = conn
        .try_get("pending_operation_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let revision: i64 = conn
        .try_get("revision")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let generation: i64 = conn
        .try_get("auth_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let credential_generation: i64 = conn
        .try_get("credential_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let current_secret_id: Option<Uuid> = conn
        .try_get("current_secret_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let to_generation = credential_generation
        .checked_add(1)
        .ok_or(GatewayAuthorityError::Conflict)?;
    if !binding_matches(&conn, scope)?
        || state != "rotation_pending"
        || pending != Some(operation_id)
        || revision != scope.expected_revision
        || generation != scope.auth_generation
        || current_secret_id.is_none()
    {
        return Err(GatewayAuthorityError::Conflict);
    }
    let affected=tx.execute("UPDATE public.sdk_gateway_operations SET token_admitted_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND connection_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND owner_user_id=$5 AND expected_revision=$6 AND auth_generation=$7 AND from_generation=$8 AND to_generation=$9 AND state='pending' AND candidate_secret_id IS NULL AND token_admitted_at IS NULL",&[&operation_id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation,&credential_generation,&to_generation]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    if affected != 1 {
        return Err(GatewayAuthorityError::ReconciliationRequired);
    }
    append_audit(&tx, scope, audit_key, "gateway_rotation_send_admitted").await?;
    tx.commit()
        .await
        .map_err(|_| GatewayAuthorityError::CommitUnknown)
}

async fn stage_rotation_inner(
    session: &Arc<DetachedSession>,
    vault: &CredentialRecordVault,
    scope: &Scope,
    operation_id: Uuid,
    tokens: &acosmi::TokenSet,
    audit_key: &[u8],
) -> Result<(Uuid, i64), GatewayAuthorityError> {
    let op = load_operation(session, scope, operation_id, false).await?;
    if op.state != "pending" || op.token_admitted_at.is_none() || op.candidate_secret_id.is_some() {
        return Err(GatewayAuthorityError::ReconciliationRequired);
    }
    let secret_id = Uuid::now_v7();
    let encrypted = seal_tokens(vault, secret_id, scope, op.to_generation, tokens)?;
    let mut guard = session.lock_client(&scope.cancel, scope.deadline).await?;
    let client = guard.as_mut().ok_or(GatewayAuthorityError::Unavailable)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?;
    verify_actor_tx(&tx, scope).await?;
    let conn=tx.query_opt("SELECT issuer,client_id,account_id,organization_id,revision,auth_generation,state,pending_operation_id,credential_generation,current_secret_id FROM public.sdk_gateway_connections WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND enabled AND deleted_at IS NULL FOR UPDATE",&[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str()]).await.map_err(|_|GatewayAuthorityError::Unavailable)?.ok_or(GatewayAuthorityError::NotVisible)?;
    let state: String = conn
        .try_get("state")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let pending: Option<Uuid> = conn
        .try_get("pending_operation_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let generation: i64 = conn
        .try_get("credential_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let current: Option<Uuid> = conn
        .try_get("current_secret_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if !binding_matches(&conn, scope)?
        || state != "rotation_pending"
        || pending != Some(operation_id)
        || generation != op.from_generation
        || current.is_none()
    {
        return Err(GatewayAuthorityError::Conflict);
    }
    let locked_op=tx.query_opt("SELECT from_generation,to_generation,state,candidate_secret_id,token_admitted_at FROM public.sdk_gateway_operations WHERE id=$1 AND connection_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND owner_user_id=$5 AND expected_revision=$6 AND auth_generation=$7 FOR UPDATE",&[&operation_id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation]).await.map_err(|_|GatewayAuthorityError::Unavailable)?.ok_or(GatewayAuthorityError::Corrupt)?;
    let locked_from: i64 = locked_op
        .try_get("from_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let locked_to: i64 = locked_op
        .try_get("to_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let locked_state: String = locked_op
        .try_get("state")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let locked_candidate: Option<Uuid> = locked_op
        .try_get("candidate_secret_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let locked_admitted: Option<OffsetDateTime> = locked_op
        .try_get("token_admitted_at")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if locked_from != op.from_generation
        || locked_to != op.to_generation
        || locked_state != "pending"
        || locked_candidate.is_some()
        || locked_admitted.is_none()
    {
        return Err(GatewayAuthorityError::ReconciliationRequired);
    }
    let now: OffsetDateTime = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?
        .try_get(0)
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    tx.execute("INSERT INTO public.sdk_gateway_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation,encrypted_value,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&secret_id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&op.to_generation,&encrypted,&now]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    let affected=tx.execute("UPDATE public.sdk_gateway_operations SET state='staged',candidate_secret_id=$2,updated_at=$3 WHERE id=$1 AND connection_id=$4 AND deployment_id=$5 AND tenant_id=$6 AND owner_user_id=$7 AND expected_revision=$8 AND auth_generation=$9 AND from_generation=$10 AND to_generation=$11 AND state='pending' AND token_admitted_at IS NOT NULL AND candidate_secret_id IS NULL",&[&operation_id,&secret_id,&now,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation,&op.from_generation,&op.to_generation]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    if affected != 1 {
        return Err(GatewayAuthorityError::ReconciliationRequired);
    }
    append_audit(&tx, scope, audit_key, "gateway_rotation_staged").await?;
    tx.commit()
        .await
        .map_err(|_| GatewayAuthorityError::CommitUnknown)?;
    drop(guard);
    session.begin(&scope.cancel, scope.deadline).await?;
    let readback = async {
        let connection = load_connection(session, scope, false).await?;
        if connection.state != "rotation_pending"
            || connection.pending_operation_id != Some(operation_id)
            || connection.credential_generation != op.from_generation
            || connection.current_secret_id != current
        {
            return Err(GatewayAuthorityError::ReconciliationRequired);
        }
        let operation = load_operation(session, scope, operation_id, false).await?;
        if operation.state != "staged"
            || operation.from_generation != op.from_generation
            || operation.to_generation != op.to_generation
            || operation.candidate_secret_id != Some(secret_id)
            || operation.token_admitted_at.is_none()
        {
            return Err(GatewayAuthorityError::ReconciliationRequired);
        }
        load_secret(session, scope, secret_id, op.to_generation).await
    }
    .await;
    let rollback = session.rollback(&scope.cancel, scope.deadline).await;
    let stored = match (readback, rollback) {
        (Ok(stored), Ok(())) => stored,
        _ => return Err(GatewayAuthorityError::ReconciliationRequired),
    };
    let opened = open_tokens(vault, secret_id, &stored, scope, op.to_generation)?;
    if !token_bytes_equal(&opened, tokens) {
        return Err(GatewayAuthorityError::Corrupt);
    }
    Ok((secret_id, op.to_generation))
}

async fn finalize_rotation_inner(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    operation_id: Uuid,
    secret_id: Uuid,
    to_generation: i64,
    audit_key: &[u8],
) -> Result<(), GatewayAuthorityError> {
    let mut guard = session.lock_client(&scope.cancel, scope.deadline).await?;
    let client = guard.as_mut().ok_or(GatewayAuthorityError::Unavailable)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?;
    verify_actor_tx(&tx, scope).await?;
    let conn=tx.query_opt("SELECT issuer,client_id,account_id,organization_id,state,pending_operation_id,current_secret_id,credential_generation,revision,auth_generation FROM public.sdk_gateway_connections WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND enabled AND deleted_at IS NULL FOR UPDATE",&[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str()]).await.map_err(|_|GatewayAuthorityError::Unavailable)?.ok_or(GatewayAuthorityError::NotVisible)?;
    let state: String = conn
        .try_get("state")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let pending: Option<Uuid> = conn
        .try_get("pending_operation_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let old: Option<Uuid> = conn
        .try_get("current_secret_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let from: i64 = conn
        .try_get("credential_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let revision: i64 = conn
        .try_get("revision")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let ag: i64 = conn
        .try_get("auth_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if !binding_matches(&conn, scope)?
        || state != "rotation_pending"
        || pending != Some(operation_id)
        || old.is_none()
        || revision != scope.expected_revision
        || ag != scope.auth_generation
        || to_generation != from.checked_add(1).ok_or(GatewayAuthorityError::Conflict)?
    {
        return Err(GatewayAuthorityError::Conflict);
    }
    let op=tx.query_opt("SELECT state,candidate_secret_id,to_generation,from_generation,token_admitted_at FROM public.sdk_gateway_operations WHERE id=$1 AND connection_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND owner_user_id=$5 AND expected_revision=$6 AND auth_generation=$7 FOR UPDATE",&[&operation_id,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation]).await.map_err(|_|GatewayAuthorityError::Unavailable)?.ok_or(GatewayAuthorityError::Corrupt)?;
    let os: String = op
        .try_get("state")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let candidate: Option<Uuid> = op
        .try_get("candidate_secret_id")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let ot: i64 = op
        .try_get("to_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let of: i64 = op
        .try_get("from_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let admitted: Option<OffsetDateTime> = op
        .try_get("token_admitted_at")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if os != "staged"
        || candidate != Some(secret_id)
        || ot != to_generation
        || of != from
        || admitted.is_none()
    {
        return Err(GatewayAuthorityError::ReconciliationRequired);
    }
    let now: OffsetDateTime = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?
        .try_get(0)
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let affected=tx.execute("UPDATE public.sdk_gateway_operations SET state='committed',updated_at=$2,completed_at=$2 WHERE id=$1 AND connection_id=$3 AND deployment_id=$4 AND tenant_id=$5 AND owner_user_id=$6 AND expected_revision=$7 AND auth_generation=$8 AND from_generation=$9 AND to_generation=$10 AND state='staged' AND candidate_secret_id=$11 AND token_admitted_at IS NOT NULL",&[&operation_id,&now,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation,&from,&to_generation,&secret_id]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    if affected != 1 {
        return Err(GatewayAuthorityError::ReconciliationRequired);
    }
    let old = old.ok_or(GatewayAuthorityError::Corrupt)?;
    let affected=tx.execute("UPDATE public.sdk_gateway_connections SET state='ready',current_secret_id=$2,credential_generation=$3,pending_operation_id=NULL,updated_at=$4 WHERE id=$1 AND deployment_id=$5 AND tenant_id=$6 AND owner_user_id=$7 AND enabled AND deleted_at IS NULL AND revision=$8 AND auth_generation=$9 AND state='rotation_pending' AND current_secret_id=$10 AND credential_generation=$11 AND pending_operation_id=$12",&[&scope.connection_id,&secret_id,&to_generation,&now,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation,&old,&from,&operation_id]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    if affected != 1 {
        return Err(GatewayAuthorityError::Conflict);
    }
    let affected=tx.execute("UPDATE public.sdk_gateway_secrets SET retired_at=$2 WHERE id=$1 AND connection_id=$3 AND deployment_id=$4 AND tenant_id=$5 AND owner_user_id=$6 AND credential_generation=$7 AND retired_at IS NULL",&[&old,&now,&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&from]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    if affected != 1 {
        return Err(GatewayAuthorityError::Corrupt);
    }
    append_audit(&tx, scope, audit_key, "gateway_rotation_committed").await?;
    tx.commit()
        .await
        .map_err(|_| GatewayAuthorityError::CommitUnknown)
}

async fn clear_credentials_inner(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    audit_key: &[u8],
) -> Result<(), GatewayAuthorityError> {
    let mut guard = session.lock_client(&scope.cancel, scope.deadline).await?;
    let client = guard.as_mut().ok_or(GatewayAuthorityError::Unavailable)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?;
    verify_actor_tx(&tx, scope).await?;
    let conn=tx.query_opt("SELECT issuer,client_id,account_id,organization_id,revision,auth_generation,credential_generation,state,current_secret_id,pending_operation_id FROM public.sdk_gateway_connections WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND enabled AND deleted_at IS NULL FOR UPDATE",&[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str()]).await.map_err(|_|GatewayAuthorityError::Unavailable)?.ok_or(GatewayAuthorityError::NotVisible)?;
    let rev: i64 = conn
        .try_get("revision")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let ag: i64 = conn
        .try_get("auth_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let generation: i64 = conn
        .try_get("credential_generation")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let state: String = conn
        .try_get("state")
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if !binding_matches(&conn, scope)?
        || rev != scope.expected_revision
        || ag != scope.auth_generation
        || !matches!(state.as_str(), "ready" | "rotation_pending" | "missing")
    {
        return Err(GatewayAuthorityError::Conflict);
    }
    let next = generation
        .checked_add(1)
        .ok_or(GatewayAuthorityError::Conflict)?;
    let now: OffsetDateTime = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|_| GatewayAuthorityError::Unavailable)?
        .try_get(0)
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    tx.execute("UPDATE public.sdk_gateway_operations SET state='cleared',updated_at=$5,completed_at=coalesce(completed_at,$5) WHERE connection_id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND state IN ('pending','staged')",&[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&now]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    tx.execute("UPDATE public.sdk_gateway_secrets SET retired_at=coalesce(retired_at,$5) WHERE connection_id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4",&[&scope.connection_id,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&now]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    let affected=tx.execute("UPDATE public.sdk_gateway_connections SET credential_generation=$2,state='missing',current_secret_id=NULL,pending_operation_id=NULL,updated_at=$3 WHERE id=$1 AND deployment_id=$4 AND tenant_id=$5 AND owner_user_id=$6 AND enabled AND deleted_at IS NULL AND revision=$7 AND auth_generation=$8 AND credential_generation=$9 AND state=$10",&[&scope.connection_id,&next,&now,&scope.deployment.as_str(),&scope.tenant.as_str(),&scope.auth.actor().as_str(),&scope.expected_revision,&scope.auth_generation,&generation,&state]).await.map_err(|_|GatewayAuthorityError::Unavailable)?;
    if affected != 1 {
        return Err(GatewayAuthorityError::Conflict);
    }
    append_audit(&tx, scope, audit_key, "gateway_credentials_cleared").await?;
    tx.commit()
        .await
        .map_err(|_| GatewayAuthorityError::CommitUnknown)
}

pub(super) async fn insert_enrollment(
    session: &Arc<DetachedSession>,
    vault: &CredentialRecordVault,
    audit_key: &[u8],
    scope: &Scope,
    name: &str,
    tokens: &acosmi::TokenSet,
) -> Result<Uuid, GatewayAuthorityError> {
    bounded_operation(
        session,
        &scope.cancel,
        scope.deadline,
        insert_enrollment_inner(session, vault, audit_key, scope, name, tokens),
    )
    .await
}

pub(super) async fn begin_rotation(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    audit_key: &[u8],
) -> Result<OperationRow, GatewayAuthorityError> {
    bounded_operation(
        session,
        &scope.cancel,
        scope.deadline,
        begin_rotation_inner(session, scope, audit_key),
    )
    .await
}

pub(super) async fn admit_token_send(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    operation_id: Uuid,
    audit_key: &[u8],
) -> Result<(), GatewayAuthorityError> {
    bounded_operation(
        session,
        &scope.cancel,
        scope.deadline,
        admit_token_send_inner(session, scope, operation_id, audit_key),
    )
    .await
}

pub(super) async fn stage_rotation(
    session: &Arc<DetachedSession>,
    vault: &CredentialRecordVault,
    scope: &Scope,
    operation_id: Uuid,
    tokens: &acosmi::TokenSet,
    audit_key: &[u8],
) -> Result<(Uuid, i64), GatewayAuthorityError> {
    bounded_operation(
        session,
        &scope.cancel,
        scope.deadline,
        stage_rotation_inner(session, vault, scope, operation_id, tokens, audit_key),
    )
    .await
}

pub(super) async fn finalize_rotation(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    operation_id: Uuid,
    secret_id: Uuid,
    to_generation: i64,
    audit_key: &[u8],
) -> Result<(), GatewayAuthorityError> {
    bounded_operation(
        session,
        &scope.cancel,
        scope.deadline,
        finalize_rotation_inner(
            session,
            scope,
            operation_id,
            secret_id,
            to_generation,
            audit_key,
        ),
    )
    .await
}

pub(super) async fn clear_credentials(
    session: &Arc<DetachedSession>,
    scope: &Scope,
    audit_key: &[u8],
) -> Result<(), GatewayAuthorityError> {
    bounded_operation(
        session,
        &scope.cancel,
        scope.deadline,
        clear_credentials_inner(session, scope, audit_key),
    )
    .await
}

async fn enrollment_sql<T, E>(
    scope: &Scope,
    future: impl std::future::Future<Output = Result<T, E>>,
    map: impl FnOnce(E) -> GatewayAuthorityError,
) -> Result<T, GatewayAuthorityError> {
    let deadline = scope.deadline.min(Instant::now() + SQL_TIMEOUT);
    tokio::select! {
        biased;
        () = scope.cancel.cancelled() => Err(GatewayAuthorityError::Cancelled),
        () = tokio::time::sleep_until(deadline) => Err(GatewayAuthorityError::Timeout),
        result = future => result.map_err(map),
    }
}

async fn append_enrollment_audit_before(
    tx: &tokio_postgres::Transaction<'_>,
    scope: &Scope,
    audit_key: &[u8],
) -> Result<(), GatewayAuthorityError> {
    // Keep the original two audit utilities and fixed facts, each bounded by the original cap.
    let (id, created_at) = enrollment_sql(scope, next_event_coordinates(tx), |_| {
        GatewayAuthorityError::Unavailable
    })
    .await?;
    let event = AuditEvent {
        id,
        actor: Some(scope.auth.actor().clone()),
        event_type: AuditEventType::parse("configuration.changed")
            .ok_or(GatewayAuthorityError::Corrupt)?,
        target_kind: AuditLabel::new("sdk_gateway_connection"),
        target_id: Some(
            AuditIdentifier::new(scope.connection_id.to_string())
                .map_err(|_| GatewayAuthorityError::Corrupt)?,
        ),
        payload: AuditPayload::from_facts(vec![AuditFact::ConfigurationChange(AuditLabel::new(
            "gateway_connection_enrolled",
        ))])
        .map_err(|_| GatewayAuthorityError::Corrupt)?,
        created_at,
    };
    enrollment_sql(
        scope,
        append_event_in_transaction(tx, &event, audit_key),
        |_| GatewayAuthorityError::Unavailable,
    )
    .await
    .map(|_| ())
}

// Exact fixed R367 inserts; only this connection INSERT's typed23505 maps Conflict.
const ENROLLMENT_CONNECTION_INSERT: &str = "INSERT INTO public.sdk_gateway_connections(id,deployment_id,tenant_id,owner_user_id,name,issuer,client_id,account_id,organization_id,auth_contract_version,error_contract_version,enabled,revision,credential_generation,auth_generation,state,current_secret_id,pending_operation_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,2,1,true,1,1,$10,'ready',$11,NULL,$12,$12)";
const ENROLLMENT_SECRET_INSERT: &str = "INSERT INTO public.sdk_gateway_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation,encrypted_value,created_at) VALUES($1,$2,$3,$4,$5,1,$6,$7)";
const ENROLLMENT_CONNECTION_READBACK: &str = "SELECT name,issuer,client_id,account_id,organization_id,auth_contract_version,error_contract_version,revision,credential_generation,auth_generation,state,current_secret_id,pending_operation_id FROM public.sdk_gateway_connections WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND enabled AND deleted_at IS NULL";
const ENROLLMENT_SECRET_READBACK: &str = "SELECT encrypted_value FROM public.sdk_gateway_secrets WHERE id=$1 AND connection_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND owner_user_id=$5 AND credential_generation=1 AND retired_at IS NULL";

pub(super) async fn insert_enrollment_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
    vault: &CredentialRecordVault,
    audit_key: &[u8],
    scope: &Scope,
    name: &str,
    tokens: &acosmi::TokenSet,
) -> Result<Uuid, GatewayAuthorityError> {
    let secret_id = Uuid::now_v7();
    let encrypted = seal_tokens(vault, secret_id, scope, 1, tokens)?;
    let now: OffsetDateTime =
        enrollment_sql(scope, tx.query_one("SELECT clock_timestamp()", &[]), |_| {
            GatewayAuthorityError::Unavailable
        })
        .await?
        .try_get(0)
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let inserted = enrollment_sql(
        scope,
        tx.execute(
            ENROLLMENT_CONNECTION_INSERT,
            &[
                &scope.connection_id,
                &scope.deployment.as_str(),
                &scope.tenant.as_str(),
                &scope.auth.actor().as_str(),
                &name,
                &scope.issuer,
                &scope.client_id,
                &scope.account_id,
                &scope.organization_id,
                &scope.auth_generation,
                &secret_id,
                &now,
            ],
        ),
        |error: tokio_postgres::Error| {
            if error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                GatewayAuthorityError::Conflict
            } else {
                GatewayAuthorityError::Unavailable
            }
        },
    )
    .await?;
    if inserted != 1 {
        return Err(GatewayAuthorityError::Corrupt);
    }
    let inserted = enrollment_sql(
        scope,
        tx.execute(
            ENROLLMENT_SECRET_INSERT,
            &[
                &secret_id,
                &scope.connection_id,
                &scope.deployment.as_str(),
                &scope.tenant.as_str(),
                &scope.auth.actor().as_str(),
                &encrypted,
                &now,
            ],
        ),
        |_| GatewayAuthorityError::Unavailable,
    )
    .await?;
    if inserted != 1 {
        return Err(GatewayAuthorityError::Corrupt);
    }
    let stored: String = enrollment_sql(
        scope,
        tx.query_one(
            ENROLLMENT_SECRET_READBACK,
            &[
                &secret_id,
                &scope.connection_id,
                &scope.deployment.as_str(),
                &scope.tenant.as_str(),
                &scope.auth.actor().as_str(),
            ],
        ),
        |_| GatewayAuthorityError::Unavailable,
    )
    .await?
    .try_get(0)
    .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let verified = open_tokens(vault, secret_id, &stored, scope, 1)
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if !token_bytes_equal(&verified, tokens) {
        return Err(GatewayAuthorityError::Corrupt);
    }
    append_enrollment_audit_before(tx, scope, audit_key).await?;
    Ok(secret_id)
}

pub(super) async fn read_enrollment_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
    vault: &CredentialRecordVault,
    scope: &Scope,
    name: &str,
    secret_id: Uuid,
    original_tokens: &acosmi::TokenSet,
) -> Result<(), GatewayAuthorityError> {
    let row = enrollment_sql(
        scope,
        tx.query_opt(
            ENROLLMENT_CONNECTION_READBACK,
            &[
                &scope.connection_id,
                &scope.deployment.as_str(),
                &scope.tenant.as_str(),
                &scope.auth.actor().as_str(),
            ],
        ),
        |_| GatewayAuthorityError::Unavailable,
    )
    .await?
    .ok_or(GatewayAuthorityError::Corrupt)?;
    if !binding_matches(&row, scope)?
        || row
            .try_get::<_, String>("name")
            .map_err(|_| GatewayAuthorityError::Corrupt)?
            != name
        || row
            .try_get::<_, i16>("auth_contract_version")
            .map_err(|_| GatewayAuthorityError::Corrupt)?
            != 2
        || row
            .try_get::<_, i16>("error_contract_version")
            .map_err(|_| GatewayAuthorityError::Corrupt)?
            != 1
        || row
            .try_get::<_, i64>("credential_generation")
            .map_err(|_| GatewayAuthorityError::Corrupt)?
            != 1
        || row
            .try_get::<_, String>("state")
            .map_err(|_| GatewayAuthorityError::Corrupt)?
            != "ready"
        || row
            .try_get::<_, Option<Uuid>>("current_secret_id")
            .map_err(|_| GatewayAuthorityError::Corrupt)?
            != Some(secret_id)
        || row
            .try_get::<_, Option<Uuid>>("pending_operation_id")
            .map_err(|_| GatewayAuthorityError::Corrupt)?
            .is_some()
    {
        return Err(GatewayAuthorityError::Corrupt);
    }
    let stored: String = enrollment_sql(
        scope,
        tx.query_opt(
            ENROLLMENT_SECRET_READBACK,
            &[
                &secret_id,
                &scope.connection_id,
                &scope.deployment.as_str(),
                &scope.tenant.as_str(),
                &scope.auth.actor().as_str(),
            ],
        ),
        |_| GatewayAuthorityError::Unavailable,
    )
    .await?
    .ok_or(GatewayAuthorityError::Corrupt)?
    .try_get(0)
    .map_err(|_| GatewayAuthorityError::Corrupt)?;
    let verified = open_tokens(vault, secret_id, &stored, scope, 1)
        .map_err(|_| GatewayAuthorityError::Corrupt)?;
    if !token_bytes_equal(&verified, original_tokens) {
        return Err(GatewayAuthorityError::Corrupt);
    }
    Ok(())
}
