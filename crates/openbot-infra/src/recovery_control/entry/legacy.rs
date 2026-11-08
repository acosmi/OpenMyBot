//! Server legacy adoption (S9). Every read-only site and KEK check runs
//! before `OrdinaryInitializing`: a failure changes nothing and the same
//! intent can be retried after the configuration is fixed.

use std::time::Instant;

use openbot_contracts::ids::{ActorId, TenantId};
use openbot_domain::vault::{
    ColumnShape, EnvelopeV1, EnvelopeV2, KeyVersion, RecordBinding, SecretId, SecretKind,
    SecretPrincipal, ServiceId, WrappingKey, classify_column, decrypt_v1, open_v2,
};
use tokio_postgres::Client;
use uuid::Uuid;

use super::super::ordinary::{
    OrdinaryActivationProof, OrdinaryInitializationSession, VerifiedOrdinaryLegacyProof,
};
use super::super::{
    Hex32, OrdinaryStage, RecoveryControlError, RecoveryControlFault, ServerDatabaseSite, before,
};
use super::{ControlOwner, Directory, lock};
use crate::db::native;

/// Keyset page: the one Server keyset batch (`REVOCATION_BATCH`).
const PAGE: i64 = 32;
/// Largest stored protected value: the `sdk_gateway_secrets` column bound.
const VALUE_LIMIT: i32 = 524_288;

fn unverified() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::KeyUnverified)
}

fn io() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::IoFailure)
}

fn invalid() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::ControlInvalid)
}

/// Whether the configured KEK authenticates one stored value the way its
/// consumer reads it.
fn opens(
    key: &WrappingKey,
    stored: &str,
    binding: &RecordBinding,
    legacy_v1: bool,
    plaintext: bool,
) -> bool {
    match classify_column(stored) {
        ColumnShape::Plaintext => plaintext,
        ColumnShape::LegacyEnvelope => {
            legacy_v1
                && EnvelopeV1::parse(stored)
                    .is_ok_and(|envelope| decrypt_v1(key, &envelope).is_ok())
        }
        ColumnShape::RecordEnvelope => EnvelopeV2::parse(stored).is_ok_and(|envelope| {
            envelope.key_version() == KeyVersion::new(1) && open_v2(key, binding, &envelope).is_ok()
        }),
    }
}

fn binding(
    tenant: &TenantId,
    secret_id: String,
    kind: SecretKind,
    owner: SecretPrincipal,
    consumer: SecretPrincipal,
) -> RecordBinding {
    RecordBinding::new(
        tenant.clone(),
        SecretId::new(secret_id),
        kind,
        owner,
        consumer,
        KeyVersion::new(1),
    )
}

/// Authenticate every KEK-protected value with the configured key, one keyset
/// page at a time (G0 15, 15'). Zero protected values pass.
async fn verify_kek_values_before(
    client: &Client,
    key: &WrappingKey,
    tenant: &TenantId,
    deadline: Instant,
) -> Result<(), RecoveryControlError> {
    let value = |row: &tokio_postgres::Row| {
        row.try_get::<_, Option<String>>("value")
            .ok()
            .flatten()
            .ok_or_else(unverified)
    };
    // credentials: V1 or V2, every row including revoked ones.
    let mut after = Uuid::nil();
    loop {
        let rows = client
            .query(
                "SELECT id, kind::text AS kind, provider, key_id, CASE WHEN pg_catalog.octet_length(encrypted_value) <= $3 THEN encrypted_value END AS value FROM public.credentials WHERE id > $1 ORDER BY id LIMIT $2",
                &[&after, &PAGE, &VALUE_LIMIT],
            )
            .await
            .map_err(|_| io())?;
        for row in &rows {
            let id: Uuid = row.try_get("id").map_err(|_| io())?;
            let kind: String = row.try_get("kind").map_err(|_| io())?;
            let provider: String = row.try_get("provider").map_err(|_| io())?;
            let key_owner: String = row.try_get("key_id").map_err(|_| io())?;
            let service = || SecretPrincipal::Service(ServiceId::new(provider.clone()));
            let actor = || SecretPrincipal::Actor(ActorId::new(key_owner.clone()));
            let (kind, owner, consumer) = match kind.as_str() {
                "model" => (
                    SecretKind::Model,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Deployment,
                ),
                "connector" => (
                    SecretKind::Connector,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Deployment,
                ),
                "mcp" => (SecretKind::Mcp, SecretPrincipal::Deployment, service()),
                "agent" => (SecretKind::Agent, actor(), service()),
                "mcp_oauth_client" => (
                    SecretKind::McpOauthClient,
                    SecretPrincipal::Deployment,
                    service(),
                ),
                "mcp_user_token" => (SecretKind::McpUserToken, actor(), service()),
                _ => return Err(unverified()),
            };
            let binding = binding(tenant, id.to_string(), kind, owner, consumer);
            if !opens(key, &value(row)?, &binding, true, false) {
                return Err(unverified());
            }
            after = id;
        }
        before(deadline)?;
        if rows.len() < 32 {
            break;
        }
    }
    // model_connection_secrets and sdk_gateway_secrets: V2 only.
    for table in ["model_connection_secrets", "sdk_gateway_secrets"] {
        let sql = format!(
            "SELECT id, owner_user_id, connection_id::text AS connection, CASE WHEN pg_catalog.octet_length(encrypted_value) <= $3 THEN encrypted_value END AS value FROM public.{table} WHERE id > $1 ORDER BY id LIMIT $2"
        );
        let mut after = Uuid::nil();
        loop {
            let rows = client
                .query(&sql, &[&after, &PAGE, &VALUE_LIMIT])
                .await
                .map_err(|_| io())?;
            for row in &rows {
                let id: Uuid = row.try_get("id").map_err(|_| io())?;
                let owner: String = row.try_get("owner_user_id").map_err(|_| io())?;
                let connection: String = row.try_get("connection").map_err(|_| io())?;
                let binding = binding(
                    tenant,
                    id.to_string(),
                    SecretKind::Model,
                    SecretPrincipal::Actor(ActorId::new(owner)),
                    SecretPrincipal::Service(ServiceId::new(connection)),
                );
                if !opens(key, &value(row)?, &binding, false, false) {
                    return Err(unverified());
                }
                after = id;
            }
            before(deadline)?;
            if rows.len() < 32 {
                break;
            }
        }
    }
    // sso_providers: plaintext configuration is not a KEK value.
    let mut after = String::new();
    loop {
        let rows = client
            .query(
                "SELECT id, provider_id, oidc_config IS NOT NULL AS has_oidc, CASE WHEN pg_catalog.octet_length(oidc_config) <= $3 THEN oidc_config END AS oidc, saml_config IS NOT NULL AS has_saml, CASE WHEN pg_catalog.octet_length(saml_config) <= $3 THEN saml_config END AS saml FROM public.sso_providers WHERE id COLLATE \"C\" > $1 ORDER BY id COLLATE \"C\" LIMIT $2",
                &[&after, &PAGE, &VALUE_LIMIT],
            )
            .await
            .map_err(|_| io())?;
        for row in &rows {
            let id: String = row.try_get("id").map_err(|_| io())?;
            let provider: String = row.try_get("provider_id").map_err(|_| io())?;
            for (present, column, name) in [
                ("has_oidc", "oidc", "oidc_config"),
                ("has_saml", "saml", "saml_config"),
            ] {
                if !row.try_get::<_, bool>(present).map_err(|_| io())? {
                    continue;
                }
                let stored: String = row
                    .try_get::<_, Option<String>>(column)
                    .ok()
                    .flatten()
                    .ok_or_else(unverified)?;
                let binding = binding(
                    tenant,
                    format!("sso-provider/{provider}/{name}"),
                    SecretKind::Connector,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Deployment,
                );
                if !opens(key, &stored, &binding, true, true) {
                    return Err(unverified());
                }
            }
            after = id;
        }
        before(deadline)?;
        if rows.len() < 32 {
            break;
        }
    }
    Ok(())
}

/// No operation under `operations/` is a restore (spec 8088).
fn no_restore_operation_before(
    owner: &ControlOwner,
    deadline: Instant,
) -> Result<(), RecoveryControlError> {
    let mut files = lock(owner)?;
    let mut names = Vec::new();
    let maximum = files.limits.max_retained_operations;
    files.inventory_count(Directory::Operations, maximum, Some(&mut names), deadline)?;
    for name in names {
        let record = std::mem::size_of::<super::OwnedRecord>() as u64;
        let journal = files.read_journal(name.as_str(), record, deadline)?;
        let fee = super::super::journal::read_metadata_reservation(&journal.bytes, &files.limits)?;
        files.prepay(fee, 0)?;
        let chain = super::super::journal::observe_chain(&journal.bytes, &files.limits)?;
        files.post(deadline)?;
        if chain.is_restore() {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Read the actual Server site on `client`; `None` when it is not one PG 17
/// database whose session and current principals agree.
async fn actual_site(client: &Client) -> Result<Option<ServerDatabaseSite>, RecoveryControlError> {
    let row = client
        .query_one(crate::db::initialization::EXISTING_SERVER_IDENTITY_SQL, &[])
        .await
        .map_err(|_| io())?;
    let text = |column: &str| row.try_get::<_, String>(column).ok();
    Ok((|| {
        let principal = text("authenticated_principal")?;
        (Some(&principal) == text("current_principal").as_ref()
            && row.try_get::<_, i32>("pg_major").ok()? == 17)
            .then_some(())?;
        Some(ServerDatabaseSite {
            pg_system_id: text("system_identifier")?.parse().ok()?,
            database_oid: row.try_get("database_oid").ok()?,
            pg_major: 17,
            authenticated_principal: principal,
            database_owner: text("database_owner")?,
        })
    })())
}

/// Server legacy adoption on the writer session (S9 Server steps 2-7).
pub(in super::super) async fn adopt_server_legacy_before(
    owner: &ControlOwner,
    session: &mut OrdinaryInitializationSession,
    pool: &crate::db::pool::DatabasePool,
    database: &crate::db::pool::DatabaseConfig,
    configured: &crate::auth::config::KeyEncryptionKey,
) -> Result<(), RecoveryControlError> {
    use native::BootstrapTransactionClient as _;
    let (deployment, tenant, dataset, effect) = session.server_scope()?;
    let mut client = pool.get().await.map_err(|_| io())?;
    if session.adopts_published_head() {
        return adopt_published_server_before(
            session,
            &mut client,
            database,
            configured,
            &dataset,
            effect,
        )
        .await;
    }
    // 2. read-only site checks
    let site = actual_site(&client).await?.ok_or_else(invalid)?;
    let restore_table: bool = client
        .query_one(
            "SELECT to_regclass('openbot_internal.restore_pg_operations') IS NOT NULL",
            &[],
        )
        .await
        .and_then(|row| row.try_get(0))
        .map_err(|_| io())?;
    if restore_table {
        let restored: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM openbot_internal.restore_pg_operations)",
                &[],
            )
            .await
            .and_then(|row| row.try_get(0))
            .map_err(|_| io())?;
        if restored {
            return Err(invalid());
        }
    }
    no_restore_operation_before(owner, effect)?;
    native::validate_current(&client)
        .await
        .map_err(|_| invalid())?;
    let layout = crate::db::desktop_vault_canary::verify_pre_upgrade_layout_on(&client)
        .await
        .map_err(|_| invalid())?;
    if layout.native_version() != native::NATIVE_LATEST_VERSION {
        return Err(invalid());
    }
    before(effect)?;
    // 3. read-only KEK check
    let existing = crate::db::initialization::verify_server_canary(
        &client,
        configured,
        &deployment,
        &tenant,
        &dataset,
    )
    .await?;
    if existing.is_none() {
        verify_kek_values_before(&client, configured.wrapping_key(), &tenant, effect).await?;
    }
    // 4. seal
    session.seal_initializing(site.clone())?;
    // 5. ordinary_verify: the actual ledger head in a read-only RC transaction
    session.intend(OrdinaryStage::Verify)?;
    let transaction = client
        .bootstrap_transaction_builder()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .read_only(true)
        .start()
        .await
        .map_err(|_| io())?;
    let ledger = transaction
        .query_one(
            "SELECT version, checksum FROM openbot_internal.schema_migrations ORDER BY version DESC LIMIT 1",
            &[],
        )
        .await;
    let rollback = transaction.rollback().await;
    let returned = Instant::now();
    if !session.observe_rollback(rollback.is_ok(), returned)? {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::EffectExpired,
        ));
    }
    let row = ledger.map_err(|_| io())?;
    let version: i32 = row.try_get("version").map_err(|_| io())?;
    let migration_digest: String = row.try_get("checksum").map_err(|_| io())?;
    if version != native::NATIVE_LATEST_VERSION {
        return Err(invalid());
    }
    // 6. the first canary, only when the site has none
    let key_id = match existing {
        Some(key_id) => key_id,
        None => {
            let mut entropy = [0_u8; 16];
            getrandom::fill(&mut entropy).map_err(|_| io())?;
            let key_id = Hex32::mint(&entropy)?;
            session.intend(OrdinaryStage::KeySlot)?;
            let transaction = client
                .bootstrap_transaction_builder()
                .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
                .start()
                .await
                .map_err(|_| io())?;
            crate::db::initialization::insert_server_canary(
                &transaction,
                configured,
                &deployment,
                &tenant,
                &dataset,
                &key_id,
            )
            .await
            .map_err(|_| io())?;
            let commit = transaction.commit().await;
            let returned = Instant::now();
            if !session.observe_commit(commit.is_ok(), returned)? {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EffectExpired,
                ));
            }
            key_id
        }
    };
    // 7. proof and publication
    session.publish_active(OrdinaryActivationProof::Legacy(
        VerifiedOrdinaryLegacyProof {
            operation: session.operation()?,
            site: super::super::ordinary::LegacySite::Server { site, key_id },
            native_version: native::NATIVE_LATEST_VERSION.unsigned_abs(),
            migration_digest,
        },
    ))
}

/// A published Server head below the latest native version, after the
/// operator migrated the database and supplied a legacy_adoption intent
/// (OMB-裁-129 item 2, OMB-裁-130): the current schema and the sealed site
/// are checked read-only before the adoption operation opens; the existing
/// canary is the key proof, so there is no key_slot.
async fn adopt_published_server_before(
    session: &mut OrdinaryInitializationSession,
    client: &mut crate::db::pool::PooledClient,
    database: &crate::db::pool::DatabaseConfig,
    configured: &crate::auth::config::KeyEncryptionKey,
    dataset: &Hex32,
    effect: Instant,
) -> Result<(), RecoveryControlError> {
    use native::BootstrapTransactionClient as _;
    native::validate_current(client)
        .await
        .map_err(|_| invalid())?;
    let binding = session.published_binding()?.clone();
    super::compare_server_site_before(client, &binding, database, configured, dataset, effect)
        .await?;
    let server = binding.ordinary_server()?;
    let (site, key_id) = (
        server.server_database.clone(),
        Hex32::parse(&server.master.key_id)?,
    );
    session.seal_published()?;
    let transaction = client
        .bootstrap_transaction_builder()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .read_only(true)
        .start()
        .await
        .map_err(|_| io())?;
    let ledger = transaction
        .query_one(
            "SELECT version, checksum FROM openbot_internal.schema_migrations ORDER BY version DESC LIMIT 1",
            &[],
        )
        .await;
    let rollback = transaction.rollback().await;
    let returned = Instant::now();
    if !session.observe_rollback(rollback.is_ok(), returned)? {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::EffectExpired,
        ));
    }
    let row = ledger.map_err(|_| io())?;
    let version: i32 = row.try_get("version").map_err(|_| io())?;
    let migration_digest: String = row.try_get("checksum").map_err(|_| io())?;
    if version != native::NATIVE_LATEST_VERSION {
        return Err(invalid());
    }
    session.publish_active(OrdinaryActivationProof::Legacy(
        VerifiedOrdinaryLegacyProof {
            operation: session.operation()?,
            site: super::super::ordinary::LegacySite::Server { site, key_id },
            native_version: native::NATIVE_LATEST_VERSION.unsigned_abs(),
            migration_digest,
        },
    ))
}
