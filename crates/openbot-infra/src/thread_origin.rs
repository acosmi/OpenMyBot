//! Immutable historical creation facts. These values supply no current permission or owner grant.

use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::intelligence::IntelligenceThreadChecksum;
use serde_json::Value;
use time::OffsetDateTime;
use tokio_postgres::{GenericClient, Row, Transaction};

use crate::db::{InfraError, RowDecodeError};

#[derive(Clone, Copy)]
pub(crate) enum NativeOriginKind {
    BeginV1,
    BeginV2,
    PrivateAgentChannel,
}

impl NativeOriginKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BeginV1 => "native_begin_v1",
            Self::BeginV2 => "native_begin_v2",
            Self::PrivateAgentChannel => "private_agent_channel",
        }
    }
}

/// Absence is historical uncertainty, never an instruction to adopt or mint an existing Thread.
pub(crate) enum OriginObservation {
    Known,
    LegacyUnknown,
}

/// Complete validated historical facts. This internal value has no current permission.
pub(crate) struct KnownThreadOrigin {
    _deployment: String,
    _tenant: String,
    _creator: String,
    _thread_id: String,
    _anchor_kind: String,
    _anchor_id: String,
    _created_at: OffsetDateTime,
    _recorded_at: OffsetDateTime,
    _kind: String,
    _schema: i16,
    _bundle: Option<String>,
    _payload: Option<String>,
    _signing_key: Option<String>,
    _checksum: Option<Value>,
}

#[cfg(feature = "server-runtime")]
impl KnownThreadOrigin {
    pub(crate) fn deployment(&self) -> &str {
        &self._deployment
    }
    pub(crate) fn tenant(&self) -> &str {
        &self._tenant
    }
    pub(crate) fn creator(&self) -> &str {
        &self._creator
    }
}

pub(crate) const CURRENT_COLUMNS: &str = "o.*,t.thread_id IS NOT NULL AS base_present, \
                    t.deployment_id AS base_deployment,t.tenant_id AS base_tenant, \
                    t.created_by AS base_creator,t.anchor_kind AS base_anchor_kind, \
                    t.anchor_id AS base_anchor_id,t.created_at AS base_created_at, \
                    CASE WHEN o.origin_kind='maintenance_import' \
                              AND jsonb_typeof(o.import_thread_checksum)='object' THEN ( \
                      SELECT coalesce(bool_and(CASE WHEN jsonb_typeof(value)='number' THEN \
                        (value #>> '{}')::numeric BETWEEN 0 AND 18446744073709551615 \
                        AND (value #>> '{}')::numeric=trunc((value #>> '{}')::numeric) \
                        ELSE false END),false) \
                      FROM jsonb_each(o.import_thread_checksum) \
                      WHERE key IN ('messageCount','eventCount','memoryCount') \
                    ) ELSE o.origin_kind<>'maintenance_import' END AS import_counts_valid";

fn invalid() -> InfraError {
    InfraError::repository_invariant("thread_origin_binding_invalid")
}

fn identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode<T: tokio_postgres::types::FromSqlOwned>(
    row: &Row,
    column: &'static str,
) -> Result<T, InfraError> {
    row.try_get(column)
        .map_err(|source| RowDecodeError::column("thread_origins", column, source).into())
}

/// Called only for actual new native producers. User SHARE follows the normal revocation lock.
/// The returned admin fact is compared with the original channel scope; it is not an owner grant.
pub(crate) async fn current_native_actor(
    tx: &Transaction<'_>,
    actor: &str,
    generation: AuthGeneration,
) -> Result<Option<bool>, InfraError> {
    let Ok(generation) = i64::try_from(generation.get()) else {
        return Ok(None);
    };
    let row = tx
        .query_opt(
            "SELECT EXISTS(SELECT 1 FROM public.user_roles ur \
                      WHERE ur.user_id=u.id AND ur.role='admin') AS admin \
             FROM public.users u \
             WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 \
               AND EXISTS(SELECT 1 FROM public.user_roles ur \
                          WHERE ur.user_id=u.id AND ur.role IN ('user','admin')) \
               AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra \
                              WHERE ra.email=lower(u.email)) FOR SHARE OF u",
            &[&actor, &generation],
        )
        .await
        .map_err(|source| InfraError::query("verify new Thread current actor", source))?;
    row.map(|row| decode(&row, "admin")).transpose()
}

/// The caller has just inserted this Thread in the same transaction. All base facts come from it.
pub(crate) async fn record_new_native(
    tx: &Transaction<'_>,
    thread_id: &str,
    kind: NativeOriginKind,
) -> Result<(), InfraError> {
    record(tx, thread_id, kind.as_str(), None).await
}

/// Maintenance provenance records the real mapped import, not a cryptographic capability.
pub(crate) async fn record_new_import(
    tx: &Transaction<'_>,
    thread_id: &str,
    bundle_id: &str,
    payload_sha256: &str,
    signing_key_id: &str,
    checksum: &IntelligenceThreadChecksum,
) -> Result<(), InfraError> {
    if !identity(bundle_id) || !identity(signing_key_id) || !hash(payload_sha256) {
        return Err(invalid());
    }
    let checksum = serde_json::to_value(checksum).map_err(|_| invalid())?;
    record(
        tx,
        thread_id,
        "maintenance_import",
        Some(ImportFields {
            bundle_id,
            payload_sha256,
            signing_key_id,
            checksum: &checksum,
        }),
    )
    .await
}

struct ImportFields<'a> {
    bundle_id: &'a str,
    payload_sha256: &'a str,
    signing_key_id: &'a str,
    checksum: &'a Value,
}

async fn record(
    tx: &Transaction<'_>,
    thread_id: &str,
    kind: &str,
    import: Option<ImportFields<'_>>,
) -> Result<(), InfraError> {
    let bundle_id = import.as_ref().map(|facts| facts.bundle_id);
    let payload_sha256 = import.as_ref().map(|facts| facts.payload_sha256);
    let signing_key_id = import.as_ref().map(|facts| facts.signing_key_id);
    let checksum = import.as_ref().map(|facts| facts.checksum);
    let count = tx
        .execute(
            "INSERT INTO openbot_internal.thread_origins( \
               thread_id,deployment_id,tenant_id,creator_actor_id,anchor_kind,anchor_id, \
               thread_created_at,origin_kind,origin_schema,recorded_at, \
               import_bundle_id,import_payload_sha256,import_signing_key_id,import_thread_checksum \
             ) SELECT t.thread_id,t.deployment_id,t.tenant_id,t.created_by,t.anchor_kind,t.anchor_id, \
                      t.created_at,$2,1,clock_timestamp(),$3,$4,$5,$6 \
               FROM public.threads t WHERE t.thread_id=$1",
            &[
                &thread_id,
                &kind,
                &bundle_id,
                &payload_sha256,
                &signing_key_id,
                &checksum,
            ],
        )
        .await
        .map_err(|source| {
            if source.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                InfraError::repository_invariant("thread_origin_already_recorded")
            } else {
                InfraError::query("record new Thread historical origin", source)
            }
        })?;
    if count != 1 || !matches!(observe_on(tx, thread_id).await?, OriginObservation::Known) {
        return Err(invalid());
    }
    Ok(())
}

/// Read all historical fields and bind a surviving source tuple. A hard-deleted source leaves IDs.
/// The original caller supplies its own Client/Transaction; this never acquires or ends either.
pub(crate) async fn observe_on(
    client: &impl GenericClient,
    thread_id: &str,
) -> Result<OriginObservation, InfraError> {
    let sql = format!(
        "SELECT {CURRENT_COLUMNS} FROM openbot_internal.thread_origins o \
        LEFT JOIN public.threads t ON t.thread_id=o.thread_id WHERE o.thread_id=$1"
    );
    let row = client
        .query_opt(&sql, &[&thread_id])
        .await
        .map_err(|source| InfraError::query("observe immutable Thread origin", source))?;
    let Some(row) = row else {
        return Ok(OriginObservation::LegacyUnknown);
    };
    let _ = decode_known_row(&row, thread_id)?;
    Ok(OriginObservation::Known)
}

/// Decode the same complete 14-field projection, including the live base-tuple binding.
/// The caller separately establishes a stored row; decode failures never become LegacyUnknown.
pub(crate) fn decode_known_row(
    row: &Row,
    thread_id: &str,
) -> Result<KnownThreadOrigin, InfraError> {
    let stored_thread: String = decode(row, "thread_id")?;
    let deployment: String = decode(row, "deployment_id")?;
    let tenant: String = decode(row, "tenant_id")?;
    let creator: String = decode(row, "creator_actor_id")?;
    let anchor_kind: String = decode(row, "anchor_kind")?;
    let anchor_id: String = decode(row, "anchor_id")?;
    let created_at: OffsetDateTime = decode(row, "thread_created_at")?;
    let recorded_at: OffsetDateTime = decode(row, "recorded_at")?;
    let kind: String = decode(row, "origin_kind")?;
    let schema: i16 = decode(row, "origin_schema")?;
    if stored_thread != thread_id
        || [&stored_thread, &deployment, &tenant, &creator, &anchor_id]
            .into_iter()
            .any(|value| !identity(value))
        || !matches!(anchor_kind.as_str(), "direct_bot" | "channel")
        || !matches!(
            kind.as_str(),
            "native_begin_v1" | "native_begin_v2" | "private_agent_channel" | "maintenance_import"
        )
        || (kind == "private_agent_channel" && anchor_kind != "channel")
        || schema != 1
    {
        return Err(invalid());
    }
    let bundle: Option<String> = decode(row, "import_bundle_id")?;
    let payload: Option<String> = decode(row, "import_payload_sha256")?;
    let key: Option<String> = decode(row, "import_signing_key_id")?;
    let checksum: Option<Value> = decode(row, "import_thread_checksum")?;
    if kind == "maintenance_import" {
        let valid = bundle.as_deref().is_some_and(identity)
            && payload.as_deref().is_some_and(hash)
            && key.as_deref().is_some_and(identity)
            && decode::<bool>(row, "import_counts_valid")?
            && checksum.as_ref().is_some_and(valid_checksum);
        if !valid {
            return Err(invalid());
        }
    } else if bundle.is_some() || payload.is_some() || key.is_some() || checksum.is_some() {
        return Err(invalid());
    }
    if decode::<bool>(row, "base_present")?
        && (decode::<Option<String>>(row, "base_deployment")?.as_deref()
            != Some(deployment.as_str())
            || decode::<Option<String>>(row, "base_tenant")?.as_deref() != Some(tenant.as_str())
            || decode::<Option<String>>(row, "base_creator")?.as_deref() != Some(creator.as_str())
            || decode::<Option<String>>(row, "base_anchor_kind")?.as_deref()
                != Some(anchor_kind.as_str())
            || decode::<Option<String>>(row, "base_anchor_id")?.as_deref()
                != Some(anchor_id.as_str())
            || decode::<Option<OffsetDateTime>>(row, "base_created_at")? != Some(created_at))
    {
        return Err(invalid());
    }
    Ok(KnownThreadOrigin {
        _deployment: deployment,
        _tenant: tenant,
        _creator: creator,
        _thread_id: stored_thread,
        _anchor_kind: anchor_kind,
        _anchor_id: anchor_id,
        _created_at: created_at,
        _recorded_at: recorded_at,
        _kind: kind,
        _schema: schema,
        _bundle: bundle,
        _payload: payload,
        _signing_key: key,
        _checksum: checksum,
    })
}

fn valid_checksum(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let hashes = [
        "projectionHash",
        "messageHash",
        "eventHash",
        "terminalStateHash",
        "memoryHash",
        "sampleRenderHash",
    ];
    let counts = ["messageCount", "eventCount", "memoryCount"];
    object.len() == 9
        && hashes
            .into_iter()
            .all(|key| object.get(key).and_then(Value::as_str).is_some_and(hash))
        && counts
            .into_iter()
            .all(|key| object.get(key).is_some_and(Value::is_number))
}
