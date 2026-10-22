//! append-only audit event / checkpoint repository（v3 §8.6）。
//!
//! 全部署用 transaction advisory lock 串行分配链前驱与 checkpoint sequence；event、hash 以及
//! 首条 genesis checkpoint 同事务提交。没有 checkpoint key、已有链却没有 genesis checkpoint、
//! 或数据库 hash 无法解析时全部 fail-closed。这里没有 UPDATE/DELETE API，数据库 trigger 再挡
//! 一层绕过。

use crate::db::pool::DatabasePool as Pool;
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openbot_application::{AuditPageRequest, AuditReadError, AuditReader};
use openbot_contracts::audit::{AuditEventView, AuditPage};
use openbot_contracts::ids::{ActorId, AuditEventId};
use openbot_domain::audit::chain::{PrevRowHash, StoredAuditRow};
use openbot_domain::audit::checkpoint::{
    AuditCheckpoint, AuditCheckpointKind, CheckpointSignature,
};
use openbot_domain::audit::event::AuditEvent;
use openbot_domain::audit::hash::Sha256Digest;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::InfraError;
use crate::db::tables::{audit_checkpoints, audit_events};

pub(crate) const AUDIT_CHAIN_LOCK_KEY: i64 = 0x4f50_454e_4155_4431; // ASCII `OPENAUD1`

/// audit event 与 checkpoint 的唯一写入面。
#[derive(Clone)]
pub struct AuditEventRepo {
    pool: Pool,
}

impl AuditEventRepo {
    /// 用调用方提供的池构造。
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// 追加一条审计事件；首条 Rust 链上行与 genesis checkpoint 同事务落库。
    pub async fn append(
        &self,
        event: &AuditEvent,
        checkpoint_key: &[u8],
    ) -> Result<StoredAuditRow, InfraError> {
        let mut client = self.pool.get().await.map_err(|source| {
            InfraError::connect("为 AuditEventRepo 获取 append 事务连接", source)
        })?;
        let transaction = client
            .transaction()
            .await
            .map_err(|source| InfraError::query("开始 audit append 事务", source))?;
        let linked = append_event_in_transaction(&transaction, event, checkpoint_key).await?;
        transaction
            .commit()
            .await
            .map_err(|source| InfraError::query("提交 audit append", source))?;
        Ok(linked)
    }

    /// 追加 periodic/closure checkpoint；sequence 在同一把锁下无空洞分配。
    pub async fn append_checkpoint(
        &self,
        kind: AuditCheckpointKind,
        created_at: OffsetDateTime,
        checkpoint_key: &[u8],
    ) -> Result<AuditCheckpoint, InfraError> {
        if checkpoint_key.is_empty() {
            return Err(InfraError::repository_invariant(
                "audit_checkpoint_key_empty",
            ));
        }
        if matches!(kind, AuditCheckpointKind::Genesis { .. }) {
            return Err(InfraError::repository_invariant(
                "genesis_checkpoint_only_created_with_first_row",
            ));
        }
        let mut client = self.pool.get().await.map_err(|source| {
            InfraError::connect("为 AuditEventRepo 获取 checkpoint 事务连接", source)
        })?;
        let transaction = client
            .transaction()
            .await
            .map_err(|source| InfraError::query("开始 audit checkpoint 事务", source))?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK_KEY])
            .await
            .map_err(|source| InfraError::query("获取 audit checkpoint 锁", source))?;
        verify_checkpoint_segment(&transaction, &kind).await?;
        let next: i64 = transaction
            .query_one(
                "SELECT coalesce(max(sequence), -1)::bigint + 1 FROM public.audit_checkpoints",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("分配 audit checkpoint sequence", source))?
            .try_get(0)
            .map_err(|source| {
                crate::db::RowDecodeError::column("audit_checkpoints", "sequence", source)
            })?;
        let checkpoint = AuditCheckpoint {
            sequence: u64::try_from(next).map_err(|_| {
                InfraError::repository_invariant("audit_checkpoint_sequence_negative")
            })?,
            created_at,
            kind,
        };
        insert_checkpoint(&transaction, &checkpoint, checkpoint_key).await?;
        transaction
            .commit()
            .await
            .map_err(|source| InfraError::query("提交 audit checkpoint", source))?;
        Ok(checkpoint)
    }

    /// 按链顺序读取全部当前行（旧行 hash 双 NULL 也保留）。
    pub async fn list_all(&self) -> Result<Vec<audit_events::ChainedRow>, InfraError> {
        let client = self.pool.get().await.map_err(|source| {
            InfraError::connect("为 AuditEventRepo 读取 chain 获取连接", source)
        })?;
        let rows = client
            .query(
                "SELECT id,actor_user_id,event_type,target_type,target_id,payload,created_at, \
                        prev_hash,row_hash \
                 FROM public.audit_events ORDER BY created_at, id",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("列出 audit chain", source))?;
        rows.iter()
            .map(audit_events::ChainedRow::try_from)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    /// 按 sequence 列出 checkpoint 行。
    pub async fn list_checkpoints(&self) -> Result<Vec<audit_checkpoints::Row>, InfraError> {
        let client = self.pool.get().await.map_err(|source| {
            InfraError::connect("为 AuditEventRepo 读取 checkpoint 获取连接", source)
        })?;
        let rows = client
            .query(
                "SELECT sequence,checkpoint_kind,first_event_id,first_row_hash,last_event_id, \
                        last_row_hash,event_count,unlinked_rows_before,retention_days,signature,created_at \
                 FROM public.audit_checkpoints ORDER BY sequence",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("列出 audit checkpoints", source))?;
        rows.iter()
            .map(audit_checkpoints::Row::try_from)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

/// `/api/admin/audit-events` 的 PostgreSQL keyset reader。
#[derive(Clone, Debug)]
pub struct PostgresAuditReader {
    pool: Pool,
}

impl PostgresAuditReader {
    /// 用共享连接池构造。
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditCursor {
    created_at_unix_nanos: String,
    id: String,
}

#[async_trait]
impl AuditReader for PostgresAuditReader {
    async fn list_audit_events(
        &self,
        request: AuditPageRequest,
    ) -> Result<AuditPage, AuditReadError> {
        let cursor = request
            .cursor
            .as_deref()
            .map(decode_audit_cursor)
            .transpose()?;
        let has_types = !request.event_types.is_empty();
        let actor = request.actor_user_id.as_ref().map(ActorId::as_str);
        let has_cursor = cursor.is_some();
        let cursor_at = cursor.as_ref().map(|value| value.0);
        let cursor_id = cursor.as_ref().map(|value| value.1);
        let limit = i64::from(request.limit) + 1;
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "audit reader 获取连接失败");
            AuditReadError::Unavailable
        })?;
        let rows = client
            .query(
                "SELECT id,actor_user_id,event_type,target_type,target_id,payload,created_at \
                 FROM public.audit_events \
                 WHERE (NOT $1::boolean OR event_type=ANY($2::text[])) \
                   AND ($3::text IS NULL OR actor_user_id=$3) \
                   AND ($4::text IS NULL OR target_type=$4) \
                   AND ($5::text IS NULL OR target_id=$5) \
                   AND ($6::timestamptz IS NULL OR created_at>$6) \
                   AND ($7::timestamptz IS NULL OR created_at<$7) \
                   AND (NOT $8::boolean OR created_at<$9 \
                        OR (created_at=$9 AND id<$10)) \
                 ORDER BY created_at DESC,id DESC LIMIT $11",
                &[
                    &has_types,
                    &request.event_types,
                    &actor,
                    &request.target_type,
                    &request.target_id,
                    &request.from,
                    &request.to,
                    &has_cursor,
                    &cursor_at,
                    &cursor_id,
                    &limit,
                ],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "audit reader 查询失败");
                AuditReadError::Unavailable
            })?;
        let mut events = rows
            .iter()
            .map(audit_view_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = events.len() > request.limit as usize;
        events.truncate(request.limit as usize);
        let next_cursor = if has_more {
            events.last().map(encode_audit_cursor).transpose()?
        } else {
            None
        };
        Ok(AuditPage {
            events,
            next_cursor,
        })
    }
}

fn audit_view_from_row(row: &tokio_postgres::Row) -> Result<AuditEventView, AuditReadError> {
    let id: Uuid = audit_column(row, "id")?;
    let actor: Option<String> = audit_column(row, "actor_user_id")?;
    let payload: serde_json::Value = audit_column(row, "payload")?;
    if !payload.is_object() {
        return Err(AuditReadError::Corrupt { field: "payload" });
    }
    Ok(AuditEventView {
        id: AuditEventId::new(id.to_string()),
        actor_user_id: actor.map(ActorId::new),
        event_type: audit_column(row, "event_type")?,
        target_type: audit_column(row, "target_type")?,
        target_id: audit_column(row, "target_id")?,
        payload,
        created_at: audit_column(row, "created_at")?,
    })
}

fn audit_column<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    column: &'static str,
) -> Result<T, AuditReadError> {
    row.try_get(column).map_err(|error| {
        tracing::error!(column, error = %error, "audit reader 行解码失败");
        AuditReadError::Corrupt { field: column }
    })
}

fn encode_audit_cursor(event: &AuditEventView) -> Result<String, AuditReadError> {
    let bytes = serde_json::to_vec(&AuditCursor {
        created_at_unix_nanos: event.created_at.unix_timestamp_nanos().to_string(),
        id: event.id.as_str().to_owned(),
    })
    .map_err(|_| AuditReadError::Corrupt { field: "cursor" })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_audit_cursor(raw: &str) -> Result<(OffsetDateTime, Uuid), AuditReadError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AuditReadError::InvalidCursor)?;
    let cursor: AuditCursor =
        serde_json::from_slice(&bytes).map_err(|_| AuditReadError::InvalidCursor)?;
    let nanos = cursor
        .created_at_unix_nanos
        .parse::<i128>()
        .map_err(|_| AuditReadError::InvalidCursor)?;
    let created_at = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| AuditReadError::InvalidCursor)?;
    let id = Uuid::parse_str(&cursor.id).map_err(|_| AuditReadError::InvalidCursor)?;
    Ok((created_at, id))
}

/// 在调用方已有事务里追加事件；people/tool 等 acting 事务用它保证业务写与 audit 同 commit。
pub(crate) async fn append_event_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    event: &AuditEvent,
    checkpoint_key: &[u8],
) -> Result<StoredAuditRow, InfraError> {
    if checkpoint_key.is_empty() {
        return Err(InfraError::repository_invariant(
            "audit_checkpoint_key_empty",
        ));
    }
    let event_uuid = Uuid::parse_str(event.id.as_str())
        .map_err(|_| InfraError::repository_invariant("audit_event_id_not_uuid"))?;
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK_KEY])
        .await
        .map_err(|source| InfraError::query("获取 audit chain 锁", source))?;

    let latest = transaction
        .query_opt(
            "SELECT id,created_at,row_hash FROM public.audit_events \
             ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("读取 audit 表尾", source))?;
    let previous = match latest {
        Some(row) => {
            let latest_id: Uuid = row.try_get("id").map_err(|source| {
                crate::db::RowDecodeError::column("audit_events", "id", source)
            })?;
            let latest_at: OffsetDateTime = row.try_get("created_at").map_err(|source| {
                crate::db::RowDecodeError::column("audit_events", "created_at", source)
            })?;
            if (event.created_at, event_uuid) <= (latest_at, latest_id) {
                return Err(InfraError::repository_invariant(
                    "audit_event_order_not_monotonic",
                ));
            }
            let text: Option<String> = row.try_get("row_hash").map_err(|source| {
                crate::db::RowDecodeError::column("audit_events", "row_hash", source)
            })?;
            match text {
                Some(text) => PrevRowHash::Linked(
                    Sha256Digest::parse_hex(&text)
                        .map_err(|_| InfraError::repository_invariant("audit_row_hash_invalid"))?,
                ),
                None => {
                    let linked_exists: bool = transaction
                        .query_one(
                            "SELECT EXISTS(SELECT 1 FROM public.audit_events \
                             WHERE row_hash IS NOT NULL)",
                            &[],
                        )
                        .await
                        .map_err(|source| InfraError::query("检查 audit chain 后置旧行", source))?
                        .try_get(0)
                        .map_err(|source| {
                            crate::db::RowDecodeError::column("audit_events", "exists", source)
                        })?;
                    if linked_exists {
                        return Err(InfraError::repository_invariant(
                            "unlinked_audit_row_after_chain_start",
                        ));
                    }
                    PrevRowHash::Genesis
                }
            }
        }
        None => PrevRowHash::Genesis,
    };
    let linked = StoredAuditRow::link(event.clone(), previous);
    let prev_hash = linked.prev_hash.map(|hash| hash.to_hex());
    let row_hash = linked
        .row_hash
        .expect("StoredAuditRow::link 必有 row_hash")
        .to_hex();
    let actor = event.actor.as_ref().map(|actor| actor.as_str());
    let target_id = event.target_id.as_ref().map(|id| id.as_str());
    let payload = event.payload.to_json();
    transaction
        .execute(
            "INSERT INTO public.audit_events \
             (id, actor_user_id, event_type, target_type, target_id, payload, created_at, \
              prev_hash, row_hash) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &event_uuid,
                &actor,
                &event.event_type.as_str(),
                &event.target_kind.as_str(),
                &target_id,
                &payload,
                &event.created_at,
                &prev_hash,
                &row_hash,
            ],
        )
        .await
        .map_err(|source| InfraError::query("追加 audit event", source))?;

    if matches!(previous, PrevRowHash::Genesis) {
        let existing_checkpoints: i64 = transaction
            .query_one("SELECT count(*)::bigint FROM public.audit_checkpoints", &[])
            .await
            .map_err(|source| InfraError::query("检查 genesis checkpoint 前提", source))?
            .try_get(0)
            .map_err(|source| {
                crate::db::RowDecodeError::column("audit_checkpoints", "count", source)
            })?;
        if existing_checkpoints != 0 {
            return Err(InfraError::repository_invariant(
                "checkpoint_exists_without_audit_chain",
            ));
        }
        let unlinked_rows_before: i64 = transaction
            .query_one(
                "SELECT count(*)::bigint FROM public.audit_events \
                 WHERE row_hash IS NULL AND prev_hash IS NULL",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("统计 chain 前旧审计行", source))?
            .try_get(0)
            .map_err(|source| crate::db::RowDecodeError::column("audit_events", "count", source))?;
        let checkpoint = AuditCheckpoint {
            sequence: 0,
            created_at: event.created_at,
            kind: AuditCheckpointKind::Genesis {
                genesis_event: event.id.clone(),
                genesis_row_hash: linked.row_hash.expect("link 必有 hash"),
                unlinked_rows_before: u64::try_from(unlinked_rows_before).map_err(|_| {
                    InfraError::repository_invariant("audit_unlinked_count_negative")
                })?,
            },
        };
        insert_checkpoint(transaction, &checkpoint, checkpoint_key).await?;
    } else {
        let checkpoints: i64 = transaction
            .query_one("SELECT count(*)::bigint FROM public.audit_checkpoints", &[])
            .await
            .map_err(|source| InfraError::query("确认 audit genesis checkpoint", source))?
            .try_get(0)
            .map_err(|source| {
                crate::db::RowDecodeError::column("audit_checkpoints", "count", source)
            })?;
        if checkpoints == 0 {
            return Err(InfraError::repository_invariant(
                "audit_chain_without_genesis_checkpoint",
            ));
        }
    }
    Ok(linked)
}

/// 在 audit 锁内铸造严格晚于当前表尾的 `(id, created_at)`；跨事务业务写用。
pub(crate) async fn next_event_coordinates(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<(openbot_contracts::ids::AuditEventId, OffsetDateTime), InfraError> {
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK_KEY])
        .await
        .map_err(|source| InfraError::query("获取 audit coordinate 锁", source))?;
    let row = transaction
        .query_one(
            "SELECT gen_random_uuid() AS id, \
                    CASE WHEN max(created_at) >= clock_timestamp() \
                         THEN max(created_at) + interval '1 microsecond' \
                         ELSE clock_timestamp() END AS created_at \
             FROM public.audit_events",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("铸造 audit event coordinate", source))?;
    let id: Uuid = row
        .try_get("id")
        .map_err(|source| crate::db::RowDecodeError::column("audit_events", "id", source))?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(|source| {
        crate::db::RowDecodeError::column("audit_events", "created_at", source)
    })?;
    Ok((
        openbot_contracts::ids::AuditEventId::new(id.to_string()),
        created_at,
    ))
}

impl core::fmt::Debug for AuditEventRepo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuditEventRepo").finish_non_exhaustive()
    }
}

async fn insert_checkpoint(
    transaction: &tokio_postgres::Transaction<'_>,
    checkpoint: &AuditCheckpoint,
    key: &[u8],
) -> Result<(), InfraError> {
    let signature = checkpoint
        .sign(key)
        .map_err(|_| InfraError::repository_invariant("audit_checkpoint_key_empty"))?;
    let columns = checkpoint_columns(&checkpoint.kind)?;
    let sequence = i64::try_from(checkpoint.sequence)
        .map_err(|_| InfraError::repository_invariant("audit_checkpoint_sequence_overflow"))?;
    let event_count = i64::try_from(columns.event_count)
        .map_err(|_| InfraError::repository_invariant("audit_checkpoint_count_overflow"))?;
    let unlinked = columns
        .unlinked
        .map(i64::try_from)
        .transpose()
        .map_err(|_| InfraError::repository_invariant("audit_unlinked_count_overflow"))?;
    let signature = signature_hex(&signature);
    transaction
        .execute(
            "INSERT INTO public.audit_checkpoints \
             (sequence,checkpoint_kind,first_event_id,first_row_hash,last_event_id,last_row_hash, \
              event_count,unlinked_rows_before,retention_days,signature,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            &[
                &sequence,
                &columns.kind,
                &columns.first_event,
                &columns.first_hash,
                &columns.last_event,
                &columns.last_hash,
                &event_count,
                &unlinked,
                &columns.retention,
                &signature,
                &checkpoint.created_at,
            ],
        )
        .await
        .map_err(|source| InfraError::query("追加 audit checkpoint", source))?;
    Ok(())
}

struct CheckpointColumns {
    kind: &'static str,
    first_event: String,
    first_hash: String,
    last_event: String,
    last_hash: String,
    event_count: u64,
    unlinked: Option<u64>,
    retention: Option<i32>,
}

fn checkpoint_columns(kind: &AuditCheckpointKind) -> Result<CheckpointColumns, InfraError> {
    Ok(match kind {
        AuditCheckpointKind::Genesis {
            genesis_event,
            genesis_row_hash,
            unlinked_rows_before,
        } => CheckpointColumns {
            kind: "genesis",
            first_event: genesis_event.as_str().to_owned(),
            first_hash: genesis_row_hash.to_hex(),
            last_event: genesis_event.as_str().to_owned(),
            last_hash: genesis_row_hash.to_hex(),
            event_count: 1,
            unlinked: Some(*unlinked_rows_before),
            retention: None,
        },
        AuditCheckpointKind::Periodic { segment } => CheckpointColumns {
            kind: "periodic",
            first_event: segment.first_event.as_str().to_owned(),
            first_hash: segment.first_row_hash.to_hex(),
            last_event: segment.last_event.as_str().to_owned(),
            last_hash: segment.last_row_hash.to_hex(),
            event_count: segment.event_count,
            unlinked: None,
            retention: None,
        },
        AuditCheckpointKind::Closure {
            segment,
            retention_days,
        } => {
            CheckpointColumns {
                kind: "closure",
                first_event: segment.first_event.as_str().to_owned(),
                first_hash: segment.first_row_hash.to_hex(),
                last_event: segment.last_event.as_str().to_owned(),
                last_hash: segment.last_row_hash.to_hex(),
                event_count: segment.event_count,
                unlinked: None,
                retention: Some(i32::try_from(retention_days.get()).map_err(|_| {
                    InfraError::repository_invariant("audit_retention_days_overflow")
                })?),
            }
        }
    })
}

async fn verify_checkpoint_segment(
    transaction: &tokio_postgres::Transaction<'_>,
    kind: &AuditCheckpointKind,
) -> Result<(), InfraError> {
    let segment = match kind {
        AuditCheckpointKind::Genesis { .. } => return Ok(()),
        AuditCheckpointKind::Periodic { segment }
        | AuditCheckpointKind::Closure { segment, .. } => segment,
    };
    let first_id = Uuid::parse_str(segment.first_event.as_str())
        .map_err(|_| InfraError::repository_invariant("audit_checkpoint_first_id_not_uuid"))?;
    let last_id = Uuid::parse_str(segment.last_event.as_str())
        .map_err(|_| InfraError::repository_invariant("audit_checkpoint_last_id_not_uuid"))?;
    let first = transaction
        .query_opt(
            "SELECT created_at,row_hash FROM public.audit_events WHERE id=$1 AND row_hash=$2",
            &[&first_id, &segment.first_row_hash.to_hex()],
        )
        .await
        .map_err(|source| InfraError::query("验证 checkpoint 首边界", source))?
        .ok_or_else(|| {
            InfraError::repository_invariant("audit_checkpoint_first_boundary_missing")
        })?;
    let last = transaction
        .query_opt(
            "SELECT created_at,row_hash FROM public.audit_events WHERE id=$1 AND row_hash=$2",
            &[&last_id, &segment.last_row_hash.to_hex()],
        )
        .await
        .map_err(|source| InfraError::query("验证 checkpoint 尾边界", source))?
        .ok_or_else(|| {
            InfraError::repository_invariant("audit_checkpoint_last_boundary_missing")
        })?;
    let first_at: OffsetDateTime = first.try_get("created_at").map_err(|source| {
        crate::db::RowDecodeError::column("audit_events", "created_at", source)
    })?;
    let last_at: OffsetDateTime = last.try_get("created_at").map_err(|source| {
        crate::db::RowDecodeError::column("audit_events", "created_at", source)
    })?;
    let count: i64 = transaction
        .query_one(
            "SELECT count(*)::bigint FROM public.audit_events \
             WHERE row_hash IS NOT NULL \
               AND (created_at,id) >= ($1,$2) AND (created_at,id) <= ($3,$4)",
            &[&first_at, &first_id, &last_at, &last_id],
        )
        .await
        .map_err(|source| InfraError::query("验证 checkpoint 区间条数", source))?
        .try_get(0)
        .map_err(|source| crate::db::RowDecodeError::column("audit_events", "count", source))?;
    if u64::try_from(count).ok() != Some(segment.event_count) {
        return Err(InfraError::repository_invariant(
            "audit_checkpoint_event_count_mismatch",
        ));
    }
    Ok(())
}

fn signature_hex(signature: &CheckpointSignature) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in signature.as_bytes() {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
mod capture_periodic {
    use super::*;
    use crate::backup::whole_pg_capture_stream::CaptureClockCheck;
    use crate::db::capture_materials::{
        CaptureSqlBudget, CaptureSqlFailure, CapturedDbRow, read_capture_audit,
    };
    use openbot_domain::audit::checkpoint::ChainSegment;
    use openbot_domain::audit::hash::CanonicalWriter;
    use openbot_domain::audit::payload::AUDIT_FIELD_LEDGER;
    use std::time::Instant;

    /// Contains only the original acknowledged Periodic checkpoint and bounded actual audit
    /// facts. Its private construction does not assert that pools or the source are closed.
    pub struct CommittedCaptureCheckpoint {
        checkpoint: AuditCheckpoint,
        signature: CheckpointSignature,
        rows: Vec<CapturedDbRow>,
        unlinked_before: u64,
    }
    impl CommittedCaptureCheckpoint {
        pub fn sequence(&self) -> u64 {
            self.checkpoint.sequence
        }
        pub fn signature(&self) -> &[u8; 32] {
            self.signature.as_bytes()
        }
        pub fn event_count(&self) -> u64 {
            match &self.checkpoint.kind {
                AuditCheckpointKind::Periodic { segment } => segment.event_count,
                _ => 0,
            }
        }
        pub fn unlinked_before(&self) -> u64 {
            self.unlinked_before
        }
        pub fn write_material(
            &self,
            output: &mut impl std::io::Write,
        ) -> Result<(), CaptureSqlFailure> {
            for row in &self.rows {
                serde_json::to_writer(&mut *output, &(row.projection, &row.fields))
                    .map_err(|_| CaptureSqlFailure::Database)?;
                output
                    .write_all(b"\n")
                    .map_err(|_| CaptureSqlFailure::Database)?;
            }
            let columns = checkpoint_columns(&self.checkpoint.kind)
                .map_err(|_| CaptureSqlFailure::RowInvalid)?;
            serde_json::to_writer(
                &mut *output,
                &(
                    self.checkpoint.sequence,
                    "periodic",
                    columns.first_event,
                    columns.first_hash,
                    columns.last_event,
                    columns.last_hash,
                    columns.event_count,
                    signature_hex(&self.signature),
                    self.checkpoint.created_at.unix_timestamp_nanos(),
                ),
            )
            .map_err(|_| CaptureSqlFailure::Database)
        }
    }

    /// A cancelled manual read transaction must never return to the idle pool. The exact
    /// original lease is retired into the existing driver owner on every return or cancellation.
    struct CaptureQueryLease(Option<crate::db::pool::GuardedClient>);
    impl CaptureQueryLease {
        fn client(&self) -> &tokio_postgres::Client {
            self.0
                .as_ref()
                .expect("retained original read lease")
                .as_client()
        }
    }
    impl Drop for CaptureQueryLease {
        fn drop(&mut self) {
            if let Some(client) = self.0.take() {
                let _original = client.retire_original();
            }
        }
    }

    /// A timeout/cancel/late original COMMIT is not a committed capture checkpoint.
    pub type CaptureAuditFailure = CaptureSqlFailure;

    impl AuditEventRepo {
        // R474 exposes only the original same-Repo bounded DATA operations.
        pub async fn capture_source_identity_before(
            &self,
            budget: &mut CaptureSqlBudget,
            clock: &dyn CaptureClockCheck,
        ) -> Result<crate::db::capture_materials::CapturePgIdentity, CaptureSqlFailure> {
            let duration = budget.reserve_query(clock)?;
            let cap = Instant::now()
                .checked_add(duration)
                .ok_or(CaptureSqlFailure::Bounds)?;
            let client = self
                .pool
                .get_guarded(cap)
                .await
                .map_err(|_| CaptureSqlFailure::Database)?;
            let retained = CaptureQueryLease(Some(client));
            budget.remaining(clock)?;
            crate::db::capture_materials::read_capture_identity(retained.client(), budget, clock)
                .await
        }

        pub async fn collect_capture_materials_before(
            &self,
            expected: &crate::db::capture_materials::CaptureDbExpectation,
            budget: &mut CaptureSqlBudget,
            clock: &dyn CaptureClockCheck,
        ) -> Result<crate::db::capture_materials::CapturedDbFacts, CaptureSqlFailure> {
            let duration = budget.reserve_query(clock)?;
            let cap = Instant::now()
                .checked_add(duration)
                .ok_or(CaptureSqlFailure::Bounds)?;
            let client = self
                .pool
                .get_guarded(cap)
                .await
                .map_err(|_| CaptureSqlFailure::Database)?;
            let retained = CaptureQueryLease(Some(client));
            budget.remaining(clock)?;
            crate::db::capture_materials::collect_normal_database_materials_before(
                retained.client(),
                expected,
                budget,
                clock,
            )
            .await
        }

        pub async fn append_capture_periodic_before(
            &self,
            key: &[u8],
            budget: &mut CaptureSqlBudget,
            clock: &dyn CaptureClockCheck,
        ) -> Result<CommittedCaptureCheckpoint, CaptureAuditFailure> {
            if key.is_empty() {
                return Err(CaptureSqlFailure::RowInvalid);
            }
            let remaining = budget.reserve_query(clock)?;
            let deadline = Instant::now()
                .checked_add(remaining)
                .ok_or(CaptureSqlFailure::Bounds)?;
            let mut client = self
                .pool
                .get_guarded(deadline)
                .await
                .map_err(|_| CaptureSqlFailure::Database)?;
            budget.remaining(clock)?;
            budget.reserve_query(clock)?;
            let transaction = client
                .begin_read_committed()
                .await
                .map_err(|_| CaptureSqlFailure::Database)?;
            let tx = transaction.as_transaction();
            let duration = budget.reserve_query(clock)?;
            tokio::time::timeout(
                duration,
                tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK_KEY]),
            )
            .await
            .map_err(|_| CaptureSqlFailure::Database)?
            .map_err(|_| CaptureSqlFailure::Database)?;
            budget.remaining(clock)?;
            let rows = read_capture_audit(tx, budget, clock).await?;
            let (segment, unlinked_before) = verify_audit_rows(&rows, key, budget, clock)?;
            let kind = AuditCheckpointKind::Periodic { segment };
            // Original segment verification, sequence allocation and signed INSERT remain the
            // original repository calls. The bounded same-lock facts establish their field caps.
            budget.reserve_known(3, 3, 512, clock)?;
            let duration = budget.remaining(clock)?;
            tokio::time::timeout(duration, verify_checkpoint_segment(tx, &kind))
                .await
                .map_err(|_| CaptureSqlFailure::Database)?
                .map_err(|_| CaptureSqlFailure::RowInvalid)?;
            let duration = budget.reserve_query(clock)?;
            let next: i64 = tokio::time::timeout(
                duration,
                tx.query_one(
                    "SELECT coalesce(max(sequence), -1)::bigint + 1 FROM public.audit_checkpoints",
                    &[],
                ),
            )
            .await
            .map_err(|_| CaptureSqlFailure::Database)?
            .map_err(|_| CaptureSqlFailure::Database)?
            .try_get(0)
            .map_err(|_| CaptureSqlFailure::RowInvalid)?;
            let checkpoint = AuditCheckpoint {
                sequence: u64::try_from(next).map_err(|_| CaptureSqlFailure::Bounds)?,
                created_at: OffsetDateTime::now_utc(),
                kind,
            };
            let signature = checkpoint
                .sign(key)
                .map_err(|_| CaptureSqlFailure::RowInvalid)?;
            let duration = budget.reserve_query(clock)?;
            tokio::time::timeout(duration, insert_checkpoint(tx, &checkpoint, key))
                .await
                .map_err(|_| CaptureSqlFailure::Database)?
                .map_err(|_| CaptureSqlFailure::Database)?;
            let duration = budget.reserve_query(clock)?;
            let commit_cap = Instant::now()
                .checked_add(duration)
                .ok_or(CaptureSqlFailure::Bounds)?;
            clock
                .require_effect()
                .map_err(|_| CaptureSqlFailure::Clock)?;
            transaction
                .commit_before(commit_cap)
                .await
                .map_err(|_| CaptureSqlFailure::CommitUnknown)?;
            budget.remaining(clock)?;
            Ok(CommittedCaptureCheckpoint {
                checkpoint,
                signature,
                rows,
                unlinked_before,
            })
        }
    }

    fn text(row: &CapturedDbRow, i: usize) -> Result<&str, CaptureSqlFailure> {
        row.fields
            .get(i)
            .and_then(Option::as_deref)
            .ok_or(CaptureSqlFailure::RowInvalid)
    }
    fn digest(text: &str) -> Result<Sha256Digest, CaptureSqlFailure> {
        Sha256Digest::parse_hex(text).map_err(|_| CaptureSqlFailure::RowInvalid)
    }
    fn verify_audit_rows(
        rows: &[CapturedDbRow],
        key: &[u8],
        budget: &mut CaptureSqlBudget,
        clock: &dyn CaptureClockCheck,
    ) -> Result<(ChainSegment, u64), CaptureSqlFailure> {
        let mut previous = None;
        let mut first = None;
        let mut last = None;
        let mut count = 0_u64;
        let mut unlinked = 0_u64;
        let mut linked = Vec::new();
        for row in rows.iter().filter(|row| row.projection == "audit_events") {
            let hash = row.fields.get(8).and_then(Option::as_deref);
            let prev = row.fields.get(7).and_then(Option::as_deref);
            let Some(hash) = hash else {
                if previous.is_some() || prev.is_some() {
                    return Err(CaptureSqlFailure::RowInvalid);
                }
                unlinked = unlinked.checked_add(1).ok_or(CaptureSqlFailure::Bounds)?;
                continue;
            };
            let actual = digest(hash)?;
            let predecessor = prev.map(digest).transpose()?;
            if predecessor != previous {
                return Err(CaptureSqlFailure::SourceMismatch);
            }
            let mut writer = CanonicalWriter::new(openbot_domain::audit::chain::AUDIT_ROW_DOMAIN);
            writer.str(text(row, 1)?);
            writer.option_str(row.fields.get(2).and_then(Option::as_deref));
            let event = text(row, 3)?;
            if openbot_domain::audit::event::AuditEventType::parse(event).is_none() {
                return Err(CaptureSqlFailure::RowInvalid);
            }
            writer.str(event);
            writer.str(text(row, 4)?);
            writer.option_str(row.fields.get(5).and_then(Option::as_deref));
            let payload = bounded_payload(text(row, 6)?, budget, clock)?;
            write_payload(&payload, &mut writer)?;
            let ns = text(row, 9)?
                .parse::<i128>()
                .map_err(|_| CaptureSqlFailure::RowInvalid)?;
            writer.i128(ns);
            writer.option_digest(predecessor.as_ref());
            if writer.digest_of_written() != actual {
                return Err(CaptureSqlFailure::SourceMismatch);
            }
            let id = AuditEventId::new(text(row, 1)?);
            if first.is_none() {
                first = Some((id.clone(), actual));
            }
            linked.push((id.clone(), actual));
            last = Some((id, actual));
            previous = Some(actual);
            count = count.checked_add(1).ok_or(CaptureSqlFailure::Bounds)?;
        }
        let (first_event, first_row_hash) = first.ok_or(CaptureSqlFailure::RowInvalid)?;
        let (last_event, last_row_hash) = last.ok_or(CaptureSqlFailure::RowInvalid)?;
        let mut genesis = false;
        let mut prior = None;
        for row in rows
            .iter()
            .filter(|row| row.projection == "audit_checkpoints")
        {
            let sequence = text(row, 0)?
                .parse::<u64>()
                .map_err(|_| CaptureSqlFailure::RowInvalid)?;
            if prior.is_some_and(|p: u64| p.checked_add(1) != Some(sequence))
                || prior.is_none() && sequence != 0
            {
                return Err(CaptureSqlFailure::RowInvalid);
            }
            prior = Some(sequence);
            let first_id = AuditEventId::new(text(row, 2)?);
            let first_hash = digest(text(row, 3)?)?;
            let last_id = AuditEventId::new(text(row, 4)?);
            let last_hash = digest(text(row, 5)?)?;
            let n = text(row, 6)?
                .parse::<u64>()
                .map_err(|_| CaptureSqlFailure::RowInvalid)?;
            // Signed prior boundaries must refer to this actual complete chain, including
            // segment cardinality, rather than merely having a valid historical HMAC.
            let start = linked
                .iter()
                .position(|(id, hash)| id == &first_id && hash == &first_hash)
                .ok_or(CaptureSqlFailure::SourceMismatch)?;
            let end = linked
                .iter()
                .position(|(id, hash)| id == &last_id && hash == &last_hash)
                .ok_or(CaptureSqlFailure::SourceMismatch)?;
            let actual_count = end
                .checked_sub(start)
                .and_then(|n| n.checked_add(1))
                .and_then(|n| u64::try_from(n).ok())
                .ok_or(CaptureSqlFailure::SourceMismatch)?;
            if actual_count != n {
                return Err(CaptureSqlFailure::SourceMismatch);
            }
            let kind = match text(row, 1)? {
                "genesis" => {
                    let old = text(row, 7)?
                        .parse::<u64>()
                        .map_err(|_| CaptureSqlFailure::RowInvalid)?;
                    if genesis
                        || sequence != 0
                        || first_id != first_event
                        || first_hash != first_row_hash
                        || last_id != first_id
                        || last_hash != first_hash
                        || n != 1
                        || old != unlinked
                    {
                        return Err(CaptureSqlFailure::SourceMismatch);
                    }
                    genesis = true;
                    AuditCheckpointKind::Genesis {
                        genesis_event: first_id,
                        genesis_row_hash: first_hash,
                        unlinked_rows_before: old,
                    }
                }
                "periodic" => AuditCheckpointKind::Periodic {
                    segment: ChainSegment {
                        first_event: first_id,
                        first_row_hash: first_hash,
                        last_event: last_id,
                        last_row_hash: last_hash,
                        event_count: n,
                    },
                },
                "closure" => AuditCheckpointKind::Closure {
                    segment: ChainSegment {
                        first_event: first_id,
                        first_row_hash: first_hash,
                        last_event: last_id,
                        last_row_hash: last_hash,
                        event_count: n,
                    },
                    retention_days: openbot_domain::audit::retention::RetentionDays::new(
                        text(row, 8)?
                            .parse()
                            .map_err(|_| CaptureSqlFailure::RowInvalid)?,
                    )
                    .ok_or(CaptureSqlFailure::RowInvalid)?,
                },
                _ => return Err(CaptureSqlFailure::RowInvalid),
            };
            let created_at = parse_pg_time(text(row, 10)?)?;
            let cp = AuditCheckpoint {
                sequence,
                created_at,
                kind,
            };
            let signature = CheckpointSignature::from_bytes(*digest(text(row, 9)?)?.as_bytes());
            if !cp
                .verify(key, &signature)
                .map_err(|_| CaptureSqlFailure::RowInvalid)?
            {
                return Err(CaptureSqlFailure::SourceMismatch);
            }
        }
        if !genesis {
            return Err(CaptureSqlFailure::SourceMismatch);
        }
        Ok((
            ChainSegment {
                first_event,
                first_row_hash,
                last_event,
                last_row_hash,
                event_count: count,
            },
            unlinked,
        ))
    }

    fn parse_pg_time(value: &str) -> Result<OffsetDateTime, CaptureSqlFailure> {
        let mut canonical = value.replace(' ', "T");
        if canonical.ends_with("+00") {
            canonical.truncate(canonical.len() - 3);
            canonical.push('Z');
        }
        OffsetDateTime::parse(&canonical, &time::format_description::well_known::Rfc3339)
            .map_err(|_| CaptureSqlFailure::RowInvalid)
    }

    // Preflight JSON shape with a stack-only visitor BEFORE Value allocates a tree. This
    // supports only the existing shallow AuditFact shape, including the closed candidate list.
    fn bounded_payload(
        raw: &str,
        budget: &mut CaptureSqlBudget,
        clock: &dyn CaptureClockCheck,
    ) -> Result<serde_json::Value, CaptureSqlFailure> {
        use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
        struct Count {
            nodes: u64,
            strings: u64,
            max: u64,
        }
        struct Shape<'a> {
            count: &'a mut Count,
            depth: u8,
        }
        impl<'de> DeserializeSeed<'de> for Shape<'_> {
            type Value = ();
            fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
                self.count.nodes = self
                    .count
                    .nodes
                    .checked_add(1)
                    .ok_or_else(|| D::Error::custom("audit shape"))?;
                if self.depth > 3 || self.count.nodes > self.count.max {
                    return Err(D::Error::custom("audit shape"));
                }
                decoder.deserialize_any(self)
            }
        }
        impl<'de> Visitor<'de> for Shape<'_> {
            type Value = ();
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("closed shallow audit facts")
            }
            fn visit_unit<E: Error>(self) -> Result<(), E> {
                Ok(())
            }
            fn visit_none<E: Error>(self) -> Result<(), E> {
                Ok(())
            }
            fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
                Ok(())
            }
            fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
                Ok(())
            }
            fn visit_i64<E: Error>(self, n: i64) -> Result<(), E> {
                if n < 0 {
                    Err(E::custom("audit number"))
                } else {
                    Ok(())
                }
            }
            fn visit_str<E: Error>(self, s: &str) -> Result<(), E> {
                if s.len() > openbot_domain::audit::payload::AuditIdentifier::MAX_BYTES {
                    return Err(E::custom("audit field"));
                }
                self.count.strings = self
                    .count
                    .strings
                    .checked_add(s.len() as u64)
                    .ok_or_else(|| E::custom("audit bytes"))?;
                Ok(())
            }
            fn visit_string<E: Error>(self, s: String) -> Result<(), E> {
                self.visit_str(&s)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
                let mut n = 0_usize;
                while seq
                    .next_element_seed(Shape {
                        count: &mut *self.count,
                        depth: self.depth + 1,
                    })?
                    .is_some()
                {
                    n = n
                        .checked_add(1)
                        .ok_or_else(|| A::Error::custom("audit count"))?;
                    if n > openbot_domain::audit::payload::AuditIdentifierList::MAX_ITEMS {
                        return Err(A::Error::custom("audit count"));
                    }
                }
                Ok(())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
                let mut n = 0_usize;
                while map
                    .next_key_seed(Shape {
                        count: &mut *self.count,
                        depth: self.depth + 1,
                    })?
                    .is_some()
                {
                    n = n
                        .checked_add(1)
                        .ok_or_else(|| A::Error::custom("audit fields"))?;
                    if n > AUDIT_FIELD_LEDGER.len() {
                        return Err(A::Error::custom("audit fields"));
                    }
                    map.next_value_seed(Shape {
                        count: &mut *self.count,
                        depth: self.depth + 1,
                    })?;
                }
                Ok(())
            }
        }
        let max = AUDIT_FIELD_LEDGER
            .len()
            .checked_mul(4)
            .and_then(|n| {
                n.checked_add(openbot_domain::audit::payload::AuditIdentifierList::MAX_ITEMS)
            })
            .ok_or(CaptureSqlFailure::Bounds)?;
        let mut count = Count {
            nodes: 0,
            strings: 0,
            max: max as u64,
        };
        let mut decoder = serde_json::Deserializer::from_str(raw);
        Shape {
            count: &mut count,
            depth: 0,
        }
        .deserialize(&mut decoder)
        .map_err(|_| CaptureSqlFailure::RowInvalid)?;
        decoder.end().map_err(|_| CaptureSqlFailure::RowInvalid)?;
        let bytes = count
            .nodes
            .checked_mul(256)
            .and_then(|n| count.strings.checked_mul(4).and_then(|m| n.checked_add(m)))
            .and_then(|n| n.checked_add(raw.len() as u64))
            .ok_or(CaptureSqlFailure::Bounds)?;
        budget.reserve_known(0, 0, bytes, clock)?;
        serde_json::from_str(raw).map_err(|_| CaptureSqlFailure::RowInvalid)
    }

    fn write_payload(
        value: &serde_json::Value,
        writer: &mut CanonicalWriter,
    ) -> Result<(), CaptureSqlFailure> {
        use serde_json::Value;
        let object = value.as_object().ok_or(CaptureSqlFailure::RowInvalid)?;
        writer.u64(object.len() as u64);
        let mut ordered = object.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|(name, _)| *name);
        for (field, value) in ordered {
            if !AUDIT_FIELD_LEDGER.contains(&field.as_str()) || field.contains('.') {
                return Err(CaptureSqlFailure::RowInvalid);
            }
            writer.str(field);
            match field.as_str() {
                "canonical_args_hash" | "schema_hash" | "key_id_hash" => writer.digest(&digest(
                    value.as_str().ok_or(CaptureSqlFailure::RowInvalid)?,
                )?),
                "attempt_number" => writer.u32(
                    u32::try_from(value.as_u64().ok_or(CaptureSqlFailure::RowInvalid)?)
                        .map_err(|_| CaptureSqlFailure::Bounds)?,
                ),
                "outcome_code" => writer.option_str(match value {
                    Value::Null => None,
                    Value::String(s) => Some(s),
                    _ => return Err(CaptureSqlFailure::RowInvalid),
                }),
                "candidates" => {
                    let a = value.as_array().ok_or(CaptureSqlFailure::RowInvalid)?;
                    writer.u64(a.len() as u64);
                    for v in a {
                        writer.str(v.as_str().ok_or(CaptureSqlFailure::RowInvalid)?);
                    }
                }
                "secret_input" => {
                    let o = value.as_object().ok_or(CaptureSqlFailure::RowInvalid)?;
                    if o.len() != 4 {
                        return Err(CaptureSqlFailure::RowInvalid);
                    }
                    for key in ["secret_id", "purpose", "target_field"] {
                        writer.str(
                            o.get(key)
                                .and_then(Value::as_str)
                                .ok_or(CaptureSqlFailure::RowInvalid)?,
                        );
                    }
                    writer.u32(
                        o.get("value_len")
                            .and_then(Value::as_u64)
                            .and_then(|n| u32::try_from(n).ok())
                            .ok_or(CaptureSqlFailure::RowInvalid)?,
                    );
                }
                _ => match value {
                    Value::String(s) => writer.str(s),
                    Value::Bool(b) => writer.bool(*b),
                    Value::Number(n) => {
                        writer.u64(n.as_u64().ok_or(CaptureSqlFailure::RowInvalid)?)
                    }
                    _ => return Err(CaptureSqlFailure::RowInvalid),
                },
            }
        }
        Ok(())
    }
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub use capture_periodic::{CaptureAuditFailure, CommittedCaptureCheckpoint};
