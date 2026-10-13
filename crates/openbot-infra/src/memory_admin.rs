//! Explicit memory GUI application port 的 PostgreSQL 原子适配器。

mod actor_authority;
mod recall_authority;
mod recall_query;
pub(crate) mod remember_effect;

use async_trait::async_trait;
use openbot_application::{
    CorrectMemoryRequest, MemoryAdministration, MemoryAdministrationError, MemoryControlRequest,
    MemoryPageRequest, MutateMemoryRequest, RecallMemoriesRequest, RememberMemoryRequest,
    RememberToolMemory, RememberToolMemoryRequest, RememberToolScope, UpdateMemoryControlRequest,
};
use openbot_contracts::auth::{AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::memory::{
    MemoryControl, MemoryKind, MemoryMutation, MemoryOrigin, MemoryPage, MemoryRecall,
    MemoryRecord, MemoryScope, MemorySensitivity, MemorySource, MemorySourceAuthorization,
    MemoryStatus, RememberMemory,
};
use openbot_domain::memory::{
    Memory as DomainMemory, MemoryId as DomainMemoryId, MemoryKind as DomainMemoryKind,
    MemoryOrigin as DomainMemoryOrigin, MemoryScope as DomainMemoryScope,
    MemorySensitivity as DomainMemorySensitivity, MemorySource as DomainMemorySource,
};
use openbot_domain::thread::MessageId;
use time::OffsetDateTime;
use tokio_postgres::Transaction;
use tokio_postgres::error::SqlState;

use crate::db::InfraError;
use crate::db::tables::memories;
use crate::repo::common::columns_sql;
use crate::thread_history_writer::{CurrentWriterSchema, OpenOrClosed};

/// Explicit memory 的 production adapter；不包含 background extraction job。
#[derive(Clone)]
pub struct PostgresMemoryAdministration {
    pool: crate::db::pool::DatabasePool,
    effect_audit_key: Option<std::sync::Arc<[u8]>>,
}

impl PostgresMemoryAdministration {
    /// 用共享池构造。
    #[must_use]
    pub fn new(pool: crate::db::pool::DatabasePool) -> Self {
        Self {
            pool,
            effect_audit_key: None,
        }
    }

    /// Enable the real tool producer with the assembly's existing audit key.
    pub fn with_effect_audit_key(
        mut self,
        key: Vec<u8>,
    ) -> Result<Self, MemoryAdministrationError> {
        if key.is_empty() {
            return Err(MemoryAdministrationError::Unavailable);
        }
        self.effect_audit_key = Some(key.into());
        Ok(self)
    }
}

#[async_trait]
impl MemoryAdministration for PostgresMemoryAdministration {
    async fn memory_control(
        &self,
        request: MemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let result = async {
            actor_authority::lock_actor(&transaction, &request.actor, request.auth_generation)
                .await?;
            let row = transaction
                .query_opt(
                    "SELECT writes_enabled FROM public.user_memory_controls \
                 WHERE tenant_id=$1 AND actor_user_id=$2",
                    &[&request.tenant.as_str(), &request.actor.as_str()],
                )
                .await
                .map_err(|error| unavailable("读取 memory control 失败", error))?;
            row.map_or(Ok(MemoryControl::default()), |row| {
                row.try_get("writes_enabled")
                    .map(|writes_enabled| MemoryControl { writes_enabled })
                    .map_err(|_| MemoryAdministrationError::Corrupt {
                        field: "writes_enabled",
                    })
            })
        }
        .await;
        finish_read_transaction(transaction, result).await
    }

    async fn update_memory_control(
        &self,
        request: UpdateMemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        actor_authority::lock_actor_for_control(
            &transaction,
            &request.actor,
            request.auth_generation,
        )
        .await?;
        let row = transaction
            .query_one(
                "INSERT INTO public.user_memory_controls( \
                   tenant_id,actor_user_id,writes_enabled,updated_at \
                 ) VALUES($1,$2,$3,statement_timestamp()) \
                 ON CONFLICT (tenant_id,actor_user_id) DO UPDATE SET \
                   writes_enabled=EXCLUDED.writes_enabled,updated_at=statement_timestamp() \
                 RETURNING writes_enabled",
                &[
                    &request.tenant.as_str(),
                    &request.actor.as_str(),
                    &request.update.writes_enabled,
                ],
            )
            .await
            .map_err(|error| write_error("保存 memory control 失败", error))?;
        let writes_enabled =
            row.try_get("writes_enabled")
                .map_err(|_| MemoryAdministrationError::Corrupt {
                    field: "writes_enabled",
                })?;
        transaction
            .commit()
            .await
            .map_err(|_| MemoryAdministrationError::CommitUnknown)?;
        Ok(MemoryControl { writes_enabled })
    }

    async fn remember(
        &self,
        request: RememberMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let result = async {
            // A memory with a source message copies from that Thread's history. It takes one
            // strict schema observation before this transaction's first row lock and H SHARE
            // after the permission checks below; a memory with no source reads no Thread.
            let schema = match request.input.source {
                Some(_) => Some(
                    CurrentWriterSchema::observe(&transaction)
                        .await
                        .map_err(history_error)?,
                ),
                None => None,
            };
            actor_authority::lock_actor(&transaction, &request.actor, request.auth_generation)
                .await?;
            ensure_writes_enabled(&transaction, &request.tenant, &request.actor).await?;
            let now = database_now(&transaction).await?;
            let source_run_id = validate_memory_targets(
                &transaction,
                &request.tenant,
                &request.actor,
                &request.deployment,
                &request.input,
            )
            .await?;
            if let (Some(schema), Some(source)) = (&schema, &request.input.source)
                && schema
                    .lock_thread_write_disposition(&transaction, &source.thread_id)
                    .await
                    .map_err(history_error)?
                    == OpenOrClosed::Closed
            {
                // A closed source Thread is unknown to the caller, like any foreign source.
                return Err(MemoryAdministrationError::NotVisible);
            }
            let authorization = capture_authorization(
                &transaction,
                &request.actor,
                request.auth_generation,
                &request.tenant,
                &request.deployment,
                &request.input.scope,
                now,
            )
            .await?;
            let record = insert_memory(
                &transaction,
                &request.tenant,
                &request.actor,
                &request.input,
                MemoryCreation {
                    origin: DomainMemoryOrigin::UserAction,
                    supersedes: None,
                    now,
                    source_run_id,
                    source_authorization_snapshot: Some(authorization),
                },
            )
            .await?;
            insert_event(
                &transaction,
                &record.memory_id,
                0,
                "create",
                &request.actor,
                now,
            )
            .await?;
            Ok(record)
        }
        .await;
        finish_transaction(transaction, result).await
    }

    async fn list_memories(
        &self,
        request: MemoryPageRequest,
    ) -> Result<MemoryPage, MemoryAdministrationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let result = async {
            actor_authority::lock_actor(&transaction, &request.actor, request.auth_generation)
                .await?;
            let cursor = if let Some(cursor) = request.cursor.as_deref() {
                let row = transaction
                    .query_opt(
                        "SELECT created_at,memory_id FROM public.memories \
                     WHERE memory_id=$1 AND tenant_id=$2 AND owner_user_id=$3",
                        &[&cursor, &request.tenant.as_str(), &request.actor.as_str()],
                    )
                    .await
                    .map_err(|error| unavailable("读取 memory cursor 失败", error))?
                    .ok_or(MemoryAdministrationError::InvalidInput { field: "cursor" })?;
                Some((
                    row.try_get::<_, OffsetDateTime>("created_at")
                        .map_err(|_| MemoryAdministrationError::Corrupt {
                            field: "created_at",
                        })?,
                    row.try_get::<_, String>("memory_id")
                        .map_err(|_| MemoryAdministrationError::Corrupt { field: "memory_id" })?,
                ))
            } else {
                None
            };
            let fetch = i64::from(request.limit) + 1;
            let sql = format!(
                "SELECT {} FROM public.memories \
             WHERE tenant_id=$1 AND owner_user_id=$2 \
               AND ($3::timestamptz IS NULL OR (created_at,memory_id)<($3,$4)) \
             ORDER BY created_at DESC,memory_id DESC LIMIT $5",
                columns_sql::<memories::Row>()
            );
            let cursor_time = cursor.as_ref().map(|value| value.0);
            let cursor_id = cursor.as_ref().map(|value| value.1.as_str());
            let rows = transaction
                .query(
                    &sql,
                    &[
                        &request.tenant.as_str(),
                        &request.actor.as_str(),
                        &cursor_time,
                        &cursor_id,
                        &fetch,
                    ],
                )
                .await
                .map_err(|error| unavailable("读取 memory page 失败", error))?;
            let mut records = rows
                .iter()
                .map(|row| {
                    memories::Row::try_from(row).map_err(|_| MemoryAdministrationError::Corrupt {
                        field: "memory_row",
                    })
                })
                .map(|row| row.and_then(record_from_row))
                .collect::<Result<Vec<_>, _>>()?;
            let has_more = records.len() > request.limit as usize;
            if has_more {
                records.truncate(request.limit as usize);
            }
            let next_cursor = has_more
                .then(|| records.last().map(|record| record.memory_id.clone()))
                .flatten();
            Ok(MemoryPage {
                memories: records,
                next_cursor,
            })
        }
        .await;
        finish_read_transaction(transaction, result).await
    }

    async fn correct(
        &self,
        request: CorrectMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let result = async {
            actor_authority::lock_actor(&transaction, &request.actor, request.auth_generation)
                .await?;
            ensure_writes_enabled(&transaction, &request.tenant, &request.actor).await?;
            let now = database_now(&transaction).await?;
            let old = load_owned_for_update(
                &transaction,
                &request.tenant,
                &request.actor,
                &request.memory_id,
            )
            .await?
            .ok_or(MemoryAdministrationError::NotVisible)?;
            if old.status != "active" {
                return Err(MemoryAdministrationError::Conflict);
            }
            let old_record = record_from_row(old.clone())?;
            let input = RememberMemory {
                memory_kind: old_record.memory_kind,
                scope: old_record.scope.clone(),
                content: request.correction.content,
                tags: request.correction.tags,
                sensitivity: request.correction.sensitivity,
                source: old_record.source.clone(),
                expires_at: request.correction.expires_at,
            };
            // A saved copy keeps its original provenance, even after source access is revoked.
            // Only the chosen retention scope and the current correction actor are reauthorized.
            let scope_only = RememberMemory {
                source: None,
                ..input.clone()
            };
            validate_memory_targets(
                &transaction,
                &request.tenant,
                &request.actor,
                &request.deployment,
                &scope_only,
            )
            .await?;
            let updated = transaction
                .execute(
                    "UPDATE public.memories SET status='superseded',updated_at=$4 \
                     WHERE memory_id=$1 AND tenant_id=$2 AND owner_user_id=$3 AND status='active'",
                    &[
                        &request.memory_id,
                        &request.tenant.as_str(),
                        &request.actor.as_str(),
                        &now,
                    ],
                )
                .await
                .map_err(|error| write_error("supersede old memory 失败", error))?;
            if updated != 1 {
                return Err(MemoryAdministrationError::Conflict);
            }
            let record = insert_memory(
                &transaction,
                &request.tenant,
                &request.actor,
                &input,
                MemoryCreation {
                    origin: DomainMemoryOrigin::UserAction,
                    supersedes: Some(request.memory_id.clone()),
                    now,
                    source_run_id: old.source_run_id,
                    source_authorization_snapshot: old.source_authorization_snapshot,
                },
            )
            .await?;
            let old_seq = next_event_sequence(&transaction, &request.memory_id).await?;
            insert_event(
                &transaction,
                &request.memory_id,
                old_seq,
                "supersede",
                &request.actor,
                now,
            )
            .await?;
            let action_authorization = capture_authorization(
                &transaction,
                &request.actor,
                request.auth_generation,
                &request.tenant,
                &request.deployment,
                &input.scope,
                now,
            )
            .await?;
            insert_event_with_metadata(
                &transaction,
                &record.memory_id,
                0,
                "create",
                &request.actor,
                now,
                &serde_json::json!({"actionAuthorization":action_authorization}),
            )
            .await?;
            Ok(record)
        }
        .await;
        finish_transaction(transaction, result).await
    }

    async fn mutate(
        &self,
        request: MutateMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let result = async {
            actor_authority::lock_actor(&transaction, &request.actor, request.auth_generation)
                .await?;
            let now = database_now(&transaction).await?;
            let old = load_owned_for_update(
                &transaction,
                &request.tenant,
                &request.actor,
                &request.memory_id,
            )
            .await?
            .ok_or(MemoryAdministrationError::NotVisible)?;
            let target = match request.mutation {
                MemoryMutation::Forbid if old.status == "deleted" => "deleted",
                MemoryMutation::Forbid => "forbidden",
                MemoryMutation::Delete => "deleted",
            };
            if old.status != target {
                transaction
                    .execute(
                        "UPDATE public.memories SET status=$4,content=NULL,updated_at=$5 \
                         WHERE memory_id=$1 AND tenant_id=$2 AND owner_user_id=$3",
                        &[
                            &request.memory_id,
                            &request.tenant.as_str(),
                            &request.actor.as_str(),
                            &target,
                            &now,
                        ],
                    )
                    .await
                    .map_err(|error| write_error("擦除 memory 内容失败", error))?;
                let seq = next_event_sequence(&transaction, &request.memory_id).await?;
                insert_event(
                    &transaction,
                    &request.memory_id,
                    seq,
                    match request.mutation {
                        MemoryMutation::Forbid => "forbid",
                        MemoryMutation::Delete => "delete",
                    },
                    &request.actor,
                    now,
                )
                .await?;
            }
            let row = load_owned_for_update(
                &transaction,
                &request.tenant,
                &request.actor,
                &request.memory_id,
            )
            .await?
            .ok_or(MemoryAdministrationError::NotVisible)?;
            record_from_row(row)
        }
        .await;
        finish_transaction(transaction, result).await
    }

    async fn recall(
        &self,
        request: RecallMemoriesRequest,
    ) -> Result<MemoryRecall, MemoryAdministrationError> {
        // Defense in depth for direct adapter callers, before acquiring a database connection.
        let query = recall_query::prepare(&request.input.query)?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let result = async {
            actor_authority::lock_actor(&transaction, &request.actor, request.auth_generation).await?;
            let now = database_now(&transaction).await?;
            let limit = i64::from(request.input.limit.unwrap_or(50).clamp(1, 100));
            let bot_id = request.input.bot_id.as_ref().map(|id| id.as_str());
            let thread_id = request.input.thread_id.as_ref().map(|id| id.as_str());
            let tags = &request.input.tags;
            let sql = format!(
                "{} SELECT authority.authorized AS recall_authorized,candidate.* \
                 FROM recall_authority authority LEFT JOIN LATERAL ( \
                 SELECT {},ts_rank(to_tsvector('simple',content),plainto_tsquery('simple',$6)) AS recall_rank \
                 FROM public.memories \
                 WHERE authority.authorized AND tenant_id=$1 AND owner_user_id=$2 AND status='active' \
                   AND content IS NOT NULL AND (expires_at IS NULL OR expires_at>$5) \
                   AND (scope_kind='user' \
                        OR ($3::text IS NOT NULL AND scope_kind='bot' AND scope_id=$3) \
                        OR ($4::text IS NOT NULL AND scope_kind='thread' AND scope_id=$4)) \
                   AND (to_tsvector('simple',content) @@ plainto_tsquery('simple',$6) \
                        OR (cardinality($9::text[]) > 0 \
                            AND (numnode(plainto_tsquery('simple',$10)) = 0 \
                                 OR to_tsvector('simple',content) @@ plainto_tsquery('simple',$10)) \
                            AND NOT EXISTS(SELECT 1 FROM unnest($9::text[]) AS han(term) \
                                           WHERE strpos(content,han.term) = 0))) \
                   AND (cardinality($7::text[]) = 0 OR tags @> $7::text[]) \
                 ORDER BY recall_rank DESC,created_at DESC,memory_id DESC LIMIT $8) candidate ON TRUE \
                 ORDER BY candidate.recall_rank DESC,candidate.created_at DESC,candidate.memory_id DESC",
                recall_authority::CONTEXT_CTE,
                columns_sql::<memories::Row>()
            );
            let rows = transaction
                .query(
                    &sql,
                    &[
                        &request.tenant.as_str(),
                        &request.actor.as_str(),
                        &bot_id,
                        &thread_id,
                        &now,
                        &request.input.query,
                        &tags,
                        &limit,
                        &query.han_literals,
                        &query.non_han_query,
                        &request.deployment.as_str(),
                    ],
                )
                .await
                .map_err(|error| unavailable("召回 explicit memory 失败", error))?;
            let mut memories = Vec::new();
            if rows.is_empty() {
                return Err(MemoryAdministrationError::Corrupt { field: "recall_authority" });
            }
            for row in &rows {
                let authorized: bool = row.try_get("recall_authorized")
                    .map_err(|_| MemoryAdministrationError::Corrupt { field: "recall_authority" })?;
                if !authorized {
                    return Err(MemoryAdministrationError::NotVisible);
                }
                // LEFT JOIN retains the authority row when an authorized query has no matches.
                let id: Option<&str> = row.try_get("memory_id")
                    .map_err(|_| MemoryAdministrationError::Corrupt { field: "memory_id" })?;
                if id.is_some() {
                    let memory = memories::Row::try_from(row)
                        .map_err(|_| MemoryAdministrationError::Corrupt { field: "memory_row" })?;
                    memories.push(record_from_row(memory)?);
                }
            }
            Ok(MemoryRecall { memories })
        }
        .await;
        let _ = transaction.rollback().await;
        result
    }
}

#[async_trait]
impl RememberToolMemory for PostgresMemoryAdministration {
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> Result<openbot_application::CommittedMemoryEffect, MemoryAdministrationError> {
        let key = self
            .effect_audit_key
            .as_deref()
            .ok_or(MemoryAdministrationError::Unavailable)?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let result = async {
            let locked = remember_effect::admit(&transaction, &request).await?;
            if let Some(receipt) =
                remember_effect::existing(&transaction, &request, &locked).await?
            {
                return Ok(receipt);
            }
            locked.require_fresh()?;
            ensure_writes_enabled(&transaction, request.tenant(), request.actor()).await?;
            // All new tool memories have the exact admitted run's user message as provenance.
            // This does not change or backfill historical preference memories without a source.
            let source = {
                let row = transaction
                    .query_opt(
                        "SELECT message_id FROM public.messages \
                         WHERE run_id=$1 AND thread_id=$2 AND role='user' \
                         ORDER BY seq DESC LIMIT 1",
                        &[&request.run().as_str(), &request.thread().as_str()],
                    )
                    .await
                    .map_err(|error| unavailable("读取 remember tool provenance 失败", error))?
                    .ok_or(MemoryAdministrationError::Corrupt {
                        field: "remember_source_message",
                    })?;
                let message_id: String =
                    row.try_get(0)
                        .map_err(|_| MemoryAdministrationError::Corrupt {
                            field: "remember_source_message",
                        })?;
                Some(MemorySource {
                    thread_id: request.thread().clone(),
                    message_id,
                })
            };
            let scope = match request.arguments().scope() {
                RememberToolScope::User => MemoryScope::User,
                RememberToolScope::Bot => MemoryScope::Bot {
                    bot_id: request.bot().clone(),
                },
                RememberToolScope::Thread => MemoryScope::Thread {
                    thread_id: request.thread().clone(),
                },
            };
            let input = RememberMemory {
                memory_kind: request.arguments().memory_kind(),
                scope,
                content: request.arguments().content().to_owned(),
                tags: request.arguments().tags().to_vec(),
                sensitivity: request.arguments().sensitivity(),
                source,
                expires_at: None,
            };
            let source_run_id = validate_memory_targets(
                &transaction,
                request.tenant(),
                request.actor(),
                request.deployment(),
                &input,
            )
            .await?;
            if source_run_id.as_deref() != Some(request.run().as_str()) {
                return Err(MemoryAdministrationError::Corrupt {
                    field: "remember_source_run",
                });
            }
            let now = database_now(&transaction).await?;
            let authorization = capture_authorization(
                &transaction,
                request.actor(),
                request.auth_generation(),
                request.tenant(),
                request.deployment(),
                &input.scope,
                now,
            )
            .await?;
            let record = insert_memory(
                &transaction,
                request.tenant(),
                request.actor(),
                &input,
                MemoryCreation {
                    origin: DomainMemoryOrigin::RememberTool,
                    supersedes: None,
                    now,
                    source_run_id,
                    source_authorization_snapshot: Some(authorization),
                },
            )
            .await?;
            insert_event(
                &transaction,
                &record.memory_id,
                0,
                "create",
                request.actor(),
                now,
            )
            .await?;
            remember_effect::append(&transaction, &request, &locked, &record.memory_id, key).await
        }
        .await;
        finish_transaction(transaction, result).await
    }
}

async fn ensure_writes_enabled(
    transaction: &Transaction<'_>,
    tenant: &TenantId,
    actor: &ActorId,
) -> Result<(), MemoryAdministrationError> {
    let enabled: bool = transaction
        .query_one(
            "SELECT coalesce(( \
               SELECT writes_enabled FROM public.user_memory_controls \
               WHERE tenant_id=$1 AND actor_user_id=$2 \
             ),true)",
            &[&tenant.as_str(), &actor.as_str()],
        )
        .await
        .map_err(|error| unavailable("检查 memory writes control 失败", error))?
        .try_get(0)
        .map_err(|_| MemoryAdministrationError::Corrupt {
            field: "writes_enabled",
        })?;
    if enabled {
        Ok(())
    } else {
        Err(MemoryAdministrationError::WritesDisabled)
    }
}

// Uses the same current context policy as recall. The source message and its exact nullable
// run binding are read in that SQL snapshot; a later binding never changes this captured fact.
async fn validate_memory_targets(
    transaction: &Transaction<'_>,
    tenant: &TenantId,
    actor: &ActorId,
    deployment: &DeploymentId,
    input: &RememberMemory,
) -> Result<Option<String>, MemoryAdministrationError> {
    let bot = match &input.scope {
        MemoryScope::Bot { bot_id } => Some(bot_id.as_str()),
        _ => None,
    };
    let thread = match &input.scope {
        MemoryScope::Thread { thread_id } => {
            if input
                .source
                .as_ref()
                .is_some_and(|source| source.thread_id != *thread_id)
            {
                return Err(MemoryAdministrationError::InvalidInput { field: "scope" });
            }
            Some(thread_id.as_str())
        }
        _ => input
            .source
            .as_ref()
            .map(|source| source.thread_id.as_str()),
    };
    let message = input
        .source
        .as_ref()
        .map(|source| source.message_id.as_str());
    let sql = format!(
        "{} SELECT authority.authorized, m.message_id, m.run_id,
        (m.run_id IS NULL OR r.thread_id=m.thread_id) AS run_matches
        FROM recall_authority authority
        LEFT JOIN public.messages m ON m.thread_id=$4 AND m.message_id=$6
        LEFT JOIN public.runs r ON r.run_id=m.run_id",
        recall_authority::CONTEXT_CTE.replace("$11", "$5")
    );
    let row = transaction
        .query_one(
            &sql,
            &[
                &tenant.as_str(),
                &actor.as_str(),
                &bot,
                &thread,
                &deployment.as_str(),
                &message,
            ],
        )
        .await
        .map_err(|error| unavailable("验证 memory scope/source 失败", error))?;
    let authorized: bool =
        row.try_get("authorized")
            .map_err(|_| MemoryAdministrationError::Corrupt {
                field: "source_authority",
            })?;
    let found: Option<String> =
        row.try_get("message_id")
            .map_err(|_| MemoryAdministrationError::Corrupt {
                field: "source_message",
            })?;
    if !authorized || (message.is_some() && found.is_none()) {
        return Err(MemoryAdministrationError::NotVisible);
    }
    let run_matches: Option<bool> =
        row.try_get("run_matches")
            .map_err(|_| MemoryAdministrationError::Corrupt {
                field: "source_run",
            })?;
    if message.is_some() && run_matches != Some(true) {
        return Err(MemoryAdministrationError::Corrupt {
            field: "source_run",
        });
    }
    row.try_get("run_id")
        .map_err(|_| MemoryAdministrationError::Corrupt {
            field: "source_run",
        })
}

async fn capture_authorization(
    transaction: &Transaction<'_>,
    actor: &ActorId,
    generation: AuthGeneration,
    tenant: &TenantId,
    deployment: &DeploymentId,
    scope: &MemoryScope,
    now: OffsetDateTime,
) -> Result<serde_json::Value, MemoryAdministrationError> {
    // The actor row is already held until commit; People changes use that same row/generation.
    let rows = transaction
        .query(
            "SELECT role::text AS role FROM public.user_roles WHERE user_id=$1 ORDER BY role::text",
            &[&actor.as_str()],
        )
        .await
        .map_err(|error| unavailable("读取 memory provenance roles 失败", error))?;
    let roles = rows
        .iter()
        .map(|row| match row.try_get::<_, &str>("role") {
            Ok("admin") => Ok(Role::Admin),
            Ok("user") => Ok(Role::User),
            _ => Err(MemoryAdministrationError::Corrupt {
                field: "source_roles",
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if roles.is_empty() || generation.get() > i64::MAX as u64 {
        return Err(MemoryAdministrationError::Corrupt {
            field: "source_authorization",
        });
    }
    serde_json::to_value(MemorySourceAuthorization {
        actor_id: actor.clone(),
        tenant_id: tenant.clone(),
        deployment_id: deployment.clone(),
        auth_generation: generation.get(),
        roles,
        scope: scope.clone(),
        captured_at: now,
    })
    .map_err(|_| MemoryAdministrationError::Corrupt {
        field: "source_authorization",
    })
}

struct MemoryCreation {
    origin: DomainMemoryOrigin,
    supersedes: Option<String>,
    now: OffsetDateTime,
    source_run_id: Option<String>,
    source_authorization_snapshot: Option<serde_json::Value>,
}

async fn insert_memory(
    transaction: &Transaction<'_>,
    tenant: &TenantId,
    actor: &ActorId,
    input: &RememberMemory,
    creation: MemoryCreation,
) -> Result<MemoryRecord, MemoryAdministrationError> {
    let MemoryCreation {
        origin,
        supersedes,
        now,
        source_run_id,
        source_authorization_snapshot,
    } = creation;
    let id = DomainMemoryId::new(uuid::Uuid::now_v7().to_string());
    let source = input.source.as_ref().map(|source| {
        DomainMemorySource::new(source.thread_id.clone(), MessageId::new(&source.message_id))
    });
    let memory = DomainMemory::new(
        id,
        tenant.clone(),
        actor.clone(),
        domain_scope(&input.scope),
        domain_kind(input.memory_kind),
        input.content.clone(),
        input.tags.clone(),
        domain_sensitivity(input.sensitivity),
        source,
        origin,
        actor.clone(),
        supersedes.clone().map(DomainMemoryId::new),
        input.expires_at,
        now,
    )
    .map_err(|error| match error {
        openbot_domain::memory::MemoryError::ExpiryInvalid => {
            MemoryAdministrationError::InvalidInput {
                field: "expires_at",
            }
        }
        openbot_domain::memory::MemoryError::SourceRequired => {
            MemoryAdministrationError::InvalidInput { field: "source" }
        }
        openbot_domain::memory::MemoryError::ContentEmpty => {
            MemoryAdministrationError::InvalidInput { field: "content" }
        }
        openbot_domain::memory::MemoryError::TagEmpty => {
            MemoryAdministrationError::InvalidInput { field: "tags" }
        }
        openbot_domain::memory::MemoryError::NotActive => MemoryAdministrationError::Conflict,
    })?;
    let tags: Vec<Option<String>> = memory.tags().iter().cloned().map(Some).collect();
    let source_thread = memory.source().map(|source| source.thread().as_str());
    let source_message = memory.source().map(|source| source.message().as_str());
    let supersedes_id = memory.supersedes().map(DomainMemoryId::as_str);
    let row = transaction
        .query_one(
            "INSERT INTO public.memories( \
               memory_id,tenant_id,owner_user_id,scope_kind,scope_id,memory_kind,content,tags, \
               sensitivity,source_thread_id,source_message_id,origin,created_by,supersedes_id, \
               status,expires_at,created_at,updated_at,source_run_id,source_authorization_snapshot \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17,$18,$19) \
             RETURNING *",
            &[
                &memory.id().as_str(),
                &memory.tenant().as_str(),
                &memory.owner().as_str(),
                &memory.scope().kind(),
                &memory.scope().id(),
                &memory.kind().as_str(),
                &memory.content(),
                &tags,
                &memory.sensitivity().as_str(),
                &source_thread,
                &source_message,
                &memory.origin().as_str(),
                &memory.created_by().as_str(),
                &supersedes_id,
                &memory.status().as_str(),
                &memory.expires_at(),
                &memory.created_at(),
                &source_run_id,
                &source_authorization_snapshot,
            ],
        )
        .await
        .map_err(|error| write_error("创建 explicit memory 失败", error))?;
    let row = memories::Row::try_from(&row).map_err(|_| MemoryAdministrationError::Corrupt {
        field: "memory_row",
    })?;
    record_from_row(row)
}

async fn load_owned_for_update(
    transaction: &Transaction<'_>,
    tenant: &TenantId,
    actor: &ActorId,
    memory_id: &str,
) -> Result<Option<memories::Row>, MemoryAdministrationError> {
    let sql = format!(
        "SELECT {} FROM public.memories \
         WHERE memory_id=$1 AND tenant_id=$2 AND owner_user_id=$3 FOR UPDATE",
        columns_sql::<memories::Row>()
    );
    transaction
        .query_opt(&sql, &[&memory_id, &tenant.as_str(), &actor.as_str()])
        .await
        .map_err(|error| unavailable("锁定 owner memory 失败", error))?
        .as_ref()
        .map(memories::Row::try_from)
        .transpose()
        .map_err(|_| MemoryAdministrationError::Corrupt {
            field: "memory_row",
        })
}

async fn next_event_sequence(
    transaction: &Transaction<'_>,
    memory_id: &str,
) -> Result<i64, MemoryAdministrationError> {
    transaction
        .query_one(
            "SELECT coalesce(max(seq),-1)::bigint+1 FROM public.memory_events WHERE memory_id=$1",
            &[&memory_id],
        )
        .await
        .map_err(|error| unavailable("分配 memory event sequence 失败", error))?
        .try_get(0)
        .map_err(|_| MemoryAdministrationError::Corrupt {
            field: "memory_event_seq",
        })
}

async fn insert_event(
    transaction: &Transaction<'_>,
    memory_id: &str,
    sequence: i64,
    event_type: &str,
    actor: &ActorId,
    now: OffsetDateTime,
) -> Result<(), MemoryAdministrationError> {
    insert_event_with_metadata(
        transaction,
        memory_id,
        sequence,
        event_type,
        actor,
        now,
        &serde_json::json!({}),
    )
    .await
}

async fn insert_event_with_metadata(
    transaction: &Transaction<'_>,
    memory_id: &str,
    sequence: i64,
    event_type: &str,
    actor: &ActorId,
    now: OffsetDateTime,
    metadata: &serde_json::Value,
) -> Result<(), MemoryAdministrationError> {
    transaction
        .execute(
            "INSERT INTO public.memory_events(memory_id,seq,event_type,actor_id,metadata,created_at) \
             VALUES($1,$2,$3,$4,$6,$5)",
            &[&memory_id, &sequence, &event_type, &actor.as_str(), &now, &metadata],
        )
        .await
        .map(|_| ())
        .map_err(|error| write_error("写 memory lifecycle event 失败", error))
}

fn record_from_row(row: memories::Row) -> Result<MemoryRecord, MemoryAdministrationError> {
    let scope = match (row.scope_kind.as_str(), row.scope_id) {
        ("user", None) => MemoryScope::User,
        ("bot", Some(id)) => MemoryScope::Bot {
            bot_id: BotId::new(id),
        },
        ("thread", Some(id)) => MemoryScope::Thread {
            thread_id: ThreadId::new(id),
        },
        _ => return Err(MemoryAdministrationError::Corrupt { field: "scope" }),
    };
    let kind = match row.memory_kind.as_str() {
        "preference" => MemoryKind::Preference,
        "fact" => MemoryKind::Fact,
        _ => {
            return Err(MemoryAdministrationError::Corrupt {
                field: "memory_kind",
            });
        }
    };
    let sensitivity = match row.sensitivity.as_str() {
        "normal" => MemorySensitivity::Normal,
        "sensitive" => MemorySensitivity::Sensitive,
        _ => {
            return Err(MemoryAdministrationError::Corrupt {
                field: "sensitivity",
            });
        }
    };
    let origin = match row.origin.as_str() {
        "user_action" => MemoryOrigin::UserAction,
        "remember_tool" => MemoryOrigin::RememberTool,
        "verified_import" => MemoryOrigin::VerifiedImport,
        _ => return Err(MemoryAdministrationError::Corrupt { field: "origin" }),
    };
    let status = match row.status.as_str() {
        "active" => MemoryStatus::Active,
        "superseded" => MemoryStatus::Superseded,
        "forbidden" => MemoryStatus::Forbidden,
        "deleted" => MemoryStatus::Deleted,
        _ => return Err(MemoryAdministrationError::Corrupt { field: "status" }),
    };
    let source = match (row.source_thread_id, row.source_message_id) {
        (Some(thread_id), Some(message_id)) => Some(MemorySource {
            thread_id: ThreadId::new(thread_id),
            message_id,
        }),
        (None, None) => None,
        _ => return Err(MemoryAdministrationError::Corrupt { field: "source" }),
    };
    let tags = row
        .tags
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(MemoryAdministrationError::Corrupt { field: "tags" })?;
    let source_run_id = row.source_run_id.map(RunId::new);
    if source_run_id
        .as_ref()
        .is_some_and(|run| run.as_str().is_empty() || source.is_none())
    {
        return Err(MemoryAdministrationError::Corrupt {
            field: "source_run",
        });
    }
    let source_authorization_snapshot = row
        .source_authorization_snapshot
        .map(serde_json::from_value::<MemorySourceAuthorization>)
        .transpose()
        .map_err(|_| MemoryAdministrationError::Corrupt {
            field: "source_authorization",
        })?;
    if source_authorization_snapshot
        .as_ref()
        .is_some_and(|snapshot| {
            snapshot.actor_id.as_str() != row.owner_user_id
                || snapshot.tenant_id.as_str() != row.tenant_id
                || snapshot.deployment_id.as_str().is_empty()
                || snapshot.scope != scope
                || snapshot.auth_generation > i64::MAX as u64
                || snapshot.captured_at > row.created_at
                || !matches!(
                    snapshot.roles.as_slice(),
                    [Role::User] | [Role::Admin] | [Role::Admin, Role::User]
                )
        })
    {
        return Err(MemoryAdministrationError::Corrupt {
            field: "source_authorization",
        });
    }
    if (matches!(status, MemoryStatus::Forbidden | MemoryStatus::Deleted) && row.content.is_some())
        || (matches!(status, MemoryStatus::Active | MemoryStatus::Superseded)
            && row.content.is_none())
    {
        return Err(MemoryAdministrationError::Corrupt { field: "content" });
    }
    Ok(MemoryRecord {
        memory_id: row.memory_id,
        owner_user_id: row.owner_user_id,
        scope,
        memory_kind: kind,
        content: row.content,
        tags,
        sensitivity,
        source,
        source_run_id,
        source_authorization_snapshot,
        origin,
        created_by: row.created_by,
        supersedes_id: row.supersedes_id,
        status,
        expires_at: row.expires_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn domain_scope(scope: &MemoryScope) -> DomainMemoryScope {
    match scope {
        MemoryScope::User => DomainMemoryScope::User,
        MemoryScope::Bot { bot_id } => DomainMemoryScope::Bot(bot_id.clone()),
        MemoryScope::Thread { thread_id } => DomainMemoryScope::Thread(thread_id.clone()),
    }
}

const fn domain_kind(kind: MemoryKind) -> DomainMemoryKind {
    match kind {
        MemoryKind::Preference => DomainMemoryKind::Preference,
        MemoryKind::Fact => DomainMemoryKind::Fact,
    }
}

const fn domain_sensitivity(value: MemorySensitivity) -> DomainMemorySensitivity {
    match value {
        MemorySensitivity::Normal => DomainMemorySensitivity::Normal,
        MemorySensitivity::Sensitive => DomainMemorySensitivity::Sensitive,
    }
}

async fn database_now(
    transaction: &Transaction<'_>,
) -> Result<OffsetDateTime, MemoryAdministrationError> {
    transaction
        .query_one("SELECT now()", &[])
        .await
        .map_err(|error| unavailable("读取 memory 数据库时钟失败", error))?
        .try_get(0)
        .map_err(|_| MemoryAdministrationError::Corrupt {
            field: "database_now",
        })
}

async fn finish_read_transaction<T>(
    transaction: deadpool_postgres::Transaction<'_>,
    result: Result<T, MemoryAdministrationError>,
) -> Result<T, MemoryAdministrationError> {
    let rollback = transaction.rollback().await;
    match result {
        Err(error) => Err(error),
        Ok(value) => rollback
            .map(|()| value)
            .map_err(|_| MemoryAdministrationError::Unavailable),
    }
}

async fn finish_transaction<T>(
    transaction: deadpool_postgres::Transaction<'_>,
    result: Result<T, MemoryAdministrationError>,
) -> Result<T, MemoryAdministrationError> {
    match result {
        Ok(value) => {
            transaction
                .commit()
                .await
                .map_err(|_| MemoryAdministrationError::CommitUnknown)?;
            Ok(value)
        }
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
}

/// Lock, query and invariant failures of the history admission keep their own class; none of
/// them reads as closed.
fn history_error(error: InfraError) -> MemoryAdministrationError {
    tracing::warn!(error = %error, "memory history admission failed");
    match error {
        InfraError::Connect { .. } | InfraError::Query { .. } => {
            MemoryAdministrationError::Unavailable
        }
        _ => MemoryAdministrationError::Corrupt {
            field: "thread_history_writer",
        },
    }
}

fn unavailable(context: &'static str, error: tokio_postgres::Error) -> MemoryAdministrationError {
    tracing::error!(
        sqlstate = error.code().map_or("none", SqlState::code),
        connection_closed = error.is_closed(),
        context,
        "memory database operation failed"
    );
    MemoryAdministrationError::Unavailable
}

fn write_error(context: &'static str, error: tokio_postgres::Error) -> MemoryAdministrationError {
    tracing::error!(
        sqlstate = error.code().map_or("none", SqlState::code),
        connection_closed = error.is_closed(),
        context,
        "memory transaction write failed"
    );
    match error.code() {
        Some(code) if code == &SqlState::UNIQUE_VIOLATION => MemoryAdministrationError::Conflict,
        Some(code) if code == &SqlState::FOREIGN_KEY_VIOLATION => {
            MemoryAdministrationError::NotVisible
        }
        _ => MemoryAdministrationError::Unavailable,
    }
}
