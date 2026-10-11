//! Intelligence verified bundle → native PostgreSQL 的逐 thread 原子 importer。

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use openbot_application::{
    IntelligenceImportCursorStatus, IntelligenceImportError, IntelligenceImportProgress,
    IntelligenceImportStore, IntelligenceThreadImportReceipt, IntelligenceThreadImportRequest,
    IntelligenceToolRunFkReport, compute_intelligence_thread_checksum, intelligence_import_kinds,
};
use openbot_contracts::command::ThreadRunEventKind;
use openbot_contracts::ids::ThreadId;
use openbot_contracts::intelligence::{
    IntelligenceMemoryExport, IntelligenceMemoryScope, IntelligenceMemoryStatus,
    IntelligenceMessageExport, IntelligenceMessageRole, IntelligenceRunEventExport,
    IntelligenceRunExport, IntelligenceRunStatus, IntelligenceThreadAnchor,
    IntelligenceThreadChecksum, IntelligenceThreadExport, IntelligenceThreadStatus,
};
use openbot_contracts::memory::{MemoryKind, MemorySensitivity, MemorySource};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio_postgres::error::SqlState;
use tokio_postgres::{GenericClient, Row, Transaction};

/// Production one-shot importer adapter；Server request path 不构造它。
#[derive(Clone, Debug)]
pub struct PostgresIntelligenceImportStore {
    pool: crate::db::pool::DatabasePool,
}

impl PostgresIntelligenceImportStore {
    /// 用 migration pool 构造。
    #[must_use]
    pub fn new(pool: crate::db::pool::DatabasePool) -> Self {
        Self { pool }
    }

    async fn client(&self) -> Result<crate::db::pool::PooledClient, IntelligenceImportError> {
        self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "intelligence importer 获取连接失败");
            IntelligenceImportError::Unavailable
        })
    }
}

#[async_trait]
impl IntelligenceImportStore for PostgresIntelligenceImportStore {
    async fn load_progress(
        &self,
        bundle_id: &str,
        target_deployment_id: &str,
        payload_sha256: &str,
    ) -> Result<Option<IntelligenceImportProgress>, IntelligenceImportError> {
        let client = self.client().await?;
        load_progress_client(&**client, bundle_id, target_deployment_id, payload_sha256).await
    }

    async fn import_thread(
        &self,
        request: IntelligenceThreadImportRequest,
    ) -> Result<IntelligenceThreadImportReceipt, IntelligenceImportError> {
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("开始 intelligence thread import 事务", error))?;
        let result = import_thread_transaction(&transaction, &request).await;
        finish_transaction(transaction, result).await
    }

    async fn verify_thread(
        &self,
        thread_id: &str,
    ) -> Result<IntelligenceThreadChecksum, IntelligenceImportError> {
        let client = self.client().await?;
        crate::db::thread_origin_schema::verify(&client)
            .await
            .map_err(import_origin_error)?;
        observe_thread_checksum(&**client, thread_id).await
    }

    async fn complete_bundle(
        &self,
        bundle_id: &str,
        target_deployment_id: &str,
        payload_sha256: &str,
        progress: &IntelligenceImportProgress,
    ) -> Result<(), IntelligenceImportError> {
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("开始 intelligence complete 事务", error))?;
        let result = complete_transaction(
            &transaction,
            bundle_id,
            target_deployment_id,
            payload_sha256,
            progress,
        )
        .await;
        finish_transaction(transaction, result).await
    }

    async fn mark_failed(
        &self,
        bundle_id: &str,
        target_deployment_id: &str,
        payload_sha256: &str,
    ) -> Result<(), IntelligenceImportError> {
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("开始 intelligence failed 事务", error))?;
        let result = mark_failed_transaction(
            &transaction,
            bundle_id,
            target_deployment_id,
            payload_sha256,
        )
        .await;
        finish_transaction(transaction, result).await
    }

    async fn validate_tool_run_fk(
        &self,
    ) -> Result<IntelligenceToolRunFkReport, IntelligenceImportError> {
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("开始 tool run FK validate 事务", error))?;
        let result = validate_tool_run_fk_transaction(&transaction).await;
        finish_transaction(transaction, result).await
    }
}

async fn validate_tool_run_fk_transaction(
    transaction: &Transaction<'_>,
) -> Result<IntelligenceToolRunFkReport, IntelligenceImportError> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('openbot:intelligence:finalize',0))",
            &[],
        )
        .await
        .map_err(|error| unavailable("锁定 intelligence finalize", error))?;
    let incomplete: i64 = transaction
        .query_one(
            "SELECT count(*)::bigint FROM( \
               SELECT bundle_id FROM public.intelligence_import_cursors GROUP BY bundle_id \
               HAVING count(*)<>4 OR NOT bool_and(status='completed') \
             ) incomplete",
            &[],
        )
        .await
        .map_err(|error| unavailable("统计 incomplete bundles", error))?
        .try_get(0)
        .map_err(|_| IntelligenceImportError::Corrupt {
            field: "incomplete_bundle_count",
        })?;
    let orphans: i64 = transaction
        .query_one(
            "SELECT count(*)::bigint FROM public.tool_calls tc \
             LEFT JOIN public.runs r ON r.run_id=tc.run_id WHERE r.run_id IS NULL",
            &[],
        )
        .await
        .map_err(|error| unavailable("统计 historical tool run orphans", error))?
        .try_get(0)
        .map_err(|_| IntelligenceImportError::Corrupt {
            field: "orphan_tool_call_count",
        })?;
    let mut validated = tool_run_fk_validated(transaction).await?;
    if incomplete == 0 && orphans == 0 && !validated {
        transaction
            .batch_execute(
                "ALTER TABLE public.tool_calls VALIDATE CONSTRAINT tool_calls_run_id_fkey",
            )
            .await
            .map_err(|error| write_error("validate tool_calls_run_id_fkey", error))?;
        validated = tool_run_fk_validated(transaction).await?;
    }
    Ok(IntelligenceToolRunFkReport {
        incomplete_bundle_count: sequence_u64(incomplete, "incomplete_bundle_count")?,
        orphan_tool_call_count: sequence_u64(orphans, "orphan_tool_call_count")?,
        validated,
    })
}

async fn tool_run_fk_validated(
    transaction: &Transaction<'_>,
) -> Result<bool, IntelligenceImportError> {
    transaction
        .query_one(
            "SELECT convalidated FROM pg_constraint \
             WHERE conrelid='public.tool_calls'::regclass AND conname='tool_calls_run_id_fkey'",
            &[],
        )
        .await
        .map_err(|error| unavailable("读取 tool run FK validation", error))?
        .try_get(0)
        .map_err(|_| IntelligenceImportError::Corrupt {
            field: "tool_calls_run_id_fkey",
        })
}

async fn import_thread_transaction(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
) -> Result<IntelligenceThreadImportReceipt, IntelligenceImportError> {
    crate::db::native::validate_thread_origin_in_transaction(transaction)
        .await
        .map_err(import_origin_error)?;
    lock_bundle(transaction, &request.bundle_id).await?;
    let current = load_progress_transaction(
        transaction,
        &request.bundle_id,
        &request.target_deployment_id,
        &request.payload_sha256,
    )
    .await?
    .unwrap_or_else(empty_progress);
    if current == request.progress {
        let observed = observe_thread_checksum(transaction, &request.thread.thread_id).await?;
        return Ok(IntelligenceThreadImportReceipt {
            checksum: observed,
            replayed: true,
        });
    }
    if current != request.previous_progress
        || request.progress.cursor != request.thread.thread_id
        || request.progress.status != IntelligenceImportCursorStatus::Running
        || compute_intelligence_thread_checksum(&request.thread)? != request.checksum
    {
        return Err(IntelligenceImportError::Conflict {
            field: "import_progress",
        });
    }
    validate_targets(transaction, request).await?;
    insert_thread(transaction, request).await?;
    crate::thread_history_writer::require_open(
        transaction,
        &ThreadId::new(&request.thread.thread_id),
    )
    .await
    .map_err(import_writer_error)?;
    insert_memberships(transaction, request).await?;
    insert_runs(transaction, request).await?;
    insert_messages(transaction, request).await?;
    insert_events(transaction, request).await?;
    insert_memories(transaction, request).await?;
    let observed = observe_thread_checksum(transaction, &request.thread.thread_id).await?;
    if observed != request.checksum {
        return Err(IntelligenceImportError::Corrupt {
            field: "database_checksum",
        });
    }
    write_progress_rows(
        transaction,
        &request.bundle_id,
        &request.target_deployment_id,
        &request.payload_sha256,
        &request.provenance,
        &request.progress,
    )
    .await?;
    Ok(IntelligenceThreadImportReceipt {
        checksum: observed,
        replayed: false,
    })
}

async fn validate_targets(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
) -> Result<(), IntelligenceImportError> {
    let mut users: BTreeSet<String> = request.thread.members.iter().cloned().collect();
    users.insert(request.thread.created_by.clone());
    for message in &request.thread.messages {
        users.extend(message.actor_id.clone());
    }
    let mut bots = BTreeSet::new();
    let mut channels = BTreeSet::new();
    match &request.thread.anchor {
        IntelligenceThreadAnchor::DirectBot { bot_id } => {
            bots.insert(bot_id.clone());
        }
        IntelligenceThreadAnchor::Channel { channel_id } => {
            channels.insert(channel_id.clone());
        }
    }
    for run in &request.thread.runs {
        users.insert(run.actor_id.clone());
        bots.insert(run.bot_id.clone());
    }
    for memory in &request.thread.memories {
        users.insert(memory.owner_user_id.clone());
        users.insert(memory.created_by.clone());
        if let IntelligenceMemoryScope::Bot { bot_id } = &memory.scope {
            bots.insert(bot_id.clone());
        }
    }
    ensure_ids_exist(transaction, "users", "id", users).await?;
    ensure_ids_exist(transaction, "agents", "id", bots).await?;
    ensure_ids_exist(transaction, "channels", "id", channels).await
}

async fn ensure_ids_exist(
    transaction: &Transaction<'_>,
    table: &'static str,
    column: &'static str,
    ids: BTreeSet<String>,
) -> Result<(), IntelligenceImportError> {
    if ids.is_empty() {
        return Ok(());
    }
    let ids = ids.into_iter().collect::<Vec<_>>();
    let sql = format!("SELECT {column} FROM public.{table} WHERE {column}=ANY($1::text[])");
    let rows = transaction
        .query(&sql, &[&ids])
        .await
        .map_err(|error| unavailable("验证 import target", error))?;
    if rows.len() == ids.len() {
        Ok(())
    } else {
        Err(IntelligenceImportError::Invalid {
            field: "target_mapping",
        })
    }
}

async fn insert_thread(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
) -> Result<(), IntelligenceImportError> {
    let thread = &request.thread;
    let (anchor_kind, anchor_id) = match &thread.anchor {
        IntelligenceThreadAnchor::DirectBot { bot_id } => ("direct_bot", bot_id.as_str()),
        IntelligenceThreadAnchor::Channel { channel_id } => ("channel", channel_id.as_str()),
    };
    let next_message = i64_count(thread.messages.len(), "next_message_seq")?;
    let event_count = thread
        .runs
        .iter()
        .try_fold(0_usize, |sum, run| sum.checked_add(run.events.len()))
        .ok_or(IntelligenceImportError::Invalid {
            field: "next_event_seq",
        })?;
    let next_event = i64_count(event_count, "next_event_seq")?;
    let inserted = transaction
        .query_opt(
            "INSERT INTO public.threads( \
               thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status, \
               next_message_seq,next_event_seq,created_at,updated_at,deleted_at \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) \
             ON CONFLICT(thread_id) DO NOTHING RETURNING thread_id",
            &[
                &thread.thread_id,
                &request.target_tenant_id,
                &request.target_deployment_id,
                &thread.created_by,
                &anchor_kind,
                &anchor_id,
                &thread.title,
                &thread_status(thread.status),
                &next_message,
                &next_event,
                &thread.created_at,
                &thread.updated_at,
                &thread.deleted_at,
            ],
        )
        .await
        .map_err(|error| write_error("写 import thread", error))?;
    let row = transaction
        .query_one(
            "SELECT tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status, \
                    next_message_seq,next_event_seq,created_at,updated_at,deleted_at \
             FROM public.threads WHERE thread_id=$1",
            &[&thread.thread_id],
        )
        .await
        .map_err(|error| unavailable("核对 import thread", error))?;
    let exact = decode::<String>(&row, "tenant_id")? == request.target_tenant_id
        && decode::<String>(&row, "deployment_id")? == request.target_deployment_id
        && decode::<String>(&row, "created_by")? == thread.created_by
        && decode::<String>(&row, "anchor_kind")? == anchor_kind
        && decode::<String>(&row, "anchor_id")? == anchor_id
        && decode::<Option<String>>(&row, "title")? == thread.title
        && decode::<String>(&row, "status")? == thread_status(thread.status)
        && decode::<i64>(&row, "next_message_seq")? == next_message
        && decode::<i64>(&row, "next_event_seq")? == next_event
        && decode::<OffsetDateTime>(&row, "created_at")? == thread.created_at
        && decode::<OffsetDateTime>(&row, "updated_at")? == thread.updated_at
        && decode::<Option<OffsetDateTime>>(&row, "deleted_at")? == thread.deleted_at;
    if !exact {
        return Err(IntelligenceImportError::Conflict { field: "thread" });
    }
    if let Some(inserted) = inserted {
        if decode::<String>(&inserted, "thread_id")? != thread.thread_id {
            return Err(IntelligenceImportError::Corrupt {
                field: "thread_origin",
            });
        }
        let signing_key_id = request
            .provenance
            .get("signingKeyId")
            .and_then(Value::as_str)
            .ok_or(IntelligenceImportError::Corrupt {
                field: "import_provenance",
            })?;
        if request
            .provenance
            .get("payloadSha256")
            .and_then(Value::as_str)
            != Some(request.payload_sha256.as_str())
        {
            return Err(IntelligenceImportError::Corrupt {
                field: "import_provenance",
            });
        }
        crate::thread_origin::record_new_import(
            transaction,
            &thread.thread_id,
            &request.bundle_id,
            &request.payload_sha256,
            signing_key_id,
            &request.checksum,
        )
        .await
        .map_err(import_origin_error)?;
    } else {
        crate::thread_origin::observe_on(transaction, &thread.thread_id)
            .await
            .map_err(import_origin_error)?;
    }
    Ok(())
}

async fn insert_memberships(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
) -> Result<(), IntelligenceImportError> {
    for user in &request.thread.members {
        transaction
            .execute(
                "INSERT INTO public.thread_memberships(thread_id,user_id,created_at) \
                 VALUES($1,$2,$3) ON CONFLICT(thread_id,user_id) DO NOTHING",
                &[&request.thread.thread_id, &user, &request.thread.created_at],
            )
            .await
            .map_err(|error| write_error("写 import membership", error))?;
    }
    let rows = transaction
        .query(
            "SELECT user_id FROM public.thread_memberships WHERE thread_id=$1 ORDER BY user_id",
            &[&request.thread.thread_id],
        )
        .await
        .map_err(|error| unavailable("核对 import memberships", error))?;
    let observed = rows
        .iter()
        .map(|row| decode::<String>(row, "user_id"))
        .collect::<Result<Vec<_>, _>>()?;
    if observed == request.thread.members {
        Ok(())
    } else {
        Err(IntelligenceImportError::Conflict {
            field: "thread_memberships",
        })
    }
}

async fn insert_runs(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
) -> Result<(), IntelligenceImportError> {
    for run in &request.thread.runs {
        let next_event = i64_count(run.events.len(), "run_next_event_seq")?;
        let terminal = run
            .events
            .iter()
            .find(|event| event.event_type.is_terminal())
            .ok_or(IntelligenceImportError::Invalid {
                field: "terminal_event",
            })?;
        let terminal_sequence = sequence_i64(terminal.sequence, "terminal_event_seq")?;
        transaction
            .execute(
                "INSERT INTO public.runs( \
                   run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq, \
                   terminal_event_seq,error_code,created_at,started_at,finished_at \
                 ) VALUES($1,$2,$3,$4,$5,$6,0,$7,$8,$9,$10,$11,$12) \
                 ON CONFLICT(run_id) DO NOTHING",
                &[
                    &run.run_id,
                    &request.thread.thread_id,
                    &run.bot_id,
                    &run.actor_id,
                    &run.foreground,
                    &run.status.as_str(),
                    &next_event,
                    &terminal_sequence,
                    &run.error_code,
                    &run.created_at,
                    &run.started_at,
                    &run.finished_at,
                ],
            )
            .await
            .map_err(|error| write_error("写 import run", error))?;
        let row = transaction
            .query_one(
                "SELECT thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq, \
                        terminal_event_seq,error_code,created_at,started_at,finished_at \
                 FROM public.runs WHERE run_id=$1",
                &[&run.run_id],
            )
            .await
            .map_err(|error| unavailable("核对 import run", error))?;
        let exact = decode::<String>(&row, "thread_id")? == request.thread.thread_id
            && decode::<String>(&row, "bot_id")? == run.bot_id
            && decode::<String>(&row, "actor_id")? == run.actor_id
            && decode::<bool>(&row, "foreground")? == run.foreground
            && decode::<String>(&row, "status")? == run.status.as_str()
            && decode::<i64>(&row, "fencing_token")? == 0
            && decode::<i64>(&row, "next_event_seq")? == next_event
            && decode::<Option<i64>>(&row, "terminal_event_seq")? == Some(terminal_sequence)
            && decode::<Option<String>>(&row, "error_code")? == run.error_code
            && decode::<OffsetDateTime>(&row, "created_at")? == run.created_at
            && decode::<Option<OffsetDateTime>>(&row, "started_at")? == run.started_at
            && decode::<Option<OffsetDateTime>>(&row, "finished_at")? == Some(run.finished_at);
        if !exact {
            return Err(IntelligenceImportError::Conflict { field: "run" });
        }
    }
    Ok(())
}

async fn insert_messages(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
) -> Result<(), IntelligenceImportError> {
    let mut messages = request.thread.messages.iter().collect::<Vec<_>>();
    messages.sort_by_key(|message| message.sequence);
    for message in messages {
        let sequence = sequence_i64(message.sequence, "message_sequence")?;
        transaction
            .execute(
                "INSERT INTO public.messages( \
                   message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at \
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(message_id) DO NOTHING",
                &[
                    &message.message_id,
                    &request.thread.thread_id,
                    &sequence,
                    &message.role.as_str(),
                    &message.content,
                    &message.search_text,
                    &message.run_id,
                    &message.actor_id,
                    &message.created_at,
                ],
            )
            .await
            .map_err(|error| write_error("写 import message", error))?;
        let row = transaction
            .query_one(
                "SELECT thread_id,seq,role,content,search_text,run_id,actor_id,created_at \
                 FROM public.messages WHERE message_id=$1",
                &[&message.message_id],
            )
            .await
            .map_err(|error| unavailable("核对 import message", error))?;
        let exact = decode::<String>(&row, "thread_id")? == request.thread.thread_id
            && decode::<i64>(&row, "seq")? == sequence
            && decode::<String>(&row, "role")? == message.role.as_str()
            && decode::<Value>(&row, "content")? == message.content
            && decode::<String>(&row, "search_text")? == message.search_text
            && decode::<Option<String>>(&row, "run_id")? == message.run_id
            && decode::<Option<String>>(&row, "actor_id")? == message.actor_id
            && decode::<OffsetDateTime>(&row, "created_at")? == message.created_at;
        if !exact {
            return Err(IntelligenceImportError::Conflict { field: "message" });
        }
    }
    Ok(())
}

async fn insert_events(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
) -> Result<(), IntelligenceImportError> {
    for run in &request.thread.runs {
        let mut events = run.events.iter().collect::<Vec<_>>();
        events.sort_by_key(|event| event.sequence);
        for event in events {
            let sequence = sequence_i64(event.sequence, "run_event_sequence")?;
            let event_sequence = sequence_i64(event.event_sequence, "thread_event_sequence")?;
            transaction
                .execute(
                    "INSERT INTO public.run_events( \
                       run_id,seq,thread_id,event_seq,event_type,payload,terminal,created_at \
                     ) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(run_id,seq) DO NOTHING",
                    &[
                        &run.run_id,
                        &sequence,
                        &request.thread.thread_id,
                        &event_sequence,
                        &event_kind(event.event_type),
                        &event.payload,
                        &event.event_type.is_terminal(),
                        &event.created_at,
                    ],
                )
                .await
                .map_err(|error| write_error("写 import run event", error))?;
            let row = transaction
                .query_one(
                    "SELECT thread_id,event_seq,event_type,payload,terminal,created_at \
                     FROM public.run_events WHERE run_id=$1 AND seq=$2",
                    &[&run.run_id, &sequence],
                )
                .await
                .map_err(|error| unavailable("核对 import run event", error))?;
            let exact = decode::<String>(&row, "thread_id")? == request.thread.thread_id
                && decode::<i64>(&row, "event_seq")? == event_sequence
                && decode::<String>(&row, "event_type")? == event_kind(event.event_type)
                && decode::<Value>(&row, "payload")? == event.payload
                && decode::<bool>(&row, "terminal")? == event.event_type.is_terminal()
                && decode::<OffsetDateTime>(&row, "created_at")? == event.created_at;
            if !exact {
                return Err(IntelligenceImportError::Conflict { field: "run_event" });
            }
        }
    }
    Ok(())
}

async fn insert_memories(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
) -> Result<(), IntelligenceImportError> {
    let mut remaining: BTreeMap<_, _> = request
        .thread
        .memories
        .iter()
        .map(|memory| (memory.memory_id.as_str(), memory))
        .collect();
    let mut inserted = BTreeSet::new();
    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .find(|(_, memory)| {
                memory
                    .supersedes_id
                    .as_ref()
                    .is_none_or(|parent| inserted.contains(parent.as_str()))
            })
            .map(|(id, _)| *id)
            .ok_or(IntelligenceImportError::Invalid {
                field: "memory_supersession_cycle",
            })?;
        let memory = remaining.remove(ready).expect("ready key exists");
        insert_memory(transaction, request, memory).await?;
        inserted.insert(ready);
    }
    Ok(())
}

async fn insert_memory(
    transaction: &Transaction<'_>,
    request: &IntelligenceThreadImportRequest,
    memory: &IntelligenceMemoryExport,
) -> Result<(), IntelligenceImportError> {
    let (scope_kind, scope_id) = match &memory.scope {
        IntelligenceMemoryScope::User => ("user", None),
        IntelligenceMemoryScope::Bot { bot_id } => ("bot", Some(bot_id.as_str())),
        IntelligenceMemoryScope::Thread { thread_id } => ("thread", Some(thread_id.as_str())),
    };
    let tags = memory.tags.iter().cloned().map(Some).collect::<Vec<_>>();
    transaction
        .execute(
            "INSERT INTO public.memories( \
               memory_id,tenant_id,owner_user_id,scope_kind,scope_id,memory_kind,content,tags, \
               sensitivity,source_thread_id,source_message_id,origin,created_by,supersedes_id, \
               status,expires_at,created_at,updated_at \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'verified_import',$12,$13,$14,$15,$16,$17) \
             ON CONFLICT(memory_id) DO NOTHING",
            &[
                &memory.memory_id,
                &request.target_tenant_id,
                &memory.owner_user_id,
                &scope_kind,
                &scope_id,
                &memory_kind(memory.memory_kind),
                &memory.content,
                &tags,
                &memory_sensitivity(memory.sensitivity),
                &memory.source.thread_id.as_str(),
                &memory.source.message_id,
                &memory.created_by,
                &memory.supersedes_id,
                &memory.status.as_str(),
                &memory.expires_at,
                &memory.created_at,
                &memory.updated_at,
            ],
        )
        .await
        .map_err(|error| write_error("写 import memory", error))?;
    let row = transaction
        .query_one(
            "SELECT tenant_id,owner_user_id,scope_kind,scope_id,memory_kind,content,tags, \
                    sensitivity,source_thread_id,source_message_id,origin,created_by,supersedes_id, \
                    status,expires_at,created_at,updated_at,source_run_id,source_authorization_snapshot \
                    FROM public.memories WHERE memory_id=$1",
            &[&memory.memory_id],
        )
        .await
        .map_err(|error| unavailable("核对 import memory", error))?;
    let exact = decode::<String>(&row, "tenant_id")? == request.target_tenant_id
        // The existing signed format does not carry these original provenance facts.
        // Neither a later message binding nor the importing actor may fill that historical gap.
        && decode::<Option<String>>(&row, "source_run_id")?.is_none()
        && decode::<Option<serde_json::Value>>(&row, "source_authorization_snapshot")?.is_none()
        && decode::<String>(&row, "owner_user_id")? == memory.owner_user_id
        && decode::<String>(&row, "scope_kind")? == scope_kind
        && decode::<Option<String>>(&row, "scope_id")?.as_deref() == scope_id
        && decode::<String>(&row, "memory_kind")? == memory_kind(memory.memory_kind)
        && decode::<Option<String>>(&row, "content")?.as_deref() == Some(memory.content.as_str())
        && decode::<Vec<Option<String>>>(&row, "tags")? == tags
        && decode::<String>(&row, "sensitivity")? == memory_sensitivity(memory.sensitivity)
        && decode::<Option<String>>(&row, "source_thread_id")?.as_deref()
            == Some(memory.source.thread_id.as_str())
        && decode::<Option<String>>(&row, "source_message_id")?.as_deref()
            == Some(memory.source.message_id.as_str())
        && decode::<String>(&row, "origin")? == "verified_import"
        && decode::<String>(&row, "created_by")? == memory.created_by
        && decode::<Option<String>>(&row, "supersedes_id")? == memory.supersedes_id
        && decode::<String>(&row, "status")? == memory.status.as_str()
        && decode::<Option<OffsetDateTime>>(&row, "expires_at")? == memory.expires_at
        && decode::<OffsetDateTime>(&row, "created_at")? == memory.created_at
        && decode::<OffsetDateTime>(&row, "updated_at")? == memory.updated_at;
    if !exact {
        return Err(IntelligenceImportError::Conflict { field: "memory" });
    }
    let metadata = json!({
        "bundleId":request.bundle_id,
        "verifiedImport":true,
        "importedStatus":memory.status.as_str(),
    });
    transaction
        .execute(
            "INSERT INTO public.memory_events(memory_id,seq,event_type,actor_id,metadata,created_at) \
             VALUES($1,0,'create',$2,$3,$4) ON CONFLICT(memory_id,seq) DO NOTHING",
            &[
                &memory.memory_id,
                &memory.created_by,
                &metadata,
                &memory.created_at,
            ],
        )
        .await
        .map_err(|error| write_error("写 import memory event", error))?;
    Ok(())
}

async fn observe_thread_checksum(
    client: &impl GenericClient,
    thread_id: &str,
) -> Result<IntelligenceThreadChecksum, IntelligenceImportError> {
    crate::thread_origin::observe_on(client, thread_id)
        .await
        .map_err(import_origin_error)?;
    let thread = reconstruct_thread(client, thread_id).await?;
    compute_intelligence_thread_checksum(&thread)
}

async fn reconstruct_thread(
    client: &impl GenericClient,
    thread_id: &str,
) -> Result<IntelligenceThreadExport, IntelligenceImportError> {
    let row = client
        .query_opt(
            "SELECT created_by,anchor_kind,anchor_id,title,status,created_at,updated_at,deleted_at \
             FROM public.threads WHERE thread_id=$1",
            &[&thread_id],
        )
        .await
        .map_err(|error| unavailable("读取 imported thread projection", error))?
        .ok_or(IntelligenceImportError::Corrupt { field: "thread" })?;
    let anchor_kind: String = decode(&row, "anchor_kind")?;
    let anchor_id: String = decode(&row, "anchor_id")?;
    let anchor = match anchor_kind.as_str() {
        "direct_bot" => IntelligenceThreadAnchor::DirectBot { bot_id: anchor_id },
        "channel" => IntelligenceThreadAnchor::Channel {
            channel_id: anchor_id,
        },
        _ => return Err(IntelligenceImportError::Corrupt { field: "anchor" }),
    };
    let raw_status: String = decode(&row, "status")?;
    let status = match raw_status.as_str() {
        "active" => IntelligenceThreadStatus::Active,
        "archived" => IntelligenceThreadStatus::Archived,
        "deleted" => IntelligenceThreadStatus::Deleted,
        _ => {
            return Err(IntelligenceImportError::Corrupt {
                field: "thread_status",
            });
        }
    };
    let members = client
        .query(
            "SELECT user_id FROM public.thread_memberships WHERE thread_id=$1 ORDER BY user_id",
            &[&thread_id],
        )
        .await
        .map_err(|error| unavailable("读取 imported memberships", error))?
        .iter()
        .map(|row| decode::<String>(row, "user_id"))
        .collect::<Result<_, _>>()?;
    let messages = reconstruct_messages(client, thread_id).await?;
    let runs = reconstruct_runs(client, thread_id).await?;
    let memories = reconstruct_memories(client, thread_id).await?;
    Ok(IntelligenceThreadExport {
        thread_id: thread_id.to_owned(),
        created_by: decode(&row, "created_by")?,
        members,
        title: decode(&row, "title")?,
        anchor,
        status,
        messages,
        runs,
        memories,
        checksum: empty_checksum(),
        created_at: decode(&row, "created_at")?,
        updated_at: decode(&row, "updated_at")?,
        deleted_at: decode(&row, "deleted_at")?,
    })
}

async fn reconstruct_messages(
    client: &impl GenericClient,
    thread_id: &str,
) -> Result<Vec<IntelligenceMessageExport>, IntelligenceImportError> {
    client
        .query(
            "SELECT message_id,seq,role,content,search_text,run_id,actor_id,created_at \
             FROM public.messages WHERE thread_id=$1 ORDER BY seq",
            &[&thread_id],
        )
        .await
        .map_err(|error| unavailable("读取 imported messages", error))?
        .iter()
        .map(|row| {
            let role: String = decode(row, "role")?;
            Ok(IntelligenceMessageExport {
                message_id: decode(row, "message_id")?,
                sequence: sequence_u64(decode(row, "seq")?, "message_sequence")?,
                role: parse_message_role(&role)?,
                content: decode(row, "content")?,
                search_text: decode(row, "search_text")?,
                run_id: decode(row, "run_id")?,
                actor_id: decode(row, "actor_id")?,
                created_at: decode(row, "created_at")?,
            })
        })
        .collect()
}

async fn reconstruct_runs(
    client: &impl GenericClient,
    thread_id: &str,
) -> Result<Vec<IntelligenceRunExport>, IntelligenceImportError> {
    let rows = client
        .query(
            "SELECT run_id,bot_id,actor_id,foreground,status,error_code,created_at,started_at,finished_at \
             FROM public.runs WHERE thread_id=$1 ORDER BY run_id",
            &[&thread_id],
        )
        .await
        .map_err(|error| unavailable("读取 imported runs", error))?;
    let mut runs = Vec::with_capacity(rows.len());
    for row in rows {
        let run_id: String = decode(&row, "run_id")?;
        let raw_status: String = decode(&row, "status")?;
        let status = parse_run_status(&raw_status)?;
        let events = client
            .query(
                "SELECT seq,event_seq,event_type,payload,created_at FROM public.run_events \
                 WHERE run_id=$1 ORDER BY seq",
                &[&run_id],
            )
            .await
            .map_err(|error| unavailable("读取 imported events", error))?
            .iter()
            .map(|event| {
                let raw: String = decode(event, "event_type")?;
                Ok(IntelligenceRunEventExport {
                    sequence: sequence_u64(decode(event, "seq")?, "run_event_sequence")?,
                    event_sequence: sequence_u64(
                        decode(event, "event_seq")?,
                        "thread_event_sequence",
                    )?,
                    event_type: ThreadRunEventKind::from_database(&raw).ok_or(
                        IntelligenceImportError::Corrupt {
                            field: "event_type",
                        },
                    )?,
                    payload: decode(event, "payload")?,
                    created_at: decode(event, "created_at")?,
                })
            })
            .collect::<Result<_, _>>()?;
        runs.push(IntelligenceRunExport {
            run_id,
            bot_id: decode(&row, "bot_id")?,
            actor_id: decode(&row, "actor_id")?,
            foreground: decode(&row, "foreground")?,
            status,
            error_code: decode(&row, "error_code")?,
            events,
            created_at: decode(&row, "created_at")?,
            started_at: decode(&row, "started_at")?,
            finished_at: decode::<Option<OffsetDateTime>>(&row, "finished_at")?.ok_or(
                IntelligenceImportError::Corrupt {
                    field: "finished_at",
                },
            )?,
        });
    }
    Ok(runs)
}

async fn reconstruct_memories(
    client: &impl GenericClient,
    thread_id: &str,
) -> Result<Vec<IntelligenceMemoryExport>, IntelligenceImportError> {
    client
        .query(
            "SELECT memory_id,owner_user_id,scope_kind,scope_id,memory_kind,content,tags, \
                    sensitivity,source_thread_id,source_message_id,created_by,supersedes_id,status, \
                    expires_at,created_at,updated_at,source_run_id,source_authorization_snapshot \
                    FROM public.memories \
             WHERE source_thread_id=$1 ORDER BY memory_id",
            &[&thread_id],
        )
        .await
        .map_err(|error| unavailable("读取 imported memories", error))?
        .iter()
        .map(|row| {
            // Completed/resumed import observes the same original nullable facts as a new page.
            // The signed legacy format cannot silently certify later enrichment as an exact replay.
            if decode::<Option<String>>(row, "source_run_id")?.is_some()
                || decode::<Option<serde_json::Value>>(row, "source_authorization_snapshot")?.is_some()
            {
                return Err(IntelligenceImportError::Corrupt { field: "memory_source_provenance" });
            }
            let scope_kind: String = decode(row, "scope_kind")?;
            let scope_id: Option<String> = decode(row, "scope_id")?;
            let scope = match (scope_kind.as_str(), scope_id) {
                ("user", None) => IntelligenceMemoryScope::User,
                ("bot", Some(bot_id)) => IntelligenceMemoryScope::Bot { bot_id },
                ("thread", Some(thread_id)) => IntelligenceMemoryScope::Thread { thread_id },
                _ => return Err(IntelligenceImportError::Corrupt { field: "memory_scope" }),
            };
            let tags = decode::<Vec<Option<String>>>(row, "tags")?
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or(IntelligenceImportError::Corrupt { field: "memory_tags" })?;
            let source_thread = decode::<Option<String>>(row, "source_thread_id")?.ok_or(
                IntelligenceImportError::Corrupt {
                    field: "memory_source",
                },
            )?;
            let source_message = decode::<Option<String>>(row, "source_message_id")?.ok_or(
                IntelligenceImportError::Corrupt {
                    field: "memory_source",
                },
            )?;
            let kind: String = decode(row, "memory_kind")?;
            let sensitivity: String = decode(row, "sensitivity")?;
            let status: String = decode(row, "status")?;
            Ok(IntelligenceMemoryExport {
                memory_id: decode(row, "memory_id")?,
                owner_user_id: decode(row, "owner_user_id")?,
                scope,
                memory_kind: parse_memory_kind(&kind)?,
                content: decode::<Option<String>>(row, "content")?.ok_or(
                    IntelligenceImportError::Corrupt {
                        field: "memory_content",
                    },
                )?,
                tags,
                sensitivity: parse_memory_sensitivity(&sensitivity)?,
                source: MemorySource {
                    thread_id: ThreadId::new(source_thread),
                    message_id: source_message,
                },
                created_by: decode(row, "created_by")?,
                supersedes_id: decode(row, "supersedes_id")?,
                status: parse_memory_status(&status)?,
                expires_at: decode(row, "expires_at")?,
                created_at: decode(row, "created_at")?,
                updated_at: decode(row, "updated_at")?,
            })
        })
        .collect()
}

async fn complete_transaction(
    transaction: &Transaction<'_>,
    bundle_id: &str,
    deployment_id: &str,
    payload_sha256: &str,
    progress: &IntelligenceImportProgress,
) -> Result<(), IntelligenceImportError> {
    lock_bundle(transaction, bundle_id).await?;
    let existing =
        load_progress_transaction(transaction, bundle_id, deployment_id, payload_sha256).await?;
    let current = existing.clone().unwrap_or_else(empty_progress);
    if current.status == IntelligenceImportCursorStatus::Completed {
        return if same_progress_ignoring_status(&current, progress) {
            Ok(())
        } else {
            Err(IntelligenceImportError::Conflict {
                field: "completed_progress",
            })
        };
    }
    if !same_progress_ignoring_status(&current, progress) {
        return Err(IntelligenceImportError::Conflict {
            field: "completed_progress",
        });
    }
    let mut completed = progress.clone();
    completed.status = IntelligenceImportCursorStatus::Completed;
    if existing.is_none() {
        let provenance = json!({"payloadSha256":payload_sha256});
        write_progress_rows(
            transaction,
            bundle_id,
            deployment_id,
            payload_sha256,
            &provenance,
            &completed,
        )
        .await
    } else {
        let updated = transaction
            .execute(
                "UPDATE public.intelligence_import_cursors SET status='completed',updated_at=now() \
                 WHERE bundle_id=$1 AND deployment_id=$2 \
                   AND provenance->>'payloadSha256'=$3 AND status<>'completed'",
                &[&bundle_id, &deployment_id, &payload_sha256],
            )
            .await
            .map_err(|error| write_error("完成 intelligence cursors", error))?;
        if updated == intelligence_import_kinds().len() as u64 {
            Ok(())
        } else {
            Err(IntelligenceImportError::Conflict {
                field: "completed_progress",
            })
        }
    }
}

async fn mark_failed_transaction(
    transaction: &Transaction<'_>,
    bundle_id: &str,
    deployment_id: &str,
    payload_sha256: &str,
) -> Result<(), IntelligenceImportError> {
    lock_bundle(transaction, bundle_id).await?;
    let existing =
        load_progress_transaction(transaction, bundle_id, deployment_id, payload_sha256).await?;
    let current = existing.clone().unwrap_or_else(empty_progress);
    if current.status == IntelligenceImportCursorStatus::Completed {
        return Ok(());
    }
    let mut failed = current;
    failed.status = IntelligenceImportCursorStatus::Failed;
    if existing.is_none() {
        let provenance = json!({"payloadSha256":payload_sha256});
        write_progress_rows(
            transaction,
            bundle_id,
            deployment_id,
            payload_sha256,
            &provenance,
            &failed,
        )
        .await
    } else {
        let updated = transaction
            .execute(
                "UPDATE public.intelligence_import_cursors SET status='failed',updated_at=now() \
                 WHERE bundle_id=$1 AND deployment_id=$2 \
                   AND provenance->>'payloadSha256'=$3 AND status<>'completed'",
                &[&bundle_id, &deployment_id, &payload_sha256],
            )
            .await
            .map_err(|error| write_error("标记 intelligence cursors failed", error))?;
        if updated == intelligence_import_kinds().len() as u64 {
            Ok(())
        } else {
            Err(IntelligenceImportError::Conflict {
                field: "failed_progress",
            })
        }
    }
}

async fn write_progress_rows(
    transaction: &Transaction<'_>,
    bundle_id: &str,
    deployment_id: &str,
    payload_sha256: &str,
    provenance: &Value,
    progress: &IntelligenceImportProgress,
) -> Result<(), IntelligenceImportError> {
    if provenance.get("payloadSha256").and_then(Value::as_str) != Some(payload_sha256) {
        return Err(IntelligenceImportError::Invalid {
            field: "cursor_provenance",
        });
    }
    let values = [
        (
            "thread",
            progress.thread_count,
            progress.thread_hash.as_str(),
        ),
        (
            "message",
            progress.message_count,
            progress.message_hash.as_str(),
        ),
        (
            "run_event",
            progress.event_count,
            progress.event_hash.as_str(),
        ),
        (
            "memory",
            progress.memory_count,
            progress.memory_hash.as_str(),
        ),
    ];
    for (kind, count, hash) in values {
        let count = i64::try_from(count).map_err(|_| IntelligenceImportError::Invalid {
            field: "imported_count",
        })?;
        transaction
            .execute(
                "INSERT INTO public.intelligence_import_cursors( \
                   bundle_id,aggregate_kind,deployment_id,cursor,last_hash,imported_count,status, \
                   provenance,updated_at \
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()) \
                 ON CONFLICT(bundle_id,aggregate_kind) DO UPDATE SET \
                   deployment_id=excluded.deployment_id,cursor=excluded.cursor, \
                   last_hash=excluded.last_hash,imported_count=excluded.imported_count, \
                   status=excluded.status,provenance=excluded.provenance,updated_at=excluded.updated_at",
                &[
                    &bundle_id,
                    &kind,
                    &deployment_id,
                    &progress.cursor,
                    &hash,
                    &count,
                    &progress.status.as_str(),
                    &provenance,
                ],
            )
            .await
            .map_err(|error| write_error("写 intelligence import cursor", error))?;
    }
    Ok(())
}

async fn load_progress_client(
    client: &impl GenericClient,
    bundle_id: &str,
    deployment_id: &str,
    payload_sha256: &str,
) -> Result<Option<IntelligenceImportProgress>, IntelligenceImportError> {
    let rows = client
        .query(
            "SELECT aggregate_kind,deployment_id,cursor,last_hash,imported_count,status,provenance \
             FROM public.intelligence_import_cursors WHERE bundle_id=$1 ORDER BY aggregate_kind",
            &[&bundle_id],
        )
        .await
        .map_err(|error| unavailable("读取 intelligence import cursors", error))?;
    decode_progress(rows, deployment_id, payload_sha256)
}

async fn load_progress_transaction(
    transaction: &Transaction<'_>,
    bundle_id: &str,
    deployment_id: &str,
    payload_sha256: &str,
) -> Result<Option<IntelligenceImportProgress>, IntelligenceImportError> {
    let rows = transaction
        .query(
            "SELECT aggregate_kind,deployment_id,cursor,last_hash,imported_count,status,provenance \
             FROM public.intelligence_import_cursors WHERE bundle_id=$1 \
             ORDER BY aggregate_kind FOR UPDATE",
            &[&bundle_id],
        )
        .await
        .map_err(|error| unavailable("锁定 intelligence import cursors", error))?;
    decode_progress(rows, deployment_id, payload_sha256)
}

fn decode_progress(
    rows: Vec<Row>,
    deployment_id: &str,
    payload_sha256: &str,
) -> Result<Option<IntelligenceImportProgress>, IntelligenceImportError> {
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() != intelligence_import_kinds().len() {
        return Err(IntelligenceImportError::Corrupt {
            field: "cursor_set",
        });
    }
    let mut values = BTreeMap::new();
    let mut cursor = None;
    let mut status = None;
    for row in rows {
        if decode::<String>(&row, "deployment_id")? != deployment_id {
            return Err(IntelligenceImportError::Conflict {
                field: "cursor_deployment",
            });
        }
        let provenance: Value = decode(&row, "provenance")?;
        if provenance.get("payloadSha256").and_then(Value::as_str) != Some(payload_sha256) {
            return Err(IntelligenceImportError::Conflict {
                field: "cursor_bundle_hash",
            });
        }
        let row_cursor: String = decode(&row, "cursor")?;
        let row_status: String = decode(&row, "status")?;
        if cursor.get_or_insert(row_cursor.clone()) != &row_cursor
            || status.get_or_insert(row_status.clone()) != &row_status
        {
            return Err(IntelligenceImportError::Corrupt {
                field: "cursor_sync",
            });
        }
        let kind: String = decode(&row, "aggregate_kind")?;
        let count = sequence_u64(decode(&row, "imported_count")?, "imported_count")?;
        let hash: String = decode(&row, "last_hash")?;
        validate_hash(&hash)?;
        if values.insert(kind, (count, hash)).is_some() {
            return Err(IntelligenceImportError::Corrupt {
                field: "cursor_kind",
            });
        }
    }
    let status = parse_cursor_status(status.as_deref().expect("rows nonempty"))?;
    let (thread_count, thread_hash) = take_kind(&mut values, "thread")?;
    let (message_count, message_hash) = take_kind(&mut values, "message")?;
    let (event_count, event_hash) = take_kind(&mut values, "run_event")?;
    let (memory_count, memory_hash) = take_kind(&mut values, "memory")?;
    if !values.is_empty() {
        return Err(IntelligenceImportError::Corrupt {
            field: "cursor_kind",
        });
    }
    Ok(Some(IntelligenceImportProgress {
        cursor: cursor.expect("rows nonempty"),
        thread_count,
        message_count,
        event_count,
        memory_count,
        thread_hash,
        message_hash,
        event_hash,
        memory_hash,
        status,
    }))
}

fn take_kind(
    values: &mut BTreeMap<String, (u64, String)>,
    kind: &'static str,
) -> Result<(u64, String), IntelligenceImportError> {
    values.remove(kind).ok_or(IntelligenceImportError::Corrupt {
        field: "cursor_kind",
    })
}

async fn lock_bundle(
    transaction: &Transaction<'_>,
    bundle_id: &str,
) -> Result<(), IntelligenceImportError> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&bundle_id],
        )
        .await
        .map(|_| ())
        .map_err(|error| unavailable("锁定 intelligence bundle", error))
}

fn empty_progress() -> IntelligenceImportProgress {
    let empty = format!("{:x}", Sha256::digest([]));
    IntelligenceImportProgress {
        cursor: "$none".to_owned(),
        thread_count: 0,
        message_count: 0,
        event_count: 0,
        memory_count: 0,
        thread_hash: empty.clone(),
        message_hash: empty.clone(),
        event_hash: empty.clone(),
        memory_hash: empty,
        status: IntelligenceImportCursorStatus::Running,
    }
}

fn same_progress_ignoring_status(
    left: &IntelligenceImportProgress,
    right: &IntelligenceImportProgress,
) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.status = IntelligenceImportCursorStatus::Running;
    right.status = IntelligenceImportCursorStatus::Running;
    left == right
}

fn empty_checksum() -> IntelligenceThreadChecksum {
    let empty = format!("{:x}", Sha256::digest([]));
    IntelligenceThreadChecksum {
        projection_hash: empty.clone(),
        message_count: 0,
        message_hash: empty.clone(),
        event_count: 0,
        event_hash: empty.clone(),
        terminal_state_hash: empty.clone(),
        memory_count: 0,
        memory_hash: empty.clone(),
        sample_render_hash: empty,
    }
}

fn thread_status(status: IntelligenceThreadStatus) -> &'static str {
    match status {
        IntelligenceThreadStatus::Active => "active",
        IntelligenceThreadStatus::Archived => "archived",
        IntelligenceThreadStatus::Deleted => "deleted",
    }
}

fn event_kind(kind: ThreadRunEventKind) -> &'static str {
    match kind {
        ThreadRunEventKind::Started => "started",
        ThreadRunEventKind::SemanticChunk => "semantic_chunk",
        ThreadRunEventKind::Checkpoint => "checkpoint",
        ThreadRunEventKind::Completed => "completed",
        ThreadRunEventKind::Failed => "failed",
        ThreadRunEventKind::Cancelled => "cancelled",
        ThreadRunEventKind::ReconciliationRequired => "reconciliation_required",
    }
}

fn memory_kind(kind: MemoryKind) -> &'static str {
    match kind {
        MemoryKind::Preference => "preference",
        MemoryKind::Fact => "fact",
    }
}

fn memory_sensitivity(value: MemorySensitivity) -> &'static str {
    match value {
        MemorySensitivity::Normal => "normal",
        MemorySensitivity::Sensitive => "sensitive",
    }
}

fn parse_message_role(value: &str) -> Result<IntelligenceMessageRole, IntelligenceImportError> {
    match value {
        "user" => Ok(IntelligenceMessageRole::User),
        "assistant" => Ok(IntelligenceMessageRole::Assistant),
        "system" => Ok(IntelligenceMessageRole::System),
        "tool" => Ok(IntelligenceMessageRole::Tool),
        "summary" => Ok(IntelligenceMessageRole::Summary),
        _ => Err(IntelligenceImportError::Corrupt {
            field: "message_role",
        }),
    }
}

fn parse_run_status(value: &str) -> Result<IntelligenceRunStatus, IntelligenceImportError> {
    match value {
        "completed" => Ok(IntelligenceRunStatus::Completed),
        "failed" => Ok(IntelligenceRunStatus::Failed),
        "cancelled" => Ok(IntelligenceRunStatus::Cancelled),
        "reconciliation_required" => Ok(IntelligenceRunStatus::ReconciliationRequired),
        _ => Err(IntelligenceImportError::Corrupt {
            field: "run_status",
        }),
    }
}

fn parse_memory_kind(value: &str) -> Result<MemoryKind, IntelligenceImportError> {
    match value {
        "preference" => Ok(MemoryKind::Preference),
        "fact" => Ok(MemoryKind::Fact),
        _ => Err(IntelligenceImportError::Corrupt {
            field: "memory_kind",
        }),
    }
}

fn parse_memory_sensitivity(value: &str) -> Result<MemorySensitivity, IntelligenceImportError> {
    match value {
        "normal" => Ok(MemorySensitivity::Normal),
        "sensitive" => Ok(MemorySensitivity::Sensitive),
        _ => Err(IntelligenceImportError::Corrupt {
            field: "memory_sensitivity",
        }),
    }
}

fn parse_memory_status(value: &str) -> Result<IntelligenceMemoryStatus, IntelligenceImportError> {
    match value {
        "active" => Ok(IntelligenceMemoryStatus::Active),
        "superseded" => Ok(IntelligenceMemoryStatus::Superseded),
        _ => Err(IntelligenceImportError::Corrupt {
            field: "memory_status",
        }),
    }
}

fn parse_cursor_status(
    value: &str,
) -> Result<IntelligenceImportCursorStatus, IntelligenceImportError> {
    match value {
        "running" => Ok(IntelligenceImportCursorStatus::Running),
        "completed" => Ok(IntelligenceImportCursorStatus::Completed),
        "failed" => Ok(IntelligenceImportCursorStatus::Failed),
        _ => Err(IntelligenceImportError::Corrupt {
            field: "cursor_status",
        }),
    }
}

fn validate_hash(value: &str) -> Result<(), IntelligenceImportError> {
    if value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        Ok(())
    } else {
        Err(IntelligenceImportError::Corrupt {
            field: "cursor_hash",
        })
    }
}

fn import_writer_error(error: crate::db::InfraError) -> IntelligenceImportError {
    if crate::thread_history_writer::is_closed(&error) {
        return IntelligenceImportError::Conflict {
            field: "thread_history_closed",
        };
    }
    tracing::warn!(error=%error,"Import history writer admission failed");
    match error {
        crate::db::InfraError::Connect { .. } | crate::db::InfraError::Query { .. } => {
            IntelligenceImportError::Unavailable
        }
        _ => IntelligenceImportError::Corrupt {
            field: "thread_history_writer",
        },
    }
}

fn import_origin_error(error: crate::db::InfraError) -> IntelligenceImportError {
    tracing::warn!(error = %error, "import historical origin verification failed");
    match error {
        crate::db::InfraError::Connect { .. } | crate::db::InfraError::Query { .. } => {
            IntelligenceImportError::Unavailable
        }
        _ => IntelligenceImportError::Corrupt {
            field: "thread_origin",
        },
    }
}

fn i64_count(value: usize, field: &'static str) -> Result<i64, IntelligenceImportError> {
    i64::try_from(value).map_err(|_| IntelligenceImportError::Invalid { field })
}

fn sequence_i64(value: u64, field: &'static str) -> Result<i64, IntelligenceImportError> {
    i64::try_from(value).map_err(|_| IntelligenceImportError::Invalid { field })
}

fn sequence_u64(value: i64, field: &'static str) -> Result<u64, IntelligenceImportError> {
    u64::try_from(value).map_err(|_| IntelligenceImportError::Corrupt { field })
}

async fn finish_transaction<T>(
    transaction: deadpool_postgres::Transaction<'_>,
    result: Result<T, IntelligenceImportError>,
) -> Result<T, IntelligenceImportError> {
    match result {
        Ok(value) => {
            transaction.commit().await.map_err(|error| {
                tracing::error!(error = %error, "intelligence import commit 结果未知");
                IntelligenceImportError::CommitUnknown
            })?;
            Ok(value)
        }
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
}

fn decode<T>(row: &Row, column: &'static str) -> Result<T, IntelligenceImportError>
where
    T: tokio_postgres::types::FromSqlOwned,
{
    row.try_get(column)
        .map_err(|_| IntelligenceImportError::Corrupt { field: column })
}

fn unavailable(context: &'static str, error: tokio_postgres::Error) -> IntelligenceImportError {
    tracing::error!(
        sqlstate = error.code().map_or("none", SqlState::code),
        connection_closed = error.is_closed(),
        context,
        "intelligence import database operation failed"
    );
    IntelligenceImportError::Unavailable
}

fn write_error(context: &'static str, error: tokio_postgres::Error) -> IntelligenceImportError {
    if crate::thread_history_writer::is_closed_query(&error) {
        return IntelligenceImportError::Conflict {
            field: "thread_history_closed",
        };
    }
    tracing::error!(
        sqlstate = error.code().map_or("none", SqlState::code),
        connection_closed = error.is_closed(),
        context,
        "intelligence import write failed"
    );
    match error.code() {
        Some(code) if code == &SqlState::UNIQUE_VIOLATION => {
            IntelligenceImportError::Conflict { field: "unique" }
        }
        Some(code) if code == &SqlState::FOREIGN_KEY_VIOLATION => {
            IntelligenceImportError::Invalid {
                field: "target_mapping",
            }
        }
        _ => IntelligenceImportError::Unavailable,
    }
}
