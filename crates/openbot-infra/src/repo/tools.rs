//! durable tool decision / attempt repositories（v3 §8.1）。
//!
//! [`ToolCallRepo::record_first_decision`] 是持久化半边的关键入口：call 与 first attempt 在同一
//! PostgreSQL 事务写入，**commit 成功之后**才构造 `DurableDecisionReceipt`。写任一行失败都
//! 没有 receipt，类型状态机就拿不到 capability。`ToolAttemptRepo` 再以条件 UPDATE 承担
//! decision_recorded → executing → completed/reconciliation_required，状态竞争返回 `None`，不会
//! 覆盖另一执行者的结果。

use core::time::Duration;

use crate::db::pool::DatabasePool as Pool;
use async_trait::async_trait;
use openbot_application::{
    ToolDecisionDraft, ToolJournal, ToolOutcomeDraft, ToolPortError, ToolRefusalDraft,
};
use openbot_contracts::ids::{AttemptId, CapabilityId, PolicyDecisionId, ToolCallId};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditIdentifier, AuditLabel};
use openbot_domain::tool::commit::CommitState;
use openbot_domain::tool::pipeline::DurableDecisionReceipt;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::InfraError;
use crate::db::tables::{tool_attempts, tool_calls};
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::repo::common::{RepoCore, columns_sql, insert_sql};
use crate::thread_history_writer::CurrentWriterSchema;

mod fence;

/// 首次 decision 事务的两行输入。
#[derive(Clone, Debug, PartialEq)]
pub struct FirstDurableDecision {
    /// call/decision 行。
    pub call: tool_calls::Row,
    /// Durable approval row linked into the call decision.
    pub approval_id: Option<String>,
    /// 与它同事务写入的 attempt #0。
    pub attempt: tool_attempts::Row,
}

/// 一次已经发生的执行要写入 attempt 的无内容结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedToolOutcome {
    /// 提交状态。
    pub commit_state: CommitState,
    /// 输出字节数，不含输出内容。
    pub output_bytes: u32,
    /// 执行耗时。
    pub duration: Duration,
    /// 稳定错误码，不是错误文案。
    pub error_code: Option<&'static str>,
    /// 完成时刻。
    pub finished_at: OffsetDateTime,
}

/// durable tool call repository。
#[derive(Clone)]
pub struct ToolCallRepo {
    pool: Pool,
    core: RepoCore<tool_calls::Row>,
}

impl ToolCallRepo {
    /// 用调用方提供的池构造。
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self {
            core: RepoCore::new(pool.clone()),
            pool,
        }
    }

    /// 同事务写 call + attempt，commit 后签发领域回执。
    pub async fn record_first_decision(
        &self,
        decision: &FirstDurableDecision,
    ) -> Result<DurableDecisionReceipt, InfraError> {
        validate_first_decision(decision)?;
        let decision_id = decision.call.decision_id.clone();
        let attempt_id = decision.attempt.attempt_id.clone();

        let mut client = self.pool.get().await.map_err(|source| {
            InfraError::connect("为 ToolCallRepo 获取 decision 事务连接", source)
        })?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|source| InfraError::query("开始 durable tool decision 事务", source))?;
        fence::initialize(&transaction).await?;
        // One schema observation before the first row lock; a closed Thread history refuses
        // this new decision after the Run lock.
        let schema = CurrentWriterSchema::observe(&transaction).await?;
        fence::decision(&transaction, &schema, &decision.call).await?;

        let call_params = decision.call.as_sql_params();
        transaction
            .query_one(&insert_sql::<tool_calls::Row>(), &call_params)
            .await
            .map_err(|source| InfraError::query("写 durable tool call", source))?;
        if let Some(approval_id) = &decision.approval_id {
            let linked = transaction
                .execute(
                    "UPDATE public.tool_calls tc SET approval_id=$2
                      WHERE tc.tool_call_id=$1 AND EXISTS(
                        SELECT 1 FROM public.tool_approvals a
                         WHERE a.approval_id=$2 AND a.state='granted'
                           AND a.expires_at>clock_timestamp()
                           AND a.actor_id=tc.actor_id AND a.bot_id=tc.bot_id
                           AND a.run_id=tc.run_id AND a.tool_name=tc.tool_name
                           AND a.args_hash=tc.args_hash AND a.target_kind=tc.target_kind
                           AND a.target_id=tc.target_id
                           AND a.effect=tc.effect AND a.approval_class=tc.approval_class
                           AND a.catalog_generation=tc.catalog_generation
                           AND a.policy_version=tc.policy_version)",
                    &[&decision.call.tool_call_id, &approval_id],
                )
                .await
                .map_err(|source| InfraError::query("绑定 durable tool approval", source))?;
            if linked != 1 {
                return Err(InfraError::repository_invariant(
                    "tool_approval_binding_not_current",
                ));
            }
        }
        let attempt_params = decision.attempt.as_sql_params();
        transaction
            .query_one(&insert_sql::<tool_attempts::Row>(), &attempt_params)
            .await
            .map_err(|source| InfraError::query("写 durable tool attempt", source))?;

        transaction
            .commit()
            .await
            .map_err(|source| InfraError::query("提交 durable tool decision", source))?;

        Ok(DurableDecisionReceipt::issued_by_repository(
            PolicyDecisionId::new(decision_id),
            AttemptId::new(attempt_id),
        ))
    }

    /// 按 call id 读取。
    pub async fn find_by_id(&self, id: &str) -> Result<Option<tool_calls::Row>, InfraError> {
        self.core.find("\"tool_call_id\" = $1", &[&id]).await
    }

    /// 按 `(run_id, call_seq)` 稳定列出。
    pub async fn list_all(&self) -> Result<Vec<tool_calls::Row>, InfraError> {
        self.core.list("\"run_id\", \"call_seq\"").await
    }
}

impl core::fmt::Debug for ToolCallRepo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ToolCallRepo").finish_non_exhaustive()
    }
}

/// tool attempt 状态机的持久化适配器。
#[derive(Clone)]
pub struct ToolAttemptRepo {
    core: RepoCore<tool_attempts::Row>,
}

impl ToolAttemptRepo {
    /// 用调用方提供的池构造。
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self {
            core: RepoCore::new(pool),
        }
    }

    /// 记录一次重试 attempt；必须仍是未铸 capability 的 `decision_recorded` 初态。
    pub async fn insert_retry(
        &self,
        attempt: &tool_attempts::Row,
    ) -> Result<tool_attempts::Row, InfraError> {
        validate_pristine_attempt(attempt)?;
        let mut client = self.core.pool().get().await.map_err(|source| {
            InfraError::connect("为 ToolAttemptRepo 写 retry 获取连接", source)
        })?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|error| InfraError::query("开始 tool retry 事务", error))?;
        fence::initialize(&transaction).await?;
        let schema = CurrentWriterSchema::observe(&transaction).await?;
        fence::call_for_new_work(&transaction, &schema, &attempt.tool_call_id).await?;
        let params = attempt.as_sql_params();
        let row = transaction
            .query_one(&insert_sql::<tool_attempts::Row>(), &params)
            .await
            .map_err(|error| InfraError::query("写 durable retry attempt", error))?;
        let row = tool_attempts::Row::try_from(&row)?;
        transaction
            .commit()
            .await
            .map_err(|error| InfraError::query("提交 tool retry 事务", error))?;
        Ok(row)
    }

    /// 按复合主键读取。
    pub async fn find_by_key(
        &self,
        tool_call_id: &str,
        attempt_seq: i64,
    ) -> Result<Option<tool_attempts::Row>, InfraError> {
        self.core
            .find(
                "\"tool_call_id\" = $1 AND \"attempt_seq\" = $2",
                &[&tool_call_id, &attempt_seq],
            )
            .await
    }

    /// 按 call/sequence 稳定列出。
    pub async fn list_all(&self) -> Result<Vec<tool_attempts::Row>, InfraError> {
        self.core.list("\"tool_call_id\", \"attempt_seq\"").await
    }

    /// 把单次 capability 绑定到已 durable attempt，并进入 executing。
    pub async fn attach_capability(
        &self,
        tool_call_id: &str,
        attempt_seq: i64,
        capability_id: &str,
        started_at: OffsetDateTime,
    ) -> Result<Option<tool_attempts::Row>, InfraError> {
        if capability_id.is_empty() {
            return Err(InfraError::repository_invariant("capability_id_empty"));
        }
        let sql = format!(
            "UPDATE public.tool_attempts \
             SET capability_id=$3, status='executing', started_at=$4 \
             WHERE tool_call_id=$1 AND attempt_seq=$2 \
               AND status='decision_recorded' AND capability_id IS NULL \
             RETURNING {}",
            columns_sql::<tool_attempts::Row>(),
        );
        let mut client = self.core.pool().get().await.map_err(|source| {
            InfraError::connect("为 ToolAttemptRepo 绑定 capability 获取连接", source)
        })?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|error| InfraError::query("开始 tool capability 事务", error))?;
        fence::initialize(&transaction).await?;
        let schema = CurrentWriterSchema::observe(&transaction).await?;
        fence::call_for_new_work(&transaction, &schema, tool_call_id).await?;
        if fence::attempt_sequence(&transaction, tool_call_id, attempt_seq)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let row = transaction
            .query_opt(
                &sql,
                &[&tool_call_id, &attempt_seq, &capability_id, &started_at],
            )
            .await
            .map_err(|source| InfraError::query("绑定 tool capability", source))?;
        let result = row.as_ref().map(tool_attempts::Row::try_from).transpose()?;
        transaction
            .commit()
            .await
            .map_err(|error| InfraError::query("提交 tool capability 事务", error))?;
        Ok(result)
    }

    /// 记录执行 outcome；capability 必须与 executing 行逐字相等。
    pub async fn record_outcome(
        &self,
        tool_call_id: &str,
        attempt_seq: i64,
        capability_id: &str,
        outcome: &PersistedToolOutcome,
    ) -> Result<Option<tool_attempts::Row>, InfraError> {
        let mut client = self.core.pool().get().await.map_err(|source| {
            InfraError::connect("为 ToolAttemptRepo 写 outcome 获取连接", source)
        })?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|error| InfraError::query("开始低层 tool outcome 事务", error))?;
        fence::initialize(&transaction).await?;
        let call = fence::call(&transaction, tool_call_id).await?;
        if call.call.tool_name == "remember" {
            return Err(fence::conflict());
        }
        if fence::attempt_sequence(&transaction, tool_call_id, attempt_seq)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let result = record_outcome_on(
            &transaction,
            tool_call_id,
            attempt_seq,
            capability_id,
            outcome,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| InfraError::query("提交低层 tool outcome 事务", error))?;
        Ok(result)
    }
}

impl core::fmt::Debug for ToolAttemptRepo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ToolAttemptRepo").finish_non_exhaustive()
    }
}

/// §8.1 application tool journal 的 PostgreSQL 实现。
#[derive(Clone)]
pub struct PostgresToolJournal {
    pool: Pool,
    checkpoint_key: std::sync::Arc<[u8]>,
}

impl PostgresToolJournal {
    /// 构造；空 checkpoint key 会让 acting outcome 无法进入 audit，直接拒绝。
    pub fn new(pool: Pool, checkpoint_key: impl Into<Vec<u8>>) -> Result<Self, InfraError> {
        let checkpoint_key = checkpoint_key.into();
        if checkpoint_key.is_empty() {
            return Err(InfraError::repository_invariant(
                "audit_checkpoint_key_empty",
            ));
        }
        Ok(Self {
            pool,
            checkpoint_key: checkpoint_key.into(),
        })
    }
}

impl core::fmt::Debug for PostgresToolJournal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresToolJournal")
            .field("checkpoint_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ToolJournal for PostgresToolJournal {
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        let payload = draft.audit_payload().map_err(|_| ToolPortError::Corrupt {
            field: "audit_payload",
        })?;
        let mut client = self.pool.get().await.map_err(pool_port_error)?;
        let transaction = client.transaction().await.map_err(|error| {
            infra_port_error(InfraError::query("开始 tool refusal audit 事务", error))
        })?;
        append_tool_audit(
            &transaction,
            &draft.decision,
            refusal_event_type(draft.decision.target.kind),
            payload,
            &self.checkpoint_key,
        )
        .await
        .map_err(infra_port_error)?;
        transaction
            .commit()
            .await
            .map_err(|error| infra_port_error(InfraError::query("提交 tool refusal audit", error)))
    }

    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        if draft.metadata.approval_class.requires_human_approval() != draft.approval_id.is_some() {
            return Err(ToolPortError::Corrupt {
                field: "approval_id",
            });
        }
        let decision = first_decision_rows(draft).map_err(infra_port_error)?;
        ToolCallRepo::new(self.pool.clone())
            .record_first_decision(&decision)
            .await
            .map_err(|error| match error {
                InfraError::RepositoryInvariant {
                    code: "tool_approval_binding_not_current",
                } => ToolPortError::Conflict,
                error => journal_write_error(error),
            })
    }

    async fn attach_capability(
        &self,
        call_id: &ToolCallId,
        capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        let row = ToolAttemptRepo::new(self.pool.clone())
            .attach_capability(
                call_id.as_str(),
                0,
                capability.as_str(),
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(journal_write_error)?;
        row.map(|_| ()).ok_or(ToolPortError::Conflict)
    }

    async fn record_outcome(&self, draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        let payload = draft.audit_payload().map_err(|_| ToolPortError::Corrupt {
            field: "audit_payload",
        })?;
        let persisted = PersistedToolOutcome {
            commit_state: draft.outcome.commit_state,
            output_bytes: draft.outcome.output_bytes,
            duration: draft.outcome.duration,
            error_code: draft.outcome.error_code,
            finished_at: OffsetDateTime::now_utc(),
        };
        let mut client = self.pool.get().await.map_err(pool_port_error)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|error| {
                infra_port_error(InfraError::query("开始 tool outcome/audit 事务", error))
            })?;
        let remember = draft.decision.metadata.name.as_str() == "remember";
        let attempt_seq = if remember {
            // This guard's first statement sets lock_timeout. Never acquire a run lock before
            // entering its actor-first producer-compatible lock order.
            crate::memory_admin::remember_effect::guard_outcome(&transaction, draft).await?
        } else {
            fence::initialize(&transaction)
                .await
                .map_err(journal_write_error)?;
            fence::outcome(&transaction, draft)
                .await
                .map_err(journal_write_error)?
        };
        let map_write_error: fn(InfraError) -> ToolPortError = if remember {
            infra_port_error
        } else {
            journal_write_error
        };
        let row = record_outcome_on(
            &transaction,
            draft.decision.call_id.as_str(),
            attempt_seq,
            draft.capability_id.as_str(),
            &persisted,
        )
        .await
        .map_err(map_write_error)?;
        if row.is_none() {
            return Err(ToolPortError::Conflict);
        }
        append_tool_audit(
            &transaction,
            &draft.decision,
            outcome_event_type(draft),
            payload,
            &self.checkpoint_key,
        )
        .await
        .map_err(|error| {
            if remember {
                infra_port_error(error)
            } else {
                tracing::error!(error = %error, "generic tool outcome audit 失败");
                ToolPortError::Unavailable {
                    dependency: "database",
                }
            }
        })?;
        transaction
            .commit()
            .await
            .map_err(|error| infra_port_error(InfraError::query("提交 tool outcome/audit", error)))
    }
}

fn first_decision_rows(draft: &ToolDecisionDraft) -> Result<FirstDurableDecision, InfraError> {
    let call_seq = i64::try_from(draft.call_seq)
        .map_err(|_| InfraError::repository_invariant("tool_call_sequence_overflow"))?;
    let catalog_generation = i64::try_from(draft.metadata.catalog_generation.get())
        .map_err(|_| InfraError::repository_invariant("catalog_generation_overflow"))?;
    let now = OffsetDateTime::now_utc();
    Ok(FirstDurableDecision {
        call: tool_calls::Row {
            tool_call_id: draft.call_id.as_str().to_owned(),
            run_id: draft.run_id.as_str().to_owned(),
            call_seq,
            decision_id: Uuid::now_v7().to_string(),
            actor_id: draft.actor.as_str().to_owned(),
            bot_id: draft.bot.as_str().to_owned(),
            tool_name: draft.metadata.name.as_str().to_owned(),
            schema_hash: draft.metadata.schema_hash.to_hex(),
            catalog_generation,
            args_hash: draft.args_hash.to_hex(),
            target_kind: draft.target.kind.to_owned(),
            target_id: draft.target.id.clone(),
            effect: draft.metadata.effect.effect().as_str().to_owned(),
            effect_downgraded: draft.metadata.effect.was_downgraded(),
            idempotency: draft.metadata.idempotency.as_str().to_owned(),
            idempotency_key: draft
                .idempotency_key
                .as_ref()
                .map(|key| key.as_str().to_owned()),
            approval_class: draft.metadata.approval_class.as_str().to_owned(),
            policy_version: draft.policy_version.as_str().to_owned(),
            decided_at: now,
        },
        approval_id: draft.approval_id.clone(),
        attempt: tool_attempts::Row {
            tool_call_id: draft.call_id.as_str().to_owned(),
            attempt_seq: 0,
            attempt_id: Uuid::now_v7().to_string(),
            capability_id: None,
            status: "decision_recorded".to_owned(),
            commit_state: None,
            output_bytes: None,
            duration_ms: None,
            error_code: None,
            started_at: None,
            finished_at: None,
            created_at: now,
        },
    })
}

async fn record_outcome_on(
    client: &tokio_postgres::Transaction<'_>,
    tool_call_id: &str,
    attempt_seq: i64,
    capability_id: &str,
    outcome: &PersistedToolOutcome,
) -> Result<Option<tool_attempts::Row>, InfraError> {
    let duration_ms = i64::try_from(outcome.duration.as_millis())
        .map_err(|_| InfraError::repository_invariant("tool_duration_overflow"))?;
    let output_bytes = i64::from(outcome.output_bytes);
    let status = if outcome.commit_state.requires_reconciliation() {
        "reconciliation_required"
    } else {
        "completed"
    };
    let commit_state = outcome.commit_state.as_str();
    let sql = format!(
        "UPDATE public.tool_attempts \
         SET status=$4, commit_state=$5, output_bytes=$6, duration_ms=$7, \
             error_code=$8, finished_at=$9 \
         WHERE tool_call_id=$1 AND attempt_seq=$2 \
           AND capability_id=$3 AND status='executing' \
         RETURNING {}",
        columns_sql::<tool_attempts::Row>(),
    );
    let row = client
        .query_opt(
            &sql,
            &[
                &tool_call_id,
                &attempt_seq,
                &capability_id,
                &status,
                &commit_state,
                &output_bytes,
                &duration_ms,
                &outcome.error_code,
                &outcome.finished_at,
            ],
        )
        .await
        .map_err(|source| InfraError::query("记录 tool outcome", source))?;
    row.as_ref()
        .map(tool_attempts::Row::try_from)
        .transpose()
        .map_err(Into::into)
}

async fn append_tool_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    decision: &ToolDecisionDraft,
    event_type: AuditEventType,
    payload: openbot_domain::audit::payload::AuditPayload,
    checkpoint_key: &[u8],
) -> Result<(), InfraError> {
    let (id, created_at) = next_event_coordinates(transaction).await?;
    let target = AuditIdentifier::new(decision.target.id.as_str())
        .map_err(|_| InfraError::repository_invariant("tool_target_not_audit_identifier"))?;
    let event = AuditEvent {
        id,
        actor: Some(decision.actor.clone()),
        event_type,
        target_kind: AuditLabel::new(decision.target.kind),
        target_id: Some(target),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
}

fn refusal_event_type(target_kind: &str) -> AuditEventType {
    if target_kind.starts_with("mcp") {
        AuditEventType::MCP_CALL_REJECTED
    } else if target_kind.starts_with("memory") {
        AuditEventType::MEMORY_REMEMBER_REFUSED
    } else {
        AuditEventType::COMPUTER_ACTION_REFUSED
    }
}

fn outcome_event_type(draft: &ToolOutcomeDraft) -> AuditEventType {
    let succeeded =
        draft.outcome.error_code.is_none() && draft.outcome.commit_state == CommitState::Committed;
    if draft.decision.target.kind.starts_with("mcp") {
        if succeeded {
            AuditEventType::MCP_CALL_SUCCEEDED
        } else {
            AuditEventType::MCP_CALL_FAILED
        }
    } else if draft.decision.target.kind.starts_with("memory") && succeeded {
        AuditEventType::MEMORY_REMEMBER_SUCCEEDED
    } else if draft.decision.target.kind.starts_with("memory") {
        AuditEventType::MEMORY_REMEMBER_FAILED
    } else if succeeded {
        AuditEventType::COMPUTER_ACTION_ALLOWED
    } else {
        AuditEventType::COMPUTER_ACTION_FAILED
    }
}

fn pool_port_error(error: crate::db::pool::PoolError) -> ToolPortError {
    tracing::error!(error = %error, "tool journal 获取连接失败");
    ToolPortError::Unavailable {
        dependency: "database",
    }
}

fn infra_port_error(error: InfraError) -> ToolPortError {
    tracing::error!(error = %error, "tool journal 失败");
    match error {
        InfraError::RowDecode(_) | InfraError::RepositoryInvariant { .. } => {
            ToolPortError::Corrupt {
                field: "tool_journal",
            }
        }
        InfraError::Connect { .. }
        | InfraError::Query { .. }
        | InfraError::IncompatibleDatabase(_)
        | InfraError::NativeMigration(_) => ToolPortError::Unavailable {
            dependency: "database",
        },
    }
}

// Only these write-site conflicts are expected. Audit errors continue through infra_port_error;
// sharing this mapper with audit would incorrectly classify an unrelated unique violation.
fn journal_write_error(error: InfraError) -> ToolPortError {
    let expected = match &error {
        InfraError::RepositoryInvariant { code } => *code == fence::CONFLICT,
        InfraError::Query { source, .. } => {
            source.sqlstate() == Some("23505")
                && matches!(
                    source.constraint(),
                    Some(
                        "tool_calls_pkey"
                            | "tool_calls_run_call_seq_key"
                            | "tool_calls_decision_id_key"
                            | "tool_attempts_pkey"
                            | "tool_attempts_attempt_id_key"
                            | "tool_attempts_capability_id_key"
                    )
                )
        }
        _ => false,
    };
    if expected {
        ToolPortError::Conflict
    } else {
        infra_port_error(error)
    }
}

fn validate_first_decision(decision: &FirstDurableDecision) -> Result<(), InfraError> {
    if decision.attempt.tool_call_id != decision.call.tool_call_id {
        return Err(InfraError::repository_invariant("attempt_call_id_mismatch"));
    }
    if decision.attempt.attempt_seq != 0 {
        return Err(InfraError::repository_invariant(
            "first_attempt_sequence_not_zero",
        ));
    }
    validate_pristine_attempt(&decision.attempt)
}

fn validate_pristine_attempt(attempt: &tool_attempts::Row) -> Result<(), InfraError> {
    if attempt.status != "decision_recorded"
        || attempt.capability_id.is_some()
        || attempt.commit_state.is_some()
        || attempt.output_bytes.is_some()
        || attempt.duration_ms.is_some()
        || attempt.error_code.is_some()
        || attempt.started_at.is_some()
        || attempt.finished_at.is_some()
    {
        return Err(InfraError::repository_invariant(
            "attempt_not_pristine_decision_record",
        ));
    }
    Ok(())
}
