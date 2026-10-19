//! Native PostgreSQL thread runtime；最终请求路径不读、不写、不连接 Intelligence。

use core::pin::Pin;
use core::task::{Context, Poll};
use std::future::poll_fn;

use async_trait::async_trait;
use futures_core::Stream;
use openbot_application::{
    AppEventStream, BeginThreadRunRequest, BeginThreadRunV2Request, CancelThreadRunRequest,
    ChannelActivitySubscription, RunInputArtifactMaterial, ThreadConversationRequest,
    ThreadDirectory, ThreadDirectoryError, ThreadEventSubscription, ThreadHistoryRequest,
};
use openbot_contracts::command::{
    AppEvent, ChannelActivityEvent, ThreadConversationSnapshot, ThreadForegroundRunState,
    ThreadHistory, ThreadHistoryMessage, ThreadHistoryRole, ThreadRunAnchor, ThreadRunCancellation,
    ThreadRunCancellationState, ThreadRunEvent, ThreadRunEventKind, ThreadRunStarted,
};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId, ThreadId};
use openbot_domain::run::{Run, RunEvent, RunEventKind};
use openbot_domain::thread::{FencingToken, Message, MessageId, MessageRole};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tokio::sync::{mpsc, watch};
use tokio_postgres::error::SqlState;
use tokio_postgres::{AsyncMessage, Client, Connection, NoTls, Socket, Transaction};

use crate::db::{InfraError, occupancy};
use crate::run_runtime::{
    RUN_CANCEL_DESTINATION, RUN_CONTROL_TOPIC, RunCancelAcceptance, run_cancel_acceptance,
    run_cancel_outbox_id, thread_history_closed_by_sql,
};
use crate::thread_id::mint_thread_id;
use crate::thread_listener::ThreadListenerDatabase;

pub(crate) mod artifact_refs;
mod effect_receipts;
mod reconciliation;
pub(crate) mod reconciliation_visibility;
mod skills;

/// foreground writer lease 的新增默认值；每 30 秒失效，后续 runtime 必须在 10 秒内续租。
///
/// 这不是上游 parity 常量。它只决定 failover/fencing 窗口，不是 run deadline；绝不能拿它
/// 代替 §7.2 的 `OPENBOT_RUN_DEADLINE_MS`。
pub const DEFAULT_THREAD_LEASE_DURATION: Duration = Duration::seconds(30);
const THREAD_EVENT_TOPIC: &str = "openbot_thread_events";
const THREAD_EVENT_BATCH: i64 = 256;
const THREAD_EVENT_CHANNEL_CAPACITY: usize = 256;
const THREAD_RECONNECT_DELAY: core::time::Duration = core::time::Duration::from_millis(100);
const THREAD_CATCH_UP_PERIOD: core::time::Duration = core::time::Duration::from_secs(1);
const CUSTOM_MODEL_V2_ACCEPT_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(5);
const V2_REPLAY_VERIFIED: u8 = 1;
const V2_COMMIT_ENTERED: u8 = 2;

#[derive(Default)]
struct V2BeginProgress {
    stage: std::sync::atomic::AtomicU8,
    failure: std::sync::Mutex<Option<ThreadDirectoryError>>,
}

fn map_dataset_error(error: crate::model_dataset::ModelDatasetError) -> ThreadDirectoryError {
    match error {
        crate::model_dataset::ModelDatasetError::InvalidBinding => ThreadDirectoryError::Corrupt {
            field: "model_dataset_binding",
        },
        crate::model_dataset::ModelDatasetError::Unavailable => ThreadDirectoryError::Unavailable,
    }
}
fn map_v2_begin_error(error: crate::db::pool::TransactionOwnerError) -> ThreadDirectoryError {
    use crate::db::pool::TransactionOwnerError as E;
    match error {
        E::AlreadyStarted => ThreadDirectoryError::Corrupt {
            field: "model_dataset_transaction",
        },
        E::DeadlineExceeded
        | E::BeginUnavailable
        | E::RollbackUnproven
        | E::RollbackAcknowledgedAfterDeadline => ThreadDirectoryError::Unavailable,
        E::CommitUnknown => ThreadDirectoryError::CommitUnknown,
        E::CommitAcknowledgedAfterDeadline => ThreadDirectoryError::AcknowledgedAfterDeadline,
    }
}
fn map_v2_commit_end_error(error: crate::db::pool::TransactionOwnerError) -> ThreadDirectoryError {
    tracing::warn!(state=?error,"custom v2 original commit end state");
    map_v2_begin_error(error)
}
fn map_v2_replay_end_error(error: crate::db::pool::TransactionOwnerError) -> ThreadDirectoryError {
    use crate::db::pool::TransactionOwnerError as E;
    tracing::warn!(state=?error,"custom v2 original replay end state");
    match error {
        E::AlreadyStarted => ThreadDirectoryError::Corrupt {
            field: "model_dataset_transaction",
        },
        E::RollbackAcknowledgedAfterDeadline => ThreadDirectoryError::AcknowledgedAfterDeadline,
        E::DeadlineExceeded
        | E::BeginUnavailable
        | E::RollbackUnproven
        | E::CommitUnknown
        | E::CommitAcknowledgedAfterDeadline => ThreadDirectoryError::ReplayClosureUnproven,
    }
}

// A miss or refusal cannot be promoted to an accepted/unknown receipt. Only an already
// verified exact receipt retains the original replay-closure/late-ACK reconciliation class.
fn close_replay_observation(
    outcome: Result<Option<ThreadRunStarted>, ThreadDirectoryError>,
    rollback: Result<(), crate::db::pool::TransactionOwnerError>,
    deadline: std::time::Instant,
) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
    let exact_receipt = matches!(&outcome, Ok(Some(_)));
    if let Err(error) = rollback {
        return Err(if exact_receipt {
            map_v2_replay_end_error(error)
        } else {
            map_v2_begin_error(error)
        });
    }
    if std::time::Instant::now() >= deadline {
        return Err(if exact_receipt {
            ThreadDirectoryError::AcknowledgedAfterDeadline
        } else {
            ThreadDirectoryError::Unavailable
        });
    }
    outcome
}

#[derive(Clone)]
struct RuntimeLease {
    database: ThreadListenerDatabase,
    owner_id: String,
    duration: Duration,
}

/// OS CSPRNG issuer + scope-aware PostgreSQL status/transactional append。
#[derive(Clone)]
pub struct PostgresThreadDirectory {
    pool: crate::db::pool::DatabasePool,
    runtime: Option<RuntimeLease>,
    model_dataset_binding:
        Option<std::sync::Arc<crate::model_dataset::PostgresModelDatasetBinding>>,
}

impl PostgresThreadDirectory {
    /// 用共享连接池构造只读/mint 目录；`begin_thread_run` 会 fail-closed。
    #[must_use]
    pub fn new(pool: crate::db::pool::DatabasePool) -> Self {
        Self {
            pool,
            runtime: None,
            model_dataset_binding: None,
        }
    }

    /// 追加当前进程唯一 lease owner，使 transactional append 可用。
    ///
    /// # Errors
    ///
    /// owner 为空或 duration 非正时拒绝构造。
    pub fn with_runtime(
        pool: crate::db::pool::DatabasePool,
        database: impl Into<ThreadListenerDatabase>,
        owner_id: String,
        duration: Duration,
    ) -> Result<Self, ThreadDirectoryError> {
        if owner_id.is_empty() || duration <= Duration::ZERO {
            return Err(ThreadDirectoryError::Corrupt {
                field: "thread_lease_config",
            });
        }
        Ok(Self {
            pool,
            runtime: Some(RuntimeLease {
                database: database.into(),
                owner_id,
                duration,
            }),
            model_dataset_binding: None,
        })
    }

    /// Attach the same original-Pool dataset producer once, before host admission.
    pub fn with_model_dataset_binding(
        mut self,
        binding: std::sync::Arc<crate::model_dataset::PostgresModelDatasetBinding>,
    ) -> Result<Self, ThreadDirectoryError> {
        if self.model_dataset_binding.is_some() || !binding.matches_original_pool(&self.pool) {
            return Err(ThreadDirectoryError::Corrupt {
                field: "model_dataset_binding",
            });
        }
        self.model_dataset_binding = Some(binding);
        Ok(self)
    }

    async fn begin_legacy_with_materials(
        &self,
        request: BeginThreadRunRequest,
        materials: Vec<RunInputArtifactMaterial>,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        artifact_refs::validate_materials(&request.command.artifact_refs, &materials)?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(ThreadDirectoryError::Unavailable)?;
        let mut client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "begin thread run 获取数据库连接失败");
            ThreadDirectoryError::Unavailable
        })?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|error| unavailable("begin thread run 开始事务失败", error))?;
        transaction
            .batch_execute("SET LOCAL lock_timeout='5s'")
            .await
            .map_err(|error| unavailable("begin thread run 设置锁等待限制失败", error))?;
        let outcome = apply_begin(&transaction, runtime, &request, &materials).await;
        match outcome {
            Ok(BeginOutcome::Replayed(receipt)) => {
                if let Err(error) = transaction.rollback().await {
                    tracing::warn!(error = %error, "幂等 replay 只读事务 rollback 失败");
                    if !materials.is_empty() {
                        return Err(ThreadDirectoryError::ReplayClosureUnproven);
                    }
                }
                Ok(receipt)
            }
            Ok(BeginOutcome::Created(receipt)) => {
                transaction.commit().await.map_err(|error| {
                    tracing::error!(error = %error, "begin thread run commit 结果未知");
                    ThreadDirectoryError::CommitUnknown
                })?;
                Ok(receipt)
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::warn!(error = %rollback_error, "begin thread run 失败事务 rollback 未确认");
                    if !materials.is_empty() {
                        return Err(ThreadDirectoryError::Unavailable);
                    }
                }
                Err(error)
            }
        }
    }

    async fn begin_v2_with_materials(
        &self,
        request: BeginThreadRunV2Request,
        materials: Vec<RunInputArtifactMaterial>,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        artifact_refs::validate_materials(&request.command.artifact_refs, &materials)?;
        let deadline = std::time::Instant::now() + CUSTOM_MODEL_V2_ACCEPT_TIMEOUT;
        use openbot_contracts::versioned_model_selection::{
            ModelSelectionIntentSource, VersionedRunModelSelection,
        };
        if request.command.model_selection.source() != ModelSelectionIntentSource::Custom
            || !VersionedRunModelSelection::V2(request.command.model_selection.clone()).is_valid()
        {
            return Err(ThreadDirectoryError::InvalidInput {
                field: "model_selection",
            });
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(ThreadDirectoryError::Unavailable)?;
        let progress = V2BeginProgress::default();
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.begin_v2_guarded(&request, runtime, deadline, &progress, &materials),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                if let Some(error) = progress.failure.lock().ok().and_then(|failure| *failure) {
                    return Err(error);
                }
                Err(
                    match progress.stage.load(std::sync::atomic::Ordering::SeqCst) {
                        V2_REPLAY_VERIFIED => ThreadDirectoryError::ReplayClosureUnproven,
                        V2_COMMIT_ENTERED => ThreadDirectoryError::CommitUnknown,
                        _ => ThreadDirectoryError::Unavailable,
                    },
                )
            }
        }
    }

    async fn observe_legacy_replay_guarded(
        &self,
        request: &BeginThreadRunRequest,
        deadline: std::time::Instant,
        progress: &V2BeginProgress,
    ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| ThreadDirectoryError::Unavailable)?;
        let original = client
            .begin_read_committed()
            .await
            .map_err(map_v2_begin_error)?;
        let outcome = async {
            let transaction = original.as_transaction();
            let remaining = deadline.saturating_duration_since(std::time::Instant::now()).as_millis().max(1).to_string();
            transaction.query_one("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)", &[&remaining])
                .await.map_err(|_| ThreadDirectoryError::Unavailable)?;
    // One same-transaction observation of the strict current schema, before any lock;
    // writer admission and the channel source below consume this proof.
    let _schema = crate::thread_history_writer::CurrentWriterSchema::observe(transaction)
        .await
        .map_err(origin_error)?;
    crate::model_runtime::validate_actor(transaction, request).await?;
    skills::validate_actor(transaction, request).await?;
    let command = &request.command;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&command.thread_id.as_str()],
        )
        .await
        .map_err(|error| unavailable("获取 thread transaction lock 失败", error))?;

    let existing_thread = load_thread(transaction, request).await?;
    if existing_thread.is_some() {
        crate::thread_origin::observe_on(transaction, command.thread_id.as_str())
            .await
            .map_err(origin_error)?;
    }
    if existing_thread
        .as_ref()
        .is_some_and(|state| state.status == "deleted")
    {
        return Err(ThreadDirectoryError::NotVisible);
    }
    if existing_thread.is_some() && request.command.model_selection.is_some() {
        crate::model_runtime::validate_thread(transaction, request).await?;
    }
    if let Some(receipt) = replay_existing(transaction, request).await? {
        // Preserve historical replay's original authority checks; still reject damaged occupancy.
        checked_thread_occupancy(transaction, &command.thread_id).await?;
        return Ok(Some(receipt));
    }

    Ok(None)
        }.await;
        if matches!(&outcome, Ok(Some(_))) {
            progress
                .stage
                .store(V2_REPLAY_VERIFIED, std::sync::atomic::Ordering::SeqCst);
        }
        let rollback = original.rollback().await;
        close_replay_observation(outcome, rollback, deadline)
    }

    async fn observe_v2_replay_guarded(
        &self,
        request: &BeginThreadRunV2Request,
        deadline: std::time::Instant,
        progress: &V2BeginProgress,
    ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
        let binding = self
            .model_dataset_binding
            .as_ref()
            .ok_or(ThreadDirectoryError::Unavailable)?;
        if !binding.matches_pool_scope(&self.pool, &request.deployment, &request.tenant) {
            return Err(ThreadDirectoryError::Corrupt {
                field: "model_dataset_binding",
            });
        }
        let mut checkout = binding
            .checkout(deadline)
            .await
            .map_err(map_dataset_error)?;
        let original = checkout
            .begin_read_committed()
            .await
            .map_err(map_v2_begin_error)?;
        let outcome = async {
            let model_transaction = &original;
            let remaining = deadline.saturating_duration_since(std::time::Instant::now()).as_millis().max(1).to_string();
            original.as_transaction().query_one("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)", &[&remaining])
                .await.map_err(|_| ThreadDirectoryError::Unavailable)?;
    let transaction = model_transaction.as_transaction();
    // One same-transaction observation of the strict current schema, before any lock;
    // writer admission and the channel source below consume this proof.
    let _schema = crate::thread_history_writer::CurrentWriterSchema::observe(transaction)
        .await
        .map_err(|error| match error {
            InfraError::RepositoryInvariant {
                code: "thread_origin_native_prefix_invalid",
            } => ThreadDirectoryError::Corrupt {
                field: "model_dataset_binding",
            },
            error => origin_error(error),
        })?;
    crate::model_runtime::validate_actor_v2(transaction, request).await?;
    skills::validate_v2_slugs(request)?;
    let command = &request.command;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&command.thread_id.as_str()],
        )
        .await
        .map_err(|error| unavailable("获取 thread transaction lock 失败", error))?;

    let existing_thread = load_thread_v2(transaction, request).await?;
    if existing_thread.is_some() {
        crate::thread_origin::observe_on(transaction, command.thread_id.as_str())
            .await
            .map_err(origin_error)?;
    }
    if existing_thread
        .as_ref()
        .is_some_and(|state| state.status == "deleted")
    {
        return Err(ThreadDirectoryError::NotVisible);
    }
    if existing_thread.is_some() {
        crate::model_runtime::validate_thread_v2(transaction, request).await?;
    }
    if let Some(receipt) = replay_existing_v2(model_transaction, request).await? {
        // Preserve historical replay's original authority checks; still reject damaged occupancy.
        checked_thread_occupancy(transaction, &command.thread_id).await?;
        return Ok(Some(receipt));
    }

    Ok(None)
        }.await;
        if matches!(&outcome, Ok(Some(_))) {
            progress
                .stage
                .store(V2_REPLAY_VERIFIED, std::sync::atomic::Ordering::SeqCst);
        }
        let rollback = original.rollback().await;
        close_replay_observation(outcome, rollback, deadline)
    }

    async fn begin_v2_guarded(
        &self,
        request: &BeginThreadRunV2Request,
        runtime: &RuntimeLease,
        deadline: std::time::Instant,
        progress: &V2BeginProgress,
        materials: &[RunInputArtifactMaterial],
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        let binding = self
            .model_dataset_binding
            .as_ref()
            .ok_or(ThreadDirectoryError::Unavailable)?;
        if !binding.matches_pool_scope(&self.pool, &request.deployment, &request.tenant) {
            return Err(ThreadDirectoryError::Corrupt {
                field: "model_dataset_binding",
            });
        }
        let mut checkout = binding
            .checkout(deadline)
            .await
            .map_err(map_dataset_error)?;
        let transaction = checkout
            .begin_read_committed()
            .await
            .map_err(map_v2_begin_error)?;
        let remaining = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .max(1)
            .to_string();
        transaction
            .as_transaction()
            .query_one(
                "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",
                &[&remaining],
            )
            .await
            .map_err(|_| ThreadDirectoryError::Unavailable)?;
        let outcome = apply_begin_v2(&transaction, runtime, request, materials).await;
        match outcome {
            Ok(BeginOutcome::Replayed(receipt)) => {
                progress
                    .stage
                    .store(V2_REPLAY_VERIFIED, std::sync::atomic::Ordering::SeqCst);
                transaction
                    .rollback()
                    .await
                    .map_err(map_v2_replay_end_error)?;
                if std::time::Instant::now() >= deadline {
                    return Err(ThreadDirectoryError::AcknowledgedAfterDeadline);
                }
                Ok(receipt)
            }
            Ok(BeginOutcome::Created(receipt)) => {
                if std::time::Instant::now() >= deadline {
                    return Err(ThreadDirectoryError::Unavailable);
                }
                // This observes entry into the possible COMMIT call, never a wire send or ACK.
                progress
                    .stage
                    .store(V2_COMMIT_ENTERED, std::sync::atomic::Ordering::SeqCst);
                transaction
                    .commit()
                    .await
                    .map_err(map_v2_commit_end_error)?;
                if std::time::Instant::now() >= deadline {
                    return Err(ThreadDirectoryError::AcknowledgedAfterDeadline);
                }
                Ok(receipt)
            }
            Err(error) => {
                // Preserve the legacy empty-input classification. New references cannot
                // publish a refusal until the original transaction has really closed.
                if materials.is_empty()
                    && let Ok(mut failure) = progress.failure.lock()
                {
                    *failure = Some(error);
                }
                if let Err(end) = transaction.rollback().await {
                    tracing::warn!(state=?end,"custom v2 rejected transaction closure not timely");
                    if !materials.is_empty() {
                        return Err(ThreadDirectoryError::Unavailable);
                    }
                }
                if !materials.is_empty() {
                    if std::time::Instant::now() >= deadline {
                        return Err(ThreadDirectoryError::Unavailable);
                    }
                    if let Ok(mut failure) = progress.failure.lock() {
                        *failure = Some(error);
                    }
                }
                Err(error)
            }
        }
    }
}

#[async_trait]
impl ThreadDirectory for PostgresThreadDirectory {
    async fn begin_thread_run_v2(
        &self,
        request: BeginThreadRunV2Request,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        if !request.command.artifact_refs.is_empty() {
            return Err(ThreadDirectoryError::Unavailable);
        }
        self.begin_v2_with_materials(request, Vec::new()).await
    }

    async fn begin_thread_run_with_artifacts_v2(
        &self,
        request: BeginThreadRunV2Request,
        materials: Vec<RunInputArtifactMaterial>,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        self.begin_v2_with_materials(request, materials).await
    }

    async fn run_effect_receipts(
        &self,
        request: openbot_application::RunEffectReceiptsRequest,
    ) -> Result<openbot_contracts::reconciliation::RunEffectReceiptsSnapshot, ThreadDirectoryError>
    {
        effect_receipts::read(&self.pool, request).await
    }

    async fn run_reconciliation(
        &self,
        request: openbot_application::RunReconciliationRequest,
    ) -> Result<openbot_contracts::reconciliation::RunReconciliationSnapshot, ThreadDirectoryError>
    {
        reconciliation::read(&self.pool, request).await
    }

    async fn mint_thread_id(
        &self,
        deployment: &DeploymentId,
    ) -> Result<ThreadId, ThreadDirectoryError> {
        mint_thread_id(deployment).map_err(|_| ThreadDirectoryError::Unavailable)
    }

    async fn thread_known(
        &self,
        deployment: &DeploymentId,
        tenant: &TenantId,
        actor: &ActorId,
        thread: &ThreadId,
    ) -> Result<bool, ThreadDirectoryError> {
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "native thread status 获取数据库连接失败");
            ThreadDirectoryError::Unavailable
        })?;
        let row = client
            .query_one(
                "SELECT EXISTS( \
                   SELECT 1 FROM public.threads t \
                   WHERE t.thread_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 \
                     AND NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_completions hc \
                       WHERE hc.thread_id=t.thread_id AND hc.deployment_id=t.deployment_id \
                         AND hc.tenant_id=t.tenant_id) \
                     AND t.status<>'deleted' AND ( \
                       (t.anchor_kind='direct_bot' AND EXISTS( \
                         SELECT 1 FROM public.thread_memberships tm \
                         WHERE tm.thread_id=t.thread_id AND tm.user_id=$4 \
                       )) OR (t.anchor_kind='channel' AND EXISTS( \
                         SELECT 1 FROM public.channel_memberships cm \
                         WHERE cm.channel_id=t.anchor_id AND cm.user_id=$4 \
                       )) \
                     ) \
                 ) AS known",
                &[
                    &thread.as_str(),
                    &deployment.as_str(),
                    &tenant.as_str(),
                    &actor.as_str(),
                ],
            )
            .await
            .map_err(|error| unavailable("native thread status 查询失败", error))?;
        row.try_get::<_, bool>("known")
            .map_err(|_| ThreadDirectoryError::Corrupt { field: "known" })
    }

    async fn begin_thread_run(
        &self,
        request: BeginThreadRunRequest,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        if !request.command.artifact_refs.is_empty() {
            return Err(ThreadDirectoryError::Unavailable);
        }
        self.begin_legacy_with_materials(request, Vec::new()).await
    }

    async fn begin_thread_run_with_artifacts(
        &self,
        request: BeginThreadRunRequest,
        materials: Vec<RunInputArtifactMaterial>,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        self.begin_legacy_with_materials(request, materials).await
    }

    async fn observe_begin_replay(
        &self,
        request: BeginThreadRunRequest,
    ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
        artifact_refs::validate_ids(&request.command.artifact_refs)?;
        if self.runtime.is_none() {
            return Err(ThreadDirectoryError::Unavailable);
        }
        let deadline = std::time::Instant::now() + CUSTOM_MODEL_V2_ACCEPT_TIMEOUT;
        let progress = V2BeginProgress::default();
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.observe_legacy_replay_guarded(&request, deadline, &progress),
        )
        .await
        {
            Ok(result) => result,
            Err(_)
                if progress.stage.load(std::sync::atomic::Ordering::SeqCst)
                    == V2_REPLAY_VERIFIED =>
            {
                Err(ThreadDirectoryError::ReplayClosureUnproven)
            }
            Err(_) => Err(ThreadDirectoryError::Unavailable),
        }
    }

    async fn observe_begin_replay_v2(
        &self,
        request: BeginThreadRunV2Request,
    ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
        use openbot_contracts::versioned_model_selection::{
            ModelSelectionIntentSource, VersionedRunModelSelection,
        };
        artifact_refs::validate_ids(&request.command.artifact_refs)?;
        if request.command.model_selection.source() != ModelSelectionIntentSource::Custom
            || !VersionedRunModelSelection::V2(request.command.model_selection.clone()).is_valid()
        {
            return Err(ThreadDirectoryError::InvalidInput {
                field: "model_selection",
            });
        }
        if self.runtime.is_none() {
            return Err(ThreadDirectoryError::Unavailable);
        }
        let deadline = std::time::Instant::now() + CUSTOM_MODEL_V2_ACCEPT_TIMEOUT;
        let progress = V2BeginProgress::default();
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.observe_v2_replay_guarded(&request, deadline, &progress),
        )
        .await
        {
            Ok(result) => result,
            Err(_)
                if progress.stage.load(std::sync::atomic::Ordering::SeqCst)
                    == V2_REPLAY_VERIFIED =>
            {
                Err(ThreadDirectoryError::ReplayClosureUnproven)
            }
            Err(_) => Err(ThreadDirectoryError::Unavailable),
        }
    }

    async fn cancel_thread_run(
        &self,
        request: CancelThreadRunRequest,
    ) -> Result<ThreadRunCancellation, ThreadDirectoryError> {
        if self.runtime.is_none() {
            return Err(ThreadDirectoryError::Unavailable);
        }
        let mut client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "cancel thread run 获取数据库连接失败");
            ThreadDirectoryError::Unavailable
        })?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("cancel thread run 开始事务失败", error))?;
        let outcome = request_run_cancellation(&transaction, &request).await;
        match outcome {
            Ok(CancelRequestOutcome::Created(reply)) => {
                transaction.commit().await.map_err(|error| {
                    tracing::error!(error = %error, "cancel thread run commit 结果未知");
                    ThreadDirectoryError::CommitUnknown
                })?;
                Ok(reply)
            }
            Ok(CancelRequestOutcome::Observed(reply)) => {
                if let Err(error) = transaction.rollback().await {
                    tracing::warn!(error = %error, "cancel replay只读事务rollback失败");
                }
                Ok(reply)
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::warn!(error = %rollback_error, "cancel thread run失败rollback未确认");
                }
                Err(error)
            }
        }
    }

    async fn subscribe_thread_events(
        &self,
        request: ThreadEventSubscription,
    ) -> Result<AppEventStream, ThreadDirectoryError> {
        if request
            .after_event_sequence
            .is_some_and(|value| i64::try_from(value).is_err())
        {
            return Err(ThreadDirectoryError::InvalidInput {
                field: "after_event_sequence",
            });
        }
        if !self
            .thread_known(
                &request.deployment,
                &request.tenant,
                &request.actor,
                &request.thread,
            )
            .await?
        {
            return Err(ThreadDirectoryError::NotVisible);
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(ThreadDirectoryError::Unavailable)?;
        let (stop, stop_rx) = watch::channel(false);
        let active = listen_thread_once(&runtime.database, stop_rx.clone()).await?;
        let (sender, receiver) = mpsc::channel(THREAD_EVENT_CHANNEL_CAPACITY);
        tokio::spawn(supervise_thread_stream(
            self.pool.clone(),
            runtime.database.clone(),
            request,
            sender,
            stop_rx,
            active,
        ));
        Ok(Box::pin(ThreadEventReceiver { receiver, stop }))
    }

    async fn subscribe_channel_activity(
        &self,
        request: ChannelActivitySubscription,
    ) -> Result<AppEventStream, ThreadDirectoryError> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(ThreadDirectoryError::Unavailable)?;
        let (stop, stop_rx) = watch::channel(false);
        let active = listen_channel_once(&runtime.database, stop_rx.clone()).await?;
        let (sender, receiver) = mpsc::channel(THREAD_EVENT_CHANNEL_CAPACITY);
        tokio::spawn(drive_channel_activity(
            self.pool.clone(),
            request,
            sender,
            stop_rx,
            active,
        ));
        Ok(Box::pin(ThreadEventReceiver { receiver, stop }))
    }

    async fn thread_history(
        &self,
        request: ThreadHistoryRequest,
    ) -> Result<ThreadHistory, ThreadDirectoryError> {
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "thread history 获取数据库连接失败");
            ThreadDirectoryError::Unavailable
        })?;
        let rows = client
            .query(
                "SELECT (hc.operation_id IS NOT NULL) AS history_completed, \
                        m.message_id,m.role,m.content,r.bot_id AS agent_id \
                 FROM public.threads t \
                 LEFT JOIN openbot_internal.thread_history_clear_completions hc \
                   ON hc.thread_id=t.thread_id AND hc.deployment_id=t.deployment_id \
                     AND hc.tenant_id=t.tenant_id \
                 LEFT JOIN public.messages m ON m.thread_id=t.thread_id AND hc.operation_id IS NULL \
                 LEFT JOIN public.runs r ON r.run_id=m.run_id \
                 WHERE t.thread_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 \
                   AND (t.status<>'deleted' OR hc.operation_id IS NOT NULL) AND ( \
                     (t.anchor_kind='direct_bot' AND EXISTS( \
                       SELECT 1 FROM public.thread_memberships tm \
                       WHERE tm.thread_id=t.thread_id AND tm.user_id=$4 \
                     )) OR (t.anchor_kind='channel' AND EXISTS( \
                       SELECT 1 FROM public.channel_memberships cm \
                       WHERE cm.channel_id=t.anchor_id AND cm.user_id=$4 \
                     )) \
                   ) \
                 ORDER BY m.seq",
                &[
                    &request.thread.as_str(),
                    &request.deployment.as_str(),
                    &request.tenant.as_str(),
                    &request.actor.as_str(),
                ],
            )
            .await
            .map_err(|error| unavailable("读取 thread history 失败", error))?;
        if let Some(first) = rows.first()
            && decode::<bool>(first, "history_completed")?
        {
            return Err(ThreadDirectoryError::NotVisible);
        }
        let mut messages = Vec::with_capacity(rows.len());
        for row in &rows {
            if decode::<Option<String>>(row, "message_id")?.is_some() {
                messages.push(decode_history_message(row)?);
            }
        }
        Ok(ThreadHistory { messages })
    }

    async fn thread_conversation(
        &self,
        request: ThreadConversationRequest,
    ) -> Result<ThreadConversationSnapshot, ThreadDirectoryError> {
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "thread conversation 获取数据库连接失败");
            ThreadDirectoryError::Unavailable
        })?;
        let query = format!(
            "WITH occupancy_scope AS (SELECT $1::text AS thread_id) {} {}",
            occupancy::INTEGRITY_CTE,
            "SELECT (hc.operation_id IS NOT NULL) AS history_completed, \
                        i.bad_occupancy,t.next_event_seq,coalesce(a.run_ids,'{}'::text[]) AS active_run_ids, \
                        coalesce(a.run_statuses,'{}'::text[]) AS active_run_statuses, \
                        coalesce(a.run_actors,'{}'::text[]) AS active_run_actors, \
                        coalesce(a.cancel_requested,'{}'::boolean[]) AS cancel_requested, \
                        coalesce(a.run_texts,'{}'::text[]) AS active_run_texts, \
                        m.message_id,m.role,m.content,mr.bot_id AS agent_id \
                 FROM public.threads t \
                 LEFT JOIN openbot_internal.thread_history_clear_completions hc \
                   ON hc.thread_id=t.thread_id AND hc.deployment_id=t.deployment_id \
                     AND hc.tenant_id=t.tenant_id \
                 LEFT JOIN occupancy_integrity i ON i.thread_id=t.thread_id \
                 LEFT JOIN public.messages m ON m.thread_id=t.thread_id AND hc.operation_id IS NULL \
                 LEFT JOIN public.runs mr ON mr.run_id=m.run_id \
                 LEFT JOIN LATERAL ( \
                   SELECT array_agg(r.run_id ORDER BY r.created_at,r.run_id) AS run_ids, \
                          array_agg(r.status ORDER BY r.created_at,r.run_id) AS run_statuses, \
                          array_agg(r.actor_id ORDER BY r.created_at,r.run_id) AS run_actors, \
                          array_agg(EXISTS(SELECT 1 FROM public.outbox o \
                            WHERE o.aggregate_id=r.run_id AND o.destination=$5 \
                              AND o.status<>'dead_letter') \
                            ORDER BY r.created_at,r.run_id) AS cancel_requested, \
                          array_agg(coalesce(( \
                            SELECT string_agg(e.payload->>'delta','' ORDER BY e.seq) \
                            FROM public.run_events e WHERE e.run_id=r.run_id \
                              AND e.event_type='semantic_chunk' \
                              AND e.payload->>'channel'='text' \
                              AND e.seq>coalesce(( \
                                SELECT max(c.seq) FROM public.run_events c \
                                WHERE c.run_id=r.run_id AND c.event_type='checkpoint' \
                                  AND c.payload->>'kind'='tool_exchange' \
                              ),-1) \
                          ),'') ORDER BY r.created_at,r.run_id) AS run_texts \
                   FROM public.thread_run_occupancy slot \
                   JOIN public.runs r ON r.thread_id=slot.thread_id AND r.run_id=slot.run_id \
                   WHERE slot.thread_id=t.thread_id AND hc.operation_id IS NULL \
                 ) a ON true \
                 WHERE t.thread_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 \
                   AND (i.thread_id IS NOT NULL OR hc.operation_id IS NOT NULL) \
                   AND (t.status<>'deleted' OR hc.operation_id IS NOT NULL) AND ( \
                     (t.anchor_kind='direct_bot' AND EXISTS( \
                       SELECT 1 FROM public.thread_memberships tm \
                       WHERE tm.thread_id=t.thread_id AND tm.user_id=$4 \
                     )) OR (t.anchor_kind='channel' AND EXISTS( \
                       SELECT 1 FROM public.channel_memberships cm \
                       WHERE cm.channel_id=t.anchor_id AND cm.user_id=$4 \
                     )) \
                   ) \
                 ORDER BY m.seq NULLS FIRST"
        );
        let rows = client
            .query(
                &query,
                &[
                    &request.thread.as_str(),
                    &request.deployment.as_str(),
                    &request.tenant.as_str(),
                    &request.actor.as_str(),
                    &RUN_CANCEL_DESTINATION,
                ],
            )
            .await
            .map_err(|error| unavailable("读取 thread conversation 失败", error))?;
        let Some(first) = rows.first() else {
            return Ok(ThreadConversationSnapshot::default());
        };
        if decode::<bool>(first, "history_completed")? {
            return Err(ThreadDirectoryError::NotVisible);
        }
        if decode::<bool>(first, "bad_occupancy")? {
            return Err(ThreadDirectoryError::Corrupt {
                field: "thread_run_occupancy",
            });
        }
        let next_event_sequence: i64 = decode(first, "next_event_seq")?;
        if next_event_sequence < 0 {
            return Err(ThreadDirectoryError::Corrupt {
                field: "next_event_seq",
            });
        }
        let active: Vec<String> = decode(first, "active_run_ids")?;
        let active_statuses: Vec<String> = decode(first, "active_run_statuses")?;
        let active_actors: Vec<String> = decode(first, "active_run_actors")?;
        let cancel_requested: Vec<bool> = decode(first, "cancel_requested")?;
        let active_texts: Vec<String> = decode(first, "active_run_texts")?;
        if active.len() > 1
            || active.len() != active_statuses.len()
            || active.len() != active_actors.len()
            || active.len() != cancel_requested.len()
            || active.len() != active_texts.len()
        {
            return Err(ThreadDirectoryError::Corrupt {
                field: "active_foreground",
            });
        }
        let active_run_state = match (
            active_statuses.first().map(String::as_str),
            cancel_requested.first().copied().unwrap_or(false),
        ) {
            (None, false) => None,
            (Some("queued"), false) => Some(ThreadForegroundRunState::Queued),
            (Some("running"), false) => Some(ThreadForegroundRunState::Running),
            (Some("queued" | "running"), true) => Some(ThreadForegroundRunState::Cancelling),
            (Some("reconciliation_required"), false) => {
                Some(ThreadForegroundRunState::ReconciliationRequired)
            }
            _ => {
                return Err(ThreadDirectoryError::Corrupt {
                    field: "active_run_state",
                });
            }
        };
        let active_run_cancellable =
            matches!(active_run_state, Some(ThreadForegroundRunState::Running))
                && active_actors
                    .first()
                    .is_some_and(|actor| actor == request.actor.as_str());
        let mut messages = Vec::with_capacity(rows.len());
        for row in &rows {
            let message_id: Option<String> = decode(row, "message_id")?;
            if message_id.is_some() {
                messages.push(decode_history_message(row)?);
            }
        }
        Ok(ThreadConversationSnapshot {
            messages,
            active_run_id: active
                .into_iter()
                .next()
                .map(openbot_contracts::ids::RunId::new),
            active_run_state,
            active_run_cancellable,
            active_run_text: active_texts.into_iter().next().unwrap_or_default(),
            last_event_sequence: if next_event_sequence == 0 {
                None
            } else {
                Some(checked_sequence(
                    next_event_sequence - 1,
                    "last_event_sequence",
                )?)
            },
        })
    }
}

enum CancelRequestOutcome {
    Created(ThreadRunCancellation),
    Observed(ThreadRunCancellation),
}

async fn request_run_cancellation(
    transaction: &Transaction<'_>,
    request: &CancelThreadRunRequest,
) -> Result<CancelRequestOutcome, ThreadDirectoryError> {
    let row = transaction
        .query_opt(
            "SELECT r.status \
             FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id \
             WHERE r.run_id=$1 AND r.thread_id=$2 AND r.actor_id=$5 \
               AND t.deployment_id=$3 AND t.tenant_id=$4 AND t.status<>'deleted' AND ( \
                 (t.anchor_kind='direct_bot' AND EXISTS( \
                   SELECT 1 FROM public.thread_memberships tm \
                   WHERE tm.thread_id=t.thread_id AND tm.user_id=$5 \
                 )) OR (t.anchor_kind='channel' AND EXISTS( \
                   SELECT 1 FROM public.channel_memberships cm \
                   WHERE cm.channel_id=t.anchor_id AND cm.user_id=$5 \
                 )) \
               ) \
             FOR UPDATE OF r",
            &[
                &request.command.run_id.as_str(),
                &request.command.thread_id.as_str(),
                &request.deployment.as_str(),
                &request.tenant.as_str(),
                &request.actor.as_str(),
            ],
        )
        .await
        .map_err(|error| unavailable("锁定 cancellation run 失败", error))?;
    let Some(row) = row else {
        return Err(ThreadDirectoryError::NotVisible);
    };
    let status: String = decode(&row, "status")?;
    let reply = |state| ThreadRunCancellation {
        thread_id: request.command.thread_id.clone(),
        run_id: request.command.run_id.clone(),
        state,
    };
    if matches!(
        status.as_str(),
        "completed" | "failed" | "cancelled" | "reconciliation_required"
    ) {
        return Ok(CancelRequestOutcome::Observed(reply(
            ThreadRunCancellationState::AlreadyTerminal,
        )));
    }
    // Production BeginThreadRun creates a running row and a lease in one transaction. A legacy or
    // corrupt queued row has no proven child/lease owner, so this path must not manufacture one.
    if status != "running" {
        return Err(ThreadDirectoryError::LeaseConflict);
    }

    let outbox_id = run_cancel_outbox_id(request.command.run_id.as_str());
    let payload = json!({
        "runId": request.command.run_id.as_str(),
        "threadId": request.command.thread_id.as_str(),
        "requestedBy": request.actor.as_str(),
    });
    // One statement reads the acceptance and, for a system acceptance, whether the Thread's head is
    // closed by exactly the operation it names. Only the acceptance row is locked: the head and
    // intent tables are read without a lock.
    let existing_sql = format!(
        "SELECT o.aggregate_kind,o.aggregate_id,o.seq,o.destination,o.delivery_class,o.payload,\
         o.status,{} AS system_bound FROM public.outbox o WHERE o.outbox_id=$1 FOR UPDATE OF o",
        thread_history_closed_by_sql("o.payload->>'operationId'", "$2")
    );
    if let Some(existing) = transaction
        .query_opt(
            &existing_sql,
            &[&outbox_id, &request.command.thread_id.as_str()],
        )
        .await
        .map_err(|error| unavailable("读取 cancellation outbox 失败", error))?
    {
        let aggregate_kind: String = decode(&existing, "aggregate_kind")?;
        let aggregate_id: String = decode(&existing, "aggregate_id")?;
        let seq: i64 = decode(&existing, "seq")?;
        let destination: String = decode(&existing, "destination")?;
        let delivery_class: String = decode(&existing, "delivery_class")?;
        let stored_payload: Value = decode(&existing, "payload")?;
        let outbox_status: String = decode(&existing, "status")?;
        // The Run has one acceptance. Besides this actor's own request, the system's closed-history
        // stop is an accepted request too, but only when its operation closed this Thread's head:
        // it is then observed as such and never replaced. A system-shaped row the head and intent
        // do not bear out is a broken binding.
        let system_acceptance = matches!(
            run_cancel_acceptance(
                &stored_payload,
                request.command.run_id.as_str(),
                request.command.thread_id.as_str(),
            ),
            Some(RunCancelAcceptance::ThreadHistoryClosed { .. })
        ) && decode::<bool>(&existing, "system_bound")?;
        if aggregate_kind != "run"
            || aggregate_id != request.command.run_id.as_str()
            || seq != 0
            || destination != RUN_CANCEL_DESTINATION
            || delivery_class != "internal"
            || (stored_payload != payload && !system_acceptance)
            || !matches!(outbox_status.as_str(), "pending" | "delivering")
        {
            return Err(ThreadDirectoryError::Corrupt {
                field: "run_cancel_outbox",
            });
        }
        return Ok(CancelRequestOutcome::Observed(reply(
            ThreadRunCancellationState::AlreadyRequested,
        )));
    }

    transaction
        .execute(
            "INSERT INTO public.outbox( \
               outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload \
             ) VALUES($1,'run',$2,0,$3,'internal',$4)",
            &[
                &outbox_id,
                &request.command.run_id.as_str(),
                &RUN_CANCEL_DESTINATION,
                &payload,
            ],
        )
        .await
        .map_err(|error| write_error("写 cancellation outbox 失败", error))?;
    transaction
        .query_one("SELECT pg_notify($1,'')", &[&RUN_CONTROL_TOPIC])
        .await
        .map_err(|error| write_error("发送 cancellation notify 失败", error))?;
    Ok(CancelRequestOutcome::Created(reply(
        ThreadRunCancellationState::Requested,
    )))
}

fn decode_history_message(
    row: &tokio_postgres::Row,
) -> Result<ThreadHistoryMessage, ThreadDirectoryError> {
    let id: String = decode(row, "message_id")?;
    let raw_role: String = decode(row, "role")?;
    let value: Value = decode(row, "content")?;
    let role = match raw_role.as_str() {
        "user" => ThreadHistoryRole::User,
        "assistant" => ThreadHistoryRole::Assistant,
        "system" | "summary" => ThreadHistoryRole::System,
        "tool" => ThreadHistoryRole::Tool,
        _ => return Err(ThreadDirectoryError::Corrupt { field: "role" }),
    };
    let content = history_text(&value).ok_or(ThreadDirectoryError::Corrupt { field: "content" })?;
    let selected_skill_slugs = match value.get("selectedSkillSlugs") {
        None => Vec::new(),
        Some(slugs) if role == ThreadHistoryRole::User => {
            let slugs: Vec<String> = serde_json::from_value(slugs.clone()).map_err(|_| {
                ThreadDirectoryError::Corrupt {
                    field: "selected_skill_slugs",
                }
            })?;
            if !openbot_contracts::command::valid_selected_skill_slugs(&slugs) {
                return Err(ThreadDirectoryError::Corrupt {
                    field: "selected_skill_slugs",
                });
            }
            slugs
        }
        Some(_) => {
            return Err(ThreadDirectoryError::Corrupt {
                field: "selected_skill_slugs",
            });
        }
    };
    let agent_id = decode::<Option<String>>(row, "agent_id")?.map(BotId::new);
    let tool_call_id = if role == ThreadHistoryRole::Tool {
        Some(
            value
                .get("toolCallId")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(ThreadDirectoryError::Corrupt {
                    field: "toolCallId",
                })?,
        )
    } else {
        None
    };
    let tool_name = if role == ThreadHistoryRole::Tool {
        Some(
            value
                .get("toolName")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or(ThreadDirectoryError::Corrupt { field: "toolName" })?,
        )
    } else {
        None
    };
    let tool_error_code = if role == ThreadHistoryRole::Tool {
        match value.get("errorCode") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if !value.is_empty() && !value.as_bytes().contains(&0) => {
                Some(value.clone())
            }
            _ => return Err(ThreadDirectoryError::Corrupt { field: "errorCode" }),
        }
    } else {
        None
    };
    let tool_calls = if role == ThreadHistoryRole::Assistant {
        value.get("toolCalls").and_then(Value::as_array).cloned()
    } else {
        None
    };
    Ok(ThreadHistoryMessage {
        selected_skill_slugs,
        id,
        role,
        content,
        agent_id,
        tool_call_id,
        tool_name,
        tool_error_code,
        tool_calls,
    })
}

fn history_text(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_owned());
    }
    if let Some(text) = value
        .get("text")
        .or_else(|| value.get("content"))
        .and_then(Value::as_str)
    {
        return Some(text.to_owned());
    }
    value.as_array().map(|parts| {
        parts
            .iter()
            .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

struct ThreadEventReceiver {
    receiver: mpsc::Receiver<AppEvent>,
    stop: watch::Sender<bool>,
}

impl Stream for ThreadEventReceiver {
    type Item = AppEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

impl Drop for ThreadEventReceiver {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

type PgConnection = Connection<Socket, tokio_postgres::tls::NoTlsStream>;

struct ActiveThreadListener {
    _client: Client,
    connection: PgConnection,
}

async fn listen_thread_once(
    database: &ThreadListenerDatabase,
    mut stop: watch::Receiver<bool>,
) -> Result<ActiveThreadListener, ThreadDirectoryError> {
    let (client, mut connection) = database
        .config()
        .connect(NoTls)
        .await
        .map_err(|error| unavailable("建立 thread event LISTEN 连接失败", error))?;
    {
        let listen = client.batch_execute("LISTEN openbot_thread_events");
        tokio::pin!(listen);
        loop {
            tokio::select! {
                result = &mut listen => {
                    result.map_err(|error| unavailable("订阅 thread event channel 失败", error))?;
                    break;
                }
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return Err(ThreadDirectoryError::Unavailable);
                    }
                }
                message = poll_fn(|cx| connection.poll_message(cx)) => match message {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        return Err(unavailable("建立 LISTEN 时连接失败", error));
                    }
                    None => return Err(ThreadDirectoryError::Unavailable),
                }
            }
        }
    }
    Ok(ActiveThreadListener {
        _client: client,
        connection,
    })
}

async fn supervise_thread_stream(
    pool: crate::db::pool::DatabasePool,
    database: ThreadListenerDatabase,
    request: ThreadEventSubscription,
    sender: mpsc::Sender<AppEvent>,
    mut stop: watch::Receiver<bool>,
    mut active: ActiveThreadListener,
) {
    let mut cursor = request.after_event_sequence.map_or(-1, |value| {
        i64::try_from(value).expect("subscribe 已验证 cursor")
    });
    loop {
        match replay_all(&pool, &request, &sender, &mut cursor).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                emit_stream_error(&sender, error).await;
                return;
            }
        }

        let mut catch_up = tokio::time::interval(THREAD_CATCH_UP_PERIOD);
        catch_up.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // interval 首拍立即 ready；先消费掉，避免紧接 initial replay 再做一次相同查询。
        catch_up.tick().await;
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return;
                    }
                }
                () = sender.closed() => {
                    return;
                }
                _ = catch_up.tick() => {
                    // NOTIFY 只是一种低延迟 wake；周期补取负责“通知丢失仍不丢 durable event”
                    // 与 membership 撤销后的 fail-closed 收口。
                    match replay_all(&pool, &request, &sender, &mut cursor).await {
                        Ok(true) => {}
                        Ok(false) => return,
                        Err(error) => {
                            emit_stream_error(&sender, error).await;
                            return;
                        }
                    }
                }
                message = poll_fn(|cx| active.connection.poll_message(cx)) => {
                    match message {
                        Some(Ok(AsyncMessage::Notification(notification)))
                            if notification.channel() == THREAD_EVENT_TOPIC =>
                        {
                            match replay_all(&pool, &request, &sender, &mut cursor).await {
                                Ok(true) => {}
                                Ok(false) => return,
                                Err(error) => {
                                    emit_stream_error(&sender, error).await;
                                    return;
                                }
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(error)) => {
                            tracing::error!(error = %error,
                                "thread event LISTEN 连接失败，准备重连");
                            break;
                        }
                        None => {
                            tracing::warn!("thread event LISTEN 连接关闭，准备重连");
                            break;
                        }
                    }
                }
            }
        }

        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return;
                    }
                }
                () = sender.closed() => return,
                () = tokio::time::sleep(THREAD_RECONNECT_DELAY) => {}
            }
            match listen_thread_once(&database, stop.clone()).await {
                Ok(listener) => {
                    active = listener;
                    break;
                }
                Err(error) => tracing::error!(code = %error.into_app_error().code(),
                    "thread event LISTEN 重连失败；继续重试并依赖 durable replay"),
            }
        }
    }
}

async fn replay_all(
    pool: &crate::db::pool::DatabasePool,
    request: &ThreadEventSubscription,
    sender: &mpsc::Sender<AppEvent>,
    cursor: &mut i64,
) -> Result<bool, ThreadDirectoryError> {
    loop {
        let events = replay_batch(pool, request, *cursor).await?;
        if events.is_empty() {
            return Ok(true);
        }
        let full = events.len() == THREAD_EVENT_BATCH as usize;
        for event in events {
            *cursor =
                i64::try_from(event.event_sequence).map_err(|_| ThreadDirectoryError::Corrupt {
                    field: "event_sequence",
                })?;
            if sender.send(AppEvent::ThreadRunEvent(event)).await.is_err() {
                return Ok(false);
            }
        }
        if !full {
            return Ok(true);
        }
    }
}

async fn replay_batch(
    pool: &crate::db::pool::DatabasePool,
    request: &ThreadEventSubscription,
    cursor: i64,
) -> Result<Vec<ThreadRunEvent>, ThreadDirectoryError> {
    let client = pool.get().await.map_err(|error| {
        tracing::error!(error = %error, "thread event replay 获取连接失败");
        ThreadDirectoryError::Unavailable
    })?;
    let rows = client
        .query(
            "WITH visible_thread AS ( \
               SELECT t.thread_id FROM public.threads t \
               WHERE t.thread_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 \
                 AND NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_completions hc \
                   WHERE hc.thread_id=t.thread_id AND hc.deployment_id=t.deployment_id \
                     AND hc.tenant_id=t.tenant_id) \
                 AND t.status<>'deleted' AND ( \
                   (t.anchor_kind='direct_bot' AND EXISTS( \
                     SELECT 1 FROM public.thread_memberships tm \
                     WHERE tm.thread_id=t.thread_id AND tm.user_id=$4 \
                   )) OR (t.anchor_kind='channel' AND EXISTS( \
                     SELECT 1 FROM public.channel_memberships cm \
                     WHERE cm.channel_id=t.anchor_id AND cm.user_id=$4 \
                   )) \
                 ) \
             ) SELECT e.run_id,e.event_seq,e.event_type,e.payload,e.terminal,e.created_at \
               FROM visible_thread v LEFT JOIN LATERAL ( \
                 SELECT run_id,event_seq,event_type,payload,terminal,created_at \
                 FROM public.run_events WHERE thread_id=v.thread_id AND event_seq>$5 \
                 ORDER BY event_seq LIMIT $6 \
               ) e ON true ORDER BY e.event_seq NULLS FIRST",
            &[
                &request.thread.as_str(),
                &request.deployment.as_str(),
                &request.tenant.as_str(),
                &request.actor.as_str(),
                &cursor,
                &THREAD_EVENT_BATCH,
            ],
        )
        .await
        .map_err(|error| unavailable("补取 durable thread events 失败", error))?;
    if rows.is_empty() {
        return Err(ThreadDirectoryError::NotVisible);
    }
    let mut events = Vec::with_capacity(rows.len());
    for row in &rows {
        if decode::<Option<i64>>(row, "event_seq")?.is_some() {
            events.push(decode_thread_event(row, &request.thread)?);
        }
    }
    Ok(events)
}

fn decode_thread_event(
    row: &tokio_postgres::Row,
    thread: &ThreadId,
) -> Result<ThreadRunEvent, ThreadDirectoryError> {
    let sequence: i64 = decode(row, "event_seq")?;
    let event_sequence = checked_sequence(sequence, "event_seq")?;
    let raw_kind: String = decode(row, "event_type")?;
    let event_type =
        ThreadRunEventKind::from_database(&raw_kind).ok_or(ThreadDirectoryError::Corrupt {
            field: "event_type",
        })?;
    let payload: Value = decode(row, "payload")?;
    if !payload.is_object() {
        return Err(ThreadDirectoryError::Corrupt { field: "payload" });
    }
    let terminal: bool = decode(row, "terminal")?;
    if terminal != event_type.is_terminal() {
        return Err(ThreadDirectoryError::Corrupt { field: "terminal" });
    }
    Ok(ThreadRunEvent {
        thread_id: thread.clone(),
        run_id: openbot_contracts::ids::RunId::new(decode::<String>(row, "run_id")?),
        event_sequence,
        event_type,
        payload,
        terminal,
        created_at: decode(row, "created_at")?,
    })
}

async fn emit_stream_error(sender: &mpsc::Sender<AppEvent>, error: ThreadDirectoryError) {
    let _ = sender
        .send(AppEvent::ThreadStreamError {
            code: error.into_app_error().code().as_str().to_owned(),
        })
        .await;
}

async fn listen_channel_once(
    database: &ThreadListenerDatabase,
    mut stop: watch::Receiver<bool>,
) -> Result<ActiveThreadListener, ThreadDirectoryError> {
    let (client, mut connection) = database
        .config()
        .connect(NoTls)
        .await
        .map_err(|error| unavailable("建立 channel activity LISTEN 连接失败", error))?;
    {
        let listen = client.batch_execute("LISTEN openbot_channel_activity");
        tokio::pin!(listen);
        loop {
            tokio::select! {
                result = &mut listen => {
                    result.map_err(|error| unavailable("订阅 channel activity 失败", error))?;
                    break;
                }
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return Err(ThreadDirectoryError::Unavailable);
                    }
                }
                message = poll_fn(|cx| connection.poll_message(cx)) => match message {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        return Err(unavailable("建立 channel LISTEN 时连接失败", error));
                    }
                    None => return Err(ThreadDirectoryError::Unavailable),
                }
            }
        }
    }
    Ok(ActiveThreadListener {
        _client: client,
        connection,
    })
}

async fn drive_channel_activity(
    pool: crate::db::pool::DatabasePool,
    request: ChannelActivitySubscription,
    sender: mpsc::Sender<AppEvent>,
    mut stop: watch::Receiver<bool>,
    mut active: ActiveThreadListener,
) {
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
            () = sender.closed() => return,
            message = poll_fn(|cx| active.connection.poll_message(cx)) => match message {
                Some(Ok(AsyncMessage::Notification(notification)))
                    if notification.channel() == crate::channel_activity::CHANNEL_ACTIVITY_TOPIC =>
                {
                    let Ok(event) = serde_json::from_str::<ChannelActivityEvent>(notification.payload()) else {
                        tracing::warn!("ignored malformed channel activity notification");
                        continue;
                    };
                    if !channel_event_is_bounded(&event) {
                        tracing::warn!("ignored unbounded channel activity notification");
                        continue;
                    }
                    match channel_visible(&pool, &request, &event).await {
                        Ok(true) => {
                            if sender.send(AppEvent::ChannelActivity(event)).await.is_err() {
                                return;
                            }
                        }
                        Ok(false) => {}
                        Err(error) => {
                            emit_channel_stream_error(&sender, error).await;
                            return;
                        }
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    tracing::error!(error = %error, "channel activity LISTEN connection failed");
                    emit_channel_stream_error(&sender, ThreadDirectoryError::Unavailable).await;
                    return;
                }
                None => {
                    tracing::warn!("channel activity LISTEN connection closed");
                    emit_channel_stream_error(&sender, ThreadDirectoryError::Unavailable).await;
                    return;
                }
            }
        }
    }
}

fn channel_event_is_bounded(event: &ChannelActivityEvent) -> bool {
    !event.channel_id.as_str().is_empty()
        && event.channel_id.as_str().len() <= 512
        && !event.channel_id.as_str().chars().any(char::is_control)
        && event.last_message.as_ref().is_none_or(|message| {
            message.chars().count() <= 200 && !message.chars().any(char::is_control)
        })
        && event
            .last_message_agent_id
            .as_ref()
            .is_none_or(|agent| !agent.as_str().is_empty() && agent.as_str().len() <= 512)
}

async fn channel_visible(
    pool: &crate::db::pool::DatabasePool,
    request: &ChannelActivitySubscription,
    event: &ChannelActivityEvent,
) -> Result<bool, ThreadDirectoryError> {
    let client = pool.get().await.map_err(|error| {
        tracing::error!(error = %error, "channel activity membership 获取连接失败");
        ThreadDirectoryError::Unavailable
    })?;
    client
        .query_one(
            "SELECT EXISTS( \
               SELECT 1 FROM public.channel_memberships \
               WHERE channel_id=$1 AND user_id=$2 \
             )",
            &[&event.channel_id.as_str(), &request.actor.as_str()],
        )
        .await
        .map_err(|error| unavailable("验证 channel activity membership 失败", error))?
        .try_get(0)
        .map_err(|_| ThreadDirectoryError::Corrupt {
            field: "channel_activity_visible",
        })
}

async fn emit_channel_stream_error(sender: &mpsc::Sender<AppEvent>, error: ThreadDirectoryError) {
    let _ = sender
        .send(AppEvent::ChannelStreamError {
            code: error.into_app_error().code().as_str().to_owned(),
        })
        .await;
}

enum BeginOutcome {
    Replayed(ThreadRunStarted),
    Created(ThreadRunStarted),
}

struct ThreadState {
    status: String,
    next_message_seq: i64,
    next_event_seq: i64,
}

async fn checked_thread_occupancy(
    transaction: &Transaction<'_>,
    thread: &ThreadId,
) -> Result<bool, ThreadDirectoryError> {
    occupancy::thread_is_occupied(transaction, thread.as_str())
        .await
        .map_err(|error| match error {
            InfraError::RepositoryInvariant { .. } | InfraError::RowDecode(_) => {
                ThreadDirectoryError::Corrupt {
                    field: "thread_run_occupancy",
                }
            }
            _ => ThreadDirectoryError::Unavailable,
        })
}

async fn apply_begin(
    transaction: &Transaction<'_>,
    runtime: &RuntimeLease,
    request: &BeginThreadRunRequest,
    materials: &[RunInputArtifactMaterial],
) -> Result<BeginOutcome, ThreadDirectoryError> {
    // One same-transaction observation of the strict current schema, before any lock;
    // writer admission and the channel source below consume this proof.
    let schema = crate::thread_history_writer::CurrentWriterSchema::observe(transaction)
        .await
        .map_err(origin_error)?;
    // New artifact inputs must serialize with the original cleanup actor UPDATE
    // before any Thread/lease/artifact locks. Empty legacy begins keep their path.
    if !materials.is_empty()
        && crate::thread_origin::current_native_actor(
            transaction,
            request.actor.as_str(),
            request.auth_generation,
        )
        .await
        .map_err(origin_error)?
        .is_none()
    {
        return Err(ThreadDirectoryError::NotVisible);
    }
    crate::model_runtime::validate_actor(transaction, request).await?;
    skills::validate_actor(transaction, request).await?;
    let command = &request.command;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&command.thread_id.as_str()],
        )
        .await
        .map_err(|error| unavailable("获取 thread transaction lock 失败", error))?;

    let existing_thread = load_thread(transaction, request).await?;
    if existing_thread.is_some() {
        crate::thread_origin::observe_on(transaction, command.thread_id.as_str())
            .await
            .map_err(origin_error)?;
    }
    if existing_thread
        .as_ref()
        .is_some_and(|state| state.status == "deleted")
    {
        return Err(ThreadDirectoryError::NotVisible);
    }
    if existing_thread.is_some() && request.command.model_selection.is_some() {
        crate::model_runtime::validate_thread(transaction, request).await?;
    }
    if let Some(receipt) = replay_existing(transaction, request).await? {
        // Preserve historical replay's original authority checks; still reject damaged occupancy.
        checked_thread_occupancy(transaction, &command.thread_id).await?;
        return Ok(BeginOutcome::Replayed(receipt));
    }

    let now = database_now(transaction).await?;
    let state = match existing_thread {
        Some(state) => {
            if state.status != "active" {
                return Err(ThreadDirectoryError::NotVisible);
            }
            if !target_visible(transaction, request).await? {
                return Err(ThreadDirectoryError::NotVisible);
            }
            state
        }
        None => {
            if !ThreadIdentity::new(&request.deployment).owns(&command.thread_id) {
                return Err(ThreadDirectoryError::InvalidInput { field: "thread_id" });
            }
            if !target_visible(transaction, request).await? {
                return Err(ThreadDirectoryError::NotVisible);
            }
            insert_thread(transaction, request, now).await?;
            ThreadState {
                status: "active".to_owned(),
                next_message_seq: 0,
                next_event_seq: 0,
            }
        }
    };

    schema
        .require_open(transaction, &command.thread_id)
        .await
        .map_err(writer_error)?;
    // Re-observe the original authority in a fresh statement after actual admission.
    // H is retained on this same transaction; it grants neither visibility nor a lease.
    // Check visible state before a competing lease can hide a damaged projection.
    let active = checked_thread_occupancy(transaction, &command.thread_id).await?;

    if matches!(&command.anchor, ThreadRunAnchor::Channel { .. }) {
        transaction
            .execute(
                "INSERT INTO public.thread_memberships(thread_id,user_id,created_at) \
                 VALUES($1,$2,$3) ON CONFLICT(thread_id,user_id) DO NOTHING",
                &[&command.thread_id.as_str(), &request.actor.as_str(), &now],
            )
            .await
            .map_err(|error| write_error("materialize channel thread membership", error))?;
    }

    let expires_at = now
        .checked_add(runtime.duration)
        .ok_or(ThreadDirectoryError::Corrupt {
            field: "thread_lease_expiry",
        })?;
    let fencing = acquire_lease(transaction, request, runtime, now, expires_at).await?;

    if active {
        return Err(ThreadDirectoryError::LeaseConflict);
    }

    crate::model_runtime::validate_actor(transaction, request).await?;
    skills::validate_actor(transaction, request).await?;
    if !target_visible(transaction, request).await? {
        return Err(ThreadDirectoryError::NotVisible);
    }
    let skill_snapshots = skills::resolve(transaction, request).await?;
    let model_snapshot = crate::model_runtime::resolve(transaction, request).await?;
    artifact_refs::verify_current(
        transaction,
        &schema,
        (&request.deployment, &request.tenant),
        &request.actor,
        request.auth_generation.get(),
        &command.thread_id,
        materials,
    )
    .await?;
    let user_message_seq = state
        .next_message_seq
        .checked_add(skill_snapshots.len() as i64)
        .and_then(|sequence| sequence.checked_add(materials.len() as i64))
        .ok_or(ThreadDirectoryError::Corrupt {
            field: "next_message_seq",
        })?;
    let message_sequence = checked_sequence(user_message_seq, "next_message_seq")?;
    let event_sequence = checked_sequence(state.next_event_seq, "next_event_seq")?;
    let next_message_seq =
        user_message_seq
            .checked_add(1)
            .ok_or(ThreadDirectoryError::Corrupt {
                field: "next_message_seq",
            })?;
    let next_event_seq =
        state
            .next_event_seq
            .checked_add(1)
            .ok_or(ThreadDirectoryError::Corrupt {
                field: "next_event_seq",
            })?;

    let mut run = Run::queued(
        command.run_id.clone(),
        command.thread_id.clone(),
        command.bot_id.clone(),
        request.actor.clone(),
        true,
        FencingToken::new(fencing).map_err(|_| ThreadDirectoryError::Corrupt {
            field: "fencing_token",
        })?,
        now,
    );
    run.start(now).map_err(|_| ThreadDirectoryError::Corrupt {
        field: "run_transition",
    })?;
    let budget_row = transaction
        .query_opt(
            "SELECT currency,max_cost_micro_units FROM public.user_run_cost_budgets \
             WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3",
            &[
                &request.deployment.as_str(),
                &request.tenant.as_str(),
                &request.actor.as_str(),
            ],
        )
        .await
        .map_err(|error| unavailable("读取 run cost budget snapshot 失败", error))?;
    let (budget_currency, budget_max_cost_micro_units) = match budget_row {
        Some(row) => {
            let currency = row.try_get::<_, String>("currency").map_err(|_| {
                ThreadDirectoryError::Corrupt {
                    field: "budget_cost_currency",
                }
            })?;
            let amount = row.try_get::<_, i64>("max_cost_micro_units").map_err(|_| {
                ThreadDirectoryError::Corrupt {
                    field: "budget_max_cost_micro_units",
                }
            })?;
            if currency.len() != 3
                || !currency.bytes().all(|byte| byte.is_ascii_uppercase())
                || amount <= 0
            {
                return Err(ThreadDirectoryError::Corrupt {
                    field: "run_cost_budget",
                });
            }
            (Some(currency), Some(amount))
        }
        None => (None, None),
    };
    let message_id = input_message_id(command.run_id.as_str());
    let content = skills::input_content(command);
    let message = Message::new(
        MessageId::new(&message_id),
        command.thread_id.clone(),
        message_sequence,
        MessageRole::User,
        content.clone(),
        command.message.clone(),
        Some(command.run_id.clone()),
        Some(request.actor.clone()),
        now,
    );
    let event = RunEvent::new(
        command.run_id.clone(),
        0,
        command.thread_id.clone(),
        event_sequence,
        RunEventKind::Started,
        json!({
            "runId": command.run_id,
            "messageId": message_id,
            "botId": command.bot_id,
        }),
        now,
    );

    transaction
        .execute(
            "UPDATE public.threads SET next_message_seq=$2,next_event_seq=$3,updated_at=$4 \
             WHERE thread_id=$1",
            &[
                &command.thread_id.as_str(),
                &next_message_seq,
                &next_event_seq,
                &now,
            ],
        )
        .await
        .map_err(|error| write_error("推进 thread sequence 失败", error))?;
    transaction
        .execute(
            "INSERT INTO public.runs( \
               run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq, \
               terminal_event_seq,error_code,created_at,started_at,finished_at, \
               budget_cost_currency,budget_max_cost_micro_units \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,1,NULL,NULL,$8,$9,NULL,$10,$11)",
            &[
                &run.id().as_str(),
                &run.thread().as_str(),
                &run.bot().as_str(),
                &run.actor().as_str(),
                &run.foreground(),
                &run.status().as_str(),
                &run.fencing().get(),
                &run.created_at(),
                &run.started_at(),
                &budget_currency,
                &budget_max_cost_micro_units,
            ],
        )
        .await
        .map_err(|error| write_error("写 running run 失败", error))?;
    if let Some(snapshot) = &model_snapshot {
        crate::model_runtime::insert(transaction, request, snapshot, now).await?;
    }
    for (index, snapshot) in skill_snapshots.iter().enumerate() {
        let skill_message_id = format!("{}:selected_skill:{index}", command.run_id);
        let content = json!({"text": snapshot.instructions, "selectedSkillSlug": snapshot.slug});
        transaction
            .execute(
                "INSERT INTO public.messages( \
               message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at \
             ) VALUES($1,$2,$3,'system',$4,$5,$6,$7,$8)",
                &[
                    &skill_message_id,
                    &command.thread_id.as_str(),
                    &(state.next_message_seq + index as i64),
                    &content,
                    &snapshot.instructions,
                    &command.run_id.as_str(),
                    &request.actor.as_str(),
                    &now,
                ],
            )
            .await
            .map_err(|error| write_error("写 selected skill snapshot 失败", error))?;
    }
    artifact_refs::insert_messages(
        transaction,
        &command.run_id,
        &command.thread_id,
        &request.actor,
        state
            .next_message_seq
            .checked_add(skill_snapshots.len() as i64)
            .ok_or(ThreadDirectoryError::Corrupt {
                field: "next_message_seq",
            })?,
        now,
        materials,
    )
    .await?;
    transaction
        .execute(
            "INSERT INTO public.messages( \
               message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &message.id().as_str(),
                &message.thread().as_str(),
                &(message.sequence() as i64),
                &message.role().as_str(),
                message.content(),
                &message.search_text(),
                &message.run().map(|value| value.as_str()),
                &message.actor().map(|value| value.as_str()),
                &message.created_at(),
            ],
        )
        .await
        .map_err(|error| write_error("写 initial message 失败", error))?;
    transaction
        .execute(
            "INSERT INTO public.run_events( \
               run_id,seq,thread_id,event_seq,event_type,payload,terminal,created_at \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &event.run().as_str(),
                &(event.sequence() as i64),
                &event.thread().as_str(),
                &(event.thread_sequence() as i64),
                &event.kind().as_str(),
                event.payload(),
                &event.kind().is_terminal(),
                &event.created_at(),
            ],
        )
        .await
        .map_err(|error| write_error("写 run started event 失败", error))?;
    let outbox_id = format!("{}:agent_run_dispatch", command.run_id);
    let outbox_payload = json!({
        "runId": command.run_id,
        "threadId": command.thread_id,
        "eventSequence": event_sequence,
    });
    transaction
        .execute(
            "INSERT INTO public.outbox( \
               outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload, \
               available_at,created_at,updated_at \
             ) VALUES($1,'thread',$2,$3,'agent_run_dispatch','internal',$4,$5,$5,$5)",
            &[
                &outbox_id,
                &command.thread_id.as_str(),
                &(event_sequence as i64),
                &outbox_payload,
                &now,
            ],
        )
        .await
        .map_err(|error| write_error("写 replay-safe dispatch outbox 失败", error))?;
    if matches!(&command.anchor, ThreadRunAnchor::Channel { .. }) {
        crate::channel_activity::record_from_message(&schema, message.id())
            .await
            .map_err(writer_error)?;
    }
    transaction
        .query_one("SELECT pg_notify('openbot_thread_events','')", &[])
        .await
        .map_err(|error| unavailable("提交 thread wakeup 失败", error))?;

    Ok(BeginOutcome::Created(ThreadRunStarted {
        thread_id: command.thread_id.clone(),
        run_id: command.run_id.clone(),
        message_sequence,
        event_sequence,
        replayed: false,
    }))
}

async fn load_thread(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<Option<ThreadState>, ThreadDirectoryError> {
    let command = &request.command;
    let row = transaction
        .query_opt(
            "SELECT t.deployment_id,t.tenant_id,t.anchor_kind,t.anchor_id,t.status, \
                    t.next_message_seq,t.next_event_seq, \
                    CASE WHEN t.anchor_kind='channel' THEN EXISTS( \
                      SELECT 1 FROM public.channel_memberships cm \
                      WHERE cm.channel_id=t.anchor_id AND cm.user_id=$2 \
                    ) ELSE EXISTS( \
                      SELECT 1 FROM public.thread_memberships tm \
                      WHERE tm.thread_id=t.thread_id AND tm.user_id=$2 \
                    ) END AS member \
             FROM public.threads t WHERE t.thread_id=$1 FOR UPDATE OF t",
            &[&command.thread_id.as_str(), &request.actor.as_str()],
        )
        .await
        .map_err(|error| unavailable("读取并锁定 thread 失败", error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let deployment: String = decode(&row, "deployment_id")?;
    let tenant: String = decode(&row, "tenant_id")?;
    let anchor_kind: String = decode(&row, "anchor_kind")?;
    let anchor_id: String = decode(&row, "anchor_id")?;
    let member: bool = decode(&row, "member")?;
    if deployment != request.deployment.as_str() || tenant != request.tenant.as_str() || !member {
        return Err(ThreadDirectoryError::NotVisible);
    }
    if !anchor_matches(
        &command.anchor,
        command.bot_id.as_str(),
        &anchor_kind,
        &anchor_id,
    ) {
        return Err(ThreadDirectoryError::RequestConflict);
    }
    Ok(Some(ThreadState {
        status: decode(&row, "status")?,
        next_message_seq: decode(&row, "next_message_seq")?,
        next_event_seq: decode(&row, "next_event_seq")?,
    }))
}

async fn replay_existing(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
    let command = &request.command;
    let message_id = input_message_id(command.run_id.as_str());
    let row = transaction
        .query_opt(
            "SELECT r.thread_id,r.bot_id,r.actor_id,r.foreground, \
                    m.seq AS message_seq,m.content,e.event_seq \
             FROM public.runs r \
             LEFT JOIN public.messages m ON m.message_id=$2 AND m.run_id=r.run_id \
             LEFT JOIN public.run_events e ON e.run_id=r.run_id AND e.seq=0 \
                                           AND e.event_type='started' \
             WHERE r.run_id=$1",
            &[&command.run_id.as_str(), &message_id],
        )
        .await
        .map_err(|error| unavailable("查询 run idempotency receipt 失败", error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let thread: String = decode(&row, "thread_id")?;
    let bot: String = decode(&row, "bot_id")?;
    let actor: String = decode(&row, "actor_id")?;
    let foreground: bool = decode(&row, "foreground")?;
    let message_seq: Option<i64> = decode(&row, "message_seq")?;
    let content: Option<Value> = decode(&row, "content")?;
    let event_seq: Option<i64> = decode(&row, "event_seq")?;
    if thread != command.thread_id.as_str()
        || bot != command.bot_id.as_str()
        || actor != request.actor.as_str()
        || !foreground
        || content.as_ref() != Some(&skills::input_content(command))
    {
        return Err(ThreadDirectoryError::RequestConflict);
    }
    let message_sequence = checked_sequence(
        message_seq.ok_or(ThreadDirectoryError::Corrupt {
            field: "idempotent_message",
        })?,
        "idempotent_message",
    )?;
    let event_sequence = checked_sequence(
        event_seq.ok_or(ThreadDirectoryError::Corrupt {
            field: "idempotent_event",
        })?,
        "idempotent_event",
    )?;
    Ok(Some(ThreadRunStarted {
        thread_id: command.thread_id.clone(),
        run_id: command.run_id.clone(),
        message_sequence,
        event_sequence,
        replayed: true,
    }))
}

async fn target_visible(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<bool, ThreadDirectoryError> {
    if request.command.model_selection.is_some() {
        crate::model_runtime::validate_target(transaction, request).await?;
        return Ok(true);
    }
    let command = &request.command;
    let row = match &command.anchor {
        ThreadRunAnchor::DirectBot => {
            transaction
                .query_one(
                    "SELECT EXISTS( \
                       SELECT 1 FROM public.agent_profiles p \
                       WHERE p.agent_id=$1 AND p.deleted_at IS NULL \
                         AND (p.visibility='public' OR p.owner_user_id=$2 OR EXISTS( \
                              SELECT 1 FROM public.user_roles ur \
                               WHERE ur.user_id=$2 AND ur.role='admin')) \
                     )",
                    &[&command.bot_id.as_str(), &request.actor.as_str()],
                )
                .await
        }
        ThreadRunAnchor::Channel { channel_id } => {
            transaction
                .query_one(
                    "SELECT EXISTS( \
                       SELECT 1 FROM public.channel_memberships cm \
                       JOIN public.channel_agents ca ON ca.channel_id=cm.channel_id \
                       JOIN public.agent_profiles p ON p.agent_id=ca.agent_id \
                       WHERE cm.channel_id=$1 AND cm.user_id=$2 AND ca.agent_id=$3 \
                         AND p.deleted_at IS NULL \
                         AND (p.visibility='public' OR p.owner_user_id=$2 OR EXISTS( \
                              SELECT 1 FROM public.user_roles ur \
                               WHERE ur.user_id=$2 AND ur.role='admin')) \
                     )",
                    &[
                        &channel_id.as_str(),
                        &request.actor.as_str(),
                        &command.bot_id.as_str(),
                    ],
                )
                .await
        }
    }
    .map_err(|error| unavailable("验证 thread target 可见性失败", error))?;
    row.try_get(0).map_err(|_| ThreadDirectoryError::Corrupt {
        field: "target_visible",
    })
}

async fn insert_thread(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunRequest,
    now: OffsetDateTime,
) -> Result<(), ThreadDirectoryError> {
    crate::thread_origin::current_native_actor(
        transaction,
        request.actor.as_str(),
        request.auth_generation,
    )
    .await
    .map_err(origin_error)?
    .ok_or(ThreadDirectoryError::NotVisible)?;
    let command = &request.command;
    let (anchor_kind, anchor_id) = match &command.anchor {
        ThreadRunAnchor::DirectBot => ("direct_bot", command.bot_id.as_str()),
        ThreadRunAnchor::Channel { channel_id } => ("channel", channel_id.as_str()),
    };
    transaction
        .execute(
            "INSERT INTO public.threads( \
               thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status, \
               next_message_seq,next_event_seq,created_at,updated_at,deleted_at \
             ) VALUES($1,$2,$3,$4,$5,$6,NULL,'active',0,0,$7,$7,NULL)",
            &[
                &command.thread_id.as_str(),
                &request.tenant.as_str(),
                &request.deployment.as_str(),
                &request.actor.as_str(),
                &anchor_kind,
                &anchor_id,
                &now,
            ],
        )
        .await
        .map_err(|error| write_error("创建 native thread 失败", error))?;
    crate::thread_origin::record_new_native(
        transaction,
        command.thread_id.as_str(),
        crate::thread_origin::NativeOriginKind::BeginV1,
    )
    .await
    .map_err(origin_error)?;
    transaction
        .execute(
            "INSERT INTO public.thread_memberships(thread_id,user_id,created_at) \
             VALUES($1,$2,$3)",
            &[&command.thread_id.as_str(), &request.actor.as_str(), &now],
        )
        .await
        .map_err(|error| write_error("创建 thread membership 失败", error))?;
    Ok(())
}

async fn acquire_lease(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunRequest,
    runtime: &RuntimeLease,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<i64, ThreadDirectoryError> {
    let row = transaction
        .query_opt(
            "INSERT INTO public.thread_leases( \
               thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at \
             ) VALUES($1,$2,1,$3,$4,$3) \
             ON CONFLICT(thread_id) DO UPDATE SET \
               owner_id=excluded.owner_id, \
               fencing_token=CASE WHEN thread_leases.expires_at<=$3 \
                                  THEN thread_leases.fencing_token+1 \
                                  ELSE thread_leases.fencing_token END, \
               acquired_at=CASE WHEN thread_leases.expires_at<=$3 \
                                THEN $3 ELSE thread_leases.acquired_at END, \
               expires_at=$4,updated_at=$3 \
             WHERE (thread_leases.owner_id=$2 AND thread_leases.expires_at>$3) \
                OR (thread_leases.expires_at<=$3 \
                    AND thread_leases.fencing_token<9223372036854775807) \
             RETURNING fencing_token",
            &[
                &request.command.thread_id.as_str(),
                &runtime.owner_id,
                &now,
                &expires_at,
            ],
        )
        .await
        .map_err(|error| write_error("获取 thread lease 失败", error))?;
    let Some(row) = row else {
        return Err(ThreadDirectoryError::LeaseConflict);
    };
    row.try_get(0).map_err(|_| ThreadDirectoryError::Corrupt {
        field: "fencing_token",
    })
}

async fn database_now(
    transaction: &Transaction<'_>,
) -> Result<OffsetDateTime, ThreadDirectoryError> {
    transaction
        .query_one("SELECT now()", &[])
        .await
        .map_err(|error| unavailable("读取数据库时钟失败", error))?
        .try_get(0)
        .map_err(|_| ThreadDirectoryError::Corrupt {
            field: "database_now",
        })
}

fn anchor_matches(
    anchor: &ThreadRunAnchor,
    bot_id: &str,
    stored_kind: &str,
    stored_id: &str,
) -> bool {
    match anchor {
        ThreadRunAnchor::DirectBot => stored_kind == "direct_bot" && stored_id == bot_id,
        ThreadRunAnchor::Channel { channel_id } => {
            stored_kind == "channel" && stored_id == channel_id.as_str()
        }
    }
}

fn input_message_id(run_id: &str) -> String {
    format!("{run_id}:input")
}

fn checked_sequence(value: i64, field: &'static str) -> Result<u64, ThreadDirectoryError> {
    u64::try_from(value).map_err(|_| ThreadDirectoryError::Corrupt { field })
}

fn decode<T>(row: &tokio_postgres::Row, field: &'static str) -> Result<T, ThreadDirectoryError>
where
    for<'a> T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(field)
        .map_err(|_| ThreadDirectoryError::Corrupt { field })
}

fn writer_error(error: InfraError) -> ThreadDirectoryError {
    if crate::thread_history_writer::is_closed(&error) {
        return ThreadDirectoryError::NotVisible;
    }
    tracing::warn!(error=%error,"Thread history writer admission failed");
    match error {
        InfraError::Connect { .. } | InfraError::Query { .. } => ThreadDirectoryError::Unavailable,
        _ => ThreadDirectoryError::Corrupt {
            field: "thread_history_writer",
        },
    }
}

fn origin_error(error: InfraError) -> ThreadDirectoryError {
    tracing::warn!(error = %error, "Thread historical origin verification failed");
    match error {
        InfraError::Connect { .. } | InfraError::Query { .. } => ThreadDirectoryError::Unavailable,
        _ => ThreadDirectoryError::Corrupt {
            field: "thread_origin",
        },
    }
}

fn unavailable(context: &'static str, error: tokio_postgres::Error) -> ThreadDirectoryError {
    tracing::error!(
        sqlstate = error.code().map_or("none", SqlState::code),
        connection_closed = error.is_closed(),
        context,
        "native thread database operation failed"
    );
    ThreadDirectoryError::Unavailable
}

fn write_error(context: &'static str, error: tokio_postgres::Error) -> ThreadDirectoryError {
    if crate::thread_history_writer::is_closed_query(&error) {
        return ThreadDirectoryError::NotVisible;
    }
    tracing::error!(
        sqlstate = error.code().map_or("none", SqlState::code),
        connection_closed = error.is_closed(),
        context,
        "native thread transaction write failed"
    );
    match error.code() {
        Some(code) if code == &SqlState::UNIQUE_VIOLATION => ThreadDirectoryError::RequestConflict,
        Some(code) if code == &SqlState::FOREIGN_KEY_VIOLATION => ThreadDirectoryError::NotVisible,
        _ => ThreadDirectoryError::Unavailable,
    }
}

// V2 has its own accepted-intent/transaction path; no synthetic legacy request is built.
async fn apply_begin_v2(
    model_transaction: &crate::model_dataset::ModelDatasetTransaction<'_>,
    runtime: &RuntimeLease,
    request: &BeginThreadRunV2Request,
    materials: &[RunInputArtifactMaterial],
) -> Result<BeginOutcome, ThreadDirectoryError> {
    let transaction = model_transaction.as_transaction();
    // One same-transaction observation of the strict current schema, before any lock;
    // writer admission and the channel source below consume this proof.
    let schema = crate::thread_history_writer::CurrentWriterSchema::observe(transaction)
        .await
        .map_err(|error| match error {
            InfraError::RepositoryInvariant {
                code: "thread_origin_native_prefix_invalid",
            } => ThreadDirectoryError::Corrupt {
                field: "model_dataset_binding",
            },
            error => origin_error(error),
        })?;
    crate::model_runtime::validate_actor_v2(transaction, request).await?;
    skills::validate_v2_slugs(request)?;
    let command = &request.command;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&command.thread_id.as_str()],
        )
        .await
        .map_err(|error| unavailable("获取 thread transaction lock 失败", error))?;

    let existing_thread = load_thread_v2(transaction, request).await?;
    if existing_thread.is_some() {
        crate::thread_origin::observe_on(transaction, command.thread_id.as_str())
            .await
            .map_err(origin_error)?;
    }
    if existing_thread
        .as_ref()
        .is_some_and(|state| state.status == "deleted")
    {
        return Err(ThreadDirectoryError::NotVisible);
    }
    if existing_thread.is_some() {
        crate::model_runtime::validate_thread_v2(transaction, request).await?;
    }
    if let Some(receipt) = replay_existing_v2(model_transaction, request).await? {
        // Preserve historical replay's original authority checks; still reject damaged occupancy.
        checked_thread_occupancy(transaction, &command.thread_id).await?;
        return Ok(BeginOutcome::Replayed(receipt));
    }

    let now = database_now(transaction).await?;
    let state = match existing_thread {
        Some(state) => {
            if state.status != "active" {
                return Err(ThreadDirectoryError::NotVisible);
            }
            crate::model_runtime::validate_target_v2(transaction, request).await?;
            state
        }
        None => {
            if !ThreadIdentity::new(&request.deployment).owns(&command.thread_id) {
                return Err(ThreadDirectoryError::InvalidInput { field: "thread_id" });
            }
            crate::model_runtime::validate_target_v2(transaction, request).await?;
            insert_thread_v2(transaction, request, now).await?;
            ThreadState {
                status: "active".to_owned(),
                next_message_seq: 0,
                next_event_seq: 0,
            }
        }
    };

    schema
        .require_open(transaction, &command.thread_id)
        .await
        .map_err(writer_error)?;
    // Re-observe the original authority in a fresh statement after actual admission.
    // H is retained on this same transaction; it grants neither visibility nor a lease.
    // Check visible state before a competing lease can hide a damaged projection.
    let active = checked_thread_occupancy(transaction, &command.thread_id).await?;

    if matches!(&command.anchor, ThreadRunAnchor::Channel { .. }) {
        transaction
            .execute(
                "INSERT INTO public.thread_memberships(thread_id,user_id,created_at) \
                 VALUES($1,$2,$3) ON CONFLICT(thread_id,user_id) DO NOTHING",
                &[&command.thread_id.as_str(), &request.actor.as_str(), &now],
            )
            .await
            .map_err(|error| write_error("materialize channel thread membership", error))?;
    }

    let expires_at = now
        .checked_add(runtime.duration)
        .ok_or(ThreadDirectoryError::Corrupt {
            field: "thread_lease_expiry",
        })?;
    let fencing = acquire_lease_v2(transaction, request, runtime, now, expires_at).await?;

    if active {
        return Err(ThreadDirectoryError::LeaseConflict);
    }

    crate::model_runtime::validate_actor_v2(transaction, request).await?;
    crate::model_runtime::validate_target_v2(transaction, request).await?;
    let skill_snapshots = skills::resolve_v2(transaction, request).await?;
    let model_snapshot = crate::model_runtime::resolve_v2(transaction, request).await?;
    let dataset = model_transaction
        .verify_current_dataset()
        .await
        .map_err(map_dataset_error)?;
    crate::model_runtime::verify_accept_v2_current(
        transaction,
        request,
        &model_snapshot,
        &dataset,
        fencing,
    )
    .await?;
    artifact_refs::verify_current(
        transaction,
        &schema,
        (&request.deployment, &request.tenant),
        &request.actor,
        request.auth_generation.get(),
        &command.thread_id,
        materials,
    )
    .await?;
    let user_message_seq = state
        .next_message_seq
        .checked_add(skill_snapshots.len() as i64)
        .and_then(|sequence| sequence.checked_add(materials.len() as i64))
        .ok_or(ThreadDirectoryError::Corrupt {
            field: "next_message_seq",
        })?;
    let message_sequence = checked_sequence(user_message_seq, "next_message_seq")?;
    let event_sequence = checked_sequence(state.next_event_seq, "next_event_seq")?;
    let next_message_seq =
        user_message_seq
            .checked_add(1)
            .ok_or(ThreadDirectoryError::Corrupt {
                field: "next_message_seq",
            })?;
    let next_event_seq =
        state
            .next_event_seq
            .checked_add(1)
            .ok_or(ThreadDirectoryError::Corrupt {
                field: "next_event_seq",
            })?;

    let mut run = Run::queued(
        command.run_id.clone(),
        command.thread_id.clone(),
        command.bot_id.clone(),
        request.actor.clone(),
        true,
        FencingToken::new(fencing).map_err(|_| ThreadDirectoryError::Corrupt {
            field: "fencing_token",
        })?,
        now,
    );
    run.start(now).map_err(|_| ThreadDirectoryError::Corrupt {
        field: "run_transition",
    })?;
    let budget_row = transaction
        .query_opt(
            "SELECT currency,max_cost_micro_units FROM public.user_run_cost_budgets \
             WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3",
            &[
                &request.deployment.as_str(),
                &request.tenant.as_str(),
                &request.actor.as_str(),
            ],
        )
        .await
        .map_err(|error| unavailable("读取 run cost budget snapshot 失败", error))?;
    let (budget_currency, budget_max_cost_micro_units) = match budget_row {
        Some(row) => {
            let currency = row.try_get::<_, String>("currency").map_err(|_| {
                ThreadDirectoryError::Corrupt {
                    field: "budget_cost_currency",
                }
            })?;
            let amount = row.try_get::<_, i64>("max_cost_micro_units").map_err(|_| {
                ThreadDirectoryError::Corrupt {
                    field: "budget_max_cost_micro_units",
                }
            })?;
            if currency.len() != 3
                || !currency.bytes().all(|byte| byte.is_ascii_uppercase())
                || amount <= 0
            {
                return Err(ThreadDirectoryError::Corrupt {
                    field: "run_cost_budget",
                });
            }
            (Some(currency), Some(amount))
        }
        None => (None, None),
    };
    if budget_currency.is_some() || budget_max_cost_micro_units.is_some() {
        return Err(ThreadDirectoryError::InvalidInput {
            field: "custom_model_unpriced",
        });
    }
    let message_id = input_message_id(command.run_id.as_str());
    let content = skills::input_content_v2(command);
    let message = Message::new(
        MessageId::new(&message_id),
        command.thread_id.clone(),
        message_sequence,
        MessageRole::User,
        content.clone(),
        command.message.clone(),
        Some(command.run_id.clone()),
        Some(request.actor.clone()),
        now,
    );
    let event = RunEvent::new(
        command.run_id.clone(),
        0,
        command.thread_id.clone(),
        event_sequence,
        RunEventKind::Started,
        json!({
            "runId": command.run_id,
            "messageId": message_id,
            "botId": command.bot_id,
        }),
        now,
    );

    transaction
        .execute(
            "UPDATE public.threads SET next_message_seq=$2,next_event_seq=$3,updated_at=$4 \
             WHERE thread_id=$1",
            &[
                &command.thread_id.as_str(),
                &next_message_seq,
                &next_event_seq,
                &now,
            ],
        )
        .await
        .map_err(|error| write_error("推进 thread sequence 失败", error))?;
    transaction
        .execute(
            "INSERT INTO public.runs( \
               run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq, \
               terminal_event_seq,error_code,created_at,started_at,finished_at, \
               budget_cost_currency,budget_max_cost_micro_units \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,1,NULL,NULL,$8,$9,NULL,$10,$11)",
            &[
                &run.id().as_str(),
                &run.thread().as_str(),
                &run.bot().as_str(),
                &run.actor().as_str(),
                &run.foreground(),
                &run.status().as_str(),
                &run.fencing().get(),
                &run.created_at(),
                &run.started_at(),
                &budget_currency,
                &budget_max_cost_micro_units,
            ],
        )
        .await
        .map_err(|error| write_error("写 running run 失败", error))?;
    crate::model_runtime::insert_v2(transaction, request, &model_snapshot, &dataset, now).await?;
    for (index, snapshot) in skill_snapshots.iter().enumerate() {
        let skill_message_id = format!("{}:selected_skill:{index}", command.run_id);
        let content = json!({"text": snapshot.instructions, "selectedSkillSlug": snapshot.slug});
        transaction
            .execute(
                "INSERT INTO public.messages( \
               message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at \
             ) VALUES($1,$2,$3,'system',$4,$5,$6,$7,$8)",
                &[
                    &skill_message_id,
                    &command.thread_id.as_str(),
                    &(state.next_message_seq + index as i64),
                    &content,
                    &snapshot.instructions,
                    &command.run_id.as_str(),
                    &request.actor.as_str(),
                    &now,
                ],
            )
            .await
            .map_err(|error| write_error("写 selected skill snapshot 失败", error))?;
    }
    artifact_refs::insert_messages(
        transaction,
        &command.run_id,
        &command.thread_id,
        &request.actor,
        state
            .next_message_seq
            .checked_add(skill_snapshots.len() as i64)
            .ok_or(ThreadDirectoryError::Corrupt {
                field: "next_message_seq",
            })?,
        now,
        materials,
    )
    .await?;
    transaction
        .execute(
            "INSERT INTO public.messages( \
               message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &message.id().as_str(),
                &message.thread().as_str(),
                &(message.sequence() as i64),
                &message.role().as_str(),
                message.content(),
                &message.search_text(),
                &message.run().map(|value| value.as_str()),
                &message.actor().map(|value| value.as_str()),
                &message.created_at(),
            ],
        )
        .await
        .map_err(|error| write_error("写 initial message 失败", error))?;
    transaction
        .execute(
            "INSERT INTO public.run_events( \
               run_id,seq,thread_id,event_seq,event_type,payload,terminal,created_at \
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &event.run().as_str(),
                &(event.sequence() as i64),
                &event.thread().as_str(),
                &(event.thread_sequence() as i64),
                &event.kind().as_str(),
                event.payload(),
                &event.kind().is_terminal(),
                &event.created_at(),
            ],
        )
        .await
        .map_err(|error| write_error("写 run started event 失败", error))?;
    let outbox_id = format!("{}:agent_run_dispatch", command.run_id);
    let outbox_payload = json!({
        "runId": command.run_id,
        "threadId": command.thread_id,
        "eventSequence": event_sequence,
    });
    transaction
        .execute(
            "INSERT INTO public.outbox( \
               outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload, \
               available_at,created_at,updated_at \
             ) VALUES($1,'thread',$2,$3,'agent_run_dispatch','internal',$4,$5,$5,$5)",
            &[
                &outbox_id,
                &command.thread_id.as_str(),
                &(event_sequence as i64),
                &outbox_payload,
                &now,
            ],
        )
        .await
        .map_err(|error| write_error("写 replay-safe dispatch outbox 失败", error))?;
    if matches!(&command.anchor, ThreadRunAnchor::Channel { .. }) {
        crate::channel_activity::record_from_message(&schema, message.id())
            .await
            .map_err(writer_error)?;
    }
    transaction
        .query_one("SELECT pg_notify('openbot_thread_events','')", &[])
        .await
        .map_err(|error| unavailable("提交 thread wakeup 失败", error))?;

    Ok(BeginOutcome::Created(ThreadRunStarted {
        thread_id: command.thread_id.clone(),
        run_id: command.run_id.clone(),
        message_sequence,
        event_sequence,
        replayed: false,
    }))
}

async fn load_thread_v2(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunV2Request,
) -> Result<Option<ThreadState>, ThreadDirectoryError> {
    let command = &request.command;
    let row = transaction
        .query_opt(
            "SELECT t.deployment_id,t.tenant_id,t.anchor_kind,t.anchor_id,t.status, \
                    t.next_message_seq,t.next_event_seq, \
                    CASE WHEN t.anchor_kind='channel' THEN EXISTS( \
                      SELECT 1 FROM public.channel_memberships cm \
                      WHERE cm.channel_id=t.anchor_id AND cm.user_id=$2 \
                    ) ELSE EXISTS( \
                      SELECT 1 FROM public.thread_memberships tm \
                      WHERE tm.thread_id=t.thread_id AND tm.user_id=$2 \
                    ) END AS member \
             FROM public.threads t WHERE t.thread_id=$1 FOR UPDATE OF t",
            &[&command.thread_id.as_str(), &request.actor.as_str()],
        )
        .await
        .map_err(|error| unavailable("读取并锁定 thread 失败", error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let deployment: String = decode(&row, "deployment_id")?;
    let tenant: String = decode(&row, "tenant_id")?;
    let anchor_kind: String = decode(&row, "anchor_kind")?;
    let anchor_id: String = decode(&row, "anchor_id")?;
    let member: bool = decode(&row, "member")?;
    if deployment != request.deployment.as_str() || tenant != request.tenant.as_str() || !member {
        return Err(ThreadDirectoryError::NotVisible);
    }
    if !anchor_matches(
        &command.anchor,
        command.bot_id.as_str(),
        &anchor_kind,
        &anchor_id,
    ) {
        return Err(ThreadDirectoryError::RequestConflict);
    }
    Ok(Some(ThreadState {
        status: decode(&row, "status")?,
        next_message_seq: decode(&row, "next_message_seq")?,
        next_event_seq: decode(&row, "next_event_seq")?,
    }))
}

async fn insert_thread_v2(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunV2Request,
    now: OffsetDateTime,
) -> Result<(), ThreadDirectoryError> {
    crate::thread_origin::current_native_actor(
        transaction,
        request.actor.as_str(),
        request.auth_generation,
    )
    .await
    .map_err(origin_error)?
    .ok_or(ThreadDirectoryError::NotVisible)?;
    let command = &request.command;
    let (anchor_kind, anchor_id) = match &command.anchor {
        ThreadRunAnchor::DirectBot => ("direct_bot", command.bot_id.as_str()),
        ThreadRunAnchor::Channel { channel_id } => ("channel", channel_id.as_str()),
    };
    transaction
        .execute(
            "INSERT INTO public.threads( \
               thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status, \
               next_message_seq,next_event_seq,created_at,updated_at,deleted_at \
             ) VALUES($1,$2,$3,$4,$5,$6,NULL,'active',0,0,$7,$7,NULL)",
            &[
                &command.thread_id.as_str(),
                &request.tenant.as_str(),
                &request.deployment.as_str(),
                &request.actor.as_str(),
                &anchor_kind,
                &anchor_id,
                &now,
            ],
        )
        .await
        .map_err(|error| write_error("创建 native thread 失败", error))?;
    crate::thread_origin::record_new_native(
        transaction,
        command.thread_id.as_str(),
        crate::thread_origin::NativeOriginKind::BeginV2,
    )
    .await
    .map_err(origin_error)?;
    transaction
        .execute(
            "INSERT INTO public.thread_memberships(thread_id,user_id,created_at) \
             VALUES($1,$2,$3)",
            &[&command.thread_id.as_str(), &request.actor.as_str(), &now],
        )
        .await
        .map_err(|error| write_error("创建 thread membership 失败", error))?;
    Ok(())
}

async fn acquire_lease_v2(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunV2Request,
    runtime: &RuntimeLease,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<i64, ThreadDirectoryError> {
    let row = transaction
        .query_opt(
            "INSERT INTO public.thread_leases( \
               thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at \
             ) VALUES($1,$2,1,$3,$4,$3) \
             ON CONFLICT(thread_id) DO UPDATE SET \
               owner_id=excluded.owner_id, \
               fencing_token=CASE WHEN thread_leases.expires_at<=$3 \
                                  THEN thread_leases.fencing_token+1 \
                                  ELSE thread_leases.fencing_token END, \
               acquired_at=CASE WHEN thread_leases.expires_at<=$3 \
                                THEN $3 ELSE thread_leases.acquired_at END, \
               expires_at=$4,updated_at=$3 \
             WHERE (thread_leases.owner_id=$2 AND thread_leases.expires_at>$3) \
                OR (thread_leases.expires_at<=$3 \
                    AND thread_leases.fencing_token<9223372036854775807) \
             RETURNING fencing_token",
            &[
                &request.command.thread_id.as_str(),
                &runtime.owner_id,
                &now,
                &expires_at,
            ],
        )
        .await
        .map_err(|error| write_error("获取 thread lease 失败", error))?;
    let Some(row) = row else {
        return Err(ThreadDirectoryError::LeaseConflict);
    };
    row.try_get(0).map_err(|_| ThreadDirectoryError::Corrupt {
        field: "fencing_token",
    })
}

async fn replay_existing_v2(
    model_transaction: &crate::model_dataset::ModelDatasetTransaction<'_>,
    request: &BeginThreadRunV2Request,
) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
    let transaction = model_transaction.as_transaction();
    let command = &request.command;
    let row=transaction.query_opt("SELECT r.thread_id,r.bot_id,r.actor_id,r.foreground,r.created_at,
        m.seq AS message_seq,m.content,m.role,m.thread_id AS input_thread,m.actor_id AS input_actor,
        e.event_seq,o.outbox_id
        FROM public.runs r LEFT JOIN public.messages m ON m.message_id=$2 AND m.run_id=r.run_id
        LEFT JOIN public.run_events e ON e.run_id=r.run_id AND e.seq=0 AND e.event_type='started'
          AND e.thread_id=r.thread_id AND NOT e.terminal
        LEFT JOIN public.outbox o ON o.outbox_id=r.run_id||':agent_run_dispatch' AND o.aggregate_kind='thread'
          AND o.aggregate_id=r.thread_id AND o.destination='agent_run_dispatch' AND o.delivery_class='internal'
        WHERE r.run_id=$1", &[&command.run_id.as_str(),&input_message_id(command.run_id.as_str())])
        .await.map_err(|_|ThreadDirectoryError::Unavailable)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if decode::<String>(&row, "thread_id")? != command.thread_id.as_str()
        || decode::<String>(&row, "bot_id")? != command.bot_id.as_str()
        || decode::<String>(&row, "actor_id")? != request.actor.as_str()
        || !decode::<bool>(&row, "foreground")?
        || decode::<Option<Value>>(&row, "content")?.as_ref()
            != Some(&skills::input_content_v2(command))
    {
        return Err(ThreadDirectoryError::RequestConflict);
    }
    if decode::<Option<String>>(&row, "role")?.as_deref() != Some("user")
        || decode::<Option<String>>(&row, "input_thread")?.as_deref()
            != Some(command.thread_id.as_str())
        || decode::<Option<String>>(&row, "input_actor")?.as_deref() != Some(request.actor.as_str())
        || decode::<Option<String>>(&row, "outbox_id")?.is_none()
    {
        return Err(ThreadDirectoryError::Corrupt {
            field: "idempotent_message",
        });
    }
    // Current target authorization remains necessary, but no current connection/secret is
    // reselected for an exact receipt. Historical definition and key references stay fixed.
    crate::model_runtime::validate_target_v2(transaction, request).await?;
    let dataset = model_transaction
        .verify_current_dataset()
        .await
        .map_err(map_dataset_error)?;
    crate::model_runtime::verify_v2_replay_snapshot(
        transaction,
        request,
        &dataset,
        decode(&row, "created_at")?,
    )
    .await?;
    let message_sequence = checked_sequence(
        decode::<Option<i64>>(&row, "message_seq")?.ok_or(ThreadDirectoryError::Corrupt {
            field: "idempotent_message",
        })?,
        "idempotent_message",
    )?;
    let event_sequence = checked_sequence(
        decode::<Option<i64>>(&row, "event_seq")?.ok_or(ThreadDirectoryError::Corrupt {
            field: "idempotent_event",
        })?,
        "idempotent_event",
    )?;
    Ok(Some(ThreadRunStarted {
        thread_id: command.thread_id.clone(),
        run_id: command.run_id.clone(),
        message_sequence,
        event_sequence,
        replayed: true,
    }))
}
