//! Native thread ID 与可见性用例（v3 §4.1 / §4.3，API ledger T-API-0035/0036）。

use std::time::{Duration, Instant};

use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRecordMetadata, MAX_ARTIFACT_BYTES, canonical_artifact_uuid_v7,
    is_valid_artifact_identity, is_valid_artifact_sha256,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{
    BeginThreadRun, BeginThreadRunV2, CancelThreadRun, MAX_THREAD_MESSAGE_BYTES,
    ThreadConversationSnapshot, ThreadHistory, ThreadMinted, ThreadRunAnchor,
    ThreadRunCancellation, ThreadRunStarted, ThreadStatus,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ThreadId;
use openbot_contracts::ids::thread::ThreadIdentity;

use sha2::{Digest, Sha256};

use crate::artifacts::{ArtifactAdministration, require_current_request_binding};
use crate::ports::{
    BeginThreadRunRequest, BeginThreadRunV2Request, CancelThreadRunRequest,
    ChannelActivitySubscription, RunInputArtifactMaterial, ThreadConversationRequest,
    ThreadDirectory, ThreadEventSubscription, ThreadHistoryRequest,
};
use crate::service::AppEventStream;

/// 为权威 deployment 铸造一个 thread ID。
pub async fn mint_thread_id<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
) -> Result<ThreadMinted, AppError> {
    let thread_id = directory
        .mint_thread_id(auth.deployment())
        .await
        .map_err(|error| error.into_app_error())?;
    Ok(ThreadMinted { thread_id })
}

/// 查询当前权威 scope 是否仍可产生一条 native thread。
///
/// UUID 外形检查保留固定上游输入契约；ownership 不能参与判定，因为另一个 deployment 或
/// 旧版铸造的 UUID 仍可能经迁移属于当前 actor。不存在、已删除与不可见统一 `known:false`。
pub async fn get_thread_status<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread_id: &ThreadId,
) -> Result<ThreadStatus, AppError> {
    if !ThreadIdentity::is_plausible(thread_id) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    let known = directory
        .thread_known(auth.deployment(), auth.tenant(), auth.actor(), thread_id)
        .await
        .map_err(|error| error.into_app_error())?;
    Ok(ThreadStatus { known })
}

/// 校验 caller-controlled 字段后，把一次 foreground turn 交给唯一事务端口。
pub async fn begin_thread_run<D: ThreadDirectory>(
    directory: &D,
    artifacts: &dyn ArtifactAdministration,
    auth: &AuthContext,
    mut command: BeginThreadRun,
) -> Result<ThreadRunStarted, AppError> {
    if !ThreadIdentity::is_plausible(&command.thread_id) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if command.run_id.as_str().is_empty() {
        return Err(AppError::MalformedPayload { field: "run_id" });
    }
    if command.bot_id.as_str().is_empty() {
        return Err(AppError::MalformedPayload { field: "bot_id" });
    }
    if matches!(
        &command.anchor,
        ThreadRunAnchor::Channel { channel_id } if channel_id.as_str().is_empty()
    ) {
        return Err(AppError::MalformedPayload {
            field: "channel_id",
        });
    }
    if command.message.is_empty()
        || command.message.as_bytes().contains(&0)
        || command.message.len() > MAX_THREAD_MESSAGE_BYTES
    {
        return Err(AppError::MalformedPayload { field: "message" });
    }
    if !openbot_contracts::command::valid_selected_skill_slugs(&command.selected_skill_slugs) {
        return Err(AppError::MalformedPayload {
            field: "selected_skill_slugs",
        });
    }
    if command
        .model_selection
        .as_ref()
        .is_some_and(|selection| !selection.is_valid())
    {
        return Err(AppError::MalformedPayload {
            field: "model_selection",
        });
    }
    normalize_artifact_refs(&mut command.artifact_refs)?;
    let request = BeginThreadRunRequest {
        auth_generation: auth.auth_generation(),
        deployment: auth.deployment().clone(),
        tenant: auth.tenant().clone(),
        actor: auth.actor().clone(),
        command,
    };
    if request.command.artifact_refs.is_empty() {
        return directory
            .begin_thread_run(request)
            .await
            .map_err(|error| error.into_app_error());
    }
    require_current_request_binding(auth).await?;
    let replay = directory.observe_begin_replay(request.clone()).await;
    require_current_request_binding(auth).await?;
    if let Some(receipt) = replay.map_err(|error| error.into_app_error())? {
        return Ok(receipt);
    }
    let materials =
        preread_artifact_materials(artifacts, auth, &request.command.artifact_refs).await?;
    let result = directory
        .begin_thread_run_with_artifacts(request, materials)
        .await;
    require_current_request_binding(auth).await?;
    result.map_err(|error| error.into_app_error())
}

/// 核验 v2 原值、消息及技能预算，再交唯一真实事务端口；不降为 v1。
pub async fn begin_thread_run_v2<D: ThreadDirectory>(
    directory: &D,
    artifacts: &dyn ArtifactAdministration,
    auth: &AuthContext,
    mut command: BeginThreadRunV2,
) -> Result<ThreadRunStarted, AppError> {
    if !ThreadIdentity::is_plausible(&command.thread_id) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if command.run_id.as_str().is_empty() {
        return Err(AppError::MalformedPayload { field: "run_id" });
    }
    if command.bot_id.as_str().is_empty() {
        return Err(AppError::MalformedPayload { field: "bot_id" });
    }
    if matches!(&command.anchor, ThreadRunAnchor::Channel { channel_id } if channel_id.as_str().is_empty())
    {
        return Err(AppError::MalformedPayload {
            field: "channel_id",
        });
    }
    if command.message.is_empty()
        || command.message.as_bytes().contains(&0)
        || command.message.len() > MAX_THREAD_MESSAGE_BYTES
    {
        return Err(AppError::MalformedPayload { field: "message" });
    }
    if !openbot_contracts::command::valid_selected_skill_slugs(&command.selected_skill_slugs) {
        return Err(AppError::MalformedPayload {
            field: "selected_skill_slugs",
        });
    }
    use openbot_contracts::versioned_model_selection::{
        ModelSelectionIntentSource, VersionedRunModelSelection,
    };
    if !VersionedRunModelSelection::V2(command.model_selection.clone()).is_valid()
        || command.model_selection.source() != ModelSelectionIntentSource::Custom
    {
        return Err(AppError::MalformedPayload {
            field: "model_selection",
        });
    }
    normalize_artifact_refs(&mut command.artifact_refs)?;
    let request = BeginThreadRunV2Request {
        auth_generation: auth.auth_generation(),
        deployment: auth.deployment().clone(),
        tenant: auth.tenant().clone(),
        actor: auth.actor().clone(),
        command,
    };
    if request.command.artifact_refs.is_empty() {
        return directory
            .begin_thread_run_v2(request)
            .await
            .map_err(|error| error.into_app_error());
    }
    require_current_request_binding(auth).await?;
    let replay = directory.observe_begin_replay_v2(request.clone()).await;
    require_current_request_binding(auth).await?;
    if let Some(receipt) = replay.map_err(|error| error.into_app_error())? {
        return Ok(receipt);
    }
    let materials =
        preread_artifact_materials(artifacts, auth, &request.command.artifact_refs).await?;
    let result = directory
        .begin_thread_run_with_artifacts_v2(request, materials)
        .await;
    require_current_request_binding(auth).await?;
    result.map_err(|error| error.into_app_error())
}

fn artifact_refs_malformed() -> AppError {
    AppError::MalformedPayload {
        field: "artifact_refs",
    }
}

fn artifact_input_unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "artifacts",
    }
}

fn normalize_artifact_refs(refs: &mut Vec<String>) -> Result<(), AppError> {
    if refs.len() > 8 {
        return Err(artifact_refs_malformed());
    }
    let mut canonical = Vec::with_capacity(refs.len());
    for id in refs.iter() {
        let id = canonical_artifact_uuid_v7(id).ok_or_else(artifact_refs_malformed)?;
        if canonical.contains(&id) {
            return Err(artifact_refs_malformed());
        }
        canonical.push(id);
    }
    *refs = canonical;
    Ok(())
}

fn require_preread_time(deadline: Instant) -> Result<(), AppError> {
    if Instant::now() >= deadline {
        Err(artifact_input_unavailable())
    } else {
        Ok(())
    }
}

async fn preread_before<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    require_preread_time(deadline)?;
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| artifact_input_unavailable())?
}

fn validate_input_metadata(
    auth: &AuthContext,
    id: &str,
    record: &ArtifactRecordMetadata,
) -> Result<(), AppError> {
    if record.artifact_id != id
        || &record.deployment_id != auth.deployment()
        || &record.tenant_id != auth.tenant()
        || &record.owner_actor_id != auth.actor()
        || !is_valid_artifact_identity(record.deployment_id.as_str())
        || !is_valid_artifact_identity(record.tenant_id.as_str())
        || !is_valid_artifact_identity(record.owner_actor_id.as_str())
        || !is_valid_artifact_identity(&record.dataset_id)
        || !ThreadIdentity::is_plausible(&record.source_thread_id)
        || !is_valid_artifact_identity(record.source_run_id.as_str())
        || !is_valid_artifact_identity(&record.media_type)
        || !is_valid_artifact_sha256(&record.sha256)
        || record.byte_length > MAX_ARTIFACT_BYTES
    {
        return Err(artifact_input_unavailable());
    }
    Ok(())
}

fn input_media_is_text(media_type: &str) -> bool {
    let essence = media_type
        .split(';')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    essence.starts_with("text/") || essence == "application/json"
}

async fn preread_artifact_materials(
    artifacts: &dyn ArtifactAdministration,
    auth: &AuthContext,
    refs: &[String],
) -> Result<Vec<RunInputArtifactMaterial>, AppError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or_else(artifact_input_unavailable)?;
    let mut observations = Vec::with_capacity(refs.len());
    for id in refs {
        require_preread_time(deadline)?;
        preread_before(deadline, require_current_request_binding(auth)).await?;
        let result = preread_before(
            deadline,
            artifacts.observe_run_input_metadata_current(auth, id, deadline),
        )
        .await;
        // Keep even an error intact until the original Host postcheck has completed.
        preread_before(deadline, require_current_request_binding(auth)).await?;
        require_preread_time(deadline)?;
        let observation = result?;
        let ArtifactMetadata::Available(record) = observation.metadata else {
            return Err(AppError::NotVisible);
        };
        observations.push((record, observation.cleanup_armed));
    }
    // Finish every reference's current visibility/status check before either refusal below.
    for (id, (record, _)) in refs.iter().zip(&observations) {
        validate_input_metadata(auth, id, record)?;
    }
    if observations.iter().any(|(_, armed)| *armed) {
        return Err(artifact_input_unavailable());
    }
    let mut text_bytes = 0_u64;
    for (record, _) in &observations {
        if input_media_is_text(&record.media_type) {
            if record.byte_length > 256 * 1024 {
                return Err(artifact_refs_malformed());
            }
            text_bytes = text_bytes
                .checked_add(record.byte_length)
                .ok_or_else(artifact_refs_malformed)?;
            if text_bytes > 1024 * 1024 {
                return Err(artifact_refs_malformed());
            }
        }
    }
    let mut materials = Vec::with_capacity(observations.len());
    for (record, _) in observations {
        require_preread_time(deadline)?;
        let body = if input_media_is_text(&record.media_type) {
            preread_before(deadline, require_current_request_binding(auth)).await?;
            let result = preread_before(
                deadline,
                artifacts.read_host_bound_chunk(auth, &record.artifact_id),
            )
            .await;
            preread_before(deadline, require_current_request_binding(auth)).await?;
            require_preread_time(deadline)?;
            let bytes = result?.handoff(auth)?;
            require_preread_time(deadline)?;
            if u64::try_from(bytes.len()).ok() != Some(record.byte_length)
                || format!("{:x}", Sha256::digest(&bytes)) != record.sha256
            {
                return Err(artifact_input_unavailable());
            }
            let text = String::from_utf8(bytes).map_err(|_| artifact_input_unavailable())?;
            require_preread_time(deadline)?;
            Some(text)
        } else {
            None
        };
        materials.push(RunInputArtifactMaterial {
            artifact_id: record.artifact_id,
            dataset_id: record.dataset_id,
            sha256: record.sha256,
            media_type: record.media_type,
            byte_length: record.byte_length,
            source_thread_id: record.source_thread_id,
            source_run_id: record.source_run_id,
            body,
        });
    }
    require_preread_time(deadline)?;
    Ok(materials)
}

/// Validate public identities, then persist cancellation through the single authority-aware port.
pub async fn cancel_thread_run<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    command: CancelThreadRun,
) -> Result<ThreadRunCancellation, AppError> {
    if !ThreadIdentity::is_plausible(&command.thread_id) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if command.run_id.as_str().is_empty() || command.run_id.as_str().as_bytes().contains(&0) {
        return Err(AppError::MalformedPayload { field: "run_id" });
    }
    directory
        .cancel_thread_run(CancelThreadRunRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            command,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// 建立 scope-aware durable thread event stream。
pub async fn subscribe_thread_events<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread: ThreadId,
    after_event_sequence: Option<u64>,
) -> Result<AppEventStream, AppError> {
    if !ThreadIdentity::is_plausible(&thread) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if after_event_sequence.is_some_and(|value| i64::try_from(value).is_err()) {
        return Err(AppError::MalformedPayload {
            field: "after_event_sequence",
        });
    }
    directory
        .subscribe_thread_events(ThreadEventSubscription {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            thread,
            after_event_sequence,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Establish an authority-scoped channel activity stream.
pub async fn subscribe_channel_activity<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
) -> Result<AppEventStream, AppError> {
    directory
        .subscribe_channel_activity(ChannelActivitySubscription {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// 读取 scope-aware durable history；未知/不可见/已删除由 port 统一投影为空列表。
pub async fn get_thread_history<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread: ThreadId,
) -> Result<ThreadHistory, AppError> {
    if !ThreadIdentity::is_plausible(&thread) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    directory
        .thread_history(ThreadHistoryRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            thread,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Read an atomic history/foreground/cursor snapshot for gap-free realtime attachment.
pub async fn get_thread_conversation<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread: ThreadId,
) -> Result<ThreadConversationSnapshot, AppError> {
    if !ThreadIdentity::is_plausible(&thread) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    directory
        .thread_conversation(ThreadConversationRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            thread,
        })
        .await
        .map_err(|error| error.into_app_error())
}

#[cfg(test)]
#[path = "run_reconciliation_tests.rs"]
mod reconciliation_tests;

#[cfg(test)]
#[path = "run_effect_receipts_tests.rs"]
mod effect_receipts_tests;

/// Read immutable positive evidence without changing the original Unknown or its occupancy.
pub async fn get_run_effect_receipts<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread: ThreadId,
    run: openbot_contracts::ids::RunId,
    after: Option<openbot_contracts::reconciliation::RunReconciliationCursor>,
    limit: Option<u32>,
) -> Result<openbot_contracts::reconciliation::RunEffectReceiptsSnapshot, AppError> {
    use openbot_contracts::reconciliation::{
        MAX_RUN_RECONCILIATION_RESPONSE_BYTES, RunReconciliationCursor, valid_reconciliation_id,
        validate_page,
    };
    if !ThreadIdentity::is_plausible(&thread) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if !valid_reconciliation_id(run.as_str()) {
        return Err(AppError::MalformedPayload { field: "run_id" });
    }
    let limit = validate_page(after, limit)?;
    let snapshot = directory
        .run_effect_receipts(crate::ports::RunEffectReceiptsRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
            thread: thread.clone(),
            run: run.clone(),
            after,
            limit,
        })
        .await
        .map_err(|error| error.into_app_error())?;
    let unavailable = || AppError::DependencyUnavailable {
        dependency: "thread_directory",
    };
    if snapshot.thread_id != thread
        || snapshot.run_id != run
        || snapshot.terminal_event_sequence > i64::MAX as u64
        || snapshot.receipts.len() > limit as usize
    {
        return Err(unavailable());
    }
    let mut previous = after;
    for receipt in &snapshot.receipts {
        let cursor = RunReconciliationCursor {
            call_sequence: receipt.call_sequence,
            attempt_sequence: receipt.attempt_sequence,
        };
        if !cursor.is_valid()
            || previous.is_some_and(|value| cursor <= value)
            || !valid_reconciliation_id(&receipt.receipt_id)
            || !valid_reconciliation_id(&receipt.tool_call_id)
            || !valid_reconciliation_id(&receipt.attempt_id)
        {
            return Err(unavailable());
        }
        previous = Some(cursor);
    }
    if snapshot.next.is_some()
        && (snapshot.receipts.len() != limit as usize || snapshot.next != previous)
    {
        return Err(unavailable());
    }
    // Bound identities and collection length before allocating the serialized response.
    if serde_json::to_vec(&snapshot)
        .map_err(|_| unavailable())?
        .len()
        > MAX_RUN_RECONCILIATION_RESPONSE_BYTES
    {
        return Err(unavailable());
    }
    Ok(snapshot)
}

/// Read current actor-owned durable Unknown facts without authorizing any follow-up effect.
pub async fn get_run_reconciliation<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread: ThreadId,
    run: openbot_contracts::ids::RunId,
    after: Option<openbot_contracts::reconciliation::RunReconciliationCursor>,
    limit: Option<u32>,
) -> Result<openbot_contracts::reconciliation::RunReconciliationSnapshot, AppError> {
    use openbot_contracts::reconciliation::{
        MAX_RUN_RECONCILIATION_RESPONSE_BYTES, RunReconciliationCursor, valid_reconciliation_id,
        validate_page,
    };
    if !ThreadIdentity::is_plausible(&thread) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if !valid_reconciliation_id(run.as_str()) {
        return Err(AppError::MalformedPayload { field: "run_id" });
    }
    let limit = validate_page(after, limit)?;
    let snapshot = directory
        .run_reconciliation(crate::ports::RunReconciliationRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
            thread: thread.clone(),
            run: run.clone(),
            after,
            limit,
        })
        .await
        .map_err(|error| error.into_app_error())?;
    let unavailable = || AppError::DependencyUnavailable {
        dependency: "thread_directory",
    };
    if snapshot.thread_id != thread
        || snapshot.run_id != run
        || snapshot.terminal_event_sequence > i64::MAX as u64
        || snapshot.attempts.len() > limit as usize
    {
        return Err(unavailable());
    }
    let mut previous = after;
    for attempt in &snapshot.attempts {
        let cursor = RunReconciliationCursor {
            call_sequence: attempt.call_sequence,
            attempt_sequence: attempt.attempt_sequence,
        };
        if !cursor.is_valid()
            || previous.is_some_and(|value| cursor <= value)
            || !valid_reconciliation_id(&attempt.tool_call_id)
            || !valid_reconciliation_id(&attempt.attempt_id)
        {
            return Err(unavailable());
        }
        previous = Some(cursor);
    }
    if snapshot.next.is_some()
        && (snapshot.attempts.len() != limit as usize || snapshot.next != previous)
    {
        return Err(unavailable());
    }
    // Strings and collection lengths were checked before allocating serialized bytes.
    let bytes = serde_json::to_vec(&snapshot).map_err(|_| unavailable())?;
    if bytes.len() > MAX_RUN_RECONCILIATION_RESPONSE_BYTES {
        return Err(unavailable());
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

    use super::*;
    use crate::ports::ThreadDirectoryError;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct KnownCall {
        deployment: DeploymentId,
        tenant: TenantId,
        actor: ActorId,
        thread: ThreadId,
    }

    struct FakeDirectory {
        minted: ThreadId,
        known: Result<bool, ThreadDirectoryError>,
        mint_deployments: Mutex<Vec<DeploymentId>>,
        known_calls: Mutex<Vec<KnownCall>>,
    }

    impl FakeDirectory {
        fn new(known: Result<bool, ThreadDirectoryError>) -> Self {
            Self {
                minted: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
                known,
                mint_deployments: Mutex::new(Vec::new()),
                known_calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ThreadDirectory for FakeDirectory {
        async fn mint_thread_id(
            &self,
            deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            self.mint_deployments
                .lock()
                .expect("fake lock")
                .push(deployment.clone());
            Ok(self.minted.clone())
        }

        async fn thread_known(
            &self,
            deployment: &DeploymentId,
            tenant: &TenantId,
            actor: &ActorId,
            thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            self.known_calls.lock().expect("fake lock").push(KnownCall {
                deployment: deployment.clone(),
                tenant: tenant.clone(),
                actor: actor.clone(),
                thread: thread.clone(),
            });
            self.known
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep-authoritative"),
            TenantId::new("tenant-authoritative"),
            ActorId::new("actor-authoritative"),
            [Role::User],
            AuthGeneration::new(7),
            false,
        )
    }

    #[tokio::test]
    async fn mint_uses_the_authoritative_deployment_and_returns_the_port_id() {
        let directory = FakeDirectory::new(Ok(false));
        let reply = mint_thread_id(&directory, &auth()).await.unwrap();
        assert_eq!(reply.thread_id, directory.minted);
        assert_eq!(
            directory
                .mint_deployments
                .lock()
                .expect("fake lock")
                .as_slice(),
            &[DeploymentId::new("dep-authoritative")]
        );
    }

    #[tokio::test]
    async fn status_uses_all_three_authoritative_scope_axes() {
        let directory = FakeDirectory::new(Ok(true));
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        assert!(
            get_thread_status(&directory, &auth(), &thread)
                .await
                .unwrap()
                .known
        );
        assert_eq!(
            directory.known_calls.lock().expect("fake lock").as_slice(),
            &[KnownCall {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                thread,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_id_is_rejected_before_the_directory_is_touched() {
        let directory = FakeDirectory::new(Ok(true));
        let error = get_thread_status(&directory, &auth(), &ThreadId::new("not-a-uuid"))
            .await
            .unwrap_err();
        assert_eq!(error, AppError::MalformedPayload { field: "thread_id" });
        assert!(directory.known_calls.lock().expect("fake lock").is_empty());
    }

    #[tokio::test]
    async fn directory_failure_is_a_stable_dependency_error() {
        let directory = FakeDirectory::new(Err(ThreadDirectoryError::Unavailable));
        let error = get_thread_status(
            &directory,
            &auth(),
            &ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AppError::DependencyUnavailable {
                dependency: "thread_directory"
            }
        );
    }

    struct BeginDirectory {
        result: Result<ThreadRunStarted, ThreadDirectoryError>,
        calls: Mutex<Vec<BeginThreadRunRequest>>,
        v2_calls: Mutex<Vec<BeginThreadRunV2Request>>,
    }

    #[async_trait]
    impl ThreadDirectory for BeginDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn begin_thread_run(
            &self,
            request: BeginThreadRunRequest,
        ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
            self.calls.lock().expect("fake lock").push(request);
            self.result.clone()
        }

        async fn begin_thread_run_v2(
            &self,
            request: BeginThreadRunV2Request,
        ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
            self.v2_calls.lock().expect("fake v2 lock").push(request);
            self.result.clone()
        }
    }

    fn begin_command() -> BeginThreadRun {
        BeginThreadRun {
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            artifact_refs: Vec::new(),
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
            bot_id: openbot_contracts::ids::BotId::new("bot-1"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "hello".to_owned(),
        }
    }

    fn begin_directory(result: Result<ThreadRunStarted, ThreadDirectoryError>) -> BeginDirectory {
        BeginDirectory {
            result,
            calls: Mutex::new(Vec::new()),
            v2_calls: Mutex::new(Vec::new()),
        }
    }

    fn begin_v2_command() -> BeginThreadRunV2 {
        use openbot_contracts::versioned_model_selection::{
            ModelSelectionIntentSource, RunModelSelectionV2,
        };
        let old = begin_command();
        BeginThreadRunV2 {
            model_selection: RunModelSelectionV2::new(
                ModelSelectionIntentSource::Custom,
                "abcdef12-abcd-4bcd-8abc-abcdef123456".to_owned(),
                7,
                "custom:abcdef12-abcd-4bcd-8abc-abcdef123456".to_owned(),
                9,
            )
            .unwrap(),
            thread_id: old.thread_id,
            run_id: old.run_id,
            bot_id: old.bot_id,
            anchor: old.anchor,
            message: old.message,
            selected_skill_slugs: vec!["one".to_owned(), "two".to_owned()],
            artifact_refs: Vec::new(),
        }
    }

    #[tokio::test]
    async fn begin_v2_injects_original_auth_without_using_legacy_port() {
        let directory = begin_directory(Err(ThreadDirectoryError::Unavailable));
        let command = begin_v2_command();
        assert_eq!(
            begin_thread_run_v2(
                &directory,
                &crate::artifacts::NoArtifactAdministration,
                &auth(),
                command.clone()
            )
            .await,
            Err(AppError::DependencyUnavailable {
                dependency: "thread_directory"
            })
        );
        assert!(directory.calls.lock().unwrap().is_empty());
        assert_eq!(
            *directory.v2_calls.lock().unwrap(),
            vec![BeginThreadRunV2Request {
                auth_generation: auth().auth_generation(),
                deployment: auth().deployment().clone(),
                tenant: auth().tenant().clone(),
                actor: auth().actor().clone(),
                command,
            }]
        );
    }

    #[tokio::test]
    async fn begin_v2_default_port_closes_without_invoking_a_working_legacy_port() {
        struct LegacyOnlyDirectory(BeginDirectory);

        #[async_trait]
        impl ThreadDirectory for LegacyOnlyDirectory {
            async fn mint_thread_id(
                &self,
                _deployment: &DeploymentId,
            ) -> Result<ThreadId, ThreadDirectoryError> {
                Err(ThreadDirectoryError::Unavailable)
            }

            async fn thread_known(
                &self,
                _deployment: &DeploymentId,
                _tenant: &TenantId,
                _actor: &ActorId,
                _thread: &ThreadId,
            ) -> Result<bool, ThreadDirectoryError> {
                Err(ThreadDirectoryError::Unavailable)
            }

            async fn begin_thread_run(
                &self,
                request: BeginThreadRunRequest,
            ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
                self.0.begin_thread_run(request).await
            }
        }

        let old_command = begin_command();
        let expected = ThreadRunStarted {
            thread_id: old_command.thread_id.clone(),
            run_id: old_command.run_id.clone(),
            message_sequence: 0,
            event_sequence: 0,
            replayed: false,
        };
        let directory = LegacyOnlyDirectory(begin_directory(Ok(expected.clone())));
        let closed = Err(AppError::DependencyUnavailable {
            dependency: "thread_directory",
        });
        assert_eq!(
            begin_thread_run_v2(
                &directory,
                &crate::artifacts::NoArtifactAdministration,
                &auth(),
                begin_v2_command()
            )
            .await,
            closed
        );
        assert!(directory.0.calls.lock().unwrap().is_empty());
        assert!(directory.0.v2_calls.lock().unwrap().is_empty());
        assert_eq!(
            begin_thread_run_v2(
                &crate::ports::NoThreadDirectory,
                &crate::artifacts::NoArtifactAdministration,
                &auth(),
                begin_v2_command()
            )
            .await,
            closed
        );
        assert_eq!(
            begin_thread_run(
                &directory,
                &crate::artifacts::NoArtifactAdministration,
                &auth(),
                old_command
            )
            .await
            .unwrap(),
            expected
        );
        assert_eq!(directory.0.calls.lock().unwrap().len(), 1);
        assert!(directory.0.v2_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn begin_v2_rejects_unsupported_source_and_original_budgets_before_port() {
        use openbot_contracts::versioned_model_selection::{
            ModelSelectionIntentSource, RunModelSelectionV2,
        };
        let good = begin_v2_command();
        let mut commands = Vec::new();
        for source in [
            ModelSelectionIntentSource::SdkGateway,
            ModelSelectionIntentSource::AccountBridge,
        ] {
            let mut command = good.clone();
            command.model_selection = RunModelSelectionV2::new(
                source,
                command.model_selection.connection_id().to_owned(),
                7,
                command.model_selection.model_id().to_owned(),
                9,
            )
            .unwrap();
            commands.push(command);
        }
        let mut no_message = good.clone();
        no_message.message.clear();
        commands.push(no_message);
        let mut duplicate_skills = good.clone();
        duplicate_skills.selected_skill_slugs = vec!["one".to_owned(), "one".to_owned()];
        commands.push(duplicate_skills);
        let mut oversized = good;
        oversized.message = "x".repeat(MAX_THREAD_MESSAGE_BYTES + 1);
        commands.push(oversized);
        let mut nul_message = begin_v2_command();
        nul_message.message = "bad\0message".to_owned();
        commands.push(nul_message);
        let mut bad_thread = begin_v2_command();
        bad_thread.thread_id = ThreadId::new("bad");
        commands.push(bad_thread);
        let mut empty_run = begin_v2_command();
        empty_run.run_id = openbot_contracts::ids::RunId::new("");
        commands.push(empty_run);
        let mut empty_bot = begin_v2_command();
        empty_bot.bot_id = openbot_contracts::ids::BotId::new("");
        commands.push(empty_bot);
        let mut empty_channel = begin_v2_command();
        empty_channel.anchor = ThreadRunAnchor::Channel {
            channel_id: openbot_contracts::ids::ChannelId::new(""),
        };
        commands.push(empty_channel);
        for slugs in [
            vec!["missing/grammar".to_owned()],
            (0..17).map(|index| format!("skill-{index}")).collect(),
        ] {
            let mut command = begin_v2_command();
            command.selected_skill_slugs = slugs;
            commands.push(command);
        }
        for command in commands {
            let directory = begin_directory(Err(ThreadDirectoryError::Unavailable));
            assert!(matches!(
                begin_thread_run_v2(
                    &directory,
                    &crate::artifacts::NoArtifactAdministration,
                    &auth(),
                    command
                )
                .await,
                Err(AppError::MalformedPayload { .. })
            ));
            assert!(directory.calls.lock().unwrap().is_empty());
            assert!(directory.v2_calls.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn begin_v2_known_late_and_exact_replay_unproven_map_to_reconciliation() {
        for error in [
            ThreadDirectoryError::AcknowledgedAfterDeadline,
            ThreadDirectoryError::ReplayClosureUnproven,
            ThreadDirectoryError::CommitUnknown,
        ] {
            let directory = begin_directory(Err(error));
            assert_eq!(
                begin_thread_run_v2(
                    &directory,
                    &crate::artifacts::NoArtifactAdministration,
                    &auth(),
                    begin_v2_command()
                )
                .await,
                Err(AppError::ReconciliationRequired { accepted: true })
            );
            assert!(directory.calls.lock().unwrap().is_empty());
            assert_eq!(directory.v2_calls.lock().unwrap().len(), 1);
        }
        assert_eq!(
            ThreadDirectoryError::AcknowledgedAfterDeadline.to_string(),
            "thread_acknowledged_after_deadline"
        );
        assert_eq!(
            ThreadDirectoryError::ReplayClosureUnproven.to_string(),
            "thread_replay_closure_unproven"
        );
    }

    #[tokio::test]
    async fn begin_injects_authoritative_scope_and_returns_the_durable_receipt() {
        let expected = ThreadRunStarted {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
            message_sequence: 0,
            event_sequence: 0,
            replayed: false,
        };
        let directory = begin_directory(Ok(expected.clone()));
        let command = begin_command();
        assert_eq!(
            begin_thread_run(
                &directory,
                &crate::artifacts::NoArtifactAdministration,
                &auth(),
                command.clone()
            )
            .await
            .unwrap(),
            expected
        );
        assert_eq!(
            directory.calls.lock().expect("fake lock").as_slice(),
            &[BeginThreadRunRequest {
                auth_generation: openbot_contracts::auth::AuthGeneration::new(7),
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                command,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_begin_is_rejected_before_any_transaction_port_call() {
        let invalid = [
            ("model_selection", {
                let mut value = begin_command();
                value.model_selection =
                    Some(openbot_contracts::model_connections::RunModelSelection {
                        connection_id: "not-a-uuid".to_owned(),
                        expected_revision: 1,
                    });
                value
            }),
            ("model_selection", {
                let mut value = begin_command();
                value.model_selection =
                    Some(openbot_contracts::model_connections::RunModelSelection {
                        connection_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
                        expected_revision: 0,
                    });
                value
            }),
            ("thread_id", {
                let mut value = begin_command();
                value.thread_id = ThreadId::new("bad");
                value
            }),
            ("run_id", {
                let mut value = begin_command();
                value.run_id = openbot_contracts::ids::RunId::new("");
                value
            }),
            ("bot_id", {
                let mut value = begin_command();
                value.bot_id = openbot_contracts::ids::BotId::new("");
                value
            }),
            ("message", {
                let mut value = begin_command();
                value.message.clear();
                value
            }),
            ("message", {
                let mut value = begin_command();
                value.message = "bad\0message".to_owned();
                value
            }),
            ("channel_id", {
                let mut value = begin_command();
                value.anchor = ThreadRunAnchor::Channel {
                    channel_id: openbot_contracts::ids::ChannelId::new(""),
                };
                value
            }),
        ];
        for (field, command) in invalid {
            let directory = begin_directory(Err(ThreadDirectoryError::Unavailable));
            assert_eq!(
                begin_thread_run(
                    &directory,
                    &crate::artifacts::NoArtifactAdministration,
                    &auth(),
                    command
                )
                .await
                .unwrap_err(),
                AppError::MalformedPayload { field }
            );
            assert!(directory.calls.lock().expect("fake lock").is_empty());
        }
        for slugs in [
            vec!["missing/grammar".to_owned()],
            vec!["repeat".to_owned(), "repeat".to_owned()],
            (0..17).map(|index| format!("skill-{index}")).collect(),
        ] {
            let directory = begin_directory(Err(ThreadDirectoryError::Unavailable));
            let mut command = begin_command();
            command.selected_skill_slugs = slugs;
            assert_eq!(
                begin_thread_run(
                    &directory,
                    &crate::artifacts::NoArtifactAdministration,
                    &auth(),
                    command
                )
                .await,
                Err(AppError::MalformedPayload {
                    field: "selected_skill_slugs"
                }),
            );
            assert!(directory.calls.lock().expect("fake lock").is_empty());
        }
    }

    #[tokio::test]
    async fn begin_conflicts_keep_their_distinct_stable_semantics() {
        for (port, expected) in [
            (ThreadDirectoryError::NotVisible, AppError::NotVisible),
            (
                ThreadDirectoryError::LeaseConflict,
                AppError::LeaseConflict { holder: None },
            ),
            (
                ThreadDirectoryError::RequestConflict,
                AppError::RequestConflict { resource: "run" },
            ),
            (
                ThreadDirectoryError::CommitUnknown,
                AppError::ReconciliationRequired { accepted: true },
            ),
            (
                ThreadDirectoryError::AcknowledgedAfterDeadline,
                AppError::ReconciliationRequired { accepted: true },
            ),
            (
                ThreadDirectoryError::ReplayClosureUnproven,
                AppError::ReconciliationRequired { accepted: true },
            ),
        ] {
            let directory = begin_directory(Err(port));
            assert_eq!(
                begin_thread_run(
                    &directory,
                    &crate::artifacts::NoArtifactAdministration,
                    &auth(),
                    begin_command()
                )
                .await
                .unwrap_err(),
                expected
            );
        }
    }

    struct CancelDirectory {
        result: Result<ThreadRunCancellation, ThreadDirectoryError>,
        calls: Mutex<Vec<CancelThreadRunRequest>>,
    }

    #[async_trait]
    impl ThreadDirectory for CancelDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn cancel_thread_run(
            &self,
            request: CancelThreadRunRequest,
        ) -> Result<ThreadRunCancellation, ThreadDirectoryError> {
            self.calls.lock().expect("fake lock").push(request);
            self.result.clone()
        }
    }

    fn cancel_command() -> CancelThreadRun {
        CancelThreadRun {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
        }
    }

    #[tokio::test]
    async fn cancel_injects_authoritative_scope_and_returns_only_the_durable_ack() {
        let expected = ThreadRunCancellation {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
            state: openbot_contracts::command::ThreadRunCancellationState::Requested,
        };
        let directory = CancelDirectory {
            result: Ok(expected.clone()),
            calls: Mutex::new(Vec::new()),
        };
        let command = cancel_command();
        assert_eq!(
            cancel_thread_run(&directory, &auth(), command.clone())
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            directory.calls.lock().expect("fake lock").as_slice(),
            &[CancelThreadRunRequest {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                command,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_cancel_identities_never_reach_the_port() {
        let invalid = [
            ("thread_id", {
                let mut command = cancel_command();
                command.thread_id = ThreadId::new("not-a-uuid");
                command
            }),
            ("run_id", {
                let mut command = cancel_command();
                command.run_id = openbot_contracts::ids::RunId::new("");
                command
            }),
            ("run_id", {
                let mut command = cancel_command();
                command.run_id = openbot_contracts::ids::RunId::new("bad\0run");
                command
            }),
        ];
        for (field, command) in invalid {
            let directory = CancelDirectory {
                result: Err(ThreadDirectoryError::Unavailable),
                calls: Mutex::new(Vec::new()),
            };
            assert_eq!(
                cancel_thread_run(&directory, &auth(), command)
                    .await
                    .unwrap_err(),
                AppError::MalformedPayload { field }
            );
            assert!(directory.calls.lock().expect("fake lock").is_empty());
        }
    }

    struct SubscriptionDirectory {
        thread_calls: Mutex<Vec<ThreadEventSubscription>>,
        channel_calls: Mutex<Vec<ChannelActivitySubscription>>,
    }

    #[async_trait]
    impl ThreadDirectory for SubscriptionDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn subscribe_thread_events(
            &self,
            request: ThreadEventSubscription,
        ) -> Result<AppEventStream, ThreadDirectoryError> {
            self.thread_calls.lock().expect("fake lock").push(request);
            Ok(crate::use_cases::health_stream(
                core::time::Duration::from_secs(1),
            ))
        }

        async fn subscribe_channel_activity(
            &self,
            request: ChannelActivitySubscription,
        ) -> Result<AppEventStream, ThreadDirectoryError> {
            self.channel_calls.lock().expect("fake lock").push(request);
            Ok(crate::use_cases::health_stream(
                core::time::Duration::from_secs(1),
            ))
        }
    }

    #[tokio::test]
    async fn subscribe_injects_scope_and_rejects_unrepresentable_cursor_before_port() {
        let directory = SubscriptionDirectory {
            thread_calls: Mutex::new(Vec::new()),
            channel_calls: Mutex::new(Vec::new()),
        };
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        let _stream = subscribe_thread_events(&directory, &auth(), thread.clone(), Some(7))
            .await
            .unwrap();
        assert_eq!(
            directory.thread_calls.lock().expect("fake lock").as_slice(),
            &[ThreadEventSubscription {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                thread,
                after_event_sequence: Some(7),
            }]
        );

        let before = directory.thread_calls.lock().expect("fake lock").len();
        assert_eq!(
            subscribe_thread_events(&directory, &auth(), ThreadId::new("not-a-uuid"), None,)
                .await
                .err(),
            Some(AppError::MalformedPayload { field: "thread_id" })
        );
        assert_eq!(
            directory.thread_calls.lock().expect("fake lock").len(),
            before
        );

        if usize::BITS > 32 {
            assert_eq!(
                subscribe_thread_events(
                    &directory,
                    &auth(),
                    ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
                    Some(i64::MAX as u64 + 1),
                )
                .await
                .err(),
                Some(AppError::MalformedPayload {
                    field: "after_event_sequence"
                })
            );
            assert_eq!(
                directory.thread_calls.lock().expect("fake lock").len(),
                before
            );
        }

        let _stream = subscribe_channel_activity(&directory, &auth())
            .await
            .unwrap();
        assert_eq!(
            directory
                .channel_calls
                .lock()
                .expect("fake lock")
                .as_slice(),
            &[ChannelActivitySubscription {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
            }]
        );
    }

    struct HistoryDirectory {
        result: Result<ThreadHistory, ThreadDirectoryError>,
        calls: Mutex<Vec<ThreadHistoryRequest>>,
    }

    #[async_trait]
    impl ThreadDirectory for HistoryDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_history(
            &self,
            request: ThreadHistoryRequest,
        ) -> Result<ThreadHistory, ThreadDirectoryError> {
            self.calls.lock().expect("fake lock").push(request);
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn history_uses_authoritative_scope_and_empty_is_a_success_value() {
        let directory = HistoryDirectory {
            result: Ok(ThreadHistory::default()),
            calls: Mutex::new(Vec::new()),
        };
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(
            get_thread_history(&directory, &auth(), thread.clone())
                .await
                .unwrap(),
            ThreadHistory::default()
        );
        assert_eq!(
            directory.calls.lock().expect("fake lock").as_slice(),
            &[ThreadHistoryRequest {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                thread,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_history_id_never_reaches_the_port() {
        let directory = HistoryDirectory {
            result: Ok(ThreadHistory::default()),
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            get_thread_history(&directory, &auth(), ThreadId::new("not-a-uuid"))
                .await
                .unwrap_err(),
            AppError::MalformedPayload { field: "thread_id" }
        );
        assert!(directory.calls.lock().expect("fake lock").is_empty());
    }
    const INPUT_A: &str = "019a7778-abcd-7abc-8abc-0123456789ab";
    const INPUT_B: &str = "019a7778-abcd-7abc-8abc-0123456789ac";

    // Synthetic witnesses below exercise only Application ordering, not a live Host or PG.
    struct InputHostGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl openbot_contracts::HostRequestBindingGuard for InputHostGuard {
        fn verify_current<'a>(
            &'a self,
            _auth: &'a AuthContext,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<(), openbot_contracts::HostRequestBindingError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async {
                if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(openbot_contracts::HostRequestBindingError::NotCurrent)
                }
            })
        }
    }

    fn input_auth() -> (
        openbot_contracts::RequestBindingOwnerLease,
        AuthContext,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let current = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let auth = auth();
        let (owner, issuer) = openbot_contracts::RequestBindingOwnerLease::for_trusted_host(
            openbot_contracts::HostRequestBindingKind::DesktopWindow,
        );
        let binding = issuer
            .bind_desktop_window(
                &auth,
                "input-ordering-unit".into(),
                1,
                std::sync::Arc::new(InputHostGuard(current.clone())),
            )
            .unwrap();
        (
            owner,
            auth.with_verified_request_binding(binding).unwrap(),
            current,
        )
    }

    fn input_record(id: &str, media_type: &str, bytes: &[u8]) -> ArtifactRecordMetadata {
        use openbot_contracts::artifacts::{ArtifactRetentionClass, ArtifactWorkspace};
        let auth = auth();
        let source = begin_command();
        ArtifactRecordMetadata {
            artifact_id: id.into(),
            deployment_id: auth.deployment().clone(),
            tenant_id: auth.tenant().clone(),
            dataset_id: "input-dataset".into(),
            owner_actor_id: auth.actor().clone(),
            workspace: ArtifactWorkspace::Thread {
                id: source.thread_id.as_str().into(),
            },
            source_thread_id: source.thread_id,
            source_run_id: source.run_id,
            source_call_seq: None,
            source_attempt_seq: None,
            media_type: media_type.into(),
            byte_length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            retention_class: ArtifactRetentionClass::ExplicitSaved,
            saved_by: Some(auth.actor().clone()),
            saved_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        }
    }

    struct InputTarget(String);
    impl openbot_contracts::request_binding::ArtifactReadCurrentTarget for InputTarget {
        fn lookup_id(&self) -> &str {
            &self.0
        }
        fn matches_authority(&self, _: &std::sync::Arc<()>) -> bool {
            true
        }
        fn matches_auth(&self, _: &AuthContext) -> bool {
            true
        }
        fn matches_current_record(
            &self,
            _: openbot_contracts::request_binding::ArtifactReadRecordFacts<'_>,
        ) -> bool {
            true
        }
        fn verify_physical_current(
            &self,
        ) -> Result<(), openbot_contracts::request_binding::ArtifactReadCurrentError> {
            Ok(())
        }
    }
    struct InputTail;
    impl openbot_contracts::request_binding::ArtifactReadTailWitness for InputTail {
        fn verify_current(
            &self,
            _: &AuthContext,
            deadline: Instant,
        ) -> Result<(), openbot_contracts::request_binding::ArtifactReadCurrentError> {
            if Instant::now() < deadline {
                Ok(())
            } else {
                Err(openbot_contracts::request_binding::ArtifactReadCurrentError::Unavailable)
            }
        }
    }

    #[derive(Default)]
    struct InputArtifacts {
        records: Vec<(String, ArtifactMetadata, bool)>,
        metadata_calls: Mutex<Vec<String>>,
        deadlines: Mutex<Vec<Instant>>,
        reads: std::sync::atomic::AtomicUsize,
        body: Vec<u8>,
        revoke_on_metadata: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        revoke_on_body: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    }
    #[async_trait]
    impl ArtifactAdministration for InputArtifacts {
        async fn observe_run_input_metadata_current(
            &self,
            _auth: &AuthContext,
            id: &str,
            deadline: Instant,
        ) -> Result<crate::artifacts::RunInputArtifactMetadataObservation, AppError> {
            self.metadata_calls.lock().unwrap().push(id.into());
            self.deadlines.lock().unwrap().push(deadline);
            if let Some(current) = &self.revoke_on_metadata {
                current.store(false, std::sync::atomic::Ordering::SeqCst);
            }
            let (_, metadata, armed) = self
                .records
                .iter()
                .find(|(key, _, _)| key == id)
                .ok_or(AppError::NotVisible)?;
            Ok(crate::artifacts::RunInputArtifactMetadataObservation {
                metadata: metadata.clone(),
                cleanup_armed: *armed,
            })
        }
        async fn read_host_bound_chunk(
            &self,
            auth: &AuthContext,
            id: &str,
        ) -> Result<crate::CurrentArtifactReadChunk, AppError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(current) = &self.revoke_on_body {
                current.store(false, std::sync::atomic::Ordering::SeqCst);
                return Err(AppError::NotVisible);
            }
            let mut pending =
                openbot_contracts::artifact_read::PendingArtifactReadBuffer::new_initialized()
                    .map_err(|_| artifact_input_unavailable())?;
            pending.initialized_mut()[..self.body.len()].copy_from_slice(&self.body);
            pending
                .record_actual_length(self.body.len())
                .map_err(|_| artifact_input_unavailable())?;
            crate::CurrentArtifactReadChunk::from_trusted_observation(
                pending,
                auth.clone(),
                std::sync::Arc::new(InputTarget(id.into())),
                Box::new(InputTail),
                Instant::now() + Duration::from_secs(5),
            )
        }
        async fn save_run_message_text(
            &self,
            _: &AuthContext,
            _: openbot_contracts::artifacts::SaveRunMessageTextArtifact,
        ) -> Result<
            openbot_contracts::artifacts::ArtifactRegistrationReceipt,
            crate::artifacts::ArtifactAdministrationError,
        > {
            panic!("run input must never call the save producer")
        }
        async fn get_metadata(
            &self,
            _: &AuthContext,
            _: &str,
        ) -> Result<ArtifactMetadata, crate::artifacts::ArtifactAdministrationError> {
            panic!("run input must use the dedicated zero-body current observer")
        }
    }

    struct InputDirectory {
        replay: Result<Option<ThreadRunStarted>, ThreadDirectoryError>,
        write_result: Result<ThreadRunStarted, ThreadDirectoryError>,
        observed_refs: Mutex<Vec<Vec<String>>>,
        material_ids: Mutex<Vec<String>>,
        revoke_on_observe: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        revoke_on_write: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    }
    impl InputDirectory {
        fn miss() -> Self {
            Self {
                replay: Ok(None),
                write_result: Err(ThreadDirectoryError::CommitUnknown),
                observed_refs: Mutex::new(Vec::new()),
                material_ids: Mutex::new(Vec::new()),
                revoke_on_observe: None,
                revoke_on_write: None,
            }
        }
        fn observed(
            &self,
            refs: Vec<String>,
        ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
            self.observed_refs.lock().unwrap().push(refs);
            if let Some(current) = &self.revoke_on_observe {
                current.store(false, std::sync::atomic::Ordering::SeqCst);
            }
            self.replay.clone()
        }
        fn wrote(
            &self,
            materials: Vec<RunInputArtifactMaterial>,
        ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
            *self.material_ids.lock().unwrap() =
                materials.into_iter().map(|m| m.artifact_id).collect();
            if let Some(current) = &self.revoke_on_write {
                current.store(false, std::sync::atomic::Ordering::SeqCst);
            }
            self.write_result.clone()
        }
    }
    #[async_trait]
    impl ThreadDirectory for InputDirectory {
        async fn mint_thread_id(&self, _: &DeploymentId) -> Result<ThreadId, ThreadDirectoryError> {
            panic!("input path must not mint before its original transaction")
        }
        async fn thread_known(
            &self,
            _: &DeploymentId,
            _: &TenantId,
            _: &ActorId,
            _: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            panic!("shape must not query the directory")
        }
        async fn observe_begin_replay(
            &self,
            request: BeginThreadRunRequest,
        ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
            self.observed(request.command.artifact_refs)
        }
        async fn observe_begin_replay_v2(
            &self,
            request: BeginThreadRunV2Request,
        ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
            self.observed(request.command.artifact_refs)
        }
        async fn begin_thread_run_with_artifacts(
            &self,
            _: BeginThreadRunRequest,
            materials: Vec<RunInputArtifactMaterial>,
        ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
            self.wrote(materials)
        }
        async fn begin_thread_run_with_artifacts_v2(
            &self,
            _: BeginThreadRunV2Request,
            materials: Vec<RunInputArtifactMaterial>,
        ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
            self.wrote(materials)
        }
    }

    #[tokio::test]
    async fn artifact_refs_shape_is_zero_ports_for_both_versions() {
        let directory = InputDirectory::miss();
        let artifacts = InputArtifacts::default();
        for refs in [
            vec!["not-an-artifact".into()],
            vec![INPUT_A.into(), INPUT_A.to_uppercase()],
            vec![INPUT_A.into(); 9],
        ] {
            let mut command = begin_command();
            command.artifact_refs = refs.clone();
            assert_eq!(
                begin_thread_run(&directory, &artifacts, &auth(), command).await,
                Err(artifact_refs_malformed())
            );
            let mut command = begin_v2_command();
            command.artifact_refs = refs;
            assert_eq!(
                begin_thread_run_v2(&directory, &artifacts, &auth(), command).await,
                Err(artifact_refs_malformed())
            );
        }
        assert!(directory.observed_refs.lock().unwrap().is_empty());
        assert!(directory.material_ids.lock().unwrap().is_empty());
        assert!(artifacts.metadata_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn artifact_replay_preserves_canonical_order_and_skips_all_artifact_observation() {
        let (_lease, auth, _) = input_auth();
        let mut directory = InputDirectory::miss();
        let command = begin_command();
        let receipt = ThreadRunStarted {
            thread_id: command.thread_id,
            run_id: command.run_id,
            message_sequence: 7,
            event_sequence: 9,
            replayed: true,
        };
        directory.replay = Ok(Some(receipt.clone()));
        let artifacts = InputArtifacts::default();
        let mut command = begin_command();
        command.artifact_refs = vec![INPUT_B.to_uppercase(), INPUT_A.into()];
        assert_eq!(
            begin_thread_run(&directory, &artifacts, &auth, command).await,
            Ok(receipt.clone())
        );
        let mut command = begin_v2_command();
        command.artifact_refs = vec![INPUT_B.into(), INPUT_A.to_uppercase()];
        assert_eq!(
            begin_thread_run_v2(&directory, &artifacts, &auth, command).await,
            Ok(receipt)
        );
        assert_eq!(
            *directory.observed_refs.lock().unwrap(),
            vec![vec![INPUT_B.to_owned(), INPUT_A.to_owned()]; 2]
        );
        assert!(directory.material_ids.lock().unwrap().is_empty());
        assert!(artifacts.metadata_calls.lock().unwrap().is_empty());
        assert_eq!(artifacts.reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn all_metadata_404_precedes_armed503_and_budget400_without_body_reads() {
        let (_lease, auth, _) = input_auth();
        let mut oversized = input_record(INPUT_A, "text/plain; charset=utf-8", b"x");
        oversized.byte_length = 256 * 1024 + 1;
        let second = input_record(INPUT_B, "text/plain; charset=utf-8", b"x");
        for (visible_second, armed, expected) in [
            (false, true, AppError::NotVisible),
            (true, true, artifact_input_unavailable()),
            (true, false, artifact_refs_malformed()),
        ] {
            let mut artifacts = InputArtifacts::default();
            artifacts.records.push((
                INPUT_A.into(),
                ArtifactMetadata::Available(oversized.clone()),
                armed,
            ));
            if visible_second {
                artifacts.records.push((
                    INPUT_B.into(),
                    ArtifactMetadata::Available(second.clone()),
                    false,
                ));
            }
            let result =
                preread_artifact_materials(&artifacts, &auth, &[INPUT_A.into(), INPUT_B.into()])
                    .await;
            assert!(matches!(result, Err(error) if error == expected));
            assert_eq!(
                *artifacts.metadata_calls.lock().unwrap(),
                vec![INPUT_A.to_owned(), INPUT_B.to_owned()]
            );
            assert_eq!(artifacts.reads.load(std::sync::atomic::Ordering::SeqCst), 0);
            let deadlines = artifacts.deadlines.lock().unwrap();
            assert_eq!(deadlines.len(), 2);
            assert_eq!(deadlines[0], deadlines[1]);
        }
    }

    #[tokio::test]
    async fn input_body_is_complete_verified_text_and_nontext_is_metadata_only() {
        let (_lease, auth, _) = input_auth();
        let text = input_record(INPUT_A, "text/plain; charset=utf-8", b"hello");
        let mut binary = input_record(INPUT_B, "application/octet-stream", b"hello");
        binary.byte_length = 60 * 1024 * 1024;
        let artifacts = InputArtifacts {
            records: vec![
                (INPUT_A.into(), ArtifactMetadata::Available(text), false),
                (INPUT_B.into(), ArtifactMetadata::Available(binary), false),
            ],
            body: b"hello".to_vec(),
            ..InputArtifacts::default()
        };
        let materials =
            preread_artifact_materials(&artifacts, &auth, &[INPUT_A.into(), INPUT_B.into()])
                .await
                .unwrap();
        assert_eq!(materials.len(), 2);
        assert_eq!(materials[0].artifact_id, INPUT_A);
        assert_eq!(materials[0].body.as_deref(), Some("hello"));
        assert_eq!(materials[1].artifact_id, INPUT_B);
        assert!(materials[1].body.is_none());
        assert_eq!(artifacts.reads.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Media classification is pure; this does not claim JSON production/schema reachability.
        assert!(input_media_is_text("APPLICATION/JSON; charset=utf-8"));
        assert!(input_media_is_text("Text/Plain"));
        assert!(!input_media_is_text("application/json-seq"));
    }

    #[tokio::test]
    async fn wrong_body_length_digest_or_utf8_refuses_before_any_write() {
        let (_lease, auth, _) = input_auth();
        for index in 0..3 {
            let body = if index == 2 {
                vec![0xff]
            } else {
                b"hello".to_vec()
            };
            let mut record = input_record(INPUT_A, "text/plain", &body);
            if index == 0 {
                record.byte_length += 1;
            }
            if index == 1 {
                record.sha256 = "0".repeat(64);
            }
            let artifacts = InputArtifacts {
                records: vec![(INPUT_A.into(), ArtifactMetadata::Available(record), false)],
                body,
                ..InputArtifacts::default()
            };
            let directory = InputDirectory::miss();
            let mut command = begin_command();
            command.artifact_refs = vec![INPUT_A.into()];
            assert_eq!(
                begin_thread_run(&directory, &artifacts, &auth, command).await,
                Err(artifact_input_unavailable())
            );
            assert!(directory.material_ids.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn host_postcheck_preserves_replay_metadata_body_and_write_errors() {
        for phase in 0..4 {
            let (_lease, auth, current) = input_auth();
            let mut directory = InputDirectory::miss();
            let mut artifacts = InputArtifacts::default();
            if phase == 0 {
                directory.replay = Err(ThreadDirectoryError::RequestConflict);
                directory.revoke_on_observe = Some(current.clone());
            } else if phase == 1 {
                artifacts.revoke_on_metadata = Some(current.clone());
            } else {
                artifacts.records.push((
                    INPUT_A.into(),
                    ArtifactMetadata::Available(input_record(INPUT_A, "text/plain", b"hello")),
                    false,
                ));
                artifacts.body = b"hello".to_vec();
                if phase == 2 {
                    artifacts.revoke_on_body = Some(current.clone());
                }
                if phase == 3 {
                    directory.revoke_on_write = Some(current.clone());
                }
            }
            let mut command = begin_command();
            command.artifact_refs = vec![INPUT_A.into()];
            assert_eq!(
                begin_thread_run(&directory, &artifacts, &auth, command).await,
                Err(AppError::Unauthenticated)
            );
        }
        let (_lease, auth, _) = input_auth();
        let directory = InputDirectory::miss();
        let artifacts = InputArtifacts {
            records: vec![(
                INPUT_A.into(),
                ArtifactMetadata::Available(input_record(
                    INPUT_A,
                    "application/octet-stream",
                    b"hello",
                )),
                false,
            )],
            ..InputArtifacts::default()
        };
        let mut command = begin_v2_command();
        command.artifact_refs = vec![INPUT_A.into()];
        assert_eq!(
            begin_thread_run_v2(&directory, &artifacts, &auth, command).await,
            Err(AppError::ReconciliationRequired { accepted: true })
        );
    }

    #[tokio::test]
    async fn artifact_defaults_fail_closed_and_delegate_only_the_double_empty_pair() {
        let directory = begin_directory(Err(ThreadDirectoryError::RequestConflict));
        let auth = auth();
        let request = |command| BeginThreadRunRequest {
            auth_generation: auth.auth_generation(),
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            command,
        };
        let request_v2 = |command| BeginThreadRunV2Request {
            auth_generation: auth.auth_generation(),
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            command,
        };
        assert!(matches!(
            directory
                .observe_begin_replay(request(begin_command()))
                .await,
            Err(ThreadDirectoryError::Unavailable)
        ));
        assert!(matches!(
            directory
                .observe_begin_replay_v2(request_v2(begin_v2_command()))
                .await,
            Err(ThreadDirectoryError::Unavailable)
        ));
        assert_eq!(
            directory
                .begin_thread_run_with_artifacts(request(begin_command()), Vec::new())
                .await,
            Err(ThreadDirectoryError::RequestConflict)
        );
        assert_eq!(
            directory
                .begin_thread_run_with_artifacts_v2(request_v2(begin_v2_command()), Vec::new())
                .await,
            Err(ThreadDirectoryError::RequestConflict)
        );
        let material = || RunInputArtifactMaterial {
            artifact_id: INPUT_A.into(),
            dataset_id: "input-dataset".into(),
            sha256: "0".repeat(64),
            media_type: "application/octet-stream".into(),
            byte_length: 1,
            source_thread_id: begin_command().thread_id,
            source_run_id: begin_command().run_id,
            body: None,
        };
        for refs_nonempty in [false, true] {
            let mut command = begin_command();
            let mut command_v2 = begin_v2_command();
            if refs_nonempty {
                command.artifact_refs = vec![INPUT_A.into()];
                command_v2.artifact_refs = vec![INPUT_A.into()];
            }
            let materials = if refs_nonempty {
                Vec::new()
            } else {
                vec![material()]
            };
            assert_eq!(
                directory
                    .begin_thread_run_with_artifacts(request(command), materials)
                    .await,
                Err(ThreadDirectoryError::Unavailable)
            );
            let materials = if refs_nonempty {
                Vec::new()
            } else {
                vec![material()]
            };
            assert_eq!(
                directory
                    .begin_thread_run_with_artifacts_v2(request_v2(command_v2), materials)
                    .await,
                Err(ThreadDirectoryError::Unavailable)
            );
        }
        assert_eq!(directory.calls.lock().unwrap().len(), 1);
        assert_eq!(directory.v2_calls.lock().unwrap().len(), 1);
        assert!(matches!(
            crate::artifacts::NoArtifactAdministration
                .observe_run_input_metadata_current(
                    &auth,
                    INPUT_A,
                    Instant::now() + Duration::from_secs(5)
                )
                .await,
            Err(AppError::DependencyUnavailable {
                dependency: "artifacts"
            })
        ));
    }

    #[tokio::test]
    async fn expired_shared_preread_limit_does_not_poll_a_new_future() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result = preread_before(Instant::now() - Duration::from_secs(1), async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert_eq!(result, Err(artifact_input_unavailable()));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn nonempty_refs_require_host_before_the_replay_port() {
        let directory = InputDirectory::miss();
        let artifacts = InputArtifacts::default();
        let mut command = begin_command();
        command.artifact_refs = vec![INPUT_A.into()];
        assert_eq!(
            begin_thread_run(&directory, &artifacts, &auth(), command).await,
            Err(AppError::DependencyUnavailable {
                dependency: "host_request_binding"
            })
        );
        let mut command = begin_v2_command();
        command.artifact_refs = vec![INPUT_A.into()];
        assert_eq!(
            begin_thread_run_v2(&directory, &artifacts, &auth(), command).await,
            Err(AppError::DependencyUnavailable {
                dependency: "host_request_binding"
            })
        );
        assert!(directory.observed_refs.lock().unwrap().is_empty());
        assert!(artifacts.metadata_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn nonavailable_metadata_is_404_without_synthetic_live_digest() {
        use openbot_contracts::artifacts::ArtifactTombstone;
        let (_lease, auth, _) = input_auth();
        let record = input_record(INPUT_A, "text/plain", b"hello");
        let tombstone = ArtifactTombstone {
            artifact_id: INPUT_A.into(),
            operation_id: "019a7779-abcd-7abc-8abc-0123456789ab".into(),
            request_id: "019a7777-abcd-7abc-8abc-0123456789ab".into(),
            owner_actor_id: auth.actor().clone(),
            source_thread_id: record.source_thread_id.clone(),
            source_run_id: record.source_run_id.clone(),
            source_message_id: "message-1".into(),
            source_call_seq: None,
            source_attempt_seq: None,
        };
        for metadata in [
            ArtifactMetadata::FailedPartial(record),
            ArtifactMetadata::Deleted(tombstone.clone()),
            ArtifactMetadata::Expired(tombstone),
        ] {
            let artifacts = InputArtifacts {
                records: vec![(INPUT_A.into(), metadata, true)],
                ..InputArtifacts::default()
            };
            assert!(matches!(
                preread_artifact_materials(&artifacts, &auth, &[INPUT_A.into()]).await,
                Err(AppError::NotVisible)
            ));
            assert_eq!(artifacts.reads.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn total_text_budget_is_checked_after_all_metadata_and_before_first_body() {
        let (_lease, auth, _) = input_auth();
        let mut artifacts = InputArtifacts::default();
        let mut refs = Vec::new();
        for index in 1..=5 {
            let id = format!("019a7778-abcd-7abc-8abc-{index:012x}");
            let mut record = input_record(&id, "text/plain", b"hello");
            record.byte_length = 256 * 1024;
            artifacts
                .records
                .push((id.clone(), ArtifactMetadata::Available(record), false));
            refs.push(id);
        }
        assert!(matches!(
            preread_artifact_materials(&artifacts, &auth, &refs).await,
            Err(AppError::MalformedPayload {
                field: "artifact_refs"
            })
        ));
        assert_eq!(*artifacts.metadata_calls.lock().unwrap(), refs);
        assert_eq!(artifacts.reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
