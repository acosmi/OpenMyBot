//! R424 authenticated artifact save/metadata boundary. Storage and current authority belong to PG.

use async_trait::async_trait;
use openbot_contracts::artifacts::{
    ArtifactGoneStatus, ArtifactMetadata, ArtifactRecordMetadata, ArtifactRegistrationReceipt,
    ArtifactRetentionClass, ArtifactTombstone, ArtifactWorkspace, GetArtifactMetadata,
    MAX_ARTIFACT_BYTES, SaveRunMessageTextArtifact, canonical_artifact_uuid_v7,
    is_valid_artifact_identity, is_valid_artifact_sha256,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;

/// Closed repository failures, carrying no user body, path or byte facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactAdministrationError {
    /// A bounded selector or digest is malformed.
    #[error("artifact_invalid_input field={field}")]
    InvalidInput {
        /// Static field name only.
        field: &'static str,
    },
    /// Missing sources/artifacts and current lack of visibility share this result.
    #[error("artifact_not_visible")]
    NotVisible,
    /// Original locator has a different durable intent.
    #[error("artifact_request_conflict")]
    RequestConflict,
    /// Frozen host quota refused admission.
    #[error("artifact_policy_refused rule={rule}")]
    PolicyRefused {
        /// A static implementation rule, never caller prose.
        rule: &'static str,
    },
    /// Current-authorized deleted/expired state.
    #[error("artifact_gone status={status}")]
    Gone {
        /// Closed sanitized state.
        status: ArtifactGoneStatus,
    },
    /// Required PG/physical storage dependency is unavailable.
    #[error("artifact_unavailable")]
    Unavailable,
    /// Stored or returned shape violates the registered contract.
    #[error("artifact_corrupt field={field}")]
    Corrupt {
        /// Static field name only.
        field: &'static str,
    },
    /// Original transaction outcome requires actual authorized observation, never replay.
    #[error("artifact_commit_unknown")]
    CommitUnknown,
}

impl ArtifactAdministrationError {
    /// Stable exhaustive mapping; R424 commit uncertainty remains 503.
    #[must_use]
    pub fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::NotVisible => AppError::NotVisible,
            Self::RequestConflict => AppError::RequestConflict {
                resource: "artifact",
            },
            Self::PolicyRefused { rule } => AppError::PolicyRefused {
                rule: rule.to_owned(),
                decision: None,
            },
            Self::Gone { status } => AppError::ArtifactGone { status },
            Self::Unavailable | Self::Corrupt { .. } | Self::CommitUnknown => {
                AppError::DependencyUnavailable {
                    dependency: "artifacts",
                }
            }
        }
    }
}

/// A zero-body current observation for run input admission, never a later read or write grant.
pub struct RunInputArtifactMetadataObservation {
    /// Actual metadata, retaining the existing closed status variants.
    pub metadata: ArtifactMetadata,
    /// Whether this available object has the complete valid armed cleanup fence.
    pub cleanup_armed: bool,
}

/// Shared authenticated port; each implementation owns its current transaction and byte proof.
#[async_trait]
pub trait ArtifactAdministration: Send + Sync {
    /// Observe current Host/source metadata and valid armed state under the shared preread limit.
    /// Unsupported adapters must not fall back to a save producer or infer an unarmed record.
    async fn observe_run_input_metadata_current(
        &self,
        _auth: &AuthContext,
        _canonical_artifact_id: &str,
        _original_preread_deadline: std::time::Instant,
    ) -> Result<RunInputArtifactMetadataObservation, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }

    /// Prepare the same actual retained FD before publishing a memory-only reader locator.
    /// The immutable deadline was anchored by Application before its first await.
    async fn prepare_host_bound_artifact_read(
        &self,
        _auth: &AuthContext,
        _artifact_id: &str,
        _original_deadline: std::time::Instant,
        _observer: std::sync::Arc<
            dyn crate::artifact_read_protocol::ArtifactReadPreparationObserver,
        >,
    ) -> Result<crate::artifact_read_protocol::PreparedArtifactRead, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// Observe an original persisted save receipt under one current own-Pool host/source check.
    /// An adapter without this dedicated observer must not fall back to the save producer.
    async fn observe_artifact_save_receipt_current(
        &self,
        _auth: &AuthContext,
        _input: &openbot_contracts::artifacts::GetArtifactSaveReceipt,
        _deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::ArtifactSaveReceiptCurrentOutcome {
        Err(openbot_contracts::request_binding::ArtifactReadCurrentError::Unavailable)
    }
    /// One enrolled own-Pool host/source observation; unsupported adapters remain unavailable.
    async fn observe_source_run_artifact_ids_current(
        &self,
        _auth: &AuthContext,
        _input: &openbot_contracts::artifacts::GetSourceRunArtifactIds,
        _deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::SourceRunArtifactIdsCurrentOutcome {
        Err(openbot_contracts::request_binding::ArtifactReadCurrentError::Unavailable)
    }
    /// 原宿主Rust-only连续读取；缺真实实现保持不可用。
    async fn open_host_bound_read_operation(
        &self,
        _auth: &AuthContext,
        _artifact_id: &str,
    ) -> Result<crate::CurrentArtifactReadOperation, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// 实际原宿主绑定的私有首块读取；缺真实消费者时拒绝，不新增公开 wire。
    async fn read_host_bound_chunk(
        &self,
        _auth: &AuthContext,
        _artifact_id: &str,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// Explicitly save the selected real PG user message, observing original operations on reentry.
    async fn save_run_message_text(
        &self,
        auth: &AuthContext,
        input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError>;

    /// Recheck current source visibility and return only registered metadata facts.
    async fn get_metadata(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError>;
}

/// 原 FD/current witness 保留到真正同步移交的封闭首块；不是公开流或票据。
pub struct CurrentArtifactReadChunk {
    pending: openbot_contracts::artifact_read::PendingArtifactReadBuffer,
    original: openbot_contracts::request_binding::VerifiedHostRequestBinding,
    auth: AuthContext,
    target: std::sync::Arc<dyn openbot_contracts::request_binding::ArtifactReadCurrentTarget>,
    witness: Box<dyn openbot_contracts::request_binding::ArtifactReadTailWitness>,
    deadline: std::time::Instant,
}
impl CurrentArtifactReadChunk {
    /// 只供实际 Infra producer，消费全初始化 RAII bytes 和保留原 FD 的真实 target。
    #[doc(hidden)]
    pub fn from_trusted_observation(
        pending: openbot_contracts::artifact_read::PendingArtifactReadBuffer,
        auth: AuthContext,
        target: std::sync::Arc<dyn openbot_contracts::request_binding::ArtifactReadCurrentTarget>,
        witness: Box<dyn openbot_contracts::request_binding::ArtifactReadTailWitness>,
        deadline: std::time::Instant,
    ) -> Result<Self, AppError> {
        if pending.actual_length().is_none() {
            return Err(AppError::DependencyUnavailable {
                dependency: "artifacts",
            });
        }
        let original = auth
            .request_binding()
            .cloned()
            .ok_or(AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            })?;
        let chunk = Self {
            pending,
            original,
            auth,
            target,
            witness,
            deadline,
        };
        chunk.verify_current(&chunk.auth)?;
        Ok(chunk)
    }
    /// 无 await 的原六事实/binding、保留FD/root及真实宿主/window/clock 尾检。
    pub fn verify_current(&self, auth: &AuthContext) -> Result<(), AppError> {
        if auth != &self.auth {
            return Err(AppError::Unauthenticated);
        }
        self.original
            .verify_artifact_read_tail(
                auth,
                self.target.as_ref(),
                self.witness.as_ref(),
                self.deadline,
            )
            .map_err(current_read_error)
    }
    /// 唯一正文出口；全部同步尾检后消费RAII缓冲，无后续await。
    pub fn handoff(self, auth: &AuthContext) -> Result<Vec<u8>, AppError> {
        self.verify_current(auth)?;
        self.pending
            .handoff(
                auth,
                &self.original,
                self.target.as_ref(),
                self.witness.as_ref(),
                self.deadline,
            )
            .map_err(current_read_error)
    }
}
fn current_read_error(
    error: openbot_contracts::request_binding::ArtifactReadCurrentError,
) -> AppError {
    use openbot_contracts::request_binding::{
        ArtifactReadCurrentError as Error, HostRequestBindingError,
    };
    match error {
        Error::Host(HostRequestBindingError::NotCurrent) => AppError::Unauthenticated,
        Error::Host(HostRequestBindingError::Missing | HostRequestBindingError::Unavailable) => {
            AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            }
        }
        Error::NotVisible => AppError::NotVisible,
        Error::Gone(status) => AppError::ArtifactGone { status },
        Error::Unavailable => AppError::DependencyUnavailable {
            dependency: "artifacts",
        },
    }
}

#[cfg(test)]
#[path = "artifact_current_read_tests.rs"]
mod current_read_tests;

/// Observe IDs only, retaining the original current witness through final synchronous handoff.
pub async fn get_source_run_artifact_ids(
    port: &dyn ArtifactAdministration,
    auth: &AuthContext,
    input: openbot_contracts::artifacts::GetSourceRunArtifactIds,
) -> Result<openbot_contracts::artifacts::SourceRunArtifactIds, AppError> {
    for (field, id) in [
        ("sourceThreadId", input.source_thread_id.as_str()),
        ("sourceRunId", input.source_run_id.as_str()),
    ] {
        if !is_valid_artifact_identity(id) {
            return Err(AppError::MalformedPayload { field });
        }
    }
    let original = auth
        .request_binding()
        .cloned()
        .ok_or(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        })?;
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(5))
        .ok_or(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        })?;
    original
        .check_source_run_artifact_ids_attachment(auth, deadline)
        .map_err(current_read_error)?;
    let outcome = port
        .observe_source_run_artifact_ids_current(auth, &input, deadline)
        .await;
    original
        .check_source_run_artifact_ids_attachment(auth, deadline)
        .map_err(current_read_error)?;
    let (witness, source) = outcome.map_err(current_read_error)?;
    // Preserve the source/shape refusal until the original current host tail has been checked.
    let source = source
        .map_err(|error| match error {
            openbot_contracts::request_binding::ArtifactReadCurrentError::Gone(_) => {
                openbot_contracts::request_binding::ArtifactReadCurrentError::Unavailable
            }
            other => other,
        })
        .and_then(|ids| {
            if ids.source_thread_id != input.source_thread_id
                || ids.source_run_id != input.source_run_id
                || ids.artifact_ids.len() > 32
                || ids.artifact_ids.iter().any(|id| !canonical_id(id))
                || ids.artifact_ids.windows(2).any(|pair| pair[0] >= pair[1])
            {
                Err(openbot_contracts::request_binding::ArtifactReadCurrentError::Unavailable)
            } else {
                Ok(ids)
            }
        });
    original
        .verify_source_run_artifact_ids_tail(auth, witness.as_ref(), deadline)
        .map_err(current_read_error)?;
    source.map_err(current_read_error)
}

#[cfg(test)]
#[path = "artifact_source_run_tests.rs"]
mod source_run_tests;

/// Genuine unavailable default when no authoritative physical dependency is composed.
#[derive(Debug, Default)]
pub struct NoArtifactAdministration;

#[async_trait]
impl ArtifactAdministration for NoArtifactAdministration {
    async fn save_run_message_text(
        &self,
        _auth: &AuthContext,
        _input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        Err(ArtifactAdministrationError::Unavailable)
    }

    async fn get_metadata(
        &self,
        _auth: &AuthContext,
        _artifact_id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        Err(ArtifactAdministrationError::Unavailable)
    }
}

/// Validate selectors and dispatch a direct user save; no tool lease or body authority is created.
pub async fn save_run_message_text_artifact(
    port: &dyn ArtifactAdministration,
    auth: &AuthContext,
    mut input: SaveRunMessageTextArtifact,
) -> Result<ArtifactRegistrationReceipt, AppError> {
    input.request_id = canonical_artifact_uuid_v7(&input.request_id)
        .ok_or(AppError::MalformedPayload { field: "requestId" })?;
    if !ThreadIdentity::is_plausible(&input.source_thread_id) {
        return Err(AppError::MalformedPayload {
            field: "sourceThreadId",
        });
    }
    for (field, value) in [
        ("sourceRunId", input.source_run_id.as_str()),
        ("sourceMessageId", input.source_message_id.as_str()),
    ] {
        if !is_valid_artifact_identity(value) {
            return Err(AppError::MalformedPayload { field });
        }
    }
    if !is_valid_artifact_sha256(&input.expected_sha256) {
        return Err(AppError::MalformedPayload {
            field: "expectedSha256",
        });
    }
    let receipt = port
        .save_run_message_text(auth, input.clone())
        .await
        .map_err(ArtifactAdministrationError::into_app_error)?;
    if !canonical_id(&receipt.operation_id)
        || !canonical_id(&receipt.artifact_id)
        || receipt.request_id != input.request_id
        || &receipt.owner_actor_id != auth.actor()
        || !is_valid_artifact_identity(receipt.owner_actor_id.as_str())
        || receipt.source_thread_id != input.source_thread_id
        || receipt.source_run_id != input.source_run_id
        || receipt.source_message_id != input.source_message_id
        || receipt.source_call_seq.is_some()
        || receipt.source_attempt_seq.is_some()
    {
        return Err(corrupt("receipt"));
    }
    Ok(receipt)
}

/// Read current-authorized metadata; gone states are projected through the sanitized 410 error.
pub async fn get_artifact_metadata(
    port: &dyn ArtifactAdministration,
    auth: &AuthContext,
    input: GetArtifactMetadata,
) -> Result<ArtifactMetadata, AppError> {
    let artifact_id =
        canonical_artifact_uuid_v7(&input.artifact_id).ok_or(AppError::MalformedPayload {
            field: "artifactId",
        })?;
    require_current_request_binding(auth).await?;
    // Preserve the entire PG result until the real host postcheck has completed, including errors.
    let result = port.get_metadata(auth, &artifact_id).await;
    require_current_request_binding(auth).await?;
    let metadata = result.map_err(ArtifactAdministrationError::into_app_error)?;
    match &metadata {
        ArtifactMetadata::Available(record) | ArtifactMetadata::FailedPartial(record) => {
            validate_record(auth, &artifact_id, record)?;
        }
        ArtifactMetadata::Deleted(tombstone) => {
            validate_tombstone(auth, &artifact_id, tombstone)?;
            return Err(AppError::ArtifactGone {
                status: ArtifactGoneStatus::Deleted,
            });
        }
        ArtifactMetadata::Expired(tombstone) => {
            validate_tombstone(auth, &artifact_id, tombstone)?;
            return Err(AppError::ArtifactGone {
                status: ArtifactGoneStatus::Expired,
            });
        }
    }
    Ok(metadata)
}

pub(crate) async fn require_current_request_binding(auth: &AuthContext) -> Result<(), AppError> {
    use openbot_contracts::request_binding::HostRequestBindingError;
    let binding = auth
        .request_binding()
        .ok_or(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        })?;
    binding
        .verify_current(auth)
        .await
        .map_err(|error| match error {
            HostRequestBindingError::NotCurrent => AppError::Unauthenticated,
            HostRequestBindingError::Missing | HostRequestBindingError::Unavailable => {
                AppError::DependencyUnavailable {
                    dependency: "host_request_binding",
                }
            }
        })
}

fn canonical_id(value: &str) -> bool {
    canonical_artifact_uuid_v7(value).as_deref() == Some(value)
}

fn validate_record(
    auth: &AuthContext,
    artifact_id: &str,
    record: &ArtifactRecordMetadata,
) -> Result<(), AppError> {
    let workspace_id = match &record.workspace {
        ArtifactWorkspace::Channel { id } => id,
        ArtifactWorkspace::Thread { id } if id == record.source_thread_id.as_str() => id,
        ArtifactWorkspace::Thread { .. } => return Err(corrupt("workspace")),
    };
    if record.artifact_id != artifact_id
        || &record.deployment_id != auth.deployment()
        || &record.tenant_id != auth.tenant()
        || &record.owner_actor_id != auth.actor()
        || !is_valid_artifact_identity(record.deployment_id.as_str())
        || !is_valid_artifact_identity(record.tenant_id.as_str())
        || !is_valid_artifact_identity(record.owner_actor_id.as_str())
        || !is_valid_artifact_identity(&record.dataset_id)
        || !is_valid_artifact_identity(workspace_id)
        || !ThreadIdentity::is_plausible(&record.source_thread_id)
        || !is_valid_artifact_identity(record.source_run_id.as_str())
        || record.source_call_seq.is_some()
        || record.source_attempt_seq.is_some()
        || record.media_type != "text/plain; charset=utf-8"
        || record.byte_length > MAX_ARTIFACT_BYTES
        || !is_valid_artifact_sha256(&record.sha256)
        || record.retention_class != ArtifactRetentionClass::ExplicitSaved
        || record.saved_by.as_ref() != Some(auth.actor())
        || record.saved_at.is_none()
    {
        return Err(corrupt("metadata"));
    }
    Ok(())
}

fn validate_tombstone(
    auth: &AuthContext,
    artifact_id: &str,
    tombstone: &ArtifactTombstone,
) -> Result<(), AppError> {
    if tombstone.artifact_id != artifact_id
        || !canonical_id(&tombstone.operation_id)
        || !canonical_id(&tombstone.request_id)
        || &tombstone.owner_actor_id != auth.actor()
        || !is_valid_artifact_identity(tombstone.owner_actor_id.as_str())
        || !ThreadIdentity::is_plausible(&tombstone.source_thread_id)
        || !is_valid_artifact_identity(tombstone.source_run_id.as_str())
        || !is_valid_artifact_identity(tombstone.source_message_id.as_str())
        || tombstone.source_call_seq.is_some()
        || tombstone.source_attempt_seq.is_some()
    {
        return Err(corrupt("tombstone"));
    }
    Ok(())
}

fn corrupt(field: &'static str) -> AppError {
    ArtifactAdministrationError::Corrupt { field }.into_app_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::fakes::{FakeChannelReader, FakePeopleAdministration, auth_for};
    use crate::{ApplicationService, OpenBotApplication};
    use openbot_contracts::command::{AppCommand, AppReply};
    use openbot_contracts::ids::{ActorId, RunId, TenantId};
    use time::OffsetDateTime;

    const REQUEST_ID: &str = "019a7777-abcd-7abc-8abc-0123456789ab";
    const ARTIFACT_ID: &str = "019a7778-abcd-7abc-8abc-0123456789ab";
    const OPERATION_ID: &str = "019a7779-abcd-7abc-8abc-0123456789ab";

    struct NoIoUnitGuard;
    impl openbot_contracts::HostRequestBindingGuard for NoIoUnitGuard {
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
            Box::pin(async { Ok(()) })
        }
    }
    fn bound_auth(actor: &str) -> (openbot_contracts::RequestBindingOwnerLease, AuthContext) {
        let auth = auth_for(actor);
        let (owner, issuer) = openbot_contracts::RequestBindingOwnerLease::for_trusted_host(
            openbot_contracts::HostRequestBindingKind::DesktopWindow,
        );
        let binding = issuer
            .bind_desktop_window(&auth, "unit-no-io".into(), 1, Arc::new(NoIoUnitGuard))
            .unwrap();
        (owner, auth.with_verified_request_binding(binding).unwrap())
    }

    #[tokio::test]
    async fn missing_host_binding_rejects_metadata_before_repository() {
        let auth = auth_for("artifact-user");
        let port = RecordingArtifacts::default();
        let result = get_artifact_metadata(
            &port,
            &auth,
            GetArtifactMetadata {
                artifact_id: ARTIFACT_ID.into(),
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::DependencyUnavailable {
                dependency: "host_request_binding"
            })
        ));
        assert!(port.reads.lock().unwrap().is_empty());
    }

    fn input(auth: &AuthContext) -> SaveRunMessageTextArtifact {
        SaveRunMessageTextArtifact {
            request_id: REQUEST_ID.to_owned(),
            source_thread_id: ThreadIdentity::new(auth.deployment()).mint_from_entropy([3; 16]),
            source_run_id: RunId::new("來源Run 大小寫保持"),
            source_message_id: String::from("使用者訊息"),
            expected_sha256: "a".repeat(64),
        }
    }

    fn receipt(
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
    ) -> ArtifactRegistrationReceipt {
        ArtifactRegistrationReceipt {
            operation_id: OPERATION_ID.to_owned(),
            artifact_id: ARTIFACT_ID.to_owned(),
            request_id: input.request_id.clone(),
            owner_actor_id: auth.actor().clone(),
            source_thread_id: input.source_thread_id.clone(),
            source_run_id: input.source_run_id.clone(),
            source_message_id: input.source_message_id.clone(),
            source_call_seq: None,
            source_attempt_seq: None,
        }
    }

    fn record(auth: &AuthContext) -> ArtifactRecordMetadata {
        let input = input(auth);
        ArtifactRecordMetadata {
            artifact_id: ARTIFACT_ID.to_owned(),
            deployment_id: auth.deployment().clone(),
            tenant_id: auth.tenant().clone(),
            dataset_id: "dataset-test".to_owned(),
            owner_actor_id: auth.actor().clone(),
            workspace: ArtifactWorkspace::Thread {
                id: input.source_thread_id.as_str().to_owned(),
            },
            source_thread_id: input.source_thread_id,
            source_run_id: input.source_run_id,
            source_call_seq: None,
            source_attempt_seq: None,
            media_type: "text/plain; charset=utf-8".to_owned(),
            byte_length: 6,
            sha256: "a".repeat(64),
            retention_class: ArtifactRetentionClass::ExplicitSaved,
            saved_by: Some(auth.actor().clone()),
            saved_at: Some(OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[derive(Default)]
    struct RecordingArtifacts {
        saves: Mutex<Vec<(AuthContext, SaveRunMessageTextArtifact)>>,
        reads: Mutex<Vec<(AuthContext, String)>>,
        error: Option<ArtifactAdministrationError>,
        returned_receipt: Option<ArtifactRegistrationReceipt>,
        returned_metadata: Option<ArtifactMetadata>,
    }

    #[async_trait]
    impl ArtifactAdministration for RecordingArtifacts {
        async fn save_run_message_text(
            &self,
            auth: &AuthContext,
            input: SaveRunMessageTextArtifact,
        ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
            self.saves
                .lock()
                .unwrap()
                .push((auth.clone(), input.clone()));
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(self
                .returned_receipt
                .clone()
                .unwrap_or_else(|| receipt(auth, &input)))
        }

        async fn get_metadata(
            &self,
            auth: &AuthContext,
            artifact_id: &str,
        ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
            self.reads
                .lock()
                .unwrap()
                .push((auth.clone(), artifact_id.to_owned()));
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(self
                .returned_metadata
                .clone()
                .unwrap_or_else(|| ArtifactMetadata::Available(record(auth))))
        }
    }

    struct SecondCheckRefuses {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl openbot_contracts::HostRequestBindingGuard for SecondCheckRefuses {
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
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if call == 0 {
                    Ok(())
                } else {
                    Err(openbot_contracts::HostRequestBindingError::NotCurrent)
                }
            })
        }
    }
    #[tokio::test]
    async fn host_postcheck_precedes_success_and_repository_error_mapping() {
        // No-I/O unit boundary; actual PG and host proof evidence belongs to integration cases.
        for error in [
            None,
            Some(ArtifactAdministrationError::NotVisible),
            Some(ArtifactAdministrationError::Gone {
                status: ArtifactGoneStatus::Expired,
            }),
            Some(ArtifactAdministrationError::Unavailable),
        ] {
            let auth = auth_for("artifact-user");
            let (_owner, issuer) = openbot_contracts::RequestBindingOwnerLease::for_trusted_host(
                openbot_contracts::HostRequestBindingKind::DesktopWindow,
            );
            let guard = Arc::new(SecondCheckRefuses {
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let binding = issuer
                .bind_desktop_window(&auth, "unit-no-io".into(), 1, guard.clone())
                .unwrap();
            let auth = auth.with_verified_request_binding(binding).unwrap();
            let port = RecordingArtifacts {
                error,
                ..Default::default()
            };
            let result = get_artifact_metadata(
                &port,
                &auth,
                GetArtifactMetadata {
                    artifact_id: ARTIFACT_ID.into(),
                },
            )
            .await;
            assert!(matches!(result, Err(AppError::Unauthenticated)));
            assert_eq!(guard.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
            assert_eq!(port.reads.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn malformed_selectors_never_reach_repository_and_do_not_echo_input() {
        let (_binding_owner, auth) = bound_auth("artifact-user");
        let port = RecordingArtifacts::default();
        let valid = input(&auth);
        let mut bad_request = valid.clone();
        bad_request.request_id = "private request\n".to_owned();
        let mut bad_thread = valid.clone();
        bad_thread.source_thread_id = openbot_contracts::ids::ThreadId::new("private thread");
        let mut bad_run = valid.clone();
        bad_run.source_run_id = RunId::new("run\u{85}control");
        let mut large_message = valid.clone();
        large_message.source_message_id = "界".repeat(171);
        let mut bad_hash = valid;
        bad_hash.expected_sha256 = "A".repeat(64);
        for (value, field) in [
            (bad_request, "requestId"),
            (bad_thread, "sourceThreadId"),
            (bad_run, "sourceRunId"),
            (large_message, "sourceMessageId"),
            (bad_hash, "expectedSha256"),
        ] {
            let error = save_run_message_text_artifact(&port, &auth, value)
                .await
                .unwrap_err();
            assert!(
                matches!(error, AppError::MalformedPayload { field: actual } if actual == field)
            );
            assert!(!error.to_string().contains("private"));
        }
        assert!(port.saves.lock().unwrap().is_empty());
        assert!(matches!(
            get_artifact_metadata(
                &port,
                &auth,
                GetArtifactMetadata {
                    artifact_id: "not-an-artifact".into()
                }
            )
            .await,
            Err(AppError::MalformedPayload {
                field: "artifactId"
            })
        ));
        assert!(port.reads.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn typed_dispatch_canonicalizes_only_uuid_locators_and_forwards_authenticated_context() {
        let (_binding_owner, auth) = bound_auth("artifact-user");
        let port = Arc::new(RecordingArtifacts::default());
        let app = OpenBotApplication::new(FakeChannelReader::empty())
            .with_artifacts(port.clone())
            .with_people(FakePeopleAdministration::seeded([]));
        let mut source = input(&auth);
        source.request_id = REQUEST_ID.to_uppercase();
        source.source_run_id = RunId::new(format!("{}  A", "界".repeat(169)));
        assert_eq!(source.source_run_id.as_str().len(), 510);
        let reply = app
            .execute(
                auth.clone(),
                AppCommand::SaveRunMessageTextArtifact(source.clone()),
            )
            .await
            .unwrap();
        let AppReply::ArtifactRegistrationReceipt(saved) = reply else {
            panic!("receipt reply required")
        };
        assert_eq!(saved.request_id, REQUEST_ID);
        assert_eq!(saved.source_run_id, source.source_run_id);
        {
            let calls = port.saves.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0.actor(), auth.actor());
            assert_eq!(calls[0].0.auth_generation(), auth.auth_generation());
            assert_eq!(calls[0].1.request_id, REQUEST_ID);
            assert_eq!(calls[0].1.source_run_id, source.source_run_id);
        }
        let reply = app
            .execute(
                auth.clone(),
                AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                    artifact_id: ARTIFACT_ID.to_uppercase(),
                }),
            )
            .await
            .unwrap();
        assert!(matches!(
            reply,
            AppReply::ArtifactMetadata(ArtifactMetadata::Available(_))
        ));
        assert_eq!(port.reads.lock().unwrap()[0].1, ARTIFACT_ID);
    }

    #[tokio::test]
    async fn absent_composition_is_unavailable_for_both_artifact_commands() {
        let (_binding_owner, auth) = bound_auth("artifact-user");
        let app = OpenBotApplication::new(FakeChannelReader::empty());
        for command in [
            AppCommand::SaveRunMessageTextArtifact(input(&auth)),
            AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                artifact_id: ARTIFACT_ID.into(),
            }),
        ] {
            assert!(matches!(
                app.execute(auth.clone(), command).await,
                Err(AppError::DependencyUnavailable {
                    dependency: "artifacts"
                })
            ));
        }
    }

    #[tokio::test]
    async fn foreign_or_noncanonical_repository_receipt_never_becomes_positive_reply() {
        let (_binding_owner, auth) = bound_auth("artifact-user");
        let input = input(&auth);
        let good = receipt(&auth, &input);
        let mut wrong_owner = good.clone();
        wrong_owner.owner_actor_id = ActorId::new("other-user");
        let mut wrong_request = good.clone();
        wrong_request.request_id = OPERATION_ID.into();
        let mut wrong_source = good.clone();
        wrong_source.source_message_id = String::from("other-message");
        let mut uppercase = good.clone();
        uppercase.artifact_id = ARTIFACT_ID.to_uppercase();
        let mut fake_tool_provenance = good;
        fake_tool_provenance.source_call_seq = Some(0);
        for returned_receipt in [
            wrong_owner,
            wrong_request,
            wrong_source,
            uppercase,
            fake_tool_provenance,
        ] {
            let port = RecordingArtifacts {
                returned_receipt: Some(returned_receipt),
                ..Default::default()
            };
            let error = save_run_message_text_artifact(&port, &auth, input.clone())
                .await
                .unwrap_err();
            assert_eq!(error.http_status(), 503);
            assert!(matches!(
                error,
                AppError::DependencyUnavailable {
                    dependency: "artifacts"
                }
            ));
        }
    }

    #[tokio::test]
    async fn live_metadata_requires_current_namespace_and_exact_saved_record_shape() {
        let (_binding_owner, auth) = bound_auth("artifact-user");
        let good = record(&auth);
        let mut foreign = good.clone();
        foreign.tenant_id = TenantId::new("foreign-tenant");
        let mut oversized = good.clone();
        oversized.byte_length = MAX_ARTIFACT_BYTES + 1;
        let mut bad_digest = good.clone();
        bad_digest.sha256 = "A".repeat(64);
        let mut wrong_workspace = good.clone();
        wrong_workspace.workspace = ArtifactWorkspace::Thread {
            id: "different-thread".into(),
        };
        let mut missing_saver = good;
        missing_saver.saved_by = None;
        for invalid in [
            foreign,
            oversized,
            bad_digest,
            wrong_workspace,
            missing_saver,
        ] {
            let port = RecordingArtifacts {
                returned_metadata: Some(ArtifactMetadata::Available(invalid)),
                ..Default::default()
            };
            assert_eq!(
                get_artifact_metadata(
                    &port,
                    &auth,
                    GetArtifactMetadata {
                        artifact_id: ARTIFACT_ID.into()
                    }
                )
                .await
                .unwrap_err()
                .http_status(),
                503
            );
        }
        let mut zero_length = record(&auth);
        zero_length.byte_length = 0;
        zero_length.sha256 =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into();
        let port = RecordingArtifacts {
            returned_metadata: Some(ArtifactMetadata::FailedPartial(zero_length.clone())),
            ..Default::default()
        };
        assert_eq!(
            get_artifact_metadata(
                &port,
                &auth,
                GetArtifactMetadata {
                    artifact_id: ARTIFACT_ID.into()
                }
            )
            .await
            .unwrap(),
            ArtifactMetadata::FailedPartial(zero_length)
        );
        // This checks the typed repository boundary; actual zero-byte file proof belongs to IO tests.
    }

    #[tokio::test]
    async fn valid_tombstone_is_closed_410_and_foreign_tombstone_is_dependency_failure() {
        let (_binding_owner, auth) = bound_auth("artifact-user");
        let saved = receipt(&auth, &input(&auth));
        let tombstone = ArtifactTombstone {
            operation_id: saved.operation_id,
            artifact_id: saved.artifact_id,
            request_id: saved.request_id,
            owner_actor_id: saved.owner_actor_id,
            source_thread_id: saved.source_thread_id,
            source_run_id: saved.source_run_id,
            source_message_id: saved.source_message_id,
            source_call_seq: None,
            source_attempt_seq: None,
        };
        for (metadata, status) in [
            (
                ArtifactMetadata::Deleted(tombstone.clone()),
                ArtifactGoneStatus::Deleted,
            ),
            (
                ArtifactMetadata::Expired(tombstone.clone()),
                ArtifactGoneStatus::Expired,
            ),
        ] {
            let port = RecordingArtifacts {
                returned_metadata: Some(metadata),
                ..Default::default()
            };
            assert!(
                matches!(get_artifact_metadata(&port, &auth, GetArtifactMetadata { artifact_id: ARTIFACT_ID.into() }).await,
                Err(AppError::ArtifactGone { status: actual }) if actual == status)
            );
        }
        let mut foreign = tombstone;
        foreign.owner_actor_id = ActorId::new("other-user");
        let port = RecordingArtifacts {
            returned_metadata: Some(ArtifactMetadata::Deleted(foreign)),
            ..Default::default()
        };
        assert_eq!(
            get_artifact_metadata(
                &port,
                &auth,
                GetArtifactMetadata {
                    artifact_id: ARTIFACT_ID.into()
                }
            )
            .await
            .unwrap_err()
            .http_status(),
            503
        );
    }

    #[test]
    fn closed_repository_errors_keep_unknown_unavailable_and_policy_rule_sanitized() {
        for (error, expected) in [
            (
                ArtifactAdministrationError::InvalidInput {
                    field: "artifactId",
                },
                400,
            ),
            (ArtifactAdministrationError::NotVisible, 404),
            (ArtifactAdministrationError::RequestConflict, 409),
            (
                ArtifactAdministrationError::PolicyRefused {
                    rule: "artifact_workspace_bytes",
                },
                403,
            ),
            (
                ArtifactAdministrationError::Gone {
                    status: ArtifactGoneStatus::Deleted,
                },
                410,
            ),
            (ArtifactAdministrationError::Unavailable, 503),
            (
                ArtifactAdministrationError::Corrupt { field: "private" },
                503,
            ),
            (ArtifactAdministrationError::CommitUnknown, 503),
        ] {
            assert_eq!(error.into_app_error().http_status(), expected);
        }
        assert!(matches!(
            ArtifactAdministrationError::CommitUnknown.into_app_error(),
            AppError::DependencyUnavailable {
                dependency: "artifacts"
            }
        ));
        assert!(
            matches!(ArtifactAdministrationError::PolicyRefused { rule: "artifact_workspace_bytes" }.into_app_error(),
            AppError::PolicyRefused { rule, decision: None } if rule == "artifact_workspace_bytes")
        );
    }
}
