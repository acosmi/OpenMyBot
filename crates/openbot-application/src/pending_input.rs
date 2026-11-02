//! Dispatch persisted direct conversation input through ordinary user authority.

use crate::{ThreadDirectory, artifacts::ArtifactAdministration};
use async_trait::async_trait;
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::BeginThreadRunV2;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId, ThreadId};
use std::{ops::Deref, sync::Arc};

/// Current database authority and frozen payload, verified inside the pending row transaction.
pub struct VerifiedPendingInput {
    /// Original submitting user.
    pub actor: ActorId,
    /// Conversation deployment.
    pub deployment: DeploymentId,
    /// Conversation tenant.
    pub tenant: TenantId,
    /// Current generation, equal to the accepted input generation.
    pub auth_generation: AuthGeneration,
    /// Current database ACL roles.
    pub roles: Vec<Role>,
    /// Original complete input, without replacing any selection.
    pub command: BeginThreadRunV2,
}

/// Application callback invoked while the pending row transaction remains open.
#[async_trait]
pub trait PendingInputConsumer: Send + Sync {
    /// Begin the frozen input as its currently authorized submitting user.
    async fn begin(
        &self,
        input: VerifiedPendingInput,
    ) -> Result<
        (
            crate::BeginThreadRunV2Request,
            Vec<crate::RunInputArtifactMaterial>,
        ),
        AppError,
    >;
}

/// In-process wake hook for committed terminals and released inputs.
#[async_trait]
pub trait PendingInputWake: Send + Sync {
    /// Attempt one pending row for this conversation.
    async fn wake(&self, thread: &ThreadId) -> Result<(), AppError>;
    /// Scan once after the host has enrolled its original dataset.
    async fn scan_startup(&self) -> Result<(), AppError> {
        Ok(())
    }
}

/// The sole consumer of durable direct conversation input.
pub struct PendingInputDispatcher<D> {
    directory: D,
    artifacts: Arc<dyn ArtifactAdministration>,
}

impl<D: Deref + Send + Sync> PendingInputDispatcher<D>
where
    D::Target: ThreadDirectory,
{
    /// Use the same thread and artifact authorities as ordinary BeginV2.
    pub fn new(directory: D, artifacts: Arc<dyn ArtifactAdministration>) -> Self {
        Self {
            directory,
            artifacts,
        }
    }

    /// Attempt exactly one row; occupancy and pending state remain database facts.
    pub async fn wake(&self, thread: &ThreadId) -> Result<(), AppError> {
        self.directory
            .dispatch_pending_input(thread, self)
            .await
            .map_err(|e| e.into_app_error())
    }

    /// Scan each currently idle conversation once, without a timer or persistent worker.
    pub async fn scan_startup(&self) -> Result<(), AppError> {
        for thread in self
            .directory
            .pending_input_threads()
            .await
            .map_err(|e| e.into_app_error())?
        {
            if let Err(error) = self.wake(&thread).await {
                tracing::warn!(
                    code = error.code().as_str(),
                    "pending input startup wake unavailable"
                );
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<D: Deref + Send + Sync> PendingInputWake for PendingInputDispatcher<D>
where
    D::Target: ThreadDirectory,
{
    async fn wake(&self, thread: &ThreadId) -> Result<(), AppError> {
        self.wake(thread).await
    }
    async fn scan_startup(&self) -> Result<(), AppError> {
        self.scan_startup().await
    }
}

#[async_trait]
impl<D: Deref + Send + Sync> PendingInputConsumer for PendingInputDispatcher<D>
where
    D::Target: ThreadDirectory,
{
    async fn begin(
        &self,
        input: VerifiedPendingInput,
    ) -> Result<
        (
            crate::BeginThreadRunV2Request,
            Vec<crate::RunInputArtifactMaterial>,
        ),
        AppError,
    > {
        let auth = AuthContextBuilder::from_verified_pending_input(
            input.actor,
            input.deployment,
            input.tenant,
            input.auth_generation,
        )
        .with_roles(input.roles)
        .build();
        let request = crate::use_cases::thread::prepare_thread_run_v2(&auth, input.command)?;
        let materials = if request.command.artifact_refs.is_empty() {
            Vec::new()
        } else {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.artifacts.preread_pending_input_materials(
                    &auth,
                    &request.command.artifact_refs,
                    deadline,
                ),
            )
            .await
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "artifacts",
            })??
        };
        Ok((request, materials))
    }
}
