//! Built-in/remote Agent 进入 application tool pipeline 的唯一入口。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openbot_application::{
    AgentAuthorizationSource, ApplicationService, RemoteCallbackAuthorization, RunExecutionLease,
    ToolCallSequence, ToolCallSequenceError, ToolCancellationRegistry, ToolExecutionCancellation,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::components::{
    ComponentDecisionRefusal, ComponentDecisionRequest, ComponentHumanDecisionRequest,
    compiled_component_confirmation, compiled_component_parallel_safe, compiled_component_title,
    is_component_human_decision_name, validate_compiled_component_arguments,
    validate_component_human_decision_answer,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{BotId, RunId, ToolCallId};
use openbot_contracts::sandboxed::{SANDBOXED_COMPONENT_CONFIRMATION, is_sandboxed_component_name};
use openbot_contracts::tool::{ToolInvocation, ToolResult};
use openbot_domain::tool::metadata::ResourceLockKey;
use serde_json::Value;
use uuid::Uuid;

/// Model-visible, redacted reply paired with a Rust-minted control-plane call id.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentToolReply {
    call_id: ToolCallId,
    content: String,
    error_code: Option<String>,
}

impl AgentToolReply {
    /// Construct from an already-redacted tool-pipeline projection.
    pub fn new(
        call_id: ToolCallId,
        content: String,
        error_code: Option<String>,
    ) -> Result<Self, AgentToolInvokeError> {
        if call_id.as_str().is_empty()
            || content.as_bytes().contains(&0)
            || error_code
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.as_bytes().contains(&0))
        {
            return Err(AgentToolInvokeError::Unavailable);
        }
        Ok(Self {
            call_id,
            content,
            error_code,
        })
    }

    /// Rust-minted tool call id used for durable decision/message identities.
    #[must_use]
    pub const fn call_id(&self) -> &ToolCallId {
        &self.call_id
    }

    /// Redacted model-visible content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Stable error code; absence means success.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }
}

impl core::fmt::Debug for AgentToolReply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentToolReply")
            .field("call_id", &self.call_id)
            .field("content_bytes", &self.content.len())
            .field("error_code", &self.error_code)
            .finish()
    }
}

/// Tool invocation cannot safely become another provider sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentToolInvokeError {
    /// Delegated authority was revoked before this effect began.
    #[error("delegation_not_current")]
    DelegationNotCurrent,
    /// Auth/application/tool dependency is unavailable or the current scope was revoked.
    #[error("agent_tool_unavailable")]
    Unavailable,
    /// A tool effect/outcome has unknown commit state.
    #[error("agent_tool_reconciliation_required")]
    ReconciliationRequired,
}

/// Maximum number of first-party resource-lock keys accepted for one parallel scheduling
/// declaration. Exceeding it conservatively falls back to serial execution.
pub const MAX_AGENT_TOOL_RESOURCE_LOCKS: usize = 32;

/// Build-owned scheduling metadata consumed only by the Agent host.
///
/// This value never grants tool authority: every invocation still reloads `AuthContext` and goes
/// through the existing `ApplicationService` policy/approval/capability pipeline. It only decides
/// whether already-authoritative invocations may be in flight at the same time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentToolScheduling {
    parallel_safe: bool,
    resource_locks: Arc<[ResourceLockKey]>,
}

impl AgentToolScheduling {
    /// Conservative default for every unknown, dynamic, acting, or human-decision tool.
    #[must_use]
    pub fn serial() -> Self {
        Self {
            parallel_safe: false,
            resource_locks: Arc::from([]),
        }
    }

    /// Declare one reviewed first-party tool parallel-safe with canonical resource locks.
    ///
    /// Too many lock keys cannot safely allocate an unbounded lock set, so the declaration becomes
    /// serial instead of truncating keys and accidentally allowing a conflict.
    #[must_use]
    pub fn parallel(mut resource_locks: Vec<ResourceLockKey>) -> Self {
        resource_locks.sort();
        resource_locks.dedup();
        if resource_locks.len() > MAX_AGENT_TOOL_RESOURCE_LOCKS {
            return Self::serial();
        }
        Self {
            parallel_safe: true,
            resource_locks: resource_locks.into(),
        }
    }

    /// Whether the first-party host explicitly allowed concurrent execution.
    #[must_use]
    pub const fn is_parallel_safe(&self) -> bool {
        self.parallel_safe
    }

    /// Canonical opaque resource-lock keys.
    #[must_use]
    pub fn resource_locks(&self) -> &[ResourceLockKey] {
        &self.resource_locks
    }
}

impl Default for AgentToolScheduling {
    fn default() -> Self {
        Self::serial()
    }
}

/// Host-facing tool boundary. Production implementation always reloads AuthContext first.
#[async_trait]
pub trait AgentToolInvoker: Send + Sync {
    /// Return build-owned scheduling metadata for one exact tool name.
    ///
    /// The default is serial. Implementations must never derive this value from provider payloads,
    /// MCP annotations, database-authored descriptions, or renderer input.
    fn scheduling(&self, _tool_name: &str) -> AgentToolScheduling {
        AgentToolScheduling::serial()
    }

    /// Invoke one provider call through ApplicationService's unique tool pipeline.
    async fn invoke(
        &self,
        lease: &RunExecutionLease,
        provider_call_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<AgentToolReply, AgentToolInvokeError>;

    /// Invoke with a private Rust-host cancellation receiver.
    ///
    /// The conservative default preserves existing local/test implementations. Production
    /// gateways override it so an already-started protocol effect can cooperatively stop before
    /// the run records reconciliation.
    async fn invoke_cancellable(
        &self,
        lease: &RunExecutionLease,
        provider_call_id: &str,
        tool_name: &str,
        arguments: Value,
        _cancellation: ToolExecutionCancellation,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        self.invoke(lease, provider_call_id, tool_name, arguments)
            .await
    }

    /// Release bounded per-run sequence state after terminal cleanup.
    fn release(&self, _run_id: &RunId) {}
}

/// Machine callback tool boundary after dual-credential/run/tool authorization.
#[async_trait]
pub trait RemoteAgentToolInvoker: Send + Sync {
    /// Invoke through the same ApplicationService pipeline and durable sequence allocator as the
    /// built-in Agent; no callback-specific executor exists.
    async fn invoke_callback(
        &self,
        authorization: RemoteCallbackAuthorization,
        tool_name: &str,
        arguments: Value,
    ) -> Result<AgentToolReply, AgentToolInvokeError>;
}

/// Explicit fail-closed placeholder for tests/runtime configurations without a real tool plane.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAgentToolInvoker;

#[async_trait]
impl AgentToolInvoker for NoAgentToolInvoker {
    async fn invoke(
        &self,
        _lease: &RunExecutionLease,
        _provider_call_id: &str,
        _tool_name: &str,
        _arguments: Value,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        Err(AgentToolInvokeError::Unavailable)
    }
}

/// Agent tool gateway。调用方只能给 run/Bot/tool/args；actor 来自 `AuthContext`，call id 与
/// sequence 由本类型铸造，模型/remote Agent 没有自报三者的参数位。
pub struct AgentToolGateway {
    application: Arc<dyn ApplicationService>,
    sequence: Arc<dyn ToolCallSequence>,
    cancellations: Option<Arc<ToolCancellationRegistry>>,
}

impl AgentToolGateway {
    /// 绑定唯一 application 实例。
    #[must_use]
    pub fn new(application: Arc<dyn ApplicationService>) -> Self {
        Self::with_sequence(application, Arc::new(InMemoryToolCallSequence::default()))
    }

    /// Bind an authoritative cross-replica sequence allocator for production assembly.
    #[must_use]
    pub fn with_sequence(
        application: Arc<dyn ApplicationService>,
        sequence: Arc<dyn ToolCallSequence>,
    ) -> Self {
        Self {
            application,
            sequence,
            cancellations: None,
        }
    }

    /// Bind the same process-local cancellation registry used by the production executor.
    #[must_use]
    pub fn with_sequence_and_cancellations(
        application: Arc<dyn ApplicationService>,
        sequence: Arc<dyn ToolCallSequence>,
        cancellations: Arc<ToolCancellationRegistry>,
    ) -> Self {
        Self {
            application,
            sequence,
            cancellations: Some(cancellations),
        }
    }

    /// 铸造调用身份并穿过 `ApplicationService::execute`。
    pub async fn invoke(
        &self,
        auth: AuthContext,
        run_id: RunId,
        bot_id: BotId,
        tool_name: impl Into<String>,
        arguments: Value,
    ) -> Result<ToolResult, AppError> {
        self.invoke_captured(auth, run_id, bot_id, tool_name.into(), arguments)
            .await
            .1
    }

    async fn invoke_captured(
        &self,
        auth: AuthContext,
        run_id: RunId,
        bot_id: BotId,
        tool_name: String,
        arguments: Value,
    ) -> (ToolCallId, Result<ToolResult, AppError>) {
        self.invoke_captured_with_cancellation(auth, run_id, bot_id, tool_name, arguments, None)
            .await
    }

    async fn invoke_captured_with_cancellation(
        &self,
        auth: AuthContext,
        run_id: RunId,
        bot_id: BotId,
        tool_name: String,
        arguments: Value,
        cancellation: Option<ToolExecutionCancellation>,
    ) -> (ToolCallId, Result<ToolResult, AppError>) {
        let call_seq = match self.sequence.next(&run_id).await {
            Ok(sequence) => sequence,
            Err(ToolCallSequenceError::Unavailable | ToolCallSequenceError::Exhausted) => {
                return (
                    ToolCallId::new("unavailable"),
                    Err(AppError::DependencyUnavailable {
                        dependency: "agent_tool_sequence",
                    }),
                );
            }
        };
        let call_id = ToolCallId::new(Uuid::now_v7().to_string());
        let _cancellation_registration = match (cancellation, &self.cancellations) {
            (Some(cancellation), Some(registry)) => {
                let Some(registration) = registry.register(call_id.clone(), cancellation) else {
                    return (
                        call_id,
                        Err(AppError::DependencyUnavailable {
                            dependency: "tool_cancellation",
                        }),
                    );
                };
                Some(registration)
            }
            // Narrow tests may have no protocol executor sharing a registry. Production
            // Server/Desktop always use the explicit constructor below.
            (Some(_), None) | (None, _) => None,
        };
        let invocation = ToolInvocation {
            call_id: call_id.clone(),
            run_id,
            bot_id,
            call_seq,
            tool_name,
            arguments,
        };
        let result = match self
            .application
            .execute(auth, AppCommand::InvokeTool(invocation))
            .await
        {
            Ok(AppReply::Tool(result)) => Ok(result),
            Ok(
                AppReply::Health(_)
                | AppReply::Channels(_)
                | AppReply::Channel(_)
                | AppReply::ChannelRouting(_)
                | AppReply::Agents(_)
                | AppReply::Agent(_)
                | AppReply::AgentLifecycle(_)
                | AppReply::AgentConnectionVerdict(_)
                | AppReply::Components(_)
                | AppReply::ComponentCatalogueAdded(_)
                | AppReply::ComponentGovernanceUpdated(_)
                | AppReply::GrantedComponents(_)
                | AppReply::ComponentDecision(_)
                | AppReply::ComponentDataFunctions(_)
                | AppReply::ComponentFunctionCall(_)
                | AppReply::PendingComponentHumanDecisions(_)
                | AppReply::ComponentHumanDecisionResolved(_)
                | AppReply::SandboxedComponents(_)
                | AppReply::PublishedSandboxedComponents(_)
                | AppReply::SandboxedComponent(_)
                | AppReply::SandboxedComponentDeleted(_)
                | AppReply::CurrentUser(_)
                | AppReply::AdminStatus(_)
                | AppReply::People(_)
                | AppReply::Person(_)
                | AppReply::AuditEvents(_)
                | AppReply::ActionPolicy { .. }
                | AppReply::ThreadMinted(_)
                | AppReply::ThreadStatus(_)
                | AppReply::ThreadRunStarted(_)
                | AppReply::ThreadRunCancellation(_)
                | AppReply::RunReconciliation(_)
                | AppReply::RunEffectReceipts(_)
                | AppReply::ThreadHistory(_)
                | AppReply::ThreadConversation(_)
                | AppReply::PendingRemoteInterrupts(_)
                | AppReply::RemoteInterruptResolved(_)
                | AppReply::Memory(_)
                | AppReply::MemoryControl(_)
                | AppReply::Memories(_)
                | AppReply::MemoryRecall(_)
                | AppReply::AgentCallbackToken(_)
                | AppReply::AgentCallbackTokenRevoked(_)
                | AppReply::McpConnections(_)
                | AppReply::Credentials(_)
                | AppReply::ModelConnections(_)
                | AppReply::CustomModelCatalog(_)
                | AppReply::ModelConnection(_)
                | AppReply::ModelConnectionDeleted(_)
                | AppReply::CredentialWritten(_)
                | AppReply::CredentialRevoked(_)
                | AppReply::McpAdminPage(_)
                | AppReply::McpOAuthAuthorization(_)
                | AppReply::McpConnectionDisconnected(_)
                | AppReply::McpOAuthClientRegistered(_)
                | AppReply::McpServerMutation(_)
                | AppReply::McpServerRemoved(_)
                | AppReply::PluginSkills(_)
                | AppReply::PluginMutationAcknowledged(_)
                | AppReply::GrantedPlugins(_)
                | AppReply::PendingToolApprovals(_)
                | AppReply::ToolApprovalResolved(_)
                | AppReply::UiPreferences(_)
                | AppReply::ArtifactRegistrationReceipt(_)
                | AppReply::ArtifactMetadata(_)
                | AppReply::SourceRunArtifactIds(_)
                | AppReply::ArtifactReadOpened(_)
                | AppReply::ArtifactReadChunkDescriptor(_)
                | AppReply::ArtifactReadAcknowledged(_)
                | AppReply::ArtifactReadClosed(_)
                | AppReply::RuntimeCapabilities(_)
                | AppReply::RunCostBudget(_)
                | AppReply::ScreenSession(_),
            ) => Err(AppError::DependencyUnavailable {
                dependency: "application",
            }),
            Err(error) => Err(error),
        };
        (call_id, result)
    }

    /// Drop per-run sequence state after the host has committed a terminal.
    pub fn release(&self, run_id: &RunId) {
        self.sequence.release(run_id);
    }

    /// 借出同一个 application trait object，供组装测试证明没有第二个业务实例。
    #[must_use]
    pub fn application(&self) -> &Arc<dyn ApplicationService> {
        &self.application
    }
}

/// Production wrapper that reloads current DB authorization before each tool effect.
pub struct AuthorizedAgentToolGateway {
    gateway: AgentToolGateway,
    authorization: Arc<dyn AgentAuthorizationSource>,
}

impl AuthorizedAgentToolGateway {
    /// Bind one ApplicationService and one authoritative authorization source.
    #[must_use]
    pub fn new(
        application: Arc<dyn ApplicationService>,
        authorization: Arc<dyn AgentAuthorizationSource>,
    ) -> Self {
        Self::with_sequence(
            application,
            authorization,
            Arc::new(InMemoryToolCallSequence::default()),
        )
    }

    /// Production constructor using one durable allocator for built-in and remote callbacks.
    #[must_use]
    pub fn with_sequence(
        application: Arc<dyn ApplicationService>,
        authorization: Arc<dyn AgentAuthorizationSource>,
        sequence: Arc<dyn ToolCallSequence>,
    ) -> Self {
        Self {
            gateway: AgentToolGateway::with_sequence(application, sequence),
            authorization,
        }
    }

    /// Production constructor sharing exact-call cancellation with the tool executor.
    #[must_use]
    pub fn with_sequence_and_cancellations(
        application: Arc<dyn ApplicationService>,
        authorization: Arc<dyn AgentAuthorizationSource>,
        sequence: Arc<dyn ToolCallSequence>,
        cancellations: Arc<ToolCancellationRegistry>,
    ) -> Self {
        Self {
            gateway: AgentToolGateway::with_sequence_and_cancellations(
                application,
                sequence,
                cancellations,
            ),
            authorization,
        }
    }

    async fn invoke_inner(
        &self,
        lease: &RunExecutionLease,
        provider_call_id: &str,
        tool_name: &str,
        arguments: Value,
        cancellation: Option<ToolExecutionCancellation>,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        let auth = self.authorization.load(lease).await.map_err(|e| match e {
            openbot_application::AgentAuthorizationError::DelegationNotCurrent => {
                AgentToolInvokeError::DelegationNotCurrent
            }
            _ => AgentToolInvokeError::Unavailable,
        })?;
        if let Some(result) = self
            .invoke_human_component(auth.clone(), lease, provider_call_id, tool_name, &arguments)
            .await
        {
            return result;
        }
        if let Some(result) = self
            .invoke_component(auth.clone(), lease, tool_name, &arguments)
            .await
        {
            return result;
        }
        if let Some(result) = self
            .invoke_sandboxed_component(auth.clone(), lease, tool_name, &arguments)
            .await
        {
            return result;
        }
        let (call_id, result) = self
            .gateway
            .invoke_captured_with_cancellation(
                auth,
                lease.run_id().clone(),
                lease.bot_id().clone(),
                tool_name.to_owned(),
                arguments,
                cancellation,
            )
            .await;
        map_application_reply(call_id, result)
    }

    async fn invoke_component(
        &self,
        auth: AuthContext,
        lease: &RunExecutionLease,
        name: &str,
        arguments: &Value,
    ) -> Option<Result<AgentToolReply, AgentToolInvokeError>> {
        let confirmation = compiled_component_confirmation(name)?;
        let call_id = ToolCallId::new(Uuid::now_v7().to_string());
        let functions = match validate_compiled_component_arguments(name, arguments) {
            Ok(functions) => functions,
            Err(_) => {
                return Some(Ok(normalized_error_reply(
                    call_id,
                    "invalid_arguments",
                    "Component arguments were invalid, so nothing was shown.",
                )));
            }
        };
        let result = self
            .gateway
            .application()
            .execute(
                auth,
                AppCommand::DecideComponent {
                    component_name: name.to_owned(),
                    request: ComponentDecisionRequest {
                        agent_id: lease.bot_id().clone(),
                        functions,
                    },
                },
            )
            .await;
        Some(match result {
            Ok(AppReply::ComponentDecision(decision)) if decision.allowed => {
                AgentToolReply::new(call_id, confirmation.to_owned(), None)
            }
            Ok(AppReply::ComponentDecision(decision)) => match decision.refusal {
                Some(refusal) => AgentToolReply::new(
                    call_id,
                    component_refusal_message(name, &refusal),
                    Some(refusal.code_str().to_owned()),
                ),
                None => Err(AgentToolInvokeError::Unavailable),
            },
            Ok(_) => Err(AgentToolInvokeError::Unavailable),
            Err(AppError::PolicyRefused { rule, .. }) if rule == "delegation_not_current" => {
                Err(AgentToolInvokeError::DelegationNotCurrent)
            }
            Err(AppError::MalformedPayload { .. }) => Ok(normalized_error_reply(
                call_id,
                "invalid_arguments",
                "Component arguments were invalid, so nothing was shown.",
            )),
            Err(AppError::NotVisible | AppError::ForbiddenRole { .. }) => {
                Ok(normalized_error_reply(
                    call_id,
                    "component_not_available",
                    "Component is not available, so nothing was shown.",
                ))
            }
            Err(AppError::ReconciliationRequired { .. }) => {
                Err(AgentToolInvokeError::ReconciliationRequired)
            }
            Err(
                AppError::Unauthenticated
                | AppError::ArtifactGone { .. }
                | AppError::DependencyUnavailable { .. }
                | AppError::VendorFailure { .. }
                | AppError::PolicyRefused { .. }
                | AppError::StaleGeneration { .. }
                | AppError::RequestConflict { .. }
                | AppError::LeaseConflict { .. }
                | AppError::IdentityConflict { .. }
                | AppError::SensitiveWriteRefused { .. },
            ) => Err(AgentToolInvokeError::Unavailable),
        })
    }

    async fn invoke_human_component(
        &self,
        auth: AuthContext,
        lease: &RunExecutionLease,
        provider_call_id: &str,
        name: &str,
        arguments: &Value,
    ) -> Option<Result<AgentToolReply, AgentToolInvokeError>> {
        if !is_component_human_decision_name(name) {
            return None;
        }
        let decision_id = Uuid::now_v7().to_string();
        let call_id = ToolCallId::new(decision_id.clone());
        if provider_call_id.is_empty() || provider_call_id.as_bytes().contains(&0) {
            return Some(Err(AgentToolInvokeError::Unavailable));
        }
        let result = self
            .gateway
            .application()
            .execute(
                auth,
                AppCommand::AwaitComponentHumanDecision(ComponentHumanDecisionRequest {
                    decision_id: decision_id.clone(),
                    provider_call_id: provider_call_id.to_owned(),
                    run_id: lease.run_id().clone(),
                    thread_id: lease.thread_id().clone(),
                    agent_id: lease.bot_id().clone(),
                    component_name: name.to_owned(),
                    arguments: arguments.clone(),
                }),
            )
            .await;
        Some(match result {
            Ok(AppReply::ComponentHumanDecisionResolved(resolved))
                if resolved.decision_id == decision_id
                    && validate_component_human_decision_answer(
                        name,
                        arguments,
                        &resolved.answer,
                    )
                    .is_ok() =>
            {
                match serde_json::to_string(&resolved.answer) {
                    Ok(content) => AgentToolReply::new(call_id, content, None),
                    Err(_) => Err(AgentToolInvokeError::Unavailable),
                }
            }
            Ok(_) => Err(AgentToolInvokeError::Unavailable),
            Err(AppError::PolicyRefused { rule, .. }) if rule == "delegation_not_current" => {
                Err(AgentToolInvokeError::DelegationNotCurrent)
            }
            Err(AppError::MalformedPayload { .. }) => Ok(normalized_error_reply(
                call_id,
                "invalid_arguments",
                "The decision request was invalid, so the person was not asked.",
            )),
            Err(
                AppError::NotVisible
                | AppError::ForbiddenRole { .. }
                | AppError::PolicyRefused { .. },
            ) => Ok(normalized_error_reply(
                call_id,
                "component_human_unavailable",
                "The person could not answer this request. Do not act as if they did.",
            )),
            Err(AppError::RequestConflict { .. } | AppError::ReconciliationRequired { .. }) => {
                Err(AgentToolInvokeError::ReconciliationRequired)
            }
            Err(
                AppError::Unauthenticated
                | AppError::ArtifactGone { .. }
                | AppError::DependencyUnavailable { .. }
                | AppError::VendorFailure { .. }
                | AppError::StaleGeneration { .. }
                | AppError::LeaseConflict { .. }
                | AppError::IdentityConflict { .. }
                | AppError::SensitiveWriteRefused { .. },
            ) => Err(AgentToolInvokeError::Unavailable),
        })
    }

    async fn invoke_sandboxed_component(
        &self,
        auth: AuthContext,
        lease: &RunExecutionLease,
        name: &str,
        arguments: &Value,
    ) -> Option<Result<AgentToolReply, AgentToolInvokeError>> {
        if !is_sandboxed_component_name(name) {
            return None;
        }
        let call_id = ToolCallId::new(Uuid::now_v7().to_string());
        let result = self
            .gateway
            .application()
            .execute(
                auth,
                AppCommand::AuthorizeSandboxedComponent {
                    component_name: name.to_owned(),
                    agent_id: lease.bot_id().clone(),
                    arguments: arguments.clone(),
                },
            )
            .await;
        Some(match result {
            Ok(AppReply::ComponentDecision(decision)) if decision.allowed => {
                AgentToolReply::new(call_id, SANDBOXED_COMPONENT_CONFIRMATION.to_owned(), None)
            }
            Ok(AppReply::ComponentDecision(decision)) => match decision.refusal {
                Some(refusal) => AgentToolReply::new(
                    call_id,
                    sandboxed_component_refusal_message(name, &refusal),
                    Some(refusal.code_str().to_owned()),
                ),
                None => Err(AgentToolInvokeError::Unavailable),
            },
            Ok(_) => Err(AgentToolInvokeError::Unavailable),
            Err(AppError::PolicyRefused { rule, .. }) if rule == "delegation_not_current" => {
                Err(AgentToolInvokeError::DelegationNotCurrent)
            }
            Err(AppError::MalformedPayload { .. }) => Ok(normalized_error_reply(
                call_id,
                "invalid_arguments",
                "Component arguments were invalid, so nothing was shown.",
            )),
            Err(AppError::NotVisible | AppError::ForbiddenRole { .. }) => {
                Ok(normalized_error_reply(
                    call_id,
                    "component_not_available",
                    "Component is not available, so nothing was shown.",
                ))
            }
            Err(AppError::ReconciliationRequired { .. }) => {
                Err(AgentToolInvokeError::ReconciliationRequired)
            }
            Err(
                AppError::Unauthenticated
                | AppError::ArtifactGone { .. }
                | AppError::DependencyUnavailable { .. }
                | AppError::VendorFailure { .. }
                | AppError::PolicyRefused { .. }
                | AppError::StaleGeneration { .. }
                | AppError::RequestConflict { .. }
                | AppError::LeaseConflict { .. }
                | AppError::IdentityConflict { .. }
                | AppError::SensitiveWriteRefused { .. },
            ) => Err(AgentToolInvokeError::Unavailable),
        })
    }
}

impl core::fmt::Debug for AuthorizedAgentToolGateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizedAgentToolGateway")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AgentToolInvoker for AuthorizedAgentToolGateway {
    fn scheduling(&self, tool_name: &str) -> AgentToolScheduling {
        if compiled_component_parallel_safe(tool_name) {
            AgentToolScheduling::parallel(Vec::new())
        } else {
            AgentToolScheduling::serial()
        }
    }

    async fn invoke(
        &self,
        lease: &RunExecutionLease,
        provider_call_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        self.invoke_inner(lease, provider_call_id, tool_name, arguments, None)
            .await
    }

    async fn invoke_cancellable(
        &self,
        lease: &RunExecutionLease,
        provider_call_id: &str,
        tool_name: &str,
        arguments: Value,
        cancellation: ToolExecutionCancellation,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        self.invoke_inner(
            lease,
            provider_call_id,
            tool_name,
            arguments,
            Some(cancellation),
        )
        .await
    }

    fn release(&self, run_id: &RunId) {
        self.gateway.release(run_id);
    }
}

#[async_trait]
impl RemoteAgentToolInvoker for AuthorizedAgentToolGateway {
    async fn invoke_callback(
        &self,
        authorization: RemoteCallbackAuthorization,
        tool_name: &str,
        arguments: Value,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        let (call_id, result) = self
            .gateway
            .invoke_captured(
                authorization.auth().clone(),
                authorization.run().clone(),
                authorization.bot().clone(),
                tool_name.to_owned(),
                arguments,
            )
            .await;
        map_application_reply(call_id, result)
    }
}

fn map_application_reply(
    call_id: ToolCallId,
    result: Result<ToolResult, AppError>,
) -> Result<AgentToolReply, AgentToolInvokeError> {
    match result {
        Ok(result) => Ok(AgentToolReply {
            call_id,
            content: result.content,
            error_code: result.error_code.or_else(|| {
                (result.commit_state == openbot_contracts::tool::ToolCommitState::NotCommitted)
                    .then(|| "tool_not_committed".to_owned())
            }),
        }),
        Err(AppError::PolicyRefused { rule, .. }) if rule == "delegation_not_current" => {
            Err(AgentToolInvokeError::DelegationNotCurrent)
        }
        Err(AppError::PolicyRefused { .. }) => Ok(normalized_error_reply(
            call_id,
            "policy_refused",
            "Refused. Tool call was refused by policy.",
        )),
        Err(AppError::MalformedPayload { .. }) => Ok(normalized_error_reply(
            call_id,
            "invalid_arguments",
            "Tool arguments were invalid.",
        )),
        Err(AppError::NotVisible | AppError::ForbiddenRole { .. }) => Ok(normalized_error_reply(
            call_id,
            "tool_not_available",
            "Tool is not available.",
        )),
        Err(AppError::ReconciliationRequired { .. }) => {
            Err(AgentToolInvokeError::ReconciliationRequired)
        }
        Err(
            AppError::Unauthenticated
            | AppError::ArtifactGone { .. }
            | AppError::DependencyUnavailable { .. }
            | AppError::VendorFailure { .. }
            | AppError::StaleGeneration { .. }
            | AppError::RequestConflict { .. }
            | AppError::LeaseConflict { .. }
            | AppError::IdentityConflict { .. }
            | AppError::SensitiveWriteRefused { .. },
        ) => Err(AgentToolInvokeError::Unavailable),
    }
}

fn normalized_error_reply(call_id: ToolCallId, error_code: &str, content: &str) -> AgentToolReply {
    AgentToolReply::new(call_id, content.to_owned(), Some(error_code.to_owned()))
        .expect("static normalized tool reply is valid")
}

fn component_refusal_message(name: &str, refusal: &ComponentDecisionRefusal) -> String {
    let title = compiled_component_title(name).unwrap_or("Component");
    let reason = match refusal {
        ComponentDecisionRefusal::UnknownComponent
        | ComponentDecisionRefusal::Unpublished
        | ComponentDecisionRefusal::WithheldFromAgent => "It is not available to this Bot now.",
        ComponentDecisionRefusal::FunctionNotGranted { .. } => {
            "An administrator has not granted the data function it needs."
        }
        ComponentDecisionRefusal::FunctionUnavailable { .. } => {
            "This build does not provide the data function it needs."
        }
        ComponentDecisionRefusal::FunctionActorNotAuthorized { .. } => {
            "The person is not allowed to read the underlying data."
        }
        ComponentDecisionRefusal::FunctionPolicyRefused { .. } => {
            "The current action policy refused the underlying data read."
        }
    };
    format!("Not shown: {title}. {reason} Nothing was displayed, so tell the person that.")
}

fn sandboxed_component_refusal_message(name: &str, refusal: &ComponentDecisionRefusal) -> String {
    let reason = match refusal {
        ComponentDecisionRefusal::UnknownComponent
        | ComponentDecisionRefusal::Unpublished
        | ComponentDecisionRefusal::WithheldFromAgent => {
            "It is not available to this Bot at the moment."
        }
        ComponentDecisionRefusal::FunctionNotGranted { .. }
        | ComponentDecisionRefusal::FunctionUnavailable { .. }
        | ComponentDecisionRefusal::FunctionActorNotAuthorized { .. }
        | ComponentDecisionRefusal::FunctionPolicyRefused { .. } => {
            "Its sandbox contract was invalid."
        }
    };
    format!("Not shown: {name}. {reason} Nothing was displayed, so tell the person that.")
}

impl core::fmt::Debug for AgentToolGateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentToolGateway")
            .field("application", &"<dyn ApplicationService>")
            .field("sequence", &"<dyn ToolCallSequence>")
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct InMemoryToolCallSequence {
    next: Mutex<BTreeMap<RunId, u64>>,
}

#[async_trait]
impl ToolCallSequence for InMemoryToolCallSequence {
    async fn next(&self, run: &RunId) -> Result<u64, ToolCallSequenceError> {
        let mut sequences = self
            .next
            .lock()
            .map_err(|_| ToolCallSequenceError::Unavailable)?;
        let next = sequences.entry(run.clone()).or_insert(0);
        let current = *next;
        *next = next
            .checked_add(1)
            .ok_or(ToolCallSequenceError::Exhausted)?;
        Ok(current)
    }

    fn release(&self, run: &RunId) {
        if let Ok(mut sequences) = self.next.lock() {
            sequences.remove(run);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use async_trait::async_trait;
    use openbot_application::{AgentAuthorizationError, AppEventStream, health};
    use openbot_contracts::auth::Role;
    use openbot_contracts::command::{HealthReport, SubscriptionRequest};
    use openbot_contracts::components::{
        ASK_APPROVAL_COMPONENT_NAME, BOT_ACTIVITY_FUNCTION_NAME, ComponentApprovalAnswer,
        ComponentApprovalDecision, ComponentDecision, ComponentHumanDecisionAnswer,
        ComponentHumanDecisionRequest, ComponentHumanDecisionResolved,
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME, SHOW_QUOTE_COMPONENT_NAME,
    };
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId, ThreadId};
    use openbot_contracts::tool::{ToolCommitState, ToolResult};
    use openbot_domain::thread::FencingToken;
    use serde_json::json;

    use super::*;

    struct FakeApplication {
        calls: Mutex<Vec<(ActorId, ToolInvocation)>>,
        wrong_reply: bool,
    }

    struct ComponentApplication {
        decision: ComponentDecision,
        calls: Mutex<Vec<(ActorId, String, ComponentDecisionRequest)>>,
    }

    struct HumanComponentApplication {
        calls: Mutex<Vec<(ActorId, ComponentHumanDecisionRequest)>>,
        answer: ComponentHumanDecisionAnswer,
    }

    struct SandboxedComponentApplication {
        decision: ComponentDecision,
        calls: Mutex<Vec<(ActorId, String, BotId, Value)>>,
    }

    #[async_trait]
    impl ApplicationService for ComponentApplication {
        async fn execute(
            &self,
            auth: AuthContext,
            command: AppCommand,
        ) -> Result<AppReply, AppError> {
            let AppCommand::DecideComponent {
                component_name,
                request,
            } = command
            else {
                return Ok(AppReply::Health(HealthReport { ok: true }));
            };
            self.calls
                .lock()
                .unwrap()
                .push((auth.actor().clone(), component_name, request));
            Ok(AppReply::ComponentDecision(self.decision.clone()))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(openbot_application::use_cases::health_stream(
                Duration::from_secs(1),
            ))
        }
    }

    #[async_trait]
    impl ApplicationService for HumanComponentApplication {
        async fn execute(
            &self,
            auth: AuthContext,
            command: AppCommand,
        ) -> Result<AppReply, AppError> {
            let AppCommand::AwaitComponentHumanDecision(request) = command else {
                return Ok(AppReply::Health(HealthReport { ok: true }));
            };
            self.calls
                .lock()
                .unwrap()
                .push((auth.actor().clone(), request.clone()));
            Ok(AppReply::ComponentHumanDecisionResolved(
                ComponentHumanDecisionResolved {
                    decision_id: request.decision_id,
                    answer: self.answer.clone(),
                    replayed: false,
                },
            ))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(openbot_application::use_cases::health_stream(
                Duration::from_secs(1),
            ))
        }
    }

    #[async_trait]
    impl ApplicationService for SandboxedComponentApplication {
        async fn execute(
            &self,
            auth: AuthContext,
            command: AppCommand,
        ) -> Result<AppReply, AppError> {
            let AppCommand::AuthorizeSandboxedComponent {
                component_name,
                agent_id,
                arguments,
            } = command
            else {
                return Ok(AppReply::Health(HealthReport { ok: true }));
            };
            self.calls.lock().unwrap().push((
                auth.actor().clone(),
                component_name,
                agent_id,
                arguments,
            ));
            Ok(AppReply::ComponentDecision(self.decision.clone()))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(openbot_application::use_cases::health_stream(
                Duration::from_secs(1),
            ))
        }
    }

    struct FixedAuthorization;

    #[async_trait]
    impl AgentAuthorizationSource for FixedAuthorization {
        async fn load(
            &self,
            lease: &RunExecutionLease,
        ) -> Result<AuthContext, AgentAuthorizationError> {
            Ok(auth(lease.actor_id().as_str()))
        }
    }

    #[async_trait]
    impl ApplicationService for FakeApplication {
        async fn execute(
            &self,
            auth: AuthContext,
            command: AppCommand,
        ) -> Result<AppReply, AppError> {
            let AppCommand::InvokeTool(invocation) = command else {
                return Ok(AppReply::Health(HealthReport { ok: true }));
            };
            self.calls
                .lock()
                .unwrap()
                .push((auth.actor().clone(), invocation.clone()));
            if self.wrong_reply {
                return Ok(AppReply::Health(health()));
            }
            Ok(AppReply::Tool(ToolResult {
                call_id: invocation.call_id,
                content: "ok".to_owned(),
                error_code: None,
                commit_state: ToolCommitState::Committed,
                visible_bytes: 2,
                truncated: false,
            }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(openbot_application::use_cases::health_stream(
                Duration::from_secs(1),
            ))
        }
    }

    fn auth(actor: &str) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep-1"),
            TenantId::new("tenant-1"),
            ActorId::new(actor),
            [Role::User],
            openbot_contracts::auth::AuthGeneration::new(1),
            false,
        )
    }

    fn fake(wrong_reply: bool) -> Arc<FakeApplication> {
        Arc::new(FakeApplication {
            calls: Mutex::new(Vec::new()),
            wrong_reply,
        })
    }

    fn lease() -> RunExecutionLease {
        RunExecutionLease::new(
            RunId::new("run-component"),
            ThreadId::new("thread-component"),
            BotId::new("bot-1"),
            ActorId::new("actor-verified"),
            FencingToken::new(1).unwrap(),
            0,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn actor_call_id_and_sequence_are_all_rust_authoritative() {
        let application = fake(false);
        let gateway = AgentToolGateway::new(application.clone());
        for (run, expected_seq) in [("run-a", 0), ("run-a", 1), ("run-b", 0)] {
            gateway
                .invoke(
                    auth("actor-verified"),
                    RunId::new(run),
                    BotId::new("bot-1"),
                    "computer.write",
                    json!({"claimedActor":"attacker","callSeq":999}),
                )
                .await
                .unwrap();
            let calls = application.calls.lock().unwrap();
            let (actor, invocation) = calls.last().unwrap();
            assert_eq!(actor.as_str(), "actor-verified");
            assert_eq!(invocation.call_seq, expected_seq);
            assert_eq!(
                Uuid::parse_str(invocation.call_id.as_str())
                    .unwrap()
                    .get_version_num(),
                7,
            );
        }
        let calls = application.calls.lock().unwrap();
        assert_ne!(calls[0].1.call_id, calls[1].1.call_id);
        assert_ne!(calls[1].1.call_id, calls[2].1.call_id);
    }

    #[tokio::test]
    async fn concurrent_calls_get_a_gap_free_unique_sequence_per_run() {
        let application = fake(false);
        let gateway = Arc::new(AgentToolGateway::new(application.clone()));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let gateway = Arc::clone(&gateway);
            tasks.push(tokio::spawn(async move {
                gateway
                    .invoke(
                        auth("actor-1"),
                        RunId::new("run-concurrent"),
                        BotId::new("bot-1"),
                        "computer.write",
                        json!({}),
                    )
                    .await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        let mut sequences: Vec<u64> = application
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, invocation)| invocation.call_seq)
            .collect();
        sequences.sort_unstable();
        assert_eq!(sequences, (0..32).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn a_mismatched_application_reply_is_not_forged_into_tool_success() {
        let application = fake(true);
        let gateway = AgentToolGateway::new(application);
        let error = gateway
            .invoke(
                auth("actor-1"),
                RunId::new("run-1"),
                BotId::new("bot-1"),
                "computer.write",
                json!({}),
            )
            .await
            .expect_err("非 Tool reply 必须报契约破损");
        assert_eq!(error.code().as_str(), "dependency_unavailable");
    }

    #[test]
    fn production_scheduling_only_allows_exact_ordinary_build_components() {
        let gateway = AuthorizedAgentToolGateway::new(fake(false), Arc::new(FixedAuthorization));
        assert!(
            gateway
                .scheduling(SHOW_QUOTE_COMPONENT_NAME)
                .is_parallel_safe()
        );
        for serial in [
            ASK_APPROVAL_COMPONENT_NAME,
            "remember",
            "custom_delivery_eta",
            "vendor.claimed_parallel",
        ] {
            assert!(!gateway.scheduling(serial).is_parallel_safe());
        }

        let too_many = (0..=MAX_AGENT_TOOL_RESOURCE_LOCKS)
            .map(|index| ResourceLockKey::new(format!("resource:{index}")))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(!AgentToolScheduling::parallel(too_many).is_parallel_safe());
    }

    #[tokio::test]
    async fn ordinary_components_validate_derive_functions_and_use_fresh_decision() {
        let application = Arc::new(ComponentApplication {
            decision: ComponentDecision::allowed(),
            calls: Mutex::new(Vec::new()),
        });
        let gateway =
            AuthorizedAgentToolGateway::new(application.clone(), Arc::new(FixedAuthorization));
        let quote = gateway
            .invoke(
                &lease(),
                "provider-quote",
                SHOW_QUOTE_COMPONENT_NAME,
                json!({"quote":"Exact words","attribution":"the report"}),
            )
            .await
            .unwrap();
        assert_eq!(
            quote.content(),
            "The quotation is now on screen for the person."
        );
        assert_eq!(quote.error_code(), None);
        let activity = gateway
            .invoke(
                &lease(),
                "provider-activity",
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
                json!({"report":"activity","days":7}),
            )
            .await
            .unwrap();
        assert!(activity.content().contains("filled with figures"));
        {
            let calls = application.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].0.as_str(), "actor-verified");
            assert!(calls[0].2.functions.is_empty());
            assert_eq!(calls[1].2.functions, [BOT_ACTIVITY_FUNCTION_NAME]);
        }

        let invalid = gateway
            .invoke(
                &lease(),
                "provider-invalid",
                SHOW_QUOTE_COMPONENT_NAME,
                json!({"quote":"missing attribution"}),
            )
            .await
            .unwrap();
        assert_eq!(invalid.error_code(), Some("invalid_arguments"));
        assert_eq!(application.calls.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn component_refusal_is_one_durable_model_visible_error_reply() {
        let application = Arc::new(ComponentApplication {
            decision: ComponentDecision::refused(ComponentDecisionRefusal::WithheldFromAgent),
            calls: Mutex::new(Vec::new()),
        });
        let gateway = AuthorizedAgentToolGateway::new(application, Arc::new(FixedAuthorization));
        let reply = gateway
            .invoke(
                &lease(),
                "provider-refused",
                SHOW_QUOTE_COMPONENT_NAME,
                json!({"quote":"Exact words","attribution":"the report"}),
            )
            .await
            .unwrap();
        assert_eq!(reply.error_code(), Some("component_withheld"));
        assert!(reply.content().starts_with("Not shown: Quotation."));
    }

    #[tokio::test]
    async fn sandboxed_component_uses_dynamic_authority_and_exact_upstream_confirmation() {
        let application = Arc::new(SandboxedComponentApplication {
            decision: ComponentDecision::allowed(),
            calls: Mutex::new(Vec::new()),
        });
        let gateway =
            AuthorizedAgentToolGateway::new(application.clone(), Arc::new(FixedAuthorization));
        let arguments = json!({"title":"Delivery ETA"});
        let reply = gateway
            .invoke(
                &lease(),
                "provider-sandbox-1",
                "custom_delivery_eta",
                arguments.clone(),
            )
            .await
            .unwrap();
        assert_eq!(reply.content(), SANDBOXED_COMPONENT_CONFIRMATION);
        assert_eq!(reply.error_code(), None);
        {
            let calls = application.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0.as_str(), "actor-verified");
            assert_eq!(calls[0].1, "custom_delivery_eta");
            assert_eq!(calls[0].2.as_str(), "bot-1");
            assert_eq!(calls[0].3, arguments);
        }

        let refused = Arc::new(SandboxedComponentApplication {
            decision: ComponentDecision::refused(ComponentDecisionRefusal::WithheldFromAgent),
            calls: Mutex::new(Vec::new()),
        });
        let gateway = AuthorizedAgentToolGateway::new(refused, Arc::new(FixedAuthorization));
        let reply = gateway
            .invoke(
                &lease(),
                "provider-sandbox-2",
                "custom_delivery_eta",
                json!({"title":"Delivery ETA"}),
            )
            .await
            .unwrap();
        assert_eq!(reply.error_code(), Some("component_withheld"));
        assert!(
            reply
                .content()
                .starts_with("Not shown: custom_delivery_eta.")
        );
    }

    #[tokio::test]
    async fn human_component_binds_provider_pairing_and_returns_the_recorded_answer() {
        let answer = ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
            decision: ComponentApprovalDecision::Approved,
            note: Some("looks right".to_owned()),
        });
        let application = Arc::new(HumanComponentApplication {
            calls: Mutex::new(Vec::new()),
            answer: answer.clone(),
        });
        let gateway =
            AuthorizedAgentToolGateway::new(application.clone(), Arc::new(FixedAuthorization));
        let arguments = json!({"title":"Refund?","summary":"Duplicate charge"});
        let reply = gateway
            .invoke(
                &lease(),
                "provider-human-1",
                ASK_APPROVAL_COMPONENT_NAME,
                arguments.clone(),
            )
            .await
            .unwrap();
        assert_eq!(reply.error_code(), None);
        assert_eq!(
            serde_json::from_str::<ComponentHumanDecisionAnswer>(reply.content()).unwrap(),
            answer
        );
        assert_eq!(
            Uuid::parse_str(reply.call_id().as_str())
                .unwrap()
                .get_version_num(),
            7
        );
        let calls = application.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.as_str(), "actor-verified");
        assert_eq!(calls[0].1.provider_call_id, "provider-human-1");
        assert_eq!(calls[0].1.run_id, RunId::new("run-component"));
        assert_eq!(calls[0].1.thread_id, ThreadId::new("thread-component"));
        assert_eq!(calls[0].1.agent_id, BotId::new("bot-1"));
        assert_eq!(calls[0].1.component_name, ASK_APPROVAL_COMPONENT_NAME);
        assert_eq!(calls[0].1.arguments, arguments);
    }
}
