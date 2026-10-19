//! Tauri 2.11.5 custom-protocol adapter for the shared Leptos bundle.

mod artifact_read;
pub use artifact_read::DesktopArtifactReadOperation;
mod artifact_reads;
mod artifact_save_receipt;
mod artifacts;
mod assets;
mod custom_model_catalog;
#[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
mod local_confirmation;
mod memories;
mod model_connections;
pub(crate) mod runtime_capabilities;
mod session_status;
mod window_chrome;

use assets::StaticAssets;
#[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
pub(crate) use assets::VerifiedUiAssets;
pub(crate) use assets::static_asset_max_bytes;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64 as HostAtomicU64, Ordering as HostAtomicOrdering};
use std::sync::{Arc, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};

use http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode};
use openbot_contracts::agent::{
    AgentConnectionTestRequest, AgentMutationRequest, AgentProfileResponse, AgentProfilesResponse,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::budget::RunCostBudgetPreference;
#[cfg(test)]
use openbot_contracts::command::BeginThreadRunBody;
use openbot_contracts::command::{
    AppCommand, AppReply, BeginThreadRun, BeginThreadRunV2, CancelThreadRun, ChannelDetailResponse,
    CreateChannelRequest, MAX_THREAD_MESSAGE_BYTES, RouteChannelRequest, SubscriptionRequest,
    ThreadRunCancellationState,
};
use openbot_contracts::components::{
    ComponentAgentGrantRequest, ComponentCatalogueRequest, ComponentDecisionRequest,
    ComponentDraftRequest, ComponentFunctionCallRequest, ComponentFunctionGrantRequest,
    ComponentGovernanceMutation, ComponentHumanDecisionAnswer, ComponentPublicationRequest,
};
use openbot_contracts::credential_admin::{
    CredentialPageRequest, CredentialRevocationReceipt, CredentialWrite,
};
use openbot_contracts::desktop::{
    DESKTOP_STRUCTURED_CLOSE_COMMAND, DESKTOP_STRUCTURED_OPEN_COMMAND,
    DESKTOP_WINDOW_CHROME_COMMAND, DesktopStructuredSubscriptionCloseRequest,
    DesktopStructuredSubscriptionOpened,
};
use openbot_contracts::error::{AppError, SensitiveWriteReason};
use openbot_contracts::ids::{BotId, ChannelId, RunId, ThreadId};
use openbot_contracts::mcp::{
    McpCuratedServerSelection, McpCustomServerRegistration, PluginGrantKind, PluginGrantMutation,
    PluginSkillMutation, PluginSkillRevisionRequest,
};
use openbot_contracts::people::CurrentUserResponse;
use openbot_contracts::reconciliation::{
    MAX_RUN_RECONCILIATION_RESPONSE_BYTES, RunReconciliationQuery,
};
use openbot_contracts::remote_interrupt::{RemoteInterruptAnswer, RemoteInterruptResolved};
use openbot_contracts::request_binding::{
    ArtifactCleanupHostObservation, ArtifactCleanupHostTailFactory, ArtifactCleanupHostTailWitness,
    ArtifactCleanupHostTarget, ArtifactCleanupSessionFacts, ArtifactReadCurrentError,
    ArtifactReadCurrentTarget, ArtifactReadTailWitness, CustomModelCatalogHostObservation,
    CustomModelCatalogHostTailFactory, CustomModelCatalogHostTailWitness,
    CustomModelCatalogHostTarget, CustomModelCatalogSessionFacts, HostRequestBindingError,
    HostRequestBindingGuard, HostRequestBindingIdentity, HostRequestBindingKind,
    RememberPreferenceHostObservation, RememberPreferenceHostTailFactory,
    RememberPreferenceHostTailWitness, RememberPreferenceHostTarget,
    RememberPreferenceSessionFacts, RequestBindingIssuer, RequestBindingOwnerLease,
    RequestBindingOwnerObservation, SourceRunArtifactIdsCurrentCheck,
    SourceRunArtifactIdsCurrentTarget, VerifiedHostRequestBinding,
};

use openbot_contracts::request_binding::{
    ThreadHistoryHostObservation, ThreadHistoryHostTailFactory, ThreadHistoryHostTailWitness,
    ThreadHistoryHostTarget, ThreadHistorySessionFacts,
};
use openbot_contracts::sandboxed::{
    SandboxedComponentRevisionRequest, SaveSandboxedComponentRequest,
};
use openbot_contracts::tool::ToolApprovalDecision;
#[cfg(test)]
use openbot_contracts::ui::UiPreferences;
use openbot_contracts::ui::{UiLocale, UiTheme, UpdateUiPreferences};
use serde::de::DeserializeOwned;
use serde_json::json;
use tauri::ipc::Channel;
use tauri::{Builder, State, Webview};

#[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
use crate::local_confirmation::GrantHandle;
#[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
use crate::local_confirmation_host::LocalConfirmationHost;
#[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
use crate::local_confirmation_service::{LocalConfirmationService, sample_now};
use crate::{
    CancellationToken, DesktopStructuredEventBridge, DesktopStructuredOpenError,
    DesktopStructuredPumpExit, DesktopStructuredSubscription, DesktopWindowLifecycle,
    InProcessTransport, OpenSessionError, WindowLabel, pump_tauri_structured_events,
    register_tauri_window_lifecycle,
};

const API_BODY_MAX_BYTES: usize = 4096;
const AGENT_BODY_MAX_BYTES: usize = 64 * 1024;
const REMOTE_INTERRUPT_BODY_MAX_BYTES: usize = 64 * 1024 + 1024;
// Server's single request-body cap and the public message cap are both 1 MiB. Using the contracts
// constant keeps Desktop from accepting a larger renderer-materialized body than Axum.
const CHANNEL_THREAD_BODY_MAX_BYTES: usize = MAX_THREAD_MESSAGE_BYTES;
const COMPONENT_CATALOGUE_BODY_MAX_BYTES: usize = 256 * 1024;
const COMPONENT_DECISION_BODY_MAX_BYTES: usize = 256 * 1024;
const COMPONENT_GOVERNANCE_BODY_MAX_BYTES: usize = 68 * 1024;
const SANDBOXED_COMPONENT_BODY_MAX_BYTES: usize = 1024 * 1024;
const MCP_ADMIN_BODY_MAX_BYTES: usize = 16 * 1024;
const PLUGIN_SKILL_BODY_MAX_BYTES: usize = 70 * 1024;
const HTML_ROOT_MARKER: &str = "<html lang=\"en\">";
const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
                   connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; \
                   object-src 'none'; base-uri 'none'; form-action 'self'; frame-src 'self'; frame-ancestors 'none'; \
                   worker-src 'none'; manifest-src 'none'; media-src 'none'";

/// Exact audited custom-command allowlist registered by [`register_tauri_protocol`].
pub const DESKTOP_TAURI_COMMANDS: [&str; 3] = [
    DESKTOP_STRUCTURED_OPEN_COMMAND,
    DESKTOP_STRUCTURED_CLOSE_COMMAND,
    DESKTOP_WINDOW_CHROME_COMMAND,
];

/// Host registration/open error without leaking filesystem content.
#[derive(Debug, thiserror::Error)]
pub enum TauriHostError {
    /// Bundle path/index failed validation.
    #[error("desktop_bundle_invalid")]
    InvalidBundle,
    /// Custom scheme is not one closed lowercase URI-scheme token.
    #[error("desktop_scheme_invalid")]
    InvalidScheme,
    /// A window label already owns an authority binding.
    #[error("desktop_window_already_bound")]
    WindowAlreadyBound,
    /// Window authority lock was poisoned.
    #[error("desktop_window_authority_unavailable")]
    AuthorityUnavailable,
    /// Fresh-session duration cannot be represented by the monotonic clock.
    #[error("desktop_freshness_invalid")]
    InvalidFreshness,
    /// No verified authority is bound to the requesting native window.
    #[error("desktop_window_unbound")]
    WindowUnbound,
    /// Typed application subscription or Desktop transport rejected the stream.
    #[error(transparent)]
    StructuredSubscription(#[from] DesktopStructuredOpenError),
    /// Host window-binding counter is exhausted; wrapping could attach work to a new window.
    #[error("desktop_window_binding_counter_exhausted")]
    WindowBindingCounterExhausted,
    /// Tauri framing was reached before the background application owner became ready.
    #[error("desktop_protocol_not_ready")]
    ProtocolNotReady,
    /// A second background owner attempted to replace the process-wide protocol.
    #[error("desktop_protocol_already_ready")]
    ProtocolAlreadyReady,
}

/// Host-verified authority for one webview label. The renderer cannot construct this type.
#[derive(Clone)]
struct WindowAuthority {
    auth: AuthContext,
    fresh_until: Option<Instant>,
    binding_id: u64,
    closed: CancellationToken,
    chrome_pending: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    local_confirmation: Option<LocalConfirmationBinding>,
}

#[derive(Clone)]
#[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
struct LocalConfirmationBinding {
    grant: GrantHandle,
    service: Arc<LocalConfirmationService>,
}

impl WindowAuthority {
    fn is_fresh(&self) -> bool {
        if self.closed.is_cancelled() {
            return false;
        }
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        if let Some(local) = &self.local_confirmation {
            return local.service.is_native_available() && local.grant.is_fresh(sample_now());
        }
        self.fresh_until
            .is_some_and(|deadline| Instant::now() < deadline)
    }
}

#[derive(Clone, Copy)]
enum ComponentGovernanceRoute<'a> {
    Functions {
        raw_name: &'a str,
    },
    Function {
        raw_name: &'a str,
        raw_function: &'a str,
    },
    Grants {
        raw_name: &'a str,
    },
    Grant {
        raw_name: &'a str,
        raw_agent_id: &'a str,
    },
    Publication {
        raw_name: &'a str,
    },
    Draft {
        raw_name: &'a str,
    },
}

#[derive(Clone, Copy)]
enum AgentRoute<'a> {
    Detail { raw_agent_id: &'a str },
    Duplicate { raw_agent_id: &'a str },
    Hide { raw_agent_id: &'a str },
    Unhide { raw_agent_id: &'a str },
    CallbackToken { raw_agent_id: &'a str },
}

#[derive(Clone, Copy)]
enum AgentReplyKind {
    Profile(StatusCode),
    CallbackToken,
    Empty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentBodyError {
    Malformed,
    TooLarge,
}

#[derive(Clone, Copy)]
enum ThreadRoute<'a> {
    Status {
        raw_thread_id: &'a str,
    },
    Conversation {
        raw_thread_id: &'a str,
    },
    Runs {
        raw_thread_id: &'a str,
    },
    Cancel {
        raw_thread_id: &'a str,
        raw_run_id: &'a str,
    },
    Reconciliation {
        raw_thread_id: &'a str,
        raw_run_id: &'a str,
        kind: ReconciliationRead,
    },
}

#[derive(Clone, Copy)]
enum ReconciliationRead {
    Attempts,
    Receipts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SensitiveBodyError {
    Malformed,
    TooLarge,
}

impl<'a> AgentRoute<'a> {
    fn raw_agent_id(self) -> &'a str {
        match self {
            Self::Detail { raw_agent_id }
            | Self::Duplicate { raw_agent_id }
            | Self::Hide { raw_agent_id }
            | Self::Unhide { raw_agent_id }
            | Self::CallbackToken { raw_agent_id } => raw_agent_id,
        }
    }
}

fn agent_route(path: &str) -> Option<AgentRoute<'_>> {
    let segments = path
        .strip_prefix("/api/agents/")?
        .split('/')
        .collect::<Vec<_>>();
    match segments.as_slice() {
        [raw_agent_id] => Some(AgentRoute::Detail { raw_agent_id }),
        [raw_agent_id, "duplicate"] => Some(AgentRoute::Duplicate { raw_agent_id }),
        [raw_agent_id, "hide"] => Some(AgentRoute::Hide { raw_agent_id }),
        [raw_agent_id, "unhide"] => Some(AgentRoute::Unhide { raw_agent_id }),
        [raw_agent_id, "callback-token"] => Some(AgentRoute::CallbackToken { raw_agent_id }),
        _ => None,
    }
}

fn raw_channel_id(path: &str) -> Option<&str> {
    let raw = path.strip_prefix("/api/channels/")?;
    (!raw.is_empty() && raw != "events" && !raw.contains('/')).then_some(raw)
}

impl<'a> ThreadRoute<'a> {
    fn raw_thread_id(self) -> &'a str {
        match self {
            Self::Status { raw_thread_id }
            | Self::Conversation { raw_thread_id }
            | Self::Runs { raw_thread_id }
            | Self::Cancel { raw_thread_id, .. }
            | Self::Reconciliation { raw_thread_id, .. } => raw_thread_id,
        }
    }
}

fn thread_route(path: &str) -> Option<ThreadRoute<'_>> {
    let segments = path
        .strip_prefix("/api/threads/")?
        .split('/')
        .collect::<Vec<_>>();
    match segments.as_slice() {
        [raw_thread_id] if *raw_thread_id != "mint" && !raw_thread_id.is_empty() => {
            Some(ThreadRoute::Status { raw_thread_id })
        }
        [raw_thread_id, "conversation"] if !raw_thread_id.is_empty() => {
            Some(ThreadRoute::Conversation { raw_thread_id })
        }
        [raw_thread_id, "runs"] if !raw_thread_id.is_empty() => {
            Some(ThreadRoute::Runs { raw_thread_id })
        }
        [raw_thread_id, "runs", raw_run_id, "cancel"]
            if !raw_thread_id.is_empty() && !raw_run_id.is_empty() =>
        {
            Some(ThreadRoute::Cancel {
                raw_thread_id,
                raw_run_id,
            })
        }
        [raw_thread_id, "runs", raw_run_id, "reconciliation"]
            if !raw_thread_id.is_empty() && !raw_run_id.is_empty() =>
        {
            Some(ThreadRoute::Reconciliation {
                raw_thread_id,
                raw_run_id,
                kind: ReconciliationRead::Attempts,
            })
        }
        [
            raw_thread_id,
            "runs",
            raw_run_id,
            "reconciliation",
            "receipts",
        ] if !raw_thread_id.is_empty() && !raw_run_id.is_empty() => {
            Some(ThreadRoute::Reconciliation {
                raw_thread_id,
                raw_run_id,
                kind: ReconciliationRead::Receipts,
            })
        }
        _ => None,
    }
}

impl<'a> ComponentGovernanceRoute<'a> {
    fn component_name(self) -> &'a str {
        match self {
            Self::Functions { raw_name }
            | Self::Function { raw_name, .. }
            | Self::Grants { raw_name }
            | Self::Grant { raw_name, .. }
            | Self::Publication { raw_name }
            | Self::Draft { raw_name } => raw_name,
        }
    }
}

fn component_governance_route(path: &str) -> Option<ComponentGovernanceRoute<'_>> {
    let segments = path
        .strip_prefix("/api/components/")?
        .split('/')
        .collect::<Vec<_>>();
    match segments.as_slice() {
        [raw_name, "functions"] => Some(ComponentGovernanceRoute::Functions { raw_name }),
        [raw_name, "functions", raw_function] => Some(ComponentGovernanceRoute::Function {
            raw_name,
            raw_function,
        }),
        [raw_name, "grants"] => Some(ComponentGovernanceRoute::Grants { raw_name }),
        [raw_name, "grants", raw_agent_id] => Some(ComponentGovernanceRoute::Grant {
            raw_name,
            raw_agent_id,
        }),
        [raw_name, "publication"] => Some(ComponentGovernanceRoute::Publication { raw_name }),
        [raw_name, "draft"] => Some(ComponentGovernanceRoute::Draft { raw_name }),
        _ => None,
    }
}

/// Window observations kept separately from the actual protocol owner's lifecycle lease.
struct WindowBindingRegistry {
    next_window_binding_id: HostAtomicU64,
    windows: Arc<RwLock<BTreeMap<String, WindowAuthority>>>,
    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    local_confirmation_slot: Arc<OnceLock<Weak<LocalConfirmationService>>>,
    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    runtime_capability_facts:
        OnceLock<Weak<openbot_infra::runtime_capability_facts::PostgresRuntimeCapabilityFacts>>,
}
/// Recheck this original window and its actual identity source without retaining the owner lease.
struct WindowRequestBindingGuard {
    registry: Weak<WindowBindingRegistry>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    label: String,
    id: u64,
    expected: AuthContext,
    source: Option<Arc<dyn HostRequestBindingGuard>>,
    upstream: Option<VerifiedHostRequestBinding>,
}
impl WindowRequestBindingGuard {
    fn repository_tail_source(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            owner: self.owner.clone(),
            issuer: self.issuer.clone(),
            label: self.label.clone(),
            id: self.id,
            expected: self.expected.clone(),
            source: None,
            upstream: None,
        }
    }

    fn check_window(&self, auth: &AuthContext) -> Result<(), HostRequestBindingError> {
        if !self.owner.is_current() || auth != &self.expected {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if !self.issuer.owns_identity(binding.identity()) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let registry = self
            .registry
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let windows = registry
            .windows
            .try_read()
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        match windows.get(&self.label) {
            Some(current)
                if current.binding_id == self.id
                    && !current.closed.is_cancelled()
                    && current.auth == self.expected =>
            {
                Ok(())
            }
            _ => Err(HostRequestBindingError::NotCurrent),
        }
    }
}
impl HostRequestBindingGuard for WindowRequestBindingGuard {
    fn borrow_artifact_cleanup_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactCleanupHostTarget,
        deadline: Instant,
    ) -> Result<ArtifactCleanupHostObservation<'a>, HostRequestBindingError> {
        self.check_window(auth)?;
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if !self
            .issuer
            .matches_desktop_window_epoch(binding.identity(), &self.label, self.id)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        // The enrolled real Local source lends its actual artifact attachment. Its async
        // current guard and an upstream Remote binding do not authorize this operation.
        let source = self
            .source
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let inner = source.borrow_artifact_cleanup_host_before(auth, target, deadline)?;
        self.check_window(auth)?;
        if inner.kind() != HostRequestBindingKind::DesktopWindow
            || !inner.identity().same_binding(binding.identity())
            || inner.server_session_epoch().is_some()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        ArtifactCleanupHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(WindowArtifactCleanupTailFactory {
                window: self.repository_tail_source(),
                original: binding.identity().clone(),
                inner,
            }),
        )
    }

    fn borrow_custom_model_catalog_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn CustomModelCatalogHostTarget,
        deadline: Instant,
    ) -> Result<CustomModelCatalogHostObservation<'a>, HostRequestBindingError> {
        self.check_window(auth)?;
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if !self
            .issuer
            .matches_desktop_window_epoch(binding.identity(), &self.label, self.id)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        // The enrolled real Local source lends its repository attachment. Its async
        // current guard and an upstream Remote binding do not authorize this operation.
        let source = self
            .source
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let inner = source.borrow_custom_model_catalog_host_before(auth, target, deadline)?;
        self.check_window(auth)?;
        if inner.kind() != HostRequestBindingKind::DesktopWindow
            || !inner.identity().same_binding(binding.identity())
            || inner.server_session_epoch().is_some()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        CustomModelCatalogHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(WindowCustomModelCatalogTailFactory {
                window: self.repository_tail_source(),
                original: binding.identity().clone(),
                inner,
            }),
        )
    }
    fn borrow_remember_preference_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn RememberPreferenceHostTarget,
        deadline: Instant,
    ) -> Result<RememberPreferenceHostObservation<'a>, HostRequestBindingError> {
        self.check_window(auth)?;
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if !self
            .issuer
            .matches_desktop_window_epoch(binding.identity(), &self.label, self.id)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        // The enrolled real Local source lends its repository attachment. Its async
        // current guard and an upstream Remote binding do not authorize this operation.
        let source = self
            .source
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let inner = source.borrow_remember_preference_host_before(auth, target, deadline)?;
        self.check_window(auth)?;
        if inner.kind() != HostRequestBindingKind::DesktopWindow
            || !inner.identity().same_binding(binding.identity())
            || inner.server_session_epoch().is_some()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        RememberPreferenceHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(WindowRememberPreferenceTailFactory {
                window: self.repository_tail_source(),
                original: binding.identity().clone(),
                inner,
            }),
        )
    }
    fn borrow_thread_history_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ThreadHistoryHostTarget,
        deadline: Instant,
    ) -> Result<ThreadHistoryHostObservation<'a>, HostRequestBindingError> {
        self.check_window(auth)?;
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if !self
            .issuer
            .matches_desktop_window_epoch(binding.identity(), &self.label, self.id)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        // The enrolled real Local source lends its Thread observer attachment. Its async
        // current guard and an upstream Remote binding do not authorize this operation.
        let source = self
            .source
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let inner = source.borrow_thread_history_host_before(auth, target, deadline)?;
        self.check_window(auth)?;
        if inner.kind() != HostRequestBindingKind::DesktopWindow
            || !inner.identity().same_binding(binding.identity())
            || inner.server_session_epoch().is_some()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        ThreadHistoryHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(WindowThreadHistoryTailFactory {
                window: self.repository_tail_source(),
                original: binding.identity().clone(),
                inner,
            }),
        )
    }

    fn verify_source_run_artifact_ids_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn SourceRunArtifactIdsCurrentTarget,
        deadline: Instant,
    ) -> SourceRunArtifactIdsCurrentCheck<'a> {
        Box::pin(async move {
            self.check_window(auth)
                .map_err(ArtifactReadCurrentError::Host)?;
            if deadline <= Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            let binding = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Missing,
                ))?;
            if !self
                .issuer
                .matches_desktop_window_epoch(binding.identity(), &self.label, self.id)
            {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let source = self.source.as_ref().ok_or(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ))?;
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                source.verify_source_run_artifact_ids_current_before(auth, target, deadline),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable));
            self.check_window(auth)
                .map_err(ArtifactReadCurrentError::Host)?;
            let (inner, outcome) = result??;
            let witness = WindowReadTail {
                window: WindowRequestBindingGuard {
                    registry: self.registry.clone(),
                    owner: self.owner.clone(),
                    issuer: self.issuer.clone(),
                    label: self.label.clone(),
                    id: self.id,
                    expected: self.expected.clone(),
                    source: None,
                    upstream: None,
                },
                original: binding.identity().clone(),
                inner,
            };
            witness.verify_current(auth, deadline)?;
            Ok((
                Box::new(witness) as Box<dyn ArtifactReadTailWitness>,
                outcome,
            ))
        })
    }

    fn verify_artifact_save_receipt_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::ArtifactSaveReceiptCurrentTarget,
        deadline: Instant,
    ) -> openbot_contracts::request_binding::ArtifactSaveReceiptCurrentCheck<'a> {
        Box::pin(async move {
            self.check_window(auth)
                .map_err(ArtifactReadCurrentError::Host)?;
            if deadline <= Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            let binding = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Missing,
                ))?;
            if !self
                .issuer
                .matches_desktop_window_epoch(binding.identity(), &self.label, self.id)
            {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let source = self.source.as_ref().ok_or(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ))?;
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                source.verify_artifact_save_receipt_current_before(auth, target, deadline),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable));
            self.check_window(auth)
                .map_err(ArtifactReadCurrentError::Host)?;
            let (inner, outcome) = result??;
            let witness = WindowReadTail {
                window: WindowRequestBindingGuard {
                    registry: self.registry.clone(),
                    owner: self.owner.clone(),
                    issuer: self.issuer.clone(),
                    label: self.label.clone(),
                    id: self.id,
                    expected: self.expected.clone(),
                    source: None,
                    upstream: None,
                },
                original: binding.identity().clone(),
                inner,
            };
            witness.verify_current(auth, deadline)?;
            Ok((
                Box::new(witness) as Box<dyn ArtifactReadTailWitness>,
                outcome,
            ))
        })
    }

    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactReadCurrentTarget,
        deadline: Instant,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.check_window(auth)
                .map_err(ArtifactReadCurrentError::Host)?;
            if deadline <= Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            let binding = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Missing,
                ))?;
            if !self
                .issuer
                .matches_desktop_window_epoch(binding.identity(), &self.label, self.id)
            {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let source = self.source.as_ref().ok_or(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ))?;
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                source.verify_artifact_read_current_before(auth, target, deadline),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable));
            self.check_window(auth)
                .map_err(ArtifactReadCurrentError::Host)?;
            let inner = result??;
            let witness = WindowReadTail {
                window: WindowRequestBindingGuard {
                    registry: self.registry.clone(),
                    owner: self.owner.clone(),
                    issuer: self.issuer.clone(),
                    label: self.label.clone(),
                    id: self.id,
                    expected: self.expected.clone(),
                    source: None,
                    upstream: None,
                },
                original: binding.identity().clone(),
                inner,
            };
            witness.verify_current(auth, deadline)?;
            Ok(Box::new(witness) as Box<dyn ArtifactReadTailWitness>)
        })
    }

    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>,
    > {
        self.verify_current_before(auth, std::time::Instant::now() + Duration::from_secs(5))
    }

    fn verify_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: std::time::Instant,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.check_window(auth)?;
            if deadline <= std::time::Instant::now() {
                return Err(HostRequestBindingError::Unavailable);
            }
            let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                match (&self.source, &self.upstream) {
                    (Some(source), _) => {
                        source.verify_current_before(&self.expected, deadline).await
                    }
                    (None, Some(upstream)) => {
                        upstream
                            .verify_current_before(&self.expected, deadline)
                            .await
                    }
                    (None, None) => Err(HostRequestBindingError::Missing),
                }
            })
            .await
            .unwrap_or(Err(HostRequestBindingError::Unavailable));
            self.check_window(auth)?;
            result
        })
    }
}

/// The actual window observation wraps the enrolled Local producer's synchronous tail.
/// No host lease, database transaction or fresh time budget is created here.
struct WindowArtifactCleanupTailFactory<'a> {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: ArtifactCleanupHostObservation<'a>,
}
impl ArtifactCleanupHostTailFactory for WindowArtifactCleanupTailFactory<'_> {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<ArtifactCleanupSessionFacts>,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactCleanupHostTailWitness>, HostRequestBindingError> {
        self.window.check_window(auth)?;
        if !auth
            .request_binding()
            .is_some_and(|binding| self.original.same_binding(binding.identity()))
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let inner = self.inner.witness(auth, session, deadline)?;
        let witness = WindowArtifactCleanupTail {
            window: self.window.repository_tail_source(),
            original: self.original.clone(),
            inner,
        };
        witness.verify_current(auth, deadline)?;
        Ok(Box::new(witness))
    }
}

struct WindowArtifactCleanupTail {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: Box<dyn ArtifactCleanupHostTailWitness>,
}
impl ArtifactCleanupHostTailWitness for WindowArtifactCleanupTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        self.window.check_window(auth)?;
        if !auth.request_binding().is_some_and(|binding| {
            self.original.same_binding(binding.identity())
                && self.window.issuer.matches_desktop_window_epoch(
                    binding.identity(),
                    &self.window.label,
                    self.window.id,
                )
        }) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        self.inner.verify_current(auth, deadline)?;
        self.window.check_window(auth)?;
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(())
    }
}

struct WindowCustomModelCatalogTailFactory<'a> {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: CustomModelCatalogHostObservation<'a>,
}
impl CustomModelCatalogHostTailFactory for WindowCustomModelCatalogTailFactory<'_> {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<CustomModelCatalogSessionFacts>,
        deadline: Instant,
    ) -> Result<Box<dyn CustomModelCatalogHostTailWitness>, HostRequestBindingError> {
        self.window.check_window(auth)?;
        if !auth
            .request_binding()
            .is_some_and(|binding| self.original.same_binding(binding.identity()))
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let inner = self.inner.witness(auth, session, deadline)?;
        let witness = WindowCustomModelCatalogTail {
            window: self.window.repository_tail_source(),
            original: self.original.clone(),
            inner,
        };
        witness.verify_current(auth, deadline)?;
        Ok(Box::new(witness))
    }
}

struct WindowCustomModelCatalogTail {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: Box<dyn CustomModelCatalogHostTailWitness>,
}
impl CustomModelCatalogHostTailWitness for WindowCustomModelCatalogTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        self.window.check_window(auth)?;
        if !auth.request_binding().is_some_and(|binding| {
            self.original.same_binding(binding.identity())
                && self.window.issuer.matches_desktop_window_epoch(
                    binding.identity(),
                    &self.window.label,
                    self.window.id,
                )
        }) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        self.inner.verify_current(auth, deadline)?;
        self.window.check_window(auth)?;
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(())
    }
}

struct WindowRememberPreferenceTailFactory<'a> {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: RememberPreferenceHostObservation<'a>,
}
struct WindowThreadHistoryTailFactory<'a> {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: ThreadHistoryHostObservation<'a>,
}
impl RememberPreferenceHostTailFactory for WindowRememberPreferenceTailFactory<'_> {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<RememberPreferenceSessionFacts>,
        deadline: Instant,
    ) -> Result<Box<dyn RememberPreferenceHostTailWitness>, HostRequestBindingError> {
        self.window.check_window(auth)?;
        if !auth
            .request_binding()
            .is_some_and(|binding| self.original.same_binding(binding.identity()))
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let inner = self.inner.witness(auth, session, deadline)?;
        let witness = WindowRememberPreferenceTail {
            window: self.window.repository_tail_source(),
            original: self.original.clone(),
            inner,
        };
        witness.verify_current(auth, deadline)?;
        Ok(Box::new(witness))
    }
}
impl ThreadHistoryHostTailFactory for WindowThreadHistoryTailFactory<'_> {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<ThreadHistorySessionFacts>,
        deadline: Instant,
    ) -> Result<Box<dyn ThreadHistoryHostTailWitness>, HostRequestBindingError> {
        self.window.check_window(auth)?;
        if !auth
            .request_binding()
            .is_some_and(|binding| self.original.same_binding(binding.identity()))
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        let inner = self.inner.witness(auth, session, deadline)?;
        let witness = WindowThreadHistoryTail {
            window: self.window.repository_tail_source(),
            original: self.original.clone(),
            inner,
        };
        witness.verify_current(auth, deadline)?;
        Ok(Box::new(witness))
    }
}

struct WindowRememberPreferenceTail {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: Box<dyn RememberPreferenceHostTailWitness>,
}
struct WindowThreadHistoryTail {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: Box<dyn ThreadHistoryHostTailWitness>,
}
impl RememberPreferenceHostTailWitness for WindowRememberPreferenceTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        self.window.check_window(auth)?;
        if !auth.request_binding().is_some_and(|binding| {
            self.original.same_binding(binding.identity())
                && self.window.issuer.matches_desktop_window_epoch(
                    binding.identity(),
                    &self.window.label,
                    self.window.id,
                )
        }) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        self.inner.verify_current(auth, deadline)?;
        self.window.check_window(auth)?;
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(())
    }
}
impl ThreadHistoryHostTailWitness for WindowThreadHistoryTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        self.window.check_window(auth)?;
        if !auth.request_binding().is_some_and(|binding| {
            self.original.same_binding(binding.identity())
                && self.window.issuer.matches_desktop_window_epoch(
                    binding.identity(),
                    &self.window.label,
                    self.window.id,
                )
        }) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        self.inner.verify_current(auth, deadline)?;
        self.window.check_window(auth)?;
        if deadline <= Instant::now() {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(())
    }
}

/// Only weak window observations and the actual joint-query tail, without a host lease.
struct WindowReadTail {
    window: WindowRequestBindingGuard,
    original: HostRequestBindingIdentity,
    inner: Box<dyn ArtifactReadTailWitness>,
}
impl ArtifactReadTailWitness for WindowReadTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.window
            .check_window(auth)
            .map_err(ArtifactReadCurrentError::Host)?;
        if !auth.request_binding().is_some_and(|binding| {
            self.original.same_binding(binding.identity())
                && self.window.issuer.matches_desktop_window_epoch(
                    binding.identity(),
                    &self.window.label,
                    self.window.id,
                )
        }) {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        if deadline <= Instant::now() {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ));
        }
        self.inner.verify_current(auth, deadline)?;
        self.window
            .check_window(auth)
            .map_err(ArtifactReadCurrentError::Host)?;
        if deadline <= Instant::now() {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ));
        }
        Ok(())
    }
}

/// Validated bundle, typed in-process application and window authority registry.
pub struct DesktopTauriProtocol {
    assets: StaticAssets,
    index: Arc<str>,
    transport: Arc<InProcessTransport>,
    structured_events: DesktopStructuredEventBridge,
    window_registry: Arc<WindowBindingRegistry>,
    windows: Arc<RwLock<BTreeMap<String, WindowAuthority>>>,
    request_binding_lease: RequestBindingOwnerLease,
    request_binding_issuer: RequestBindingIssuer,
    current_identity_source: Option<Arc<dyn HostRequestBindingGuard>>,
    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    local_capability_authority:
        Option<Arc<crate::local_confirmation_authority::PostgresLocalConfirmationAuthority>>,
    os_locale: UiLocale,
    first_frame_projection: Option<crate::DesktopUiPreferenceStore>,
    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    local_confirmation: OnceLock<LocalConfirmationHost>,
}

impl Drop for DesktopTauriProtocol {
    fn drop(&mut self) {
        self.request_binding_lease.close();
        let _closed = self
            .transport
            .service()
            .close_public_artifact_reads_for_issuer(&self.request_binding_issuer);
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        if let Some(reads) = self
            .local_capability_authority
            .as_ref()
            .and_then(|source| source.artifact_read_lifecycle())
        {
            reads.close_issuer(&self.request_binding_issuer);
        }
    }
}

/// Process-wide protocol hand-off used when `app_data_dir()` is available only inside setup.
pub(crate) struct DesktopTauriProtocolSlot {
    protocol: OnceLock<Arc<DesktopTauriProtocol>>,
}

impl DesktopTauriProtocolSlot {
    pub(crate) fn pending() -> Arc<Self> {
        Arc::new(Self {
            protocol: OnceLock::new(),
        })
    }

    pub(crate) fn ready(protocol: Arc<DesktopTauriProtocol>) -> Arc<Self> {
        let slot = Self::pending();
        assert!(
            slot.protocol.set(protocol).is_ok(),
            "fresh protocol slot must accept its initial value"
        );
        slot
    }

    #[cfg(feature = "desktop-local-runtime")]
    pub(crate) fn install(
        &self,
        protocol: Arc<DesktopTauriProtocol>,
    ) -> Result<(), TauriHostError> {
        self.protocol
            .set(protocol)
            .map_err(|_| TauriHostError::ProtocolAlreadyReady)
    }

    pub(crate) fn get(&self) -> Result<Arc<DesktopTauriProtocol>, TauriHostError> {
        self.protocol
            .get()
            .cloned()
            .ok_or(TauriHostError::ProtocolNotReady)
    }
}

impl DesktopTauriProtocol {
    /// Open a built Trunk bundle with an authoritative ApplicationService preference port.
    pub fn open(
        dist: impl AsRef<Path>,
        transport: Arc<InProcessTransport>,
    ) -> Result<Self, TauriHostError> {
        let root = fs::canonicalize(dist).map_err(|_| TauriHostError::InvalidBundle)?;
        if !fs::metadata(&root)
            .map_err(|_| TauriHostError::InvalidBundle)?
            .is_dir()
        {
            return Err(TauriHostError::InvalidBundle);
        }
        let index_path = root.join("index.html");
        let metadata = fs::metadata(&index_path).map_err(|_| TauriHostError::InvalidBundle)?;
        if !metadata.is_file() || metadata.len() > static_asset_max_bytes("index.html") {
            return Err(TauriHostError::InvalidBundle);
        }
        let index = fs::read_to_string(index_path).map_err(|_| TauriHostError::InvalidBundle)?;
        if index.len() as u64 > static_asset_max_bytes("index.html") {
            return Err(TauriHostError::InvalidBundle);
        }
        validate_index(&index)?;
        Ok(Self::from_assets(
            StaticAssets::Path(root),
            Arc::from(index),
            transport,
        ))
    }

    #[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
    pub(crate) fn from_verified_assets(
        assets: VerifiedUiAssets,
        transport: Arc<InProcessTransport>,
    ) -> Self {
        Self::from_assets(
            StaticAssets::Verified(assets.files),
            assets.index,
            transport,
        )
    }

    fn from_assets(
        assets: StaticAssets,
        index: Arc<str>,
        transport: Arc<InProcessTransport>,
    ) -> Self {
        let structured_events = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let (request_binding_lease, request_binding_issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
        // Existing Local-confirmation helpers and the weak request registry share the exact map.
        let windows = Arc::new(RwLock::new(BTreeMap::new()));
        Self {
            assets,
            index,
            transport,
            structured_events,
            // Zero is not a verified Desktop Screen binding identity.
            window_registry: Arc::new(WindowBindingRegistry {
                next_window_binding_id: HostAtomicU64::new(1),
                windows: Arc::clone(&windows),
                #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
                local_confirmation_slot: Arc::new(OnceLock::new()),
                #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
                runtime_capability_facts: OnceLock::new(),
            }),
            windows,
            request_binding_lease,
            request_binding_issuer,
            current_identity_source: None,
            #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
            local_capability_authority: None,
            os_locale: detect_os_locale(),
            first_frame_projection: None,
            #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
            local_confirmation: OnceLock::new(),
        }
    }

    /// Bind a host-selected, value-only cache for first paint when the authoritative row is absent.
    /// This store is never consumed by API reads, writes or editing version checks.
    #[must_use]
    pub fn with_first_frame_projection(mut self, store: crate::DesktopUiPreferenceStore) -> Self {
        self.first_frame_projection = Some(store);
        self
    }

    /// Close the actual protocol owner before resource teardown; Arc allocation is not liveness.
    pub fn close_request_bindings(&self) {
        self.request_binding_lease.close();
        let _closed = self
            .transport
            .service()
            .close_public_artifact_reads_for_issuer(&self.request_binding_issuer);
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        if let Some(reads) = self
            .local_capability_authority
            .as_ref()
            .and_then(|source| source.artifact_read_lifecycle())
        {
            reads.close_issuer(&self.request_binding_issuer);
        }
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        if let Some(facts) = self
            .window_registry
            .runtime_capability_facts
            .get()
            .and_then(Weak::upgrade)
        {
            facts.close();
        }
    }

    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    pub(crate) fn with_current_identity_source(
        mut self,
        source: Arc<crate::local_confirmation_authority::PostgresLocalConfirmationAuthority>,
    ) -> Self {
        self.local_capability_authority = Some(source.clone());
        self.current_identity_source = Some(source);
        self
    }

    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    pub(crate) fn with_remember_preference_identity_source(
        self,
        source: Arc<crate::local_confirmation_authority::PostgresLocalConfirmationAuthority>,
    ) -> Result<Self, HostRequestBindingError> {
        // One real issuer belongs to this protocol; each bound window retains its own
        // original label/id epoch, which the wrapper checks on every observation.
        source.enroll_remember_preference_window_issuer(&self.request_binding_issuer)?;
        Ok(self.with_current_identity_source(source))
    }

    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    pub(crate) fn with_custom_model_catalog_identity_source(
        self,
        source: Arc<crate::local_confirmation_authority::PostgresLocalConfirmationAuthority>,
    ) -> Result<Self, HostRequestBindingError> {
        let expected: Arc<dyn HostRequestBindingGuard> = source.clone();
        if self
            .current_identity_source
            .as_ref()
            .is_some_and(|current| !Arc::ptr_eq(current, &expected))
            || self
                .local_capability_authority
                .as_ref()
                .is_some_and(|current| !Arc::ptr_eq(current, &source))
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        source.enroll_custom_model_catalog_window_issuer(&self.request_binding_issuer)?;
        Ok(self.with_current_identity_source(source))
    }

    #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
    pub(crate) fn with_thread_history_identity_source(
        self,
        source: Arc<crate::local_confirmation_authority::PostgresLocalConfirmationAuthority>,
    ) -> Result<Self, HostRequestBindingError> {
        let expected: Arc<dyn HostRequestBindingGuard> = source.clone();
        if self
            .current_identity_source
            .as_ref()
            .is_some_and(|current| !Arc::ptr_eq(current, &expected))
            || self
                .local_capability_authority
                .as_ref()
                .is_some_and(|current| !Arc::ptr_eq(current, &source))
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        source.enroll_thread_history_window_issuer(&self.request_binding_issuer)?;
        Ok(self.with_current_identity_source(source))
    }

    /// Bind one host-created webview label to verified local session authority.
    pub fn bind_window(
        &self,
        label: impl Into<String>,
        auth: AuthContext,
        fresh_for: Option<Duration>,
    ) -> Result<(), TauriHostError> {
        if !self.request_binding_issuer.observation().is_current() {
            return Err(TauriHostError::AuthorityUnavailable);
        }
        let label = label.into();
        let mut windows = self
            .window_registry
            .windows
            .write()
            .map_err(|_| TauriHostError::AuthorityUnavailable)?;
        if windows.contains_key(&label) {
            return Err(TauriHostError::WindowAlreadyBound);
        }
        // A Local runtime installs its own OS-confirmation service before binding any window.
        // Verified remote-session duration remains a separate host path; it cannot grant Local
        // freshness once that runtime is installed.
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        if self.local_confirmation.get().is_some() && fresh_for.is_some() {
            return Err(TauriHostError::InvalidFreshness);
        }
        let binding_id = self
            .window_registry
            .next_window_binding_id
            .fetch_update(
                HostAtomicOrdering::SeqCst,
                HostAtomicOrdering::SeqCst,
                |current| current.checked_add(1),
            )
            .map_err(|_| TauriHostError::WindowBindingCounterExhausted)?;
        let fresh_until = fresh_for
            .map(|duration| {
                Instant::now()
                    .checked_add(duration)
                    .ok_or(TauriHostError::InvalidFreshness)
            })
            .transpose()?;
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        let local_confirmation = self
            .local_confirmation
            .get()
            .map(|local| {
                local
                    .service
                    .register_binding(binding_id, &auth)
                    .map(|grant| LocalConfirmationBinding {
                        grant,
                        service: Arc::clone(&local.service),
                    })
            })
            .transpose()
            .map_err(|_| TauriHostError::AuthorityUnavailable)?;
        let upstream = auth
            .request_binding()
            .filter(|binding| binding.kind() == HostRequestBindingKind::ServerSession)
            .cloned();
        let guard = Arc::new(WindowRequestBindingGuard {
            registry: Arc::downgrade(&self.window_registry),
            owner: self.request_binding_issuer.observation(),
            issuer: self.request_binding_issuer.clone(),
            label: label.clone(),
            id: binding_id,
            expected: auth.clone(),
            source: self.current_identity_source.clone(),
            upstream,
        });
        let binding = self
            .request_binding_issuer
            .bind_desktop_window(&auth, label.clone(), binding_id, guard)
            .map_err(|_| TauriHostError::AuthorityUnavailable)?;
        let auth = auth
            .with_verified_request_binding(binding)
            .map_err(|_| TauriHostError::AuthorityUnavailable)?;
        windows.insert(
            label,
            WindowAuthority {
                auth,
                fresh_until,
                binding_id,
                closed: CancellationToken::new(),
                chrome_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
                local_confirmation,
            },
        );
        Ok(())
    }

    /// Remove one closed window's authority immediately.
    pub fn unbind_window(&self, label: &str) -> Result<bool, TauriHostError> {
        let removed = {
            let mut windows = self
                .windows
                .write()
                .map_err(|_| TauriHostError::AuthorityUnavailable)?;
            let removed = windows.remove(label);
            if let Some(authority) = &removed {
                // Same window-registry guard as final confirmation CAS: neither removal nor
                // replacement can leave an old grant temporarily current on another thread.
                authority.closed.cancel();
                #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
                if let Some(local) = &authority.local_confirmation {
                    local.grant.revoke();
                }
            }
            removed
        };
        if let Some(authority) = removed {
            if let Some(binding) = authority.auth.request_binding() {
                let _closed = self
                    .transport
                    .service()
                    .close_public_artifact_reads_for_binding(binding.identity());
            }
            #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
            if let (Some(reads), Some(binding)) = (
                self.local_capability_authority
                    .as_ref()
                    .and_then(|source| source.artifact_read_lifecycle()),
                authority.auth.request_binding(),
            ) {
                reads.close_binding(binding.identity());
            }
            drop(authority);
            self.structured_events
                .close_window(&WindowLabel::new(label.to_owned()));
            return Ok(true);
        }
        Ok(false)
    }

    /// Whether this exact host window label currently owns verified authority.
    pub fn is_window_bound(&self, label: &str) -> Result<bool, TauriHostError> {
        self.window_registry
            .windows
            .read()
            .map(|windows| windows.contains_key(label))
            .map_err(|_| TauriHostError::AuthorityUnavailable)
    }

    /// Number of host window labels currently carrying verified authority.
    pub fn bound_window_count(&self) -> Result<usize, TauriHostError> {
        self.window_registry
            .windows
            .read()
            .map(|windows| windows.len())
            .map_err(|_| TauriHostError::AuthorityUnavailable)
    }

    /// Open one structured stream using only the authority bound by the native host.
    ///
    /// The renderer may select a closed [`SubscriptionRequest`] and durable cursor, but it cannot
    /// provide an actor, tenant, auth generation, internal broker label, or subscription identity.
    pub async fn open_structured_subscription(
        &self,
        label: &str,
        request: SubscriptionRequest,
    ) -> Result<DesktopStructuredSubscription, TauriHostError> {
        let authority = self
            .authority(label)?
            .ok_or(TauriHostError::WindowUnbound)?;
        let binding_closed = authority.closed.clone();
        let opened = tokio::select! {
            result = self.structured_events.open(
                WindowLabel::new(label.to_owned()),
                &authority.auth,
                request,
            ) => result,
            () = binding_closed.cancelled() => {
                return Err(TauriHostError::WindowUnbound);
            }
        };
        let subscription = match opened {
            Ok(subscription) => subscription,
            Err(DesktopStructuredOpenError::WindowClosed) => {
                return Err(TauriHostError::WindowUnbound);
            }
            Err(error) => return Err(TauriHostError::from(error)),
        };
        match self.authority(label) {
            Ok(Some(current)) if current.binding_id == authority.binding_id => Ok(subscription),
            Ok(_) => {
                drop(subscription);
                Err(TauriHostError::WindowUnbound)
            }
            Err(error) => {
                drop(subscription);
                Err(error)
            }
        }
    }

    /// Close one host-minted subscription only within the host-observed actual window.
    pub fn close_structured_subscription(
        &self,
        label: &str,
        subscription_id: u64,
    ) -> Result<bool, TauriHostError> {
        self.authority(label)?
            .ok_or(TauriHostError::WindowUnbound)?;
        Ok(self
            .structured_events
            .close_subscription(&WindowLabel::new(label.to_owned()), subscription_id))
    }

    /// Open and drain one structured stream into a real Tauri IPC [`Channel`].
    ///
    /// A future native binary command wrapper only needs to pass its host-observed window label,
    /// typed request, and Channel here; all ACL, sequence, gap, and terminal behavior stays below
    /// that wrapper.
    pub async fn pump_structured_events(
        &self,
        label: &str,
        request: SubscriptionRequest,
        channel: Channel<String>,
    ) -> Result<DesktopStructuredPumpExit, TauriHostError> {
        let subscription = self.open_structured_subscription(label, request).await?;
        Ok(pump_tauri_structured_events(subscription, channel).await)
    }

    /// Handle one custom-protocol request. Public for deterministic host-adapter tests.
    pub async fn handle(&self, label: &str, mut request: Request<Vec<u8>>) -> Response<Vec<u8>> {
        if custom_model_catalog::owns_path(request.uri().path()) {
            let prepared = self
                .prepare_custom_model_catalog_response(label, request)
                .await;
            return self.finish_prepared_custom_model_catalog_response(
                label,
                prepared,
                |response| response,
            );
        }
        if artifact_reads::owns_path(request.uri().path()) {
            let prepared = self
                .prepare_public_artifact_read_response(label, request)
                .await;
            return self.finish_public_artifact_read_response(label, prepared, |response| response);
        }
        if request.uri().path() == "/api/artifacts/save-requests"
            || request
                .uri()
                .path()
                .starts_with("/api/artifacts/save-requests/")
        {
            let authority = {
                let windows = match self.window_registry.windows.try_read() {
                    Ok(windows) => windows,
                    Err(_) => {
                        request.body_mut().fill(0);
                        return error_response(AppError::DependencyUnavailable {
                            dependency: "host_request_binding",
                        });
                    }
                };
                windows.get(label).cloned()
            };
            let Some(authority) = authority else {
                request.body_mut().fill(0);
                return error_response(AppError::Unauthenticated);
            };
            return self.artifact_save_receipt(label, request, authority).await;
        }
        if request.uri().path() == "/api/artifacts/source-runs"
            || request
                .uri()
                .path()
                .starts_with("/api/artifacts/source-runs/")
        {
            let authority = {
                let windows = match self.window_registry.windows.try_read() {
                    Ok(windows) => windows,
                    Err(_) => {
                        request.body_mut().fill(0);
                        return error_response(AppError::DependencyUnavailable {
                            dependency: "host_request_binding",
                        });
                    }
                };
                windows.get(label).cloned()
            };
            let Some(authority) = authority else {
                request.body_mut().fill(0);
                return error_response(AppError::Unauthenticated);
            };
            return self.artifacts(label, request, authority).await;
        }
        let authority = match self.authority(label) {
            Ok(Some(authority)) => authority,
            Ok(None) => {
                request.body_mut().fill(0);
                return error_response(AppError::Unauthenticated);
            }
            Err(_) => {
                request.body_mut().fill(0);
                return dependency_response();
            }
        };
        let path = request.uri().path().to_owned();
        if path == "/api/me/capabilities" {
            return self.runtime_capabilities_request(request, authority).await;
        }
        if path == "/api/me" {
            return self.current_user(request, authority).await;
        }
        if path == "/api/me/session" {
            return self.session_status(label, &mut request, &authority);
        }
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        if path == openbot_contracts::desktop::local_confirmation::LOCAL_CONFIRMATION_PATH {
            return self
                .local_confirmation_request(label, request, authority)
                .await;
        }
        if path == "/api/me/preferences" {
            return self.preferences(request, authority).await;
        }
        if path == "/api/me/run-cost-budget" {
            return self.run_cost_budget(request, authority).await;
        }
        if path == "/api/me/remote-interrupts" {
            return self.remote_interrupts(request, authority).await;
        }
        if path == "/api/me/model-connections" || path.starts_with("/api/me/model-connections/") {
            return self.model_connections(label, request, authority).await;
        }
        if path == "/api/memories" || path.starts_with("/api/memories/") {
            return self.memories(label, request, authority).await;
        }
        if path == "/api/artifacts" || path.starts_with("/api/artifacts/") {
            return self.artifacts(label, request, authority).await;
        }
        if path == "/api/plugins" {
            return self.plugins(request, authority).await;
        }
        if path == "/api/admin/credentials" || path.starts_with("/api/admin/credentials/") {
            return self.credential_administration(request, authority).await;
        }
        if path == "/api/plugins/connections" {
            return self.plugin_connections(request, authority).await;
        }
        if path == "/api/plugins/servers" {
            return self.curated_mcp_server(request, authority).await;
        }
        if path == "/api/plugins/skills" {
            return self.plugin_skills(request, authority).await;
        }
        if let Some(raw_slug) = path.strip_prefix("/api/plugins/skills/") {
            return self.remove_plugin_skill(request, authority, raw_slug).await;
        }
        if path == "/api/plugins/grants" {
            return self.plugin_grants(request, authority).await;
        }
        if let Some(raw_agent_id) = path.strip_prefix("/api/plugins/for/") {
            return self
                .plugins_for_agent(request, authority, raw_agent_id)
                .await;
        }
        if path == "/api/plugins/servers/custom" {
            return self.custom_mcp_server(request, authority).await;
        }
        if let Some(server_id) = path
            .strip_prefix("/api/plugins/servers/")
            .and_then(|rest| rest.strip_suffix("/refresh"))
        {
            return self
                .configured_mcp_server(request, authority, server_id, true)
                .await;
        }
        if let Some(server_id) = path.strip_prefix("/api/plugins/servers/") {
            return self
                .configured_mcp_server(request, authority, server_id, false)
                .await;
        }
        if let Some(request_id) = path.strip_prefix("/api/me/remote-interrupts/") {
            return self
                .resolve_remote_interrupt(request, authority, request_id)
                .await;
        }
        if path == "/api/channels" {
            return self.channels(request, authority).await;
        }
        if let Some(raw_channel_id) = raw_channel_id(&path) {
            return self
                .channel_detail(request, authority, raw_channel_id)
                .await;
        }
        if path == "/api/route" {
            return self.route_channel(request, authority).await;
        }
        if path == "/api/threads/mint" {
            return self.thread_mint(request, authority).await;
        }
        if let Some(route) = thread_route(&path) {
            if let ThreadRoute::Reconciliation {
                raw_thread_id,
                raw_run_id,
                kind,
            } = route
            {
                return self
                    .run_reconciliation(label, request, authority, raw_thread_id, raw_run_id, kind)
                    .await;
            }
            return self.thread_unary(request, authority, route).await;
        }
        if path == "/api/agents/test-connection" {
            return self.agent_test_connection(request, authority).await;
        }
        if path == "/api/agents" {
            return self.agents(request, authority).await;
        }
        if let Some(route) = agent_route(&path) {
            return self.agent_detail(request, authority, route).await;
        }
        if path == "/api/tool-approvals" {
            return self.approvals(request, authority).await;
        }
        if path == "/api/components" {
            return self.components(request, authority).await;
        }
        if path == "/api/components/catalogue" {
            return self.component_catalogue(request, authority).await;
        }
        if path == "/api/components/functions" {
            return self.component_functions(request, authority).await;
        }
        if path == "/api/components/human-decisions" {
            return self.component_human_decisions(request, authority).await;
        }
        if path == "/api/sandboxed/published" {
            return self
                .published_sandboxed_components(request, authority)
                .await;
        }
        if path == "/api/sandboxed" {
            return self.sandboxed_components(request, authority).await;
        }
        if let Some(raw_name) = path
            .strip_prefix("/api/sandboxed/")
            .and_then(|rest| rest.strip_suffix("/publish"))
        {
            return self
                .publish_sandboxed_component(request, authority, raw_name)
                .await;
        }
        if let Some(raw_name) = path.strip_prefix("/api/sandboxed/") {
            return self
                .delete_sandboxed_component(request, authority, raw_name)
                .await;
        }
        if let Some(raw_decision_id) = path
            .strip_prefix("/api/components/human-decisions/")
            .and_then(|rest| rest.strip_suffix("/answer"))
        {
            return self
                .component_human_decision_answer(request, authority, raw_decision_id)
                .await;
        }
        if let Some(raw_agent_id) = path.strip_prefix("/api/components/for-agent/") {
            return self
                .components_for_agent(request, authority, raw_agent_id)
                .await;
        }
        if let Some(route) = component_governance_route(&path) {
            return self.component_governance(request, authority, route).await;
        }
        if let Some(raw_name) = path
            .strip_prefix("/api/components/")
            .and_then(|rest| rest.strip_suffix("/decision"))
        {
            return self.component_decision(request, authority, raw_name).await;
        }
        if let Some(raw_name) = path
            .strip_prefix("/api/components/")
            .and_then(|rest| rest.strip_suffix("/call"))
        {
            return self.component_call(request, authority, raw_name).await;
        }
        if let Some(raw_id) = path.strip_prefix("/api/tool-approvals/") {
            return self.approval_decision(request, authority, raw_id).await;
        }
        if path == "/api" || path.starts_with("/api/") {
            request.body_mut().fill(0);
            return empty_response(StatusCode::NOT_FOUND);
        }
        if request.method() != Method::GET {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        #[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
        if let StaticAssets::Verified(files) = &self.assets
            && path
                .strip_prefix('/')
                .is_some_and(|relative| files.contains_key(relative))
        {
            // Inventory materials must pass the static allowlist, including extensionless files.
            // Only paths that are not release files can fall through to normal SPA navigation.
            return self.asset(&path);
        }
        if path == "/" || path == "/index.html" || is_spa_path(&path) {
            let preferences = match self
                .transport
                .execute(authority.auth, AppCommand::GetUiPreferences)
                .await
            {
                Ok(AppReply::UiPreferences(preferences)) => preferences,
                Ok(_) => return dependency_response(),
                Err(error) => return error_response(error),
            };
            let mut values = (preferences.theme, preferences.locale);
            if preferences.revision.is_none()
                && let Some(store) = &self.first_frame_projection
            {
                let store = store.clone();
                if let Ok(Ok(projection)) =
                    tokio::task::spawn_blocking(move || store.read_first_frame_projection()).await
                {
                    values = (projection.theme, projection.locale);
                }
            }
            return index_response(&self.index, values.0, values.1, self.os_locale);
        }
        self.asset(&path)
    }

    fn authority(&self, label: &str) -> Result<Option<WindowAuthority>, TauriHostError> {
        self.window_registry
            .windows
            .read()
            .map(|windows| windows.get(label).cloned())
            .map_err(|_| TauriHostError::AuthorityUnavailable)
    }

    async fn current_user(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::GetCurrentUser)
            .await
        {
            Ok(AppReply::CurrentUser(user)) => json_response(&CurrentUserResponse { user }),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn preferences(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        let command = match *request.method() {
            Method::GET if request.body().is_empty() => AppCommand::GetUiPreferences,
            Method::PUT if request.body().len() <= API_BODY_MAX_BYTES => {
                let update = match serde_json::from_slice::<UpdateUiPreferences>(request.body()) {
                    Ok(update) if !update.is_empty() => update,
                    _ => return error_response(AppError::MalformedPayload { field: "body" }),
                };
                AppCommand::UpdateUiPreferences(update)
            }
            Method::PUT => return payload_too_large(),
            _ => return empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        match self.transport.execute(authority.auth, command).await {
            Ok(AppReply::UiPreferences(preferences)) => json_response(&preferences),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn run_cost_budget(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        let command = match *request.method() {
            Method::GET if request.body().is_empty() => AppCommand::GetRunCostBudget,
            Method::PUT if request.body().len() <= API_BODY_MAX_BYTES => {
                let preference =
                    match serde_json::from_slice::<RunCostBudgetPreference>(request.body()) {
                        Ok(preference) => preference,
                        Err(_) => {
                            return error_response(AppError::MalformedPayload { field: "body" });
                        }
                    };
                AppCommand::ReplaceRunCostBudget(preference)
            }
            Method::PUT => return payload_too_large(),
            _ => return empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        match self.transport.execute(authority.auth, command).await {
            Ok(AppReply::RunCostBudget(preference)) => json_response(&preference),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn credential_administration(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if !authority
            .auth
            .has_role(openbot_contracts::auth::Role::Admin)
        {
            request.body_mut().fill(0);
            return error_response(AppError::ForbiddenRole {
                required: openbot_contracts::auth::Role::Admin,
            });
        }
        let path = request.uri().path().to_owned();
        let listing = path == "/api/admin/credentials" && request.method() == Method::GET;
        if !listing && !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let command = if listing {
            if !request.body().is_empty() {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload { field: "body" });
            }
            let cursor = match request.uri().query() {
                None | Some("") => None,
                Some(query)
                    if query.len() <= 1536
                        && !query.contains('&')
                        && query.starts_with("cursor=") =>
                {
                    let Some(cursor) = percent_decode_query_component(&query[7..]) else {
                        return error_response(AppError::MalformedPayload { field: "cursor" });
                    };
                    Some(cursor)
                }
                _ => return error_response(AppError::MalformedPayload { field: "query" }),
            };
            AppCommand::ListCredentials(CredentialPageRequest { cursor })
        } else {
            if request.method() != Method::POST {
                request.body_mut().fill(0);
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
            if request.uri().query().is_some() {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload { field: "query" });
            }
            if request.body().len() > 512 * 1024 {
                request.body_mut().fill(0);
                return payload_too_large();
            }
            let route = path.strip_prefix("/api/admin/credentials/");
            if let Some(raw_id) = route.and_then(|route| route.strip_suffix("/revoke")) {
                if !request.body().is_empty() {
                    request.body_mut().fill(0);
                    return error_response(AppError::MalformedPayload { field: "body" });
                }
                let Some(credential_id) = percent_decode_segment(raw_id) else {
                    return error_response(AppError::MalformedPayload {
                        field: "credential_id",
                    });
                };
                AppCommand::RevokeCredential { credential_id }
            } else {
                let parsed = serde_json::from_slice::<CredentialWrite>(request.body());
                request.body_mut().fill(0);
                let input = match parsed {
                    Ok(input) => input,
                    Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
                };
                if path == "/api/admin/credentials" {
                    AppCommand::CreateCredential(input)
                } else if let Some(raw_id) = route.and_then(|route| route.strip_suffix("/rotate")) {
                    let Some(credential_id) = percent_decode_segment(raw_id) else {
                        return error_response(AppError::MalformedPayload {
                            field: "credential_id",
                        });
                    };
                    AppCommand::RotateCredential {
                        credential_id,
                        input,
                    }
                } else {
                    return error_response(AppError::NotVisible);
                }
            }
        };
        let created = matches!(command, AppCommand::CreateCredential(_));
        let revoking = matches!(command, AppCommand::RevokeCredential { .. });
        match self.transport.execute(authority.auth, command).await {
            Ok(AppReply::Credentials(page)) if listing => json_response(&page),
            Ok(AppReply::CredentialWritten(receipt)) if !listing && !revoking => {
                let mut response = json_response(&receipt);
                if created {
                    *response.status_mut() = StatusCode::CREATED;
                }
                response
            }
            Ok(AppReply::CredentialRevoked(credential)) if revoking => {
                json_response(&CredentialRevocationReceipt { credential })
            }
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn plugins(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::ListMcpAdminPage)
            .await
        {
            Ok(AppReply::McpAdminPage(page)) => json_response(&page),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn plugin_connections(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.uri().query().is_some() {
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::ListMcpConnections)
            .await
        {
            Ok(AppReply::McpConnections(connections)) => json_response(&connections),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn curated_mcp_server(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        if request.body().len() > MCP_ADMIN_BODY_MAX_BYTES {
            request.body_mut().fill(0);
            return payload_too_large();
        }
        if request.uri().query().is_some() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        let selected = serde_json::from_slice::<McpCuratedServerSelection>(request.body());
        request.body_mut().fill(0);
        let selected = match selected {
            Ok(selected) => selected,
            Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::AddCuratedMcpServer { key: selected.key },
            )
            .await
        {
            Ok(AppReply::McpServerMutation(receipt)) => json_response(&receipt),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn custom_mcp_server(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        if request.body().len() > MCP_ADMIN_BODY_MAX_BYTES {
            request.body_mut().fill(0);
            return payload_too_large();
        }
        let registration =
            match serde_json::from_slice::<McpCustomServerRegistration>(request.body()) {
                Ok(registration) => registration,
                Err(_) => {
                    request.body_mut().fill(0);
                    return error_response(AppError::MalformedPayload { field: "body" });
                }
            };
        request.body_mut().fill(0);
        match self
            .transport
            .execute(authority.auth, AppCommand::AddCustomMcpServer(registration))
            .await
        {
            Ok(AppReply::McpServerMutation(receipt)) => json_response(&receipt),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn plugin_skills(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        if request.body().len() > PLUGIN_SKILL_BODY_MAX_BYTES {
            request.body_mut().fill(0);
            return payload_too_large();
        }
        let mutation = match serde_json::from_slice::<PluginSkillMutation>(request.body()) {
            Ok(mutation) => mutation,
            Err(_) => {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload { field: "body" });
            }
        };
        request.body_mut().fill(0);
        match self
            .transport
            .execute(authority.auth, AppCommand::SavePluginSkill(mutation))
            .await
        {
            Ok(AppReply::PluginSkills(skills)) => json_response(&skills),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn remove_plugin_skill(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_slug: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::DELETE {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let Some(slug) = percent_decode_segment(raw_slug) else {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "slug" });
        };
        if request.body().len() > 1024 {
            request.body_mut().fill(0);
            return payload_too_large();
        }
        let revision = match serde_json::from_slice::<PluginSkillRevisionRequest>(request.body()) {
            Ok(revision) => revision,
            Err(_) => {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload { field: "body" });
            }
        };
        request.body_mut().fill(0);
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::RemovePluginSkill {
                    slug,
                    expected_revision: revision.expected_revision,
                },
            )
            .await
        {
            Ok(AppReply::PluginMutationAcknowledged(receipt)) => json_response(&receipt),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn plugin_grants(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let command = match *request.method() {
            Method::POST if request.body().len() <= MCP_ADMIN_BODY_MAX_BYTES => {
                let mutation = match serde_json::from_slice::<PluginGrantMutation>(request.body()) {
                    Ok(mutation) => mutation,
                    Err(_) => {
                        request.body_mut().fill(0);
                        return error_response(AppError::MalformedPayload { field: "body" });
                    }
                };
                request.body_mut().fill(0);
                AppCommand::GrantPlugin(mutation)
            }
            Method::POST => {
                request.body_mut().fill(0);
                return payload_too_large();
            }
            Method::DELETE if request.body().is_empty() => {
                let Some(mutation) = plugin_grant_query(request.uri().query()) else {
                    return error_response(AppError::MalformedPayload { field: "query" });
                };
                AppCommand::RevokePlugin(mutation)
            }
            _ => {
                request.body_mut().fill(0);
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
        };
        match self.transport.execute(authority.auth, command).await {
            Ok(AppReply::PluginMutationAcknowledged(receipt)) => json_response(&receipt),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn plugins_for_agent(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_agent_id: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let Some(agent_id) = percent_decode_segment(raw_agent_id) else {
            return error_response(AppError::MalformedPayload { field: "agent_id" });
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::ListPluginsForAgent {
                    agent_id: BotId::new(agent_id),
                },
            )
            .await
        {
            Ok(AppReply::GrantedPlugins(plugins)) => json_response(&plugins),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn configured_mcp_server(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
        server_id: &str,
        refresh: bool,
    ) -> Response<Vec<u8>> {
        let expected_method = if refresh {
            Method::POST
        } else {
            Method::DELETE
        };
        if request.method() != expected_method || !request.body().is_empty() {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let command = if refresh {
            AppCommand::RefreshMcpServer {
                server_id: server_id.to_owned(),
            }
        } else {
            AppCommand::RemoveMcpServer {
                server_id: server_id.to_owned(),
            }
        };
        match self.transport.execute(authority.auth, command).await {
            Ok(AppReply::McpServerMutation(receipt)) if refresh => json_response(&receipt),
            Ok(AppReply::McpServerRemoved(receipt)) if !refresh => json_response(&receipt),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn remote_interrupts(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::ListPendingRemoteInterrupts)
            .await
        {
            Ok(AppReply::PendingRemoteInterrupts(pending)) => json_response(&pending),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn resolve_remote_interrupt(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        request_id: &str,
    ) -> Response<Vec<u8>> {
        if request_id.is_empty() || request_id.contains('/') {
            return empty_response(StatusCode::NOT_FOUND);
        }
        let answer = match *request.method() {
            Method::PUT if request.body().len() <= REMOTE_INTERRUPT_BODY_MAX_BYTES => {
                match serde_json::from_slice::<RemoteInterruptAnswer>(request.body()) {
                    Ok(answer) => answer,
                    Err(_) => {
                        return error_response(AppError::MalformedPayload { field: "body" });
                    }
                }
            }
            Method::PUT => return payload_too_large(),
            _ => return empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::ResolveRemoteInterrupt {
                    request_id: request_id.to_owned(),
                    answer,
                },
            )
            .await
        {
            Ok(AppReply::RemoteInterruptResolved(resolved)) => {
                let resolved: RemoteInterruptResolved = resolved;
                json_response(&resolved)
            }
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn channels(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        match *request.method() {
            Method::GET if request.body().is_empty() => {
                let (limit, cursor) = match channel_list_query(request.uri().query()) {
                    Some(query) => query,
                    None => {
                        return error_response(AppError::MalformedPayload { field: "query" });
                    }
                };
                match self
                    .transport
                    .execute(
                        authority.auth,
                        AppCommand::ListVisibleChannels { limit, cursor },
                    )
                    .await
                {
                    Ok(AppReply::Channels(page)) => json_response(&page),
                    Ok(_) => dependency_response(),
                    Err(error) => error_response(error),
                }
            }
            Method::POST => {
                let body = match parse_sensitive_body::<CreateChannelRequest>(
                    &mut request,
                    CHANNEL_THREAD_BODY_MAX_BYTES,
                ) {
                    Ok(body) => body,
                    Err(error) => return sensitive_body_error_response(error),
                };
                match self
                    .transport
                    .execute(
                        authority.auth,
                        AppCommand::CreateChannel {
                            agent_ids: body.agent_ids,
                        },
                    )
                    .await
                {
                    Ok(AppReply::Channel(channel)) => json_response_with_status(
                        &ChannelDetailResponse { channel },
                        StatusCode::CREATED,
                    ),
                    Ok(_) => dependency_response(),
                    Err(error) => error_response(error),
                }
            }
            _ => {
                request.body_mut().fill(0);
                empty_response(StatusCode::METHOD_NOT_ALLOWED)
            }
        }
    }

    async fn channel_detail(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_channel_id: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let channel_id = match percent_decode_segment(raw_channel_id) {
            Some(channel_id) => ChannelId::new(channel_id),
            None => {
                return error_response(AppError::MalformedPayload {
                    field: "channel_id",
                });
            }
        };
        match self
            .transport
            .execute(authority.auth, AppCommand::GetVisibleChannel { channel_id })
            .await
        {
            Ok(AppReply::Channel(channel)) => json_response(&ChannelDetailResponse { channel }),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn route_channel(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let body = match parse_sensitive_body::<RouteChannelRequest>(
            &mut request,
            CHANNEL_THREAD_BODY_MAX_BYTES,
        ) {
            Ok(body) => body,
            Err(error) => return sensitive_body_error_response(error),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::RouteChannelMessage {
                    text: body.text,
                    agent_id: body.agent_id,
                },
            )
            .await
        {
            Ok(AppReply::ChannelRouting(decision)) => json_response(&decision),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn thread_mint(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST || !request.body().is_empty() {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::MintThreadId)
            .await
        {
            Ok(AppReply::ThreadMinted(minted)) => json_response(&minted),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn run_reconciliation(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_thread_id: &str,
        raw_run_id: &str,
        kind: ReconciliationRead,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !request.body().is_empty() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "body" });
        }
        let Some(thread_id) = percent_decode_segment(raw_thread_id) else {
            return error_response(AppError::MalformedPayload { field: "thread_id" });
        };
        let Some(run_id) = percent_decode_segment(raw_run_id) else {
            return error_response(AppError::MalformedPayload { field: "run_id" });
        };
        let Some(query) = run_reconciliation_query(request.uri().query()) else {
            return error_response(AppError::MalformedPayload { field: "query" });
        };
        let (after, limit) = match query.into_parts() {
            Ok(parts) => parts,
            Err(error) => return error_response(error),
        };
        if let Err(error) = self.reconciliation_binding_current(label, &authority) {
            return error_response(error);
        }
        let thread_id = ThreadId::new(thread_id);
        let run_id = RunId::new(run_id);
        let command = match kind {
            ReconciliationRead::Attempts => AppCommand::GetRunReconciliation {
                thread_id,
                run_id,
                after,
                limit,
            },
            ReconciliationRead::Receipts => AppCommand::GetRunEffectReceipts {
                thread_id,
                run_id,
                after,
                limit,
            },
        };
        let outcome = self
            .transport
            .execute(authority.auth.clone(), command)
            .await;
        // A label can be closed and recreated while the shared Application is reading.
        // Never deliver the old authority's snapshot (or error) to its replacement.
        if let Err(error) = self.reconciliation_binding_current(label, &authority) {
            return error_response(error);
        }
        let body = match (kind, outcome) {
            (ReconciliationRead::Attempts, Ok(AppReply::RunReconciliation(snapshot))) => {
                serde_json::to_vec(&snapshot)
            }
            (ReconciliationRead::Receipts, Ok(AppReply::RunEffectReceipts(snapshot))) => {
                serde_json::to_vec(&snapshot)
            }
            (_, Ok(_)) => return dependency_response(),
            (_, Err(error)) => return error_response(error),
        };
        match body {
            Ok(body) if body.len() <= MAX_RUN_RECONCILIATION_RESPONSE_BYTES => {
                response(StatusCode::OK, "application/json", body, true)
            }
            _ => dependency_response(),
        }
    }

    fn reconciliation_binding_current(
        &self,
        label: &str,
        admitted: &WindowAuthority,
    ) -> Result<(), AppError> {
        match self.authority(label) {
            Ok(Some(current))
                if current.binding_id == admitted.binding_id && !admitted.closed.is_cancelled() =>
            {
                Ok(())
            }
            Ok(_) => Err(AppError::Unauthenticated),
            Err(_) => Err(AppError::DependencyUnavailable {
                dependency: "desktop_window_authority",
            }),
        }
    }

    async fn thread_unary(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
        route: ThreadRoute<'_>,
    ) -> Response<Vec<u8>> {
        let supported = matches!(
            (route, request.method()),
            (ThreadRoute::Status { .. }, &Method::GET)
                | (ThreadRoute::Conversation { .. }, &Method::GET)
                | (ThreadRoute::Runs { .. }, &Method::POST)
                | (ThreadRoute::Cancel { .. }, &Method::POST)
        );
        if !supported {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let thread_id = match percent_decode_segment(route.raw_thread_id()) {
            Some(thread_id) => ThreadId::new(thread_id),
            None => {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload { field: "thread_id" });
            }
        };
        match (route, request.method()) {
            (ThreadRoute::Status { .. }, &Method::GET) if request.body().is_empty() => {
                self.thread_command(authority.auth, AppCommand::GetThreadStatus { thread_id })
                    .await
            }
            (ThreadRoute::Conversation { .. }, &Method::GET) if request.body().is_empty() => {
                self.thread_command(
                    authority.auth,
                    AppCommand::GetThreadConversation { thread_id },
                )
                .await
            }
            (ThreadRoute::Runs { .. }, &Method::POST) => {
                let body =
                    match parse_sensitive_begin_body(&mut request, CHANNEL_THREAD_BODY_MAX_BYTES) {
                        Ok(body) => body,
                        Err(error) => return sensitive_body_error_response(error),
                    };
                use openbot_contracts::begin_thread_run_wire::DecodedBeginThreadRunBody;
                let command = match body {
                    DecodedBeginThreadRunBody::Legacy(body) => {
                        AppCommand::BeginThreadRun(BeginThreadRun {
                            artifact_refs: body.artifact_refs,
                            model_selection: body.model_selection,
                            selected_skill_slugs: body.selected_skill_slugs,
                            thread_id,
                            run_id: body.run_id,
                            bot_id: body.bot_id,
                            anchor: body.anchor,
                            message: body.message,
                        })
                    }
                    DecodedBeginThreadRunBody::V2(body) => {
                        AppCommand::BeginThreadRunV2(BeginThreadRunV2 {
                            artifact_refs: body.artifact_refs,
                            model_selection: body.model_selection,
                            selected_skill_slugs: body.selected_skill_slugs,
                            thread_id,
                            run_id: body.run_id,
                            bot_id: body.bot_id,
                            anchor: body.anchor,
                            message: body.message,
                        })
                    }
                };
                self.thread_command(authority.auth, command).await
            }
            (ThreadRoute::Cancel { raw_run_id, .. }, &Method::POST)
                if request.body().is_empty() =>
            {
                let run_id = match percent_decode_segment(raw_run_id) {
                    Some(run_id) => RunId::new(run_id),
                    None => {
                        return error_response(AppError::MalformedPayload { field: "run_id" });
                    }
                };
                self.thread_command(
                    authority.auth,
                    AppCommand::CancelThreadRun(CancelThreadRun { thread_id, run_id }),
                )
                .await
            }
            _ => {
                request.body_mut().fill(0);
                empty_response(StatusCode::METHOD_NOT_ALLOWED)
            }
        }
    }

    async fn thread_command(&self, auth: AuthContext, command: AppCommand) -> Response<Vec<u8>> {
        match self.transport.execute(auth, command).await {
            Ok(AppReply::ThreadStatus(status)) => json_response(&status),
            Ok(AppReply::ThreadConversation(snapshot)) => json_response(&snapshot),
            Ok(AppReply::ThreadRunStarted(started)) => {
                let status = if started.replayed {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                };
                json_response_with_status(&started, status)
            }
            Ok(AppReply::ThreadRunCancellation(cancelled)) => {
                let status = if cancelled.state == ThreadRunCancellationState::AlreadyTerminal {
                    StatusCode::OK
                } else {
                    StatusCode::ACCEPTED
                };
                json_response_with_status(&cancelled, status)
            }
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn agents(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        match *request.method() {
            Method::GET if request.body().is_empty() => {
                let hidden = match agent_hidden_query(request.uri().query()) {
                    Some(hidden) => hidden,
                    None => {
                        return error_response(AppError::MalformedPayload { field: "query" });
                    }
                };
                match self
                    .transport
                    .execute(authority.auth, AppCommand::ListVisibleAgents { hidden })
                    .await
                {
                    Ok(AppReply::Agents(agents)) => {
                        json_response(&AgentProfilesResponse { agents })
                    }
                    Ok(_) => dependency_response(),
                    Err(error) => error_response(error),
                }
            }
            Method::POST => {
                if !authority.is_fresh() {
                    request.body_mut().fill(0);
                    return error_response(AppError::SensitiveWriteRefused {
                        reason: SensitiveWriteReason::SessionNotFresh,
                    });
                }
                let form = match parse_agent_body::<AgentMutationRequest>(&mut request) {
                    Ok(form) => form,
                    Err(error) => return agent_body_error_response(error),
                };
                match self
                    .transport
                    .execute(authority.auth, AppCommand::CreateAgent(form))
                    .await
                {
                    Ok(AppReply::Agent(agent)) => json_response_with_status(
                        &AgentProfileResponse { agent },
                        StatusCode::CREATED,
                    ),
                    Ok(_) => dependency_response(),
                    Err(error) => error_response(error),
                }
            }
            _ => {
                request.body_mut().fill(0);
                empty_response(StatusCode::METHOD_NOT_ALLOWED)
            }
        }
    }

    async fn agent_test_connection(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let probe = match parse_agent_body::<AgentConnectionTestRequest>(&mut request) {
            Ok(probe) => probe,
            Err(error) => return agent_body_error_response(error),
        };
        match self
            .transport
            .execute(authority.auth, AppCommand::TestAgentConnection(probe))
            .await
        {
            Ok(AppReply::AgentConnectionVerdict(verdict)) => json_response(&verdict),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn agent_detail(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
        route: AgentRoute<'_>,
    ) -> Response<Vec<u8>> {
        let supported = matches!(
            (route, request.method()),
            (AgentRoute::Detail { .. }, &Method::GET)
                | (AgentRoute::Detail { .. }, &Method::PATCH)
                | (AgentRoute::Detail { .. }, &Method::DELETE)
                | (AgentRoute::Duplicate { .. }, &Method::POST)
                | (AgentRoute::Hide { .. }, &Method::POST)
                | (AgentRoute::Unhide { .. }, &Method::POST)
                | (AgentRoute::CallbackToken { .. }, &Method::POST)
                | (AgentRoute::CallbackToken { .. }, &Method::DELETE)
        );
        if !supported {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let write = request.method() != Method::GET;
        if write && !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let agent_id = match percent_decode_segment(route.raw_agent_id()) {
            Some(agent_id) => BotId::new(agent_id),
            None => {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload { field: "agent_id" });
            }
        };
        let (command, reply_kind) = match (route, request.method()) {
            (AgentRoute::Detail { .. }, &Method::GET) if request.body().is_empty() => (
                AppCommand::GetVisibleAgent { agent_id },
                AgentReplyKind::Profile(StatusCode::OK),
            ),
            (AgentRoute::Detail { .. }, &Method::PATCH) => {
                let form = match parse_agent_body::<AgentMutationRequest>(&mut request) {
                    Ok(form) => form,
                    Err(error) => return agent_body_error_response(error),
                };
                (
                    AppCommand::UpdateAgent {
                        agent_id,
                        request: form,
                    },
                    AgentReplyKind::Profile(StatusCode::OK),
                )
            }
            (AgentRoute::Detail { .. }, &Method::DELETE) if request.body().is_empty() => {
                (AppCommand::DeleteAgent { agent_id }, AgentReplyKind::Empty)
            }
            (AgentRoute::Duplicate { .. }, &Method::POST) if request.body().is_empty() => (
                AppCommand::DuplicateAgent { agent_id },
                AgentReplyKind::Profile(StatusCode::CREATED),
            ),
            (AgentRoute::Hide { .. }, &Method::POST) if request.body().is_empty() => (
                AppCommand::SetAgentHidden {
                    agent_id,
                    hidden: true,
                },
                AgentReplyKind::Empty,
            ),
            (AgentRoute::Unhide { .. }, &Method::POST) if request.body().is_empty() => (
                AppCommand::SetAgentHidden {
                    agent_id,
                    hidden: false,
                },
                AgentReplyKind::Empty,
            ),
            (AgentRoute::CallbackToken { .. }, &Method::POST) if request.body().is_empty() => (
                AppCommand::IssueAgentCallbackToken { agent_id },
                AgentReplyKind::CallbackToken,
            ),
            (AgentRoute::CallbackToken { .. }, &Method::DELETE) if request.body().is_empty() => (
                AppCommand::RevokeAgentCallbackToken { agent_id },
                AgentReplyKind::Empty,
            ),
            _ => {
                request.body_mut().fill(0);
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
        };
        match (
            self.transport.execute(authority.auth, command).await,
            reply_kind,
        ) {
            (Ok(AppReply::Agent(agent)), AgentReplyKind::Profile(status)) => {
                json_response_with_status(&AgentProfileResponse { agent }, status)
            }
            (Ok(AppReply::AgentCallbackToken(token)), AgentReplyKind::CallbackToken) => {
                json_response_with_status(&token, StatusCode::CREATED)
            }
            (Ok(AppReply::AgentCallbackTokenRevoked(_)), AgentReplyKind::Empty) => {
                empty_response(StatusCode::NO_CONTENT)
            }
            (Ok(AppReply::AgentLifecycle(_)), AgentReplyKind::Empty) => {
                empty_response(StatusCode::NO_CONTENT)
            }
            (Ok(_), _) => dependency_response(),
            (Err(error), _) => error_response(error),
        }
    }

    async fn approvals(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::ListPendingToolApprovals)
            .await
        {
            Ok(AppReply::PendingToolApprovals(approvals)) => json_response(&approvals),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn components(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::ListComponents)
            .await
        {
            Ok(AppReply::Components(components)) => json_response(&components),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn component_catalogue(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::PUT {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.body().len() > COMPONENT_CATALOGUE_BODY_MAX_BYTES {
            return payload_too_large();
        }
        let catalogue = match serde_json::from_slice::<ComponentCatalogueRequest>(request.body()) {
            Ok(catalogue) => catalogue,
            Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::SyncComponentCatalogue(catalogue),
            )
            .await
        {
            Ok(AppReply::ComponentCatalogueAdded(added)) => json_response(&added),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn sandboxed_components(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        let command = match *request.method() {
            Method::GET if request.body().is_empty() => AppCommand::ListSandboxedComponents,
            Method::POST if !authority.is_fresh() => {
                return error_response(AppError::SensitiveWriteRefused {
                    reason: SensitiveWriteReason::SessionNotFresh,
                });
            }
            Method::POST if request.body().len() > SANDBOXED_COMPONENT_BODY_MAX_BYTES => {
                return payload_too_large();
            }
            Method::POST => {
                let draft =
                    match serde_json::from_slice::<SaveSandboxedComponentRequest>(request.body()) {
                        Ok(draft) => draft,
                        Err(_) => {
                            return error_response(AppError::MalformedPayload { field: "body" });
                        }
                    };
                AppCommand::SaveSandboxedComponent(draft)
            }
            _ => return empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        match self.transport.execute(authority.auth, command).await {
            Ok(AppReply::SandboxedComponents(components)) => json_response(&components),
            Ok(AppReply::SandboxedComponent(component)) => json_response(&component),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn published_sandboxed_components(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::ListPublishedSandboxedComponents)
            .await
        {
            Ok(AppReply::PublishedSandboxedComponents(components)) => json_response(&components),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn publish_sandboxed_component(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_name: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let revision =
            match serde_json::from_slice::<SandboxedComponentRevisionRequest>(request.body()) {
                Ok(value) => value,
                Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
            };
        let component_name = match percent_decode_segment(raw_name) {
            Some(name) => name,
            None => {
                return error_response(AppError::MalformedPayload {
                    field: "component_name",
                });
            }
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::PublishSandboxedComponent {
                    component_name,
                    expected_revision: revision.expected_revision,
                },
            )
            .await
        {
            Ok(AppReply::SandboxedComponent(component)) => json_response(&component),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn delete_sandboxed_component(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_name: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::DELETE {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let revision =
            match serde_json::from_slice::<SandboxedComponentRevisionRequest>(request.body()) {
                Ok(value) => value,
                Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
            };
        let component_name = match percent_decode_segment(raw_name) {
            Some(name) => name,
            None => {
                return error_response(AppError::MalformedPayload {
                    field: "component_name",
                });
            }
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::DeleteSandboxedComponent {
                    component_name,
                    expected_revision: revision.expected_revision,
                },
            )
            .await
        {
            Ok(AppReply::SandboxedComponentDeleted(deleted)) => json_response(&deleted),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn components_for_agent(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_agent_id: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let agent_id = match percent_decode_segment(raw_agent_id) {
            Some(agent_id) => BotId::new(agent_id),
            None => return error_response(AppError::MalformedPayload { field: "agent_id" }),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::ListComponentsForAgent { agent_id },
            )
            .await
        {
            Ok(AppReply::GrantedComponents(components)) => json_response(&components),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn component_decision(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_name: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.body().len() > COMPONENT_DECISION_BODY_MAX_BYTES {
            return payload_too_large();
        }
        let component_name = match percent_decode_segment(raw_name) {
            Some(name) => name,
            None => {
                return error_response(AppError::MalformedPayload {
                    field: "component_name",
                });
            }
        };
        let decision = match serde_json::from_slice::<ComponentDecisionRequest>(request.body()) {
            Ok(decision) => decision,
            Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::DecideComponent {
                    component_name,
                    request: decision,
                },
            )
            .await
        {
            Ok(AppReply::ComponentDecision(decision)) => json_response(&decision),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn component_functions(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::ListComponentDataFunctions)
            .await
        {
            Ok(AppReply::ComponentDataFunctions(functions)) => json_response(&functions),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn component_governance(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        route: ComponentGovernanceRoute<'_>,
    ) -> Response<Vec<u8>> {
        if !authority.is_fresh() {
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        if request.body().len() > COMPONENT_GOVERNANCE_BODY_MAX_BYTES {
            return payload_too_large();
        }
        let component_name = match percent_decode_segment(route.component_name()) {
            Some(component_name) => component_name,
            None => {
                return error_response(AppError::MalformedPayload {
                    field: "component_name",
                });
            }
        };
        let mutation = match route {
            ComponentGovernanceRoute::Functions { .. } if request.method() == Method::POST => {
                let request =
                    match serde_json::from_slice::<ComponentFunctionGrantRequest>(request.body()) {
                        Ok(request) => request,
                        Err(_) => {
                            return error_response(AppError::MalformedPayload { field: "body" });
                        }
                    };
                ComponentGovernanceMutation::SetFunctionGrant {
                    component_name,
                    function: request.function,
                    granted: true,
                }
            }
            ComponentGovernanceRoute::Function { raw_function, .. }
                if request.method() == Method::DELETE && request.body().is_empty() =>
            {
                let function = match percent_decode_segment(raw_function) {
                    Some(function) => function,
                    None => {
                        return error_response(AppError::MalformedPayload { field: "function" });
                    }
                };
                ComponentGovernanceMutation::SetFunctionGrant {
                    component_name,
                    function,
                    granted: false,
                }
            }
            ComponentGovernanceRoute::Grants { .. } if request.method() == Method::POST => {
                let request =
                    match serde_json::from_slice::<ComponentAgentGrantRequest>(request.body()) {
                        Ok(request) => request,
                        Err(_) => {
                            return error_response(AppError::MalformedPayload { field: "body" });
                        }
                    };
                ComponentGovernanceMutation::SetAgentGrant {
                    component_name,
                    agent_id: request.agent_id,
                    granted: true,
                }
            }
            ComponentGovernanceRoute::Grant { raw_agent_id, .. }
                if request.method() == Method::DELETE && request.body().is_empty() =>
            {
                let agent_id = match percent_decode_segment(raw_agent_id) {
                    Some(agent_id) => BotId::new(agent_id),
                    None => {
                        return error_response(AppError::MalformedPayload { field: "agent_id" });
                    }
                };
                ComponentGovernanceMutation::SetAgentGrant {
                    component_name,
                    agent_id,
                    granted: false,
                }
            }
            ComponentGovernanceRoute::Publication { .. } if request.method() == Method::POST => {
                let request =
                    match serde_json::from_slice::<ComponentPublicationRequest>(request.body()) {
                        Ok(request) => request,
                        Err(_) => {
                            return error_response(AppError::MalformedPayload { field: "body" });
                        }
                    };
                ComponentGovernanceMutation::SetPublication {
                    component_name,
                    published: request.published,
                }
            }
            ComponentGovernanceRoute::Draft { .. } if request.method() == Method::PUT => {
                let request = match serde_json::from_slice::<ComponentDraftRequest>(request.body())
                {
                    Ok(request) => request,
                    Err(_) => {
                        return error_response(AppError::MalformedPayload { field: "body" });
                    }
                };
                ComponentGovernanceMutation::SaveDraft {
                    component_name,
                    description: request.description,
                }
            }
            _ => return empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::UpdateComponentGovernance(mutation),
            )
            .await
        {
            Ok(AppReply::ComponentGovernanceUpdated(receipt)) => json_response(&receipt),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn component_human_decisions(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET || !request.body().is_empty() {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::ListPendingComponentHumanDecisions,
            )
            .await
        {
            Ok(AppReply::PendingComponentHumanDecisions(decisions)) => json_response(&decisions),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn component_human_decision_answer(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_decision_id: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.body().len() > COMPONENT_DECISION_BODY_MAX_BYTES {
            return payload_too_large();
        }
        let decision_id = match percent_decode_segment(raw_decision_id) {
            Some(decision_id) => decision_id,
            None => {
                return error_response(AppError::MalformedPayload {
                    field: "decision_id",
                });
            }
        };
        let answer = match serde_json::from_slice::<ComponentHumanDecisionAnswer>(request.body()) {
            Ok(answer) => answer,
            Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::ResolveComponentHumanDecision {
                    decision_id,
                    answer,
                },
            )
            .await
        {
            Ok(AppReply::ComponentHumanDecisionResolved(resolved)) => json_response(&resolved),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn component_call(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_name: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.body().len() > COMPONENT_DECISION_BODY_MAX_BYTES {
            return payload_too_large();
        }
        let component_name = match percent_decode_segment(raw_name) {
            Some(name) => name,
            None => {
                return error_response(AppError::MalformedPayload {
                    field: "component_name",
                });
            }
        };
        let call = match serde_json::from_slice::<ComponentFunctionCallRequest>(request.body()) {
            Ok(call) => call,
            Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::CallComponentFunction {
                    component_name,
                    request: call,
                },
            )
            .await
        {
            Ok(AppReply::ComponentFunctionCall(result)) => {
                let status = if result.error.is_some() {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::OK
                };
                json_response_with_status(&result, status)
            }
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    async fn approval_decision(
        &self,
        request: Request<Vec<u8>>,
        authority: WindowAuthority,
        raw_id: &str,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !authority.is_fresh() {
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        if request.body().len() > API_BODY_MAX_BYTES {
            return payload_too_large();
        }
        let approval_id = match percent_decode_segment(raw_id) {
            Some(id) if !id.is_empty() && id.len() <= 128 && !id.as_bytes().contains(&0) => id,
            _ => {
                return error_response(AppError::MalformedPayload {
                    field: "approvalId",
                });
            }
        };
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DecisionBody {
            decision: ToolApprovalDecision,
        }
        let body = match serde_json::from_slice::<DecisionBody>(request.body()) {
            Ok(body) => body,
            Err(_) => return error_response(AppError::MalformedPayload { field: "body" }),
        };
        match self
            .transport
            .execute(
                authority.auth,
                AppCommand::DecideToolApproval {
                    approval_id,
                    decision: body.decision,
                },
            )
            .await
        {
            Ok(AppReply::ToolApprovalResolved(resolved)) => json_response(&resolved),
            Ok(_) => dependency_response(),
            Err(error) => error_response(error),
        }
    }

    fn asset(&self, path: &str) -> Response<Vec<u8>> {
        let Some(relative) = closed_asset_path(path) else {
            return empty_response(StatusCode::NOT_FOUND);
        };
        #[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
        let root = match &self.assets {
            StaticAssets::Verified(files) => {
                return match files.get(relative) {
                    Some(body) if body.len() as u64 <= static_asset_max_bytes(relative) => {
                        static_response(content_type(Path::new(relative)), body.to_vec())
                    }
                    _ => empty_response(StatusCode::NOT_FOUND),
                };
            }
            StaticAssets::Path(root) => root,
        };
        #[cfg(not(any(all(feature = "desktop-launcher", target_os = "macos"), test)))]
        let StaticAssets::Path(root) = &self.assets;
        let candidate = root.join(relative);
        let Ok(canonical) = fs::canonicalize(candidate) else {
            return empty_response(StatusCode::NOT_FOUND);
        };
        if !canonical.starts_with(root) {
            return empty_response(StatusCode::NOT_FOUND);
        }
        let Ok(metadata) = fs::metadata(&canonical) else {
            return empty_response(StatusCode::NOT_FOUND);
        };
        if !metadata.is_file() || metadata.len() > static_asset_max_bytes(relative) {
            return empty_response(StatusCode::NOT_FOUND);
        }
        let Ok(body) = fs::read(&canonical) else {
            return empty_response(StatusCode::NOT_FOUND);
        };
        if body.len() as u64 > static_asset_max_bytes(relative) {
            return empty_response(StatusCode::NOT_FOUND);
        }
        static_response(content_type(&canonical), body)
    }
}

#[tauri::command]
async fn openbot_structured_events_open(
    webview: Webview,
    protocol: State<'_, Arc<DesktopTauriProtocolSlot>>,
    request: SubscriptionRequest,
    channel: Channel<String>,
) -> Result<DesktopStructuredSubscriptionOpened, String> {
    let label = webview.label().to_owned();
    let protocol = protocol
        .get()
        .map_err(|error| tauri_host_error_code(&error).to_owned())?;
    let subscription = protocol
        .open_structured_subscription(&label, request)
        .await
        .map_err(|error| tauri_host_error_code(&error).to_owned())?;
    let opened = DesktopStructuredSubscriptionOpened {
        subscription_id: subscription.subscription_id(),
    };
    tauri::async_runtime::spawn(async move {
        let _ = pump_tauri_structured_events(subscription, channel).await;
    });
    Ok(opened)
}

#[tauri::command]
fn openbot_structured_events_close(
    webview: Webview,
    protocol: State<'_, Arc<DesktopTauriProtocolSlot>>,
    request: DesktopStructuredSubscriptionCloseRequest,
) -> Result<bool, String> {
    protocol
        .get()
        .map_err(|error| tauri_host_error_code(&error).to_owned())?
        .close_structured_subscription(webview.label(), request.subscription_id)
        .map_err(|error| tauri_host_error_code(&error).to_owned())
}

fn tauri_host_error_code(error: &TauriHostError) -> &'static str {
    match error {
        TauriHostError::InvalidBundle => "desktop_bundle_invalid",
        TauriHostError::InvalidScheme => "desktop_scheme_invalid",
        TauriHostError::WindowAlreadyBound => "desktop_window_already_bound",
        TauriHostError::AuthorityUnavailable => "desktop_window_authority_unavailable",
        TauriHostError::InvalidFreshness => "desktop_freshness_invalid",
        TauriHostError::WindowUnbound => "desktop_window_unbound",
        TauriHostError::WindowBindingCounterExhausted => "desktop_window_binding_counter_exhausted",
        TauriHostError::ProtocolNotReady => "desktop_protocol_not_ready",
        TauriHostError::ProtocolAlreadyReady => "desktop_protocol_already_ready",
        TauriHostError::StructuredSubscription(DesktopStructuredOpenError::CounterExhausted) => {
            "structured_subscription_counter_exhausted"
        }
        TauriHostError::StructuredSubscription(
            DesktopStructuredOpenError::WindowBudgetExhausted,
        ) => "structured_subscription_window_budget_exhausted",
        TauriHostError::StructuredSubscription(DesktopStructuredOpenError::WindowClosed) => {
            "desktop_window_unbound"
        }
        TauriHostError::StructuredSubscription(DesktopStructuredOpenError::Session(
            OpenSessionError::Application(error),
        )) => error.code().as_str(),
        TauriHostError::StructuredSubscription(DesktopStructuredOpenError::Session(
            OpenSessionError::WindowAlreadyOpen(_),
        )) => "desktop_subscription_conflict",
        TauriHostError::StructuredSubscription(DesktopStructuredOpenError::Session(
            OpenSessionError::ShuttingDown,
        )) => "desktop_shutting_down",
    }
}

/// Register the exact caller-selected custom scheme and audited custom commands.
pub fn register_tauri_protocol(
    builder: Builder<tauri::Wry>,
    scheme: &str,
    protocol: Arc<DesktopTauriProtocol>,
) -> Result<Builder<tauri::Wry>, TauriHostError> {
    if !valid_scheme(scheme) {
        return Err(TauriHostError::InvalidScheme);
    }
    let scheme = scheme.to_owned();
    let lifecycle = Arc::new(
        DesktopWindowLifecycle::new(&scheme, Arc::clone(&protocol))
            .map_err(|_| TauriHostError::InvalidScheme)?,
    );
    let slot = DesktopTauriProtocolSlot::ready(protocol);
    let builder = register_tauri_window_lifecycle(builder, lifecycle);
    register_tauri_protocol_slot(builder, &scheme, slot)
}

pub(crate) fn register_tauri_protocol_slot(
    builder: Builder<tauri::Wry>,
    scheme: &str,
    slot: Arc<DesktopTauriProtocolSlot>,
) -> Result<Builder<tauri::Wry>, TauriHostError> {
    if !valid_scheme(scheme) {
        return Err(TauriHostError::InvalidScheme);
    }
    let scheme = scheme.to_owned();
    let request_slot = Arc::clone(&slot);
    let builder = builder
        .manage(slot)
        .invoke_handler(tauri::generate_handler![
            openbot_structured_events_open,
            openbot_structured_events_close,
            window_chrome::wrok_bot_window_chrome
        ]);
    Ok(builder.register_asynchronous_uri_scheme_protocol(
        scheme,
        move |context, request, responder| {
            let Ok(protocol) = request_slot.get() else {
                responder.respond(empty_response(StatusCode::SERVICE_UNAVAILABLE));
                return;
            };
            let label = context.webview_label().to_owned();
            tauri::async_runtime::spawn(async move {
                if custom_model_catalog::owns_path(request.uri().path()) {
                    let prepared = protocol
                        .prepare_custom_model_catalog_response(&label, request)
                        .await;
                    protocol.finish_prepared_custom_model_catalog_response(
                        &label,
                        prepared,
                        |response| {
                            responder.respond(response);
                        },
                    );
                } else if artifact_reads::owns_path(request.uri().path()) {
                    let prepared = protocol
                        .prepare_public_artifact_read_response(&label, request)
                        .await;
                    protocol.finish_public_artifact_read_response(&label, prepared, |response| {
                        responder.respond(response);
                    });
                } else {
                    responder.respond(protocol.handle(&label, request).await);
                }
            });
        },
    ))
}

/// Detect the first-release Desktop OS fallback without accepting arbitrary locales.
#[must_use]
pub fn detect_os_locale() -> UiLocale {
    sys_locale::get_locale().map_or(UiLocale::En, |locale| {
        let normalized = locale.to_ascii_lowercase();
        if normalized == "zh" || normalized.starts_with("zh-") || normalized.starts_with("zh_") {
            UiLocale::ZhCn
        } else {
            UiLocale::En
        }
    })
}

fn validate_index(index: &str) -> Result<(), TauriHostError> {
    if index.matches(HTML_ROOT_MARKER).count() != 1 || index.to_ascii_lowercase().contains("<base")
    {
        return Err(TauriHostError::InvalidBundle);
    }
    let lower = index.to_ascii_lowercase();
    let scripts = lower.matches("<script").count();
    if scripts != 1
        || lower.matches(" src=").count() != 1
        || !(lower.contains(" src=\"/openbot-bootstrap.mjs\"")
            || lower.contains(" src=\"./openbot-bootstrap.mjs\""))
    {
        return Err(TauriHostError::InvalidBundle);
    }
    let start = lower.find("<script").ok_or(TauriHostError::InvalidBundle)?;
    let opening_end = lower[start..]
        .find('>')
        .map(|offset| start + offset)
        .ok_or(TauriHostError::InvalidBundle)?;
    let close = lower[opening_end + 1..]
        .find("</script>")
        .map(|offset| opening_end + 1 + offset)
        .ok_or(TauriHostError::InvalidBundle)?;
    if !lower[opening_end + 1..close].trim().is_empty() {
        return Err(TauriHostError::InvalidBundle);
    }
    Ok(())
}

fn index_response(
    index: &str,
    theme: Option<UiTheme>,
    locale: Option<UiLocale>,
    os_locale: UiLocale,
) -> Response<Vec<u8>> {
    let theme = theme.unwrap_or(UiTheme::System);
    let locale = locale.unwrap_or(os_locale);
    let replacement = index_root(theme, locale, cfg!(target_os = "macos"));
    let body = index
        .replacen(HTML_ROOT_MARKER, &replacement, 1)
        .into_bytes();
    let mut response = response(StatusCode::OK, "text/html; charset=utf-8", body, true);
    response
        .headers_mut()
        .insert(CONTENT_SECURITY_POLICY, CSP.parse().expect("static CSP"));
    response
}

fn index_root(theme: UiTheme, locale: UiLocale, macos_overlay: bool) -> String {
    let class = match theme {
        UiTheme::System => "",
        UiTheme::Light => " class=\"light\"",
        UiTheme::Dark => " class=\"dark\"",
    };
    // Layout hint from the same host compile-time branch as the native Overlay builder. This
    // attribute is not an authority assertion and never comes from renderer platform claims.
    let chrome = if macos_overlay {
        " data-window-chrome=\"macos-overlay\""
    } else {
        ""
    };
    format!("<html lang=\"{}\"{class}{chrome}>", locale.as_str())
}

fn json_response<T: serde::Serialize>(value: &T) -> Response<Vec<u8>> {
    json_response_with_status(value, StatusCode::OK)
}

fn json_response_with_status<T: serde::Serialize>(
    value: &T,
    status: StatusCode,
) -> Response<Vec<u8>> {
    match serde_json::to_vec(value) {
        Ok(body) => response(status, "application/json", body, true),
        Err(_) => dependency_response(),
    }
}

fn parse_agent_body<T: serde::de::DeserializeOwned>(
    request: &mut Request<Vec<u8>>,
) -> Result<T, AgentBodyError> {
    if request.body().len() > AGENT_BODY_MAX_BYTES {
        request.body_mut().fill(0);
        return Err(AgentBodyError::TooLarge);
    }
    let parsed = serde_json::from_slice::<T>(request.body());
    request.body_mut().fill(0);
    parsed.map_err(|_| AgentBodyError::Malformed)
}

fn agent_body_error_response(error: AgentBodyError) -> Response<Vec<u8>> {
    match error {
        AgentBodyError::Malformed => error_response(AppError::MalformedPayload { field: "body" }),
        AgentBodyError::TooLarge => payload_too_large(),
    }
}

fn parse_sensitive_begin_body(
    request: &mut Request<Vec<u8>>,
    maximum: usize,
) -> Result<openbot_contracts::begin_thread_run_wire::DecodedBeginThreadRunBody, SensitiveBodyError>
{
    if request.body().len() > maximum {
        request.body_mut().fill(0);
        return Err(SensitiveBodyError::TooLarge);
    }
    // The decoder returns owned DTOs; every borrowed RawValue/span has ended before zeroing.
    let parsed =
        openbot_contracts::begin_thread_run_wire::decode_begin_thread_run_body(request.body());
    request.body_mut().fill(0);
    parsed.map_err(|_| SensitiveBodyError::Malformed)
}

fn parse_sensitive_body<T: DeserializeOwned>(
    request: &mut Request<Vec<u8>>,
    maximum: usize,
) -> Result<T, SensitiveBodyError> {
    if request.body().len() > maximum {
        request.body_mut().fill(0);
        return Err(SensitiveBodyError::TooLarge);
    }
    let parsed = serde_json::from_slice::<T>(request.body());
    request.body_mut().fill(0);
    parsed.map_err(|_| SensitiveBodyError::Malformed)
}

fn sensitive_body_error_response(error: SensitiveBodyError) -> Response<Vec<u8>> {
    match error {
        SensitiveBodyError::Malformed => {
            error_response(AppError::MalformedPayload { field: "body" })
        }
        SensitiveBodyError::TooLarge => payload_too_large(),
    }
}

fn error_response(error: AppError) -> Response<Vec<u8>> {
    let body = match &error {
        AppError::StaleGeneration {
            subject: openbot_contracts::error::StaleGenerationSubject::Configuration { snapshot },
        } => serde_json::to_vec(snapshot),
        AppError::ArtifactGone { status } => {
            serde_json::to_vec(&json!({"code":error.code().as_str(),"status":status}))
        }
        AppError::PolicyRefused { rule, .. }
            if matches!(rule.as_str(), "artifact_disk_space" | "artifact_quota") =>
        {
            serde_json::to_vec(&json!({"code":error.code().as_str(),"rule":rule}))
        }
        _ => serde_json::to_vec(&json!({"code": error.code().as_str()})),
    }
    .unwrap_or_else(|_| b"{\"code\":\"dependency_unavailable\"}".to_vec());
    response(
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
        "application/json",
        body,
        true,
    )
}

fn dependency_response() -> Response<Vec<u8>> {
    error_response(AppError::DependencyUnavailable {
        dependency: "application",
    })
}

fn payload_too_large() -> Response<Vec<u8>> {
    response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "application/json",
        b"{\"code\":\"malformed_payload\"}".to_vec(),
        true,
    )
}

fn empty_response(status: StatusCode) -> Response<Vec<u8>> {
    response(status, "application/octet-stream", Vec::new(), true)
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    no_store: bool,
) -> Response<Vec<u8>> {
    let mut response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(body)
        .expect("closed desktop response");
    if no_store {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, "no-store".parse().expect("static no-store"));
    }
    response
}

fn static_response(mime: &'static str, body: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = response(StatusCode::OK, mime, body, false);
    response
        .headers_mut()
        .insert(CONTENT_SECURITY_POLICY, CSP.parse().expect("static CSP"));
    response.headers_mut().insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("static nosniff"),
    );
    response
}

fn closed_asset_path(path: &str) -> Option<&str> {
    let relative = path.strip_prefix('/')?;
    if relative.is_empty()
        || relative.contains('%')
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    matches!(
        Path::new(relative)
            .extension()
            .and_then(|value| value.to_str()),
        Some("css" | "js" | "mjs" | "wasm" | "woff2" | "txt" | "png" | "gif" | "svg")
    )
    .then_some(relative)
}

fn is_spa_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("/.well-known/")
        && !path.starts_with("/fonts/")
        && !path
            .rsplit('/')
            .next()
            .is_some_and(|segment| segment.contains('.'))
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

pub(crate) fn valid_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && scheme.len() <= 32
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+-.".contains(&byte)
        })
        && !matches!(scheme, "http" | "https" | "tauri" | "asset")
}

fn run_reconciliation_query(raw: Option<&str>) -> Option<RunReconciliationQuery> {
    let mut query = RunReconciliationQuery::default();
    for pair in raw
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_query_component(key)?;
        let value = percent_decode_query_component(value)?;
        match key.as_str() {
            "afterCallSequence" if query.after_call_sequence.is_none() => {
                query.after_call_sequence = Some(value.parse().ok()?);
            }
            "afterAttemptSequence" if query.after_attempt_sequence.is_none() => {
                query.after_attempt_sequence = Some(value.parse().ok()?);
            }
            "limit" if query.limit.is_none() => query.limit = Some(value.parse().ok()?),
            _ => return None,
        }
    }
    Some(query)
}

fn agent_hidden_query(query: Option<&str>) -> Option<bool> {
    match query {
        None | Some("") | Some("hidden=false") => Some(false),
        Some("hidden=true") => Some(true),
        Some(_) => None,
    }
}

fn channel_list_query(query: Option<&str>) -> Option<(Option<u32>, Option<String>)> {
    let Some(query) = query else {
        return Some((None, None));
    };
    if query.is_empty() {
        return Some((None, None));
    }
    if query.len() > API_BODY_MAX_BYTES {
        return None;
    }
    let mut limit = None;
    let mut cursor = None;
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=')?;
        let key = percent_decode_query_component(raw_key)?;
        let value = percent_decode_query_component(raw_value)?;
        match key.as_str() {
            "limit" if limit.is_none() => limit = Some(value.parse().ok()?),
            "cursor" if cursor.is_none() => cursor = Some(value),
            _ => return None,
        }
    }
    Some((limit, cursor))
}

fn plugin_grant_query(query: Option<&str>) -> Option<PluginGrantMutation> {
    let query = query?;
    if query.is_empty() || query.len() > MCP_ADMIN_BODY_MAX_BYTES {
        return None;
    }
    let mut kind = None;
    let mut reference = None;
    let mut agent_id = None;
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=')?;
        let key = percent_decode_query_component(raw_key)?;
        let value = percent_decode_query_component(raw_value)?;
        match key.as_str() {
            "kind" if kind.is_none() => {
                kind = Some(match value.as_str() {
                    "mcp" => PluginGrantKind::Mcp,
                    "skill" => PluginGrantKind::Skill,
                    _ => return None,
                });
            }
            "ref" if reference.is_none() => reference = Some(value),
            "agentId" if agent_id.is_none() => agent_id = Some(value),
            _ => return None,
        }
    }
    Some(PluginGrantMutation {
        kind: kind?,
        reference: reference?,
        agent_id: agent_id?,
    })
}

fn percent_decode_segment(raw: &str) -> Option<String> {
    if raw.contains('/') {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push(hex(high)? << 4 | hex(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn percent_decode_query_component(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = *bytes.get(index + 1)?;
                let low = *bytes.get(index + 2)?;
                decoded.push(hex(high)? << 4 | hex(low)?);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "tauri_host/local_confirmation_tests.rs"]
mod local_confirmation_tests;

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "tauri_host/current_request_binding_local_tests.rs"]
mod current_request_binding_local_tests;

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "tauri_host/artifact_source_run_local_tests.rs"]
mod artifact_source_run_local_tests;

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "tauri_host/runtime_capabilities_local_tests.rs"]
mod runtime_capabilities_local_tests;

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "tauri_host/approval_preference_local_tests.rs"]
mod approval_preference_local_tests;

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "tauri_host/custom_model_v2_tests.rs"]
mod custom_model_v2_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DesktopStructuredEventFrame;
    use async_trait::async_trait;
    use openbot_application::cursor::ChannelCursor;
    use openbot_application::{
        AgentAdministration, AgentAdministrationError, AgentAdministrationScope,
        AgentCallbackTokenAdministration, AgentCallbackTokenError, AgentDirectory,
        AgentReachability, AgentReadScope, BeginThreadRunRequest, CancelThreadRunRequest,
        ChannelAdministration, ChannelAdministrationError, ChannelCreateRequest, ChannelReadScope,
        ChannelReader, ChannelRoutingBackend, ChannelRoutingBackendError, ComponentAdministration,
        ComponentAdministrationError, ComponentFunctionArguments, ComponentFunctionCallPlan,
        ComponentRuntimeScope, McpConnectionAdministration, McpConnectionError, OpenBotApplication,
        PeopleAdministration, PeoplePageRequest, PeoplePortError, PortError,
        ProviderRemoteInterruptBatch, ProviderRemoteResume, ProviderRemoteResumeStatus,
        RemoteInterruptCoordinator, RemoteInterruptError, RemoteInterruptPending,
        RemoteInterruptPendingInput, RemoteInterruptResolutionReceipt, RoutingAuditRecord,
        RunCostBudgetAdministration, RunCostBudgetAdministrationError, RunCostCap,
        RunExecutionLease, SandboxedComponentAdministration, SandboxedComponentAdministrationError,
        SandboxedComponentDraft, ThreadConversationRequest, ThreadDirectory, ThreadDirectoryError,
        ToolApprovalAdministration, ToolApprovalAdministrationError, UiPreferenceAdministration,
        UiPreferenceAdministrationError,
    };
    use openbot_contracts::agent::{
        AgentConnectionVerdict, AgentLifecycleReceipt, AgentLifecycleState, AgentProfile,
        AgentVisibility, CallbackTokenIssued, CallbackTokenRevoked,
    };
    use openbot_contracts::auth::{AuthGeneration, Role};
    use openbot_contracts::budget::{RunCostBudgetPreference, RunCostCapInput};
    use openbot_contracts::command::{
        ChannelDetail, ChannelPage, ChannelRoutingDecision, ChannelSummary,
        ThreadConversationSnapshot, ThreadForegroundRunState, ThreadMinted, ThreadRunAnchor,
        ThreadRunCancellation, ThreadRunStarted, ThreadStatus,
    };
    use openbot_contracts::components::{
        BOT_ACTIVITY_FUNCTION_NAME, BotActivityReport, CompiledComponentManifestEntry,
        ComponentApprovalAnswer, ComponentApprovalDecision, ComponentCatalogueAdded,
        ComponentDataFunctions, ComponentDecision, ComponentDecisionRequest, ComponentFunctionCall,
        ComponentFunctionData, ComponentGovernanceMutation, ComponentGovernanceReceipt,
        ComponentHumanDecisionAnswer, ComponentHumanDecisionResolved, ComponentRecord,
        ComponentRecords, GrantedCompiledComponent, GrantedCompiledComponents,
        PendingComponentHumanDecisions, SHOW_QUOTE_COMPONENT_NAME, compiled_component_manifest,
    };
    use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
    use openbot_contracts::mcp::{
        GrantedPlugins, McpAdminAuthentication, McpAdminCatalogueEntry, McpAdminPage,
        McpConnectionDisconnected, McpConnections, McpOAuthAuthorization, McpOAuthClientRegistered,
        McpOAuthClientRegistration, McpOAuthReturnTo, McpServerMutation, McpServerRemoved,
        PluginGrantMutation, PluginMutationAcknowledged, PluginSkillMutation, PluginSkills,
    };
    use openbot_contracts::people::{CurrentUser, PeoplePage, Person};
    use openbot_contracts::reconciliation::{
        RunEffectReceipt, RunEffectReceiptFact, RunEffectReceiptsSnapshot,
        RunReconciliationAttempt, RunReconciliationAttemptStatus, RunReconciliationCursor,
        RunReconciliationSnapshot, RunReconciliationStatus,
    };
    use openbot_contracts::remote_interrupt::{
        PendingRemoteInterrupts, RemoteInterruptAnswerStatus, RemoteInterruptResolved,
    };
    use openbot_contracts::sandboxed::{
        PublishedSandboxedComponent, PublishedSandboxedComponents, SandboxedComponentDeleted,
        SandboxedComponentRecord, SandboxedComponentResponse, SandboxedComponents,
        SaveSandboxedComponentRequest,
    };
    use openbot_contracts::tool::{PendingToolApprovals, ToolApprovalResolved};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tauri::ipc::InvokeResponseBody;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct NeverAppStream;

    impl futures_core::Stream for NeverAppStream {
        type Item = openbot_contracts::command::AppEvent;

        fn poll_next(
            self: core::pin::Pin<&mut Self>,
            _context: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Option<Self::Item>> {
            core::task::Poll::Pending
        }
    }

    struct BlockingSubscriptionService {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl openbot_application::ApplicationService for BlockingSubscriptionService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(openbot_contracts::command::HealthReport {
                ok: true,
            }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<openbot_application::AppEventStream, AppError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(Box::pin(NeverAppStream))
        }
    }

    #[derive(Default)]
    struct ReconciliationService {
        calls: Mutex<Vec<(AuthContext, AppCommand)>>,
        error: Option<AppError>,
        wrong_reply: bool,
        oversized: bool,
        barrier: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    }

    #[async_trait]
    impl openbot_application::ApplicationService for ReconciliationService {
        async fn execute(
            &self,
            auth: AuthContext,
            command: AppCommand,
        ) -> Result<AppReply, AppError> {
            self.calls.lock().unwrap().push((auth, command.clone()));
            if let Some((entered, release)) = &self.barrier {
                entered.notify_one();
                release.notified().await;
            }
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            // Similar snapshot envelopes do not make the sibling read reply interchangeable.
            let command = if self.wrong_reply {
                match command {
                    AppCommand::GetRunReconciliation {
                        thread_id,
                        run_id,
                        after,
                        limit,
                    } => AppCommand::GetRunEffectReceipts {
                        thread_id,
                        run_id,
                        after,
                        limit,
                    },
                    AppCommand::GetRunEffectReceipts {
                        thread_id,
                        run_id,
                        after,
                        limit,
                    } => AppCommand::GetRunReconciliation {
                        thread_id,
                        run_id,
                        after,
                        limit,
                    },
                    _ => panic!("only closed reconciliation reads are admitted"),
                }
            } else {
                command
            };
            if let AppCommand::GetRunEffectReceipts {
                thread_id, run_id, ..
            } = &command
            {
                return Ok(AppReply::RunEffectReceipts(RunEffectReceiptsSnapshot {
                    thread_id: thread_id.clone(),
                    run_id: run_id.clone(),
                    status: RunReconciliationStatus::ReconciliationRequired,
                    terminal_event_sequence: 12,
                    observed_at: time::OffsetDateTime::UNIX_EPOCH,
                    foreground_blocked: true,
                    receipts: vec![
                        RunEffectReceipt {
                            receipt_id: "550e8400-e29b-41d4-a716-446655440077".into(),
                            tool_call_id: "internal-call".into(),
                            call_sequence: 7,
                            attempt_id: "internal-attempt".into(),
                            attempt_sequence: 2,
                            fact: RunEffectReceiptFact::MemoryCreated,
                            recorded_at: time::OffsetDateTime::UNIX_EPOCH,
                        };
                        if self.oversized { 2000 } else { 1 }
                    ],
                    next: Some(RunReconciliationCursor {
                        call_sequence: 7,
                        attempt_sequence: 2,
                    }),
                    available_actions: [],
                }));
            }
            let AppCommand::GetRunReconciliation {
                thread_id, run_id, ..
            } = command
            else {
                panic!("reconciliation must use its closed Application command");
            };
            let attempt = RunReconciliationAttempt {
                tool_call_id: "internal-call".into(),
                call_sequence: 7,
                attempt_id: "internal-attempt".into(),
                attempt_sequence: 2,
                status: RunReconciliationAttemptStatus::Executing,
                recorded_commit_state: None,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                started_at: None,
                finished_at: None,
            };
            Ok(AppReply::RunReconciliation(RunReconciliationSnapshot {
                thread_id,
                run_id,
                status: RunReconciliationStatus::ReconciliationRequired,
                terminal_event_sequence: 12,
                observed_at: time::OffsetDateTime::UNIX_EPOCH,
                foreground_blocked: true,
                attempts: vec![attempt; if self.oversized { 2000 } else { 1 }],
                next: None,
                available_actions: [],
            }))
        }

        async fn subscribe(
            &self,
            _: AuthContext,
            _: SubscriptionRequest,
        ) -> Result<openbot_application::AppEventStream, AppError> {
            panic!("reconciliation is unary");
        }
    }

    fn reconciliation_protocol(
        service: Arc<ReconciliationService>,
    ) -> (Arc<DesktopTauriProtocol>, PathBuf) {
        let root = protocol_root();
        let protocol = Arc::new(
            DesktopTauriProtocol::open(&root, Arc::new(InProcessTransport::new(service))).unwrap(),
        );
        protocol.bind_window("main", auth(), None).unwrap();
        (protocol, root)
    }

    fn reconciliation_request(receipts: bool, run: &str, query: &str) -> Request<Vec<u8>> {
        let suffix = if receipts { "/receipts" } else { "" };
        Request::builder()
            .uri(format!(
                "/api/threads/550e8400-e29b-81d4-a716-446655440001/runs/{run}/reconciliation{suffix}{query}"
            ))
            .body(Vec::new())
            .unwrap()
    }

    fn reconciliation_body(response: &Response<Vec<u8>>) -> serde_json::Value {
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        if response.body().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(response.body()).unwrap()
        }
    }

    #[tokio::test]
    async fn reconciliation_maps_shared_command_and_decodes_opaque_run_exactly_once() {
        for receipts in [false, true] {
            let service = Arc::new(ReconciliationService::default());
            let (protocol, root) = reconciliation_protocol(service.clone());
            for (encoded, decoded) in [
                ("legacy%2Frun", "legacy/run"),
                ("legacy%252Frun", "legacy%2Frun"),
                ("%E8%BF%90%E8%A1%8C%25", "运行%"),
            ] {
                let response = protocol
                    .handle(
                        "main",
                        reconciliation_request(
                            receipts,
                            encoded,
                            "?afterCallSequence=7&afterAttemptSequence=2&limit=100",
                        ),
                    )
                    .await;
                assert_eq!(response.status(), StatusCode::OK);
                let body = reconciliation_body(&response);
                assert_eq!(body["runId"], decoded);
                assert_eq!(body["status"], "reconciliation_required");
                assert_eq!(body["availableActions"], json!([]));
                assert_eq!(body.as_object().unwrap().len(), 9);
                if receipts {
                    assert_eq!(
                        body["receipts"],
                        json!([{
                            "receiptId":"550e8400-e29b-41d4-a716-446655440077",
                            "toolCallId":"internal-call","callSequence":7,
                            "attemptId":"internal-attempt","attemptSequence":2,
                            "fact":"memory_created","recordedAt":"1970-01-01T00:00:00Z"
                        }])
                    );
                    assert_eq!(body["next"], json!({"callSequence":7,"attemptSequence":2}));
                    assert!(body.get("attempts").is_none());
                } else {
                    assert_eq!(
                        body["attempts"][0]["recordedCommitState"],
                        serde_json::Value::Null
                    );
                    assert_eq!(body["attempts"][0]["startedAt"], serde_json::Value::Null);
                    assert_eq!(body["attempts"][0]["finishedAt"], serde_json::Value::Null);
                    assert_eq!(body["attempts"][0].as_object().unwrap().len(), 9);
                    assert!(body.get("receipts").is_none());
                }
                let calls = service.calls.lock().unwrap();
                let (observed_auth, command) = calls.last().unwrap();
                assert_eq!(observed_auth, &auth());
                assert_eq!(
                    command,
                    &if receipts {
                        AppCommand::GetRunEffectReceipts {
                            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440001"),
                            run_id: RunId::new(decoded),
                            after: Some(RunReconciliationCursor {
                                call_sequence: 7,
                                attempt_sequence: 2,
                            }),
                            limit: Some(100),
                        }
                    } else {
                        AppCommand::GetRunReconciliation {
                            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440001"),
                            run_id: RunId::new(decoded),
                            after: Some(RunReconciliationCursor {
                                call_sequence: 7,
                                attempt_sequence: 2,
                            }),
                            limit: Some(100),
                        }
                    }
                );
            }
            let response = protocol
                .handle("main", reconciliation_request(receipts, "opaque", ""))
                .await;
            assert_eq!(response.status(), StatusCode::OK);
            reconciliation_body(&response);
            assert!(matches!(
                service.calls.lock().unwrap().last().unwrap().1,
                AppCommand::GetRunReconciliation {
                    after: None,
                    limit: None,
                    ..
                } | AppCommand::GetRunEffectReceipts {
                    after: None,
                    limit: None,
                    ..
                }
            ));
            protocol.unbind_window("main").unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn reconciliation_rejects_malformed_query_path_and_any_get_body_before_dispatch() {
        for receipts in [false, true] {
            let service = Arc::new(ReconciliationService::default());
            let (protocol, root) = reconciliation_protocol(service.clone());
            for query in [
                "?actor=secret-sentinel",
                "?limit=1&limit=2",
                "?limit=1&%6cimit=2",
                "?afterCallSequence=0",
                "?afterAttemptSequence=0",
                "?limit=0",
                "?limit=101",
                "?limit=4294967296",
                "?afterCallSequence=9223372036854775808&afterAttemptSequence=0",
                "?afterCallSequence=-1&afterAttemptSequence=0",
                "?limit=1.0",
                "?limit=",
                "?limit=1%",
                "?limit=%2",
                "?limit=%GG",
                "?limit=%FF",
                "?%FF=1",
            ] {
                let response = protocol
                    .handle("main", reconciliation_request(receipts, "opaque", query))
                    .await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
                assert_eq!(
                    reconciliation_body(&response),
                    json!({"code":"malformed_payload"})
                );
            }
            for run in ["%FF", "%", "%2", "%GG"] {
                let response = protocol
                    .handle("main", reconciliation_request(receipts, run, ""))
                    .await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(
                    reconciliation_body(&response),
                    json!({"code":"malformed_payload"})
                );
            }
            for length in [1, CHANNEL_THREAD_BODY_MAX_BYTES + 1] {
                let mut request = reconciliation_request(receipts, "opaque", "");
                *request.body_mut() = vec![b'x'; length];
                let response = protocol.handle("main", request).await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(
                    reconciliation_body(&response),
                    json!({"code":"malformed_payload"})
                );
            }
            for method in [Method::POST, Method::HEAD] {
                let mut request = reconciliation_request(receipts, "opaque", "");
                *request.method_mut() = method;
                let response = protocol.handle("main", request).await;
                assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
                reconciliation_body(&response);
            }
            assert!(service.calls.lock().unwrap().is_empty());
            protocol.unbind_window("main").unwrap();
            let response = protocol
                .handle("main", reconciliation_request(receipts, "opaque", ""))
                .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                reconciliation_body(&response),
                json!({"code":"unauthenticated"})
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn reconciliation_errors_are_redacted_and_responses_are_bounded() {
        for receipts in [false, true] {
            for service in [
                ReconciliationService {
                    error: Some(AppError::NotVisible),
                    ..Default::default()
                },
                ReconciliationService {
                    error: Some(AppError::RequestConflict { resource: "run" }),
                    ..Default::default()
                },
                ReconciliationService {
                    error: Some(AppError::DependencyUnavailable {
                        dependency: "secret-sentinel",
                    }),
                    ..Default::default()
                },
                ReconciliationService {
                    wrong_reply: true,
                    ..Default::default()
                },
                ReconciliationService {
                    oversized: true,
                    ..Default::default()
                },
            ] {
                let (status, code) = service
                    .error
                    .as_ref()
                    .map_or((503, "dependency_unavailable"), |error| {
                        (error.http_status(), error.code().as_str())
                    });
                let (protocol, root) = reconciliation_protocol(Arc::new(service));
                let response = protocol
                    .handle("main", reconciliation_request(receipts, "opaque", ""))
                    .await;
                assert_eq!(response.status().as_u16(), status);
                assert_eq!(reconciliation_body(&response), json!({"code":code}));
                protocol.unbind_window("main").unwrap();
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn reconciliation_rechecks_original_binding_before_and_after_application_await() {
        for receipts in [false, true] {
            for rebind in [false, true] {
                for application_error in [false, true] {
                    let entered = Arc::new(tokio::sync::Notify::new());
                    let release = Arc::new(tokio::sync::Notify::new());
                    let service = Arc::new(ReconciliationService {
                        barrier: Some((entered.clone(), release.clone())),
                        error: application_error.then_some(AppError::NotVisible),
                        ..Default::default()
                    });
                    let (protocol, root) = reconciliation_protocol(service.clone());
                    let old_authority = protocol.authority("main").unwrap().unwrap();
                    let reading = protocol.clone();
                    let task = tokio::spawn(async move {
                        reading
                            .handle("main", reconciliation_request(receipts, "opaque", ""))
                            .await
                    });
                    tokio::time::timeout(Duration::from_secs(2), entered.notified())
                        .await
                        .unwrap();
                    protocol.unbind_window("main").unwrap();
                    if rebind {
                        protocol.bind_window("main", admin_auth(), None).unwrap();
                    }
                    release.notify_one();
                    let response = tokio::time::timeout(Duration::from_secs(2), task)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                    assert_eq!(
                        reconciliation_body(&response),
                        json!({"code":"unauthenticated"})
                    );
                    // A previously captured authority cannot dispatch after its binding was removed.
                    let response = protocol
                        .run_reconciliation(
                            "main",
                            reconciliation_request(receipts, "opaque", ""),
                            old_authority,
                            "550e8400-e29b-81d4-a716-446655440001",
                            "opaque",
                            if receipts {
                                ReconciliationRead::Receipts
                            } else {
                                ReconciliationRead::Attempts
                            },
                        )
                        .await;
                    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                    assert_eq!(
                        reconciliation_body(&response),
                        json!({"code":"unauthenticated"})
                    );
                    assert_eq!(service.calls.lock().unwrap().len(), 1);
                    if rebind {
                        protocol.unbind_window("main").unwrap();
                    }
                    fs::remove_dir_all(root).unwrap();
                }
            }
        }
    }

    #[derive(Clone)]
    struct FakeChannelRuntime {
        inner: Arc<FakeChannelRuntimeInner>,
    }

    struct FakeChannelRuntimeInner {
        channels: Mutex<Vec<ChannelDetail>>,
        threads: Mutex<Vec<ThreadId>>,
        runs: Mutex<BTreeMap<(ThreadId, RunId), FakePersistedRun>>,
        next_channel: AtomicU64,
        next_thread: AtomicU64,
    }

    #[derive(Clone)]
    struct FakePersistedRun {
        command: BeginThreadRun,
        receipt: ThreadRunStarted,
        cancelled: bool,
    }

    impl FakeChannelRuntime {
        fn new() -> Self {
            let thread_id = ThreadId::new("550e8400-e29b-81d4-a716-446655440001");
            Self {
                inner: Arc::new(FakeChannelRuntimeInner {
                    channels: Mutex::new(vec![ChannelDetail {
                        id: ChannelId::new("channel-one"),
                        name: "Agent One".to_owned(),
                        agent_ids: vec![BotId::new("agent-one")],
                        thread_id: Some(thread_id.clone()),
                        active: true,
                    }]),
                    threads: Mutex::new(vec![thread_id]),
                    runs: Mutex::new(BTreeMap::new()),
                    next_channel: AtomicU64::new(1),
                    next_thread: AtomicU64::new(2),
                }),
            }
        }

        fn authorize_scope(
            deployment: &DeploymentId,
            tenant: &TenantId,
            actor: &ActorId,
        ) -> Result<(), ThreadDirectoryError> {
            if deployment.as_str() != "dep"
                || tenant.as_str() != "tenant"
                || actor.as_str() != "actor"
            {
                return Err(ThreadDirectoryError::NotVisible);
            }
            Ok(())
        }

        fn thread_id(sequence: u64) -> ThreadId {
            ThreadId::new(format!("550e8400-e29b-81d4-a716-{sequence:012x}"))
        }

        fn summary(detail: &ChannelDetail) -> ChannelSummary {
            ChannelSummary {
                id: detail.id.clone(),
                name: detail.name.clone(),
                agent_ids: detail.agent_ids.clone(),
                last_message: None,
                last_message_at: None,
                last_message_agent_id: None,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                thread_id: detail.thread_id.clone(),
                active: detail.active,
            }
        }
    }

    #[async_trait]
    impl ChannelReader for FakeChannelRuntime {
        async fn list_visible_channels(
            &self,
            actor: &ActorId,
            limit: u32,
            cursor: Option<ChannelCursor>,
        ) -> Result<Vec<ChannelSummary>, PortError> {
            if actor.as_str() != "actor" {
                return Err(PortError::Unavailable {
                    dependency: "fixture_channels",
                });
            }
            if cursor.is_some() {
                return Ok(Vec::new());
            }
            Ok(self
                .inner
                .channels
                .lock()
                .unwrap()
                .iter()
                .take(limit as usize)
                .map(Self::summary)
                .collect())
        }

        async fn get_visible_channel(
            &self,
            scope: &ChannelReadScope,
            channel_id: &ChannelId,
        ) -> Result<Option<ChannelSummary>, PortError> {
            if scope.deployment.as_str() != "dep"
                || scope.tenant.as_str() != "tenant"
                || scope.actor.as_str() != "actor"
            {
                return Err(PortError::Unavailable {
                    dependency: "fixture_channels",
                });
            }
            Ok(self
                .inner
                .channels
                .lock()
                .unwrap()
                .iter()
                .find(|channel| &channel.id == channel_id)
                .map(Self::summary))
        }
    }

    #[async_trait]
    impl ChannelAdministration for FakeChannelRuntime {
        async fn create_channel(
            &self,
            request: ChannelCreateRequest,
        ) -> Result<ChannelDetail, ChannelAdministrationError> {
            if request.scope.deployment.as_str() != "dep"
                || request.scope.tenant.as_str() != "tenant"
                || request.scope.actor.as_str() != "actor"
            {
                return Err(ChannelAdministrationError::NotVisible);
            }
            let sequence = self.inner.next_channel.fetch_add(1, Ordering::SeqCst);
            let thread_id = Self::thread_id(self.inner.next_thread.fetch_add(1, Ordering::SeqCst));
            let channel = ChannelDetail {
                id: ChannelId::new(format!("desktop-channel-{sequence}")),
                name: request
                    .agent_ids
                    .iter()
                    .map(BotId::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                agent_ids: request.agent_ids,
                thread_id: Some(thread_id.clone()),
                active: true,
            };
            self.inner.threads.lock().unwrap().push(thread_id);
            self.inner.channels.lock().unwrap().push(channel.clone());
            Ok(channel)
        }
    }

    #[async_trait]
    impl ThreadDirectory for FakeChannelRuntime {
        async fn mint_thread_id(
            &self,
            deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            if deployment.as_str() != "dep" {
                return Err(ThreadDirectoryError::NotVisible);
            }
            let thread_id = Self::thread_id(self.inner.next_thread.fetch_add(1, Ordering::SeqCst));
            self.inner.threads.lock().unwrap().push(thread_id.clone());
            Ok(thread_id)
        }

        async fn thread_known(
            &self,
            deployment: &DeploymentId,
            tenant: &TenantId,
            actor: &ActorId,
            thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Self::authorize_scope(deployment, tenant, actor)?;
            Ok(self.inner.threads.lock().unwrap().contains(thread))
        }

        async fn begin_thread_run(
            &self,
            request: BeginThreadRunRequest,
        ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
            Self::authorize_scope(&request.deployment, &request.tenant, &request.actor)?;
            if !self
                .inner
                .threads
                .lock()
                .unwrap()
                .contains(&request.command.thread_id)
            {
                return Err(ThreadDirectoryError::NotVisible);
            }
            if let ThreadRunAnchor::Channel { channel_id } = &request.command.anchor {
                let channel_matches = self.inner.channels.lock().unwrap().iter().any(|channel| {
                    &channel.id == channel_id
                        && channel.thread_id.as_ref() == Some(&request.command.thread_id)
                        && channel.agent_ids.contains(&request.command.bot_id)
                });
                if !channel_matches {
                    return Err(ThreadDirectoryError::NotVisible);
                }
            }
            let key = (
                request.command.thread_id.clone(),
                request.command.run_id.clone(),
            );
            let mut runs = self.inner.runs.lock().unwrap();
            if let Some(existing) = runs.get(&key) {
                if existing.command != request.command {
                    return Err(ThreadDirectoryError::RequestConflict);
                }
                let mut replayed = existing.receipt.clone();
                replayed.replayed = true;
                return Ok(replayed);
            }
            let receipt = ThreadRunStarted {
                thread_id: request.command.thread_id.clone(),
                run_id: request.command.run_id.clone(),
                message_sequence: 1,
                event_sequence: 1,
                replayed: false,
            };
            runs.insert(
                key,
                FakePersistedRun {
                    command: request.command,
                    receipt: receipt.clone(),
                    cancelled: false,
                },
            );
            Ok(receipt)
        }

        async fn cancel_thread_run(
            &self,
            request: CancelThreadRunRequest,
        ) -> Result<ThreadRunCancellation, ThreadDirectoryError> {
            Self::authorize_scope(&request.deployment, &request.tenant, &request.actor)?;
            let key = (
                request.command.thread_id.clone(),
                request.command.run_id.clone(),
            );
            let mut runs = self.inner.runs.lock().unwrap();
            let run = runs.get_mut(&key).ok_or(ThreadDirectoryError::NotVisible)?;
            let state = if run.cancelled {
                ThreadRunCancellationState::AlreadyRequested
            } else {
                run.cancelled = true;
                ThreadRunCancellationState::Requested
            };
            Ok(ThreadRunCancellation {
                thread_id: request.command.thread_id,
                run_id: request.command.run_id,
                state,
            })
        }

        async fn thread_conversation(
            &self,
            request: ThreadConversationRequest,
        ) -> Result<ThreadConversationSnapshot, ThreadDirectoryError> {
            Self::authorize_scope(&request.deployment, &request.tenant, &request.actor)?;
            let runs = self.inner.runs.lock().unwrap();
            let run = runs
                .values()
                .find(|run| run.command.thread_id == request.thread);
            Ok(run.map_or_else(ThreadConversationSnapshot::default, |run| {
                ThreadConversationSnapshot {
                    messages: Vec::new(),
                    active_run_id: Some(run.command.run_id.clone()),
                    active_run_state: Some(if run.cancelled {
                        ThreadForegroundRunState::Cancelling
                    } else {
                        ThreadForegroundRunState::Running
                    }),
                    active_run_cancellable: !run.cancelled,
                    active_run_text: String::new(),
                    last_event_sequence: Some(run.receipt.event_sequence),
                }
            }))
        }
    }

    struct FakeRouting;

    #[async_trait]
    impl ChannelRoutingBackend for FakeRouting {
        async fn complete(&self, _prompt: &str) -> Result<String, ChannelRoutingBackendError> {
            Ok(r#"{"agentId":"agent-one","reason":"fixture","confidence":1.0}"#.to_owned())
        }

        async fn reachable_systems(
            &self,
            agents: &[BotId],
        ) -> Result<Vec<AgentReachability>, ChannelRoutingBackendError> {
            Ok(agents
                .iter()
                .cloned()
                .map(|agent_id| AgentReachability {
                    agent_id,
                    systems: Vec::new(),
                })
                .collect())
        }

        async fn record_routing(
            &self,
            _record: RoutingAuditRecord,
        ) -> Result<(), ChannelRoutingBackendError> {
            Ok(())
        }
    }

    struct FakeAgents {
        rows: Mutex<Vec<AgentProfile>>,
        next: AtomicU64,
        callback_sequence: AtomicU64,
    }

    impl FakeAgents {
        fn new() -> Self {
            Self {
                rows: Mutex::new(vec![AgentProfile {
                    id: BotId::new("agent-one"),
                    name: "Agent One".to_owned(),
                    title: "First Agent".to_owned(),
                    role_description: "Existing standing role".to_owned(),
                    avatar_seed: "agent-one".to_owned(),
                    visibility: AgentVisibility::Public,
                    endpoint: Some("https://agent.example/ag-ui".to_owned()),
                    has_auth: false,
                    has_callback_token: false,
                    hidden: false,
                    system_owned: false,
                    can_manage: true,
                    mine: true,
                }]),
                next: AtomicU64::new(1),
                callback_sequence: AtomicU64::new(1),
            }
        }

        fn authorize(scope: &AgentAdministrationScope) -> Result<(), AgentAdministrationError> {
            if scope.tenant != TenantId::new("tenant")
                || scope.actor != ActorId::new("actor")
                || scope.auth_generation != AuthGeneration::new(1)
            {
                return Err(AgentAdministrationError::Forbidden);
            }
            Ok(())
        }
    }

    #[async_trait]
    impl AgentDirectory for FakeAgents {
        async fn list_visible_agents(
            &self,
            scope: &AgentReadScope,
            hidden: bool,
        ) -> Result<Vec<AgentProfile>, PortError> {
            if scope.tenant != TenantId::new("tenant") || scope.actor != ActorId::new("actor") {
                return Err(PortError::Unavailable {
                    dependency: "fixture_agents",
                });
            }
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|profile| profile.hidden == hidden)
                .cloned()
                .collect())
        }

        async fn get_visible_agent(
            &self,
            scope: &AgentReadScope,
            agent_id: &BotId,
        ) -> Result<Option<AgentProfile>, PortError> {
            if scope.tenant != TenantId::new("tenant") || scope.actor != ActorId::new("actor") {
                return Err(PortError::Unavailable {
                    dependency: "fixture_agents",
                });
            }
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|profile| &profile.id == agent_id)
                .cloned())
        }
    }

    #[async_trait]
    impl AgentAdministration for FakeAgents {
        async fn create_agent(
            &self,
            scope: &AgentAdministrationScope,
            request: AgentMutationRequest,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            Self::authorize(scope)?;
            let sequence = self.next.fetch_add(1, Ordering::SeqCst);
            let profile = AgentProfile {
                id: BotId::new(format!("desktop-agent-{sequence}")),
                name: request.name,
                title: request.title,
                role_description: request.role_description,
                avatar_seed: format!("desktop-agent-{sequence}"),
                visibility: request.visibility,
                endpoint: request.endpoint,
                has_auth: request.auth.is_some(),
                has_callback_token: false,
                hidden: false,
                system_owned: false,
                can_manage: true,
                mine: true,
            };
            self.rows.lock().unwrap().push(profile.clone());
            Ok(profile)
        }

        async fn update_agent(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
            request: AgentMutationRequest,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            Self::authorize(scope)?;
            let mut rows = self.rows.lock().unwrap();
            let profile = rows
                .iter_mut()
                .find(|profile| &profile.id == agent_id)
                .ok_or(AgentAdministrationError::NotVisible)?;
            profile.name = request.name;
            profile.title = request.title;
            profile.role_description = request.role_description;
            profile.visibility = request.visibility;
            profile.endpoint = request.endpoint;
            if request.auth.is_some() {
                profile.has_auth = true;
            }
            if profile.endpoint.is_none() {
                profile.has_auth = false;
                profile.has_callback_token = false;
            }
            Ok(profile.clone())
        }

        async fn duplicate_agent(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            Self::authorize(scope)?;
            let mut rows = self.rows.lock().unwrap();
            let source = rows
                .iter()
                .find(|profile| &profile.id == agent_id)
                .cloned()
                .ok_or(AgentAdministrationError::NotVisible)?;
            let sequence = self.next.fetch_add(1, Ordering::SeqCst);
            let copy = AgentProfile {
                id: BotId::new(format!("desktop-agent-{sequence}")),
                name: source.name,
                title: source.title,
                role_description: source.role_description,
                avatar_seed: source.avatar_seed,
                visibility: AgentVisibility::Private,
                endpoint: None,
                has_auth: false,
                has_callback_token: false,
                hidden: false,
                system_owned: false,
                can_manage: true,
                mine: true,
            };
            rows.push(copy.clone());
            Ok(copy)
        }

        async fn set_agent_hidden(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
            hidden: bool,
        ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
            Self::authorize(scope)?;
            let mut rows = self.rows.lock().unwrap();
            let profile = rows
                .iter_mut()
                .find(|profile| &profile.id == agent_id)
                .ok_or(AgentAdministrationError::NotVisible)?;
            profile.hidden = hidden;
            Ok(AgentLifecycleReceipt {
                agent_id: agent_id.clone(),
                state: if hidden {
                    AgentLifecycleState::Hidden
                } else {
                    AgentLifecycleState::Visible
                },
            })
        }

        async fn delete_agent(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
        ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
            Self::authorize(scope)?;
            let mut rows = self.rows.lock().unwrap();
            let index = rows
                .iter()
                .position(|profile| &profile.id == agent_id)
                .ok_or(AgentAdministrationError::NotVisible)?;
            rows.remove(index);
            Ok(AgentLifecycleReceipt {
                agent_id: agent_id.clone(),
                state: AgentLifecycleState::Deleted,
            })
        }

        async fn test_agent_connection(
            &self,
            scope: &AgentAdministrationScope,
            _request: AgentConnectionTestRequest,
        ) -> Result<AgentConnectionVerdict, AgentAdministrationError> {
            Self::authorize(scope)?;
            Ok(AgentConnectionVerdict::working(vec![
                "RUN_STARTED".to_owned(),
            ]))
        }
    }

    struct FakeCallbackTokens(Arc<FakeAgents>);

    #[async_trait]
    impl AgentCallbackTokenAdministration for FakeCallbackTokens {
        async fn issue(
            &self,
            auth: &AuthContext,
            agent: &BotId,
        ) -> Result<CallbackTokenIssued, AgentCallbackTokenError> {
            if auth.tenant() != &TenantId::new("tenant")
                || auth.actor() != &ActorId::new("actor")
                || auth.auth_generation() != AuthGeneration::new(1)
            {
                return Err(AgentCallbackTokenError::NotVisible);
            }
            let mut rows = self.0.rows.lock().unwrap();
            let profile = rows
                .iter_mut()
                .find(|profile| &profile.id == agent && profile.endpoint.is_some())
                .ok_or(AgentCallbackTokenError::NotVisible)?;
            profile.has_callback_token = true;
            let sequence = self.0.callback_sequence.fetch_add(1, Ordering::SeqCst);
            CallbackTokenIssued::new(format!("obot_agt_DESKTOP_CALLBACK_{sequence:032}"))
                .map_err(|_| AgentCallbackTokenError::Corrupt { field: "token" })
        }

        async fn revoke(
            &self,
            auth: &AuthContext,
            agent: &BotId,
        ) -> Result<CallbackTokenRevoked, AgentCallbackTokenError> {
            if auth.tenant() != &TenantId::new("tenant")
                || auth.actor() != &ActorId::new("actor")
                || auth.auth_generation() != AuthGeneration::new(1)
            {
                return Err(AgentCallbackTokenError::NotVisible);
            }
            let mut rows = self.0.rows.lock().unwrap();
            let profile = rows
                .iter_mut()
                .find(|profile| &profile.id == agent && profile.endpoint.is_some())
                .ok_or(AgentCallbackTokenError::NotVisible)?;
            profile.has_callback_token = false;
            Ok(CallbackTokenRevoked)
        }
    }

    struct FakePeople;

    #[async_trait]
    impl PeopleAdministration for FakePeople {
        async fn current_user(&self, actor: &ActorId) -> Result<CurrentUser, PeoplePortError> {
            Ok(CurrentUser {
                id: actor.clone(),
                email: "desktop@example.test".to_owned(),
                name: Some("Desktop User".to_owned()),
                image: None,
                role: Role::Admin,
            })
        }

        async fn list_people(
            &self,
            _request: PeoplePageRequest,
        ) -> Result<PeoplePage, PeoplePortError> {
            Err(PeoplePortError::Unavailable)
        }

        async fn change_role(
            &self,
            _actor: &ActorId,
            _subject: &ActorId,
            _desired: Role,
        ) -> Result<Person, PeoplePortError> {
            Err(PeoplePortError::Unavailable)
        }

        async fn change_access(
            &self,
            _actor: &ActorId,
            _subject: &ActorId,
            _revoked: bool,
        ) -> Result<Person, PeoplePortError> {
            Err(PeoplePortError::Unavailable)
        }
    }

    struct FakePreferences(Mutex<UiPreferences>);

    /// Synthetic authoritative port: this fixture makes no PostgreSQL coverage claim.
    struct FirstFramePreferenceAuthority {
        reply: Mutex<Result<UiPreferences, UiPreferenceAdministrationError>>,
        reads: AtomicU64,
        writes: AtomicU64,
    }

    #[async_trait]
    impl UiPreferenceAdministration for FirstFramePreferenceAuthority {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            *self.reply.lock().unwrap()
        }

        async fn update(
            &self,
            _auth: &AuthContext,
            _update: UpdateUiPreferences,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Err(UiPreferenceAdministrationError::Unavailable)
        }
    }

    #[async_trait]
    impl UiPreferenceAdministration for FakePreferences {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            Ok(*self.0.lock().unwrap())
        }

        async fn update(
            &self,
            _auth: &AuthContext,
            update: UpdateUiPreferences,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            let mut stored = self.0.lock().unwrap();
            let revision = match stored.revision {
                Some(current) if update.expected_revision != Some(current) => {
                    return Err(UiPreferenceAdministrationError::StaleSnapshot(
                        stored.revision_snapshot().unwrap(),
                    ));
                }
                Some(current) => current
                    .checked_add(1)
                    .ok_or(UiPreferenceAdministrationError::Corrupt { field: "revision" })?,
                None if update.expected_revision.is_some() => {
                    return Err(UiPreferenceAdministrationError::NotVisible);
                }
                None => 1,
            };
            stored.theme = update.theme.or(stored.theme);
            stored.locale = update.locale.or(stored.locale);
            stored.revision = Some(revision);
            stored.updated_at = Some(time::OffsetDateTime::UNIX_EPOCH);
            Ok(*stored)
        }
    }

    struct FakeRunCostBudgets(Mutex<Option<RunCostCap>>);

    #[derive(Default)]
    struct FakeMcpConnections {
        reads: Mutex<Vec<ActorId>>,
        additions: Mutex<Vec<(ActorId, String)>>,
    }

    #[async_trait]
    impl McpConnectionAdministration for FakeMcpConnections {
        async fn list_connections(
            &self,
            auth: &AuthContext,
        ) -> Result<McpConnections, McpConnectionError> {
            self.reads.lock().unwrap().push(auth.actor().clone());
            Ok(McpConnections {
                available_server_ids: vec![format!("notes-{}", auth.actor().as_str())],
                connections: Vec::new(),
                redirect_uri: None,
            })
        }

        async fn add_curated_server(
            &self,
            auth: &AuthContext,
            key: &str,
        ) -> Result<McpServerMutation, McpConnectionError> {
            self.additions
                .lock()
                .unwrap()
                .push((auth.actor().clone(), key.to_owned()));
            if key != "google-drive" {
                return Err(McpConnectionError::NotVisible);
            }
            Ok(McpServerMutation {
                server_id: key.to_owned(),
                catalog_generation: 1,
                tool_count: 4,
                suspended_grants: 0,
            })
        }

        async fn list_admin_page(
            &self,
            _auth: &AuthContext,
        ) -> Result<McpAdminPage, McpConnectionError> {
            Ok(McpAdminPage {
                catalogue: vec![McpAdminCatalogueEntry {
                    key: "google-drive".to_owned(),
                    title: "Google Drive".to_owned(),
                    vendor: "Google".to_owned(),
                    summary: "Files".to_owned(),
                    docs_url: "https://developers.google.com/".to_owned(),
                    auth: McpAdminAuthentication::UserOAuth,
                    per_instance: false,
                }],
                bots_may_call_back: false,
                servers: Vec::new(),
                skills: Vec::new(),
                redirect_uri: None,
            })
        }

        async fn begin_oauth(
            &self,
            _auth: &AuthContext,
            _server_id: &str,
            _return_to: McpOAuthReturnTo,
        ) -> Result<McpOAuthAuthorization, McpConnectionError> {
            Err(McpConnectionError::Unavailable)
        }

        async fn disconnect(
            &self,
            _auth: &AuthContext,
            _server_id: &str,
        ) -> Result<McpConnectionDisconnected, McpConnectionError> {
            Err(McpConnectionError::Unavailable)
        }

        async fn register_oauth_client(
            &self,
            _auth: &AuthContext,
            _server_id: &str,
            _registration: &McpOAuthClientRegistration,
        ) -> Result<McpOAuthClientRegistered, McpConnectionError> {
            Err(McpConnectionError::Unavailable)
        }

        async fn add_custom_server(
            &self,
            _auth: &AuthContext,
            registration: &McpCustomServerRegistration,
        ) -> Result<McpServerMutation, McpConnectionError> {
            Ok(McpServerMutation {
                server_id: registration.id.clone(),
                catalog_generation: 1,
                tool_count: 1,
                suspended_grants: 0,
            })
        }

        async fn remove_server(
            &self,
            _auth: &AuthContext,
            _server_id: &str,
        ) -> Result<McpServerRemoved, McpConnectionError> {
            Ok(McpServerRemoved::success())
        }

        async fn refresh_server(
            &self,
            _auth: &AuthContext,
            server_id: &str,
        ) -> Result<McpServerMutation, McpConnectionError> {
            Ok(McpServerMutation {
                server_id: server_id.to_owned(),
                catalog_generation: 2,
                tool_count: 1,
                suspended_grants: 0,
            })
        }

        async fn save_skill(
            &self,
            auth: &AuthContext,
            mutation: &PluginSkillMutation,
        ) -> Result<PluginSkills, McpConnectionError> {
            let skill = openbot_contracts::mcp::McpAdminSkill {
                id: mutation.slug.clone(),
                slug: mutation.slug.clone(),
                owner_user_id: (!mutation.deployment_wide)
                    .then(|| auth.actor().as_str().to_owned()),
                title: mutation.title.clone(),
                summary: mutation.summary.clone(),
                instructions: mutation.instructions.clone(),
                origin: "yours".into(),
                installed_by: None,
                revision: mutation.expected_revision.map_or(1, |r| r + 1),
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
                granted_to: Vec::new(),
            };
            if mutation.expected_revision == Some(9) {
                return Err(McpConnectionError::StaleSnapshot(
                    skill.revision_snapshot().unwrap(),
                ));
            }
            Ok(PluginSkills {
                skills: vec![skill],
            })
        }

        async fn remove_skill(
            &self,
            _auth: &AuthContext,
            slug: &str,
            expected_revision: i64,
        ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
            if expected_revision == 9 {
                return Err(McpConnectionError::StaleSnapshot(
                    openbot_contracts::revision::RevisionSnapshot::from_public(
                        10,
                        time::OffsetDateTime::UNIX_EPOCH,
                        &serde_json::json!({"slug": slug, "revision": 10}),
                    )
                    .unwrap(),
                ));
            }
            Ok(PluginMutationAcknowledged::success())
        }

        async fn set_grant(
            &self,
            _auth: &AuthContext,
            _mutation: &PluginGrantMutation,
            _enabled: bool,
        ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
            Ok(PluginMutationAcknowledged::success())
        }

        async fn list_for_agent(
            &self,
            _auth: &AuthContext,
            _agent_id: &BotId,
        ) -> Result<GrantedPlugins, McpConnectionError> {
            Ok(GrantedPlugins {
                tools: Vec::new(),
                skills: Vec::new(),
            })
        }
    }

    struct FakeRemoteInterrupts;

    #[async_trait]
    impl RemoteInterruptCoordinator for FakeRemoteInterrupts {
        async fn list_pending(
            &self,
            _auth: &AuthContext,
        ) -> Result<Vec<RemoteInterruptPending>, RemoteInterruptError> {
            Ok(vec![RemoteInterruptPending::new(
                RemoteInterruptPendingInput {
                    request_id: "018f6f8a-5f4b-7c2d-8a31-111111111111".to_owned(),
                    run_id: "desktop-run".to_owned(),
                    bot_id: "desktop-agent-1".to_owned(),
                    protocol_run_id: "desktop-run".to_owned(),
                    interrupt_id: "remote-1".to_owned(),
                    untrusted_payload: json!({
                        "id":"remote-1","reason":"confirmation","message":"Remote asks"
                    }),
                    requested_at: time::OffsetDateTime::UNIX_EPOCH,
                    expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30),
                },
            )?])
        }

        async fn resolve(
            &self,
            _auth: &AuthContext,
            request_id: &str,
            status: ProviderRemoteResumeStatus,
            _payload: Option<serde_json::Value>,
        ) -> Result<RemoteInterruptResolutionReceipt, RemoteInterruptError> {
            RemoteInterruptResolutionReceipt::new(request_id.to_owned(), status, false)
        }

        async fn persist_and_wait(
            &self,
            _lease: &RunExecutionLease,
            _batch: &ProviderRemoteInterruptBatch,
        ) -> Result<ProviderRemoteResume, RemoteInterruptError> {
            Err(RemoteInterruptError::Unavailable)
        }
    }

    #[async_trait]
    impl RunCostBudgetAdministration for FakeRunCostBudgets {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
            Ok(self.0.lock().unwrap().clone())
        }

        async fn replace(
            &self,
            _auth: &AuthContext,
            cap: Option<RunCostCap>,
        ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
            *self.0.lock().unwrap() = cap.clone();
            Ok(cap)
        }
    }

    struct FakeApprovals;

    struct FakeComponents;

    struct FakeSandboxed;

    #[async_trait]
    impl SandboxedComponentAdministration for FakeSandboxed {
        async fn list_sandboxed_components(
            &self,
            auth: &AuthContext,
        ) -> Result<SandboxedComponents, SandboxedComponentAdministrationError> {
            Ok(SandboxedComponents {
                components: vec![sandboxed_draft_record(auth.actor().as_str())],
            })
        }

        async fn list_published_sandboxed_components(
            &self,
            _auth: &AuthContext,
        ) -> Result<PublishedSandboxedComponents, SandboxedComponentAdministrationError> {
            Ok(PublishedSandboxedComponents {
                components: vec![PublishedSandboxedComponent {
                    name: "custom_delivery_eta".to_owned(),
                    html: "<p>ETA</p>".to_owned(),
                    css: "p{}".to_owned(),
                    js_functions: "function draw(){}".to_owned(),
                    argument_schema: BTreeMap::new(),
                }],
            })
        }

        async fn save_sandboxed_component(
            &self,
            auth: &AuthContext,
            draft: &SandboxedComponentDraft,
        ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
            Ok(SandboxedComponentRecord {
                editing_revision: 1,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
                name: draft.name.clone(),
                title: draft.title.clone(),
                draft_description: draft.description.clone(),
                draft_html: draft.html.clone(),
                draft_css: draft.css.clone(),
                draft_js_functions: draft.js_functions.clone(),
                draft_argument_schema: draft.argument_schema.clone(),
                published_html: None,
                published_css: None,
                published_js_functions: None,
                published_argument_schema: None,
                sample_arguments: draft.sample_arguments.clone(),
                revision: 0,
                published: false,
                published_at: None,
                authored_by: Some(auth.actor().as_str().to_owned()),
                has_unpublished_changes: false,
            })
        }

        async fn publish_sandboxed_component(
            &self,
            auth: &AuthContext,
            _component_name: &str,
            expected_revision: i64,
        ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
            let mut record = sandboxed_draft_record(auth.actor().as_str());
            record.published_html = Some(record.draft_html.clone());
            record.published_css = Some(record.draft_css.clone());
            record.published_js_functions = Some(record.draft_js_functions.clone());
            record.published_argument_schema = Some(record.draft_argument_schema.clone());
            if expected_revision != record.editing_revision {
                return Err(SandboxedComponentAdministrationError::StaleSnapshot(
                    openbot_contracts::revision::RevisionSnapshot::from_public(
                        record.editing_revision,
                        record.updated_at,
                        &record,
                    )
                    .unwrap(),
                ));
            }
            record.editing_revision = 2;
            record.revision = 1;
            record.published = true;
            record.published_at = Some(time::OffsetDateTime::UNIX_EPOCH);
            Ok(record)
        }

        async fn delete_sandboxed_component(
            &self,
            _auth: &AuthContext,
            _component_name: &str,
            _expected_revision: i64,
        ) -> Result<(), SandboxedComponentAdministrationError> {
            Ok(())
        }
    }

    fn sandboxed_draft_record(actor: &str) -> SandboxedComponentRecord {
        SandboxedComponentRecord {
            editing_revision: 1,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            name: "custom_delivery_eta".to_owned(),
            title: "Delivery ETA".to_owned(),
            draft_description: "Delivery estimate".to_owned(),
            draft_html: "<p>ETA</p>".to_owned(),
            draft_css: "p{}".to_owned(),
            draft_js_functions: "function draw(){}".to_owned(),
            draft_argument_schema: BTreeMap::new(),
            published_html: None,
            published_css: None,
            published_js_functions: None,
            published_argument_schema: None,
            sample_arguments: BTreeMap::new(),
            revision: 0,
            published: false,
            published_at: None,
            authored_by: Some(actor.to_owned()),
            has_unpublished_changes: false,
        }
    }

    #[async_trait]
    impl ComponentAdministration for FakeComponents {
        async fn list_components(
            &self,
            _auth: &AuthContext,
        ) -> Result<ComponentRecords, ComponentAdministrationError> {
            Ok(ComponentRecords::default())
        }

        async fn sync_catalogue(
            &self,
            _auth: &AuthContext,
            entries: &[CompiledComponentManifestEntry],
        ) -> Result<ComponentCatalogueAdded, ComponentAdministrationError> {
            Ok(ComponentCatalogueAdded {
                added: entries.iter().map(|entry| entry.name.clone()).collect(),
            })
        }

        async fn update_component_governance(
            &self,
            auth: &AuthContext,
            mutation: &ComponentGovernanceMutation,
        ) -> Result<ComponentRecord, ComponentAdministrationError> {
            let mut component = ComponentRecord {
                name: mutation.component_name().to_owned(),
                title: "Quotation".to_owned(),
                kind: openbot_contracts::components::CompiledComponentKind::Card,
                draft_description: "quote".to_owned(),
                published_description: Some("quote".to_owned()),
                published: true,
                published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
                updated_by: Some(auth.actor().as_str().to_owned()),
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
                has_unpublished_changes: false,
                withheld_from: Vec::new(),
                functions: Vec::new(),
            };
            match mutation {
                ComponentGovernanceMutation::SetAgentGrant {
                    agent_id, granted, ..
                } if !granted => component.withheld_from.push(agent_id.as_str().to_owned()),
                ComponentGovernanceMutation::SetFunctionGrant {
                    function, granted, ..
                } if *granted => component.functions.push(function.clone()),
                ComponentGovernanceMutation::SetPublication { published, .. } => {
                    component.published = *published;
                }
                ComponentGovernanceMutation::SaveDraft { description, .. } => {
                    component.draft_description = description.clone();
                    component.has_unpublished_changes = true;
                }
                _ => {}
            }
            Ok(component)
        }

        async fn list_components_for_agent(
            &self,
            _scope: &ComponentRuntimeScope,
            _renderer_names: &[String],
        ) -> Result<GrantedCompiledComponents, ComponentAdministrationError> {
            Ok(GrantedCompiledComponents {
                components: vec![GrantedCompiledComponent {
                    name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                    description: "published quote".to_owned(),
                }],
            })
        }

        async fn decide_component(
            &self,
            _scope: &ComponentRuntimeScope,
            _component_name: &str,
            _build_has_renderer: bool,
            _functions: &[String],
        ) -> Result<ComponentDecision, ComponentAdministrationError> {
            Ok(ComponentDecision::allowed())
        }

        async fn call_component_function(
            &self,
            _scope: &ComponentRuntimeScope,
            _component_name: &str,
            _build_has_renderer: bool,
            plan: &ComponentFunctionCallPlan,
        ) -> Result<ComponentFunctionCall, ComponentAdministrationError> {
            let days = match plan.arguments {
                Some(ComponentFunctionArguments::BotActivity { days }) => days,
                _ => return Err(ComponentAdministrationError::Corrupt { field: "arguments" }),
            };
            Ok(ComponentFunctionCall::succeeded(
                ComponentFunctionData::BotActivity(BotActivityReport {
                    days,
                    rows: Vec::new(),
                }),
            ))
        }

        async fn list_component_human_decisions(
            &self,
            _auth: &AuthContext,
        ) -> Result<PendingComponentHumanDecisions, ComponentAdministrationError> {
            Ok(PendingComponentHumanDecisions::default())
        }

        async fn resolve_component_human_decision(
            &self,
            _auth: &AuthContext,
            decision_id: &str,
            answer: &ComponentHumanDecisionAnswer,
        ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
            Ok(ComponentHumanDecisionResolved {
                decision_id: decision_id.to_owned(),
                answer: answer.clone(),
                replayed: false,
            })
        }
    }

    #[async_trait]
    impl ToolApprovalAdministration for FakeApprovals {
        async fn list_pending(
            &self,
            _auth: &AuthContext,
        ) -> Result<PendingToolApprovals, ToolApprovalAdministrationError> {
            Ok(PendingToolApprovals {
                approvals: Vec::new(),
            })
        }

        async fn decide(
            &self,
            _auth: &AuthContext,
            approval_id: &str,
            decision: ToolApprovalDecision,
        ) -> Result<ToolApprovalResolved, ToolApprovalAdministrationError> {
            Ok(ToolApprovalResolved {
                approval_id: approval_id.to_owned(),
                decision,
            })
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            AuthGeneration::new(1),
            true,
        )
    }

    fn admin_auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("admin"),
            [Role::Admin],
            AuthGeneration::new(1),
            true,
        )
    }

    fn protocol_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "openbot-tauri-protocol-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("index.html"),
            "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>",
        )
        .unwrap();
        fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
        root
    }

    #[test]
    fn verified_assets_keep_checked_bytes_after_disk_replacement_and_deletion() {
        let (original, root) = protocol();
        let index = fs::read(root.join("index.html")).unwrap();
        let checked_js = fs::read(root.join("openbot-bootstrap.mjs")).unwrap();
        let mut files = BTreeMap::from([
            ("index.html".to_owned(), index.clone()),
            ("openbot-bootstrap.mjs".to_owned(), checked_js.clone()),
            ("large.wasm".to_owned(), vec![0x42; 9_501_967]),
        ]);
        let assets = VerifiedUiAssets::from_verified_release(files.clone()).unwrap();
        let checked =
            DesktopTauriProtocol::from_verified_assets(assets, Arc::clone(&original.transport));
        fs::write(root.join("openbot-bootstrap.mjs"), "unverified replacement").unwrap();
        fs::write(root.join("injected.js"), "unlisted").unwrap();
        assert_eq!(checked.asset("/openbot-bootstrap.mjs").body(), &checked_js);
        assert_eq!(
            checked.asset("/injected.js").status(),
            StatusCode::NOT_FOUND
        );
        fs::remove_dir_all(&root).unwrap();
        assert_eq!(checked.index.as_bytes(), index);
        assert_eq!(checked.asset("/openbot-bootstrap.mjs").body(), &checked_js);
        let wasm = checked.asset("/large.wasm");
        assert_eq!(wasm.status(), StatusCode::OK);
        assert_eq!(wasm.body().len(), 9_501_967);
        assert_eq!(wasm.headers()[CONTENT_TYPE], "application/wasm");
        assert_eq!(wasm.headers()[CONTENT_SECURITY_POLICY], CSP);
        assert_eq!(
            wasm.headers()[http::header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        files.insert("large.wasm".to_owned(), vec![0; 16 * 1024 * 1024 + 1]);
        assert!(VerifiedUiAssets::from_verified_release(files).is_err());
    }

    #[test]
    fn verified_image_mime_is_closed_and_non_wasm_budgets_stay_small() {
        let (original, root) = protocol();
        let mut files = BTreeMap::from([
            (
                "index.html".to_owned(),
                fs::read(root.join("index.html")).unwrap(),
            ),
            ("openbot-bootstrap.mjs".to_owned(), b"export {};".to_vec()),
        ]);
        for (path, _) in [
            ("brand/logo.png", "image/png"),
            ("brand/logo.gif", "image/gif"),
            ("brand/logo.svg", "image/svg+xml"),
        ] {
            files.insert(path.to_owned(), vec![1, 2, 3]);
        }
        files.insert("brand/provenance.json".to_owned(), b"{}".to_vec());
        let checked = DesktopTauriProtocol::from_verified_assets(
            VerifiedUiAssets::from_verified_release(files.clone()).unwrap(),
            Arc::clone(&original.transport),
        );
        for (path, mime) in [
            ("brand/logo.png", "image/png"),
            ("brand/logo.gif", "image/gif"),
            ("brand/logo.svg", "image/svg+xml"),
        ] {
            let response = checked.asset(&format!("/{path}"));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[CONTENT_TYPE], mime);
            assert_eq!(response.headers()[CONTENT_SECURITY_POLICY], CSP);
            assert_eq!(
                response.headers()[http::header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
        }
        for path in [
            "/brand/provenance.json",
            "/index.html",
            "/../openbot-bootstrap.mjs",
            "/%2e%2e/openbot-bootstrap.mjs",
        ] {
            assert_eq!(checked.asset(path).status(), StatusCode::NOT_FOUND);
        }
        files.insert("large.js".to_owned(), vec![0; 8 * 1024 * 1024 + 1]);
        assert!(VerifiedUiAssets::from_verified_release(files).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
    #[tokio::test]
    #[ignore = "explicit existing production dist and independent inventory; no GUI or PG"]
    async fn current_release_dist_verified_snapshot_serves_every_supported_asset() {
        let dist = PathBuf::from(
            std::env::var_os("WROK_BOT_UI_DIST_TEST_ROOT").expect("explicit existing dist"),
        );
        let inventory = fs::read(
            std::env::var_os("WROK_BOT_UI_INVENTORY_TEST_FILE")
                .expect("independent recorded inventory"),
        )
        .unwrap();
        let assets = crate::desktop_release::verified_ui_snapshot_for_test(&dist, &inventory);
        let expected = assets.files.clone();
        let expected_index = Arc::clone(&assets.index);
        let (original, temporary) = protocol();
        let checked =
            DesktopTauriProtocol::from_verified_assets(assets, Arc::clone(&original.transport));
        checked.bind_window("main", auth(), None).unwrap();
        let mut served = 0;
        let mut withheld = 0;
        let mut wasm_bytes = 0;
        for (relative, bytes) in &expected {
            let path = format!("/{relative}");
            let response = checked
                .handle(
                    "main",
                    Request::builder().uri(&path).body(Vec::new()).unwrap(),
                )
                .await;
            if closed_asset_path(&path).is_some() {
                assert_eq!(response.status(), StatusCode::OK, "{relative}");
                assert_eq!(response.body().as_slice(), bytes.as_ref(), "{relative}");
                assert_eq!(response.headers()[CONTENT_SECURITY_POLICY], CSP);
                assert_eq!(
                    response.headers()[http::header::X_CONTENT_TYPE_OPTIONS],
                    "nosniff"
                );
                served += 1;
                if relative.ends_with(".wasm") {
                    wasm_bytes += bytes.len();
                }
            } else {
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{relative}");
                assert!(response.body().is_empty(), "{relative}");
                withheld += 1;
            }
        }
        assert_eq!(checked.index, expected_index);
        let expected_html = expected_index.replacen(
            HTML_ROOT_MARKER,
            &index_root(UiTheme::Dark, UiLocale::ZhCn, cfg!(target_os = "macos")),
            1,
        );
        for path in ["/", "/index.html", "/settings"] {
            let response = checked
                .handle(
                    "main",
                    Request::builder().uri(path).body(Vec::new()).unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.body(), expected_html.as_bytes(), "{path}");
            assert_eq!(response.headers()[CONTENT_SECURITY_POLICY], CSP);
        }
        assert!(wasm_bytes > 8 * 1024 * 1024 && wasm_bytes <= 16 * 1024 * 1024);
        assert_eq!(
            checked
                .handle(
                    "main",
                    Request::builder()
                        .uri("/unlisted.js")
                        .body(Vec::new())
                        .unwrap(),
                )
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        println!(
            "verified_snapshot_dispatcher index=1 served={served} withheld={withheld} wasm_bytes={wasm_bytes}"
        );
        fs::remove_dir_all(temporary).unwrap();
    }

    #[tokio::test]
    async fn verified_inventory_materials_do_not_fall_back_to_spa() {
        let (original, root) = protocol();
        let mut files = BTreeMap::from([
            (
                "index.html".to_owned(),
                fs::read(root.join("index.html")).unwrap(),
            ),
            ("openbot-bootstrap.mjs".to_owned(), b"export {};".to_vec()),
        ]);
        let materials = [
            "brand/provenance.json",
            "notices/LICENSE.md",
            "notices/NOTICE",
            "notices/private.html",
        ];
        for relative in materials {
            files.insert(
                relative.to_owned(),
                b"non-public inventory material".to_vec(),
            );
        }
        let checked = DesktopTauriProtocol::from_verified_assets(
            VerifiedUiAssets::from_verified_release(files).unwrap(),
            Arc::clone(&original.transport),
        );
        checked.bind_window("main", auth(), None).unwrap();
        for relative in materials {
            let response = checked
                .handle(
                    "main",
                    Request::builder()
                        .uri(format!("/{relative}"))
                        .body(Vec::new())
                        .unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{relative}");
            assert!(response.body().is_empty(), "{relative}");
        }
        for path in ["/", "/index.html", "/settings", "/notices/route-not-a-file"] {
            let response = checked
                .handle(
                    "main",
                    Request::builder().uri(path).body(Vec::new()).unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[CONTENT_SECURITY_POLICY], CSP);
            assert!(
                std::str::from_utf8(response.body())
                    .unwrap()
                    .contains(&index_root(
                        UiTheme::Dark,
                        UiLocale::ZhCn,
                        cfg!(target_os = "macos")
                    )),
                "{path}"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    fn protocol() -> (Arc<DesktopTauriProtocol>, PathBuf) {
        protocol_with_mcp(Arc::new(FakeMcpConnections::default()))
    }

    fn protocol_with_mcp(
        mcp: Arc<dyn McpConnectionAdministration>,
    ) -> (Arc<DesktopTauriProtocol>, PathBuf) {
        protocol_with_admin_ports(
            mcp,
            Arc::new(openbot_application::credential_admin::NoCredentialAdministration),
        )
    }

    fn protocol_with_admin_ports(
        mcp: Arc<dyn McpConnectionAdministration>,
        credentials: Arc<dyn openbot_application::credential_admin::CredentialAdministration>,
    ) -> (Arc<DesktopTauriProtocol>, PathBuf) {
        let root = protocol_root();
        let preferences = Arc::new(FakePreferences(Mutex::new(UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: Some(UiLocale::ZhCn),
            revision: Some(1),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        })));
        let agents = Arc::new(FakeAgents::new());
        let channels = FakeChannelRuntime::new();
        let application = Arc::new(
            OpenBotApplication::new(channels.clone())
                .with_channel_administration(Arc::new(channels.clone()))
                .with_channel_routing(Arc::new(FakeRouting))
                .with_threads(channels)
                .with_people(FakePeople)
                .with_agent_callback_tokens(FakeCallbackTokens(agents.clone()))
                .with_agent_directory(agents.clone())
                .with_agent_administration(agents)
                .with_ui_preferences(preferences)
                .with_run_cost_budgets(Arc::new(FakeRunCostBudgets(Mutex::new(None))))
                .with_mcp_connections(mcp)
                .with_credentials(credentials)
                .with_remote_interrupts(Arc::new(FakeRemoteInterrupts))
                .with_component_administration(Arc::new(FakeComponents))
                .with_sandboxed_component_administration(Arc::new(FakeSandboxed))
                .with_tool_approvals(Arc::new(FakeApprovals)),
        );
        let transport = Arc::new(InProcessTransport::new(application));
        let protocol = Arc::new(DesktopTauriProtocol::open(&root, transport).unwrap());
        (protocol, root)
    }

    #[test]
    fn window_binding_identity_is_positive_and_never_reused_on_rebind() {
        let (protocol, root) = protocol();
        protocol.bind_window("main", auth(), None).unwrap();
        let first = protocol.authority("main").unwrap().unwrap();
        assert!(first.binding_id > 0);
        assert!(protocol.unbind_window("main").unwrap());
        assert!(first.closed.is_cancelled());
        protocol.bind_window("main", auth(), None).unwrap();
        let replacement = protocol.authority("main").unwrap().unwrap();
        assert!(replacement.binding_id > first.binding_id);
        assert!(!replacement.closed.is_cancelled());
        protocol.bind_window("auxiliary", auth(), None).unwrap();
        let other = protocol.authority("auxiliary").unwrap().unwrap();
        assert!(other.binding_id > replacement.binding_id);
        assert!(!other.closed.is_cancelled());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn window_chrome_pending_is_unique_consumed_and_cannot_affect_a_replacement() {
        use openbot_contracts::desktop::{
            DesktopWindowChromeAction, DesktopWindowChromeErrorCode as Code,
            DesktopWindowChromeRequest,
        };
        use window_chrome::PendingDrag;
        let (protocol, root) = protocol();
        assert!(
            matches!(PendingDrag::claim(&protocol, "main"), Err(error) if error.code == Code::Stale)
        );
        protocol.bind_window("main", auth(), None).unwrap();
        let first = PendingDrag::claim(&protocol, "main").unwrap();
        assert!(
            matches!(PendingDrag::claim(&protocol, "main"), Err(error) if error.code == Code::Busy)
        );
        protocol.unbind_window("main").unwrap();
        protocol.bind_window("main", auth(), None).unwrap();
        let replacement = PendingDrag::claim(&protocol, "main").unwrap();
        let calls = AtomicU64::new(0);
        let request = DesktopWindowChromeRequest {
            action: DesktopWindowChromeAction::StartDrag,
        };
        assert_eq!(
            first.run(&protocol, request, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Err(Code::Stale.into())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            matches!(PendingDrag::claim(&protocol, "main"), Err(error) if error.code == Code::Busy)
        );
        assert!(
            replacement
                .run(&protocol, request, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .unwrap()
                .accepted
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Dropped queued work releases only its own permit and performs no native action.
        drop(PendingDrag::claim(&protocol, "main").unwrap());
        assert!(PendingDrag::claim(&protocol, "main").is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn window_chrome_native_failure_and_in_call_unbind_release_without_replay_or_locks() {
        use openbot_contracts::desktop::{
            DesktopWindowChromeAction, DesktopWindowChromeErrorCode as Code,
            DesktopWindowChromeRequest,
        };
        use window_chrome::PendingDrag;
        let (protocol, root) = protocol();
        protocol.bind_window("main", auth(), None).unwrap();
        let request = DesktopWindowChromeRequest {
            action: DesktopWindowChromeAction::StartDrag,
        };
        let pending = PendingDrag::claim(&protocol, "main").unwrap();
        assert_eq!(
            pending.run(&protocol, request, || Err(())),
            Err(Code::Unavailable.into())
        );
        let pending = PendingDrag::claim(&protocol, "main").unwrap();
        let calls = AtomicU64::new(0);
        assert_eq!(
            pending.run(&protocol, request, || {
                calls.fetch_add(1, Ordering::SeqCst);
                // This needs the authority write lock; the native callback must not retain a reader.
                protocol.unbind_window("main").unwrap();
                Ok(())
            }),
            Err(Code::Stale.into())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            matches!(PendingDrag::claim(&protocol, "main"), Err(error) if error.code == Code::Stale)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn legacy_preferences_only_fill_first_paint_after_authorized_no_row_read() {
        let root = protocol_root();
        let projection_path = root.join("first-frame-fixture");
        let legacy = b"openbot-ui-preferences-v1\ntheme=dark\nlocale=zh-CN\n";
        fs::write(&projection_path, legacy).unwrap();
        let authority = Arc::new(FirstFramePreferenceAuthority {
            reply: Mutex::new(Ok(UiPreferences::default())),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
        });
        let authoritative: Arc<dyn UiPreferenceAdministration> = authority.clone();
        let preferences = Arc::new(crate::DesktopUiPreferenceAdministration::new(
            authoritative,
            projection_path.clone(),
        ));
        let application = Arc::new(
            OpenBotApplication::new(FakeChannelRuntime::new()).with_ui_preferences(preferences),
        );
        let protocol =
            DesktopTauriProtocol::open(&root, Arc::new(InProcessTransport::new(application)))
                .unwrap()
                .with_first_frame_projection(crate::DesktopUiPreferenceStore::new(
                    &projection_path,
                ));
        protocol.bind_window("main", auth(), None).unwrap();

        for path in ["/", "/index.html", "/settings"] {
            let response = protocol
                .handle(
                    "main",
                    Request::builder().uri(path).body(Vec::new()).unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                std::str::from_utf8(response.body())
                    .unwrap()
                    .contains(&index_root(
                        UiTheme::Dark,
                        UiLocale::ZhCn,
                        cfg!(target_os = "macos")
                    ))
            );
        }
        let api = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/me/preferences")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(api.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(api.body()).unwrap(),
            serde_json::json!({"theme":null,"locale":null,"revision":null,"updatedAt":null})
        );
        assert_eq!(authority.reads.load(Ordering::SeqCst), 4);
        assert_eq!(authority.writes.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&projection_path).unwrap(), legacy);

        // A cache cannot turn a failed authoritative read into a successful page or API reply.
        *authority.reply.lock().unwrap() = Err(UiPreferenceAdministrationError::Unavailable);
        for path in ["/", "/api/me/preferences"] {
            let response = protocol
                .handle(
                    "main",
                    Request::builder().uri(path).body(Vec::new()).unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let unbound = protocol
            .handle(
                "unbound",
                Request::builder().uri("/").body(Vec::new()).unwrap(),
            )
            .await;
        assert_eq!(unbound.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(authority.reads.load(Ordering::SeqCst), 6);
        assert_eq!(authority.writes.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&projection_path).unwrap(), legacy);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn window_chrome_index_hint_preserves_all_themes_and_locales_only_for_macos() {
        for (locale, language) in [(UiLocale::En, "en"), (UiLocale::ZhCn, "zh-CN")] {
            for (theme, class) in [
                (UiTheme::System, ""),
                (UiTheme::Light, " class=\"light\""),
                (UiTheme::Dark, " class=\"dark\""),
            ] {
                assert_eq!(
                    index_root(theme, locale, false),
                    format!("<html lang=\"{language}\"{class}>")
                );
                assert_eq!(
                    index_root(theme, locale, true),
                    format!(
                        "<html lang=\"{language}\"{class} data-window-chrome=\"macos-overlay\">"
                    )
                );
                let response = index_response(
                    "<html lang=\"en\"></html>",
                    Some(theme),
                    Some(locale),
                    UiLocale::En,
                );
                let body = String::from_utf8(response.into_body()).unwrap();
                assert_eq!(
                    body.contains("data-window-chrome=\"macos-overlay\""),
                    cfg!(target_os = "macos")
                );
            }
        }
    }

    #[test]
    fn window_binding_identity_exhaustion_fails_without_authority() {
        let (protocol, root) = protocol();
        protocol
            .window_registry
            .next_window_binding_id
            .store(u64::MAX, Ordering::SeqCst);
        assert!(matches!(
            protocol.bind_window("main", auth(), None),
            Err(TauriHostError::WindowBindingCounterExhausted)
        ));
        assert!(protocol.authority("main").unwrap().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registration_installs_the_closed_wry_protocol_and_command_handler() {
        let (protocol, root) = protocol();
        let builder = Builder::<tauri::Wry>::default();
        assert!(register_tauri_protocol(builder, "openbot", protocol).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "desktop-local-runtime")]
    #[test]
    fn deferred_protocol_slot_is_not_ready_then_install_once() {
        let (protocol, root) = protocol();
        let slot = DesktopTauriProtocolSlot::pending();
        assert!(matches!(slot.get(), Err(TauriHostError::ProtocolNotReady)));
        slot.install(Arc::clone(&protocol)).unwrap();
        assert!(Arc::ptr_eq(&slot.get().unwrap(), &protocol));
        assert!(matches!(
            slot.install(protocol),
            Err(TauriHostError::ProtocolAlreadyReady)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn command_audit_list_and_generated_handler_are_exactly_joined() {
        // The production text ends at the test-module header. Single test-only `use` items come
        // earlier, so the first `#[cfg(test)]` is not the header; a missing header must fail
        // here rather than fall back to the whole file.
        let source = include_str!("tauri_host.rs");
        let (production, _) = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("tauri_host.rs must keep its test module header");
        let chrome_source = include_str!("tauri_host/window_chrome.rs");
        let (chrome_production, _) = chrome_source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("window_chrome.rs must keep its test module header");
        assert_eq!(production.matches("#[tauri::command]").count(), 2);
        assert_eq!(chrome_production.matches("#[tauri::command]").count(), 1);
        let handler = production
            .split("tauri::generate_handler![")
            .nth(1)
            .and_then(|tail| tail.split("])").next())
            .expect("generated handler must remain explicit");
        for command in DESKTOP_TAURI_COMMANDS {
            assert!(
                production.contains(&format!("fn {command}("))
                    || chrome_production.contains(&format!("fn {command}(")),
                "missing command function {command}"
            );
            assert!(handler.contains(command), "handler omitted {command}");
        }
        assert_eq!(
            handler
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .count(),
            DESKTOP_TAURI_COMMANDS.len()
        );
    }

    #[test]
    fn scheme_asset_and_percent_decoders_are_closed() {
        assert_eq!(
            DESKTOP_TAURI_COMMANDS,
            [
                "openbot_structured_events_open",
                "openbot_structured_events_close",
                "wrok_bot_window_chrome"
            ]
        );
        assert!(valid_scheme("app-ui"));
        for invalid in ["", "OpenBot", "http", "tauri", "has space", "a/b"] {
            assert!(!valid_scheme(invalid), "{invalid}");
        }
        assert_eq!(closed_asset_path("/app-1.css"), Some("app-1.css"));
        for invalid in ["/../secret", "/a%2Fb.js", "/missing", "/a//b.js"] {
            assert_eq!(closed_asset_path(invalid), None, "{invalid}");
        }
        assert_eq!(
            percent_decode_segment("approval%2Fone"),
            Some("approval/one".to_owned())
        );
        assert_eq!(percent_decode_segment("bad%2"), None);
        assert_eq!(percent_decode_segment("raw/slash"), None);
        assert_eq!(agent_hidden_query(None), Some(false));
        assert_eq!(agent_hidden_query(Some("")), Some(false));
        assert_eq!(agent_hidden_query(Some("hidden=false")), Some(false));
        assert_eq!(agent_hidden_query(Some("hidden=true")), Some(true));
        assert_eq!(agent_hidden_query(Some("hidden=1")), None);
        assert!(matches!(
            agent_route("/api/agents/agent%2Done/duplicate"),
            Some(AgentRoute::Duplicate { .. })
        ));
        assert!(agent_route("/api/agents/agent/one").is_none());
        assert_eq!(
            raw_channel_id("/api/channels/channel%2Done"),
            Some("channel%2Done")
        );
        assert!(raw_channel_id("/api/channels/events").is_none());
        assert!(raw_channel_id("/api/channels/channel/one").is_none());
        assert!(matches!(
            thread_route("/api/threads/thread%2Done/runs/run%2Done/cancel"),
            Some(ThreadRoute::Cancel { .. })
        ));
        assert!(thread_route("/api/threads/mint").is_none());
        assert!(thread_route("/api/threads/thread/one/runs").is_none());
        assert_eq!(channel_list_query(None), Some((None, None)));
        assert_eq!(
            channel_list_query(Some("cursor=opaque%2B%2F%3D&limit=50")),
            Some((Some(50), Some("opaque+/=".to_owned())))
        );
        for invalid in [
            "limit=-1",
            "limit=1&limit=2",
            "cursor=a&cursor=b",
            "unknown=value",
            "limit",
            "limit=%GG",
        ] {
            assert_eq!(channel_list_query(Some(invalid)), None, "{invalid}");
        }
    }

    #[test]
    fn revision_conflict_projects_the_closed_snapshot_without_cache_or_internal_fields() {
        let snapshot = openbot_contracts::revision::RevisionSnapshot::from_public(
            2,
            time::OffsetDateTime::UNIX_EPOCH,
            &json!({"revision":2}),
        )
        .unwrap();
        let response = error_response(AppError::StaleGeneration {
            subject: openbot_contracts::error::StaleGenerationSubject::Configuration { snapshot },
        });
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
            serde_json::to_value(snapshot).unwrap()
        );
    }

    #[test]
    fn structured_command_errors_are_stable_and_hide_internal_labels() {
        let duplicate = TauriHostError::StructuredSubscription(
            DesktopStructuredOpenError::Session(OpenSessionError::WindowAlreadyOpen(
                crate::WindowAlreadyOpen(WindowLabel::new("private-internal-label")),
            )),
        );
        assert_eq!(
            tauri_host_error_code(&duplicate),
            "desktop_subscription_conflict"
        );
        assert!(!tauri_host_error_code(&duplicate).contains("private"));
        assert_eq!(
            tauri_host_error_code(&TauriHostError::StructuredSubscription(
                DesktopStructuredOpenError::WindowBudgetExhausted,
            )),
            "structured_subscription_window_budget_exhausted"
        );
        assert_eq!(
            tauri_host_error_code(&TauriHostError::StructuredSubscription(
                DesktopStructuredOpenError::WindowClosed,
            )),
            "desktop_window_unbound"
        );
        let application =
            TauriHostError::StructuredSubscription(DesktopStructuredOpenError::Session(
                OpenSessionError::Application(AppError::NotVisible),
            ));
        assert_eq!(tauri_host_error_code(&application), "not_visible");
    }

    #[test]
    fn agent_body_parser_zeroes_success_malformed_and_oversized_buffers() {
        let mut valid = Request::builder()
            .body(
                br#"{"endpoint":"https://agent.example/ag-ui","auth":{"header":"Authorization","value":"Bearer DESKTOP_SECRET"}}"#
                    .to_vec(),
            )
            .unwrap();
        let parsed = parse_agent_body::<AgentConnectionTestRequest>(&mut valid).unwrap();
        assert!(parsed.auth.is_some());
        assert!(valid.body().iter().all(|byte| *byte == 0));

        let mut malformed = Request::builder()
            .body(b"{DESKTOP_SECRET".to_vec())
            .unwrap();
        assert!(matches!(
            parse_agent_body::<AgentConnectionTestRequest>(&mut malformed),
            Err(AgentBodyError::Malformed)
        ));
        assert!(malformed.body().iter().all(|byte| *byte == 0));

        let mut oversized = Request::builder()
            .body(vec![b'x'; AGENT_BODY_MAX_BYTES + 1])
            .unwrap();
        assert!(matches!(
            parse_agent_body::<AgentConnectionTestRequest>(&mut oversized),
            Err(AgentBodyError::TooLarge)
        ));
        assert!(oversized.body().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sensitive_body_parser_zeroes_user_text_on_every_exit() {
        let mut valid = Request::builder()
            .body(br#"{"text":"DESKTOP_MESSAGE_SECRET","agentId":"agent-one"}"#.to_vec())
            .unwrap();
        let parsed =
            parse_sensitive_body::<RouteChannelRequest>(&mut valid, CHANNEL_THREAD_BODY_MAX_BYTES)
                .unwrap();
        assert_eq!(parsed.text, "DESKTOP_MESSAGE_SECRET");
        assert!(valid.body().iter().all(|byte| *byte == 0));

        let mut malformed = Request::builder()
            .body(b"{DESKTOP_MESSAGE_SECRET".to_vec())
            .unwrap();
        assert!(matches!(
            parse_sensitive_body::<RouteChannelRequest>(
                &mut malformed,
                CHANNEL_THREAD_BODY_MAX_BYTES,
            ),
            Err(SensitiveBodyError::Malformed)
        ));
        assert!(malformed.body().iter().all(|byte| *byte == 0));

        let mut oversized = Request::builder()
            .body(vec![b'x'; CHANNEL_THREAD_BODY_MAX_BYTES + 1])
            .unwrap();
        assert!(matches!(
            parse_sensitive_body::<RouteChannelRequest>(
                &mut oversized,
                CHANNEL_THREAD_BODY_MAX_BYTES,
            ),
            Err(SensitiveBodyError::TooLarge)
        ));
        assert!(oversized.body().iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn an_inflight_old_binding_cannot_attach_to_a_recreated_window_label() {
        let root = protocol_root();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let service = Arc::new(BlockingSubscriptionService {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let transport = Arc::new(InProcessTransport::new(service));
        let protocol = Arc::new(DesktopTauriProtocol::open(&root, transport).unwrap());
        protocol.bind_window("main", auth(), None).unwrap();

        let opening = Arc::clone(&protocol);
        let task = tokio::spawn(async move {
            opening
                .open_structured_subscription("main", SubscriptionRequest::Health)
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("old binding must enter application subscribe");
        assert!(protocol.unbind_window("main").unwrap());
        protocol.bind_window("main", admin_auth(), None).unwrap();
        release.notify_one();

        let outcome = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("stale open must finish")
            .unwrap();
        assert!(matches!(outcome, Err(TauriHostError::WindowUnbound)));
        assert_eq!(protocol.transport.broker().window_count(), 0);
        assert_eq!(protocol.structured_events.active_subscription_count(), 0);
        assert!(protocol.unbind_window("main").unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn exact_close_is_scoped_to_the_host_observed_window() {
        let (protocol, root) = protocol();
        protocol.bind_window("main", auth(), None).unwrap();
        protocol.bind_window("auxiliary", auth(), None).unwrap();
        let mut main = protocol
            .open_structured_subscription("main", SubscriptionRequest::Health)
            .await
            .unwrap();
        let auxiliary = protocol
            .open_structured_subscription("auxiliary", SubscriptionRequest::Health)
            .await
            .unwrap();
        assert_eq!(protocol.transport.broker().window_count(), 2);

        assert!(
            !protocol
                .close_structured_subscription("main", auxiliary.subscription_id())
                .unwrap()
        );
        assert!(
            protocol
                .close_structured_subscription("main", main.subscription_id())
                .unwrap()
        );
        assert!(
            !protocol
                .close_structured_subscription("main", main.subscription_id())
                .unwrap()
        );
        assert!(matches!(
            protocol.close_structured_subscription("unbound", auxiliary.subscription_id()),
            Err(TauriHostError::WindowUnbound)
        ));
        assert_eq!(protocol.transport.broker().window_count(), 1);

        let terminal = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = main.next_frame().await.unwrap().unwrap();
                if frame.terminal_reason().is_some() {
                    break frame;
                }
            }
        })
        .await
        .expect("exact close must wake the selected subscription");
        assert_eq!(
            terminal.terminal_reason(),
            Some(crate::DesktopStructuredTerminalReason::SubscriptionClosed)
        );
        assert_eq!(protocol.structured_events.active_subscription_count(), 1);

        drop(auxiliary);
        assert_eq!(protocol.transport.broker().window_count(), 0);
        assert_eq!(protocol.structured_events.active_subscription_count(), 0);
        assert!(protocol.unbind_window("main").unwrap());
        assert!(protocol.unbind_window("auxiliary").unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn structured_channel_uses_bound_authority_and_unbind_closes_the_route() {
        let (protocol, root) = protocol();
        assert!(matches!(
            protocol
                .open_structured_subscription("main", SubscriptionRequest::Health)
                .await,
            Err(TauriHostError::WindowUnbound)
        ));
        assert_eq!(protocol.transport.broker().window_count(), 0);

        protocol.bind_window("main", auth(), None).unwrap();
        let frames = Arc::new(Mutex::new(Vec::<DesktopStructuredEventFrame>::new()));
        let sink = Arc::clone(&frames);
        let channel = Channel::new(move |body| {
            let InvokeResponseBody::Json(json) = body else {
                panic!("structured frame must use Tauri's JSON IPC lane");
            };
            let frame_json = serde_json::from_str::<String>(&json)?;
            sink.lock()
                .unwrap()
                .push(serde_json::from_str(&frame_json)?);
            Ok(())
        });
        let running = Arc::clone(&protocol);
        let pump = tokio::spawn(async move {
            running
                .pump_structured_events("main", SubscriptionRequest::Health, channel)
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            while protocol.transport.broker().window_count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("host-owned structured route must open");
        assert_eq!(protocol.structured_events.active_subscription_count(), 1);
        assert!(protocol.unbind_window("main").unwrap());
        assert_eq!(protocol.transport.broker().window_count(), 0);
        assert_eq!(protocol.structured_events.active_subscription_count(), 0);

        let exit = tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .expect("window close must wake a pending structured pump")
            .unwrap()
            .unwrap();
        assert_eq!(
            exit,
            DesktopStructuredPumpExit::Terminal(
                crate::DesktopStructuredTerminalReason::SubscriptionClosed
            )
        );
        assert!(matches!(
            frames.lock().unwrap().last(),
            Some(DesktopStructuredEventFrame::Terminal {
                reason: crate::DesktopStructuredTerminalReason::SubscriptionClosed,
                ..
            })
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn artifact_refs_local_v1_v2_body_mapping_reaches_application_shape_guard() {
        let (protocol, root) = protocol();
        protocol.bind_window("artifact-refs", auth(), None).unwrap();
        for selection in [
            serde_json::Value::Null,
            json!({
                "schemaVersion": 2, "source": "custom",
                "connectionId": "0196ea23-b506-73c8-8153-213383fdc24a",
                "expectedConnectionRevision": 1, "modelId": "model",
                "expectedCatalogRevision": 1
            }),
        ] {
            let wire = json!({
                "runId": "artifact-forwarding", "botId": "agent-one",
                "anchor": {"kind": "direct_bot"}, "message": "unchanged",
                "modelSelection": selection, "artifactRefs": ["not-a-uuid-v7"]
            });
            let response = protocol
                .handle(
                    "artifact-refs",
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/threads/550e8400-e29b-41d4-a716-446655440000/runs")
                        .body(serde_json::to_vec(&wire).unwrap())
                        .unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(response.body()).unwrap()["code"],
                "malformed_payload"
            );
        }
        assert!(protocol.unbind_window("artifact-refs").unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn channel_and_thread_unary_routes_share_typed_application_without_fake_streaming() {
        const SECRET: &str = "DESKTOP_CHANNEL_MESSAGE_SECRET";
        let (protocol, root) = protocol();
        // Server uses OriginAuthenticated, not the fresh-session extractor, for these writes.
        // The custom scheme is intrinsically same-origin, so an ordinary bound window must work.
        protocol.bind_window("channel", auth(), None).unwrap();

        let list = protocol
            .handle(
                "channel",
                Request::builder()
                    .uri("/api/channels?limit=50")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(list.status(), StatusCode::OK);
        assert_eq!(list.headers()[CACHE_CONTROL], "no-store");
        let page = serde_json::from_slice::<ChannelPage>(list.body()).unwrap();
        assert_eq!(page.channels.len(), 1);
        assert_eq!(page.channels[0].id.as_str(), "channel-one");

        for query in ["unknown=value", "limit=-1", "limit=1&limit=2"] {
            let rejected = protocol
                .handle(
                    "channel",
                    Request::builder()
                        .uri(format!("/api/channels?{query}"))
                        .body(Vec::new())
                        .unwrap(),
                )
                .await;
            assert_eq!(rejected.status(), StatusCode::BAD_REQUEST, "{query}");
        }

        let created = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/channels")
                    .body(br#"{"agentIds":["agent-one"]}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created = serde_json::from_slice::<ChannelDetailResponse>(created.body())
            .unwrap()
            .channel;
        assert_eq!(created.id.as_str(), "desktop-channel-1");
        assert_eq!(created.agent_ids.as_slice(), [BotId::new("agent-one")]);
        let thread_id = created.thread_id.clone().unwrap();

        let detail = protocol
            .handle(
                "channel",
                Request::builder()
                    .uri("/api/channels/desktop-channel-1")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(detail.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<ChannelDetailResponse>(detail.body())
                .unwrap()
                .channel,
            created
        );

        let routing = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/route")
                    .body(format!(r#"{{"text":"{SECRET}","agentId":"agent-one"}}"#).into_bytes())
                    .unwrap(),
            )
            .await;
        assert_eq!(routing.status(), StatusCode::OK);
        assert!(!String::from_utf8_lossy(routing.body()).contains(SECRET));
        let routing = serde_json::from_slice::<ChannelRoutingDecision>(routing.body()).unwrap();
        assert_eq!(routing.agent_id.as_str(), "agent-one");
        assert!(routing.via_mention);

        let minted = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/threads/mint")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(minted.status(), StatusCode::OK);
        let minted = serde_json::from_slice::<ThreadMinted>(minted.body()).unwrap();
        let status = protocol
            .handle(
                "channel",
                Request::builder()
                    .uri(format!("/api/threads/{}", minted.thread_id.as_str()))
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(status.status(), StatusCode::OK);
        assert!(
            serde_json::from_slice::<ThreadStatus>(status.body())
                .unwrap()
                .known
        );

        let run_id = RunId::new("desktop-run-1");
        let begin_body = serde_json::to_vec(&BeginThreadRunBody {
            artifact_refs: Vec::new(),
            model_selection: None,
            selected_skill_slugs: vec!["skill-one".to_owned()],
            run_id: run_id.clone(),
            bot_id: BotId::new("agent-one"),
            anchor: ThreadRunAnchor::Channel {
                channel_id: created.id.clone(),
            },
            message: SECRET.to_owned(),
        })
        .unwrap();
        let begin_path = format!("/api/threads/{}/runs", thread_id.as_str());
        let started = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri(&begin_path)
                    .body(begin_body.clone())
                    .unwrap(),
            )
            .await;
        assert_eq!(started.status(), StatusCode::CREATED);
        assert!(!String::from_utf8_lossy(started.body()).contains(SECRET));
        let started = serde_json::from_slice::<ThreadRunStarted>(started.body()).unwrap();
        assert_eq!(started.thread_id, thread_id);
        assert_eq!(started.run_id, run_id);
        assert!(!started.replayed);

        let replayed = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri(&begin_path)
                    .body(begin_body)
                    .unwrap(),
            )
            .await;
        assert_eq!(replayed.status(), StatusCode::OK);
        assert!(
            serde_json::from_slice::<ThreadRunStarted>(replayed.body())
                .unwrap()
                .replayed
        );

        let conversation_path = format!("/api/threads/{}/conversation", started.thread_id.as_str());
        let conversation = protocol
            .handle(
                "channel",
                Request::builder()
                    .uri(&conversation_path)
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(conversation.status(), StatusCode::OK);
        let conversation =
            serde_json::from_slice::<ThreadConversationSnapshot>(conversation.body()).unwrap();
        assert_eq!(conversation.active_run_id.as_ref(), Some(&run_id));
        assert_eq!(
            conversation.active_run_state,
            Some(ThreadForegroundRunState::Running)
        );
        assert!(conversation.active_run_cancellable);

        let cancel_path = format!(
            "/api/threads/{}/runs/{}/cancel",
            started.thread_id.as_str(),
            run_id.as_str()
        );
        let cancelled = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri(&cancel_path)
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(cancelled.status(), StatusCode::ACCEPTED);
        assert_eq!(
            serde_json::from_slice::<ThreadRunCancellation>(cancelled.body())
                .unwrap()
                .state,
            ThreadRunCancellationState::Requested
        );
        let cancelled_again = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri(&cancel_path)
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(cancelled_again.status(), StatusCode::ACCEPTED);
        assert_eq!(
            serde_json::from_slice::<ThreadRunCancellation>(cancelled_again.body())
                .unwrap()
                .state,
            ThreadRunCancellationState::AlreadyRequested
        );

        let cancelling = protocol
            .handle(
                "channel",
                Request::builder()
                    .uri(&conversation_path)
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        let cancelling =
            serde_json::from_slice::<ThreadConversationSnapshot>(cancelling.body()).unwrap();
        assert_eq!(
            cancelling.active_run_state,
            Some(ThreadForegroundRunState::Cancelling)
        );
        assert!(!cancelling.active_run_cancellable);

        let malformed = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri(&begin_path)
                    .body(format!("{{malformed:{SECRET}").into_bytes())
                    .unwrap(),
            )
            .await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert!(!String::from_utf8_lossy(malformed.body()).contains(SECRET));

        let oversized = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/route")
                    .body(vec![b'x'; CHANNEL_THREAD_BODY_MAX_BYTES + 1])
                    .unwrap(),
            )
            .await;
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let ignored_mint_body = protocol
            .handle(
                "channel",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/threads/mint")
                    .body(SECRET.as_bytes().to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(ignored_mint_body.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(!String::from_utf8_lossy(ignored_mint_body.body()).contains(SECRET));

        let thread_events = protocol
            .handle(
                "channel",
                Request::builder()
                    .uri(format!(
                        "/api/threads/{}/events",
                        started.thread_id.as_str()
                    ))
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(thread_events.status(), StatusCode::NOT_FOUND);
        let channel_events = protocol
            .handle(
                "channel",
                Request::builder()
                    .uri("/api/channels/events")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(channel_events.status(), StatusCode::NOT_FOUND);

        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn agent_routes_share_typed_application_freshness_and_secret_free_framing() {
        const SECRET: &str = "DESKTOP_AGENT_SECRET_CANARY";
        let (protocol, root) = protocol();
        protocol.bind_window("agents", auth(), None).unwrap();

        let list = protocol
            .handle(
                "agents",
                Request::builder()
                    .uri("/api/agents")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(list.status(), StatusCode::OK);
        assert_eq!(list.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<AgentProfilesResponse>(list.body())
                .unwrap()
                .agents
                .len(),
            1
        );

        let detail = protocol
            .handle(
                "agents",
                Request::builder()
                    .uri("/api/agents/agent-one")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(detail.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<AgentProfileResponse>(detail.body())
                .unwrap()
                .agent
                .id
                .as_str(),
            "agent-one"
        );

        let stale = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents")
                    .body(format!("{{malformed:{SECRET}").into_bytes())
                    .unwrap(),
            )
            .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
        assert!(!String::from_utf8_lossy(stale.body()).contains(SECRET));

        let stale_callback = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/agent-one/callback-token")
                    .body(SECRET.as_bytes().to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(stale_callback.status(), StatusCode::UNAUTHORIZED);
        assert!(!String::from_utf8_lossy(stale_callback.body()).contains(SECRET));

        assert!(protocol.unbind_window("agents").unwrap());
        protocol
            .bind_window("agents", auth(), Some(Duration::from_secs(60)))
            .unwrap();

        let issued = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/agent-one/callback-token")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(issued.status(), StatusCode::CREATED);
        assert_eq!(issued.headers()[CACHE_CONTROL], "no-store");
        let first_token = serde_json::from_slice::<CallbackTokenIssued>(issued.body())
            .unwrap()
            .expose()
            .to_owned();
        assert!(first_token.starts_with("obot_agt_"));
        let issued_again = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/agent-one/callback-token")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(issued_again.status(), StatusCode::CREATED);
        let second_token = serde_json::from_slice::<CallbackTokenIssued>(issued_again.body())
            .unwrap()
            .expose()
            .to_owned();
        assert_ne!(first_token, second_token);
        assert!(!String::from_utf8_lossy(issued_again.body()).contains(&first_token));
        let callback_profile = protocol
            .handle(
                "agents",
                Request::builder()
                    .uri("/api/agents/agent-one")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert!(
            serde_json::from_slice::<AgentProfileResponse>(callback_profile.body())
                .unwrap()
                .agent
                .has_callback_token
        );
        let callback_body_rejected = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/agent-one/callback-token")
                    .body(SECRET.as_bytes().to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(
            callback_body_rejected.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert!(!String::from_utf8_lossy(callback_body_rejected.body()).contains(SECRET));
        let revoked = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/agents/agent-one/callback-token")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        assert!(revoked.body().is_empty());
        let revoked_profile = protocol
            .handle(
                "agents",
                Request::builder()
                    .uri("/api/agents/agent-one")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert!(
            !serde_json::from_slice::<AgentProfileResponse>(revoked_profile.body())
                .unwrap()
                .agent
                .has_callback_token
        );

        let bad_query = protocol
            .handle(
                "agents",
                Request::builder()
                    .uri("/api/agents?hidden=yes")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(bad_query.status(), StatusCode::BAD_REQUEST);

        let forged = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents")
                    .body(br#"{"name":"Forged","title":"Title","roleDescription":"Role","visibility":"private","ownerUserId":"admin"}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(forged.status(), StatusCode::BAD_REQUEST);

        let oversized = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents")
                    .body(vec![b'x'; AGENT_BODY_MAX_BYTES + 1])
                    .unwrap(),
            )
            .await;
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let create_body = format!(
            "{{\"name\":\"Remote\",\"title\":\"Remote title\",\"roleDescription\":\"Remote role\",\"visibility\":\"public\",\"endpoint\":\"https://agent.example/ag-ui\",\"auth\":{{\"header\":\"Authorization\",\"value\":\"Bearer {SECRET}\"}}}}"
        );
        let created = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents")
                    .body(create_body.into_bytes())
                    .unwrap(),
            )
            .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(created.headers()[CACHE_CONTROL], "no-store");
        assert!(!String::from_utf8_lossy(created.body()).contains(SECRET));
        let created = serde_json::from_slice::<AgentProfileResponse>(created.body())
            .unwrap()
            .agent;
        assert_eq!(created.id.as_str(), "desktop-agent-1");
        assert!(created.has_auth);

        let probe = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/test-connection")
                    .body(
                        format!(
                            "{{\"endpoint\":\"https://agent.example/ag-ui\",\"auth\":{{\"header\":\"Authorization\",\"value\":\"Bearer {SECRET}\"}}}}"
                        )
                        .into_bytes(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(probe.status(), StatusCode::OK);
        assert!(!String::from_utf8_lossy(probe.body()).contains(SECRET));
        assert_eq!(
            serde_json::from_slice::<AgentConnectionVerdict>(probe.body()).unwrap(),
            AgentConnectionVerdict::working(vec!["RUN_STARTED".to_owned()])
        );

        let updated = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::PATCH)
                    .uri("/api/agents/desktop-agent-1")
                    .body(br#"{"name":"Remote updated","title":"Updated title","roleDescription":"Updated role","visibility":"public","endpoint":"https://agent.example/ag-ui-v2"}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(updated.status(), StatusCode::OK);
        let updated = serde_json::from_slice::<AgentProfileResponse>(updated.body())
            .unwrap()
            .agent;
        assert!(updated.has_auth);
        assert_eq!(
            updated.endpoint.as_deref(),
            Some("https://agent.example/ag-ui-v2")
        );

        let duplicated = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/desktop-agent-1/duplicate")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(duplicated.status(), StatusCode::CREATED);
        let duplicate = serde_json::from_slice::<AgentProfileResponse>(duplicated.body())
            .unwrap()
            .agent;
        assert_eq!(duplicate.visibility, AgentVisibility::Private);
        assert!(!duplicate.has_auth);
        assert!(duplicate.endpoint.is_none());

        let hidden = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/desktop-agent-1/hide")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(hidden.status(), StatusCode::NO_CONTENT);
        assert!(hidden.body().is_empty());

        let default_roster = protocol
            .handle(
                "agents",
                Request::builder()
                    .uri("/api/agents?hidden=false")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert!(
            serde_json::from_slice::<AgentProfilesResponse>(default_roster.body())
                .unwrap()
                .agents
                .iter()
                .all(|agent| agent.id.as_str() != "desktop-agent-1")
        );
        let hidden_roster = protocol
            .handle(
                "agents",
                Request::builder()
                    .uri("/api/agents?hidden=true")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(
            serde_json::from_slice::<AgentProfilesResponse>(hidden_roster.body())
                .unwrap()
                .agents[0]
                .id
                .as_str(),
            "desktop-agent-1"
        );

        let unhidden = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/desktop-agent-1/unhide")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(unhidden.status(), StatusCode::NO_CONTENT);

        let deleted = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/agents/desktop-agent-1")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let missing = protocol
            .handle(
                "agents",
                Request::builder()
                    .uri("/api/agents/desktop-agent-1")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let wrong_method = protocol
            .handle(
                "agents",
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/agents")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn preferences_cas_keeps_member_authority_without_new_freshness_and_closed_conflicts() {
        let (protocol, root) = protocol();
        protocol
            .bind_window("preferences-member", auth(), None)
            .unwrap();
        let request = |method: Method, body: &[u8]| {
            Request::builder()
                .method(method)
                .uri("/api/me/preferences")
                .body(body.to_vec())
                .unwrap()
        };
        let saved = protocol
            .handle(
                "preferences-member",
                request(Method::PUT, br#"{"theme":"light","expectedRevision":1}"#),
            )
            .await;
        assert_eq!(saved.status(), StatusCode::OK);
        let current: UiPreferences = serde_json::from_slice(saved.body()).unwrap();
        assert_eq!(current.revision, Some(2));
        assert_eq!(current.theme, Some(UiTheme::Light));
        assert_eq!(current.locale, Some(UiLocale::ZhCn));
        for body in [
            br#"{"theme":"dark"}"#.as_slice(),
            br#"{"theme":"dark","expectedRevision":1}"#,
            br#"{"theme":"dark","expectedRevision":9223372036854775807}"#,
        ] {
            let response = protocol
                .handle("preferences-member", request(Method::PUT, body))
                .await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
            assert_eq!(
                body,
                serde_json::to_value(current.revision_snapshot().unwrap()).unwrap()
            );
            assert_eq!(body.as_object().unwrap().len(), 3);
        }
        for body in [
            br#"{"theme":"dark","expectedRevision":0}"#.as_slice(),
            br#"{"theme":"dark","expectedRevision":"2"}"#,
            br#"{"theme":"dark","expectedRevision":2,"actor":"forged"}"#,
        ] {
            assert_eq!(
                protocol
                    .handle("preferences-member", request(Method::PUT, body))
                    .await
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let fetched = protocol
            .handle("preferences-member", request(Method::GET, b""))
            .await;
        assert_eq!(
            serde_json::from_slice::<UiPreferences>(fetched.body()).unwrap(),
            current
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn bound_window_gets_rewritten_bundle_and_typed_preferences_and_approval() {
        let (protocol, root) = protocol();
        let unbound = protocol
            .handle(
                "main",
                Request::builder().uri("/").body(Vec::new()).unwrap(),
            )
            .await;
        assert_eq!(unbound.status(), StatusCode::UNAUTHORIZED);

        protocol.bind_window("main", auth(), None).unwrap();
        let index = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/approvals")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(index.headers()[CONTENT_SECURITY_POLICY], CSP);
        assert!(
            String::from_utf8(index.body().clone())
                .unwrap()
                .contains("lang=\"zh-CN\" class=\"dark\"")
        );

        let current_user = protocol
            .handle(
                "main",
                Request::builder().uri("/api/me").body(Vec::new()).unwrap(),
            )
            .await;
        assert_eq!(current_user.status(), StatusCode::OK);
        assert_eq!(current_user.headers()[CACHE_CONTROL], "no-store");
        let current_user =
            serde_json::from_slice::<CurrentUserResponse>(current_user.body()).unwrap();
        assert_eq!(current_user.user.id.as_str(), "actor");
        assert_eq!(current_user.user.email, "desktop@example.test");
        assert_eq!(current_user.user.role, Role::Admin);

        let update = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/me/preferences")
                    .body(br#"{"theme":"light","expectedRevision":1}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(update.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<UiPreferences>(update.body()).unwrap(),
            UiPreferences {
                theme: Some(UiTheme::Light),
                locale: Some(UiLocale::ZhCn),
                revision: Some(2),
                updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            }
        );

        let budget = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/me/run-cost-budget")
                    .body(br#"{"cap":{"currency":"USD","maxCostMicroUnits":"250000"}}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(budget.status(), StatusCode::OK);
        assert_eq!(budget.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<RunCostBudgetPreference>(budget.body()).unwrap(),
            RunCostBudgetPreference {
                cap: Some(RunCostCapInput {
                    currency: "USD".to_owned(),
                    max_cost_micro_units: "250000".to_owned(),
                }),
            }
        );
        let smuggled = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/me/run-cost-budget")
                    .body(
                        br#"{"cap":{"currency":"USD","maxCostMicroUnits":"1","actor":"admin"}}"#
                            .to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(smuggled.status(), StatusCode::BAD_REQUEST);

        let interrupts = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/me/remote-interrupts")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(interrupts.status(), StatusCode::OK);
        assert_eq!(interrupts.headers()[CACHE_CONTROL], "no-store");
        let interrupts =
            serde_json::from_slice::<PendingRemoteInterrupts>(interrupts.body()).unwrap();
        assert_eq!(interrupts.interrupts.len(), 1);
        let resolved = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/me/remote-interrupts/018f6f8a-5f4b-7c2d-8a31-111111111111")
                    .body(br#"{"status":"resolved","payload":{"approved":true}}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(resolved.status(), StatusCode::OK);
        let resolved = serde_json::from_slice::<RemoteInterruptResolved>(resolved.body()).unwrap();
        assert_eq!(resolved.status, RemoteInterruptAnswerStatus::Resolved);
        let invalid_cancel = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/me/remote-interrupts/018f6f8a-5f4b-7c2d-8a31-111111111111")
                    .body(br#"{"status":"cancelled","payload":true}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(invalid_cancel.status(), StatusCode::BAD_REQUEST);

        let approvals = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/tool-approvals")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(approvals.status(), StatusCode::OK);
        assert_eq!(approvals.body(), br#"{"approvals":[]}"#);

        let components = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/components")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(components.status(), StatusCode::OK);
        assert_eq!(components.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(components.body(), br#"{"components":[]}"#);

        let catalogue = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/components/catalogue")
                    .body(
                        serde_json::to_vec(&ComponentCatalogueRequest {
                            components: compiled_component_manifest(),
                        })
                        .unwrap(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(catalogue.status(), StatusCode::OK);
        assert_eq!(catalogue.headers()[CACHE_CONTROL], "no-store");
        let expected = compiled_component_manifest()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::from_slice::<ComponentCatalogueAdded>(catalogue.body())
                .unwrap()
                .added,
            expected
        );

        let runtime_grants = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/components/for-agent/agent%2Done")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(runtime_grants.status(), StatusCode::OK);
        assert_eq!(runtime_grants.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<GrantedCompiledComponents>(runtime_grants.body())
                .unwrap()
                .components[0]
                .name,
            SHOW_QUOTE_COMPONENT_NAME
        );

        let component_decision = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/components/showQuote/decision")
                    .body(
                        serde_json::to_vec(&ComponentDecisionRequest {
                            agent_id: BotId::new("agent-one"),
                            functions: Vec::new(),
                        })
                        .unwrap(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(component_decision.status(), StatusCode::OK);
        assert_eq!(component_decision.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<ComponentDecision>(component_decision.body()).unwrap(),
            ComponentDecision::allowed()
        );

        let component_functions = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/components/functions")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(component_functions.status(), StatusCode::OK);
        assert_eq!(component_functions.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<ComponentDataFunctions>(component_functions.body())
                .unwrap()
                .functions[0]
                .name,
            BOT_ACTIVITY_FUNCTION_NAME
        );

        let component_call = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/components/showActivityReport/call")
                    .body(
                        serde_json::to_vec(&ComponentFunctionCallRequest {
                            agent_id: BotId::new("agent-one"),
                            function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                            args: serde_json::json!({"days": 14}),
                        })
                        .unwrap(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(component_call.status(), StatusCode::OK);
        assert_eq!(component_call.headers()[CACHE_CONTROL], "no-store");
        assert!(matches!(
            serde_json::from_slice::<ComponentFunctionCall>(component_call.body())
                .unwrap()
                .data,
            Some(ComponentFunctionData::BotActivity(BotActivityReport {
                days: 14,
                ..
            }))
        ));

        let human_decisions = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/components/human-decisions")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(human_decisions.status(), StatusCode::OK);
        assert_eq!(human_decisions.headers()[CACHE_CONTROL], "no-store");
        assert!(
            serde_json::from_slice::<PendingComponentHumanDecisions>(human_decisions.body())
                .unwrap()
                .decisions
                .is_empty()
        );

        let human_answer = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/components/human-decisions/decision%2D1/answer")
                    .body(
                        serde_json::to_vec(&ComponentHumanDecisionAnswer::Approval(
                            ComponentApprovalAnswer {
                                decision: ComponentApprovalDecision::Approved,
                                note: None,
                            },
                        ))
                        .unwrap(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(human_answer.status(), StatusCode::OK);
        assert_eq!(human_answer.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<ComponentHumanDecisionResolved>(human_answer.body())
                .unwrap()
                .decision_id,
            "decision-1"
        );

        let stale = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/tool-approvals/approval-1")
                    .body(br#"{"decision":"grant"}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

        assert!(protocol.unbind_window("main").unwrap());
        protocol
            .bind_window("main", auth(), Some(Duration::from_secs(60)))
            .unwrap();
        let granted = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/tool-approvals/approval%2D1")
                    .body(br#"{"decision":"grant"}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(granted.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<ToolApprovalResolved>(granted.body()).unwrap(),
            ToolApprovalResolved {
                approval_id: "approval-1".to_owned(),
                decision: ToolApprovalDecision::Grant,
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[derive(Default)]
    struct CredentialProbe(Mutex<Vec<(ActorId, &'static str)>>);

    #[async_trait]
    impl openbot_application::credential_admin::CredentialAdministration for CredentialProbe {
        async fn list(
            &self,
            auth: &AuthContext,
            _: &CredentialPageRequest,
        ) -> Result<
            openbot_contracts::credential_admin::CredentialPage,
            openbot_application::credential_admin::CredentialAdministrationError,
        > {
            self.0.lock().unwrap().push((auth.actor().clone(), "list"));
            Ok(openbot_contracts::credential_admin::CredentialPage {
                credentials: Vec::new(),
                next_cursor: None,
                model_reference: None,
            })
        }
        async fn create(
            &self,
            auth: &AuthContext,
            input: &CredentialWrite,
        ) -> Result<
            openbot_contracts::credential_admin::CredentialWritten,
            openbot_application::credential_admin::CredentialAdministrationError,
        > {
            self.0
                .lock()
                .unwrap()
                .push((auth.actor().clone(), "create"));
            assert_eq!(input.expose_plaintext(), "desktop-secret-canary");
            Ok(credential_probe_receipt(input))
        }
        async fn rotate(
            &self,
            auth: &AuthContext,
            _: &str,
            input: &CredentialWrite,
        ) -> Result<
            openbot_contracts::credential_admin::CredentialWritten,
            openbot_application::credential_admin::CredentialAdministrationError,
        > {
            self.0
                .lock()
                .unwrap()
                .push((auth.actor().clone(), "rotate"));
            Ok(credential_probe_receipt(input))
        }
        async fn revoke(
            &self,
            auth: &AuthContext,
            id: &str,
        ) -> Result<
            openbot_contracts::credential_admin::CredentialRevoked,
            openbot_application::credential_admin::CredentialAdministrationError,
        > {
            self.0
                .lock()
                .unwrap()
                .push((auth.actor().clone(), "revoke"));
            Ok(openbot_contracts::credential_admin::CredentialRevoked {
                id: id.to_owned(),
                revoked_at: time::OffsetDateTime::UNIX_EPOCH,
                external_revocation:
                    openbot_contracts::credential_admin::CredentialExternalRevocation::Pending,
            })
        }
    }
    fn credential_probe_receipt(
        input: &CredentialWrite,
    ) -> openbot_contracts::credential_admin::CredentialWritten {
        use openbot_contracts::credential_admin::{
            CredentialExternalRevocation, CredentialRecordKind, CredentialStatus, CredentialWritten,
        };
        CredentialWritten {
            credential: CredentialStatus {
                id: "00000000-0000-4000-8000-000000000001".to_owned(),
                kind: CredentialRecordKind::Model,
                provider: input.provider().to_owned(),
                key_id: input.key_id().to_owned(),
                metadata: input.metadata().clone(),
                revoked_at: None,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                external_revocation: CredentialExternalRevocation::NotRequested,
            },
        }
    }

    #[tokio::test]
    async fn credential_framing_enforces_host_admin_freshness_and_keeps_secret_out_of_receipts() {
        let probe = Arc::new(CredentialProbe::default());
        let (protocol, root) =
            protocol_with_admin_ports(Arc::new(FakeMcpConnections::default()), probe.clone());
        protocol.bind_window("stale", admin_auth(), None).unwrap();
        protocol
            .bind_window("user", auth(), Some(Duration::from_secs(60)))
            .unwrap();
        protocol
            .bind_window("admin", admin_auth(), Some(Duration::from_secs(60)))
            .unwrap();
        let request = |path: &str, body: Vec<u8>| {
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .body(body)
                .unwrap()
        };
        let valid=br#"{"kind":"model","provider":"openai","keyId":"primary","metadata":{},"plaintext":"desktop-secret-canary"}"#.to_vec();
        for (window,body,expected) in [("absent",valid.clone(),StatusCode::UNAUTHORIZED),("stale",b"bad".to_vec(),StatusCode::UNAUTHORIZED),("user",b"bad".to_vec(),StatusCode::FORBIDDEN),("admin",br#"{"kind":"mcp_user_token","provider":"openai","keyId":"primary","metadata":{},"plaintext":"canary"}"#.to_vec(),StatusCode::BAD_REQUEST)] {
            assert_eq!(protocol.handle(window,request("/api/admin/credentials",body)).await.status(),expected);
            assert!(probe.0.lock().unwrap().is_empty());
        }
        for (path, expected) in [
            ("/api/admin/credentials", StatusCode::CREATED),
            ("/api/admin/credentials/old/rotate", StatusCode::OK),
        ] {
            let reply = protocol.handle("admin", request(path, valid.clone())).await;
            assert_eq!(reply.status(), expected);
            assert_eq!(reply.headers()[CACHE_CONTROL], "no-store");
            assert!(!String::from_utf8_lossy(reply.body()).contains("desktop-secret-canary"));
        }
        let reply = protocol
            .handle(
                "admin",
                request("/api/admin/credentials/old/revoke", Vec::new()),
            )
            .await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<CredentialRevocationReceipt>(reply.body())
                .unwrap()
                .credential
                .id,
            "old"
        );
        let forged = protocol
            .handle(
                "admin",
                Request::builder()
                    .uri("/api/admin/credentials?actor=other")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(forged.status(), StatusCode::BAD_REQUEST);
        let list = protocol
            .handle(
                "admin",
                Request::builder()
                    .uri("/api/admin/credentials")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(list.status(), StatusCode::OK);
        assert_eq!(
            *probe.0.lock().unwrap(),
            [
                (ActorId::new("admin"), "create"),
                (ActorId::new("admin"), "rotate"),
                (ActorId::new("admin"), "revoke"),
                (ActorId::new("admin"), "list")
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn plugin_connection_reads_are_bound_to_the_host_window_and_reject_query_authority() {
        let mcp = Arc::new(FakeMcpConnections::default());
        let (protocol, root) = protocol_with_mcp(mcp.clone());
        let request = |uri: &str| {
            Request::builder()
                .uri(uri)
                .header("x-openbot-actor", "admin")
                .body(Vec::new())
                .unwrap()
        };
        let absent = protocol
            .handle("user", request("/api/plugins/connections"))
            .await;
        assert_eq!(absent.status(), StatusCode::UNAUTHORIZED);
        assert!(mcp.reads.lock().unwrap().is_empty());
        protocol.bind_window("user", auth(), None).unwrap();
        let injected = protocol
            .handle("user", request("/api/plugins/connections?actor=admin"))
            .await;
        assert_eq!(injected.status(), StatusCode::BAD_REQUEST);
        assert!(mcp.reads.lock().unwrap().is_empty());
        let reply = protocol
            .handle("user", request("/api/plugins/connections"))
            .await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers()[CACHE_CONTROL], "no-store");
        let page: McpConnections = serde_json::from_slice(reply.body()).unwrap();
        assert_eq!(page.available_server_ids, ["notes-actor"]);
        assert!(page.redirect_uri.is_none());
        assert_eq!(*mcp.reads.lock().unwrap(), [ActorId::new("actor")]);
        protocol.unbind_window("user").unwrap();
        assert_eq!(
            protocol
                .handle("user", request("/api/plugins/connections"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(mcp.reads.lock().unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn curated_plugins_share_closed_selection_and_require_fresh_admin_before_effect() {
        let mcp = Arc::new(FakeMcpConnections::default());
        let (protocol, root) = protocol_with_mcp(mcp.clone());
        protocol.bind_window("stale", admin_auth(), None).unwrap();
        protocol
            .bind_window("user", auth(), Some(Duration::from_secs(60)))
            .unwrap();
        protocol
            .bind_window("admin", admin_auth(), Some(Duration::from_secs(60)))
            .unwrap();
        let request = |method: Method, uri: &str, body: Vec<u8>| {
            Request::builder()
                .method(method)
                .uri(uri)
                .body(body)
                .unwrap()
        };
        let valid = br#"{"key":"google-drive"}"#.to_vec();
        for (window, body, status) in [
            ("absent", valid.clone(), StatusCode::UNAUTHORIZED),
            ("stale", b"malformed".to_vec(), StatusCode::UNAUTHORIZED),
            ("user", valid.clone(), StatusCode::FORBIDDEN),
            ("admin", b"{}".to_vec(), StatusCode::BAD_REQUEST),
            (
                "admin",
                br#"{"key":"google-drive","url":"https://injected.example.test"}"#.to_vec(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "admin",
                br#"{"key":"google-drive","actor":"forged"}"#.to_vec(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "admin",
                br#"{"key":"google-drive","key":"other"}"#.to_vec(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "admin",
                vec![b'x'; MCP_ADMIN_BODY_MAX_BYTES + 1],
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            assert_eq!(
                protocol
                    .handle(window, request(Method::POST, "/api/plugins/servers", body))
                    .await
                    .status(),
                status
            );
            assert!(mcp.additions.lock().unwrap().is_empty());
        }
        assert_eq!(
            protocol
                .handle(
                    "admin",
                    request(Method::GET, "/api/plugins/servers", Vec::new())
                )
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            protocol
                .handle(
                    "admin",
                    request(
                        Method::POST,
                        "/api/plugins/servers?key=injected",
                        valid.clone()
                    )
                )
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(mcp.additions.lock().unwrap().is_empty());
        let reply = protocol
            .handle(
                "admin",
                request(Method::POST, "/api/plugins/servers", valid),
            )
            .await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<McpServerMutation>(reply.body())
                .unwrap()
                .server_id,
            "google-drive"
        );
        assert_eq!(
            *mcp.additions.lock().unwrap(),
            [(ActorId::new("admin"), "google-drive".to_owned())]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn plugin_admin_protocol_uses_typed_commands_and_host_freshness() {
        let (protocol, root) = protocol();
        protocol
            .bind_window("stale-plugins", admin_auth(), None)
            .unwrap();
        let page = protocol
            .handle(
                "stale-plugins",
                Request::builder()
                    .uri("/api/plugins")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<McpAdminPage>(page.body())
                .unwrap()
                .catalogue[0]
                .key,
            "google-drive"
        );
        let stale = protocol
            .handle(
                "stale-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/servers/custom")
                    .body(
                        br#"{"id":"private-notes","title":"Private notes","url":"https://notes.example/mcp"}"#
                            .to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

        protocol
            .bind_window("fresh-plugins", admin_auth(), Some(Duration::from_secs(60)))
            .unwrap();
        let malformed = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/servers/custom")
                    .body(
                        br#"{"id":"private-notes","title":"Private notes","url":"https://notes.example/mcp","actor":"forged"}"#
                            .to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let added = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/servers/custom")
                    .body(
                        br#"{"id":"private-notes","title":"Private notes","url":"https://notes.example/mcp","egressAllowCidrs":["10.0.0.0/8"]}"#
                            .to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(added.status(), StatusCode::OK);
        assert_eq!(added.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<McpServerMutation>(added.body())
                .unwrap()
                .server_id,
            "private-notes"
        );
        let refreshed = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/servers/private-notes/refresh")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(refreshed.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<McpServerMutation>(refreshed.body())
                .unwrap()
                .catalog_generation,
            2
        );
        let removed = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/plugins/servers/private-notes")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(removed.status(), StatusCode::OK);
        assert!(
            serde_json::from_slice::<McpServerRemoved>(removed.body())
                .unwrap()
                .ok
        );

        let skill = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/skills")
                    .body(
                        br#"{"slug":"review-notes","title":"Review notes","summary":"Review","instructions":"Review the notes.","global":true}"#
                            .to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(skill.status(), StatusCode::OK);
        assert_eq!(skill.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<PluginSkills>(skill.body())
                .unwrap()
                .skills[0]
                .revision,
            1
        );
        let smuggled_skill = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/skills")
                    .body(
                        br#"{"slug":"review-notes","title":"Review notes","summary":"Review","instructions":"Review the notes.","global":true,"actor":"forged"}"#
                            .to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(smuggled_skill.status(), StatusCode::BAD_REQUEST);

        let granted = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/grants")
                    .body(
                        br#"{"kind":"skill","ref":"review-notes","agentId":"agent-one"}"#.to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(granted.status(), StatusCode::OK);
        assert!(
            serde_json::from_slice::<PluginMutationAcknowledged>(granted.body())
                .unwrap()
                .ok
        );
        let listed = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .uri("/api/plugins/for/agent-one")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(listed.status(), StatusCode::OK);
        assert!(
            serde_json::from_slice::<GrantedPlugins>(listed.body())
                .unwrap()
                .tools
                .is_empty()
        );
        let revoked = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/plugins/grants?kind=skill&ref=review-notes&agentId=agent-one")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(revoked.status(), StatusCode::OK);
        let duplicate_query = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::DELETE)
                    .uri(
                        "/api/plugins/grants?kind=skill&ref=review-notes&ref=forged&agentId=agent-one",
                    )
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(duplicate_query.status(), StatusCode::BAD_REQUEST);
        let removed_skill = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/plugins/skills/review%2Dnotes")
                    .body(br#"{"expectedRevision":1}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(removed_skill.status(), StatusCode::OK);

        let stale_grant = protocol
            .handle(
                "stale-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/grants")
                    .body(
                        br#"{"kind":"skill","ref":"review-notes","agentId":"agent-one"}"#.to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(stale_grant.status(), StatusCode::UNAUTHORIZED);
        let removed_legacy_call = protocol
            .handle(
                "fresh-plugins",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/plugins/call")
                    .body(
                        br#"{"ref":"notes/search","args":{"query":"private"},"agentId":"agent-one"}"#
                            .to_vec(),
                    )
                    .unwrap(),
            )
            .await;
        assert_eq!(removed_legacy_call.status(), StatusCode::NOT_FOUND);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn skill_editing_desktop_requires_revision_and_returns_closed_stale_metadata() {
        let (protocol, root) = protocol_with_mcp(Arc::new(FakeMcpConnections::default()));
        protocol
            .bind_window("fresh-skill", auth(), Some(Duration::from_secs(60)))
            .unwrap();
        protocol.bind_window("stale-skill", auth(), None).unwrap();
        let request = |method: Method, uri: &str, body: &[u8]| {
            Request::builder()
                .method(method)
                .uri(uri)
                .body(body.to_vec())
                .unwrap()
        };
        let stale = protocol
            .handle(
                "stale-skill",
                request(Method::DELETE, "/api/plugins/skills/review", b"malformed"),
            )
            .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
        for body in [
            "",
            "{}",
            r#"{"expectedRevision":0}"#,
            r#"{"expectedRevision":"1"}"#,
            r#"{"expectedRevision":1,"actor":"forged"}"#,
        ] {
            assert_eq!(
                protocol
                    .handle(
                        "fresh-skill",
                        request(
                            Method::DELETE,
                            "/api/plugins/skills/review",
                            body.as_bytes()
                        )
                    )
                    .await
                    .status(),
                StatusCode::BAD_REQUEST,
                "{body}"
            );
        }
        for response in [
            protocol.handle("fresh-skill", request(Method::POST, "/api/plugins/skills", br#"{"slug":"review","title":"Review","instructions":"Sources","expectedRevision":9}"#)).await,
            protocol.handle("fresh-skill", request(Method::DELETE, "/api/plugins/skills/review", br#"{"expectedRevision":9}"#)).await,
        ] {
            assert_eq!(response.status(), StatusCode::CONFLICT);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
            assert_eq!(body.as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(), ["currentRevision", "currentSha256", "updatedAt"]);
            assert_eq!(body["currentRevision"], 10);
            assert_eq!(body["currentSha256"].as_str().unwrap().len(), 64);
            assert_eq!(body["updatedAt"], "1970-01-01T00:00:00Z");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn component_governance_routes_share_typed_application_and_require_fresh_admin() {
        let (protocol, root) = protocol();
        protocol.bind_window("admin", admin_auth(), None).unwrap();
        let stale = protocol
            .handle(
                "admin",
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/components/showQuote/draft")
                    .body(br#"{"description":"edited"}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
        assert!(protocol.unbind_window("admin").unwrap());
        protocol
            .bind_window("admin", admin_auth(), Some(Duration::from_secs(60)))
            .unwrap();

        let requests = [
            (
                Method::POST,
                "/api/components/showQuote/functions",
                br#"{"function":"botActivity"}"#.to_vec(),
            ),
            (
                Method::DELETE,
                "/api/components/showQuote/functions/botActivity",
                Vec::new(),
            ),
            (
                Method::POST,
                "/api/components/showQuote/grants",
                br#"{"agentId":"agent-one"}"#.to_vec(),
            ),
            (
                Method::DELETE,
                "/api/components/showQuote/grants/agent-one",
                Vec::new(),
            ),
            (
                Method::POST,
                "/api/components/showQuote/publication",
                br#"{"published":false}"#.to_vec(),
            ),
            (
                Method::PUT,
                "/api/components/showQuote/draft",
                br#"{"description":"edited quote"}"#.to_vec(),
            ),
        ];
        for (method, uri, body) in requests {
            let response = protocol
                .handle(
                    "admin",
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(body)
                        .unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            assert_eq!(
                serde_json::from_slice::<ComponentGovernanceReceipt>(response.body())
                    .unwrap()
                    .component
                    .name,
                SHOW_QUOTE_COMPONENT_NAME
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn sandboxed_routes_share_typed_application_and_require_fresh_admin_for_writes() {
        let (protocol, root) = protocol();
        protocol.bind_window("main", auth(), None).unwrap();
        let published = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/sandboxed/published")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(published.status(), StatusCode::OK);
        let published =
            serde_json::from_slice::<PublishedSandboxedComponents>(published.body()).unwrap();
        assert_eq!(published.components[0].name, "custom_delivery_eta");

        let drafts = protocol
            .handle(
                "main",
                Request::builder()
                    .uri("/api/sandboxed")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(drafts.status(), StatusCode::FORBIDDEN);

        assert!(protocol.unbind_window("main").unwrap());
        protocol.bind_window("main", admin_auth(), None).unwrap();
        let stale = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/sandboxed")
                    .body(b"{".to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

        assert!(protocol.unbind_window("main").unwrap());
        protocol
            .bind_window("main", admin_auth(), Some(Duration::from_secs(60)))
            .unwrap();
        let draft = SaveSandboxedComponentRequest {
            expected_revision: None,
            slug: "delivery_eta".to_owned(),
            title: "Delivery ETA".to_owned(),
            description: "Delivery estimate".to_owned(),
            html: "<p>ETA</p>".to_owned(),
            css: "p{}".to_owned(),
            js_functions: "function draw(){}".to_owned(),
            argument_schema: BTreeMap::new(),
            sample_arguments: BTreeMap::new(),
        };
        let saved = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/sandboxed")
                    .body(serde_json::to_vec(&draft).unwrap())
                    .unwrap(),
            )
            .await;
        assert_eq!(saved.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<SandboxedComponentResponse>(saved.body())
                .unwrap()
                .component
                .name,
            "custom_delivery_eta"
        );

        let published = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/sandboxed/custom_delivery_eta/publish")
                    .body(br#"{"expectedRevision":1}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(published.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<SandboxedComponentResponse>(published.body())
                .unwrap()
                .component
                .revision,
            1
        );

        let deleted = protocol
            .handle(
                "main",
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/sandboxed/custom_delivery_eta")
                    .body(br#"{"expectedRevision":2}"#.to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(deleted.status(), StatusCode::OK);
        assert!(
            serde_json::from_slice::<SandboxedComponentDeleted>(deleted.body())
                .unwrap()
                .ok
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "tauri_host/thread_history_management_local_tests.rs"]
mod thread_history_management_local_tests;

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "tauri_host/thread_history_stop_clear_local_tests.rs"]
mod thread_history_stop_clear_local_tests;
