//! Same-origin browser transport for typed GUI APIs.
//!
//! This module only performs HTTP framing. Approval binding, actor resolution and the durable
//! decision remain behind `ApplicationService` on the Server.

#[path = "desktop_chrome.rs"]
pub(crate) mod desktop_chrome;

#[path = "http_request.rs"]
pub(crate) mod request;

#[path = "desktop_transport.rs"]
pub(crate) mod desktop_transport;

#[path = "model_connections_api.rs"]
pub(crate) mod model_connections;
#[path = "plugins_api.rs"]
pub(crate) mod plugins;
#[path = "preference_cas_api.rs"]
pub(crate) mod preference_cas;
#[path = "skills_api.rs"]
pub(crate) mod skills;

#[path = "reconciliation_api.rs"]
pub(crate) mod reconciliation;

#[path = "artifact_api.rs"]
pub(crate) mod artifacts;

#[path = "credentials_api.rs"]
pub(crate) mod credentials;

/// Serialize a sensitive request without a serde_json::Value copy. The temporary Rust JSON buffer
/// is zeroized before awaiting the browser request; JS/network buffers remain browser-owned.
#[cfg(target_arch = "wasm32")]
fn secret_json<T: serde::Serialize>(
    builder: gloo_net::http::RequestBuilder,
    value: &T,
) -> Result<gloo_net::http::Request, ApiError> {
    let body = zeroize::Zeroizing::new(
        serde_json::to_string(value).map_err(|_| ApiError::InvalidResponse)?,
    );
    builder
        .header("Content-Type", "application/json")
        .body(body.as_str())
        .map_err(|_| ApiError::InvalidResponse)
}

use openbot_contracts::agent::{
    AgentConnectionTestRequest, AgentConnectionVerdict, AgentMutationRequest, AgentProfile,
    CallbackTokenIssued,
};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::agent::{AgentProfileResponse, AgentProfilesResponse};
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::audit::AuditEventView;
use openbot_contracts::audit::AuditPage;
use openbot_contracts::auth::{AuthProviderId, AuthenticationCapabilities};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::auth::{
    AuthenticationStartResponse, EnterpriseSsoRoutingAccepted, EnterpriseSsoStartRequest,
    MAX_SSO_ROUTING_EMAIL_BYTES,
};
use openbot_contracts::budget::{RunCostBudgetPreference, RunCostCapInput};
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::command::MAX_CHANNEL_ROUTING_REASON_CODE_POINTS;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::command::ThreadRunCancellationState;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::command::{
    BeginThreadRunBody, CreateChannelRequest, RouteChannelRequest, ThreadMinted, ThreadStatus,
};
use openbot_contracts::command::{
    ChannelDetail, ChannelPage, ChannelRoutingDecision, MAX_THREAD_MESSAGE_BYTES,
    ThreadConversationSnapshot, ThreadRunAnchor, ThreadRunCancellation, ThreadRunStarted,
};
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::components::{
    BOT_ACTIVITY_FUNCTION_NAME, ComponentDecisionRefusal, ComponentFunctionData,
    RECENT_REFUSALS_FUNCTION_NAME, is_component_human_decision_name,
    validate_component_human_decision_arguments,
};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::components::{
    ComponentAgentGrantRequest, ComponentDraftRequest, ComponentFunctionGrantRequest,
    ComponentGovernanceReceipt, ComponentPublicationRequest,
};
use openbot_contracts::components::{
    ComponentCatalogueAdded, ComponentCatalogueRequest, ComponentDataFunctions, ComponentDecision,
    ComponentDecisionRequest, ComponentFunctionCall, ComponentFunctionCallRequest,
    ComponentHumanDecisionAnswer, ComponentHumanDecisionResolved, ComponentRecord,
    ComponentRecords, GrantedCompiledComponents, MAX_COMPONENT_DESCRIPTION_BYTES,
    PendingComponentHumanDecisions, compiled_component_manifest, component_data_function_manifest,
};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::identity_provider::{IdentityProviderRemoved, IdentityProvidersResponse};
use openbot_contracts::identity_provider::{
    MAX_IDENTITY_PROVIDER_DOMAINS, MAX_IDENTITY_PROVIDER_ID_BYTES, RegisterIdentityProviderRequest,
    RegisteredIdentityProvider,
};
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::identity_provider::{
    MAX_IDENTITY_PROVIDER_URL_BYTES, MAX_IDENTITY_PROVIDERS,
};
use openbot_contracts::ids::{BotId, ChannelId, RunId, ThreadId};
use openbot_contracts::mcp::{McpConnectionDisconnected, McpConnections, McpOAuthAuthorization};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::memory::UpdateMemoryControl;
use openbot_contracts::memory::{
    CorrectMemory, MemoryControl, MemoryMutation, MemoryPage, MemoryRecord,
};
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::memory::{MemoryScope, MemoryStatus};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::people::{
    AdminState, AdminStatus, ChangePersonAccess, ChangePersonRole, CurrentUserResponse,
    PersonResponse,
};
use openbot_contracts::people::{CurrentUser, PeoplePage, Person};
use openbot_contracts::policy::ActionPolicyDocument;
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::policy::ActionPolicyResponse;
use openbot_contracts::remote_interrupt::{
    PendingRemoteInterrupts, RemoteInterruptAnswer, RemoteInterruptResolved,
    is_remote_interrupt_request_id,
};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::sandboxed::SandboxedComponentDeleted;
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::sandboxed::{PublishedSandboxedComponent, SandboxedComponentRecord};
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponents, SandboxedComponentResponse, SandboxedComponents,
    SaveSandboxedComponentRequest, is_sandboxed_component_name,
};
use openbot_contracts::tool::{PendingToolApprovals, ToolApprovalDecision, ToolApprovalResolved};
use openbot_contracts::ui::{SessionStatus, UiPreferences, UpdateUiPreferences};

/// Stable, payload-free failure categories suitable for localized presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// Local validation or request construction failed before any HTTP dispatch.
    NotSubmitted,
    /// The browser could not complete the request.
    Network,
    /// The current session is absent or expired.
    Unauthorized,
    /// The actor is not allowed to access the approval.
    Forbidden,
    /// The authenticated actor cannot see the requested resource.
    NotFound,
    /// The approval was concurrently resolved or invalidated.
    Conflict,
    /// A host accepted a write but cannot return its result after an authority change.
    /// Read current authoritative state before another write; do not replay the old request.
    ReconciliationRequired,
    /// The Server response did not match the closed contract.
    InvalidResponse,
    /// The Server returned another unsuccessful status.
    Server,
    /// The browser-only API was called by a non-WASM target.
    Unavailable,
}

// Only pure preflight call sites use this classification. HTTP receipts never do.
fn not_submitted(error: ApiError) -> ApiError {
    if error == ApiError::InvalidResponse {
        ApiError::NotSubmitted
    } else {
        error
    }
}

/// Roster page size; the application still owns the authoritative 1..=200 clamp.
pub const CHANNEL_PAGE_SIZE: u32 = 50;
/// Memory page size; the application owns the authoritative clamp.
pub const MEMORY_PAGE_SIZE: u32 = 50;
/// Audit page size; application clamps the authoritative maximum to 100.
pub const AUDIT_PAGE_SIZE: u32 = 50;
/// People page size; the application owns the authoritative 1..=200 clamp.
pub const PEOPLE_PAGE_SIZE: u32 = 50;

/// Announce the exact build-owned compiled component manifest; existing governance is untouched.
pub async fn announce_component_catalogue() -> Result<ComponentCatalogueAdded, ApiError> {
    let request = ComponentCatalogueRequest {
        components: compiled_component_manifest(),
    };
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(
            Request::put("/api/components/catalogue")
                .json(&request)
                .map_err(|_| ApiError::InvalidResponse)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let added = crate::api::request::Request::decode::<ComponentCatalogueAdded>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_catalogue_added(&request, &added)?;
        Ok(added)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = request;
        Err(ApiError::Unavailable)
    }
}

/// Load all durable compiled-component governance rows for authenticated Settings/Admin views.
pub async fn load_components() -> Result<ComponentRecords, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/components")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let records = crate::api::request::Request::decode::<ComponentRecords>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_component_records(&records)?;
        Ok(records)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Grant or withhold one component for one Agent; success returns the authoritative row.
pub async fn set_component_agent_grant(
    name: &str,
    agent_id: &str,
    granted: bool,
) -> Result<ComponentRecord, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Components,
        name.to_owned(),
        set_component_agent_grant_write(name, agent_id, granted),
    )
    .await
}

async fn set_component_agent_grant_write(
    name: &str,
    agent_id: &str,
    granted: bool,
) -> Result<ComponentRecord, ApiError> {
    validate_component_name(name).map_err(not_submitted)?;
    validate_agent_id(agent_id).map_err(not_submitted)?;
    let base = format!("/api/components/{}", encode_url_component(name));
    let path = if granted {
        format!("{base}/grants")
    } else {
        format!("{base}/grants/{}", encode_url_component(agent_id))
    };
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let response = if granted {
            Request::post(&path)
                .json(&ComponentAgentGrantRequest {
                    agent_id: BotId::new(agent_id),
                })
                .map_err(|_| ApiError::NotSubmitted)?
                .send()
                .await
        } else {
            Request::delete(&path).send().await
        }
        .map_err(|_| ApiError::Network)?;
        let component = component_governance_response(response, name).await?;
        if component.withheld_from.iter().any(|id| id == agent_id) == granted {
            return Err(ApiError::InvalidResponse);
        }
        Ok(component)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

/// Grant or revoke one build-owned data function for one component.
pub async fn set_component_function_grant(
    name: &str,
    function: &str,
    granted: bool,
) -> Result<ComponentRecord, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Components,
        name.to_owned(),
        set_component_function_grant_write(name, function, granted),
    )
    .await
}

async fn set_component_function_grant_write(
    name: &str,
    function: &str,
    granted: bool,
) -> Result<ComponentRecord, ApiError> {
    validate_component_name(name).map_err(not_submitted)?;
    validate_component_name(function).map_err(not_submitted)?;
    if !component_data_function_manifest()
        .iter()
        .any(|entry| entry.name == function)
    {
        return Err(ApiError::NotSubmitted);
    }
    let base = format!("/api/components/{}", encode_url_component(name));
    let path = if granted {
        format!("{base}/functions")
    } else {
        format!("{base}/functions/{}", encode_url_component(function))
    };
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let response = if granted {
            Request::post(&path)
                .json(&ComponentFunctionGrantRequest {
                    function: function.to_owned(),
                })
                .map_err(|_| ApiError::NotSubmitted)?
                .send()
                .await
        } else {
            Request::delete(&path).send().await
        }
        .map_err(|_| ApiError::Network)?;
        let component = component_governance_response(response, name).await?;
        if component.functions.iter().any(|value| value == function) != granted {
            return Err(ApiError::InvalidResponse);
        }
        Ok(component)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

/// Publish or withdraw one compiled component.
pub async fn set_component_publication(
    name: &str,
    published: bool,
) -> Result<ComponentRecord, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Components,
        name.to_owned(),
        set_component_publication_write(name, published),
    )
    .await
}

async fn set_component_publication_write(
    name: &str,
    published: bool,
) -> Result<ComponentRecord, ApiError> {
    validate_component_name(name).map_err(not_submitted)?;
    let path = format!("/api/components/{}/publication", encode_url_component(name));
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let response = Request::send(
            Request::post(&path)
                .json(&ComponentPublicationRequest { published })
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        let component = component_governance_response(response, name).await?;
        if component.published != published {
            return Err(ApiError::InvalidResponse);
        }
        Ok(component)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, published);
        Err(ApiError::Unavailable)
    }
}

/// Save one compiled model-facing draft without publishing it.
pub async fn save_component_draft(
    name: &str,
    description: &str,
) -> Result<ComponentRecord, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Components,
        name.to_owned(),
        save_component_draft_write(name, description),
    )
    .await
}

async fn save_component_draft_write(
    name: &str,
    description: &str,
) -> Result<ComponentRecord, ApiError> {
    validate_component_name(name).map_err(not_submitted)?;
    let description = openbot_contracts::text::trim_ecmascript(description);
    if description.is_empty()
        || description.len() > MAX_COMPONENT_DESCRIPTION_BYTES
        || description.as_bytes().contains(&0)
    {
        return Err(ApiError::NotSubmitted);
    }
    let path = format!("/api/components/{}/draft", encode_url_component(name));
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let response = Request::send(
            Request::put(&path)
                .json(&ComponentDraftRequest {
                    description: description.to_owned(),
                })
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        let component = component_governance_response(response, name).await?;
        if component.draft_description != description {
            return Err(ApiError::InvalidResponse);
        }
        Ok(component)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, description);
        Err(ApiError::Unavailable)
    }
}

#[cfg(target_arch = "wasm32")]
async fn component_governance_response(
    response: gloo_net::http::Response,
    expected_name: &str,
) -> Result<ComponentRecord, ApiError> {
    if response.status() != 200 {
        return Err(status_error(response.status()));
    }
    let receipt = crate::api::request::Request::decode::<ComponentGovernanceReceipt>(&response)
        .await
        .map_err(|_| ApiError::InvalidResponse)?;
    validate_component_record(&receipt.component)?;
    if receipt.component.name != expected_name {
        return Err(ApiError::InvalidResponse);
    }
    Ok(receipt.component)
}

/// Load administrator-only sandbox drafts and sample arguments.
pub async fn load_sandboxed_components() -> Result<SandboxedComponents, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/sandboxed")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let components = crate::api::request::Request::decode::<SandboxedComponents>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_sandboxed_components(&components)?;
        Ok(components)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Load published sandbox source; the response type cannot contain drafts or sample arguments.
pub async fn load_published_sandboxed_components() -> Result<PublishedSandboxedComponents, ApiError>
{
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/sandboxed/published")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let components =
            crate::api::request::Request::decode::<PublishedSandboxedComponents>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        validate_published_sandboxed_components(&components)?;
        Ok(components)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Save one fresh-admin sandbox draft without publishing it.
pub async fn save_sandboxed_component_draft(
    request: &SaveSandboxedComponentRequest,
) -> Result<SandboxedComponentResponse, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Sandbox,
        format!("custom_{}", request.slug),
        save_sandboxed_component_draft_write(request),
    )
    .await
}

/// Existing draft CAS with its own exact closed conflict and explicit recovery ownership.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn save_sandboxed_component_draft_cas(
    request: &SaveSandboxedComponentRequest,
    mode: crate::configuration_writes::SandboxCasMode,
) -> Result<SandboxedComponentResponse, crate::configuration_writes::CasWriteError> {
    use crate::configuration_writes::{CasWriteError, track_sandbox_cas};
    let Some(expected) = request.expected_revision.filter(|revision| *revision > 0) else {
        return Err(CasWriteError::Rejected(ApiError::NotSubmitted));
    };
    validate_sandboxed_request(request)
        .map_err(|_| CasWriteError::Rejected(ApiError::NotSubmitted))?;
    track_sandbox_cas(format!("custom_{}", request.slug), expected, mode, async {
        #[cfg(target_arch = "wasm32")]
        {
            use crate::api::request::Request;
            let response = Request::send(
                Request::post("/api/sandboxed")
                    .json(request)
                    .map_err(|_| CasWriteError::Rejected(ApiError::NotSubmitted))?,
            )
            .await
            .map_err(CasWriteError::Unknown)?;
            if response.status() == 409 {
                let snapshot =
                    Request::decode::<openbot_contracts::revision::RevisionSnapshot>(&response)
                        .await
                        .map_err(|_| CasWriteError::Unknown(ApiError::InvalidResponse))?;
                if snapshot.current_revision() <= expected {
                    return Err(CasWriteError::Unknown(ApiError::InvalidResponse));
                }
                return Err(CasWriteError::Conflict(snapshot));
            }
            if response.status() != 200 {
                let error = status_error(response.status());
                return Err(
                    if matches!(
                        error,
                        ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound
                    ) {
                        CasWriteError::Rejected(error)
                    } else {
                        CasWriteError::Unknown(error)
                    },
                );
            }
            let saved = Request::decode::<SandboxedComponentResponse>(&response)
                .await
                .map_err(CasWriteError::Unknown)?;
            validate_sandboxed_record(&saved.component).map_err(CasWriteError::Unknown)?;
            validate_sandboxed_draft_receipt(request, &saved.component)
                .map_err(CasWriteError::Unknown)?;
            Ok(saved)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Err(CasWriteError::Unknown(ApiError::Unavailable))
        }
    })
    .await
}

async fn save_sandboxed_component_draft_write(
    request: &SaveSandboxedComponentRequest,
) -> Result<SandboxedComponentResponse, ApiError> {
    validate_sandboxed_request(request).map_err(not_submitted)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(
            Request::post("/api/sandboxed")
                .json(request)
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let saved = crate::api::request::Request::decode::<SandboxedComponentResponse>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_sandboxed_record(&saved.component)?;
        validate_sandboxed_draft_receipt(request, &saved.component)?;
        Ok(saved)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Save the editor state, then publish exactly that stored draft as the next revision.
pub async fn publish_sandboxed_component(
    request: &SaveSandboxedComponentRequest,
) -> Result<SandboxedComponentResponse, ApiError> {
    crate::configuration_writes::track_with_phase(
        crate::configuration_writes::ConfigurationKind::Sandbox,
        format!("custom_{}", request.slug),
        |phase| publish_sandboxed_component_write(request, phase),
    )
    .await
}

async fn publish_sandboxed_component_write(
    request: &SaveSandboxedComponentRequest,
    phase: crate::configuration_writes::WritePhase,
) -> Result<SandboxedComponentResponse, ApiError> {
    let saved = save_sandboxed_component_draft_write(request).await?;
    let expected_revision = saved.component.editing_revision;
    let name = saved.component.name.clone();
    phase.sandbox_draft_saved();
    if !is_sandboxed_component_name(&name) {
        return Err(ApiError::InvalidResponse);
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = format!("/api/sandboxed/{}/publish", encode_url_component(&name));
        let response = Request::send(
            Request::post(&path)
                .json(
                    &openbot_contracts::sandboxed::SandboxedComponentRevisionRequest {
                        expected_revision,
                    },
                )
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let published =
            crate::api::request::Request::decode::<SandboxedComponentResponse>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        validate_sandboxed_record(&published.component)?;
        validate_sandboxed_publication_receipt(request, &saved.component, &published.component)?;
        Ok(published)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = expected_revision;
        Err(ApiError::Unavailable)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_sandboxed_draft_receipt(
    request: &SaveSandboxedComponentRequest,
    saved: &SandboxedComponentRecord,
) -> Result<(), ApiError> {
    validate_sandboxed_draft_fields(request, saved)?;
    if request.expected_revision.unwrap_or(0).checked_add(1) != Some(saved.editing_revision) {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_sandboxed_draft_fields(
    request: &SaveSandboxedComponentRequest,
    saved: &SandboxedComponentRecord,
) -> Result<(), ApiError> {
    if saved.name != format!("custom_{}", request.slug)
        || saved.title != request.title
        || saved.draft_description != request.description
        || saved.draft_html != request.html
        || saved.draft_css != request.css
        || saved.draft_js_functions != request.js_functions
        || saved.draft_argument_schema != request.argument_schema
        || saved.sample_arguments != request.sample_arguments
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_sandboxed_publication_receipt(
    request: &SaveSandboxedComponentRequest,
    saved: &SandboxedComponentRecord,
    published: &SandboxedComponentRecord,
) -> Result<(), ApiError> {
    validate_sandboxed_draft_fields(request, published)?;
    if !published.published
        || saved.editing_revision.checked_add(1) != Some(published.editing_revision)
        || saved.revision.checked_add(1) != Some(published.revision)
        || published.published_html.as_ref() != Some(&request.html)
        || published.published_css.as_ref() != Some(&request.css)
        || published.published_js_functions.as_ref() != Some(&request.js_functions)
        || published.published_argument_schema.as_ref() != Some(&request.argument_schema)
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

/// Delete one fresh-admin browser-authored component.
pub async fn delete_sandboxed_component(
    name: &str,
    expected_revision: i64,
) -> Result<(), ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Sandbox,
        name.to_owned(),
        delete_sandboxed_component_write(name, expected_revision),
    )
    .await
}

async fn delete_sandboxed_component_write(
    name: &str,
    expected_revision: i64,
) -> Result<(), ApiError> {
    if expected_revision <= 0 || !is_sandboxed_component_name(name) {
        return Err(ApiError::NotSubmitted);
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = format!("/api/sandboxed/{}", encode_url_component(name));
        let response = Request::send(
            Request::delete(&path)
                .json(
                    &openbot_contracts::sandboxed::SandboxedComponentRevisionRequest {
                        expected_revision,
                    },
                )
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let deleted = crate::api::request::Request::decode::<SandboxedComponentDeleted>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if !deleted.ok {
            return Err(ApiError::InvalidResponse);
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Load the current build's published, non-withheld renderer grants for one Agent.
pub async fn load_components_for_agent(
    agent_id: &BotId,
) -> Result<GrantedCompiledComponents, ApiError> {
    validate_bounded_identifier(agent_id.as_str(), 256)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = format!(
            "/api/components/for-agent/{}",
            encode_url_component(agent_id.as_str())
        );
        let response = Request::send(Request::get(&path)).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let granted = crate::api::request::Request::decode::<GrantedCompiledComponents>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_granted_components(&granted)?;
        Ok(granted)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Re-authorize one compiled renderer immediately before accepting its tool call.
pub async fn decide_component(
    name: &str,
    agent_id: &BotId,
    functions: &[String],
) -> Result<ComponentDecision, ApiError> {
    validate_component_name(name)?;
    validate_bounded_identifier(agent_id.as_str(), 256)?;
    if functions.len() > 1024 {
        return Err(ApiError::InvalidResponse);
    }
    let mut previous = None::<&str>;
    for function in functions {
        validate_component_name(function)?;
        if previous.is_some_and(|previous| previous >= function.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(function);
    }
    let request = ComponentDecisionRequest {
        agent_id: agent_id.clone(),
        functions: functions.to_vec(),
    };
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = format!("/api/components/{}/decision", encode_url_component(name));
        let response = Request::send(
            Request::post(&path)
                .json(&request)
                .map_err(|_| ApiError::InvalidResponse)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let decision = crate::api::request::Request::decode::<ComponentDecision>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_component_decision(&decision, functions)?;
        Ok(decision)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = request;
        Err(ApiError::Unavailable)
    }
}

/// Load the exact build-owned component data-function registry.
pub async fn load_component_data_functions() -> Result<ComponentDataFunctions, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/components/functions")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let functions = crate::api::request::Request::decode::<ComponentDataFunctions>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_component_data_functions(&functions)?;
        Ok(functions)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Execute one component-owned data read through the deployment's runtime checks.
pub async fn call_component_function(
    component: &str,
    agent_id: &BotId,
    function: &str,
    args: serde_json::Value,
) -> Result<ComponentFunctionCall, ApiError> {
    validate_component_name(component)?;
    validate_bounded_identifier(agent_id.as_str(), 256)?;
    validate_component_name(function)?;
    let request = ComponentFunctionCallRequest {
        agent_id: agent_id.clone(),
        function: function.to_owned(),
        args,
    };
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = format!("/api/components/{}/call", encode_url_component(component));
        let response = Request::send(
            Request::post(&path)
                .json(&request)
                .map_err(|_| ApiError::InvalidResponse)?,
        )
        .await?;
        if !matches!(response.status(), 200 | 502) {
            return Err(status_error(response.status()));
        }
        let result = crate::api::request::Request::decode::<ComponentFunctionCall>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_component_function_call(&result, function, response.status())?;
        Ok(result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = request;
        Err(ApiError::Unavailable)
    }
}

/// Load the current actor's durable component decisions without browser cache.
pub async fn list_pending_component_human_decisions()
-> Result<PendingComponentHumanDecisions, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/components/human-decisions")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let decisions =
            crate::api::request::Request::decode::<PendingComponentHumanDecisions>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        validate_pending_component_human_decisions(&decisions)?;
        Ok(decisions)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Commit one closed answer to an actor-owned durable component decision.
pub async fn answer_component_human_decision(
    decision_id: &str,
    answer: &ComponentHumanDecisionAnswer,
) -> Result<ComponentHumanDecisionResolved, ApiError> {
    let path = component_human_decision_answer_path(decision_id)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(
            Request::post(&path)
                .json(answer)
                .map_err(|_| ApiError::InvalidResponse)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let resolved =
            crate::api::request::Request::decode::<ComponentHumanDecisionResolved>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        if resolved.decision_id != decision_id || &resolved.answer != answer {
            return Err(ApiError::InvalidResponse);
        }
        Ok(resolved)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, answer);
        Err(ApiError::Unavailable)
    }
}

/// Load current-actor pending remote AG-UI interrupts without browser cache.
pub async fn list_pending_remote_interrupts() -> Result<PendingRemoteInterrupts, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/me/remote-interrupts")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let pending = crate::api::request::Request::decode::<PendingRemoteInterrupts>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_pending_remote_interrupts(&pending)?;
        Ok(pending)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Commit one closed answer to a server-minted remote interrupt handle.
pub async fn answer_remote_interrupt(
    request_id: &str,
    answer: &RemoteInterruptAnswer,
) -> Result<RemoteInterruptResolved, ApiError> {
    let path = remote_interrupt_answer_path(request_id)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(
            Request::put(&path)
                .json(answer)
                .map_err(|_| ApiError::InvalidResponse)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let resolved = crate::api::request::Request::decode::<RemoteInterruptResolved>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if resolved.request_id != request_id || resolved.status != answer.status {
            return Err(ApiError::InvalidResponse);
        }
        Ok(resolved)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, answer);
        Err(ApiError::Unavailable)
    }
}

/// Load reviewed user-OAuth servers and the current actor's connection rows.
pub async fn load_mcp_connections() -> Result<McpConnections, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/plugins/connections")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let page = crate::api::request::Request::decode::<McpConnections>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_mcp_connections(&page)?;
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Ask the Server to mint OAuth state/PKCE and validate its navigation receipt.
pub async fn begin_mcp_connection(server_id: &str) -> Result<McpOAuthAuthorization, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::ToolConnections,
        server_id.to_owned(),
        begin_mcp_connection_write(server_id),
    )
    .await
}

async fn begin_mcp_connection_write(server_id: &str) -> Result<McpOAuthAuthorization, ApiError> {
    validate_mcp_server_id(server_id).map_err(not_submitted)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = mcp_connect_path(server_id).map_err(not_submitted)?;
        let response = Request::send(Request::post(&path)).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let authorization =
            crate::api::request::Request::decode::<McpOAuthAuthorization>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        validate_authorization_target(&authorization.authorization_url)?;
        Ok(authorization)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = server_id;
        Err(ApiError::Unavailable)
    }
}

/// Tombstone one actor-owned connection and verify the exact Server receipt.
pub async fn disconnect_mcp_connection(
    server_id: &str,
) -> Result<McpConnectionDisconnected, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::ToolConnections,
        server_id.to_owned(),
        disconnect_mcp_connection_write(server_id),
    )
    .await
}

async fn disconnect_mcp_connection_write(
    server_id: &str,
) -> Result<McpConnectionDisconnected, ApiError> {
    validate_mcp_server_id(server_id).map_err(not_submitted)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = mcp_disconnect_path(server_id).map_err(not_submitted)?;
        let response = Request::send(Request::delete(&path)).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let receipt = crate::api::request::Request::decode::<McpConnectionDisconnected>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if receipt.server_id != server_id {
            return Err(ApiError::InvalidResponse);
        }
        Ok(receipt)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = server_id;
        Err(ApiError::Unavailable)
    }
}

/// Create one private channel for a single URL-selected recipient.
pub async fn create_channel(agent_id: &BotId) -> Result<ChannelDetail, ApiError> {
    validate_agent_id(agent_id.as_str())?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let request = Request::post("/api/channels")
            .json(&CreateChannelRequest {
                agent_ids: vec![agent_id.clone()],
            })
            .map_err(|_| ApiError::InvalidResponse)?;
        let response = Request::send(request).await?;
        if response.status() != 201 {
            return Err(status_error(response.status()));
        }
        let channel = crate::api::request::Request::decode::<
            openbot_contracts::command::ChannelDetailResponse,
        >(&response)
        .await
        .map(|response| response.channel)
        .map_err(|_| ApiError::InvalidResponse)?;
        if channel.agent_ids.as_slice() != [agent_id.clone()]
            || channel.thread_id.is_none()
            || !channel.active
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(channel)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = agent_id;
        Err(ApiError::Unavailable)
    }
}

/// Validate or infer one first-message recipient through the native routing API.
pub async fn route_channel_message(
    text: &str,
    agent_id: Option<&BotId>,
) -> Result<ChannelRoutingDecision, ApiError> {
    let text = openbot_contracts::text::trim_ecmascript(text);
    if text.is_empty() || text.len() > MAX_THREAD_MESSAGE_BYTES || text.as_bytes().contains(&0) {
        return Err(ApiError::InvalidResponse);
    }
    if let Some(agent_id) = agent_id {
        validate_agent_id(agent_id.as_str())?;
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let request = Request::post("/api/route")
            .json(&RouteChannelRequest {
                text: text.to_owned(),
                agent_id: agent_id.cloned(),
            })
            .map_err(|_| ApiError::InvalidResponse)?;
        let response = Request::send(request).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let decision = crate::api::request::Request::decode::<ChannelRoutingDecision>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_routing_decision(agent_id, &decision)?;
        Ok(decision)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (text, agent_id);
        Err(ApiError::Unavailable)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_routing_decision(
    explicit: Option<&BotId>,
    decision: &ChannelRoutingDecision,
) -> Result<(), ApiError> {
    validate_agent_id(decision.agent_id.as_str())?;
    if decision.name.is_empty()
        || decision.name.len() > 512
        || decision.name.chars().any(char::is_control)
        || decision.reason.is_empty()
        || decision.reason.chars().count() > MAX_CHANNEL_ROUTING_REASON_CODE_POINTS
        || decision.reason.chars().any(char::is_control)
    {
        return Err(ApiError::InvalidResponse);
    }
    match explicit {
        Some(explicit)
            if decision.agent_id == *explicit && decision.via_mention && !decision.fallback =>
        {
            Ok(())
        }
        None if !decision.via_mention => Ok(()),
        _ => Err(ApiError::InvalidResponse),
    }
}

/// Begin one durable native run against an exact channel or direct-Bot anchor.
pub async fn begin_thread_run(
    thread_id: &ThreadId,
    agent_id: &BotId,
    run_id: &RunId,
    anchor: ThreadRunAnchor,
    message: &str,
) -> Result<ThreadRunStarted, ApiError> {
    begin_thread_run_with_skills(thread_id, agent_id, run_id, anchor, message, &[]).await
}

/// Begin a run with explicit ordered skill selections. Rust resolves granted instruction snapshots.
pub async fn begin_thread_run_with_skills(
    thread_id: &ThreadId,
    agent_id: &BotId,
    run_id: &RunId,
    anchor: ThreadRunAnchor,
    message: &str,
    selected_skill_slugs: &[String],
) -> Result<ThreadRunStarted, ApiError> {
    begin_thread_run_with_skills_and_model(
        thread_id,
        agent_id,
        run_id,
        anchor,
        message,
        selected_skill_slugs,
        None,
    )
    .await
}

/// Begin a run with ordered skills and one explicitly frozen v1 model connection revision.
pub async fn begin_thread_run_with_skills_and_model(
    thread_id: &ThreadId,
    agent_id: &BotId,
    run_id: &RunId,
    anchor: ThreadRunAnchor,
    message: &str,
    selected_skill_slugs: &[String],
    model_selection: Option<&openbot_contracts::model_connections::RunModelSelection>,
) -> Result<ThreadRunStarted, ApiError> {
    if !openbot_contracts::command::valid_selected_skill_slugs(selected_skill_slugs) {
        return Err(ApiError::InvalidResponse);
    }
    if model_selection.is_some_and(|selection| !selection.is_valid()) {
        return Err(ApiError::InvalidResponse);
    }
    validate_agent_id(agent_id.as_str())?;
    if let ThreadRunAnchor::Channel { channel_id } = &anchor {
        validate_channel_id(channel_id.as_str())?;
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = thread_run_path(thread_id.as_str())?;
        let request = Request::post(&path)
            .json(&BeginThreadRunBody {
                model_selection: model_selection.cloned(),
                run_id: run_id.clone(),
                bot_id: agent_id.clone(),
                anchor,
                message: message.to_owned(),
                selected_skill_slugs: selected_skill_slugs.to_vec(),
                artifact_refs: Vec::new(),
            })
            .map_err(|_| ApiError::InvalidResponse)?;
        let response = Request::send(request).await?;
        let status = response.status();
        if !matches!(status, 200 | 201) {
            return Err(status_error(status));
        }
        let started = crate::api::request::Request::decode::<ThreadRunStarted>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if started.thread_id != *thread_id
            || started.run_id != *run_id
            || started.replayed != (status == 200)
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(started)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (
            thread_id,
            agent_id,
            run_id,
            anchor,
            message,
            selected_skill_slugs,
            model_selection,
        );
        Err(ApiError::Unavailable)
    }
}

/// Begin the first durable native run for a channel-created thread.
pub async fn begin_channel_run(
    thread_id: &ThreadId,
    channel_id: &ChannelId,
    agent_id: &BotId,
    run_id: &RunId,
    message: &str,
) -> Result<ThreadRunStarted, ApiError> {
    begin_thread_run(
        thread_id,
        agent_id,
        run_id,
        ThreadRunAnchor::Channel {
            channel_id: channel_id.clone(),
        },
        message,
    )
    .await
}

/// Persist cancellation for the exact active native run; terminal still arrives via snapshot/SSE.
pub async fn cancel_thread_run(
    thread_id: &ThreadId,
    run_id: &RunId,
) -> Result<ThreadRunCancellation, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = thread_cancel_path(thread_id.as_str(), run_id.as_str())?;
        let response = Request::send(Request::post(&path)).await?;
        let status = response.status();
        if !matches!(status, 200 | 202) {
            return Err(status_error(status));
        }
        let reply = crate::api::request::Request::decode::<ThreadRunCancellation>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        let status_matches = matches!(
            (status, reply.state),
            (
                202,
                ThreadRunCancellationState::Requested
                    | ThreadRunCancellationState::AlreadyRequested
            ) | (200, ThreadRunCancellationState::AlreadyTerminal)
        );
        if reply.thread_id != *thread_id || reply.run_id != *run_id || !status_matches {
            return Err(ApiError::InvalidResponse);
        }
        Ok(reply)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (thread_id, run_id);
        Err(ApiError::Unavailable)
    }
}

/// Mint one browser-CSPRNG-backed durable idempotency key.
#[must_use]
pub fn mint_run_id() -> RunId {
    RunId::new(uuid::Uuid::now_v7().to_string())
}

/// Ask the Server to mint a deployment-owned native thread identity.
pub async fn mint_thread_id() -> Result<ThreadId, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::post("/api/threads/mint")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<ThreadMinted>(&response)
            .await
            .map(|minted| minted.thread_id)
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Recheck whether one remembered native thread is still known to the current authoritative scope.
pub async fn load_thread_status(thread_id: &ThreadId) -> Result<bool, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = thread_status_path(thread_id.as_str())?;
        let response = Request::send(Request::get(&path)).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<ThreadStatus>(&response)
            .await
            .map(|status| status.known)
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = thread_id;
        Err(ApiError::Unavailable)
    }
}

/// Load one atomic durable history/active-run/event-cursor snapshot.
pub async fn load_thread_conversation(
    thread_id: &ThreadId,
) -> Result<ThreadConversationSnapshot, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = thread_conversation_path(thread_id.as_str())?;
        let response = Request::send(Request::get(&path)).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let snapshot =
            crate::api::request::Request::decode::<ThreadConversationSnapshot>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        let active_shape_matches =
            snapshot.active_run_id.is_some() == snapshot.active_run_state.is_some();
        let cancellable_matches = !snapshot.active_run_cancellable
            || matches!(
                snapshot.active_run_state,
                Some(openbot_contracts::command::ThreadForegroundRunState::Running)
            );
        if !active_shape_matches
            || !cancellable_matches
            || (snapshot.active_run_id.is_none() && !snapshot.active_run_text.is_empty())
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(snapshot)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = thread_id;
        Err(ApiError::Unavailable)
    }
}

/// Load the current actor's authoritative visible or per-user-hidden coworker roster.
pub async fn list_agents(hidden: bool) -> Result<Vec<AgentProfile>, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = if hidden {
            "/api/agents?hidden=true"
        } else {
            "/api/agents"
        };
        let response = Request::send(Request::get(path)).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<AgentProfilesResponse>(&response)
            .await
            .map(|response| response.agents)
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = hidden;
        Err(ApiError::Unavailable)
    }
}

/// The current roster load owns both reads' browser cancellation signal.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn list_agents_with_abort_signal(
    hidden: bool,
    signal: &web_sys::AbortSignal,
) -> Result<Vec<AgentProfile>, ApiError> {
    use crate::api::request::Request;

    let path = if hidden {
        "/api/agents?hidden=true"
    } else {
        "/api/agents"
    };
    let response = Request::send(Request::get(path).abort_signal(Some(signal))).await?;
    if !response.ok() {
        return Err(status_error(response.status()));
    }
    crate::api::request::Request::decode::<AgentProfilesResponse>(&response)
        .await
        .map(|response| response.agents)
        .map_err(|_| ApiError::InvalidResponse)
}

/// Load one current-actor-visible coworker profile.
pub async fn load_agent(agent_id: &str) -> Result<AgentProfile, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = agent_detail_path(agent_id)?;
        let response = Request::send(Request::get(&path)).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<AgentProfileResponse>(&response)
            .await
            .map(|response| response.agent)
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = agent_id;
        Err(ApiError::Unavailable)
    }
}

/// The selected profile panel owns this read's browser cancellation signal.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn load_agent_with_abort_signal(
    agent_id: &str,
    signal: &web_sys::AbortSignal,
) -> Result<AgentProfile, ApiError> {
    use crate::api::request::Request;

    let path = agent_detail_path(agent_id)?;
    let response = Request::send(Request::get(&path).abort_signal(Some(signal))).await?;
    if !response.ok() {
        return Err(status_error(response.status()));
    }
    crate::api::request::Request::decode::<AgentProfileResponse>(&response)
        .await
        .map(|response| response.agent)
        .map_err(|_| ApiError::InvalidResponse)
}

/// Create one caller-owned Agent; response is the authoritative profile.
pub async fn create_agent(request: AgentMutationRequest) -> Result<AgentProfile, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Agents,
        "$create".to_owned(),
        create_agent_write(request),
    )
    .await
}

async fn create_agent_write(request: AgentMutationRequest) -> Result<AgentProfile, ApiError> {
    agent_profile_mutation("/api/agents", "POST", request, None).await
}

/// Update one manageable Agent; response is the authoritative profile.
pub async fn update_agent(
    agent_id: &str,
    request: AgentMutationRequest,
) -> Result<AgentProfile, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Agents,
        agent_id.to_owned(),
        update_agent_write(agent_id, request),
    )
    .await
}

async fn update_agent_write(
    agent_id: &str,
    request: AgentMutationRequest,
) -> Result<AgentProfile, ApiError> {
    let path = agent_detail_path(agent_id).map_err(not_submitted)?;
    agent_profile_mutation(&path, "PATCH", request, Some(agent_id)).await
}

/// Duplicate one visible Agent into a new private managed-slot profile.
pub async fn duplicate_agent(agent_id: &str) -> Result<AgentProfile, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Agents,
        agent_id.to_owned(),
        duplicate_agent_write(agent_id),
    )
    .await
}

async fn duplicate_agent_write(agent_id: &str) -> Result<AgentProfile, ApiError> {
    validate_agent_id(agent_id).map_err(not_submitted)?;
    let path = format!("/api/agents/{}/duplicate", encode_url_component(agent_id));
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let response = Request::send(Request::post(&path)).await?;
        let profile = agent_profile_response(response, 201).await?;
        validate_agent_duplicate_receipt(agent_id, &profile)?;
        Ok(profile)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

/// Hide/unhide one visible Agent for only the current actor.
pub async fn set_agent_hidden(agent_id: &str, hidden: bool) -> Result<(), ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Agents,
        agent_id.to_owned(),
        set_agent_hidden_write(agent_id, hidden),
    )
    .await
}

async fn set_agent_hidden_write(agent_id: &str, hidden: bool) -> Result<(), ApiError> {
    validate_agent_id(agent_id).map_err(not_submitted)?;
    let path = format!(
        "/api/agents/{}/{}",
        encode_url_component(agent_id),
        if hidden { "hide" } else { "unhide" }
    );
    agent_empty_mutation(&path, "POST").await
}

/// Soft-delete one manageable non-package Agent.
pub async fn delete_agent(agent_id: &str) -> Result<(), ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Agents,
        agent_id.to_owned(),
        delete_agent_write(agent_id),
    )
    .await
}

async fn delete_agent_write(agent_id: &str) -> Result<(), ApiError> {
    let path = agent_detail_path(agent_id).map_err(not_submitted)?;
    agent_empty_mutation(&path, "DELETE").await
}

/// Issue or rotate the one-time callback token for one manageable remote Agent.
pub async fn issue_agent_callback_token(agent_id: &str) -> Result<CallbackTokenIssued, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Agents,
        agent_id.to_owned(),
        issue_agent_callback_token_write(agent_id),
    )
    .await
}

async fn issue_agent_callback_token_write(agent_id: &str) -> Result<CallbackTokenIssued, ApiError> {
    let path = agent_callback_token_path(agent_id).map_err(not_submitted)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let response = Request::send(Request::post(&path)).await?;
        if response.status() != 201 {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<CallbackTokenIssued>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

/// Revoke the current callback token; the remote Agent remains conversational.
pub async fn revoke_agent_callback_token(agent_id: &str) -> Result<(), ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Agents,
        agent_id.to_owned(),
        revoke_agent_callback_token_write(agent_id),
    )
    .await
}

async fn revoke_agent_callback_token_write(agent_id: &str) -> Result<(), ApiError> {
    let path = agent_callback_token_path(agent_id).map_err(not_submitted)?;
    agent_empty_mutation(&path, "DELETE").await
}

/// Perform one uncached real remote AG-UI connection probe.
pub async fn test_agent_connection(
    request: AgentConnectionTestRequest,
) -> Result<AgentConnectionVerdict, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let builder = Request::post("/api/agents/test-connection");
        let outgoing = secret_json(builder, &request)?;
        drop(request);
        let response = Request::send(outgoing).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let verdict = crate::api::request::Request::decode::<AgentConnectionVerdict>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if verdict.ok != verdict.reason.is_none()
            || (verdict.ok && verdict.events.is_empty())
            || (!verdict.ok && !verdict.events.is_empty())
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(verdict)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = request;
        Err(ApiError::Unavailable)
    }
}

async fn agent_profile_mutation(
    path: &str,
    method: &'static str,
    request: AgentMutationRequest,
    expected_id: Option<&str>,
) -> Result<AgentProfile, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let builder = match method {
            "POST" => Request::post(path),
            "PATCH" => Request::patch(path),
            _ => return Err(ApiError::NotSubmitted),
        };
        let builder = builder;
        let expected = AgentWriteIntent::new(&request)?;
        let outgoing = secret_json(builder, &request).map_err(not_submitted)?;
        drop(request);
        let response = Request::send(outgoing).await?;
        let profile =
            agent_profile_response(response, if expected_id.is_some() { 200 } else { 201 }).await?;
        expected.validate_receipt(&profile, expected_id)?;
        Ok(profile)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, method, request, expected_id);
        Err(ApiError::Unavailable)
    }
}

#[cfg(target_arch = "wasm32")]
async fn agent_profile_response(
    response: gloo_net::http::Response,
    expected_status: u16,
) -> Result<AgentProfile, ApiError> {
    if response.status() != expected_status {
        return Err(status_error(response.status()));
    }
    crate::api::request::Request::decode::<AgentProfileResponse>(&response)
        .await
        .map(|response| response.agent)
        .map_err(|_| ApiError::InvalidResponse)
}

/// Non-secret fields after the application's existing ECMAScript normalization.
#[cfg(any(target_arch = "wasm32", test))]
struct AgentWriteIntent {
    name: String,
    title: String,
    role_description: String,
    visibility: openbot_contracts::agent::AgentVisibility,
    endpoint: Option<String>,
    replacement_auth: bool,
}

#[cfg(any(target_arch = "wasm32", test))]
impl AgentWriteIntent {
    fn new(request: &AgentMutationRequest) -> Result<Self, ApiError> {
        use openbot_contracts::agent::{
            MAX_AGENT_ENDPOINT_BYTES, MAX_AGENT_NAME_BYTES, MAX_AGENT_ROLE_DESCRIPTION_BYTES,
            MAX_AGENT_TITLE_BYTES,
        };
        use openbot_contracts::text::trim_ecmascript;
        let name = trim_ecmascript(&request.name);
        let title = trim_ecmascript(&request.title);
        let role_description = trim_ecmascript(&request.role_description);
        let endpoint = request
            .endpoint
            .as_deref()
            .map(trim_ecmascript)
            .filter(|value| !value.is_empty());
        if [(name, MAX_AGENT_NAME_BYTES), (title, MAX_AGENT_TITLE_BYTES)]
            .iter()
            .any(|(value, limit)| {
                value.is_empty() || value.len() > *limit || value.chars().any(char::is_control)
            })
            || role_description.is_empty()
            || role_description.len() > MAX_AGENT_ROLE_DESCRIPTION_BYTES
            || role_description.as_bytes().contains(&0)
            || endpoint.is_some_and(|value| {
                value.len() > MAX_AGENT_ENDPOINT_BYTES
                    || value.chars().any(|c| c.is_whitespace() || c.is_control())
                    || !(value.starts_with("https://") || value.starts_with("http://"))
            })
            || (request.auth.is_some() && endpoint.is_none())
        {
            return Err(ApiError::NotSubmitted);
        }
        Ok(Self {
            name: name.to_owned(),
            title: title.to_owned(),
            role_description: role_description.to_owned(),
            visibility: request.visibility,
            endpoint: endpoint.map(str::to_owned),
            replacement_auth: request.auth.is_some(),
        })
    }

    fn validate_receipt(
        &self,
        profile: &AgentProfile,
        expected_id: Option<&str>,
    ) -> Result<(), ApiError> {
        validate_agent_id(profile.id.as_str())?;
        let create = expected_id.is_none();
        if expected_id.is_some_and(|id| profile.id.as_str() != id)
            || profile.name != self.name
            || profile.title != self.title
            || profile.role_description != self.role_description
            || profile.visibility != self.visibility
            || profile.endpoint != self.endpoint
            || profile.system_owned
            || !profile.can_manage
            || !profile.mine
            || (create
                && (profile.hidden
                    || profile.has_callback_token
                    || profile.has_auth != self.replacement_auth))
            || (self.replacement_auth && !profile.has_auth)
            || (self.endpoint.is_none() && (profile.has_auth || profile.has_callback_token))
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_agent_duplicate_receipt(
    source_id: &str,
    profile: &AgentProfile,
) -> Result<(), ApiError> {
    validate_agent_id(profile.id.as_str())?;
    if profile.id.as_str() == source_id
        || profile.visibility != openbot_contracts::agent::AgentVisibility::Private
        || profile.endpoint.is_some()
        || profile.has_auth
        || profile.has_callback_token
        || profile.hidden
        || profile.system_owned
        || !profile.can_manage
        || !profile.mine
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

async fn agent_empty_mutation(path: &str, method: &'static str) -> Result<(), ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let builder = match method {
            "POST" => Request::post(path),
            "DELETE" => Request::delete(path),
            _ => return Err(ApiError::NotSubmitted),
        };
        let response = Request::send(builder).await?;
        if response.status() != 204 {
            return Err(status_error(response.status()));
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, method);
        Err(ApiError::Unavailable)
    }
}

/// Load one authoritative channel roster page.
pub async fn list_channels(cursor: Option<&str>) -> Result<ChannelPage, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = channel_list_path(cursor)?;
        let response = Request::send(Request::get(&path)).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        let page = crate::api::request::Request::decode::<ChannelPage>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if page.channels.len() > CHANNEL_PAGE_SIZE as usize {
            return Err(ApiError::InvalidResponse);
        }
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = cursor;
        Err(ApiError::Unavailable)
    }
}

/// Load one membership-visible channel detail.
pub async fn load_channel(channel_id: &str) -> Result<ChannelDetail, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = channel_detail_path(channel_id)?;
        let response = Request::send(Request::get(&path)).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<openbot_contracts::command::ChannelDetailResponse>(
            &response,
        )
        .await
        .map(|response| response.channel)
        .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = channel_id;
        Err(ApiError::Unavailable)
    }
}

/// Load the current actor's runtime memory write control.
pub async fn load_memory_control() -> Result<MemoryControl, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/memories/control")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<MemoryControl>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Persist and verify the current actor's runtime memory write control.
pub async fn save_memory_control(writes_enabled: bool) -> Result<MemoryControl, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Memory,
        "$control".to_owned(),
        save_memory_control_write(writes_enabled),
    )
    .await
}

async fn save_memory_control_write(writes_enabled: bool) -> Result<MemoryControl, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let request = Request::put("/api/memories/control")
            .json(&UpdateMemoryControl { writes_enabled })
            .map_err(|_| ApiError::NotSubmitted)?;
        let response = Request::send(request).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let control = crate::api::request::Request::decode::<MemoryControl>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if control.writes_enabled != writes_enabled {
            return Err(ApiError::InvalidResponse);
        }
        Ok(control)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = writes_enabled;
        Err(ApiError::Unavailable)
    }
}

/// Load one owner-scoped memory keyset page.
pub async fn list_memories(cursor: Option<&str>) -> Result<MemoryPage, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = memory_list_path(cursor)?;
        let response = Request::send(Request::get(&path)).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let page = crate::api::request::Request::decode::<MemoryPage>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_memory_page(&page)?;
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = cursor;
        Err(ApiError::Unavailable)
    }
}

/// Recall only the current actor's User-scope entries through the existing read-only endpoint.
pub async fn recall_user_memories(
    query: &str,
) -> Result<openbot_contracts::memory::MemoryRecall, ApiError> {
    if query.trim().is_empty() || query.len() > 4096 || query.as_bytes().contains(&0) {
        return Err(ApiError::NotSubmitted);
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        use openbot_contracts::memory::{MemoryRecall, MemoryScope, MemoryStatus, RecallMemories};
        let input = RecallMemories {
            query: query.to_owned(),
            tags: Vec::new(),
            bot_id: None,
            thread_id: None,
            limit: Some(50),
        };
        let response = Request::send(
            Request::post("/api/memories/recall")
                .json(&input)
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let recall = Request::decode::<MemoryRecall>(&response).await?;
        if recall.memories.iter().any(|record| {
            record.status != MemoryStatus::Active || record.scope != MemoryScope::User
        }) {
            return Err(ApiError::InvalidResponse);
        }
        let page = MemoryPage {
            memories: recall.memories,
            next_cursor: None,
        };
        validate_memory_page(&page)?;
        Ok(MemoryRecall {
            memories: page.memories,
        })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Persist an explicitly reviewed message memory. No owner or origin is accepted from the renderer.
pub async fn remember_memory_record(
    input: openbot_contracts::memory::RememberMemory,
) -> Result<MemoryRecord, ApiError> {
    if input.content.trim().is_empty()
        || input.content.len() > 64 * 1024
        || input.content.as_bytes().contains(&0)
    {
        return Err(ApiError::InvalidResponse);
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let response = Request::send(
            Request::post("/api/memories")
                .json(&input)
                .map_err(|_| ApiError::InvalidResponse)?,
        )
        .await?;
        if response.status() != 201 {
            return Err(status_error(response.status()));
        }
        let record = crate::api::request::Request::decode::<MemoryRecord>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_memory_record(&record)?;
        if record.status != MemoryStatus::Active
            || record.origin != openbot_contracts::memory::MemoryOrigin::UserAction
            || record.content.as_deref() != Some(input.content.as_str())
            || record.scope != input.scope
            || record.memory_kind != input.memory_kind
            || record.source != input.source
            || record.sensitivity != input.sensitivity
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(record)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = input;
        Err(ApiError::Unavailable)
    }
}

/// Correct one active memory; the Server creates a replacement and preserves provenance.
pub async fn correct_memory_record(
    memory_id: &str,
    correction: CorrectMemory,
) -> Result<MemoryRecord, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Memory,
        memory_id.to_owned(),
        correct_memory_record_write(memory_id, correction),
    )
    .await
}

async fn correct_memory_record_write(
    memory_id: &str,
    correction: CorrectMemory,
) -> Result<MemoryRecord, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = memory_detail_path(memory_id).map_err(not_submitted)?;
        let request = Request::put(&path)
            .json(&correction)
            .map_err(|_| ApiError::NotSubmitted)?;
        let response = Request::send(request).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let record = crate::api::request::Request::decode::<MemoryRecord>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_memory_correction_receipt(memory_id, &correction, &record)?;
        Ok(record)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (memory_id, correction);
        Err(ApiError::Unavailable)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_memory_correction_receipt(
    original_id: &str,
    correction: &CorrectMemory,
    record: &MemoryRecord,
) -> Result<(), ApiError> {
    validate_memory_record(record)?;
    let mut tags = correction.tags.clone();
    tags.sort();
    tags.dedup();
    if record.status != MemoryStatus::Active
        || record.memory_id == original_id
        || record.supersedes_id.as_deref() != Some(original_id)
        || record.content.as_deref() != Some(correction.content.as_str())
        || record.tags != tags
        || record.sensitivity != correction.sensitivity
        || record.expires_at != correction.expires_at
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

/// Forbid or delete one owner memory and verify that retained content is erased.
pub async fn mutate_memory_record(
    memory_id: &str,
    mutation: MemoryMutation,
) -> Result<MemoryRecord, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Memory,
        memory_id.to_owned(),
        mutate_memory_record_write(memory_id, mutation),
    )
    .await
}

async fn mutate_memory_record_write(
    memory_id: &str,
    mutation: MemoryMutation,
) -> Result<MemoryRecord, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = match mutation {
            MemoryMutation::Forbid => format!(
                "{}/forbid",
                memory_detail_path(memory_id).map_err(not_submitted)?
            ),
            MemoryMutation::Delete => memory_detail_path(memory_id).map_err(not_submitted)?,
        };
        let request = match mutation {
            MemoryMutation::Forbid => Request::post(&path),
            MemoryMutation::Delete => Request::delete(&path),
        };
        let response = Request::send(request).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let record = crate::api::request::Request::decode::<MemoryRecord>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_memory_record(&record)?;
        let expected = match mutation {
            MemoryMutation::Forbid => MemoryStatus::Forbidden,
            MemoryMutation::Delete => MemoryStatus::Deleted,
        };
        if record.memory_id != memory_id || record.status != expected || record.content.is_some() {
            return Err(ApiError::InvalidResponse);
        }
        Ok(record)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (memory_id, mutation);
        Err(ApiError::Unavailable)
    }
}

/// Load the complete anonymous sign-in capability surface before painting provider controls.
pub async fn load_authentication_capabilities() -> Result<AuthenticationCapabilities, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/capabilities")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let capabilities =
            crate::api::request::Request::decode::<AuthenticationCapabilities>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        if !capabilities.is_canonical() {
            return Err(ApiError::InvalidResponse);
        }
        Ok(capabilities)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Mint one environment-provider OIDC attempt and return its validated full-page target.
pub async fn start_environment_sign_in(provider: AuthProviderId) -> Result<String, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = environment_sign_in_path(provider);
        let response = Request::send(Request::post(&path)).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let started =
            crate::api::request::Request::decode::<AuthenticationStartResponse>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        validate_oidc_authorization_target(&started.url)?;
        Ok(started.url)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = provider;
        Err(ApiError::Unavailable)
    }
}

/// Issue one enumeration-resistant enterprise-email route ticket.
///
/// The caller must navigate to `/api/auth/sso/continue` only after this exact 202 receipt.
pub async fn start_enterprise_sign_in(email: String) -> Result<(), ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        if email.is_empty() || email.len() > MAX_SSO_ROUTING_EMAIL_BYTES {
            return Err(ApiError::InvalidResponse);
        }
        let response = Request::send(
            Request::post("/api/auth/sso/start")
                .json(&EnterpriseSsoStartRequest { email })
                .map_err(|_| ApiError::InvalidResponse)?,
        )
        .await?;
        if response.status() != 202 {
            return Err(status_error(response.status()));
        }
        let accepted =
            crate::api::request::Request::decode::<EnterpriseSsoRoutingAccepted>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        if !accepted.accepted {
            return Err(ApiError::InvalidResponse);
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = email;
        Err(ApiError::Unavailable)
    }
}

/// Load the current authenticated user for the sidebar footer and route guard.
pub async fn load_current_user() -> Result<CurrentUser, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/me")).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<CurrentUserResponse>(&response)
            .await
            .map(|response| response.user)
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Verify the current session has passed the production administrator gate.
pub async fn require_admin_status() -> Result<(), ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/admin/status")).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        let status = crate::api::request::Request::decode::<AdminStatus>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if status.status != AdminState::Ok {
            return Err(ApiError::InvalidResponse);
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Load the deployment-wide action policy; `None` keeps first-setup default-deny explicit.
pub async fn load_action_policy() -> Result<Option<ActionPolicyDocument>, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/computers/policy")).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<ActionPolicyResponse>(&response)
            .await
            .map(|response| response.policy)
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Replace the whole ordered action policy and require the authoritative receipt to match.
pub async fn save_action_policy(
    policy: &ActionPolicyDocument,
) -> Result<ActionPolicyDocument, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Boundaries,
        "$policy".to_owned(),
        save_action_policy_write(policy),
    )
    .await
}

async fn save_action_policy_write(
    policy: &ActionPolicyDocument,
) -> Result<ActionPolicyDocument, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(
            Request::put("/api/computers/policy")
                .json(policy)
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let response = crate::api::request::Request::decode::<ActionPolicyResponse>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_action_policy_receipt(policy, response)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = policy;
        Err(ApiError::Unavailable)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_action_policy_receipt(
    requested: &ActionPolicyDocument,
    response: ActionPolicyResponse,
) -> Result<ActionPolicyDocument, ApiError> {
    let stored = response.policy.ok_or(ApiError::InvalidResponse)?;
    if &stored != requested {
        return Err(ApiError::InvalidResponse);
    }
    Ok(stored)
}

/// Load every deployment-owned dynamic identity provider.
pub async fn load_identity_providers() -> Result<Vec<RegisteredIdentityProvider>, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/admin/identity-providers")).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        let response = crate::api::request::Request::decode::<IdentityProvidersResponse>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_identity_providers(&response.providers)?;
        Ok(response.providers)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Register one SAML/OIDC provider and bind the public receipt to the non-secret request fields.
pub async fn register_identity_provider(
    request: RegisterIdentityProviderRequest,
) -> Result<RegisteredIdentityProvider, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::IdentityProviders,
        request.provider_id().to_owned(),
        register_identity_provider_write(request),
    )
    .await
}

async fn register_identity_provider_write(
    request: RegisterIdentityProviderRequest,
) -> Result<RegisteredIdentityProvider, ApiError> {
    let expected_domain =
        canonical_identity_provider_domains(request.domain()).map_err(not_submitted)?;
    if !valid_identity_provider_id(request.provider_id()) {
        return Err(ApiError::NotSubmitted);
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let builder = Request::post("/api/auth/sso/register");
        let expected = (
            request.provider_id().to_owned(),
            request.issuer().to_owned(),
            request.protocol(),
        );
        let outgoing = secret_json(builder, &request).map_err(not_submitted)?;
        drop(request);
        let response = Request::send(outgoing).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let provider =
            crate::api::request::Request::decode::<RegisteredIdentityProvider>(&response)
                .await
                .map_err(|_| ApiError::InvalidResponse)?;
        validate_identity_provider(&provider)?;
        if provider.provider_id != expected.0
            || provider.issuer != expected.1
            || provider.domain != expected_domain
            || provider.protocol != expected.2
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(provider)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (request, expected_domain);
        Err(ApiError::Unavailable)
    }
}

/// Remove one provider by a validated path segment and require an exact positive receipt.
pub async fn remove_identity_provider(provider_id: &str) -> Result<(), ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::IdentityProviders,
        provider_id.to_owned(),
        remove_identity_provider_write(provider_id),
    )
    .await
}

async fn remove_identity_provider_write(provider_id: &str) -> Result<(), ApiError> {
    let path = identity_provider_remove_path(provider_id).map_err(not_submitted)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::delete(&path)).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let receipt = crate::api::request::Request::decode::<IdentityProviderRemoved>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if !receipt.removed {
            return Err(ApiError::InvalidResponse);
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

fn identity_provider_remove_path(provider_id: &str) -> Result<String, ApiError> {
    if !valid_identity_provider_id(provider_id) {
        return Err(ApiError::InvalidResponse);
    }
    Ok(format!(
        "/api/admin/identity-providers/{}",
        encode_url_component(provider_id)
    ))
}

/// Load one administrator people keyset page using server-side search.
pub async fn load_people_page(search: &str, cursor: Option<&str>) -> Result<PeoplePage, ApiError> {
    let path = people_page_path(search, cursor)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get(&path)).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        let page = crate::api::request::Request::decode::<PeoplePage>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_people_page(&page)?;
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

/// Commit one role mutation for a Server-selected person row.
pub async fn change_person_role(
    user_id: &str,
    role: openbot_contracts::auth::Role,
) -> Result<Person, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::People,
        user_id.to_owned(),
        change_person_role_write(user_id, role),
    )
    .await
}

async fn change_person_role_write(
    user_id: &str,
    role: openbot_contracts::auth::Role,
) -> Result<Person, ApiError> {
    let path = person_mutation_path(user_id, "role").map_err(not_submitted)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(
            Request::post(&path)
                .json(&ChangePersonRole { role })
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let response = crate::api::request::Request::decode::<PersonResponse>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_mutated_person(user_id, &response.person)?;
        if response.person.role != role {
            return Err(ApiError::InvalidResponse);
        }
        Ok(response.person)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, role);
        Err(ApiError::Unavailable)
    }
}

/// Commit one access removal or restoration for a Server-selected person row.
pub async fn change_person_access(user_id: &str, revoked: bool) -> Result<Person, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::People,
        user_id.to_owned(),
        change_person_access_write(user_id, revoked),
    )
    .await
}

async fn change_person_access_write(user_id: &str, revoked: bool) -> Result<Person, ApiError> {
    let path = person_mutation_path(user_id, "access").map_err(not_submitted)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(
            Request::post(&path)
                .json(&ChangePersonAccess { revoked })
                .map_err(|_| ApiError::NotSubmitted)?,
        )
        .await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let response = crate::api::request::Request::decode::<PersonResponse>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_mutated_person(user_id, &response.person)?;
        if response.person.revoked != revoked {
            return Err(ApiError::InvalidResponse);
        }
        Ok(response.person)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, revoked);
        Err(ApiError::Unavailable)
    }
}

/// Load one administrator audit keyset page through the existing typed API.
pub async fn load_audit_page(cursor: Option<&str>) -> Result<AuditPage, ApiError> {
    let path = audit_page_path(cursor)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get(&path)).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        let page = crate::api::request::Request::decode::<AuditPage>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_audit_page(&page)?;
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

/// Load at most the Server-bounded current-actor approval page without using browser cache.
pub async fn list_pending_tool_approvals() -> Result<PendingToolApprovals, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/tool-approvals")).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let page = crate::api::request::Request::decode::<PendingToolApprovals>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if page.approvals.len() > 100 {
            return Err(ApiError::InvalidResponse);
        }
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Commit one grant or denial for a Server-minted id; no binding fields are accepted here.
pub async fn decide_tool_approval(
    approval_id: &str,
    decision: ToolApprovalDecision,
) -> Result<ToolApprovalResolved, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let path = approval_decision_path(approval_id)?;
        let body = serde_json::json!({"decision": decision});
        let request = Request::post(&path)
            .json(&body)
            .map_err(|_| ApiError::InvalidResponse)?;
        let response = Request::send(request).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let receipt = crate::api::request::Request::decode::<ToolApprovalResolved>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if receipt.approval_id != approval_id || receipt.decision != decision {
            return Err(ApiError::InvalidResponse);
        }
        Ok(receipt)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (approval_id, decision);
        Err(ApiError::Unavailable)
    }
}

/// Read authenticated stored UI preferences; absent fields preserve the host-rendered fallback.
pub async fn load_ui_preferences() -> Result<UiPreferences, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/me/preferences")).await?;
        preference_response_status(response.status())?;
        let stored = crate::api::request::Request::decode::<UiPreferences>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_ui_preference_projection(stored)?;
        Ok(stored)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Merge one or both closed preference fields through the authenticated same-origin API.
pub async fn save_ui_preferences(update: UpdateUiPreferences) -> Result<UiPreferences, ApiError> {
    if update.is_empty()
        || update
            .expected_revision
            .is_some_and(|revision| revision <= 0)
    {
        return Err(ApiError::InvalidResponse);
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let request = Request::put("/api/me/preferences")
            .json(&update)
            .map_err(|_| ApiError::InvalidResponse)?;
        let response = Request::send(request).await?;
        preference_response_status(response.status())?;
        let stored = crate::api::request::Request::decode::<UiPreferences>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_ui_preference_receipt(update, stored)?;
        Ok(stored)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn preference_response_status(status: u16) -> Result<(), ApiError> {
    if status == 200 {
        Ok(())
    } else {
        Err(status_error(status))
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_ui_preference_projection(stored: UiPreferences) -> Result<(), ApiError> {
    let valid = match (stored.revision, stored.updated_at) {
        (None, None) => stored.theme.is_none() && stored.locale.is_none(),
        (Some(_), Some(_)) => stored.revision_snapshot().is_ok(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ApiError::InvalidResponse)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_ui_preference_receipt(
    update: UpdateUiPreferences,
    stored: UiPreferences,
) -> Result<(), ApiError> {
    validate_ui_preference_projection(stored)?;
    let expected_revision = update
        .expected_revision
        .map_or(Some(1), |r| r.checked_add(1));
    if expected_revision.is_none()
        || stored.revision != expected_revision
        || update.theme.is_some() && stored.theme != update.theme
        || update.locale.is_some() && stored.locale != update.locale
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod ui_preference_receipt_tests {
    use super::*;
    use openbot_contracts::ui::UiTheme;

    #[test]
    fn preference_get_and_save_require_committed_metadata_and_exact_expected_revision() {
        let update = UpdateUiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            expected_revision: Some(2),
        };
        let stored = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            revision: Some(3),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        assert!(validate_ui_preference_projection(UiPreferences::default()).is_ok());
        assert!(validate_ui_preference_receipt(update, stored).is_ok());
        // A matching metadata body on Accepted is still not the committed PUT acknowledgement.
        assert!(preference_response_status(200).is_ok());
        for status in [201, 202, 204] {
            assert!(preference_response_status(status).is_err());
        }
        for invalid in [
            UiPreferences::default(),
            UiPreferences {
                revision: Some(2),
                ..stored
            },
            UiPreferences {
                updated_at: None,
                ..stored
            },
            UiPreferences {
                theme: Some(UiTheme::Light),
                ..stored
            },
        ] {
            assert_eq!(
                validate_ui_preference_receipt(update, invalid),
                Err(ApiError::InvalidResponse)
            );
        }
        assert!(
            validate_ui_preference_projection(UiPreferences {
                revision: None,
                updated_at: None,
                ..stored
            })
            .is_err()
        );
    }
}

/// Read the authenticated actor's optional per-run provider-cost upper-bound preference.
pub async fn load_run_cost_budget() -> Result<RunCostBudgetPreference, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/me/run-cost-budget")).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        let preference = crate::api::request::Request::decode::<RunCostBudgetPreference>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_run_cost_budget_preference(&preference)?;
        Ok(preference)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Fully replace the authenticated actor's optional per-run provider-cost upper-bound preference.
pub async fn replace_run_cost_budget(
    preference: RunCostBudgetPreference,
) -> Result<RunCostBudgetPreference, ApiError> {
    crate::configuration_writes::track(
        crate::configuration_writes::ConfigurationKind::Preferences,
        "$budget".to_owned(),
        replace_run_cost_budget_write(preference),
    )
    .await
}

async fn replace_run_cost_budget_write(
    preference: RunCostBudgetPreference,
) -> Result<RunCostBudgetPreference, ApiError> {
    validate_run_cost_budget_preference(&preference).map_err(not_submitted)?;
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let request = Request::put("/api/me/run-cost-budget")
            .json(&preference)
            .map_err(|_| ApiError::NotSubmitted)?;
        let response = Request::send(request).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let stored = crate::api::request::Request::decode::<RunCostBudgetPreference>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        validate_run_cost_budget_preference(&stored)?;
        if stored != preference {
            return Err(ApiError::InvalidResponse);
        }
        Ok(stored)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = preference;
        Err(ApiError::Unavailable)
    }
}

fn validate_run_cost_budget_preference(
    preference: &RunCostBudgetPreference,
) -> Result<(), ApiError> {
    let Some(RunCostCapInput {
        currency,
        max_cost_micro_units,
    }) = preference.cap.as_ref()
    else {
        return Ok(());
    };
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(ApiError::InvalidResponse);
    }
    let amount = max_cost_micro_units.as_bytes();
    if amount.is_empty()
        || amount.len() > 19
        || !matches!(amount[0], b'1'..=b'9')
        || !amount[1..].iter().all(u8::is_ascii_digit)
    {
        return Err(ApiError::InvalidResponse);
    }
    let parsed = max_cost_micro_units
        .parse::<u64>()
        .map_err(|_| ApiError::InvalidResponse)?;
    if parsed > i64::MAX as u64 {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

/// Discover whether the current authenticated host uses one revocable database session.
pub async fn load_session_status() -> Result<SessionStatus, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        let response = Request::send(Request::get("/api/me/session")).await?;
        if !response.ok() {
            return Err(status_error(response.status()));
        }
        crate::api::request::Request::decode::<SessionStatus>(&response)
            .await
            .map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Revoke exactly the current database session; navigation happens only after the 204 receipt.
pub async fn sign_out_current_session() -> Result<(), ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;

        // Let this sign-out request finish across the following full-document navigation.
        let request = Request::post("/api/auth/sign-out")
            .build()
            .map_err(|_| ApiError::NotSubmitted)?;
        let request: web_sys::Request = request.into();
        let init = web_sys::RequestInit::new();
        let keepalive_set = js_sys::Reflect::set(
            init.as_ref(),
            &wasm_bindgen::JsValue::from_str("keepalive"),
            &wasm_bindgen::JsValue::TRUE,
        )
        .map_err(|_| ApiError::NotSubmitted)?;
        if !keepalive_set {
            return Err(ApiError::NotSubmitted);
        }
        let request = web_sys::Request::new_with_request_and_init(&request, &init)
            .map_err(|_| ApiError::NotSubmitted)?;
        let response = Request::send(gloo_net::http::Request::from(request)).await?;
        if response.status() != 204 {
            return Err(status_error(response.status()));
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

/// Build one same-origin Settings gallery detail URL for a closed component name.
pub fn component_gallery_href(name: &str) -> Result<String, ApiError> {
    validate_component_name(name)?;
    Ok(format!(
        "/settings/components-gallery/{}",
        encode_url_component(name)
    ))
}

fn validate_component_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_catalogue_added(
    request: &ComponentCatalogueRequest,
    added: &ComponentCatalogueAdded,
) -> Result<(), ApiError> {
    if added.added.len() > request.components.len() {
        return Err(ApiError::InvalidResponse);
    }
    let requested = request
        .components
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut unique = std::collections::BTreeSet::new();
    for name in &added.added {
        validate_component_name(name)?;
        if !requested.contains(name.as_str()) || !unique.insert(name.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_component_records(records: &ComponentRecords) -> Result<(), ApiError> {
    if records.components.len() > 256 {
        return Err(ApiError::InvalidResponse);
    }
    let mut names = std::collections::BTreeSet::new();
    let mut previous = None::<(&str, &str, &str)>;
    for record in &records.components {
        validate_component_record(record)?;
        if !names.insert(record.name.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
        let key = (
            record.kind.as_str(),
            record.title.as_str(),
            record.name.as_str(),
        );
        if previous.is_some_and(|previous| previous > key) {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_sandboxed_request(request: &SaveSandboxedComponentRequest) -> Result<(), ApiError> {
    if request
        .expected_revision
        .is_some_and(|revision| revision <= 0)
        || !is_sandboxed_component_name(&format!("custom_{}", request.slug))
        || request.title.is_empty()
        || request.title.as_bytes().contains(&0)
        || [
            &request.description,
            &request.html,
            &request.css,
            &request.js_functions,
        ]
        .into_iter()
        .any(|value| value.as_bytes().contains(&0))
        || serde_json::to_vec(request)
            .map_err(|_| ApiError::InvalidResponse)?
            .len()
            > 1024 * 1024
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_sandboxed_components(components: &SandboxedComponents) -> Result<(), ApiError> {
    let mut previous = None::<(&str, &str)>;
    for component in &components.components {
        validate_sandboxed_record(component)?;
        let key = (component.title.as_str(), component.name.as_str());
        if previous.is_some_and(|previous| previous >= key) {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(key);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_sandboxed_record(component: &SandboxedComponentRecord) -> Result<(), ApiError> {
    if component.editing_revision <= 0
        || !is_sandboxed_component_name(&component.name)
        || component.title.is_empty()
        || component.title.as_bytes().contains(&0)
        || [
            component.draft_description.as_str(),
            component.draft_html.as_str(),
            component.draft_css.as_str(),
            component.draft_js_functions.as_str(),
        ]
        .into_iter()
        .any(|value| value.as_bytes().contains(&0))
    {
        return Err(ApiError::InvalidResponse);
    }
    if component.published
        && (component.revision == 0
            || component.published_at.is_none()
            || component.published_html.is_none()
            || component.published_css.is_none()
            || component.published_js_functions.is_none()
            || component.published_argument_schema.is_none())
    {
        return Err(ApiError::InvalidResponse);
    }
    let expected_changes = component.published
        && (component.published_html.as_deref() != Some(component.draft_html.as_str())
            || component.published_css.as_deref() != Some(component.draft_css.as_str())
            || component.published_js_functions.as_deref()
                != Some(component.draft_js_functions.as_str()));
    if component.has_unpublished_changes != expected_changes {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_published_sandboxed_components(
    components: &PublishedSandboxedComponents,
) -> Result<(), ApiError> {
    let mut previous = None::<&str>;
    for component in &components.components {
        validate_published_sandboxed_component(component)?;
        if previous.is_some_and(|previous| previous >= component.name.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(component.name.as_str());
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_published_sandboxed_component(
    component: &PublishedSandboxedComponent,
) -> Result<(), ApiError> {
    if !is_sandboxed_component_name(&component.name)
        || [&component.html, &component.css, &component.js_functions]
            .into_iter()
            .any(|value| value.as_bytes().contains(&0))
    {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_component_record(record: &ComponentRecord) -> Result<(), ApiError> {
    validate_component_name(&record.name)?;
    if record.kind == openbot_contracts::components::CompiledComponentKind::Sandboxed
        && (!is_sandboxed_component_name(&record.name) || !record.functions.is_empty())
    {
        return Err(ApiError::InvalidResponse);
    }
    validate_component_identifier(&record.title, 512)?;
    validate_component_description(&record.draft_description)?;
    if let Some(description) = record.published_description.as_deref() {
        validate_component_description(description)?;
    }
    if record.published && (record.published_description.is_none() || record.published_at.is_none())
    {
        return Err(ApiError::InvalidResponse);
    }
    if record.has_unpublished_changes
        != (record.draft_description != record.published_description.as_deref().unwrap_or(""))
    {
        return Err(ApiError::InvalidResponse);
    }
    if let Some(updated_by) = record.updated_by.as_deref() {
        validate_component_identifier(updated_by, 512)?;
    }
    validate_component_identifier_list(&record.withheld_from)?;
    validate_component_identifier_list(&record.functions)?;
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_granted_components(granted: &GrantedCompiledComponents) -> Result<(), ApiError> {
    let renderers = compiled_component_manifest()
        .into_iter()
        .map(|entry| entry.name)
        .collect::<std::collections::BTreeSet<_>>();
    if granted.components.len() > renderers.len() {
        return Err(ApiError::InvalidResponse);
    }
    let mut previous = None::<&str>;
    for component in &granted.components {
        validate_component_name(&component.name)?;
        validate_component_description(&component.description)?;
        if !renderers.contains(&component.name)
            || previous.is_some_and(|previous| previous >= component.name.as_str())
        {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(&component.name);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_component_decision(
    decision: &ComponentDecision,
    requested_functions: &[String],
) -> Result<(), ApiError> {
    if !decision.is_consistent() {
        return Err(ApiError::InvalidResponse);
    }
    if let Some(function) = decision
        .refusal
        .as_ref()
        .and_then(ComponentDecisionRefusal::function)
        && requested_functions
            .binary_search_by(|candidate| candidate.as_str().cmp(function))
            .is_err()
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_component_data_functions(functions: &ComponentDataFunctions) -> Result<(), ApiError> {
    if functions.functions != component_data_function_manifest() {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_component_function_call(
    result: &ComponentFunctionCall,
    requested_function: &str,
    status: u16,
) -> Result<(), ApiError> {
    if !result.is_consistent() || (result.error.is_some()) != (status == 502) {
        return Err(ApiError::InvalidResponse);
    }
    if let Some(function) = result
        .refusal
        .as_ref()
        .and_then(ComponentDecisionRefusal::function)
        && function != requested_function
    {
        return Err(ApiError::InvalidResponse);
    }
    match (&result.data, requested_function) {
        (Some(ComponentFunctionData::BotActivity(report)), BOT_ACTIVITY_FUNCTION_NAME) => {
            if !(1..=90).contains(&report.days) || report.rows.len() > 12 {
                return Err(ApiError::InvalidResponse);
            }
            let mut previous = None::<(u64, &str)>;
            for row in &report.rows {
                validate_bounded_identifier(&row.bot, 256)?;
                let current = (row.actions, row.bot.as_str());
                if previous.is_some_and(|previous| {
                    previous.0 < current.0 || (previous.0 == current.0 && previous.1 > current.1)
                }) {
                    return Err(ApiError::InvalidResponse);
                }
                previous = Some(current);
            }
        }
        (Some(ComponentFunctionData::RecentRefusals(report)), RECENT_REFUSALS_FUNCTION_NAME) => {
            if report.rows.len() > 50 {
                return Err(ApiError::InvalidResponse);
            }
            for row in &report.rows {
                if let Some(bot) = row.bot.as_deref() {
                    validate_bounded_identifier(bot, 256)?;
                }
                validate_bounded_identifier(&row.what, 128)?;
                if let Some(reason) = row.reason.as_deref() {
                    validate_bounded_identifier(reason, 256)?;
                }
            }
        }
        (None, _) => {}
        _ => return Err(ApiError::InvalidResponse),
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_pending_component_human_decisions(
    decisions: &PendingComponentHumanDecisions,
) -> Result<(), ApiError> {
    if decisions.decisions.len() > 100 {
        return Err(ApiError::InvalidResponse);
    }
    let mut decision_ids = std::collections::BTreeSet::new();
    let mut provider_calls = std::collections::BTreeSet::new();
    let mut previous = None;
    for decision in &decisions.decisions {
        let argument_bytes =
            serde_json::to_vec(&decision.arguments).map_err(|_| ApiError::InvalidResponse)?;
        validate_opaque_identifier(&decision.decision_id, 256)?;
        validate_opaque_identifier(decision.run_id.as_str(), 256)?;
        validate_opaque_identifier(&decision.provider_call_id, 1024)?;
        validate_opaque_identifier(decision.agent_id.as_str(), 256)?;
        if !decision_ids.insert(decision.decision_id.as_str())
            || !provider_calls
                .insert((decision.run_id.as_str(), decision.provider_call_id.as_str()))
            || !is_component_human_decision_name(&decision.component_name)
            || validate_component_human_decision_arguments(
                &decision.component_name,
                &decision.arguments,
            )
            .is_err()
            || argument_bytes.len() > 64 * 1024
            || decision.expires_at <= decision.requested_at
        {
            return Err(ApiError::InvalidResponse);
        }
        let key = (decision.requested_at, decision.decision_id.as_str());
        if previous.is_some_and(|previous| previous > key) {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(key);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_component_description(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > MAX_COMPONENT_DESCRIPTION_BYTES
        || value.as_bytes().contains(&0)
    {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_component_identifier(value: &str, max: usize) -> Result<(), ApiError> {
    validate_bounded_identifier(value, max)
}

fn validate_bounded_identifier(value: &str, max: usize) -> Result<(), ApiError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn validate_opaque_identifier(value: &str, max: usize) -> Result<(), ApiError> {
    if value.is_empty() || value.len() > max || value.as_bytes().contains(&0) {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_component_identifier_list(values: &[String]) -> Result<(), ApiError> {
    if values.len() > 1024 {
        return Err(ApiError::InvalidResponse);
    }
    let mut previous = None::<&str>;
    for value in values {
        validate_component_identifier(value, 512)?;
        if previous.is_some_and(|previous| previous >= value.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_mcp_server_id(server_id: &str) -> Result<(), ApiError> {
    if server_id.is_empty()
        || server_id.len() > 64
        || server_id.contains("__")
        || server_id.contains('/')
        || !server_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn mcp_connect_path(server_id: &str) -> Result<String, ApiError> {
    validate_mcp_server_id(server_id)?;
    Ok(format!(
        "/api/plugins/servers/{}/connect?returnTo=settings",
        encode_url_component(server_id)
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn mcp_disconnect_path(server_id: &str) -> Result<String, ApiError> {
    validate_mcp_server_id(server_id)?;
    Ok(format!(
        "/api/plugins/connections/{}",
        encode_url_component(server_id)
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_mcp_connections(page: &McpConnections) -> Result<(), ApiError> {
    if page.available_server_ids.len() > 64 || page.connections.len() > 256 {
        return Err(ApiError::InvalidResponse);
    }
    let mut available = std::collections::BTreeSet::new();
    for server_id in &page.available_server_ids {
        validate_mcp_server_id(server_id)?;
        if !available.insert(server_id.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
    }
    let mut connected = std::collections::BTreeSet::new();
    for connection in &page.connections {
        validate_mcp_server_id(&connection.server_id)?;
        if !connected.insert(connection.server_id.as_str())
            || connection.scope.is_empty()
            || connection.scope.len() > 16 * 1024
            || connection.scope.chars().any(char::is_control)
        {
            return Err(ApiError::InvalidResponse);
        }
    }
    if let Some(redirect_uri) = page.redirect_uri.as_deref() {
        validate_callback_uri(redirect_uri)?;
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_callback_uri(value: &str) -> Result<(), ApiError> {
    if value.len() > 16 * 1024 || value.chars().any(char::is_control) {
        return Err(ApiError::InvalidResponse);
    }
    let parsed = url::Url::parse(value).map_err(|_| ApiError::InvalidResponse)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_authorization_target(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 16 * 1024
        || value.chars().any(char::is_control)
        || value.contains('\\')
        || value.contains('#')
    {
        return Err(ApiError::InvalidResponse);
    }
    if value.starts_with('/') {
        return if value.starts_with("//") {
            Err(ApiError::InvalidResponse)
        } else {
            Ok(())
        };
    }
    let parsed = url::Url::parse(value).map_err(|_| ApiError::InvalidResponse)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_oidc_authorization_target(value: &str) -> Result<(), ApiError> {
    validate_authorization_target(value)?;
    let parsed = url::Url::parse(value).map_err(|_| ApiError::InvalidResponse)?;
    if parsed.scheme() != "https" {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn environment_sign_in_path(provider: AuthProviderId) -> String {
    format!("/api/auth/oidc/{}/start", provider.as_str())
}

#[cfg(any(target_arch = "wasm32", test))]
fn approval_decision_path(approval_id: &str) -> Result<String, ApiError> {
    if approval_id.is_empty() || approval_id.len() > 128 || approval_id.as_bytes().contains(&0) {
        return Err(ApiError::InvalidResponse);
    }
    Ok(format!(
        "/api/tool-approvals/{}",
        encode_url_component(approval_id)
    ))
}

fn component_human_decision_answer_path(decision_id: &str) -> Result<String, ApiError> {
    validate_opaque_identifier(decision_id, 256)?;
    Ok(format!(
        "/api/components/human-decisions/{}/answer",
        encode_url_component(decision_id)
    ))
}

fn remote_interrupt_answer_path(request_id: &str) -> Result<String, ApiError> {
    if !is_remote_interrupt_request_id(request_id) {
        return Err(ApiError::InvalidResponse);
    }
    Ok(format!(
        "/api/me/remote-interrupts/{}",
        encode_url_component(request_id)
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_pending_remote_interrupts(pending: &PendingRemoteInterrupts) -> Result<(), ApiError> {
    if pending.interrupts.len() > 100 {
        return Err(ApiError::InvalidResponse);
    }
    let mut ids = std::collections::BTreeSet::new();
    for interrupt in &pending.interrupts {
        if !is_remote_interrupt_request_id(&interrupt.request_id) {
            return Err(ApiError::InvalidResponse);
        }
        validate_opaque_identifier(&interrupt.run_id, 1024)?;
        validate_opaque_identifier(&interrupt.agent_id, 1024)?;
        if !ids.insert(interrupt.request_id.as_str())
            || interrupt.untrusted_reason.is_empty()
            || interrupt.untrusted_reason.len() > 256
            || interrupt.untrusted_reason.chars().any(char::is_control)
            || interrupt
                .untrusted_message
                .as_ref()
                .is_some_and(|value| value.len() > 64 * 1024 || value.as_bytes().contains(&0))
            || interrupt
                .untrusted_response_schema
                .as_ref()
                .is_some_and(|value| !value.is_object())
            || interrupt.expires_at_ms <= interrupt.requested_at_ms
        {
            return Err(ApiError::InvalidResponse);
        }
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn people_page_path(search: &str, cursor: Option<&str>) -> Result<String, ApiError> {
    validate_people_text(search, 2048, true)?;
    let mut path = format!("/api/admin/people?limit={PEOPLE_PAGE_SIZE}");
    if !search.is_empty() {
        path.push_str("&search=");
        path.push_str(&encode_url_component(search));
    }
    if let Some(cursor) = cursor {
        validate_people_text(cursor, 2048, false)?;
        path.push_str("&cursor=");
        path.push_str(&encode_url_component(cursor));
    }
    Ok(path)
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn people_page_path(_search: &str, _cursor: Option<&str>) -> Result<String, ApiError> {
    Err(ApiError::Unavailable)
}

#[cfg(any(target_arch = "wasm32", test))]
fn person_mutation_path(user_id: &str, operation: &str) -> Result<String, ApiError> {
    validate_people_text(user_id, 512, false)?;
    if !matches!(operation, "role" | "access") {
        return Err(ApiError::InvalidResponse);
    }
    Ok(format!(
        "/api/admin/people/{}/{}",
        encode_url_component(user_id),
        operation,
    ))
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn person_mutation_path(_user_id: &str, _operation: &str) -> Result<String, ApiError> {
    Err(ApiError::Unavailable)
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_people_page(page: &PeoplePage) -> Result<(), ApiError> {
    if page.people.len() > PEOPLE_PAGE_SIZE as usize {
        return Err(ApiError::InvalidResponse);
    }
    let mut ids = std::collections::BTreeSet::new();
    for person in &page.people {
        validate_person(person)?;
        if !ids.insert(person.id.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
    }
    if let Some(cursor) = page.next_cursor.as_deref() {
        validate_people_text(cursor, 2048, false)?;
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_mutated_person(expected_id: &str, person: &Person) -> Result<(), ApiError> {
    validate_person(person)?;
    if person.id.as_str() != expected_id {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_person(person: &Person) -> Result<(), ApiError> {
    validate_people_text(person.id.as_str(), 512, false)?;
    validate_people_text(&person.email, 512, false)?;
    if let Some(name) = person.name.as_deref() {
        validate_people_text(name, 512, true)?;
    }
    if let Some(image) = person.image.as_deref() {
        validate_people_text(image, 2048, true)?;
    }
    if person.providers.len() > 32 {
        return Err(ApiError::InvalidResponse);
    }
    let mut previous = None;
    for provider in &person.providers {
        validate_people_text(provider, 128, false)?;
        if previous.is_some_and(|previous| previous >= provider.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(provider.as_str());
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_people_text(value: &str, max: usize, allow_empty: bool) -> Result<(), ApiError> {
    if value.len() > max || !allow_empty && value.is_empty() || value.chars().any(char::is_control)
    {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_identity_providers(providers: &[RegisteredIdentityProvider]) -> Result<(), ApiError> {
    if providers.len() > MAX_IDENTITY_PROVIDERS {
        return Err(ApiError::InvalidResponse);
    }
    let mut provider_ids = std::collections::BTreeSet::new();
    let mut domains = std::collections::BTreeSet::new();
    for provider in providers {
        validate_identity_provider(provider)?;
        if !provider_ids.insert(provider.provider_id.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
        for domain in provider.domain.split(',') {
            if !domains.insert(domain) {
                return Err(ApiError::InvalidResponse);
            }
        }
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_identity_provider(provider: &RegisteredIdentityProvider) -> Result<(), ApiError> {
    if !valid_identity_provider_id(&provider.provider_id)
        || provider.issuer.is_empty()
        || provider.issuer.len() > MAX_IDENTITY_PROVIDER_URL_BYTES
        || provider.issuer.chars().any(char::is_control)
        || canonical_identity_provider_domains(&provider.domain)? != provider.domain
        || provider.registered_by.as_deref().is_some_and(|actor| {
            actor.is_empty() || actor.len() > 512 || actor.chars().any(char::is_control)
        })
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

pub(crate) fn valid_identity_provider_id(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_IDENTITY_PROVIDER_ID_BYTES {
        return false;
    }
    let mut characters = value.chars();
    characters.next().is_some_and(|first| {
        (first.is_ascii_lowercase() || first.is_ascii_digit())
            && characters.all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '-' | '_')
            })
    })
}

pub(crate) fn canonical_identity_provider_domains(value: &str) -> Result<String, ApiError> {
    let parts = value.split(',').map(str::trim).collect::<Vec<_>>();
    if parts.is_empty()
        || parts.len() > MAX_IDENTITY_PROVIDER_DOMAINS
        || parts.iter().any(|part| part.is_empty())
    {
        return Err(ApiError::InvalidResponse);
    }
    let mut domains = std::collections::BTreeSet::new();
    for part in parts {
        if !part.is_ascii() {
            return Err(ApiError::InvalidResponse);
        }
        let domain = part.to_ascii_lowercase();
        if domain.starts_with('.')
            || domain.starts_with('-')
            || domain.ends_with('.')
            || domain.ends_with('-')
            || domain.contains("..")
            || !domain
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            || !domains.insert(domain)
        {
            return Err(ApiError::InvalidResponse);
        }
    }
    Ok(domains.into_iter().collect::<Vec<_>>().join(","))
}

#[cfg(any(target_arch = "wasm32", test))]
fn audit_page_path(cursor: Option<&str>) -> Result<String, ApiError> {
    let mut path = format!("/api/admin/audit-events?limit={AUDIT_PAGE_SIZE}");
    if let Some(cursor) = cursor {
        validate_audit_text(cursor, 2048, false)?;
        path.push_str("&cursor=");
        path.push_str(&encode_url_component(cursor));
    }
    Ok(path)
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn audit_page_path(_cursor: Option<&str>) -> Result<String, ApiError> {
    Err(ApiError::Unavailable)
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_audit_page(page: &AuditPage) -> Result<(), ApiError> {
    if page.events.len() > AUDIT_PAGE_SIZE as usize {
        return Err(ApiError::InvalidResponse);
    }
    let mut ids = std::collections::BTreeSet::new();
    for event in &page.events {
        validate_audit_event(event)?;
        if !ids.insert(event.id.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
    }
    if let Some(cursor) = page.next_cursor.as_deref() {
        validate_audit_text(cursor, 2048, false)?;
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_audit_event(event: &AuditEventView) -> Result<(), ApiError> {
    validate_audit_text(event.id.as_str(), 256, false)?;
    validate_audit_text(&event.event_type, 256, false)?;
    validate_audit_text(&event.target_type, 128, false)?;
    if let Some(actor) = event.actor_user_id.as_ref() {
        validate_audit_text(actor.as_str(), 512, false)?;
    }
    if let Some(target) = event.target_id.as_deref() {
        validate_audit_text(target, 1024, false)?;
    }
    if !event.payload.is_object()
        || serde_json::to_vec(&event.payload).map_or(true, |payload| payload.len() > 64 * 1024)
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_audit_text(value: &str, max: usize, allow_empty: bool) -> Result<(), ApiError> {
    if value.len() > max || !allow_empty && value.is_empty() || value.chars().any(char::is_control)
    {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn memory_list_path(cursor: Option<&str>) -> Result<String, ApiError> {
    let mut path = format!("/api/memories?limit={MEMORY_PAGE_SIZE}");
    if let Some(cursor) = cursor {
        validate_memory_id(cursor)?;
        path.push_str("&cursor=");
        path.push_str(&encode_url_component(cursor));
    }
    Ok(path)
}

#[cfg(any(target_arch = "wasm32", test))]
fn memory_detail_path(memory_id: &str) -> Result<String, ApiError> {
    validate_memory_id(memory_id)?;
    Ok(format!("/api/memories/{}", encode_url_component(memory_id)))
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_memory_id(memory_id: &str) -> Result<(), ApiError> {
    if memory_id.is_empty() || memory_id.len() > 512 || memory_id.chars().any(char::is_control) {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_memory_page(page: &MemoryPage) -> Result<(), ApiError> {
    if page.memories.len() > MEMORY_PAGE_SIZE as usize {
        return Err(ApiError::InvalidResponse);
    }
    let mut ids = std::collections::BTreeSet::new();
    for record in &page.memories {
        validate_memory_record(record)?;
        if !ids.insert(record.memory_id.as_str()) {
            return Err(ApiError::InvalidResponse);
        }
    }
    if let Some(cursor) = page.next_cursor.as_deref() {
        validate_memory_id(cursor)?;
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_memory_record(record: &MemoryRecord) -> Result<(), ApiError> {
    validate_memory_id(&record.memory_id)?;
    if record.owner_user_id.is_empty()
        || record.owner_user_id.chars().any(char::is_control)
        || record.created_by.is_empty()
        || record.created_by.chars().any(char::is_control)
        || record.tags.len() > 32
        || record
            .tags
            .iter()
            .any(|tag| tag.is_empty() || tag.len() > 64 || tag.chars().any(char::is_control))
    {
        return Err(ApiError::InvalidResponse);
    }
    match record.status {
        MemoryStatus::Active | MemoryStatus::Superseded
            if record.content.as_deref().is_none_or(str::is_empty) =>
        {
            return Err(ApiError::InvalidResponse);
        }
        MemoryStatus::Forbidden | MemoryStatus::Deleted if record.content.is_some() => {
            return Err(ApiError::InvalidResponse);
        }
        _ => {}
    }
    match &record.scope {
        MemoryScope::User => {}
        MemoryScope::Bot { bot_id } if bot_id.as_str().is_empty() => {
            return Err(ApiError::InvalidResponse);
        }
        MemoryScope::Thread { thread_id } if thread_id.as_str().is_empty() => {
            return Err(ApiError::InvalidResponse);
        }
        MemoryScope::Bot { .. } | MemoryScope::Thread { .. } => {}
    }
    if let Some(source) = &record.source
        && (source.thread_id.as_str().is_empty()
            || source.message_id.is_empty()
            || source.message_id.chars().any(char::is_control))
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn channel_detail_path(channel_id: &str) -> Result<String, ApiError> {
    validate_channel_id(channel_id)?;
    Ok(format!(
        "/api/channels/{}",
        encode_url_component(channel_id)
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn thread_run_path(thread_id: &str) -> Result<String, ApiError> {
    validate_thread_id(thread_id)?;
    Ok(format!(
        "/api/threads/{}/runs",
        encode_url_component(thread_id)
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn thread_status_path(thread_id: &str) -> Result<String, ApiError> {
    validate_thread_id(thread_id)?;
    Ok(format!("/api/threads/{}", encode_url_component(thread_id)))
}

#[cfg(any(target_arch = "wasm32", test))]
fn thread_cancel_path(thread_id: &str, run_id: &str) -> Result<String, ApiError> {
    validate_thread_id(thread_id)?;
    validate_run_id(run_id)?;
    Ok(format!(
        "/api/threads/{}/runs/{}/cancel",
        encode_url_component(thread_id),
        encode_url_component(run_id)
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn thread_conversation_path(thread_id: &str) -> Result<String, ApiError> {
    validate_thread_id(thread_id)?;
    Ok(format!(
        "/api/threads/{}/conversation",
        encode_url_component(thread_id)
    ))
}

/// Build the EventSource URL whose optional cursor is only the initial durable replay boundary.
#[cfg(any(target_arch = "wasm32", test))]
pub fn thread_event_stream_path(
    thread_id: &ThreadId,
    cursor: Option<u64>,
) -> Result<String, ApiError> {
    validate_thread_id(thread_id.as_str())?;
    let mut path = format!(
        "/api/threads/{}/events",
        encode_url_component(thread_id.as_str())
    );
    if let Some(cursor) = cursor {
        path.push_str("?cursor=");
        path.push_str(&cursor.to_string());
    }
    Ok(path)
}

fn agent_detail_path(agent_id: &str) -> Result<String, ApiError> {
    validate_agent_id(agent_id)?;
    Ok(format!("/api/agents/{}", encode_url_component(agent_id)))
}

fn agent_callback_token_path(agent_id: &str) -> Result<String, ApiError> {
    validate_agent_id(agent_id)?;
    Ok(format!(
        "/api/agents/{}/callback-token",
        encode_url_component(agent_id)
    ))
}

/// Build the URL-owned profile-panel route for one validated Agent identity.
pub fn agent_profile_href(agent_id: &str) -> Result<String, ApiError> {
    validate_agent_id(agent_id)?;
    Ok(format!("/agents?agent={}", encode_url_component(agent_id)))
}

fn validate_agent_id(agent_id: &str) -> Result<(), ApiError> {
    if agent_id.is_empty() || agent_id.len() > 512 || agent_id.chars().any(char::is_control) {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

/// Build one same-origin UI route for a validated channel identity.
pub fn channel_route_href(channel_id: &str) -> Result<String, ApiError> {
    validate_channel_id(channel_id)?;
    Ok(format!("/channel/{}", encode_url_component(channel_id)))
}

/// Build the URL-owned new-channel route for one selected Agent.
pub fn channel_new_href(agent_id: &str) -> Result<String, ApiError> {
    validate_agent_id(agent_id)?;
    Ok(format!(
        "/channel/new?agent={}",
        encode_url_component(agent_id)
    ))
}

/// Build the URL-owned direct-Bot chat route for one selected Agent.
pub fn bot_chat_href(agent_id: &str) -> Result<String, ApiError> {
    validate_agent_id(agent_id)?;
    Ok(format!("/bot?agent={}", encode_url_component(agent_id)))
}

/// Build the same-origin administrator detail route for one component identity.
pub fn admin_component_href(name: &str) -> Result<String, ApiError> {
    validate_component_name(name)?;
    Ok(format!("/admin/components/{}", encode_url_component(name)))
}

fn validate_channel_id(channel_id: &str) -> Result<(), ApiError> {
    if channel_id.is_empty() || channel_id.len() > 512 || channel_id.chars().any(char::is_control) {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_thread_id(thread_id: &str) -> Result<(), ApiError> {
    if thread_id.is_empty() || thread_id.len() > 512 || thread_id.chars().any(char::is_control) {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_run_id(run_id: &str) -> Result<(), ApiError> {
    if run_id.is_empty() || run_id.len() > 512 || run_id.chars().any(char::is_control) {
        Err(ApiError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn channel_list_path(cursor: Option<&str>) -> Result<String, ApiError> {
    let mut path = format!("/api/channels?limit={CHANNEL_PAGE_SIZE}");
    if let Some(cursor) = cursor {
        if cursor.is_empty() || cursor.len() > 4096 || cursor.chars().any(char::is_control) {
            return Err(ApiError::InvalidResponse);
        }
        path.push_str("&cursor=");
        path.push_str(&encode_url_component(cursor));
    }
    Ok(path)
}

fn encode_url_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use core::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

#[cfg(any(target_arch = "wasm32", test))]
fn status_error(status: u16) -> ApiError {
    match status {
        202 => ApiError::ReconciliationRequired,
        401 => ApiError::Unauthorized,
        403 => ApiError::Forbidden,
        404 => ApiError::NotFound,
        409 | 410 | 412 => ApiError::Conflict,
        _ => ApiError::Server,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use openbot_contracts::components::{
        ASK_APPROVAL_COMPONENT_NAME, CompiledComponentKind, PendingComponentHumanDecision,
        SHOW_QUOTE_COMPONENT_NAME,
    };
    use openbot_contracts::memory::{MemoryKind, MemoryOrigin, MemorySensitivity};
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn run_cost_budget_projection_accepts_only_the_closed_canonical_shape() {
        assert!(validate_run_cost_budget_preference(&RunCostBudgetPreference::default()).is_ok());
        assert!(
            validate_run_cost_budget_preference(&RunCostBudgetPreference {
                cap: Some(RunCostCapInput {
                    currency: "USD".to_owned(),
                    max_cost_micro_units: i64::MAX.to_string(),
                }),
            })
            .is_ok()
        );
        for cap in [
            RunCostCapInput {
                currency: "usd".to_owned(),
                max_cost_micro_units: "1".to_owned(),
            },
            RunCostCapInput {
                currency: "USD".to_owned(),
                max_cost_micro_units: "01".to_owned(),
            },
            RunCostCapInput {
                currency: "USD".to_owned(),
                max_cost_micro_units: "9223372036854775808".to_owned(),
            },
        ] {
            assert_eq!(
                validate_run_cost_budget_preference(&RunCostBudgetPreference { cap: Some(cap) })
                    .unwrap_err(),
                ApiError::InvalidResponse
            );
        }
    }

    #[test]
    fn remote_interrupt_path_and_projection_are_closed_bounded_and_untrusted() {
        assert_eq!(
            remote_interrupt_answer_path("018f6f8a-5f4b-7c2d-8a31-111111111111").unwrap(),
            "/api/me/remote-interrupts/018f6f8a-5f4b-7c2d-8a31-111111111111"
        );
        assert!(remote_interrupt_answer_path("").is_err());
        let interrupt = openbot_contracts::remote_interrupt::PendingRemoteInterrupt {
            request_id: "018f6f8a-5f4b-7c2d-8a31-111111111111".to_owned(),
            run_id: "run-1".to_owned(),
            agent_id: "bot-1".to_owned(),
            untrusted_reason: "confirmation".to_owned(),
            untrusted_message: Some("Remote prompt".to_owned()),
            untrusted_response_schema: Some(serde_json::json!({"type":"object"})),
            requested_at_ms: 1,
            expires_at_ms: 2,
        };
        assert!(
            validate_pending_remote_interrupts(&PendingRemoteInterrupts {
                interrupts: vec![interrupt.clone()],
            })
            .is_ok()
        );
        let mut duplicate = interrupt.clone();
        duplicate.untrusted_reason = "other".to_owned();
        assert_eq!(
            validate_pending_remote_interrupts(&PendingRemoteInterrupts {
                interrupts: vec![interrupt.clone(), duplicate],
            })
            .unwrap_err(),
            ApiError::InvalidResponse
        );
        let mut bad_time = interrupt;
        bad_time.expires_at_ms = bad_time.requested_at_ms;
        assert!(
            validate_pending_remote_interrupts(&PendingRemoteInterrupts {
                interrupts: vec![bad_time],
            })
            .is_err()
        );
    }

    #[test]
    fn all_environment_auth_providers_share_one_closed_start_route_shape() {
        assert_eq!(
            environment_sign_in_path(AuthProviderId::Google),
            "/api/auth/oidc/google/start"
        );
        assert_eq!(
            environment_sign_in_path(AuthProviderId::Microsoft),
            "/api/auth/oidc/microsoft/start"
        );
        assert_eq!(
            environment_sign_in_path(AuthProviderId::Okta),
            "/api/auth/oidc/okta/start"
        );
    }

    fn memory_record(id: &str, content: Option<&str>, status: MemoryStatus) -> MemoryRecord {
        MemoryRecord {
            memory_id: id.to_owned(),
            owner_user_id: "actor".to_owned(),
            scope: MemoryScope::User,
            memory_kind: MemoryKind::Preference,
            content: content.map(str::to_owned),
            tags: vec!["preference".to_owned()],
            sensitivity: MemorySensitivity::Normal,
            source: None,
            source_run_id: None,
            source_authorization_snapshot: None,
            origin: MemoryOrigin::UserAction,
            created_by: "actor".to_owned(),
            supersedes_id: None,
            status,
            expires_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn mcp_page() -> McpConnections {
        McpConnections {
            available_server_ids: vec!["google-drive".to_owned()],
            connections: vec![openbot_contracts::mcp::McpConnection {
                server_id: "google-drive".to_owned(),
                scope: "https://www.googleapis.com/auth/drive.readonly".to_owned(),
                connected_at: OffsetDateTime::UNIX_EPOCH,
            }],
            redirect_uri: Some("http://127.0.0.1:39015/api/plugins/oauth/callback".to_owned()),
        }
    }

    fn component_record(name: &str, title: &str, published: bool) -> ComponentRecord {
        ComponentRecord {
            name: name.to_owned(),
            title: title.to_owned(),
            kind: CompiledComponentKind::Card,
            draft_description: "Show one compiled component.".to_owned(),
            published_description: published.then(|| "Show one compiled component.".to_owned()),
            published,
            published_at: published.then_some(OffsetDateTime::UNIX_EPOCH),
            updated_by: Some("the build".to_owned()),
            updated_at: OffsetDateTime::UNIX_EPOCH,
            has_unpublished_changes: !published,
            withheld_from: Vec::new(),
            functions: Vec::new(),
        }
    }

    #[test]
    fn component_records_catalogue_receipts_and_routes_are_closed() {
        assert_eq!(
            component_gallery_href(SHOW_QUOTE_COMPONENT_NAME).unwrap(),
            "/settings/components-gallery/showQuote"
        );
        assert_eq!(
            component_gallery_href("bad/name").unwrap_err(),
            ApiError::InvalidResponse
        );
        let records = ComponentRecords {
            components: vec![component_record(
                SHOW_QUOTE_COMPONENT_NAME,
                "Quotation",
                true,
            )],
        };
        assert!(validate_component_records(&records).is_ok());

        let request = ComponentCatalogueRequest {
            components: compiled_component_manifest(),
        };
        assert!(
            validate_catalogue_added(
                &request,
                &ComponentCatalogueAdded {
                    added: vec![SHOW_QUOTE_COMPONENT_NAME.to_owned()],
                },
            )
            .is_ok()
        );
        assert_eq!(
            validate_catalogue_added(
                &request,
                &ComponentCatalogueAdded {
                    added: vec!["showUnknown".to_owned()],
                },
            )
            .unwrap_err(),
            ApiError::InvalidResponse
        );

        let mut inconsistent = records.components[0].clone();
        inconsistent.published_description = None;
        assert_eq!(
            validate_component_record(&inconsistent).unwrap_err(),
            ApiError::InvalidResponse
        );
        let mut duplicate_functions = records.components[0].clone();
        duplicate_functions.functions = vec!["read".to_owned(), "read".to_owned()];
        assert_eq!(
            validate_component_record(&duplicate_functions).unwrap_err(),
            ApiError::InvalidResponse
        );

        let grants = GrantedCompiledComponents {
            components: vec![openbot_contracts::components::GrantedCompiledComponent {
                name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                description: "published quote".to_owned(),
            }],
        };
        assert!(validate_granted_components(&grants).is_ok());
        let mut stale = grants.clone();
        stale.components[0].name = "showStale".to_owned();
        assert_eq!(
            validate_granted_components(&stale).unwrap_err(),
            ApiError::InvalidResponse
        );

        let requested = vec!["recentRefusals".to_owned()];
        assert!(validate_component_decision(&ComponentDecision::allowed(), &requested).is_ok());
        assert!(
            validate_component_decision(
                &ComponentDecision::refused(ComponentDecisionRefusal::FunctionNotGranted {
                    function: "recentRefusals".to_owned(),
                },),
                &requested,
            )
            .is_ok()
        );
        assert_eq!(
            validate_component_decision(
                &ComponentDecision::refused(ComponentDecisionRefusal::FunctionNotGranted {
                    function: "botActivity".to_owned(),
                },),
                &requested,
            )
            .unwrap_err(),
            ApiError::InvalidResponse
        );
        assert_eq!(
            validate_component_decision(
                &ComponentDecision {
                    allowed: true,
                    refusal: Some(ComponentDecisionRefusal::Unpublished),
                },
                &[],
            )
            .unwrap_err(),
            ApiError::InvalidResponse
        );

        let functions = ComponentDataFunctions {
            functions: component_data_function_manifest(),
        };
        assert!(validate_component_data_functions(&functions).is_ok());
        let valid_call = ComponentFunctionCall::succeeded(ComponentFunctionData::BotActivity(
            openbot_contracts::components::BotActivityReport {
                days: 7,
                rows: vec![openbot_contracts::components::BotActivityRow {
                    bot: "agent-one".to_owned(),
                    actions: 3,
                }],
            },
        ));
        assert!(
            validate_component_function_call(&valid_call, BOT_ACTIVITY_FUNCTION_NAME, 200).is_ok()
        );
        assert_eq!(
            validate_component_function_call(&valid_call, RECENT_REFUSALS_FUNCTION_NAME, 200)
                .unwrap_err(),
            ApiError::InvalidResponse
        );
        assert_eq!(
            validate_component_function_call(
                &ComponentFunctionCall::failed(
                    openbot_contracts::components::ComponentFunctionError::ReadFailed,
                ),
                BOT_ACTIVITY_FUNCTION_NAME,
                200,
            )
            .unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn sandboxed_admin_and_published_projections_are_closed_and_sorted() {
        let record = SandboxedComponentRecord {
            editing_revision: 1,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            name: "custom_delivery_eta".to_owned(),
            title: "Delivery ETA".to_owned(),
            draft_description: "Show an ETA.".to_owned(),
            draft_html: "<p>ETA</p>".to_owned(),
            draft_css: "p{}".to_owned(),
            draft_js_functions: "document.body.dataset.ok='1';".to_owned(),
            draft_argument_schema: BTreeMap::new(),
            published_html: Some("<p>ETA</p>".to_owned()),
            published_css: Some("p{}".to_owned()),
            published_js_functions: Some("document.body.dataset.ok='1';".to_owned()),
            published_argument_schema: Some(BTreeMap::new()),
            sample_arguments: BTreeMap::new(),
            revision: 1,
            published: true,
            published_at: Some(OffsetDateTime::UNIX_EPOCH),
            authored_by: Some("actor".to_owned()),
            has_unpublished_changes: false,
        };
        assert!(
            validate_sandboxed_components(&SandboxedComponents {
                components: vec![record.clone()],
            })
            .is_ok()
        );
        assert!(
            validate_published_sandboxed_components(&PublishedSandboxedComponents {
                components: vec![PublishedSandboxedComponent {
                    name: record.name.clone(),
                    html: record.published_html.clone().unwrap(),
                    css: record.published_css.clone().unwrap(),
                    js_functions: record.published_js_functions.clone().unwrap(),
                    argument_schema: BTreeMap::new(),
                }],
            })
            .is_ok()
        );
        let mut changed = record.clone();
        changed.draft_html = "<p>changed</p>".to_owned();
        assert_eq!(
            validate_sandboxed_record(&changed).unwrap_err(),
            ApiError::InvalidResponse
        );
        let request = SaveSandboxedComponentRequest {
            expected_revision: None,
            slug: "delivery_eta".to_owned(),
            title: record.title.clone(),
            description: record.draft_description.clone(),
            html: record.draft_html.clone(),
            css: record.draft_css.clone(),
            js_functions: record.draft_js_functions.clone(),
            argument_schema: record.draft_argument_schema.clone(),
            sample_arguments: record.sample_arguments.clone(),
        };
        assert!(validate_sandboxed_draft_receipt(&request, &record).is_ok());
        let mut wrong_target = record.clone();
        wrong_target.name = "custom_other".to_owned();
        assert_eq!(
            validate_sandboxed_draft_receipt(&request, &wrong_target),
            Err(ApiError::InvalidResponse)
        );
        assert_eq!(
            validate_sandboxed_draft_receipt(&request, &changed),
            Err(ApiError::InvalidResponse)
        );
        let mut saved = record.clone();
        saved.revision = 0;
        let mut published = record.clone();
        published.editing_revision = 2;
        assert!(validate_sandboxed_publication_receipt(&request, &saved, &published).is_ok());
        let mut wrong_editing_revision = record.clone();
        wrong_editing_revision.editing_revision = 3;
        assert_eq!(
            validate_sandboxed_draft_receipt(&request, &wrong_editing_revision),
            Err(ApiError::InvalidResponse)
        );
        assert_eq!(
            validate_sandboxed_publication_receipt(&request, &record, &record),
            Err(ApiError::InvalidResponse)
        );
        let mut wrong_snapshot = published.clone();
        wrong_snapshot.published_html = Some("<p>another</p>".into());
        assert_eq!(
            validate_sandboxed_publication_receipt(&request, &saved, &wrong_snapshot),
            Err(ApiError::InvalidResponse)
        );
        let mut shared = component_record("custom_delivery_eta", "Delivery ETA", true);
        shared.kind = CompiledComponentKind::Sandboxed;
        shared.functions = vec!["botActivity".to_owned()];
        assert_eq!(
            validate_component_record(&shared).unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn mcp_paths_projection_and_navigation_receipts_are_closed() {
        assert_eq!(
            mcp_connect_path("google-drive").unwrap(),
            "/api/plugins/servers/google-drive/connect?returnTo=settings"
        );
        assert_eq!(
            mcp_disconnect_path("google-drive").unwrap(),
            "/api/plugins/connections/google-drive"
        );
        assert!(validate_mcp_connections(&mcp_page()).is_ok());
        assert!(
            validate_authorization_target("/settings/connected-accounts?connected=google-drive")
                .is_ok()
        );
        assert!(
            validate_authorization_target(
                "https://accounts.google.com/o/oauth2/v2/auth?state=opaque"
            )
            .is_ok()
        );
        assert!(
            validate_oidc_authorization_target(
                "https://accounts.google.com/o/oauth2/v2/auth?state=opaque"
            )
            .is_ok()
        );
        for invalid in [
            "/api/auth/sso/continue",
            "http://accounts.google.com/authorize",
            "https://accounts.google.com/authorize#token",
        ] {
            assert_eq!(
                validate_oidc_authorization_target(invalid).unwrap_err(),
                ApiError::InvalidResponse
            );
        }

        for invalid in [
            "//attacker.example/path",
            "http://accounts.google.com/authorize",
            "https://user@accounts.google.com/authorize",
            "https://accounts.google.com/authorize#token",
            "javascript:alert(1)",
            "/bad\\path",
        ] {
            assert_eq!(
                validate_authorization_target(invalid).unwrap_err(),
                ApiError::InvalidResponse
            );
        }
        assert_eq!(
            validate_mcp_server_id("google__drive").unwrap_err(),
            ApiError::InvalidResponse
        );
        let mut duplicate = mcp_page();
        duplicate
            .available_server_ids
            .push("google-drive".to_owned());
        assert_eq!(
            validate_mcp_connections(&duplicate).unwrap_err(),
            ApiError::InvalidResponse
        );
        let mut credential_like_scope = mcp_page();
        credential_like_scope.connections[0].scope = "bad\nscope".to_owned();
        assert_eq!(
            validate_mcp_connections(&credential_like_scope).unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn component_human_decision_path_and_pending_projection_are_closed() {
        assert_eq!(
            component_human_decision_answer_path("decision/one?x=1").unwrap(),
            "/api/components/human-decisions/decision%2Fone%3Fx%3D1/answer"
        );
        assert_eq!(
            component_human_decision_answer_path("").unwrap_err(),
            ApiError::InvalidResponse
        );
        let pending = PendingComponentHumanDecision {
            decision_id: "decision-1".to_owned(),
            run_id: RunId::new("run-1"),
            provider_call_id: "provider-call-1".to_owned(),
            agent_id: BotId::new("bot-1"),
            component_name: ASK_APPROVAL_COMPONENT_NAME.to_owned(),
            arguments: serde_json::json!({"title":"Refund?","summary":"Duplicate"}),
            requested_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30),
        };
        let page = PendingComponentHumanDecisions {
            decisions: vec![pending.clone()],
        };
        assert!(validate_pending_component_human_decisions(&page).is_ok());
        let mut duplicate = pending;
        duplicate.decision_id = "decision-2".to_owned();
        assert_eq!(
            validate_pending_component_human_decisions(&PendingComponentHumanDecisions {
                decisions: vec![page.decisions[0].clone(), duplicate],
            })
            .unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn approval_path_is_one_encoded_segment_and_rejects_invalid_ids() {
        assert_eq!(
            approval_decision_path("approval/one?x=1").unwrap(),
            "/api/tool-approvals/approval%2Fone%3Fx%3D1"
        );
        assert_eq!(
            approval_decision_path("").unwrap_err(),
            ApiError::InvalidResponse
        );
        assert_eq!(
            approval_decision_path(&"a".repeat(129)).unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn channel_paths_are_bounded_and_encode_exactly_one_component() {
        assert_eq!(
            channel_detail_path("channel/one?x=1").unwrap(),
            "/api/channels/channel%2Fone%3Fx%3D1"
        );
        assert_eq!(
            channel_route_href("channel/one?x=1").unwrap(),
            "/channel/channel%2Fone%3Fx%3D1"
        );
        assert_eq!(
            channel_list_path(Some("opaque+/=")).unwrap(),
            "/api/channels?limit=50&cursor=opaque%2B%2F%3D"
        );
        assert_eq!(
            bot_chat_href("bot/one?x=1").unwrap(),
            "/bot?agent=bot%2Fone%3Fx%3D1"
        );
        assert_eq!(
            admin_component_href("show.Quote-1").unwrap(),
            "/admin/components/show.Quote-1"
        );
        assert_eq!(
            channel_detail_path("").unwrap_err(),
            ApiError::InvalidResponse
        );
        assert_eq!(
            thread_run_path("thread/one?x=1").unwrap(),
            "/api/threads/thread%2Fone%3Fx%3D1/runs"
        );
        assert_eq!(
            thread_status_path("thread/one?x=1").unwrap(),
            "/api/threads/thread%2Fone%3Fx%3D1"
        );
        assert_eq!(
            thread_conversation_path("thread/one?x=1").unwrap(),
            "/api/threads/thread%2Fone%3Fx%3D1/conversation"
        );
        assert_eq!(
            thread_cancel_path("thread/one?x=1", "run/one?x=2").unwrap(),
            "/api/threads/thread%2Fone%3Fx%3D1/runs/run%2Fone%3Fx%3D2/cancel"
        );
        assert_eq!(
            thread_event_stream_path(&ThreadId::new("thread/one?x=1"), Some(7)).unwrap(),
            "/api/threads/thread%2Fone%3Fx%3D1/events?cursor=7"
        );
        assert_eq!(
            channel_list_path(Some("bad\ncursor")).unwrap_err(),
            ApiError::InvalidResponse
        );

        let explicit_id = BotId::new("knowledge");
        let explicit = ChannelRoutingDecision {
            agent_id: explicit_id.clone(),
            name: "Knowledge Desk".to_owned(),
            reason: "named by the person asking".to_owned(),
            fallback: false,
            via_mention: true,
        };
        assert!(validate_routing_decision(Some(&explicit_id), &explicit).is_ok());
        assert_eq!(
            validate_routing_decision(None, &explicit).unwrap_err(),
            ApiError::InvalidResponse
        );

        let mut inferred = explicit;
        inferred.via_mention = false;
        inferred.fallback = true;
        assert!(validate_routing_decision(None, &inferred).is_ok());
        inferred.reason = "界".repeat(MAX_CHANNEL_ROUTING_REASON_CODE_POINTS + 1);
        assert_eq!(
            validate_routing_decision(None, &inferred).unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn memory_paths_and_pages_are_closed_bounded_and_owner_safe() {
        assert_eq!(
            memory_list_path(Some("memory/one?x=1")).unwrap(),
            "/api/memories?limit=50&cursor=memory%2Fone%3Fx%3D1"
        );
        assert_eq!(
            memory_detail_path("memory/one?x=1").unwrap(),
            "/api/memories/memory%2Fone%3Fx%3D1"
        );
        assert_eq!(
            memory_detail_path("bad\nmemory").unwrap_err(),
            ApiError::InvalidResponse
        );

        let active = memory_record("memory-1", Some("tea"), MemoryStatus::Active);
        assert!(validate_memory_record(&active).is_ok());
        let mut erased_active = active.clone();
        erased_active.content = None;
        assert_eq!(
            validate_memory_record(&erased_active).unwrap_err(),
            ApiError::InvalidResponse
        );
        let duplicate = MemoryPage {
            memories: vec![active.clone(), active],
            next_cursor: None,
        };
        assert_eq!(
            validate_memory_page(&duplicate).unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn audit_path_and_page_are_bounded_unique_and_payload_closed() {
        assert_eq!(
            audit_page_path(Some("cursor/one?x=1")).unwrap(),
            "/api/admin/audit-events?limit=50&cursor=cursor%2Fone%3Fx%3D1"
        );
        assert_eq!(
            audit_page_path(Some("bad\ncursor")).unwrap_err(),
            ApiError::InvalidResponse
        );
        let event = AuditEventView {
            id: openbot_contracts::ids::AuditEventId::new("event-1"),
            actor_user_id: Some(openbot_contracts::ids::ActorId::new("actor-1")),
            event_type: "tool.approval_granted".to_owned(),
            target_type: "tool_approval".to_owned(),
            target_id: Some("approval-1".to_owned()),
            payload: serde_json::json!({"effect":"execute"}),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        let page = AuditPage {
            events: vec![event.clone()],
            next_cursor: Some("cursor-2".to_owned()),
        };
        assert!(validate_audit_page(&page).is_ok());
        let duplicate = AuditPage {
            events: vec![event.clone(), event],
            next_cursor: None,
        };
        assert_eq!(
            validate_audit_page(&duplicate).unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn people_paths_pages_and_mutation_receipts_are_closed_and_unique() {
        assert_eq!(
            people_page_path("Target + one", Some("cursor/one?x=1")).unwrap(),
            "/api/admin/people?limit=50&search=Target%20%2B%20one&cursor=cursor%2Fone%3Fx%3D1"
        );
        assert_eq!(
            people_page_path("bad\nsearch", None).unwrap_err(),
            ApiError::InvalidResponse
        );
        assert_eq!(
            person_mutation_path("person/one?x=1", "role").unwrap(),
            "/api/admin/people/person%2Fone%3Fx%3D1/role"
        );
        assert_eq!(
            person_mutation_path("person-1", "delete").unwrap_err(),
            ApiError::InvalidResponse
        );

        let person = Person {
            id: openbot_contracts::ids::ActorId::new("person-1"),
            email: "person-1@example.test".to_owned(),
            name: Some("Person One".to_owned()),
            image: None,
            role: openbot_contracts::auth::Role::User,
            providers: vec!["google".to_owned(), "okta".to_owned()],
            last_signed_in_at: Some(OffsetDateTime::UNIX_EPOCH),
            revoked: false,
            configured_admin: false,
        };
        assert!(validate_mutated_person("person-1", &person).is_ok());
        assert_eq!(
            validate_mutated_person("person-2", &person).unwrap_err(),
            ApiError::InvalidResponse
        );
        let duplicate = PeoplePage {
            people: vec![person.clone(), person],
            next_cursor: None,
        };
        assert_eq!(
            validate_people_page(&duplicate).unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn identity_provider_projection_domains_and_delete_path_are_closed() {
        assert_eq!(
            canonical_identity_provider_domains("Second.Example, acme.example").unwrap(),
            "acme.example,second.example"
        );
        assert_eq!(
            canonical_identity_provider_domains("acme.example,ACME.EXAMPLE").unwrap_err(),
            ApiError::InvalidResponse
        );
        assert_eq!(
            identity_provider_remove_path("acme-saml").unwrap(),
            "/api/admin/identity-providers/acme-saml"
        );
        assert_eq!(
            identity_provider_remove_path("Acme/saml").unwrap_err(),
            ApiError::InvalidResponse
        );

        let provider = RegisteredIdentityProvider {
            provider_id: "acme-saml".to_owned(),
            issuer: "urn:acme:idp".to_owned(),
            domain: "acme.example,second.example".to_owned(),
            protocol: openbot_contracts::identity_provider::SsoProtocol::Saml,
            registered_by: Some("actor".to_owned()),
        };
        assert!(validate_identity_providers(core::slice::from_ref(&provider)).is_ok());
        assert_eq!(
            validate_identity_providers(&[provider.clone(), provider]).unwrap_err(),
            ApiError::InvalidResponse
        );

        let duplicate_domain = RegisteredIdentityProvider {
            provider_id: "other-saml".to_owned(),
            issuer: "urn:other:idp".to_owned(),
            domain: "second.example".to_owned(),
            protocol: openbot_contracts::identity_provider::SsoProtocol::Saml,
            registered_by: None,
        };
        let first = RegisteredIdentityProvider {
            provider_id: "acme-saml".to_owned(),
            issuer: "urn:acme:idp".to_owned(),
            domain: "acme.example,second.example".to_owned(),
            protocol: openbot_contracts::identity_provider::SsoProtocol::Saml,
            registered_by: None,
        };
        assert_eq!(
            validate_identity_providers(&[first, duplicate_domain]).unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn action_policy_receipt_must_be_present_and_exact() {
        let requested = ActionPolicyDocument {
            mode: openbot_contracts::policy::ActionPolicyMode::DryRun,
            deny: vec!["intent == \"activate\"".to_owned()],
            allow: vec!["true".to_owned()],
        };
        assert_eq!(
            validate_action_policy_receipt(
                &requested,
                ActionPolicyResponse {
                    policy: Some(requested.clone()),
                },
            )
            .unwrap(),
            requested,
        );
        assert_eq!(
            validate_action_policy_receipt(&requested, ActionPolicyResponse { policy: None },)
                .unwrap_err(),
            ApiError::InvalidResponse,
        );
        let mut drifted = requested.clone();
        drifted.allow.clear();
        assert_eq!(
            validate_action_policy_receipt(
                &requested,
                ActionPolicyResponse {
                    policy: Some(drifted),
                },
            )
            .unwrap_err(),
            ApiError::InvalidResponse,
        );
    }

    #[test]
    fn agent_write_ack_must_bind_target_and_normalized_public_intent() {
        use openbot_contracts::agent::AgentVisibility;
        let request = AgentMutationRequest {
            name: "\u{FEFF}Ada ".into(),
            title: " Assistant ".into(),
            role_description: " Solve\ncarefully ".into(),
            visibility: AgentVisibility::Private,
            endpoint: None,
            auth: None,
        };
        let expected = AgentWriteIntent::new(&request).unwrap();
        let profile = AgentProfile {
            id: BotId::new("agent-a"),
            name: "Ada".into(),
            title: "Assistant".into(),
            role_description: "Solve\ncarefully".into(),
            avatar_seed: "seed".into(),
            visibility: AgentVisibility::Private,
            endpoint: None,
            has_auth: false,
            has_callback_token: false,
            hidden: false,
            system_owned: false,
            can_manage: true,
            mine: true,
        };
        assert!(expected.validate_receipt(&profile, Some("agent-a")).is_ok());
        assert!(expected.validate_receipt(&profile, None).is_ok());
        assert_eq!(
            expected.validate_receipt(&profile, Some("agent-b")),
            Err(ApiError::InvalidResponse)
        );
        for variant in 0..6 {
            let mut wrong = profile.clone();
            match variant {
                0 => wrong.name.push('x'),
                1 => wrong.title.push('x'),
                2 => wrong.role_description.push('x'),
                3 => wrong.visibility = AgentVisibility::Public,
                4 => wrong.endpoint = Some("https://other.invalid".into()),
                _ => wrong.can_manage = false,
            }
            assert_eq!(
                expected.validate_receipt(&wrong, Some("agent-a")),
                Err(ApiError::InvalidResponse)
            );
        }
        assert_eq!(
            validate_agent_duplicate_receipt("agent-a", &profile),
            Err(ApiError::InvalidResponse)
        );
        assert!(validate_agent_duplicate_receipt("source", &profile).is_ok());
        let mut invalid = request;
        invalid.name.clear();
        assert!(matches!(
            AgentWriteIntent::new(&invalid),
            Err(ApiError::NotSubmitted)
        ));
    }

    #[test]
    fn memory_correction_ack_rejects_a_different_edit_of_the_same_original() {
        let correction = CorrectMemory {
            content: "未经规范化的修正".into(),
            tags: vec!["z".into(), "a".into(), "z".into()],
            sensitivity: MemorySensitivity::Sensitive,
            expires_at: Some(OffsetDateTime::UNIX_EPOCH + time::Duration::days(10)),
        };
        let mut record = memory_record(
            "replacement",
            Some(&correction.content),
            MemoryStatus::Active,
        );
        record.supersedes_id = Some("original".into());
        record.tags = vec!["a".into(), "z".into()];
        record.sensitivity = correction.sensitivity;
        record.expires_at = correction.expires_at;
        assert!(validate_memory_correction_receipt("original", &correction, &record).is_ok());
        for variant in 0..6 {
            let mut wrong = record.clone();
            match variant {
                0 => wrong.content = Some("另一份修正".into()),
                1 => wrong.tags.push("extra".into()),
                2 => wrong.sensitivity = MemorySensitivity::Normal,
                3 => wrong.expires_at = None,
                4 => wrong.supersedes_id = Some("other".into()),
                _ => wrong.memory_id = "original".into(),
            }
            assert_eq!(
                validate_memory_correction_receipt("original", &correction, &wrong),
                Err(ApiError::InvalidResponse)
            );
        }
    }

    #[test]
    fn agent_paths_are_bounded_and_encode_one_path_or_query_component() {
        assert_eq!(
            agent_detail_path("agent/one?x=1").unwrap(),
            "/api/agents/agent%2Fone%3Fx%3D1"
        );
        assert_eq!(
            agent_profile_href("agent/one?x=1").unwrap(),
            "/agents?agent=agent%2Fone%3Fx%3D1"
        );
        assert_eq!(
            agent_callback_token_path("agent/one?x=1").unwrap(),
            "/api/agents/agent%2Fone%3Fx%3D1/callback-token"
        );
        assert_eq!(
            channel_new_href("agent/one?x=1").unwrap(),
            "/channel/new?agent=agent%2Fone%3Fx%3D1"
        );
        assert_eq!(
            agent_detail_path("").unwrap_err(),
            ApiError::InvalidResponse
        );
        assert_eq!(
            agent_profile_href("bad\nagent").unwrap_err(),
            ApiError::InvalidResponse
        );
    }
}
