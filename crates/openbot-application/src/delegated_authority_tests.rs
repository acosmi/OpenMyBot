use super::*;
use crate::fakes::{FakeChannelReader, FakePeopleAdministration, auth_for, sample_person};
use openbot_contracts::agent::{AgentConnectionTestRequest, AgentMutationRequest, AgentVisibility};
use openbot_contracts::artifact_read_protocol::{
    AcknowledgeArtifactReadBlock, CloseArtifactRead, OpenArtifactRead, ReadArtifactReadBlock,
};
use openbot_contracts::artifacts::*;
use openbot_contracts::auth::{
    AuthContextBuilder, AuthGeneration, DelegationSource, Role, VerifiedDelegation,
};
use openbot_contracts::budget::RunCostBudgetPreference;
use openbot_contracts::command::*;
use openbot_contracts::components::*;
use openbot_contracts::credential_admin::{CredentialPageRequest, CredentialWrite};
use openbot_contracts::custom_model_catalog::CustomModelCatalogPageRequest;
use openbot_contracts::ids::*;
use openbot_contracts::mcp::*;
use openbot_contracts::memory::*;
use openbot_contracts::model_connections::*;
use openbot_contracts::policy::{ActionPolicyDocument, ActionPolicyMode};
use openbot_contracts::remote_interrupt::{RemoteInterruptAnswer, RemoteInterruptAnswerStatus};
use openbot_contracts::sandboxed::SaveSandboxedComponentRequest;
use openbot_contracts::screen::{
    ScreenSessionRequest, ScreenSessionTarget, ScreenViewerBindingRequest,
};
use openbot_contracts::tool::{ToolApprovalDecision, ToolInvocation};
use openbot_contracts::ui::UpdateUiPreferences;
use openbot_contracts::versioned_model_selection::{
    ModelSelectionIntentSource, RunModelSelectionV2,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

fn delegated(
    external: bool,
    roles: &[Role],
    generation: u64,
    revision: u64,
    expiry: Option<SystemTime>,
    single_user: bool,
) -> AuthContext {
    let source = if external {
        DelegationSource::ExternalBinding {
            binding_id: "binding".into(),
        }
    } else {
        DelegationSource::AutomationDefinition {
            definition_id: "definition".into(),
        }
    };
    let delegation = VerifiedDelegation::from_verified_grant(
        source,
        revision,
        "trigger".into(),
        AuthGeneration::new(generation),
        expiry,
    )
    .unwrap();
    AuthContextBuilder::from_verified_delegation(
        DeploymentId::new("dep-g1"),
        TenantId::new("tenant-g1"),
        ActorId::new("owner"),
        AuthGeneration::new(generation),
        single_user,
        delegation,
    )
    .with_roles(roles.iter().copied())
    .build()
}

fn assert_refused<T>(result: Result<T, AppError>) {
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("delegated request was dispatched"),
    };
    assert_eq!(error.http_status(), 403);
    assert_eq!(error.code().as_str(), "policy_refused");
    match error {
        AppError::PolicyRefused { rule, decision } => {
            assert_eq!(rule, "delegated_authority_refused");
            assert!(decision.is_none());
        }
        other => panic!("wrong refusal: {other:?}"),
    }
}

fn agent() -> AgentMutationRequest {
    AgentMutationRequest {
        name: String::new(),
        title: String::new(),
        role_description: String::new(),
        visibility: AgentVisibility::Private,
        endpoint: None,
        auth: None,
    }
}
fn credential() -> CredentialWrite {
    serde_json::from_value(json!({"kind":"model","provider":"fixture","keyId":"fixture","metadata":{},"plaintext":"fixture-only-secret"})).unwrap()
}
fn plugin() -> PluginGrantMutation {
    PluginGrantMutation {
        kind: PluginGrantKind::Skill,
        reference: String::new(),
        agent_id: String::new(),
    }
}
fn tool(run: &str) -> AppCommand {
    AppCommand::InvokeTool(ToolInvocation {
        call_id: ToolCallId::new("call"),
        run_id: RunId::new(run),
        bot_id: BotId::new("owner"),
        call_seq: 0,
        tool_name: String::new(),
        arguments: Value::Null,
    })
}
fn human(run: &str) -> AppCommand {
    AppCommand::AwaitComponentHumanDecision(ComponentHumanDecisionRequest {
        decision_id: String::new(),
        provider_call_id: String::new(),
        run_id: RunId::new(run),
        thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
        agent_id: BotId::new("owner"),
        component_name: String::new(),
        arguments: Value::Null,
    })
}
fn subscriptions() -> [SubscriptionRequest; 4] {
    [
        SubscriptionRequest::Health,
        SubscriptionRequest::ThreadEvents {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            after_event_sequence: None,
        },
        SubscriptionRequest::ChannelActivity,
        SubscriptionRequest::ToolApprovalActivity,
    ]
}

// Fixed independent expected inventory; no wildcard in the typed projection below.
const EXPECTED_COMMANDS: [&str; 99] = [
    "GetRuntimeCapabilities",
    "SaveRunMessageTextArtifact",
    "GetArtifactMetadata",
    "GetSourceRunArtifactIds",
    "GetArtifactSaveReceipt",
    "OpenArtifactRead",
    "ReadArtifactReadBlock",
    "AcknowledgeArtifactReadBlock",
    "CloseArtifactRead",
    "Health",
    "ListModelConnections",
    "ListCustomModelCatalog",
    "GetModelConnection",
    "CreateModelConnection",
    "UpdateModelConnection",
    "DeleteModelConnection",
    "ListVisibleChannels",
    "GetVisibleChannel",
    "CreateChannel",
    "RouteChannelMessage",
    "ListVisibleAgents",
    "GetVisibleAgent",
    "CreateAgent",
    "UpdateAgent",
    "DuplicateAgent",
    "SetAgentHidden",
    "DeleteAgent",
    "TestAgentConnection",
    "ListComponents",
    "SyncComponentCatalogue",
    "UpdateComponentGovernance",
    "ListComponentsForAgent",
    "DecideComponent",
    "ListComponentDataFunctions",
    "CallComponentFunction",
    "AwaitComponentHumanDecision",
    "ListPendingComponentHumanDecisions",
    "ResolveComponentHumanDecision",
    "ListSandboxedComponents",
    "ListPublishedSandboxedComponents",
    "SaveSandboxedComponent",
    "PublishSandboxedComponent",
    "DeleteSandboxedComponent",
    "AuthorizeSandboxedComponent",
    "GetCurrentUser",
    "AdminStatus",
    "ListPeople",
    "ChangePersonRole",
    "ChangePersonAccess",
    "ListAuditEvents",
    "GetActionPolicy",
    "SetActionPolicy",
    "InvokeTool",
    "MintThreadId",
    "GetThreadStatus",
    "BeginThreadRun",
    "BeginThreadRunV2",
    "CancelThreadRun",
    "DeleteThreadHistory",
    "GetThreadHistory",
    "GetThreadConversation",
    "GetRunReconciliation",
    "GetRunEffectReceipts",
    "ListPendingRemoteInterrupts",
    "ResolveRemoteInterrupt",
    "RememberMemory",
    "GetMemoryControl",
    "UpdateMemoryControl",
    "ListMemories",
    "CorrectMemory",
    "MutateMemory",
    "RecallMemories",
    "IssueAgentCallbackToken",
    "RevokeAgentCallbackToken",
    "ListMcpConnections",
    "ListCredentials",
    "CreateCredential",
    "RotateCredential",
    "RevokeCredential",
    "ListMcpAdminPage",
    "BeginMcpOAuth",
    "DisconnectMcpConnection",
    "RegisterMcpOAuthClient",
    "AddCuratedMcpServer",
    "AddCustomMcpServer",
    "RemoveMcpServer",
    "RefreshMcpServer",
    "SavePluginSkill",
    "RemovePluginSkill",
    "GrantPlugin",
    "RevokePlugin",
    "ListPluginsForAgent",
    "ListPendingToolApprovals",
    "DecideToolApproval",
    "GetUiPreferences",
    "UpdateUiPreferences",
    "GetRunCostBudget",
    "ReplaceRunCostBudget",
    "IssueScreenSession",
];

fn variant_name(command: &AppCommand) -> &'static str {
    match command {
        AppCommand::GetRuntimeCapabilities => "GetRuntimeCapabilities",
        AppCommand::SaveRunMessageTextArtifact(..) => "SaveRunMessageTextArtifact",
        AppCommand::GetArtifactMetadata(..) => "GetArtifactMetadata",
        AppCommand::GetSourceRunArtifactIds(..) => "GetSourceRunArtifactIds",
        AppCommand::GetArtifactSaveReceipt(..) => "GetArtifactSaveReceipt",
        AppCommand::OpenArtifactRead(..) => "OpenArtifactRead",
        AppCommand::ReadArtifactReadBlock(..) => "ReadArtifactReadBlock",
        AppCommand::AcknowledgeArtifactReadBlock(..) => "AcknowledgeArtifactReadBlock",
        AppCommand::CloseArtifactRead(..) => "CloseArtifactRead",
        AppCommand::Health => "Health",
        AppCommand::ListModelConnections(..) => "ListModelConnections",
        AppCommand::ListCustomModelCatalog(..) => "ListCustomModelCatalog",
        AppCommand::GetModelConnection { .. } => "GetModelConnection",
        AppCommand::CreateModelConnection(..) => "CreateModelConnection",
        AppCommand::UpdateModelConnection { .. } => "UpdateModelConnection",
        AppCommand::DeleteModelConnection { .. } => "DeleteModelConnection",
        AppCommand::ListVisibleChannels { .. } => "ListVisibleChannels",
        AppCommand::GetVisibleChannel { .. } => "GetVisibleChannel",
        AppCommand::CreateChannel { .. } => "CreateChannel",
        AppCommand::RouteChannelMessage { .. } => "RouteChannelMessage",
        AppCommand::ListVisibleAgents { .. } => "ListVisibleAgents",
        AppCommand::GetVisibleAgent { .. } => "GetVisibleAgent",
        AppCommand::CreateAgent(..) => "CreateAgent",
        AppCommand::UpdateAgent { .. } => "UpdateAgent",
        AppCommand::DuplicateAgent { .. } => "DuplicateAgent",
        AppCommand::SetAgentHidden { .. } => "SetAgentHidden",
        AppCommand::DeleteAgent { .. } => "DeleteAgent",
        AppCommand::TestAgentConnection(..) => "TestAgentConnection",
        AppCommand::ListComponents => "ListComponents",
        AppCommand::SyncComponentCatalogue(..) => "SyncComponentCatalogue",
        AppCommand::UpdateComponentGovernance(..) => "UpdateComponentGovernance",
        AppCommand::ListComponentsForAgent { .. } => "ListComponentsForAgent",
        AppCommand::DecideComponent { .. } => "DecideComponent",
        AppCommand::ListComponentDataFunctions => "ListComponentDataFunctions",
        AppCommand::CallComponentFunction { .. } => "CallComponentFunction",
        AppCommand::AwaitComponentHumanDecision(..) => "AwaitComponentHumanDecision",
        AppCommand::ListPendingComponentHumanDecisions => "ListPendingComponentHumanDecisions",
        AppCommand::ResolveComponentHumanDecision { .. } => "ResolveComponentHumanDecision",
        AppCommand::ListSandboxedComponents => "ListSandboxedComponents",
        AppCommand::ListPublishedSandboxedComponents => "ListPublishedSandboxedComponents",
        AppCommand::SaveSandboxedComponent(..) => "SaveSandboxedComponent",
        AppCommand::PublishSandboxedComponent { .. } => "PublishSandboxedComponent",
        AppCommand::DeleteSandboxedComponent { .. } => "DeleteSandboxedComponent",
        AppCommand::AuthorizeSandboxedComponent { .. } => "AuthorizeSandboxedComponent",
        AppCommand::GetCurrentUser => "GetCurrentUser",
        AppCommand::AdminStatus => "AdminStatus",
        AppCommand::ListPeople { .. } => "ListPeople",
        AppCommand::ChangePersonRole { .. } => "ChangePersonRole",
        AppCommand::ChangePersonAccess { .. } => "ChangePersonAccess",
        AppCommand::ListAuditEvents { .. } => "ListAuditEvents",
        AppCommand::GetActionPolicy => "GetActionPolicy",
        AppCommand::SetActionPolicy { .. } => "SetActionPolicy",
        AppCommand::InvokeTool(..) => "InvokeTool",
        AppCommand::MintThreadId => "MintThreadId",
        AppCommand::GetThreadStatus { .. } => "GetThreadStatus",
        AppCommand::BeginThreadRun(..) => "BeginThreadRun",
        AppCommand::BeginThreadRunV2(..) => "BeginThreadRunV2",
        AppCommand::CancelThreadRun(..) => "CancelThreadRun",
        AppCommand::DeleteThreadHistory { .. } => "DeleteThreadHistory",
        AppCommand::GetThreadHistory { .. } => "GetThreadHistory",
        AppCommand::GetThreadConversation { .. } => "GetThreadConversation",
        AppCommand::GetRunReconciliation { .. } => "GetRunReconciliation",
        AppCommand::GetRunEffectReceipts { .. } => "GetRunEffectReceipts",
        AppCommand::ListPendingRemoteInterrupts => "ListPendingRemoteInterrupts",
        AppCommand::ResolveRemoteInterrupt { .. } => "ResolveRemoteInterrupt",
        AppCommand::RememberMemory(..) => "RememberMemory",
        AppCommand::GetMemoryControl => "GetMemoryControl",
        AppCommand::UpdateMemoryControl(..) => "UpdateMemoryControl",
        AppCommand::ListMemories { .. } => "ListMemories",
        AppCommand::CorrectMemory { .. } => "CorrectMemory",
        AppCommand::MutateMemory { .. } => "MutateMemory",
        AppCommand::RecallMemories(..) => "RecallMemories",
        AppCommand::IssueAgentCallbackToken { .. } => "IssueAgentCallbackToken",
        AppCommand::RevokeAgentCallbackToken { .. } => "RevokeAgentCallbackToken",
        AppCommand::ListMcpConnections => "ListMcpConnections",
        AppCommand::ListCredentials(..) => "ListCredentials",
        AppCommand::CreateCredential(..) => "CreateCredential",
        AppCommand::RotateCredential { .. } => "RotateCredential",
        AppCommand::RevokeCredential { .. } => "RevokeCredential",
        AppCommand::ListMcpAdminPage => "ListMcpAdminPage",
        AppCommand::BeginMcpOAuth { .. } => "BeginMcpOAuth",
        AppCommand::DisconnectMcpConnection { .. } => "DisconnectMcpConnection",
        AppCommand::RegisterMcpOAuthClient { .. } => "RegisterMcpOAuthClient",
        AppCommand::AddCuratedMcpServer { .. } => "AddCuratedMcpServer",
        AppCommand::AddCustomMcpServer(..) => "AddCustomMcpServer",
        AppCommand::RemoveMcpServer { .. } => "RemoveMcpServer",
        AppCommand::RefreshMcpServer { .. } => "RefreshMcpServer",
        AppCommand::SavePluginSkill(..) => "SavePluginSkill",
        AppCommand::RemovePluginSkill { .. } => "RemovePluginSkill",
        AppCommand::GrantPlugin(..) => "GrantPlugin",
        AppCommand::RevokePlugin(..) => "RevokePlugin",
        AppCommand::ListPluginsForAgent { .. } => "ListPluginsForAgent",
        AppCommand::ListPendingToolApprovals => "ListPendingToolApprovals",
        AppCommand::DecideToolApproval { .. } => "DecideToolApproval",
        AppCommand::GetUiPreferences => "GetUiPreferences",
        AppCommand::UpdateUiPreferences(..) => "UpdateUiPreferences",
        AppCommand::GetRunCostBudget => "GetRunCostBudget",
        AppCommand::ReplaceRunCostBudget(..) => "ReplaceRunCostBudget",
        AppCommand::IssueScreenSession(..) => "IssueScreenSession",
    }
}

fn commands() -> Vec<AppCommand> {
    vec![
        AppCommand::GetRuntimeCapabilities,
        AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
            request_id: String::new(),
            source_thread_id: ThreadId::new(""),
            source_run_id: RunId::new(""),
            source_message_id: String::new(),
            expected_sha256: String::new(),
        }),
        AppCommand::GetArtifactMetadata(GetArtifactMetadata {
            artifact_id: String::new(),
        }),
        AppCommand::GetSourceRunArtifactIds(GetSourceRunArtifactIds {
            source_thread_id: ThreadId::new(""),
            source_run_id: RunId::new(""),
        }),
        AppCommand::GetArtifactSaveReceipt(GetArtifactSaveReceipt {
            request_id: String::new(),
        }),
        AppCommand::OpenArtifactRead(OpenArtifactRead {
            artifact_id: String::new(),
        }),
        AppCommand::ReadArtifactReadBlock(ReadArtifactReadBlock {
            handle_id: String::new(),
            sequence: u32::MAX,
        }),
        AppCommand::AcknowledgeArtifactReadBlock(AcknowledgeArtifactReadBlock {
            handle_id: String::new(),
            sequence: u32::MAX,
        }),
        AppCommand::CloseArtifactRead(CloseArtifactRead {
            handle_id: String::new(),
        }),
        AppCommand::Health,
        AppCommand::ListModelConnections(ModelConnectionPageRequest {
            cursor: Some("invalid".into()),
        }),
        AppCommand::ListCustomModelCatalog(CustomModelCatalogPageRequest {
            cursor: Some("invalid".into()),
        }),
        AppCommand::GetModelConnection {
            connection_id: String::new(),
        },
        AppCommand::CreateModelConnection(CreateModelConnection {
            name: String::new(),
            protocol: CustomModelProtocol::OpenaiResponses,
            endpoint: String::new(),
            model: String::new(),
            enabled: true,
            api_key: serde_json::from_value(json!("fixture-only-key")).unwrap(),
        }),
        AppCommand::UpdateModelConnection {
            connection_id: String::new(),
            input: UpdateModelConnection {
                expected_revision: -1,
                name: String::new(),
                protocol: CustomModelProtocol::OpenaiResponses,
                endpoint: String::new(),
                model: String::new(),
                enabled: true,
                api_key: None,
            },
        },
        AppCommand::DeleteModelConnection {
            connection_id: String::new(),
            input: DeleteModelConnection {
                expected_revision: -1,
            },
        },
        AppCommand::ListVisibleChannels {
            limit: None,
            cursor: None,
        },
        AppCommand::GetVisibleChannel {
            channel_id: ChannelId::new(""),
        },
        AppCommand::CreateChannel { agent_ids: vec![] },
        AppCommand::RouteChannelMessage {
            text: String::new(),
            agent_id: None,
        },
        AppCommand::ListVisibleAgents { hidden: false },
        AppCommand::GetVisibleAgent {
            agent_id: BotId::new(""),
        },
        AppCommand::CreateAgent(agent()),
        AppCommand::UpdateAgent {
            agent_id: BotId::new(""),
            request: agent(),
        },
        AppCommand::DuplicateAgent {
            agent_id: BotId::new(""),
        },
        AppCommand::SetAgentHidden {
            agent_id: BotId::new(""),
            hidden: false,
        },
        AppCommand::DeleteAgent {
            agent_id: BotId::new(""),
        },
        AppCommand::TestAgentConnection(AgentConnectionTestRequest {
            endpoint: String::new(),
            auth: None,
        }),
        AppCommand::ListComponents,
        AppCommand::SyncComponentCatalogue(ComponentCatalogueRequest { components: vec![] }),
        AppCommand::UpdateComponentGovernance(ComponentGovernanceMutation::SetPublication {
            component_name: String::new(),
            published: true,
        }),
        AppCommand::ListComponentsForAgent {
            agent_id: BotId::new(""),
        },
        AppCommand::DecideComponent {
            component_name: String::new(),
            request: ComponentDecisionRequest {
                agent_id: BotId::new("owner"),
                functions: vec![],
            },
        },
        AppCommand::ListComponentDataFunctions,
        AppCommand::CallComponentFunction {
            component_name: String::new(),
            request: ComponentFunctionCallRequest {
                agent_id: BotId::new(""),
                function: String::new(),
                args: Value::Null,
            },
        },
        human("trigger"),
        AppCommand::ListPendingComponentHumanDecisions,
        AppCommand::ResolveComponentHumanDecision {
            decision_id: String::new(),
            answer: ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: ComponentApprovalDecision::Approved,
                note: Some("\0".into()),
            }),
        },
        AppCommand::ListSandboxedComponents,
        AppCommand::ListPublishedSandboxedComponents,
        AppCommand::SaveSandboxedComponent(SaveSandboxedComponentRequest {
            expected_revision: Some(-1),
            slug: String::new(),
            title: String::new(),
            description: String::new(),
            html: String::new(),
            css: String::new(),
            js_functions: String::new(),
            argument_schema: Default::default(),
            sample_arguments: Default::default(),
        }),
        AppCommand::PublishSandboxedComponent {
            component_name: String::new(),
            expected_revision: -1,
        },
        AppCommand::DeleteSandboxedComponent {
            component_name: String::new(),
            expected_revision: -1,
        },
        AppCommand::AuthorizeSandboxedComponent {
            component_name: String::new(),
            agent_id: BotId::new(""),
            arguments: Value::Null,
        },
        AppCommand::GetCurrentUser,
        AppCommand::AdminStatus,
        AppCommand::ListPeople {
            search: None,
            cursor: None,
            limit: None,
        },
        AppCommand::ChangePersonRole {
            user_id: ActorId::new(""),
            role: Role::Admin,
        },
        AppCommand::ChangePersonAccess {
            user_id: ActorId::new(""),
            revoked: false,
        },
        AppCommand::ListAuditEvents {
            cursor: None,
            event_type: None,
            actor_user_id: None,
            target_type: None,
            target_id: None,
            from: None,
            to: None,
            limit: None,
        },
        AppCommand::GetActionPolicy,
        AppCommand::SetActionPolicy {
            policy: ActionPolicyDocument {
                mode: ActionPolicyMode::Enforce,
                deny: vec!["invalid CEL".into()],
                allow: vec![],
            },
        },
        tool("trigger"),
        AppCommand::MintThreadId,
        AppCommand::GetThreadStatus {
            thread_id: ThreadId::new(""),
        },
        AppCommand::BeginThreadRun(BeginThreadRun {
            model_selection: None,
            thread_id: ThreadId::new(""),
            run_id: RunId::new(""),
            bot_id: BotId::new(""),
            anchor: ThreadRunAnchor::DirectBot,
            message: String::new(),
            selected_skill_slugs: vec![],
            artifact_refs: vec![],
        }),
        AppCommand::BeginThreadRunV2(BeginThreadRunV2 {
            model_selection: RunModelSelectionV2::new(
                ModelSelectionIntentSource::Custom,
                "01901000-0000-7000-8000-000000000001".into(),
                1,
                "fixture".into(),
                1,
            )
            .unwrap(),
            thread_id: ThreadId::new(""),
            run_id: RunId::new(""),
            bot_id: BotId::new(""),
            anchor: ThreadRunAnchor::DirectBot,
            message: String::new(),
            selected_skill_slugs: vec![],
            artifact_refs: vec![],
        }),
        AppCommand::CancelThreadRun(CancelThreadRun {
            thread_id: ThreadId::new(""),
            run_id: RunId::new(""),
        }),
        AppCommand::DeleteThreadHistory {
            thread_id: ThreadId::new(""),
            request_id: String::new(),
        },
        AppCommand::GetThreadHistory {
            thread_id: ThreadId::new(""),
        },
        AppCommand::GetThreadConversation {
            thread_id: ThreadId::new(""),
        },
        AppCommand::GetRunReconciliation {
            thread_id: ThreadId::new(""),
            run_id: RunId::new(""),
            after: None,
            limit: None,
        },
        AppCommand::GetRunEffectReceipts {
            thread_id: ThreadId::new(""),
            run_id: RunId::new(""),
            after: None,
            limit: None,
        },
        AppCommand::ListPendingRemoteInterrupts,
        AppCommand::ResolveRemoteInterrupt {
            request_id: String::new(),
            answer: RemoteInterruptAnswer {
                status: RemoteInterruptAnswerStatus::Cancelled,
                payload: Some(Value::Null),
            },
        },
        AppCommand::RememberMemory(RememberMemory {
            memory_kind: MemoryKind::Fact,
            scope: MemoryScope::User,
            content: String::new(),
            tags: vec![],
            sensitivity: MemorySensitivity::Normal,
            source: None,
            expires_at: None,
        }),
        AppCommand::GetMemoryControl,
        AppCommand::UpdateMemoryControl(UpdateMemoryControl {
            writes_enabled: true,
        }),
        AppCommand::ListMemories {
            cursor: None,
            limit: None,
        },
        AppCommand::CorrectMemory {
            memory_id: String::new(),
            correction: CorrectMemory {
                content: String::new(),
                tags: vec![],
                sensitivity: MemorySensitivity::Normal,
                expires_at: None,
            },
        },
        AppCommand::MutateMemory {
            memory_id: String::new(),
            mutation: MemoryMutation::Delete,
        },
        AppCommand::RecallMemories(RecallMemories {
            query: String::new(),
            tags: vec![],
            bot_id: None,
            thread_id: None,
            limit: Some(0),
        }),
        AppCommand::IssueAgentCallbackToken {
            agent_id: BotId::new(""),
        },
        AppCommand::RevokeAgentCallbackToken {
            agent_id: BotId::new(""),
        },
        AppCommand::ListMcpConnections,
        AppCommand::ListCredentials(CredentialPageRequest {
            cursor: Some("invalid".into()),
        }),
        AppCommand::CreateCredential(credential()),
        AppCommand::RotateCredential {
            credential_id: String::new(),
            input: credential(),
        },
        AppCommand::RevokeCredential {
            credential_id: String::new(),
        },
        AppCommand::ListMcpAdminPage,
        AppCommand::BeginMcpOAuth {
            server_id: String::new(),
            return_to: McpOAuthReturnTo::Settings,
        },
        AppCommand::DisconnectMcpConnection {
            server_id: String::new(),
        },
        AppCommand::RegisterMcpOAuthClient {
            server_id: String::new(),
            registration: McpOAuthClientRegistration::new(
                "fixture".into(),
                "fixture-secret".into(),
                "https://fixture.invalid".into(),
                McpOAuthClientAuthMethod::ClientSecretBasic,
                None,
            )
            .unwrap(),
        },
        AppCommand::AddCuratedMcpServer { key: String::new() },
        AppCommand::AddCustomMcpServer(McpCustomServerRegistration {
            id: String::new(),
            title: String::new(),
            url: String::new(),
            credential_id: None,
            egress_allow_cidrs: vec![],
        }),
        AppCommand::RemoveMcpServer {
            server_id: String::new(),
        },
        AppCommand::RefreshMcpServer {
            server_id: String::new(),
        },
        AppCommand::SavePluginSkill(PluginSkillMutation {
            slug: String::new(),
            title: String::new(),
            summary: String::new(),
            instructions: String::new(),
            deployment_wide: true,
            expected_revision: Some(-1),
        }),
        AppCommand::RemovePluginSkill {
            slug: String::new(),
            expected_revision: -1,
        },
        AppCommand::GrantPlugin(plugin()),
        AppCommand::RevokePlugin(plugin()),
        AppCommand::ListPluginsForAgent {
            agent_id: BotId::new(""),
        },
        AppCommand::ListPendingToolApprovals,
        AppCommand::DecideToolApproval {
            approval_id: String::new(),
            decision: ToolApprovalDecision::Grant,
        },
        AppCommand::GetUiPreferences,
        AppCommand::UpdateUiPreferences(UpdateUiPreferences {
            theme: None,
            locale: None,
            expected_revision: Some(-1),
        }),
        AppCommand::GetRunCostBudget,
        AppCommand::ReplaceRunCostBudget(RunCostBudgetPreference { cap: None }),
        AppCommand::IssueScreenSession(ScreenSessionRequest {
            target: ScreenSessionTarget {
                computer_id: ComputerId::new(""),
                computer_generation: ComputerGeneration::new(0),
                tab_id: TabId::new(""),
            },
            binding: ScreenViewerBindingRequest::Server {
                origin: String::new(),
            },
        }),
    ]
}

use crate::components::{
    ComponentAdministrationError, ComponentFunctionCallPlan, ComponentHumanDecisionDraft,
    ComponentHumanDecisionScope, ComponentRuntimeScope,
};
use crate::ports::*;
use crate::tool::*;
use openbot_contracts::audit::AuditPage;
use openbot_domain::policy::{ActionPolicy, PolicyContext};
use openbot_domain::tool::args::ToolArguments;
use openbot_domain::tool::metadata::{ToolMetadata, ToolName};
use openbot_domain::tool::pipeline::{ApprovalOutcome, DurableDecisionReceipt};

#[derive(Clone, Default)]
struct Poison(Arc<AtomicUsize>);
impl Poison {
    fn touched(&self) -> ! {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("delegated request reached a backend port");
    }
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ThreadHistoryDeletion for Poison {
    async fn delete_thread_history_before(
        self: Arc<Self>,
        _auth: &AuthContext,
        _thread_id: &ThreadId,
        _request_id: &str,
    ) -> Result<ThreadHistoryDeletionReceipt, AppError> {
        self.touched()
    }
}

#[async_trait]
impl ToolControlPlane for Poison {
    async fn metadata(&self, _name: &ToolName) -> Result<ToolMetadata, ToolPortError> {
        self.touched()
    }
    async fn resolve_scope(
        &self,
        _auth: &AuthContext,
        _invocation: &ToolInvocation,
        _arguments: &ToolArguments,
        _metadata: &ToolMetadata,
    ) -> Result<ResolvedToolScope, ToolPortError> {
        self.touched()
    }
    async fn evaluate_policy(
        &self,
        _context: &PolicyContext,
    ) -> Result<ToolPolicyEvaluation, ToolPortError> {
        self.touched()
    }
    async fn approval(
        &self,
        _request: &ToolApprovalRequest,
    ) -> Result<ApprovalOutcome, ToolPortError> {
        self.touched()
    }
    async fn execute(&self, _call: AuthorizedToolCall) -> ToolExecutionReport {
        self.touched()
    }
}

#[async_trait]
impl ToolJournal for Poison {
    async fn record_refusal(&self, _draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        self.touched()
    }
    async fn record_decision(
        &self,
        _draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        self.touched()
    }
    async fn attach_capability(
        &self,
        _call_id: &ToolCallId,
        _capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        self.touched()
    }
    async fn record_outcome(&self, _draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        self.touched()
    }
}

#[async_trait]
impl ThreadDirectory for Poison {
    async fn mint_thread_id(
        &self,
        _deployment: &DeploymentId,
    ) -> Result<ThreadId, ThreadDirectoryError> {
        self.touched()
    }
    async fn thread_known(
        &self,
        _deployment: &DeploymentId,
        _tenant: &TenantId,
        _actor: &ActorId,
        _thread: &ThreadId,
    ) -> Result<bool, ThreadDirectoryError> {
        self.touched()
    }
    async fn begin_thread_run(
        &self,
        _request: BeginThreadRunRequest,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        self.touched()
    }
    async fn begin_thread_run_v2(
        &self,
        _request: BeginThreadRunV2Request,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        self.touched()
    }
    async fn observe_begin_replay(
        &self,
        _request: BeginThreadRunRequest,
    ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
        self.touched()
    }
    async fn observe_begin_replay_v2(
        &self,
        _request: BeginThreadRunV2Request,
    ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
        self.touched()
    }
    async fn begin_thread_run_with_artifacts(
        &self,
        _request: BeginThreadRunRequest,
        _materials: Vec<RunInputArtifactMaterial>,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        self.touched()
    }
    async fn begin_thread_run_with_artifacts_v2(
        &self,
        _request: BeginThreadRunV2Request,
        _materials: Vec<RunInputArtifactMaterial>,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        self.touched()
    }
    async fn cancel_thread_run(
        &self,
        _request: CancelThreadRunRequest,
    ) -> Result<ThreadRunCancellation, ThreadDirectoryError> {
        self.touched()
    }
    async fn subscribe_thread_events(
        &self,
        _request: ThreadEventSubscription,
    ) -> Result<AppEventStream, ThreadDirectoryError> {
        self.touched()
    }
    async fn subscribe_channel_activity(
        &self,
        _request: ChannelActivitySubscription,
    ) -> Result<AppEventStream, ThreadDirectoryError> {
        self.touched()
    }
    async fn thread_history(
        &self,
        _request: ThreadHistoryRequest,
    ) -> Result<ThreadHistory, ThreadDirectoryError> {
        self.touched()
    }
    async fn thread_conversation(
        &self,
        _request: ThreadConversationRequest,
    ) -> Result<openbot_contracts::command::ThreadConversationSnapshot, ThreadDirectoryError> {
        self.touched()
    }
    async fn run_reconciliation(
        &self,
        _request: RunReconciliationRequest,
    ) -> Result<openbot_contracts::reconciliation::RunReconciliationSnapshot, ThreadDirectoryError>
    {
        self.touched()
    }
    async fn run_effect_receipts(
        &self,
        _request: RunEffectReceiptsRequest,
    ) -> Result<openbot_contracts::reconciliation::RunEffectReceiptsSnapshot, ThreadDirectoryError>
    {
        self.touched()
    }
}

#[async_trait]
impl AuditReader for Poison {
    async fn list_audit_events(
        &self,
        _request: AuditPageRequest,
    ) -> Result<AuditPage, AuditReadError> {
        self.touched()
    }
}

#[async_trait]
impl PolicyAdministration for Poison {
    async fn current_policy(&self) -> Result<Option<ActionPolicy>, PolicyAdministrationError> {
        self.touched()
    }
    async fn set_policy(
        &self,
        _updated_by: &ActorId,
        _policy: ActionPolicy,
    ) -> Result<(), PolicyAdministrationError> {
        self.touched()
    }
}

#[async_trait]
impl ComponentAdministration for Poison {
    async fn list_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<ComponentRecords, ComponentAdministrationError> {
        self.touched()
    }
    async fn sync_catalogue(
        &self,
        _auth: &AuthContext,
        _entries: &[CompiledComponentManifestEntry],
    ) -> Result<ComponentCatalogueAdded, ComponentAdministrationError> {
        self.touched()
    }
    async fn update_component_governance(
        &self,
        _auth: &AuthContext,
        _mutation: &ComponentGovernanceMutation,
    ) -> Result<ComponentRecord, ComponentAdministrationError> {
        self.touched()
    }
    async fn list_components_for_agent(
        &self,
        _scope: &ComponentRuntimeScope,
        _renderer_names: &[String],
    ) -> Result<GrantedCompiledComponents, ComponentAdministrationError> {
        self.touched()
    }
    async fn decide_component(
        &self,
        _scope: &ComponentRuntimeScope,
        _component_name: &str,
        _build_has_renderer: bool,
        _functions: &[String],
    ) -> Result<ComponentDecision, ComponentAdministrationError> {
        self.touched()
    }
    async fn call_component_function(
        &self,
        _scope: &ComponentRuntimeScope,
        _component_name: &str,
        _build_has_renderer: bool,
        _plan: &ComponentFunctionCallPlan,
    ) -> Result<ComponentFunctionCall, ComponentAdministrationError> {
        self.touched()
    }
    async fn request_component_human_decision(
        &self,
        _scope: &ComponentHumanDecisionScope,
        _draft: &ComponentHumanDecisionDraft,
    ) -> Result<PendingComponentHumanDecision, ComponentAdministrationError> {
        self.touched()
    }
    async fn list_component_human_decisions(
        &self,
        _auth: &AuthContext,
    ) -> Result<PendingComponentHumanDecisions, ComponentAdministrationError> {
        self.touched()
    }
    async fn resolve_component_human_decision(
        &self,
        _auth: &AuthContext,
        _decision_id: &str,
        _answer: &ComponentHumanDecisionAnswer,
    ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
        self.touched()
    }
    async fn wait_component_human_decision(
        &self,
        _scope: &ComponentHumanDecisionScope,
        _decision_id: &str,
    ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
        self.touched()
    }
}

type Guarded = OpenBotApplication<
    FakeChannelReader,
    FakePeopleAdministration,
    Poison,
    Poison,
    Poison,
    Poison,
    Poison,
>;
fn guarded() -> (Guarded, Poison) {
    let poison = Poison::default();
    let app = OpenBotApplication::new(FakeChannelReader::empty())
        .with_people(FakePeopleAdministration::seeded([sample_person(
            "owner",
            Role::Admin,
        )]))
        .with_audit(poison.clone())
        .with_policy(poison.clone())
        .with_tools(poison.clone(), poison.clone())
        .with_threads(poison.clone())
        .with_component_administration(Arc::new(poison.clone()))
        .with_thread_history_deletion(Arc::new(poison.clone()));
    (app, poison)
}
fn assert_untouched(app: &Guarded, poison: &Poison) {
    assert_eq!(poison.count(), 0);
    assert_eq!(app.channels.call_count(), 0);
    assert!(app.channels.scoped_calls().is_empty());
    assert!(app.channels.detail_calls().is_empty());
    assert!(app.people.calls().is_empty());
}

#[tokio::test]
async fn every_command_variant_refuses_unbound_delegation_before_dispatch() {
    let (app, poison) = guarded();
    let inventory = commands();
    assert_eq!(inventory.len(), 99);
    assert_eq!(
        inventory.iter().map(variant_name).collect::<Vec<_>>(),
        EXPECTED_COMMANDS
    );
    for external in [false, true] {
        for roles in [&[Role::Admin][..], &[Role::User][..]] {
            let auth = delegated(external, roles, 1, 1, None, false);
            for command in &inventory {
                assert_refused(app.execute(auth.clone(), command.clone()).await);
                assert_untouched(&app, &poison);
            }
        }
    }
}

#[tokio::test]
async fn every_subscription_refuses_delegation_before_stream_creation() {
    let (app, poison) = guarded();
    for external in [false, true] {
        let auth = delegated(external, &[Role::Admin], 1, 1, None, false);
        for request in subscriptions() {
            assert_refused(app.subscribe(auth.clone(), request).await);
            assert_untouched(&app, &poison);
        }
    }
}

#[tokio::test]
async fn candidate_internal_commands_require_registered_run_proof() {
    let (app, poison) = guarded();
    for external in [false, true] {
        let auth = delegated(external, &[Role::Admin, Role::User], 1, 1, None, false);
        for run in ["arbitrary-run", "trigger", "foreign-run"] {
            for command in [
                tool(run),
                human(run),
                AppCommand::DecideComponent {
                    component_name: "component".into(),
                    request: ComponentDecisionRequest {
                        agent_id: BotId::new("owner"),
                        functions: vec![],
                    },
                },
                AppCommand::AuthorizeSandboxedComponent {
                    component_name: "component".into(),
                    agent_id: BotId::new("owner"),
                    arguments: json!({"run_id":run,"trigger_id":"trigger","actor":"owner"}),
                },
            ] {
                assert_refused(app.execute(auth.clone(), command).await);
            }
        }
    }
    assert_untouched(&app, &poison);
}

#[tokio::test]
async fn delegated_approval_and_sensitive_requests_refuse_before_validation() {
    let (app, poison) = guarded();
    let auth = delegated(true, &[Role::Admin], 1, 1, None, true);
    let sensitive = [
        "DecideToolApproval",
        "ResolveComponentHumanDecision",
        "ResolveRemoteInterrupt",
        "CreateCredential",
        "RotateCredential",
        "RevokeCredential",
        "CreateModelConnection",
        "UpdateModelConnection",
        "DeleteModelConnection",
        "BeginMcpOAuth",
        "RegisterMcpOAuthClient",
        "AddCustomMcpServer",
        "GrantPlugin",
        "RevokePlugin",
        "SavePluginSkill",
        "IssueAgentCallbackToken",
        "RevokeAgentCallbackToken",
        "SetActionPolicy",
        "UpdateUiPreferences",
        "ChangePersonRole",
        "ChangePersonAccess",
        "CreateChannel",
        "CreateAgent",
        "IssueScreenSession",
    ];
    let selected = commands()
        .into_iter()
        .filter(|command| sensitive.contains(&variant_name(command)))
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), sensitive.len());
    for command in selected {
        assert_refused(app.execute(auth.clone(), command).await);
    }
    assert_untouched(&app, &poison);
}

#[tokio::test]
async fn delegated_execute_and_subscribe_touch_no_backend_ports() {
    let (app, poison) = guarded();
    let auth = delegated(false, &[Role::Admin, Role::User], 3, 8, None, false);
    for command in commands() {
        assert_refused(app.execute(auth.clone(), command).await);
        assert_untouched(&app, &poison);
    }
    for request in subscriptions() {
        assert_refused(app.subscribe(auth.clone(), request).await);
        assert_untouched(&app, &poison);
    }
    // A positive call proves the counter is wired to the same application's channel port.
    assert!(
        app.execute(
            auth_for("owner"),
            AppCommand::ListVisibleChannels {
                limit: None,
                cursor: None
            }
        )
        .await
        .is_ok()
    );
    assert_eq!(app.channels.call_count(), 1);
    assert_eq!(poison.count(), 0);
}

#[tokio::test]
async fn delegated_history_deletion_is_refused_before_the_history_authority() {
    let (app, poison) = guarded();
    let command = AppCommand::DeleteThreadHistory {
        thread_id: ThreadId::new("550e8400-e29b-71d4-a716-446655440000"),
        request_id: "019a0300-0000-7000-8000-000000000003".to_owned(),
    };
    for external in [false, true] {
        let auth = delegated(external, &[Role::Admin, Role::User], 1, 1, None, false);
        assert_refused(app.execute(auth, command.clone()).await);
        assert_untouched(&app, &poison);
    }
}

#[tokio::test]
async fn role_generation_and_source_do_not_bypass_delegation_gate() {
    let (app, poison) = guarded();
    for external in [false, true] {
        for roles in [
            &[][..],
            &[Role::Admin][..],
            &[Role::User][..],
            &[Role::User, Role::Admin][..],
        ] {
            for generation in [0, u64::MAX] {
                for revision in [0, u64::MAX] {
                    for expiry in [
                        None,
                        Some(UNIX_EPOCH),
                        Some(UNIX_EPOCH + Duration::from_secs(10_000_000_000)),
                    ] {
                        for single_user in [false, true] {
                            let auth = delegated(
                                external,
                                roles,
                                generation,
                                revision,
                                expiry,
                                single_user,
                            );
                            assert_refused(app.execute(auth.clone(), AppCommand::Health).await);
                            assert_refused(app.execute(auth.clone(), tool("trigger")).await);
                            assert_refused(app.subscribe(auth, SubscriptionRequest::Health).await);
                        }
                    }
                }
            }
        }
    }
    // A mismatching carrier generation is also not evidence of a current grant.
    let delegation = VerifiedDelegation::from_verified_grant(
        DelegationSource::ExternalBinding {
            binding_id: "binding".into(),
        },
        1,
        "trigger".into(),
        AuthGeneration::new(0),
        None,
    )
    .unwrap();
    let auth = AuthContextBuilder::from_verified_delegation(
        DeploymentId::new("d"),
        TenantId::new("t"),
        ActorId::new("owner"),
        AuthGeneration::new(99),
        false,
        delegation,
    )
    .build();
    assert_refused(app.execute(auth, AppCommand::Health).await);
    assert_untouched(&app, &poison);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_delegated_requests_remain_refused_without_effects() {
    let (app, poison) = guarded();
    let app = Arc::new(app);
    for round in 0..10 {
        let generation = u64::try_from(round).unwrap();
        let mut tasks = Vec::new();
        for (index, command) in commands().into_iter().enumerate() {
            let app = Arc::clone(&app);
            let auth = delegated(
                (round + index).is_multiple_of(2),
                &[Role::Admin, Role::User],
                generation,
                1,
                None,
                false,
            );
            tasks.push(tokio::spawn(async move {
                assert_refused(app.execute(auth.clone(), command).await);
                assert_refused(app.subscribe(auth, SubscriptionRequest::Health).await);
            }));
        }
        for request in subscriptions() {
            let app = Arc::clone(&app);
            let auth = delegated(true, &[], generation, 0, Some(UNIX_EPOCH), true);
            tasks.push(tokio::spawn(async move {
                assert_refused(app.subscribe(auth, request).await);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_untouched(&app, &poison);
    }
}

#[tokio::test]
async fn interactive_authority_keeps_existing_dispatch_and_subscriptions() {
    let app = OpenBotApplication::new(FakeChannelReader::empty()).with_people(
        FakePeopleAdministration::seeded([sample_person("owner", Role::Admin)]),
    );
    let auth = auth_for("owner");
    assert!(auth.delegation().is_none());
    assert!(matches!(
        app.execute(auth.clone(), AppCommand::Health).await,
        Ok(AppReply::Health(_))
    ));
    assert_eq!(app.channels.call_count(), 0);
    assert!(
        app.execute(
            auth.clone(),
            AppCommand::ListVisibleChannels {
                limit: None,
                cursor: None
            }
        )
        .await
        .is_ok()
    );
    assert_eq!(app.channels.call_count(), 1);
    assert!(
        app.execute(auth.clone(), AppCommand::GetCurrentUser)
            .await
            .is_ok()
    );
    assert_eq!(app.people.calls().len(), 1);
    assert!(
        app.subscribe(auth.clone(), SubscriptionRequest::Health)
            .await
            .is_ok()
    );
    for (request, expected_dependency) in [
        (
            SubscriptionRequest::ThreadEvents {
                thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
                after_event_sequence: None,
            },
            "thread_directory",
        ),
        (SubscriptionRequest::ChannelActivity, "thread_directory"),
        (SubscriptionRequest::ToolApprovalActivity, "tool_approval"),
    ] {
        let error = match app.subscribe(auth.clone(), request).await {
            Ok(_) => panic!("missing dependency accepted"),
            Err(error) => error,
        };
        match error {
            AppError::DependencyUnavailable { dependency } => {
                assert_eq!(dependency, expected_dependency)
            }
            other => panic!("changed dependency refusal: {other:?}"),
        }
    }
    assert!(matches!(
        app.execute(auth, AppCommand::GetActionPolicy).await,
        Err(AppError::DependencyUnavailable {
            dependency: "policy_store"
        })
    ));
    assert_eq!(app.channels.call_count(), 1);
    assert_eq!(app.people.calls().len(), 1);
}
